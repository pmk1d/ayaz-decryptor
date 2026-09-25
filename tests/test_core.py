"""Проверка результата на эталонном потоке и защиты исходных файлов."""

import hashlib
import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ayaz_decryptor.__main__ import main, verify_archive
from ayaz_decryptor.core import FileInfo, decode_info, decrypt_file, read_footer, transform_body
from tests import test_crypto


def fixture():
    packed = bytes.fromhex("61e02ee074e078db09020000")
    state = test_crypto.SalsaTests.state()
    metadata = packed + struct.pack("<HQII", len(packed), 0x520000, 3, 3) + state
    stream = bytes(range(len(metadata)))
    key_blob = bytes(range(128))
    plain = b"ABC"
    # Первые три байта опубликованного вектора ECRYPT: e3 be 8f.
    body = bytes(a ^ b for a, b in zip(plain, bytes.fromhex("e3be8f")))
    data = body + bytes(a ^ b for a, b in zip(metadata, stream))
    data += struct.pack("<HI", len(metadata), 0) + key_blob
    profile = {
        "key_blob_sha256": hashlib.sha256(key_blob).hexdigest(),
        "stream_hex": stream.hex(), "known_mask_hex": (b"\1" * len(stream)).hex(),
    }
    return plain, data, profile


def fixed_only_profile(data, profile):
    size = len(read_footer(io.BytesIO(data)).encrypted_info)
    prefix = size - 82
    return profile | {
        "stream_hex": (b"\0" * prefix + bytes.fromhex(profile["stream_hex"])[prefix:]).hex(),
        "known_mask_hex": (b"\0" * prefix + b"\1" * 82).hex(),
    }


class CoreTests(unittest.TestCase):
    def test_profile_must_be_object_with_binary_mask(self):
        _, data, profile = fixture()
        footer = read_footer(io.BytesIO(data))
        for invalid in (None, [], "profile", 7):
            with self.subTest(profile=invalid), self.assertRaises(ValueError):
                decode_info(footer, invalid, "a.txt")
        mask = "02" + profile["known_mask_hex"][2:]
        with self.assertRaisesRegex(ValueError, "Маска"):
            decode_info(footer, profile | {"known_mask_hex": mask}, "a.txt", allow_unknown_name=True)

    def test_invalid_expected_hash_fails_without_creating_output(self):
        _, data, profile = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source, result = Path(tmp) / "source", Path(tmp) / "result"
            source.write_bytes(data)
            for digest in ("", "a" * 63, "g" * 64, "0 " * 32, 123):
                with self.subTest(digest=digest), self.assertRaises(ValueError):
                    decrypt_file(source, result, profile, "a.txt", digest)
                self.assertFalse(result.exists())

    def test_fixed_metadata_only_decrypt_requires_explicit_mode(self):
        plain, data, profile = fixture()
        profile = fixed_only_profile(data, profile)
        with tempfile.TemporaryDirectory() as tmp:
            source, result = Path(tmp) / "source.bin", Path(tmp) / "result.bin"
            source.write_bytes(data)
            with self.assertRaises(ValueError):
                decrypt_file(source, result, profile, "inventory.txt")
            self.assertFalse(result.exists())
            report = decrypt_file(
                source, result, profile, "inventory.txt", hashlib.sha256(plain).hexdigest(),
                allow_unknown_name=True,
            )
            self.assertEqual(result.read_bytes(), plain)
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(report["validation"], "sha256_match_name_unverified")
            self.assertEqual(report["name_validation"], "inventory_label_only")

    def test_fixed_metadata_requires_every_key_and_layout_byte(self):
        _, data, profile = fixture()
        profile = fixed_only_profile(data, profile)
        size = len(bytes.fromhex(profile["known_mask_hex"]))
        with tempfile.TemporaryDirectory() as tmp:
            source, result = Path(tmp) / "source.bin", Path(tmp) / "result.bin"
            source.write_bytes(data)
            for missing_offset in (size - 82, size - 80, size - 64, size - 1):
                mask = bytearray.fromhex(profile["known_mask_hex"])
                mask[missing_offset] = 0
                with self.subTest(offset=missing_offset), self.assertRaises(ValueError):
                    decrypt_file(
                        source, result, profile | {"known_mask_hex": mask.hex()}, "a.txt",
                        allow_unknown_name=True,
                    )
                self.assertFalse(result.exists())

    def test_optional_mode_keeps_known_filename_checks(self):
        _, data, profile = fixture()
        footer = read_footer(io.BytesIO(data))
        self.assertTrue(decode_info(footer, profile, "a.txt", allow_unknown_name=True).name_verified)
        with self.assertRaises(ValueError):
            decode_info(footer, profile, "b.txt", allow_unknown_name=True)

    def test_unknown_name_label_rejects_paths_and_empty_values(self):
        _, data, profile = fixture()
        footer = read_footer(io.BytesIO(data))
        profile = fixed_only_profile(data, profile)
        for label in ("", ".", "..", "a/b", "a\\b", "a\0b", None, 7):
            with self.subTest(label=label), self.assertRaises(ValueError):
                decode_info(footer, profile, label, allow_unknown_name=True)

    def test_unknown_name_keeps_packed_length_check(self):
        _, data, profile = fixture()
        footer = read_footer(io.BytesIO(data))
        profile = fixed_only_profile(data, profile)
        stream = bytearray.fromhex(profile["stream_hex"])
        stream[-82] ^= 1
        with self.assertRaisesRegex(ValueError, "Не совпала длина"):
            decode_info(footer, profile | {"stream_hex": stream.hex()}, "a.txt", allow_unknown_name=True)

    def test_verify_archive_supports_explicit_unknown_name(self):
        plain, data, profile = fixture()
        profile = fixed_only_profile(data, profile)
        pair = ({"inode": 1, "decrypted": {"original_name": "inventory.txt"}}, data, plain)
        with patch("ayaz_decryptor.__main__.iter_pairs", return_value=[pair]):
            self.assertEqual(verify_archive("unused.zip", profile)["matched"], 0)
            report = verify_archive("unused.zip", profile, allow_unknown_name=True)
        self.assertEqual(report["matched"], 1)
        self.assertEqual(report["results"][0]["validation"], "sha256_match_name_unverified")

    def test_cli_unknown_name_flag_and_unverified_content_label(self):
        plain, data, profile = fixture()
        profile = fixed_only_profile(data, profile)
        with tempfile.TemporaryDirectory() as tmp:
            source, result = Path(tmp) / "source.bin", Path(tmp) / "result.bin"
            profile_path = Path(tmp) / "profile.json"
            source.write_bytes(data)
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            args = [
                "decrypt", str(source), "--profile", str(profile_path),
                "--original-name", "inventory.txt", "--output", str(result),
            ]
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertFalse(result.exists())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args + ["--allow-unknown-name"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["validation"], "fixed_metadata_only_name_and_content_unverified")
            self.assertEqual(result.read_bytes(), plain)

    def test_reference_decrypt_new_file_and_keep_original(self):
        plain, data, profile = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source, result = Path(tmp) / "source.bin", Path(tmp) / "result.bin"
            source.write_bytes(data)
            report = decrypt_file(source, result, profile, "a.txt", hashlib.sha256(plain).hexdigest())
            self.assertEqual(result.read_bytes(), plain)
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(report["validation"], "sha256_match")

    def test_incomplete_stream_wrong_group_and_wrong_name(self):
        _, data, profile = fixture()
        footer = read_footer(io.BytesIO(data))
        for changes, name in (
            ({"known_mask_hex": "00" * (len(footer.encrypted_info))}, "a.txt"),
            ({"key_blob_sha256": "0" * 64}, "a.txt"),
            ({}, "b.txt"),
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decode_info(footer, profile | changes, name)

    def test_never_overwrites_source_or_existing_output(self):
        _, data, profile = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.write_bytes(data)
            link = Path(tmp) / "link"
            link.symlink_to(source)
            for output in (source, link):
                with self.assertRaises(FileExistsError):
                    decrypt_file(source, output, profile, "a.txt")
            self.assertEqual(source.read_bytes(), data)

    def test_wrong_hash_removes_failed_output(self):
        _, data, profile = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source, result = Path(tmp) / "source", Path(tmp) / "result"
            source.write_bytes(data)
            with self.assertRaises(ValueError):
                decrypt_file(source, result, profile, "a.txt", "0" * 64)
            self.assertFalse(result.exists())
            self.assertEqual(source.read_bytes(), data)

    def test_truncated_footer_and_body_rejected(self):
        with self.assertRaises(ValueError):
            read_footer(io.BytesIO(b"short"))
        with self.assertRaises(ValueError):
            transform_body(io.BytesIO(b"A"), io.BytesIO(), 2, FileInfo("a", 131072, 3, 3, bytes(64)))


if __name__ == "__main__":
    unittest.main()
