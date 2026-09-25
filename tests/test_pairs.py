import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from ayaz_decryptor import pairs


class PairArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.archive_path = Path(self.directory.name) / "pairs.zip"

    def make_archive(self, mutate=None, name_sizes=(15, 16, 37), extra=None):
        members = {}
        records = []
        stream = bytes((index * 7 + 3) % 256 for index in range(256))
        for number, name_size in enumerate(name_sizes):
            plain = b"sample original bytes"
            header = struct.pack("<HQII", name_size, 0x520000, 3, 3)
            metadata = bytes(name_size) + header + bytes(range(64))
            encrypted_metadata = bytes(a ^ b for a, b in zip(metadata, stream))
            encrypted = bytes(byte ^ 37 for byte in plain) + encrypted_metadata
            encrypted += struct.pack("<HI", len(metadata), 0x12345678) + b"K" * 128
            record = {"inode": number, "category": "documents"}
            for side, data in (("encrypted", encrypted), ("decrypted", plain)):
                member = f"documents/{number}/{side}/file.bin"
                members[member] = data
                record[side] = {
                    "archive_path": member, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            records.append(record)
        manifest = {"pair_count": len(records), "pairs": records}
        if mutate:
            mutate(manifest, members)
        members["manifest.json"] = json.dumps(manifest).encode()
        if extra:
            members.update(extra)
        with zipfile.ZipFile(self.archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return stream

    def test_validated_iteration_and_limited_coverage(self):
        stream = self.make_archive()
        loaded = list(pairs.iter_pairs(self.archive_path))
        self.assertEqual(len(loaded), 3)
        self.assertEqual(loaded[0][2], b"sample original bytes")
        report = pairs.analyze_archive(self.archive_path)
        self.assertTrue(report["all_manifest_hashes_verified"])
        self.assertFalse(report["plaintext_recovered"])
        self.assertEqual(report["group_count"], 1)
        group = report["groups"][0]
        self.assertEqual((group["info_size_min"], group["info_size_max"]), (97, 119))
        mask = group["coverage_known_mask"]
        recovered = bytes.fromhex(group["coverage_known_hex"])
        known = {15, 16, 17, 37, 38}
        self.assertEqual(group["known_bytes"], len(known))
        self.assertEqual(group["profile"]["key_blob_sha256"], group["encrypted_key_blob_sha256"])
        self.assertEqual(group["profile"]["stream_hex"], group["coverage_known_hex"])
        self.assertEqual(bytes.fromhex(group["profile"]["known_mask_hex"]), bytes(map(int, mask)))
        for index in range(len(mask)):
            self.assertEqual(mask[index], "1" if index in known else "0")
            self.assertEqual(recovered[index], stream[index] if index in known else 0)
        self.assertEqual([p["missing_key_bytes"] for p in group["pairs"]], [62, 62, 64])

    def test_corrupted_hash_rejected(self):
        def mutate(manifest, members):
            manifest["pairs"][0]["encrypted"]["sha256"] = "0" * 64
        self.make_archive(mutate)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            list(pairs.iter_pairs(self.archive_path))

    def test_manifest_traversal_rejected(self):
        def mutate(manifest, members):
            manifest["pairs"][0]["encrypted"]["archive_path"] = "../file.bin"
        self.make_archive(mutate)
        with self.assertRaisesRegex(ValueError, "путь"):
            list(pairs.iter_pairs(self.archive_path))

    def test_zip_traversal_rejected_even_when_unused(self):
        self.make_archive(extra={"../outside": b"data"})
        with self.assertRaisesRegex(ValueError, "путь"):
            list(pairs.iter_pairs(self.archive_path))

    def test_manifest_size_mismatch_rejected(self):
        def mutate(manifest, members):
            manifest["pairs"][0]["encrypted"]["size"] += 1
        self.make_archive(mutate)
        with self.assertRaisesRegex(ValueError, "Размер"):
            list(pairs.iter_pairs(self.archive_path))

    def test_entry_total_count_and_manifest_limits(self):
        self.make_archive()
        for constant, value in (
            ("MAX_ENTRY_BYTES", 10), ("MAX_TOTAL_BYTES", 10),
            ("MAX_ENTRIES", 2), ("MAX_MANIFEST_BYTES", 10),
        ):
            with self.subTest(constant=constant), patch.object(pairs, constant, value):
                with self.assertRaises(ValueError):
                    list(pairs.iter_pairs(self.archive_path))

    def test_symlink_rejected(self):
        self.make_archive()
        with zipfile.ZipFile(self.archive_path, "a") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "target")
        with self.assertRaisesRegex(ValueError, "ссылки"):
            list(pairs.iter_pairs(self.archive_path))

    def test_contradictory_stream_bytes_remain_unknown(self):
        def mutate(manifest, members):
            item = manifest["pairs"][1]["encrypted"]
            data = bytearray(members[item["archive_path"]])
            info_size = int.from_bytes(data[-134:-132], "little")
            data[len(data) - 134 - info_size + 16] ^= 1
            members[item["archive_path"]] = bytes(data)
            item["sha256"] = hashlib.sha256(data).hexdigest()
        self.make_archive(mutate)
        group = pairs.analyze_archive(self.archive_path)["groups"][0]
        self.assertEqual(group["conflicting_offsets"], [16])
        self.assertEqual(group["coverage_known_mask"][16], "0")

    def test_inconsistent_footer_size_rejected(self):
        def mutate(manifest, members):
            item = manifest["pairs"][0]["encrypted"]
            data = bytearray(members[item["archive_path"]])
            data[-134:-132] = struct.pack("<H", 1)
            members[item["archive_path"]] = bytes(data)
            item["sha256"] = hashlib.sha256(data).hexdigest()
        self.make_archive(mutate)
        with self.assertRaisesRegex(ValueError, "footer"):
            pairs.analyze_archive(self.archive_path)


if __name__ == "__main__":
    unittest.main()
