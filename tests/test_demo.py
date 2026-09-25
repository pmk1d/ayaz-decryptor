"""Проверки синтетического примера через публичные команды CLI."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from ayaz_decryptor.__main__ import main as decryptor_main
from examples.make_demo import create_demo, main as demo_main


class DemoTests(unittest.TestCase):
    def command(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            status = decryptor_main(list(arguments))
        self.assertEqual(status, 0, output.getvalue())
        return json.loads(output.getvalue())

    def test_demo_analyze_verify_decrypt_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "demo"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(demo_main([str(directory)]), 0)
            self.assertEqual(
                {item.name for item in directory.iterdir()},
                {"original.txt", "encrypted.bin", "profile.json", "pairs.zip"},
            )
            original = (directory / "original.txt").read_bytes()
            encrypted = (directory / "encrypted.bin").read_bytes()
            expected = hashlib.sha256(original).hexdigest()
            profile = str(directory / "profile.json")
            archive = str(directory / "pairs.zip")
            analysis = self.command("analyze", archive)
            self.assertEqual(analysis["pair_count"], 1)
            self.assertTrue(analysis["all_manifest_hashes_verified"])
            verification = self.command("verify", archive, "--profile", profile)
            self.assertEqual(verification["matched"], 1)
            self.assertEqual(verification["results"][0]["sha256"], expected)
            output = directory / "recovered.txt"
            result = self.command(
                "decrypt", str(directory / "encrypted.bin"), "--profile", profile,
                "--original-name", "a.txt", "--output", str(output),
                "--expected-sha256", expected,
            )
            self.assertEqual(result["validation"], "sha256_match")
            self.assertEqual(result["sha256"], expected)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual((directory / "encrypted.bin").read_bytes(), encrypted)

    def test_existing_directory_and_file_are_not_changed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = create_demo(root / "demo")
            saved = {item.name: item.read_bytes() for item in directory.iterdir()}
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(demo_main([str(directory)]), 2)
            self.assertEqual(saved, {item.name: item.read_bytes() for item in directory.iterdir()})
            occupied = root / "occupied"
            occupied.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                create_demo(occupied)
            self.assertEqual(occupied.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
