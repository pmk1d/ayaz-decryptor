"""Диагностика повреждённых профилей и командный интерфейс."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ayaz_decryptor import __version__
from ayaz_decryptor.__main__ import load_json, main


class CliTests(unittest.TestCase):
    def test_version(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as result:
            main(["--version"])
        self.assertEqual(result.exception.code, 0)
        self.assertIn(__version__, output.getvalue())

    def test_invalid_profiles_return_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile.json"
            for raw in (b"null", b"[]", b"123", b"{", b"\xff", b"[" * 3000 + b"]" * 3000):
                profile.write_bytes(raw)
                errors = io.StringIO()
                with redirect_stderr(errors), patch("ayaz_decryptor.__main__.decrypt_file") as decrypt:
                    code = main([
                        "decrypt", "unused.bin", "--profile", str(profile),
                        "--original-name", "a.txt", "--output", "unused-result.txt",
                    ])
                self.assertEqual(code, 2)
                decrypt.assert_not_called()
                self.assertIn("Ошибка:", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())

    def test_profile_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile.json"
            profile.write_bytes(b" " * (2 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "2 МиБ"):
                load_json(profile)


if __name__ == "__main__":
    unittest.main()
