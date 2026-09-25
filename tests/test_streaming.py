"""Границы чередования, ограничение памяти и ошибки потокового ввода-вывода."""

import hashlib
import io
import unittest
from unittest.mock import patch

from ayaz_decryptor.core import CHUNK, IO_BUFFER, FileInfo, transform_body
from ayaz_decryptor.crypto import salsa_crypt_python


class LimitedWriter(io.BytesIO):
    def write(self, data):
        return super().write(data[:13])


class StreamingTests(unittest.TestCase):
    def test_multiple_encrypted_spans_keep_counter_and_plain_gaps(self):
        size = 20 * CHUNK + 17
        data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
        calls = []

        def synthetic_cipher(data, state, *, block_offset):
            calls.append((len(data), block_offset))
            stream = b"".join(
                bytes([(block_offset + index) % 251]) * 64
                for index in range((len(data) + 63) // 64)
            )
            return bytes(a ^ b for a, b in zip(data, stream))

        expected = bytearray(data)
        stream_position = 0
        for start, end in ((0, 9 * CHUNK), (11 * CHUNK, 13 * CHUNK),
                           (15 * CHUNK, 17 * CHUNK), (19 * CHUNK, size)):
            for index in range(start, end):
                expected[index] ^= (stream_position // 64) % 251
                stream_position += 1
        target = io.BytesIO()
        with patch("ayaz_decryptor.core.salsa_crypt", side_effect=synthetic_cipher):
            digest = transform_body(
                io.BytesIO(data), target, size, FileInfo("a", 2 * CHUNK, 8, 1, bytes(64))
            )
        self.assertEqual(target.getvalue(), expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
        self.assertEqual(calls, [
            (IO_BUFFER, 0), (CHUNK, 16384), (2 * CHUNK, 18432),
            (2 * CHUNK, 22528), (CHUNK + 17, 26624),
        ])

    def test_partial_writes_are_completed(self):
        data = bytes(range(256))
        target = LimitedWriter()
        info = FileInfo("a", CHUNK, 0, 0, bytes(64))
        expected = salsa_crypt_python(data, info.state)
        digest = transform_body(io.BytesIO(data), target, len(data), info)
        self.assertEqual(target.getvalue(), expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())

    def test_failed_writes_are_not_reported_as_success(self):
        for result in (None, 0, -1, 1000):
            target = unittest.mock.Mock()
            target.write.return_value = result
            with self.subTest(result=result), self.assertRaises(OSError):
                transform_body(io.BytesIO(b"a"), target, 1, FileInfo("a", CHUNK, 0, 0, bytes(64)))

    def test_invalid_size_and_layout_fail_before_writing(self):
        valid = FileInfo("a", CHUNK, 0, 0, bytes(64))
        cases = [(-1, valid), (1.5, valid)]
        cases += [(0, FileInfo("a", skip, before, after, bytes(64))) for skip, before, after in (
            (0, 0, 0), (CHUNK + 1, 0, 0), (CHUNK, -1, 0), (CHUNK, 0, 4096),
        )]
        for size, info in cases:
            target = io.BytesIO()
            with self.subTest(size=size, info=info), self.assertRaises(ValueError):
                transform_body(io.BytesIO(b"a"), target, size, info)
            self.assertEqual(target.getvalue(), b"")

    def test_truncation_in_plain_gap_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Незашифрованный участок обрезан"):
            transform_body(
                io.BytesIO(bytes(CHUNK + 1)), io.BytesIO(), CHUNK + 2,
                FileInfo("a", CHUNK, 0, 0, bytes(64)),
            )


if __name__ == "__main__":
    unittest.main()
