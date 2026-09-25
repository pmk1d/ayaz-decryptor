"""Эталонные векторы шифра и проверки границ распаковщика."""

import struct
import unittest

from ayaz_decryptor.crypto import (
    APLibError,
    aplib_decompress,
    salsa_block,
    salsa_crypt,
    salsa_crypt_python,
)


class SalsaTests(unittest.TestCase):
    @staticmethod
    def state() -> bytes:
        constants = b"expand 32-byte k"
        key = bytes.fromhex("80" + "00" * 31)
        return (
            constants[:4]
            + key[:16]
            + constants[4:8]
            + bytes(16)
            + constants[8:12]
            + key[16:]
            + constants[12:]
        )

    def test_ecrypt_vector_two_blocks(self):
        # Вектор ECRYPT, Salsa20/20, 256 бит, набор 1, вектор 0.
        # https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/SelfTest/Cipher/test_Salsa20.py
        expected = bytes.fromhex(
            "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844"
            "b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117"
            "8da2b74eef1b6283e7e20166abcae538e9716e4669e2816b6b20c5c356802001"
            "cc1403a9a117d12a2669f456366d6ebb0f1246f1265150f793cdb4b253e348ae"
        )
        self.assertEqual(salsa_crypt(bytes(128), self.state()), expected)
        self.assertEqual(salsa_crypt_python(bytes(128), self.state()), expected)
        self.assertEqual(salsa_block(self.state()), expected[:64])
        self.assertEqual(salsa_crypt(bytes(64), self.state(), block_offset=1), expected[64:])

    def test_roundtrip_arbitrary_state_and_partial_block(self):
        state = bytes(range(64))
        plaintext = bytes(range(253))
        ciphertext = salsa_crypt(plaintext, state)
        self.assertEqual(len(ciphertext), len(plaintext))
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(salsa_crypt(ciphertext, state), plaintext)
        self.assertEqual(state, bytes(range(64)))

    def test_counter_carry(self):
        words = list(struct.unpack("<16I", self.state()))
        words[8], words[9] = 0xFFFFFFFF, 5
        state = struct.pack("<16I", *words)
        words[8], words[9] = 0, 6
        self.assertEqual(
            salsa_crypt(bytes(128), state)[64:], salsa_block(struct.pack("<16I", *words))
        )

    def test_invalid_state_and_counter(self):
        for state in (b"", bytes(63), bytes(65)):
            with self.assertRaises(ValueError):
                salsa_crypt(b"", state)
        for offset in (-1, 1 << 64, 1.5):
            with self.assertRaises(ValueError):
                salsa_crypt(b"test", self.state(), block_offset=offset)
        words = list(struct.unpack("<16I", self.state()))
        words[8] = words[9] = 0xFFFFFFFF
        with self.assertRaises(ValueError):
            salsa_crypt(bytes(65), struct.pack("<16I", *words))


class APLibTests(unittest.TestCase):
    def test_filename_reference_vector(self):
        self.assertEqual(
            aplib_decompress(bytes.fromhex("61e02ee074e078db09020000")),
            "a.txt\0".encode("utf-16le"),
        )

    def test_literal_vector(self):
        self.assertEqual(aplib_decompress(b"A\x30BC\x00"), b"ABC")

    def test_short_match_vector(self):
        self.assertEqual(aplib_decompress(b"A\x36BC\x07\x00"), b"ABCABC")

    def test_long_match_vector(self):
        self.assertEqual(aplib_decompress(b"A\x14BCD\x04\x60\x00"), b"ABCDABCD")

    def test_repeated_offset_vector(self):
        self.assertEqual(
            aplib_decompress(bytes.fromhex("4114424344042258c000")), b"ABCDABCDXBCD"
        )

    def test_consecutive_long_matches_vector(self):
        self.assertEqual(
            aplib_decompress(bytes.fromhex("41144243440441048000")), b"ABCDABCDABCD"
        )

    def test_nibble_match_and_zero_vector(self):
        self.assertEqual(aplib_decompress(b"A\xe1\xcb\x00\x00"), b"A\x00A")

    def test_overlap_and_exact_limit(self):
        self.assertEqual(aplib_decompress(b"A\xd8\x03\x00", max_output=4), b"AAAA")
        with self.assertRaises(APLibError):
            aplib_decompress(b"A\xd8\x03\x00", max_output=3)

    def test_truncated_or_invalid_inputs(self):
        for data in (b"", b"A", b"A\x00", b"A\xc0\xff", b"A\x80"):
            with self.subTest(data=data), self.assertRaises(APLibError):
                aplib_decompress(data)

    def test_rejects_backreference_before_start(self):
        with self.assertRaises(APLibError):
            aplib_decompress(b"A\xd8\x04\x00")

    def test_invalid_limit(self):
        for limit in (0, -1, 1.5):
            with self.assertRaises(ValueError):
                aplib_decompress(b"A\xc0\x00", max_output=limit)

    def test_trailing_data_is_outside_compressed_stream(self):
        self.assertEqual(aplib_decompress(b"A\xc0\x00metadata", max_output=1), b"A")


if __name__ == "__main__":
    unittest.main()
