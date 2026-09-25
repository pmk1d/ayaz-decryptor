"""Проверки совместимости необязательного ускорителя и реализации на Python."""

from concurrent.futures import ThreadPoolExecutor
import random
import struct
import unittest
from unittest.mock import patch

from ayaz_decryptor import crypto

try:
    from ayaz_decryptor import _native
except ImportError:
    _native = None


def make_state(counter: int) -> bytes:
    state = bytearray((index * 73 + 19) % 256 for index in range(64))
    struct.pack_into("<Q", state, 32, counter)
    return bytes(state)


class BufferSubclass(bytes):
    def __len__(self):
        raise AssertionError("Использован переопределенный метод буфера")

    def __getitem__(self, key):
        raise AssertionError("Использован переопределенный метод буфера")


class IntegerSubclass(int):
    def __int__(self):
        raise AssertionError("Использовано переопределенное преобразование числа")

    def __radd__(self, other):
        raise AssertionError("Использована переопределенная арифметика")

    def __le__(self, other):
        raise AssertionError("Использовано переопределенное сравнение")

    def __ge__(self, other):
        raise AssertionError("Использовано переопределенное сравнение")


class IndexOnly:
    def __index__(self):
        return 0


class BackendTests(unittest.TestCase):
    def test_explicit_python_and_unavailable_native(self):
        data, state = bytes(range(255)), make_state(123)
        expected = crypto.salsa_crypt_python(data, state, block_offset=19)
        with patch.object(crypto, "_native_salsa_crypt", None):
            self.assertEqual(crypto.salsa_crypt(data, state, block_offset=19), expected)

    def test_mutable_buffers_and_subclasses_have_equal_results(self):
        data, state = bytes(range(255)), make_state(321)
        expected = crypto.salsa_crypt_python(data, state, block_offset=7)
        for backend in (crypto.salsa_crypt_python, crypto.salsa_crypt):
            for constructor in (bytearray, memoryview, BufferSubclass):
                with self.subTest(backend=backend.__name__, buffer=constructor.__name__):
                    data_buffer, state_buffer = constructor(data), constructor(state)
                    self.assertEqual(
                        backend(data_buffer, state_buffer, block_offset=IntegerSubclass(7)),
                        expected,
                    )
                    self.assertEqual(memoryview(data_buffer).tobytes(), data)
                    self.assertEqual(memoryview(state_buffer).tobytes(), state)

    def test_last_counter_and_empty_input(self):
        maximum = (1 << 64) - 1
        state = make_state(maximum)
        expected = crypto.salsa_block(state)
        for backend in (crypto.salsa_crypt_python, crypto.salsa_crypt):
            for length in (0, 1, 63, 64):
                with self.subTest(backend=backend.__name__, length=length):
                    self.assertEqual(backend(bytes(length), state), expected[:length])
            with self.assertRaises(ValueError):
                backend(bytes(65), state)
            with self.assertRaises(ValueError):
                backend(b"", state, block_offset=1)
            self.assertEqual(backend(b"", make_state(0), block_offset=maximum), b"")

    def test_invalid_values_rejected_by_both_backends(self):
        for backend in (crypto.salsa_crypt_python, crypto.salsa_crypt):
            for offset in (-1, 1 << 64, 1 << 200, 0.0, "0", None, IndexOnly()):
                with self.subTest(backend=backend.__name__, offset=repr(offset)):
                    with self.assertRaises(ValueError):
                        backend(b"", make_state(0), block_offset=offset)
            for state in (b"", bytes(63), bytes(65)):
                with self.assertRaises(ValueError):
                    backend(b"", state)
            for data in (1, "text", [0, 1]):
                with self.assertRaises(TypeError):
                    backend(data, make_state(0))
            self.assertEqual(
                backend(bytes(65), make_state(0), block_offset=True),
                backend(bytes(65), make_state(1)),
            )


@unittest.skipIf(_native is None, "Необязательный C backend не собран")
class NativeTests(unittest.TestCase):
    def test_public_dispatch_uses_native(self):
        self.assertIs(crypto._native_salsa_crypt, _native.salsa_crypt)
        data, state = b"synthetic test", make_state(0)
        with patch.object(crypto, "salsa_crypt_python", side_effect=AssertionError):
            self.assertEqual(crypto.salsa_crypt(data, state), _native.salsa_crypt(data, state))

    def test_random_differential(self):
        rng = random.Random(918273645)
        for case in range(256):
            data = rng.randbytes(rng.randrange(2049))
            state = bytearray(rng.randbytes(64))
            struct.pack_into("<Q", state, 32, rng.getrandbits(62))
            state = bytes(state)
            offset = rng.getrandbits(20)
            with self.subTest(case=case, length=len(data)):
                expected = crypto.salsa_crypt_python(data, state, block_offset=offset)
                self.assertEqual(_native.salsa_crypt(data, state, block_offset=offset), expected)

    def test_counter_boundary_differential(self):
        maximum = (1 << 64) - 1
        for counter in (0, (1 << 32) - 1, maximum - 1, maximum):
            for offset in (0, 1, 2, (1 << 32), maximum):
                for length in (0, 1, 63, 64, 65, 127, 128, 129):
                    state = make_state(counter)
                    data = bytes((index * 29) % 256 for index in range(length))
                    with self.subTest(counter=counter, offset=offset, length=length):
                        try:
                            expected = crypto.salsa_crypt_python(data, state, block_offset=offset)
                        except ValueError:
                            with self.assertRaises(ValueError):
                                _native.salsa_crypt(data, state, block_offset=offset)
                        else:
                            self.assertEqual(
                                _native.salsa_crypt(data, state, block_offset=offset), expected
                            )

    def test_native_rejects_mutable_buffers_and_invalid_arguments(self):
        state = make_state(0)
        for data in (bytearray(64), memoryview(bytes(64)), 64, "text"):
            with self.assertRaises(TypeError):
                _native.salsa_crypt(data, state)
        for value in (bytearray(state), memoryview(state), None):
            with self.assertRaises(TypeError):
                _native.salsa_crypt(b"", value)
        for value in (b"", bytes(63), bytes(65)):
            with self.assertRaises(ValueError):
                _native.salsa_crypt(b"", value)
        for offset in (-1, 1 << 64, 1 << 200, 0.0, None, IndexOnly()):
            with self.assertRaises(ValueError):
                _native.salsa_crypt(b"", state, block_offset=offset)
        with self.assertRaises(TypeError):
            _native.salsa_crypt(b"", state, 0)

    def test_simultaneous_calls_keep_independent_state(self):
        state = make_state((1 << 32) - 8)
        data = bytes(range(256)) * 128 + b"z"
        expected = [crypto.salsa_crypt_python(data, state, block_offset=i) for i in range(4)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(_native.salsa_crypt, data, state, block_offset=i) for i in range(4)]
            self.assertEqual([future.result() for future in futures], expected)


if __name__ == "__main__":
    unittest.main()
