"""Переносимые примитивы для чтения файлов LockBit 3 без исполнения образцов."""

import struct

try:
    from ._native import salsa_crypt as _native_salsa_crypt
except ImportError:
    _native_salsa_crypt = None


_MASK32 = (1 << 32) - 1
_MASK64 = (1 << 64) - 1
_WORDS = struct.Struct("<16I")
_QUARTERS = (
    (0, 4, 8, 12),
    (5, 9, 13, 1),
    (10, 14, 2, 6),
    (15, 3, 7, 11),
    (0, 1, 2, 3),
    (5, 6, 7, 4),
    (10, 11, 8, 9),
    (15, 12, 13, 14),
)


def _salsa_block(words: list[int]) -> bytes:
    x = words.copy()
    for _ in range(10):
        for a, b, c, d in _QUARTERS:
            value = (x[a] + x[d]) & _MASK32
            x[b] ^= ((value << 7) | (value >> 25)) & _MASK32
            value = (x[b] + x[a]) & _MASK32
            x[c] ^= ((value << 9) | (value >> 23)) & _MASK32
            value = (x[c] + x[b]) & _MASK32
            x[d] ^= ((value << 13) | (value >> 19)) & _MASK32
            value = (x[d] + x[c]) & _MASK32
            x[a] ^= ((value << 18) | (value >> 14)) & _MASK32
    return _WORDS.pack(*((left + right) & _MASK32 for left, right in zip(x, words)))


def salsa_block(state: bytes) -> bytes:
    """Вычисляет блок Salsa20/20 из полного состояния длиной 64 байта."""
    if len(state) != 64:
        raise ValueError("Состояние Salsa20 должно содержать 64 байта")
    return _salsa_block(list(_WORDS.unpack(state)))


def _immutable_bytes(value: bytes) -> bytes:
    if type(value) is bytes:
        return value
    return memoryview(value).tobytes()


def salsa_crypt_python(data: bytes, state: bytes, *, block_offset: int = 0) -> bytes:
    """Применяет Salsa20 на Python; смещение задается в блоках по 64 байта."""
    data = _immutable_bytes(data)
    state = _immutable_bytes(state)
    if len(state) != 64:
        raise ValueError("Состояние Salsa20 должно содержать 64 байта")
    if not isinstance(block_offset, int):
        raise ValueError("Смещение блока должно быть беззнаковым 64-битным числом")
    block_offset = int.__int__(block_offset)
    if not 0 <= block_offset <= _MASK64:
        raise ValueError("Смещение блока должно быть беззнаковым 64-битным числом")
    words = list(_WORDS.unpack(state))
    counter = (words[8] | (words[9] << 32)) + block_offset
    blocks = (len(data) + 63) // 64
    if counter > _MASK64 or counter + blocks > (1 << 64):
        raise ValueError("Переполнение счетчика Salsa20")
    words[8], words[9] = counter & _MASK32, counter >> 32
    result = bytearray(len(data))
    for position in range(0, len(data), 64):
        key_stream = _salsa_block(words)
        piece = data[position : position + 64]
        result[position : position + len(piece)] = bytes(
            value ^ key for value, key in zip(piece, key_stream)
        )
        words[8] = (words[8] + 1) & _MASK32
        if words[8] == 0:
            words[9] = (words[9] + 1) & _MASK32
    return bytes(result)


def salsa_crypt(data: bytes, state: bytes, *, block_offset: int = 0) -> bytes:
    """Применяет Salsa20 через доступный backend без изменения входных буферов."""
    if _native_salsa_crypt is None:
        return salsa_crypt_python(data, state, block_offset=block_offset)
    return _native_salsa_crypt(
        _immutable_bytes(data), _immutable_bytes(state), block_offset=block_offset
    )


class APLibError(ValueError):
    """Некорректный или слишком большой поток aPLib."""


class _BitReader:
    def __init__(self, data: bytes, gamma_limit: int):
        self.data = data
        self.position = 0
        self.tag = 0
        self.bits_left = 0
        self.gamma_limit = gamma_limit

    def byte(self) -> int:
        if self.position >= len(self.data):
            raise APLibError("Неожиданный конец потока aPLib")
        value = self.data[self.position]
        self.position += 1
        return value

    def bit(self) -> int:
        if self.bits_left == 0:
            self.tag = self.byte()
            self.bits_left = 8
        self.bits_left -= 1
        return (self.tag >> self.bits_left) & 1

    def gamma(self) -> int:
        value = 1
        while True:
            value = (value << 1) | self.bit()
            if value > self.gamma_limit:
                raise APLibError("Слишком большое число в потоке aPLib")
            if not self.bit():
                return value


def aplib_decompress(data: bytes, *, max_output: int = 8192) -> bytes:
    """Распаковывает один сырой поток aPLib с обязательным лимитом результата."""
    if not isinstance(max_output, int) or max_output < 1:
        raise ValueError("Лимит распаковки должен быть положительным числом")
    reader = _BitReader(data, max_output + 3)
    output = bytearray([reader.byte()])
    previous_offset = 0
    last_was_match = False

    def append_byte(value: int) -> None:
        if len(output) >= max_output:
            raise APLibError("Превышен лимит распаковки aPLib")
        output.append(value)

    def copy_match(offset: int, length: int) -> None:
        if not 1 <= offset <= len(output):
            raise APLibError("Ссылка aPLib выходит за границы результата")
        if length > max_output - len(output):
            raise APLibError("Превышен лимит распаковки aPLib")
        for _ in range(length):
            output.append(output[-offset])

    while True:
        if not reader.bit():
            append_byte(reader.byte())
            last_was_match = False
        elif not reader.bit():
            encoded_offset = reader.gamma()
            if not last_was_match and encoded_offset == 2:
                copy_match(previous_offset, reader.gamma())
            else:
                high = encoded_offset - (2 if last_was_match else 3)
                if high < 0:
                    raise APLibError("Некорректное смещение aPLib")
                offset = (high << 8) | reader.byte()
                length = reader.gamma()
                if offset >= 32000:
                    length += 1
                if offset >= 1280:
                    length += 1
                if offset < 128:
                    length += 2
                copy_match(offset, length)
                previous_offset = offset
            last_was_match = True
        elif not reader.bit():
            value = reader.byte()
            offset = value >> 1
            if offset == 0:
                return bytes(output)
            copy_match(offset, 2 + (value & 1))
            previous_offset = offset
            last_was_match = True
        else:
            offset = 0
            for _ in range(4):
                offset = (offset << 1) | reader.bit()
            if offset:
                copy_match(offset, 1)
            else:
                append_byte(0)
            last_was_match = False
