"""Разбор метаданных и расшифровка в отдельный новый файл."""

import hashlib
import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from .crypto import aplib_decompress, salsa_crypt


TRAILER = 134
CHUNK = 0x20000
IO_BUFFER = 1024 * 1024
MAX_FEI = 8192


@dataclass(frozen=True)
class Footer:
    body_size: int
    encrypted_info: bytes
    key_blob: bytes
    checksum: int

    @property
    def group(self):
        return hashlib.sha256(self.key_blob).hexdigest()


@dataclass(frozen=True)
class FileInfo:
    name: str
    skipped_bytes: int
    before: int
    after: int
    state: bytes
    name_verified: bool = True


def read_footer(handle) -> Footer:
    handle.seek(0, 2)
    size = handle.tell()
    if size < TRAILER + 83:
        raise ValueError("Файл слишком короткий для LockBit 3")
    handle.seek(-TRAILER, 2)
    tail = handle.read(TRAILER)
    if len(tail) != TRAILER:
        raise ValueError("Трейлер прочитан не полностью")
    length, checksum = struct.unpack_from("<HI", tail)
    if not 83 <= length <= MAX_FEI or length + TRAILER > size:
        raise ValueError("Недопустимая длина метаданных LockBit 3")
    body_size = size - TRAILER - length
    handle.seek(body_size)
    encrypted_info = handle.read(length)
    if len(encrypted_info) != length:
        raise ValueError("Метаданные прочитаны не полностью")
    return Footer(body_size, encrypted_info, tail[6:], checksum)


def decode_info(
    footer: Footer, profile: dict, expected_name: str, *, allow_unknown_name: bool = False
) -> FileInfo:
    if (
        not isinstance(expected_name, str) or not expected_name
        or expected_name in (".", "..") or any(ch in expected_name for ch in "/\\\0")
    ):
        raise ValueError("Недопустимое ожидаемое имя файла")
    if not isinstance(profile, dict):
        raise ValueError("Профиль должен быть JSON-объектом")
    if profile.get("key_blob_sha256") != footer.group:
        raise ValueError("Поток относится к другой группе шифрования")
    stream = bytes.fromhex(profile["stream_hex"])
    mask = bytes.fromhex(profile["known_mask_hex"])
    size = len(footer.encrypted_info)
    if not 83 <= size <= MAX_FEI:
        raise ValueError("Недопустимая длина метаданных LockBit 3")
    if len(stream) != len(mask) or len(stream) < size:
        raise ValueError("Недостаточная длина потока метаданных")
    if any(value not in (0, 1) for value in mask):
        raise ValueError("Маска должна содержать только байты 00 и 01")
    fixed_start = size - 82
    required_start = fixed_start if allow_unknown_name else 0
    if any(value != 1 for value in mask[required_start:size]):
        missing = sum(value != 1 for value in mask[required_start:size])
        raise ValueError(f"Неизвестны {missing} байт потока метаданных; расшифровка остановлена")
    fixed = bytes(
        left ^ right for left, right in zip(footer.encrypted_info[fixed_start:], stream[fixed_start:size])
    )
    packed_size, skipped, before, after = struct.unpack_from("<HQII", fixed)
    if packed_size != fixed_start:
        raise ValueError("Не совпала длина сжатого имени: неверный поток")
    name_verified = all(value == 1 for value in mask[:packed_size])
    name = expected_name
    if name_verified:
        packed = bytes(
            left ^ right for left, right in zip(footer.encrypted_info[:packed_size], stream[:packed_size])
        )
        raw_name = aplib_decompress(packed, max_output=1024)
        if len(raw_name) % 2 or not raw_name.endswith(b"\0\0"):
            raise ValueError("Неверное исходное имя в метаданных")
        name = raw_name[:-2].decode("utf-16le")
        if name != expected_name:
            raise ValueError("Имя в метаданных не совпало с ожидаемым исходным именем")
    if skipped < CHUNK or skipped % CHUNK or not (0 <= before < 4096 and 0 <= after < 4096):
        raise ValueError("Недопустимая схема чередования зашифрованных блоков")
    return FileInfo(name, skipped, before, after, fixed[-64:], name_verified)


def _write_all(target, data: bytes):
    written = target.write(data)
    if written == len(data):
        return
    view = memoryview(data)
    total = 0
    while True:
        if not isinstance(written, int) or not 0 < written <= len(data) - total:
            raise OSError("Не удалось полностью записать результат")
        total += written
        if total == len(data):
            return
        written = target.write(view[total:])


def transform_body(source, target, size: int, info: FileInfo) -> str:
    if not isinstance(size, int) or size < 0:
        raise ValueError("Размер содержимого должен быть неотрицательным целым числом")
    if (
        not all(isinstance(value, int) for value in (info.skipped_bytes, info.before, info.after))
        or info.skipped_bytes < CHUNK or info.skipped_bytes % CHUNK
        or not (0 <= info.before < 4096 and 0 <= info.after < 4096)
        or len(info.state) != 64
    ):
        raise ValueError("Недопустимые параметры расшифровки")
    source.seek(0)
    remaining = size
    encrypted_chunks = info.before + 1
    block_offset = 0
    digest = hashlib.sha256()
    while remaining:
        encrypted = min(encrypted_chunks * CHUNK, remaining)
        while encrypted:
            length = min(IO_BUFFER, encrypted)
            data = source.read(length)
            if len(data) != length:
                raise ValueError("Содержимое исходного файла изменилось или обрезано")
            result = salsa_crypt(data, info.state, block_offset=block_offset)
            block_offset += (length + 63) // 64
            _write_all(target, result)
            digest.update(result)
            remaining -= length
            encrypted -= length
        skip = min(info.skipped_bytes, remaining)
        while skip:
            length = min(IO_BUFFER, skip)
            data = source.read(length)
            if len(data) != length:
                raise ValueError("Незашифрованный участок обрезан")
            _write_all(target, data)
            digest.update(data)
            remaining -= length
            skip -= length
        encrypted_chunks = info.after + 1
    return digest.hexdigest()


def decrypt_file(
    source_path, output_path, profile, expected_name, expected_sha256=None, *, allow_unknown_name=False
):
    if expected_sha256 is not None:
        if (
            not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected_sha256)
        ):
            raise ValueError("Ожидаемый SHA-256 должен содержать ровно 64 hex-символа")
        expected_sha256 = expected_sha256.lower()
    source_path, output_path = Path(source_path), Path(output_path)
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(source_path, flags), "rb") as source:
        initial = os.fstat(source.fileno())
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("Вход должен быть обычным файлом")
        footer = read_footer(source)
        info = decode_info(footer, profile, expected_name, allow_unknown_name=allow_unknown_name)
        # O_EXCL исключает перезапись исходника, существующего результата и ссылки.
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                digest = transform_body(source, target, footer.body_size, info)
                current = os.fstat(source.fileno())
                if (initial.st_size, initial.st_mtime_ns) != (current.st_size, current.st_mtime_ns):
                    raise ValueError("Исходный файл изменился во время чтения")
                if expected_sha256 and digest != expected_sha256:
                    raise ValueError("Результат не совпал с ожидаемым SHA-256")
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            output_path.unlink()
            raise
    validation = "sha256_match" if expected_sha256 else "metadata_only_content_unverified"
    if not info.name_verified:
        validation = (
            "sha256_match_name_unverified" if expected_sha256
            else "fixed_metadata_only_name_and_content_unverified"
        )
    return {
        "output": str(output_path.resolve()), "size": footer.body_size,
        "sha256": digest, "group": footer.group,
        "validation": validation,
        "name_validation": "metadata_match" if info.name_verified else "inventory_label_only",
    }
