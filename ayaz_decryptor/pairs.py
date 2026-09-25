"""Ограниченное чтение архива известных пар без извлечения файлов."""

from collections import defaultdict
import hashlib
import json
from pathlib import PurePosixPath
import stat
import struct
import zipfile


MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
TRAILER_SIZE = 134
FIXED_INFO_SIZE = 82


def _safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("Недопустимое имя элемента ZIP")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.rstrip("/").split("/")):
        raise ValueError("Небезопасный путь в ZIP или manifest")
    if ":" in path.parts[0]:
        raise ValueError("Недопустимый корневой путь в ZIP")
    return value


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Повторяющийся ключ JSON")
        result[key] = value
    return result


def _read_member(archive, info, limit):
    if info.file_size > limit:
        raise ValueError("Размер элемента ZIP превышает лимит")
    with archive.open(info, "r") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit or len(data) != info.file_size:
        raise ValueError("Неверный или чрезмерный размер элемента ZIP")
    return data


def _load_manifest(archive):
    entries = archive.infolist()
    if len(entries) > MAX_ENTRIES:
        raise ValueError("Слишком много элементов ZIP")
    total = 0
    members = {}
    for info in entries:
        name = _safe_path(info.filename)
        if name in members:
            raise ValueError("Повторяющееся имя элемента ZIP")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError("Специальные файлы и ссылки в ZIP запрещены")
        if info.flag_bits & 1:
            raise ValueError("Архив ZIP защищён паролем")
        if info.file_size < 0 or info.file_size > MAX_ENTRY_BYTES:
            raise ValueError("Размер элемента ZIP превышает лимит")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Общий размер ZIP превышает лимит")
        members[name] = info
    info = members.get("manifest.json")
    if info is None or info.is_dir():
        raise ValueError("В ZIP нет manifest.json")
    try:
        manifest = json.loads(
            _read_member(archive, info, MAX_MANIFEST_BYTES).decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Некорректный manifest.json") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("pairs"), list):
        raise ValueError("В manifest отсутствует список pairs")
    pairs = manifest["pairs"]
    if not pairs or len(pairs) > MAX_ENTRIES // 2:
        raise ValueError("Недопустимое количество пар")
    if type(manifest.get("pair_count")) is not int or manifest["pair_count"] != len(pairs):
        raise ValueError("Число пар не совпадает с pair_count")
    used = set()
    for pair in pairs:
        if not isinstance(pair, dict):
            raise ValueError("Некорректная запись пары")
        for side in ("encrypted", "decrypted"):
            item = pair.get(side)
            if not isinstance(item, dict):
                raise ValueError("В паре отсутствует описание файла")
            name = _safe_path(item.get("archive_path"))
            info = members.get(name)
            if info is None or info.is_dir() or name in used or name == "manifest.json":
                raise ValueError("Файл пары отсутствует, повторяется или не является файлом")
            used.add(name)
            if type(item.get("size")) is not int or item["size"] != info.file_size:
                raise ValueError("Размер файла не совпадает с manifest")
            digest = item.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("Некорректная SHA-256 в manifest")
            try:
                if len(bytes.fromhex(digest)) != 32:
                    raise ValueError
            except ValueError as exc:
                raise ValueError("Некорректная SHA-256 в manifest") from exc
    return manifest, members


def iter_pairs(path):
    """Возвращает метаданные и байты каждой пары после проверки её SHA-256."""
    try:
        with zipfile.ZipFile(path, "r") as archive:
            manifest, members = _load_manifest(archive)
            for pair in manifest["pairs"]:
                payloads = []
                for side in ("encrypted", "decrypted"):
                    item = pair[side]
                    data = _read_member(archive, members[item["archive_path"]], MAX_ENTRY_BYTES)
                    if hashlib.sha256(data).hexdigest() != item["sha256"].lower():
                        raise ValueError("SHA-256 файла не совпадает с manifest")
                    payloads.append(data)
                yield pair, payloads[0], payloads[1]
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError) as exc:
        raise ValueError("Не удалось безопасно прочитать ZIP") from exc


def analyze_archive(path):
    """Проверяет пары и выводит только подтверждённые байты потока метаданных."""
    groups = {}
    total_bytes = 0
    pair_count = 0
    categories = defaultdict(int)
    for pair, encrypted, decrypted in iter_pairs(path):
        if len(encrypted) < TRAILER_SIZE:
            raise ValueError("Зашифрованный файл короче footer")
        info_size = struct.unpack_from("<H", encrypted, len(encrypted) - TRAILER_SIZE)[0]
        name_size = info_size - FIXED_INFO_SIZE
        payload_size = len(encrypted) - TRAILER_SIZE - info_size
        if name_size <= 0 or payload_size < 0 or payload_size != len(decrypted):
            raise ValueError("Размер footer не согласуется с парой")
        footer = encrypted[payload_size:payload_size + info_size]
        group_id = hashlib.sha256(encrypted[-128:]).hexdigest()
        group = groups.setdefault(group_id, {
            "sizes": [], "observations": defaultdict(set), "pairs": [],
            "checksums": set(),
        })
        group["sizes"].append(info_size)
        group["checksums"].add(encrypted[-132:-128].hex())
        for index, byte in enumerate(struct.pack("<H", name_size), start=name_size):
            group["observations"][index].add(footer[index] ^ byte)
        group["pairs"].append({
            "inode": pair.get("inode"),
            "encrypted_archive_path": pair["encrypted"]["archive_path"],
            "info_size": info_size,
            "compressed_name_size": name_size,
            "content_size": payload_size,
        })
        total_bytes += len(encrypted) + len(decrypted)
        pair_count += 1
        category = pair.get("category", "unspecified")
        categories[category if isinstance(category, str) else "unspecified"] += 1
    result_groups = []
    for group_id, group in sorted(groups.items()):
        maximum = max(group["sizes"])
        stream = bytearray(maximum)
        mask = ["0"] * maximum
        conflicts = []
        for index, values in group["observations"].items():
            if len(values) == 1:
                stream[index] = next(iter(values))
                mask[index] = "1"
            else:
                conflicts.append(index)
        for pair in group["pairs"]:
            key_start = pair["compressed_name_size"] + 18
            pair["key_offset"] = key_start
            pair["missing_key_bytes"] = mask[key_start:key_start + 64].count("0")
        result_groups.append({
            "encrypted_key_blob_sha256": group_id,
            "pair_count": len(group["pairs"]),
            "info_size_min": min(group["sizes"]),
            "info_size_max": maximum,
            "compressed_name_size_min": min(group["sizes"]) - FIXED_INFO_SIZE,
            "compressed_name_size_max": maximum - FIXED_INFO_SIZE,
            "stored_checksums_le_hex": sorted(group["checksums"]),
            "coverage_known_mask": "".join(mask),
            "coverage_known_hex": stream.hex(),
            "profile": {
                "key_blob_sha256": group_id,
                "stream_hex": stream.hex(),
                "known_mask_hex": bytes(int(value) for value in mask).hex(),
            },
            "known_bytes": mask.count("1"),
            "unknown_bytes": mask.count("0"),
            "conflicting_offsets": sorted(conflicts),
            "pairs": group["pairs"],
        })
    return {
        "pair_count": pair_count,
        "group_count": len(result_groups),
        "categories": dict(categories),
        "pair_bytes_total": total_bytes,
        "all_manifest_hashes_verified": True,
        "plaintext_recovered": False,
        "keystream_basis": "compressed_filename_size_uint16_only",
        "limits": {
            "entry_bytes": MAX_ENTRY_BYTES, "total_bytes": MAX_TOTAL_BYTES,
            "entries": MAX_ENTRIES, "manifest_bytes": MAX_MANIFEST_BYTES,
        },
        "limitations": [
            "Совпадение SHA-256 с manifest подтверждает соответствие архиву, а не исправность исходного файла.",
            "Часть результатов в архиве имеет ограниченную проверку восстановления.",
            "Неизвестные байты coverage_known_hex заполнены нулями; учитывать coverage_known_mask обязательно.",
            "Байты потока выведены из длины сжатого имени в предполагаемом формате LockBit v3.",
            "Полные ключи содержимого из известных пар не получены; расшифровка не выполнялась.",
        ],
        "groups": result_groups,
    }
