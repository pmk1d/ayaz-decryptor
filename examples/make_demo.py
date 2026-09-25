"""Создаёт небольшой синтетический набор для проверки всех команд CLI."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

from ayaz_decryptor.crypto import salsa_crypt


def create_demo(directory: Path) -> Path:
    directory = Path(directory)
    plain = b"Synthetic recovery example.\n"
    packed_name = bytes.fromhex("61e02ee074e078db09020000")
    state = bytes(range(64))
    metadata = packed_name + struct.pack("<HQII", len(packed_name), 0x20000, 0, 0) + state
    stream = bytes((index * 7 + 3) % 256 for index in range(len(metadata)))
    key_blob = bytes(range(128))
    encrypted = salsa_crypt(plain, state)
    encrypted += bytes(left ^ right for left, right in zip(metadata, stream))
    encrypted += struct.pack("<HI", len(metadata), 0) + key_blob
    profile = {
        "key_blob_sha256": hashlib.sha256(key_blob).hexdigest(),
        "stream_hex": stream.hex(),
        "known_mask_hex": (b"\x01" * len(stream)).hex(),
    }
    pair = {"inode": 1, "category": "synthetic", "validation": "synthetic_fixture"}
    entries = {"encrypted/encrypted.bin": encrypted, "decrypted/a.txt": plain}
    for side, member, name in (
        ("encrypted", "encrypted/encrypted.bin", "encrypted.bin"),
        ("decrypted", "decrypted/a.txt", "a.txt"),
    ):
        data = entries[member]
        pair[side] = {
            "archive_path": member,
            "original_name": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    manifest = {"pair_count": 1, "pairs": [pair]}
    directory.mkdir(mode=0o700)
    for name, data in (("original.txt", plain), ("encrypted.bin", encrypted)):
        with (directory / name).open("xb") as handle:
            handle.write(data)
    with (directory / "profile.json").open("x", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2)
        handle.write("\n")
    with zipfile.ZipFile(directory / "pairs.zip", "x", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        for name, data in entries.items():
            archive.writestr(name, data)
    return directory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Создать полностью синтетический пример")
    parser.add_argument("directory", type=Path, help="Новая папка для четырёх файлов примера")
    args = parser.parse_args(argv)
    try:
        directory = create_demo(args.directory)
    except (OSError, ValueError) as error:
        print(f"Ошибка создания примера: {error}", file=sys.stderr)
        return 2
    print(f"Синтетический пример создан: {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
