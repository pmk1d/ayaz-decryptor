"""Возобновляемый поиск Salsa20: до 48 неизвестных бит, без потери совпадений."""

from __future__ import annotations

import contextlib
from decimal import Decimal
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from typing import Callable, Iterator, Sequence


class SearchError(RuntimeError):
    """Ошибка исполнителя или нарушение непрерывности проверяемого диапазона."""


def _integer(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _json(data: str | bytes) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Недопустимое число JSON: {value}")

    return json.loads(data, parse_constant=reject_constant)


def _config(state: bytes, offsets: tuple[int, ...], target: bytes) -> tuple[dict, str]:
    config = {
        "algorithm": "salsa20-full-state-prefix-v1",
        "state_hex": state.hex(),
        "unknown_offsets": list(offsets),
        "target_hex": target.hex(),
    }
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    return config, hashlib.sha256(encoded).hexdigest()


def _save(path: Path, config: dict, digest: str, next_candidate: int, total: int) -> None:
    document = {
        "version": 1,
        "config": config,
        "config_sha256": digest,
        "next_candidate": next_candidate,
        "total_candidates": total,
    }
    data = (json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def _load(path: Path, config: dict, digest: str, total: int) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        _save(path, config, digest, 0, total)
        return 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise SearchError("Некорректный файл checkpoint")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            document = _json(source.read(1024 * 1024 + 1))
    except (ValueError, UnicodeError) as error:
        raise SearchError("Повреждённый checkpoint") from error
    finally:
        os.close(descriptor)
    if not isinstance(document, dict) or not _integer(document.get("version"), 1, 1):
        raise SearchError("Неизвестный формат checkpoint")
    if (document.get("config") != config or document.get("config_sha256") != digest
            or document.get("total_candidates") != total):
        raise SearchError("Checkpoint относится к другой конфигурации поиска")
    position = document.get("next_candidate")
    if not _integer(position, 0, total):
        raise SearchError("Позиция checkpoint вне диапазона")
    return position


def _signal_worker(process: subprocess.Popen, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        try:
            os.killpg(process.pid, sig)
        except PermissionError:
            # На macOS группа может исчезнуть между poll() и отправкой сигнала.
            if process.poll() is None:
                try:
                    process.send_signal(sig)
                except PermissionError:
                    if process.poll() is None:
                        raise


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        _signal_worker(process, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _signal_worker(process, signal.SIGKILL)
            process.wait(timeout=3)


def _worker_events(command: list[str], timeout: float) -> Iterator[tuple[str, object]]:
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    pending = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout
    try:
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SearchError(f"Исполнитель превысил предельное время; stderr: {stderr.decode(errors='replace')}")
            events = selector.select(min(0.25, remaining))
            if not events:
                suspended = time.monotonic()
                yield "tick", None
                deadline += time.monotonic() - suspended
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr.extend(chunk)
                    del stderr[:-65536]
                    continue
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    if len(line) > 131072:
                        raise SearchError("Слишком длинная строка исполнителя")
                    try:
                        record = _json(line)
                    except (ValueError, UnicodeError) as error:
                        raise SearchError("Некорректный JSON исполнителя") from error
                    suspended = time.monotonic()
                    yield "record", record
                    deadline += time.monotonic() - suspended
                if len(pending) > 131072:
                    raise SearchError("Слишком длинная строка исполнителя")
        if pending:
            raise SearchError("Незавершённая строка исполнителя")
        try:
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise SearchError("Исполнитель не завершился после закрытия вывода") from error
        yield "exit", {"returncode": code, "stderr": stderr.decode(errors="replace")}
    finally:
        try:
            _stop(process)
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()


def run_search(
    worker: str | Path | Sequence[str],
    state_base: bytes,
    unknown_offsets: tuple[int, ...],
    target: bytes,
    checkpoint_path: Path,
    *,
    batch_count: int = 2**28,
    threads: int = 256,
    segment_seconds: float = 30,
    status_callback: Callable[[dict], None] | None = None,
) -> Iterator[int]:
    """Выдаёт совпадения; вызывающая сторона проверяет их и закрывает генератор при успехе.

    Checkpoint продвигается после возобновления генератора за последним yield пакета.
    Поэтому закрытие или сбой во время проверки совпадения приведут к повтору пакета.
    """
    if not isinstance(state_base, bytes) or len(state_base) != 64:
        raise ValueError("state_base должен содержать 64 байта")
    if (not isinstance(unknown_offsets, tuple) or len(unknown_offsets) > 6
            or any(not _integer(offset, 0, 63) for offset in unknown_offsets)
            or len(set(unknown_offsets)) != len(unknown_offsets)):
        raise ValueError("Допустимо от 0 до 6 уникальных смещений 0..63")
    if not isinstance(target, bytes) or not 1 <= len(target) <= 64:
        raise ValueError("target должен содержать от 1 до 64 байт")
    if not _integer(batch_count, 1, 2**32 - 1):
        raise ValueError("Недопустимый batch_count")
    if not _integer(threads, 32, 1024) or threads % 32:
        raise ValueError("threads должен быть кратен 32 в диапазоне 32..1024")
    if (isinstance(segment_seconds, bool) or not isinstance(segment_seconds, (int, float))
            or not math.isfinite(segment_seconds) or segment_seconds <= 0):
        raise ValueError("segment_seconds должен быть положительным конечным числом")
    command_base = [os.fspath(worker)] if isinstance(worker, (str, Path)) else list(worker)
    if not command_base or any(not isinstance(value, str) or not value or "\0" in value for value in command_base):
        raise ValueError("Некорректная команда исполнителя")
    checkpoint_path = Path(checkpoint_path)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = checkpoint_path.with_name(checkpoint_path.name + ".lock")
    lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            raise SearchError("Файл блокировки должен быть обычным файлом")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SearchError("Этот checkpoint уже используется другим поиском") from error
        config, digest = _config(state_base, unknown_offsets, target)
        total = 1 << (8 * len(unknown_offsets))
        next_candidate = _load(checkpoint_path, config, digest, total)
        resumed_from = next_candidate
        started = time.monotonic()
        last_status = 0.0

        def status(event: str, force: bool = False) -> None:
            nonlocal last_status
            now = time.monotonic()
            if not status_callback or (not force and now - last_status < 1):
                return
            last_status = now
            elapsed = now - started
            tested = next_candidate - resumed_from
            status_callback({
                "type": "search_status", "event": event, "config_sha256": digest,
                "next_candidate": next_candidate, "total_candidates": total,
                "tested_this_run": tested, "elapsed_seconds": elapsed,
                "rate": tested / elapsed if elapsed > 0 else 0,
                "shard": min(next_candidate >> 40, 255) if len(unknown_offsets) == 6 else 0,
            })

        status("start", True)
        while next_candidate < total:
            state = bytearray(state_base)
            if len(unknown_offsets) == 6:
                shard = next_candidate >> 40
                state[unknown_offsets[5]] = shard
                offsets = unknown_offsets[:5]
                worker_start = next_candidate & ((1 << 40) - 1)
                count = (1 << 40) - worker_start
            elif unknown_offsets:
                offsets = unknown_offsets
                worker_start = next_candidate
                count = total - next_candidate
            else:
                offsets = (0,)
                worker_start = state[0]
                count = 1
            delta = next_candidate - worker_start
            worker_next = worker_start
            worker_end = worker_start + count
            command = command_base + [
                "search", state.hex(), ",".join(map(str, offsets)), target.hex(),
                str(worker_start), str(count), str(batch_count), format(Decimal(str(segment_seconds)), "f"), "0", str(threads),
            ]
            saw_device = False
            summary = None
            exited = False
            events = _worker_events(command, max(30.0, segment_seconds + 30.0))
            try:
                for kind, value in events:
                    status("heartbeat")
                    if kind == "tick":
                        continue
                    if kind == "exit":
                        exited = True
                        if value["returncode"] != 0:
                            raise SearchError(f"Исполнитель завершился с кодом {value['returncode']}: {value['stderr']}")
                        continue
                    if not isinstance(value, dict) or summary is not None:
                        raise SearchError("Нарушен порядок записей исполнителя")
                    record_type = value.get("type")
                    if record_type == "device":
                        if saw_device:
                            raise SearchError("Повторная запись device")
                        saw_device = True
                        continue
                    if record_type == "error":
                        raise SearchError(f"Ошибка исполнителя: {value.get('message', 'неизвестная ошибка')}")
                    if not saw_device:
                        raise SearchError("Отсутствует запись device")
                    if record_type == "batch":
                        start, checked = value.get("start"), value.get("count")
                        expected = min(batch_count, worker_end - worker_next)
                        if (not _integer(start, 0, worker_end) or start != worker_next
                                or not _integer(checked, 1, batch_count) or checked != expected
                                or value.get("overflow") is not False):
                            raise SearchError("Разрыв диапазона или переполнение пакета")
                        hits = value.get("hits")
                        if (not isinstance(hits, list) or len(hits) > 4096
                                or any(not _integer(hit, start, start + checked - 1) for hit in hits)
                                or any(left >= right for left, right in zip(hits, hits[1:]))):
                            raise SearchError("Некорректный список совпадений")
                        for hit in hits:
                            yield hit + delta
                        advanced = start + checked
                        _save(checkpoint_path, config, digest, advanced + delta, total)
                        worker_next = advanced
                        next_candidate = advanced + delta
                        status("heartbeat")
                    elif record_type == "summary":
                        completed = worker_next == worker_end
                        if (not _integer(value.get("start"), worker_start, worker_start)
                                or not _integer(value.get("next_candidate"), worker_next, worker_next)
                                or not _integer(value.get("tested"), worker_next - worker_start, worker_next - worker_start)
                                or type(value.get("completed")) is not bool or value["completed"] != completed
                                or value.get("stop_reason") != ("completed" if completed else "max_seconds")):
                            raise SearchError("Итог исполнителя не соответствует подтверждённым пакетам")
                        summary = value
                    else:
                        raise SearchError("Неизвестная запись исполнителя")
            finally:
                events.close()
            if not exited or summary is None:
                raise SearchError("Исполнитель не подтвердил завершение сегмента")
            if worker_next == worker_start:
                raise SearchError("Исполнитель не проверил ни одного кандидата")
            status("segment_complete", True)
        status("complete", True)
    finally:
        os.close(lock)


iter_search = run_search
