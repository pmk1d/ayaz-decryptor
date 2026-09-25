"""Воспроизводимый замер Salsa20 на синтетических данных."""

import argparse
import hashlib
import json
import platform
import statistics
import struct
import sys
import time

from ayaz_decryptor import crypto


def positive_integer(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Значение должно быть положительным")
    return number


def synthetic_inputs(size):
    data = (bytes(range(256)) * ((size + 255) // 256))[:size]
    state = bytearray(hashlib.sha512(b"salsa20-synthetic-benchmark-v1").digest())
    struct.pack_into("<Q", state, 32, 0)
    return data, bytes(state)


def timed_calls(function, data, state, repeats):
    start = time.perf_counter()
    for _ in range(repeats):
        result = function(data, state, block_offset=7)
    return time.perf_counter() - start, result


def measure(function, name, data, state, expected, samples, min_seconds=0):
    repeats = 1
    if min_seconds:
        while True:
            elapsed, result = timed_calls(function, data, state, repeats)
            if result != expected:
                raise RuntimeError(f"Результат {name} отличается от Python")
            if elapsed >= min_seconds:
                break
            repeats *= 2

    durations = []
    for _ in range(samples):
        elapsed, result = timed_calls(function, data, state, repeats)
        if result != expected:
            raise RuntimeError(f"Результат {name} отличается от Python")
        durations.append(elapsed)
    median = statistics.median(durations)
    return {
        "backend": name,
        "samples": samples,
        "repeats_per_sample": repeats,
        "median_seconds": median,
        "min_seconds": min(durations),
        "max_seconds": max(durations),
        "mib_per_second": len(data) * repeats / (1024 ** 2 * median),
    }


def run_benchmark(size, python_samples, native_samples):
    data, state = synthetic_inputs(size)
    expected = crypto.salsa_crypt_python(data, state, block_offset=7)
    native_available = crypto._native_salsa_crypt is not None
    if native_available and crypto.salsa_crypt(data, state, block_offset=7) != expected:
        raise RuntimeError("C backend не прошел побайтное сравнение с Python")
    results = [
        measure(crypto.salsa_crypt_python, "python", data, state, expected, python_samples)
    ]
    if native_available:
        results.append(
            measure(crypto.salsa_crypt, "native", data, state, expected, native_samples, 0.2)
        )
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "implementation": sys.implementation.name,
        "timer": "perf_counter",
        "parameters": {
            "size_bytes": size,
            "python_samples": python_samples,
            "native_samples": native_samples,
            "native_min_seconds_per_sample": 0.2,
        },
        "native_available": native_available,
        "native_equals_python": True if native_available else None,
        "result_sha256": hashlib.sha256(expected).hexdigest(),
        "results": results,
        "speedup": results[1]["mib_per_second"] / results[0]["mib_per_second"]
        if native_available else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-bytes", type=positive_integer, default=262144)
    parser.add_argument("--python-samples", type=positive_integer, default=3)
    parser.add_argument("--native-samples", type=positive_integer, default=5)
    parser.add_argument("--json", action="store_true", help="Вывести результат в JSON")
    args = parser.parse_args()
    report = run_benchmark(args.size_bytes, args.python_samples, args.native_samples)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    print(f"Платформа: {report['platform']} ({report['machine']})")
    print(f"Python: {report['python']} ({report['implementation']})")
    print(f"Размер: {args.size_bytes} байт; время — медиана независимых серий")
    for result in report["results"]:
        print(
            f"{result['backend']}: {result['mib_per_second']:.3f} MiB/s; "
            f"{result['samples']} серий по {result['repeats_per_sample']} вызовов; "
            f"медиана {result['median_seconds']:.6f} с"
        )
    if report["native_available"]:
        print(f"Ускорение: {report['speedup']:.2f}×; побайтное сравнение: совпадает")
    else:
        print("C backend недоступен; измерена реализация на Python")
    print(f"SHA-256 синтетического результата: {report['result_sha256']}")


if __name__ == "__main__":
    main()
