#!/usr/bin/env python3
"""Run the release lifecycle benchmark in isolated measured processes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
from time import time_ns


PASSWORD = "unpackio-performance-only"


def sample(command: list[str]) -> int:
    try:
        import resource
    except ImportError:
        resource = None
    before = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
    wall_start = time_ns()
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    wall_ns = time_ns() - wall_start
    after = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        return completed.returncode
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"benchmark emitted unexpected output: {completed.stdout!r}")
    result = json.loads(lines[0])
    result["process_wall_ns"] = wall_ns
    if before is not None and after is not None:
        result.update(
            {
                "user_cpu_ns": round((after.ru_utime - before.ru_utime) * 1_000_000_000),
                "system_cpu_ns": round(
                    (after.ru_stime - before.ru_stime) * 1_000_000_000
                ),
                "peak_rss_bytes": after.ru_maxrss,
                "block_inputs": after.ru_inblock - before.ru_inblock,
                "block_outputs": after.ru_oublock - before.ru_oublock,
            }
        )
    print(json.dumps(result, sort_keys=True))
    return 0


def cases() -> list[tuple[str, str, str, int, str | None]]:
    result: list[tuple[str, str, str, int, str | None]] = []
    archive_fixtures = (
        ("7z", "solid.7z"),
        ("zip", "mixed.zipx"),
        ("rpm", "payload.rpm"),
        ("cpio", "payload.cpio"),
        ("deb", "payload.deb"),
        ("arj", "payload.arj"),
    )
    for kind, fixture in archive_fixtures:
        for operation in (
            "inventory",
            "path-inventory",
            "bytes",
            "writer",
            "callback",
            "batch",
            "verify",
            "cancelled",
        ):
            iterations = 50 if operation in {"inventory", "path-inventory"} else 10
            if kind in {"7z", "rpm", "deb"}:
                iterations = min(iterations, 10)
            if kind in {"rpm", "cpio"} and operation in {
                "bytes",
                "writer",
                "callback",
            }:
                iterations = 200
            if kind in {"rpm", "cpio"} and operation in {"batch", "verify"}:
                iterations = 100
            if kind == "deb" and operation in {
                "bytes",
                "writer",
                "callback",
                "batch",
                "verify",
            }:
                iterations = 1_000
            if operation == "cancelled":
                iterations = 1_000
            result.append((kind, fixture, operation, iterations, None))
    for fixture in ("payload.lz4", "payload.zst", "payload.Z"):
        for operation in (
            "inventory",
            "path-inventory",
            "bytes",
            "writer",
            "callback",
            "verify",
            "cancelled",
        ):
            iterations = 50 if operation in {"inventory", "path-inventory"} else 10
            if fixture == "payload.Z":
                iterations = min(iterations, 5)
            result.append(("stream", fixture, operation, iterations, None))
    for fixture in (
        "zip-deflate64.zipx",
        "zip-zstd.zipx",
        "zip-zstd-deprecated.zipx",
        "zip-xz.zipx",
        "zip-ppmd.zipx",
        "winzip-jpeg.zipx",
        "winzip-wavpack.zipx",
    ):
        result.extend(
            [
                ("zip", fixture, "callback", 5, None),
                ("zip", fixture, "verify", 5, None),
            ]
        )
    for fixture in (
        "7z-copy.7z",
        "7z-lzma.7z",
        "7z-lzma2.7z",
        "7z-delta.7z",
        "7z-bcj.7z",
        "7z-bcj2.7z",
        "7z-ppc.7z",
        "7z-arm.7z",
        "7z-arm64.7z",
        "7z-sparc.7z",
        "7z-deflate.7z",
        "7z-bzip2.7z",
        "7z-ppmd.7z",
        "7z-deflate64.7z",
        "7z-ia64.7z",
        "7z-arm-thumb.7z",
        "7z-riscv.7z",
        "7z-swap2.7z",
        "7z-swap4.7z",
    ):
        result.append(("7z", fixture, "verify", 20, None))
    result.append(("7z", "split.7z.001", "path-verify", 5, None))
    result.extend(
        [
            ("7z", "solid.7z", "cancel-latency", 5, None),
            ("zip", "mixed.zipx", "cancel-latency", 5, None),
            ("arj", "payload.arj", "cancel-latency", 5, None),
            ("stream", "payload.Z", "cancel-latency", 5, None),
            ("7z", "encrypted.7z", "verify", 1, PASSWORD),
            ("7z", "encrypted.7z", "callback", 1, PASSWORD),
            ("7z", "encrypted.7z", "cancelled", 5, PASSWORD),
            ("7z", "encrypted.7z", "cancel-latency", 3, PASSWORD),
        ]
    )
    return result


def median_record(records: list[dict[str, object]]) -> dict[str, object]:
    first = records[0]
    result = {
        key: value
        for key, value in first.items()
        if key
        not in {
            "elapsed_ns",
            "average_ns",
            "process_wall_ns",
            "user_cpu_ns",
            "system_cpu_ns",
            "peak_rss_bytes",
            "block_inputs",
            "block_outputs",
        }
    }
    for key in (
        "elapsed_ns",
        "average_ns",
        "process_wall_ns",
        "user_cpu_ns",
        "system_cpu_ns",
        "peak_rss_bytes",
        "block_inputs",
        "block_outputs",
    ):
        values = [record[key] for record in records if key in record]
        if values:
            result[f"median_{key}"] = int(statistics.median(values))
    result["samples"] = records
    return result


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--sample":
        return sample(sys.argv[2:])

    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--phase", required=True)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    if args.samples <= 0:
        raise SystemExit("--samples must be positive")
    directory = args.directory.resolve()
    binary = args.binary.resolve()
    records = []
    for kind, fixture, operation, iterations, password in cases():
        path = directory / fixture
        if not path.is_file():
            raise FileNotFoundError(path)
        command = [str(binary), kind, str(path), operation, str(iterations)]
        if password is not None:
            command.append(password)
        samples = []
        for _ in range(args.samples):
            wrapper = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--sample", *command],
                capture_output=True,
                text=True,
                check=True,
            )
            samples.append(json.loads(wrapper.stdout))
        record = median_record(samples)
        records.append(record)
        print(
            f"{fixture:28} {operation:14} {record['median_average_ns']:>12} ns",
            flush=True,
        )
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    report = {
        "schema": 1,
        "phase": args.phase,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version,
            "rustc": subprocess.run(
                [args.rustc, "-Vv"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
        },
        "benchmark_binary": {
            "path": str(binary),
            "bytes": binary.stat().st_size,
            "sha256": __import__("hashlib").sha256(binary.read_bytes()).hexdigest(),
        },
        "fixture_manifest": manifest,
        "records": records,
    }
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
