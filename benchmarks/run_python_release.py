#!/usr/bin/env python3
"""Run installed-wheel Python lifecycle benchmarks in isolated processes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys


PASSWORD = "unpackio-performance-only"


def cases() -> list[tuple[str, str, str, int, str | None]]:
    result: list[tuple[str, str, str, int, str | None]] = []
    for kind, fixture in (
        ("7z", "solid.7z"),
        ("zip", "mixed.zipx"),
        ("rpm", "payload.rpm"),
        ("cpio", "payload.cpio"),
        ("deb", "payload.deb"),
        ("arj", "payload.arj"),
    ):
        for operation in (
            "inventory",
            "path-inventory",
            "writer",
            "callback",
            "batch",
            "verify",
            "cancelled",
        ):
            iterations = 20 if operation in {"inventory", "path-inventory"} else 5
            if kind in {"7z", "rpm", "deb"}:
                iterations = min(iterations, 5)
            result.append((kind, fixture, operation, iterations, None))
    for fixture in ("payload.lz4", "payload.zst", "payload.Z"):
        for operation in (
            "inventory",
            "path-inventory",
            "writer",
            "callback",
            "verify",
            "cancelled",
        ):
            iterations = 20 if operation in {"inventory", "path-inventory"} else 5
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
        result.append(("zip", fixture, "callback", 3, None))
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
        result.append(("7z", fixture, "verify", 10, None))
    result.append(("7z", "split.7z.001", "path-verify", 3, None))
    result.extend(
        [
            ("7z", "encrypted.7z", "verify", 1, PASSWORD),
            ("7z", "encrypted.7z", "callback", 1, PASSWORD),
        ]
    )
    return result


def median_record(samples: list[dict[str, object]]) -> dict[str, object]:
    varying = {
        "elapsed_ns",
        "average_ns",
        "process_wall_ns",
        "user_cpu_ns",
        "system_cpu_ns",
        "peak_rss_bytes",
        "block_inputs",
        "block_outputs",
    }
    result = {key: value for key, value in samples[0].items() if key not in varying}
    for key in varying:
        values = [sample[key] for sample in samples if key in sample]
        if values:
            result[f"median_{key}"] = int(statistics.median(values))
    result["samples"] = samples
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--phase", required=True)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    if args.samples <= 0:
        raise SystemExit("--samples must be positive")
    directory = args.directory.resolve()
    python = args.python.absolute()
    wheel = args.wheel.resolve()
    benchmark = Path(__file__).with_name("python_lifecycle.py").resolve()
    wrapper = Path(__file__).with_name("run_release.py").resolve()
    records = []
    for kind, fixture, operation, iterations, password in cases():
        command = [python, benchmark, kind, directory / fixture, operation, str(iterations)]
        if password is not None:
            command.append(password)
        samples = []
        for _ in range(args.samples):
            completed = subprocess.run(
                [sys.executable, wrapper, "--sample", *map(str, command)],
                capture_output=True,
                text=True,
                check=True,
            )
            samples.append(json.loads(completed.stdout))
        record = median_record(samples)
        records.append(record)
        print(
            f"{fixture:28} {operation:14} "
            f"{record['median_average_ns']:>12} ns",
            flush=True,
        )
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    report = {
        "schema": 1,
        "phase": args.phase,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "runner_python": sys.version,
            "rustc": subprocess.run(
                [args.rustc, "-Vv"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
        },
        "wheel": {
            "path": str(wheel),
            "bytes": wheel.stat().st_size,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
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
