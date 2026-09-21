#!/usr/bin/env python3
"""Measure one installed-package archive or stream lifecycle operation."""

from __future__ import annotations

import gc
import hashlib
import json
from pathlib import Path
import sys
from time import perf_counter_ns
from typing import Any, Callable

import unpackio
import unpackio._native as native


DEFAULT_ITERATIONS = 10


class CountingWriter:
    def __init__(self) -> None:
        self.bytes = 0
        self.writes = 0

    def write(self, data: bytes) -> int:
        self.bytes += len(data)
        self.writes += 1
        return len(data)

    def callback(self, data: bytes) -> None:
        self.write(data)


class CountingSink:
    def __init__(self) -> None:
        self.entries = 0
        self.bytes = 0
        self.writes = 0

    def begin_entry(self, _entry: object, _size: int) -> None:
        self.entries += 1

    def write_entry(self, _index: int, data: bytes) -> None:
        self.bytes += len(data)
        self.writes += 1

    def finish_entry(self, _index: int) -> None:
        return None


def openers(
    kind: str,
) -> tuple[Callable[..., Any], Callable[..., Any], dict[str, object]]:
    if kind == "7z":
        return unpackio.open_bytes, unpackio.open_path, {}
    if kind == "zip":
        return unpackio.open_zip_bytes, unpackio.open_zip_path, {}
    if kind == "rpm":
        return unpackio.open_rpm_bytes, unpackio.open_rpm_path, {}
    if kind == "cpio":
        return unpackio.open_cpio_bytes, unpackio.open_cpio_path, {}
    if kind == "deb":
        return unpackio.open_deb_bytes, unpackio.open_deb_path, {}
    if kind == "arj":
        return unpackio.open_arj_bytes, unpackio.open_arj_path, {}
    if kind == "stream":
        return unpackio.open_stream_bytes, unpackio.open_stream_path, {}
    raise ValueError(f"unknown benchmark kind {kind!r}")


def password_options(kind: str, password: str | None) -> dict[str, object]:
    if password is None:
        return {}
    if kind == "zip":
        return {"password": password.encode("utf-8")}
    if kind == "7z":
        return {"password": password}
    raise ValueError(f"password is not supported for {kind!r}")


def project_entries(archive: object) -> tuple[int, int]:
    projected = 0
    entries = archive.entries()
    for entry in entries:
        for attribute in ("index", "name", "raw_name", "size", "is_safe_path"):
            if hasattr(entry, attribute):
                value = getattr(entry, attribute)
                projected += len(value) if isinstance(value, (bytes, list, str)) else 1
    return len(entries), projected


def archive_iteration(
    kind: str,
    path: Path,
    data: bytes,
    operation: str,
    opened: object | None,
    password: str | None,
) -> dict[str, int]:
    open_bytes, open_path, _ = openers(kind)
    options = password_options(kind, password)
    metrics = {"entries": 0, "output_bytes": 0, "writes": 0, "projected": 0}
    if operation == "inventory":
        archive = open_bytes(data, **options)
        metrics["entries"], metrics["projected"] = project_entries(archive)
    elif operation == "path-inventory":
        archive = open_path(path, **options)
        metrics["entries"], metrics["projected"] = project_entries(archive)
    elif operation == "path-verify":
        archive = open_path(path, **options)
        archive.verify()
    elif operation == "writer":
        if opened is None:
            raise RuntimeError("opened archive is unavailable")
        writer = CountingWriter()
        metrics["output_bytes"] = opened.extract_entry_to(0, writer)
        metrics["writes"] = writer.writes
        if writer.bytes != metrics["output_bytes"]:
            raise RuntimeError("writer byte count disagrees with extraction")
    elif operation == "callback":
        if opened is None:
            raise RuntimeError("opened archive is unavailable")
        writer = CountingWriter()
        metrics["output_bytes"] = opened.stream_entry(0, writer.callback)
        metrics["writes"] = writer.writes
        if writer.bytes != metrics["output_bytes"]:
            raise RuntimeError("callback byte count disagrees with extraction")
    elif operation == "batch":
        if opened is None:
            raise RuntimeError("opened archive is unavailable")
        sink = CountingSink()
        metrics["output_bytes"] = opened.extract_entries_to(sink)
        metrics["entries"] = sink.entries
        metrics["writes"] = sink.writes
        if sink.bytes != metrics["output_bytes"]:
            raise RuntimeError("batch byte count disagrees with extraction")
    elif operation == "verify":
        if opened is None:
            raise RuntimeError("opened archive is unavailable")
        opened.verify()
    elif operation == "cancelled":
        if opened is None:
            raise RuntimeError("opened archive is unavailable")
        cancellation = unpackio.CancellationToken()
        cancellation.cancel()
        try:
            opened.verify(cancellation=cancellation)
        except unpackio.CancelledError:
            pass
        else:
            raise RuntimeError("pre-cancelled verification succeeded")
    else:
        raise ValueError(f"unknown archive operation {operation!r}")
    return metrics


def stream_iteration(
    path: Path,
    data: bytes,
    operation: str,
    opened: object | None,
) -> dict[str, int]:
    metrics = {"entries": 0, "output_bytes": 0, "writes": 0, "projected": 0}
    if operation == "inventory":
        stream = unpackio.open_stream_bytes(data)
        metrics["projected"] = len(repr(stream.info))
    elif operation == "path-inventory":
        stream = unpackio.open_stream_path(path)
        metrics["projected"] = len(repr(stream.info))
    elif operation == "writer":
        if opened is None:
            raise RuntimeError("opened stream is unavailable")
        writer = CountingWriter()
        metrics["output_bytes"] = opened.extract_to(writer)
        metrics["writes"] = writer.writes
        if writer.bytes != metrics["output_bytes"]:
            raise RuntimeError("writer byte count disagrees with extraction")
    elif operation == "callback":
        if opened is None:
            raise RuntimeError("opened stream is unavailable")
        writer = CountingWriter()
        metrics["output_bytes"] = opened.stream(writer.callback)
        metrics["writes"] = writer.writes
        if writer.bytes != metrics["output_bytes"]:
            raise RuntimeError("callback byte count disagrees with extraction")
    elif operation == "verify":
        if opened is None:
            raise RuntimeError("opened stream is unavailable")
        opened.verify()
    elif operation == "cancelled":
        if opened is None:
            raise RuntimeError("opened stream is unavailable")
        cancellation = unpackio.CancellationToken()
        cancellation.cancel()
        try:
            opened.verify(cancellation=cancellation)
        except unpackio.CancelledError:
            pass
        else:
            raise RuntimeError("pre-cancelled stream verification succeeded")
    else:
        raise ValueError(f"unknown stream operation {operation!r}")
    return metrics


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) not in {4, 5}:
        raise SystemExit(
            "usage: python_lifecycle.py KIND PATH OPERATION ITERATIONS [PASSWORD]"
        )
    kind, path_text, operation, iterations_text = arguments[:4]
    password = arguments[4] if len(arguments) == 5 else None
    path = Path(path_text).resolve()
    iterations = int(iterations_text)
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    data = path.read_bytes()
    open_bytes, _, _ = openers(kind)
    opened = None
    if operation not in {"inventory", "path-inventory", "path-verify"}:
        opened = open_bytes(data, **password_options(kind, password))

    def iteration() -> dict[str, int]:
        if kind == "stream":
            return stream_iteration(path, data, operation, opened)
        return archive_iteration(kind, path, data, operation, opened, password)

    expected = iteration()
    gc.collect()
    start = perf_counter_ns()
    for _ in range(iterations):
        observed = iteration()
        if observed != expected:
            raise RuntimeError(f"metrics changed: {expected!r} != {observed!r}")
    elapsed_ns = perf_counter_ns() - start
    native_path = Path(native.__file__).resolve()
    report = {
        "kind": kind,
        "fixture": str(path),
        "operation": operation,
        "iterations": iterations,
        "input_bytes": len(data),
        "elapsed_ns": elapsed_ns,
        "average_ns": elapsed_ns // iterations,
        "python_version": sys.version.split()[0],
        "package_path": str(Path(unpackio.__file__).resolve()),
        "native_path": str(native_path),
        "native_bytes": native_path.stat().st_size,
        "native_sha256": hashlib.sha256(native_path.read_bytes()).hexdigest(),
        **expected,
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
