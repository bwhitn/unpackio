#!/usr/bin/env python3
"""Generate reproducible-content, local-only performance fixtures.

This is benchmark support, not a shipped archive-writing API. External tools
are fixture generators only; unpackio never invokes them at runtime.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import zlib


FIXED_TIME = 1_700_000_000
PASSWORD = "unpackio-performance-only"


def deterministic_payload(size: int) -> bytes:
    phrase = (
        b"unpackio measured archive lifecycle fixture; hostile input remains bounded\n"
    )
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(phrase * 64)
        output.extend(hashlib.sha256(counter.to_bytes(8, "little")).digest() * 32)
        counter += 1
    return bytes(output[:size])


def append_newc_record(output: bytearray, name: bytes, data: bytes, crc: bool) -> None:
    values = (
        1,
        0o100644,
        1000,
        1000,
        1,
        FIXED_TIME,
        len(data),
        0,
        0,
        0,
        0,
        len(name) + 1,
        sum(data) & 0xFFFFFFFF if crc else 0,
    )
    output.extend(b"070702" if crc else b"070701")
    for value in values:
        output.extend(f"{value:08x}".encode("ascii"))
    output.extend(name)
    output.append(0)
    output.extend(b"\0" * (-len(output) % 4))
    output.extend(data)
    output.extend(b"\0" * (-len(output) % 4))


def build_cpio(chunks: list[tuple[bytes, bytes]], crc: bool = True) -> bytes:
    output = bytearray()
    for name, data in chunks:
        append_newc_record(output, name, data, crc)
    append_newc_record(output, b"TRAILER!!!", b"", crc)
    return bytes(output)


def rpm_header(values: list[tuple[int, int, int, bytes]]) -> bytes:
    store = bytearray()
    indexes = bytearray()
    for tag, value_type, count, value in values:
        indexes.extend(struct.pack(">IIII", tag, value_type, len(store), count))
        store.extend(value)
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(
        ">II", len(values), len(store)
    ) + bytes(indexes) + bytes(store)


def rpm_string(tag: int, value: bytes, value_type: int = 6) -> tuple[int, int, int, bytes]:
    return tag, value_type, 1, value + b"\0"


def build_rpm(cpio: bytes) -> bytes:
    compressed = gzip.compress(cpio, compresslevel=6, mtime=0)
    main = rpm_header(
        [
            (5093, 4, 1, struct.pack(">I", 8)),
            rpm_string(1000, b"unpackio-performance"),
            rpm_string(1001, b"1.0"),
            rpm_string(1002, b"1"),
            rpm_string(1022, b"noarch"),
            rpm_string(1124, b"cpio"),
            rpm_string(1125, b"gzip"),
            rpm_string(5092, hashlib.sha256(compressed).hexdigest().encode("ascii"), 8),
            rpm_string(5097, hashlib.sha256(cpio).hexdigest().encode("ascii"), 8),
        ]
    )
    signature = rpm_header(
        [
            rpm_string(269, hashlib.sha1(main).hexdigest().encode("ascii")),  # noqa: S324
            rpm_string(273, hashlib.sha256(main).hexdigest().encode("ascii")),
        ]
    )
    lead = bytearray(96)
    lead[:4] = b"\xed\xab\xee\xdb"
    lead[4:6] = b"\x03\x00"
    lead[6:10] = struct.pack(">HH", 0, 1)
    lead[10:30] = b"unpackio-performance"
    lead[76:80] = struct.pack(">HH", 1, 5)
    lead[80:96] = b"benchmark-only!!"
    output = lead + signature
    output.extend(b"\0" * (-len(output) % 8))
    output.extend(main)
    output.extend(compressed)
    return bytes(output)


def build_tar(chunks: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in chunks:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.uid = 1000
            info.gid = 1000
            info.mtime = FIXED_TIME
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def append_ar_member(output: bytearray, name: bytes, data: bytes) -> None:
    if len(name) > 15:
        raise ValueError(f"ar member name is too long: {name!r}")
    fields = (
        (name + b"/").ljust(16),
        str(FIXED_TIME).encode("ascii").ljust(12),
        b"0".ljust(6),
        b"0".ljust(6),
        b"100644".ljust(8),
        str(len(data)).encode("ascii").ljust(10),
        b"`\n",
    )
    output.extend(b"".join(fields))
    output.extend(data)
    if len(data) % 2:
        output.extend(b"\n")


def build_deb(chunks: list[tuple[str, bytes]]) -> bytes:
    control_tar = build_tar([("control", b"Package: unpackio-performance\n")])
    data_tar = build_tar(chunks)
    control_gz = gzip.compress(control_tar, compresslevel=6, mtime=0)
    data_gz = gzip.compress(data_tar, compresslevel=6, mtime=0)
    output = bytearray(b"!<arch>\n")
    append_ar_member(output, b"debian-binary", b"2.0\n")
    append_ar_member(output, b"control.tar.gz", control_gz)
    append_ar_member(output, b"data.tar.gz", data_gz)
    return bytes(output)


def arj_header(basic: bytes) -> bytes:
    return (
        b"\x60\xea"
        + struct.pack("<H", len(basic))
        + basic
        + struct.pack("<I", zlib.crc32(basic))
        + b"\0\0"
    )


def build_arj(chunks: list[tuple[bytes, bytes]]) -> bytes:
    main = bytearray(30)
    main[0:7] = bytes((30, 11, 1, 2, 0, 0, 2))
    main.extend(b"performance.arj\0generated\0")
    output = bytearray(arj_header(bytes(main)))
    for name, data in chunks:
        local = bytearray(30)
        local[0:7] = bytes((30, 11, 1, 2, 0, 0, 0))
        local[12:16] = struct.pack("<I", len(data))
        local[16:20] = struct.pack("<I", len(data))
        local[20:24] = struct.pack("<I", zlib.crc32(data))
        local.extend(name + b"\0\0")
        output.extend(arj_header(bytes(local)))
        output.extend(data)
    output.extend(b"\x60\xea\0\0")
    return bytes(output)


def build_zip_member(name: bytes, decoded: bytes, payload: bytes, method: int) -> bytes:
    crc = zlib.crc32(decoded)
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        method,
        0,
        0x5021,
        crc,
        len(payload),
        len(decoded),
        len(name),
        0,
    )
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        0x031E,
        20,
        0,
        method,
        0,
        0x5021,
        crc,
        len(payload),
        len(decoded),
        len(name),
        0,
        0,
        0,
        0,
        0o100644 << 16,
        0,
    )
    local_record = local + name + payload
    central_record = central + name
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central_record),
        len(local_record),
        0,
    )
    return local_record + central_record + end


def run(command: list[str], *, stdout: Path | None = None) -> None:
    if stdout is None:
        subprocess.run(command, check=True)
        return
    with stdout.open("wb") as destination:
        subprocess.run(command, check=True, stdout=destination)


def tool_record(name: str) -> dict[str, str]:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"required fixture generator is unavailable: {name}")
    path = Path(executable).resolve()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    probes = (
        ([name],)
        if name == "7zz"
        else ([name, "--version"], [name, "-V"], [name, "-h"])
    )
    version = ""
    for probe in probes:
        result = subprocess.run(probe, capture_output=True, text=True, check=False)
        candidate = (result.stdout + result.stderr).strip().splitlines()
        useful = [
            line
            for line in candidate
            if not any(
                marker in line.lower()
                for marker in ("command line error", "illegal option", "usage:")
            )
        ]
        if useful:
            version = useful[0]
            break
    if not version:
        version = "no supported version flag; identify by path and sha256"
    return {"path": str(path), "sha256": digest, "version": version}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_existing(directory: Path, byte_count: int, file_count: int) -> bool:
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        if any(directory.iterdir()):
            raise RuntimeError(
                "fixture directory is nonempty but has no manifest; use a fresh directory"
            )
        return False

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        raise RuntimeError("existing fixture manifest has an unsupported schema")
    if manifest.get("generator") != "benchmarks/generate_fixtures.py":
        raise RuntimeError("existing fixture manifest names a different generator")
    if manifest.get("password") != PASSWORD:
        raise RuntimeError("existing fixture manifest has an unexpected password record")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, dict):
        raise RuntimeError("existing fixture manifest has no fixture map")

    expected_files = set(fixtures)
    actual_files = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and path.name != manifest_path.name
    }
    if actual_files != expected_files:
        raise RuntimeError("existing fixture file set does not match its manifest")
    actual_directories = {path.name for path in directory.iterdir() if path.is_dir()}
    if actual_directories != {"source"}:
        raise RuntimeError("existing fixture directory set is unexpected")

    for name, record in fixtures.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise RuntimeError("existing fixture manifest contains a non-local name")
        if not isinstance(record, dict):
            raise RuntimeError(f"existing fixture record is invalid: {name}")
        path = directory / name
        if path.stat().st_size != record.get("bytes") or sha256(path) != record.get(
            "sha256"
        ):
            raise RuntimeError(f"existing fixture does not match its manifest: {name}")

    payload = deterministic_payload(byte_count)
    source = directory / "payload.bin"
    source_record = manifest.get("source")
    if not isinstance(source_record, dict):
        raise RuntimeError("existing fixture manifest has no source record")
    if (
        source_record.get("bytes") != byte_count
        or source_record.get("sha256") != hashlib.sha256(payload).hexdigest()
        or source.read_bytes() != payload
    ):
        raise RuntimeError("existing fixture source does not match requested --bytes")

    source_dir = directory / "source"
    expected_source_names = {f"entry-{index:04}.dat" for index in range(file_count)}
    actual_source_names = {path.name for path in source_dir.iterdir() if path.is_file()}
    if actual_source_names != expected_source_names or any(
        path.is_dir() for path in source_dir.iterdir()
    ):
        raise RuntimeError("existing source split does not match requested --files")
    for index in range(file_count):
        start = len(payload) * index // file_count
        end = len(payload) * (index + 1) // file_count
        if (source_dir / f"entry-{index:04}.dat").read_bytes() != payload[start:end]:
            raise RuntimeError("existing source split bytes do not match the source payload")
    return True


def write_manifest(directory: Path, tools: dict[str, dict[str, str]], source: Path) -> None:
    fixtures = {}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "manifest.json":
            fixtures[path.name] = {"bytes": path.stat().st_size, "sha256": sha256(path)}
    manifest = {
        "schema": 1,
        "generator": "benchmarks/generate_fixtures.py",
        "source": {"bytes": source.stat().st_size, "sha256": sha256(source)},
        "password": PASSWORD,
        "tools": tools,
        "fixtures": fixtures,
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--files", type=int, default=32)
    args = parser.parse_args()
    if args.bytes <= 0 or args.files <= 0:
        raise SystemExit("--bytes and --files must be positive")

    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if validate_existing(directory, args.bytes, args.files):
        print(f"validated existing fixture directory: {directory}")
        return
    source_dir = directory / "source"
    source_dir.mkdir(exist_ok=True)
    payload = deterministic_payload(args.bytes)
    source = directory / "payload.bin"
    source.write_bytes(payload)

    chunks: list[tuple[bytes, bytes]] = []
    source_names: list[str] = []
    for index in range(args.files):
        start = len(payload) * index // args.files
        end = len(payload) * (index + 1) // args.files
        name = f"entry-{index:04}.dat".encode("ascii")
        data = payload[start:end]
        chunks.append((name, data))
        source_name = name.decode("ascii")
        source_names.append(source_name)
        (source_dir / source_name).write_bytes(data)

    tools = {name: tool_record(name) for name in ("7zz", "lz4", "zstd", "compress")}
    common_7z = [
        "7zz",
        "a",
        "-y",
        "-bd",
        "-bb0",
        "-mtm=off",
        "-mta=off",
        "-mtc=off",
    ]
    for name in (
        "solid.7z",
        "encrypted.7z",
        "zip-deflate64.zipx",
        "zip-xz.zipx",
        "zip-ppmd.zipx",
    ):
        (directory / name).unlink(missing_ok=True)
    decoder_archives = (
        ("7z-copy.7z", ("-m0=Copy",)),
        ("7z-lzma.7z", ("-m0=LZMA:d=1m",)),
        ("7z-lzma2.7z", ("-m0=LZMA2:d=1m",)),
        ("7z-delta.7z", ("-m0=Copy", "-m1=Delta:4")),
        ("7z-bcj.7z", ("-m0=Copy", "-m1=BCJ")),
        ("7z-bcj2.7z", ("-m0=BCJ2",)),
        ("7z-ppc.7z", ("-m0=Copy", "-m1=PPC")),
        ("7z-arm.7z", ("-m0=Copy", "-m1=ARM")),
        ("7z-arm64.7z", ("-m0=Copy", "-m1=ARM64")),
        ("7z-sparc.7z", ("-m0=Copy", "-m1=SPARC")),
        ("7z-deflate.7z", ("-m0=Deflate",)),
        ("7z-bzip2.7z", ("-m0=BZip2",)),
        ("7z-ppmd.7z", ("-m0=PPMd:o=6:mem=1m",)),
        ("7z-deflate64.7z", ("-m0=Deflate64",)),
        ("7z-ia64.7z", ("-m0=Copy", "-m1=IA64")),
        ("7z-arm-thumb.7z", ("-m0=Copy", "-m1=ARMT")),
        ("7z-riscv.7z", ("-m0=Copy", "-m1=RISCV")),
        ("7z-swap2.7z", ("-m0=Copy", "-m1=Swap2")),
        ("7z-swap4.7z", ("-m0=Copy", "-m1=Swap4")),
    )
    for name, _ in decoder_archives:
        (directory / name).unlink(missing_ok=True)
    for path in directory.glob("split.7z.*"):
        if path.is_file():
            path.unlink()
    subprocess.run(
        common_7z
        + ["-t7z", "-m0=lzma2", "-mx=5", "-ms=on", str(directory / "solid.7z")]
        + source_names,
        cwd=source_dir,
        check=True,
    )
    for name, methods in decoder_archives:
        subprocess.run(
            common_7z
            + ["-t7z", "-mhc=off", *methods, str(directory / name), source_names[0]],
            cwd=source_dir,
            check=True,
        )
    subprocess.run(
        common_7z
        + [
            "-t7z",
            "-m0=LZMA2:d=1m",
            "-ms=on",
            "-v8k",
            str(directory / "split.7z"),
        ]
        + source_names,
        cwd=source_dir,
        check=True,
    )
    subprocess.run(
        common_7z
        + [
            "-t7z",
            "-m0=lzma2",
            "-mx=5",
            "-ms=on",
            f"-p{PASSWORD}",
            "-mhe=on",
            str(directory / "encrypted.7z"),
        ]
        + source_names,
        cwd=source_dir,
        check=True,
    )

    import zipfile

    with zipfile.ZipFile(directory / "mixed.zipx", "w", allowZip64=True) as archive:
        methods = (
            zipfile.ZIP_STORED,
            zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2,
            zipfile.ZIP_LZMA,
        )
        for index, (name, data) in enumerate(chunks):
            info = zipfile.ZipInfo(name.decode("ascii"), (2023, 11, 14, 0, 0, 0))
            info.compress_type = methods[index % len(methods)]
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)

    first_source = source_names[0]
    for method, target in (
        ("Deflate64", "zip-deflate64.zipx"),
        ("XZ", "zip-xz.zipx"),
        ("PPMd", "zip-ppmd.zipx"),
    ):
        subprocess.run(
            common_7z
            + ["-tzip", f"-mm={method}", str(directory / target), first_source],
            cwd=source_dir,
            check=True,
        )

    cpio = build_cpio(chunks)
    (directory / "payload.cpio").write_bytes(cpio)
    (directory / "payload.rpm").write_bytes(build_rpm(cpio))
    text_chunks = [(name.decode("ascii"), data) for name, data in chunks]
    (directory / "payload.deb").write_bytes(build_deb(text_chunks))
    (directory / "payload.arj").write_bytes(build_arj(chunks))
    run(["lz4", "-q", "-f", str(source), str(directory / "payload.lz4")])
    run(["zstd", "-q", "-f", "-5", str(source), "-o", str(directory / "payload.zst")])
    compress_source = directory / "payload-for-compress"
    shutil.copyfile(source, compress_source)
    run(["compress", "-f", str(compress_source)])
    Path(f"{compress_source}.Z").replace(directory / "payload.Z")
    zstd_payload = (directory / "payload.zst").read_bytes()
    for method, target in (
        (93, "zip-zstd.zipx"),
        (20, "zip-zstd-deprecated.zipx"),
    ):
        (directory / target).write_bytes(
            build_zip_member(b"payload.bin", payload, zstd_payload, method)
        )

    # Decode the committed advanced-method evidence into local benchmark files.
    repo = Path(__file__).resolve().parents[1]
    committed = {
        "winzip-jpeg.zipx": repo
        / "crates/unpackio/tests/fixtures/method96/winzip21-method96.zipx.b64",
        "winzip-wavpack.wv": repo
        / "crates/unpackio/tests/fixtures/method97/pcm16_multiblock.wv.hex",
    }
    (directory / "winzip-jpeg.zipx").write_bytes(
        base64.b64decode(committed["winzip-jpeg.zipx"].read_text(encoding="ascii"))
    )
    wavpack_payload = bytes.fromhex(
        committed["winzip-wavpack.wv"].read_text(encoding="ascii")
    )
    wavpack_decoded = bytearray.fromhex(
        "524946462494040057415645666d7420100000000100010044ac0000885801000200100064617461e0930400"
    )
    wavpack_decoded.extend(b"\0" * (300_044 - len(wavpack_decoded)))
    wavpack_decoded.extend(
        bytes.fromhex("4c49535417000000494e464f6d6574686f6439372d6d756c7469626c6f636b00")
    )
    (directory / "winzip-wavpack.zipx").write_bytes(
        build_zip_member(
            b"multiblock.wav", bytes(wavpack_decoded), wavpack_payload, 97
        )
    )
    write_manifest(directory, tools, source)


if __name__ == "__main__":
    main()
