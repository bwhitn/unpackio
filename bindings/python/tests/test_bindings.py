from __future__ import annotations

import binascii
import importlib.metadata
import io
import pathlib
import struct
import tempfile
import threading
import time
import unittest
import warnings
import zipfile

import unpackio
import unpackio._native as native


SIGNATURE = b"7z\xbc\xaf\x27\x1c"
HELLO_DOT_Z = bytes.fromhex(
    "1f9d9068cab061f306441d3769f08018f3a60d1c3965e6cc5100"
)
AES256_AE2_ARCHIVE = bytes.fromhex(
    "504b03043300010063000000215000000000310000001500000007000b00"
    "6165732e7478740199070002004145030000030303030303030303030303"
    "030303030c6c46d804fc400134e536bc271c2f10fbb194bacc2cc95c9dbb"
    "e2612140e756ea504b01023f033300010063000000215000000000310000"
    "001500000007000b000000000000000000a481000000006165732e747874"
    "0199070002004145030000504b0506000000000100010040000000610000"
    "000000"
)


def raw_lz4_frame(payload: bytes) -> bytes:
    if len(payload) > 64 * 1024:
        raise ValueError("test LZ4 payload exceeds one block")
    block = b""
    if payload:
        block_header = (len(payload) | (1 << 31)).to_bytes(4, "little")
        block = block_header + payload
    return b"\x04\x22\x4d\x18\x60\x40\x82" + block + b"\0\0\0\0"


def raw_zstandard_frame(payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("test Zstandard payload exceeds one-byte content size")
    block_header = ((len(payload) << 3) | 1).to_bytes(4, "little")[:3]
    return b"\x28\xb5\x2f\xfd\x20" + bytes((len(payload),)) + block_header + payload


def encode_uint(value: int) -> bytes:
    if value < 0 or value > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("fixture integer is outside u64")
    for extra in range(9):
        if extra == 8 or value < (1 << (7 * (extra + 1))):
            prefix = (0xFF << (8 - extra)) & 0xFF
            high_mask = 0 if extra == 8 else (0x7F >> extra)
            first = prefix | ((value >> (8 * extra)) & high_mask)
            low = bytes((value >> (8 * index)) & 0xFF for index in range(extra))
            return bytes((first,)) + low
    raise AssertionError("unreachable fixture integer encoding")


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFF_FFFF


def zip_archive(entries: list[tuple[str, bytes]], compression: int) -> bytes:
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            for name, payload in entries:
                archive.writestr(name, payload)
    return output.getvalue()


def zip_metadata_archive() -> bytes:
    output = io.BytesIO()
    entries = [("same.txt", b"first"), ("same.txt", b"second"), ("empty", b"")]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.comment = b"archive comment"
            for index, (name, payload) in enumerate(entries):
                info = zipfile.ZipInfo(name, date_time=(2024, 7, 21, 12, 34, 56))
                info.comment = f"entry {index}".encode()
                info.extra = b"\xfe\xca\x02\x00ok"
                info.create_system = 3
                info.internal_attr = index
                info.external_attr = (0o100640 + index) << 16
                archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


def zipcrypto_archive(name: bytes, payload: bytes, password: bytes) -> bytes:
    checksum = crc32(payload)
    key0 = 0x1234_5678
    key1 = 0x2345_6789
    key2 = 0x3456_7890

    def crc_byte(value: int, byte: int) -> int:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB8_8320 if value & 1 else 0)
        return value & 0xFFFF_FFFF

    def update(byte: int) -> None:
        nonlocal key0, key1, key2
        key0 = crc_byte(key0, byte)
        key1 = ((key1 + (key0 & 0xFF)) * 134_775_813 + 1) & 0xFFFF_FFFF
        key2 = crc_byte(key2, key1 >> 24)

    for byte in password:
        update(byte)

    def encrypt(byte: int) -> int:
        temporary = key2 | 2
        mask = ((temporary * (temporary ^ 1)) >> 8) & 0xFF
        encrypted = byte ^ mask
        update(byte)
        return encrypted

    encryption_header = bytearray(12)
    encryption_header[-1] = checksum >> 24
    encrypted = bytes(encrypt(byte) for byte in encryption_header + payload)
    flags = 1
    version = 20
    modified_time = 0
    modified_date = 0x5021
    local = struct.pack(
        "<I5H3I2H",
        0x0403_4B50,
        version,
        flags,
        0,
        modified_time,
        modified_date,
        checksum,
        len(encrypted),
        len(payload),
        len(name),
        0,
    ) + name + encrypted
    central = struct.pack(
        "<I6H3I5H2I",
        0x0201_4B50,
        (3 << 8) | version,
        version,
        flags,
        0,
        modified_time,
        modified_date,
        checksum,
        len(encrypted),
        len(payload),
        len(name),
        0,
        0,
        0,
        0,
        0o100644 << 16,
        0,
    ) + name
    comment = b"ALES encrypted fixture"
    end = struct.pack(
        "<I4H2IH",
        0x0605_4B50,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        len(comment),
    ) + comment
    return local + central + end


def rpm_header(entries: list[tuple[int, int, int, bytes]]) -> bytes:
    store = bytearray()
    indices = bytearray()
    for tag, value_type, count, value in entries:
        alignment = {3: 2, 4: 4, 5: 8}.get(value_type, 1)
        store += b"\0" * ((alignment - len(store) % alignment) % alignment)
        indices += struct.pack(">IIII", tag, value_type, len(store), count)
        store += value
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(
        ">II", len(entries), len(store)
    ) + indices + store


def rpm_string(tag: int, value: bytes) -> tuple[int, int, int, bytes]:
    return tag, 6, 1, value + b"\0"


def rpm_int16(tag: int, values: list[int]) -> tuple[int, int, int, bytes]:
    return tag, 3, len(values), b"".join(struct.pack(">H", value) for value in values)


def rpm_int32(tag: int, values: list[int]) -> tuple[int, int, int, bytes]:
    return tag, 4, len(values), b"".join(struct.pack(">I", value) for value in values)


def rpm_strings(tag: int, values: list[bytes], value_type: int = 8) -> tuple[int, int, int, bytes]:
    return tag, value_type, len(values), b"".join(value + b"\0" for value in values)


def cpio_record(
    magic: bytes,
    name: bytes,
    data: bytes,
    mode: int,
    checksum: int,
) -> bytes:
    fields = (
        1,
        mode,
        1000,
        1000,
        1,
        1_700_000_000,
        len(data),
        0,
        0,
        0,
        0,
        len(name) + 1,
        checksum,
    )
    output = bytearray(magic + b"".join(f"{value:08x}".encode() for value in fields))
    output += name + b"\0"
    output += b"\0" * ((4 - len(output) % 4) % 4)
    output += data
    output += b"\0" * ((4 - len(output) % 4) % 4)
    return bytes(output)


def cpio_archive() -> bytes:
    payload = bytearray()
    payload += cpio_record(b"070702", b"./same.txt", b"first", 0o100644, sum(b"first"))
    payload += cpio_record(b"070701", b"./same.txt", b"second", 0o100600, 0)
    payload += cpio_record(b"070701", b"./empty", b"", 0o100644, 0)
    payload += cpio_record(b"070701", b"TRAILER!!!", b"", 0, 0)
    return bytes(payload)


def rpm_archive() -> bytes:
    payload = cpio_archive()

    lead = bytearray(96)
    lead[:4] = b"\xed\xab\xee\xdb"
    lead[4:6] = b"\x03\x00"
    lead[6:10] = struct.pack(">HH", 0, 1)
    lead[10:17] = b"fixture"
    lead[76:80] = struct.pack(">HH", 1, 5)
    lead[80:96] = bytes(range(16))
    signature = rpm_header([rpm_int32(1007, [11])])
    main = rpm_header(
        [
            rpm_string(1000, b"fixture"),
            rpm_string(1001, b"1.0"),
            rpm_string(1002, b"1"),
            rpm_strings(1004, [b"fixture summary", b"ignored locale"], 9),
            rpm_int32(1006, [1_700_000_000]),
            rpm_string(1022, b"noarch"),
            rpm_strings(1049, [b"python", b"libc"]),
            rpm_int32(1048, [8, 12]),
            rpm_strings(1050, [b"3.9", b"2.34"]),
            rpm_strings(5000, [b"./same.txt", b"./same.txt", b"./empty"]),
            rpm_int16(1030, [0o100644, 0o100600, 0o100644]),
            rpm_string(5012, b"https://bugs.example.invalid"),
            rpm_string(1124, b"cpio"),
            rpm_string(1125, b"none"),
            rpm_string(6000, b"unknown-tag"),
        ]
    )
    output = lead + signature
    output += b"\0" * ((8 - len(output) % 8) % 8)
    output += main + payload
    return bytes(output)


def tar_record(
    name: bytes,
    data: bytes,
    type_flag: bytes = b"0",
    link_name: bytes = b"",
) -> bytes:
    if len(name) > 100 or len(link_name) > 100 or len(type_flag) != 1:
        raise ValueError("test tar field does not fit")
    header = bytearray(512)
    header[: len(name)] = name

    def octal(offset: int, width: int, value: int) -> None:
        encoded = f"{value:0{width - 1}o}".encode() + b"\0"
        if len(encoded) != width:
            raise ValueError("test tar number does not fit")
        header[offset : offset + width] = encoded

    octal(100, 8, 0o644)
    octal(108, 8, 1000)
    octal(116, 8, 1000)
    octal(124, 12, len(data))
    octal(136, 12, 1_700_000_000)
    header[148:156] = b" " * 8
    header[156:157] = type_flag
    header[157 : 157 + len(link_name)] = link_name
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode()
    output = header + data
    output += b"\0" * ((512 - len(output) % 512) % 512)
    return bytes(output)


def tar_archive(entries: list[tuple[bytes, bytes, bytes, bytes]]) -> bytes:
    output = bytearray()
    for name, data, type_flag, link_name in entries:
        output += tar_record(name, data, type_flag, link_name)
    output += b"\0" * 1024
    return bytes(output)


def ar_member(name: bytes, data: bytes) -> bytes:
    if not name or len(name) > 15:
        raise ValueError("test ar member name does not fit")
    header = bytearray(b" " * 60)
    header[: len(name)] = name
    header[len(name)] = ord("/")
    header[16:28] = f"{1_700_000_000:<12}".encode()
    header[28:34] = f"{0:<6}".encode()
    header[34:40] = f"{0:<6}".encode()
    header[40:48] = f"{0o100644:<8o}".encode()
    header[48:58] = f"{len(data):<10}".encode()
    header[58:60] = b"`\n"
    return bytes(header) + data + (b"\n" if len(data) % 2 else b"")


def deb_archive() -> bytes:
    control = tar_archive([(b"control", b"Package: fixture\n", b"0", b"")])
    data = tar_archive(
        [
            (b"usr/bin/tool", b"payload", b"0", b""),
            (b"usr/bin/link", b"", b"2", b"tool"),
            (b"empty", b"", b"0", b""),
        ]
    )
    return (
        b"!<arch>\n"
        + ar_member(b"debian-binary", b"2.0\n")
        + ar_member(b"control.tar", control)
        + ar_member(b"data.tar", data)
    )


def arj_header(basic: bytes) -> bytes:
    if len(basic) > 0xFFFF:
        raise ValueError("test ARJ header does not fit")
    return (
        b"\x60\xea"
        + len(basic).to_bytes(2, "little")
        + basic
        + crc32(basic).to_bytes(4, "little")
        + b"\0\0"
    )


def arj_archive(
    payload: bytes = b"hello ARJ",
    *,
    flags: int = 0,
    method: int = 0,
    member_crc: int | None = None,
) -> bytes:
    main = bytearray(30)
    main[0] = 30
    main[1] = 11
    main[2] = 1
    main[3] = 2
    main[6] = 2
    main += b"fixture.arj\0generated\0"

    local = bytearray(30)
    local[0] = 30
    local[1] = 11
    local[2] = 1
    local[3] = 2
    local[4] = flags
    local[5] = method
    local[6] = 0
    local[12:16] = len(payload).to_bytes(4, "little")
    local[16:20] = len(payload).to_bytes(4, "little")
    checksum = crc32(payload) if member_crc is None else member_crc
    local[20:24] = checksum.to_bytes(4, "little")
    local += b"hello.txt\0\0"
    return arj_header(bytes(main)) + arj_header(bytes(local)) + payload + b"\x60\xea\0\0"


def copy_archive(payload: bytes, raw_name: list[int] | None = None) -> bytes:
    name_units = raw_name if raw_name is not None else [ord(character) for character in "member.bin"]

    size = len(payload)
    streams = bytearray((0x06,))
    streams += encode_uint(0)
    streams += encode_uint(1)
    streams.append(0x09)
    streams += encode_uint(size)
    streams.append(0x00)
    streams += bytes((0x07, 0x0B))
    streams += encode_uint(1)
    streams.append(0)
    streams += encode_uint(1)
    streams += bytes((1, 0))
    streams.append(0x0C)
    streams += encode_uint(size)
    streams += bytes((0x0A, 1))
    streams += crc32(payload).to_bytes(4, "little")
    streams += bytes((0x00, 0x00))

    name_property = bytearray((0,))
    for unit in name_units:
        name_property += unit.to_bytes(2, "little")
    name_property += b"\0\0"
    files = bytearray()
    files += encode_uint(1)
    files.append(0x11)
    files += encode_uint(len(name_property))
    files += name_property
    files.append(0)

    next_header = bytearray((0x01, 0x04))
    next_header += streams
    next_header.append(0x05)
    next_header += files
    next_header.append(0)

    start_fields = bytearray()
    start_fields += size.to_bytes(8, "little")
    start_fields += len(next_header).to_bytes(8, "little")
    start_fields += crc32(next_header).to_bytes(4, "little")
    return (
        SIGNATURE
        + bytes((0, 4))
        + crc32(start_fields).to_bytes(4, "little")
        + start_fields
        + payload
        + next_header
    )


def bit_vector(values: list[bool]) -> bytes:
    output = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            output[index // 8] |= 0x80 >> (index % 8)
    return bytes(output)


def solid_copy_archive(
    entries: list[tuple[str, bytes | None]],
    *,
    corrupt_stream_index: int | None = None,
) -> bytes:
    streamed = [payload for _, payload in entries if payload is not None]
    if len(streamed) < 2:
        raise ValueError("solid fixture requires at least two streamed entries")
    payload = b"".join(streamed)

    streams = bytearray((0x06,))
    streams += encode_uint(0)
    streams += encode_uint(1)
    streams.append(0x09)
    streams += encode_uint(len(payload))
    streams += bytes((0x0A, 1))
    streams += crc32(payload).to_bytes(4, "little")
    streams += bytes((0x00, 0x07, 0x0B))
    streams += encode_uint(1)
    streams.append(0)
    streams += encode_uint(1)
    streams += bytes((1, 0))
    streams.append(0x0C)
    streams += encode_uint(len(payload))
    streams += bytes((0x0A, 1))
    streams += crc32(payload).to_bytes(4, "little")
    streams.append(0)
    streams += bytes((0x08, 0x0D))
    streams += encode_uint(len(streamed))
    streams.append(0x09)
    for member in streamed[:-1]:
        streams += encode_uint(len(member))
    streams += bytes((0x0A, 1))
    for index, member in enumerate(streamed):
        checksum = crc32(member)
        if index == corrupt_stream_index:
            checksum ^= 1
        streams += checksum.to_bytes(4, "little")
    streams += bytes((0, 0))

    files = bytearray()
    files += encode_uint(len(entries))
    empty_streams = [member is None for _, member in entries]
    if any(empty_streams):
        empty_stream_vector = bit_vector(empty_streams)
        files.append(0x0E)
        files += encode_uint(len(empty_stream_vector))
        files += empty_stream_vector
        empty_file_vector = bit_vector([True for empty in empty_streams if empty])
        files.append(0x0F)
        files += encode_uint(len(empty_file_vector))
        files += empty_file_vector
    name_property = bytearray((0,))
    for name, _ in entries:
        for unit in name.encode("utf-16-le"):
            name_property.append(unit)
        name_property += b"\0\0"
    files.append(0x11)
    files += encode_uint(len(name_property))
    files += name_property
    files.append(0)

    next_header = bytearray((0x01, 0x04))
    next_header += streams
    next_header.append(0x05)
    next_header += files
    next_header.append(0)

    start_fields = bytearray()
    start_fields += len(payload).to_bytes(8, "little")
    start_fields += len(next_header).to_bytes(8, "little")
    start_fields += crc32(next_header).to_bytes(4, "little")
    return (
        SIGNATURE
        + bytes((0, 4))
        + crc32(start_fields).to_bytes(4, "little")
        + start_fields
        + payload
        + next_header
    )


class CollectEntrySink:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []
        self.entries: dict[int, bytearray] = {}
        self.chunks: list[int] = []

    def begin_entry(self, entry: unpackio.Entry, size: int) -> None:
        self.events.append(("begin", entry.index, entry.name, size))
        self.entries[entry.index] = bytearray()

    def write_entry(self, index: int, chunk: bytes) -> None:
        self.events.append(("write", index, len(chunk)))
        self.entries[index].extend(chunk)
        self.chunks.append(len(chunk))

    def finish_entry(self, index: int) -> None:
        self.events.append(("finish", index))


class BindingTests(unittest.TestCase):
    def test_distribution_and_native_module_names(self) -> None:
        distribution = importlib.metadata.distribution("unpackio")
        self.assertEqual(distribution.version, "0.1.0")
        self.assertFalse(distribution.requires)
        self.assertEqual(len(distribution.entry_points), 0)
        self.assertEqual(distribution.metadata["License-Expression"], "MIT")
        self.assertEqual(
            set(distribution.metadata.get_all("License-File") or ()),
            {
                "LICENSE",
                "LICENSES/Apache-2.0.txt",
                "LICENSES/BSD-3-Clause-bodgit-sevenzip.txt",
                "LICENSES/BSD-3-Clause-netbsd-zopen.txt",
                "LICENSES/BSD-3-Clause-ulikunitz-xz.txt",
                "LICENSES/MIT-rpmfile.txt",
                "LICENSES/MIT-stangelandcl-ppmd.txt",
                "LICENSES/README.md",
                "NOTICE",
            },
        )
        self.assertEqual(unpackio.__version__, "0.1.0")
        self.assertEqual(native.__name__, "unpackio._native")
        self.assertEqual(unpackio.Archive.__module__, "unpackio._native")
        self.assertEqual(unpackio.CompressedStream.__module__, "unpackio._native")
        self.assertEqual(unpackio.StreamInfo.__module__, "unpackio._native")
        self.assertEqual(unpackio.ZipArchive.__module__, "unpackio._native")
        self.assertEqual(unpackio.ZipEntry.__module__, "unpackio._native")
        self.assertEqual(unpackio.RpmArchive.__module__, "unpackio._native")
        self.assertEqual(unpackio.RpmEntry.__module__, "unpackio._native")
        self.assertEqual(unpackio.CpioArchive.__module__, "unpackio._native")
        self.assertEqual(unpackio.CpioEntry.__module__, "unpackio._native")
        self.assertEqual(unpackio.DebArchive.__module__, "unpackio._native")
        self.assertEqual(unpackio.DebMember.__module__, "unpackio._native")
        self.assertEqual(unpackio.DebEntry.__module__, "unpackio._native")
        self.assertEqual(unpackio.ArjArchive.__module__, "unpackio._native")
        self.assertEqual(unpackio.ArjEntry.__module__, "unpackio._native")
        self.assertEqual(unpackio.FormatError.__module__, "unpackio._native")
        self.assertEqual(
            native.IMPLEMENTATION_STATUS,
            "multi-format-unpack-readers-pre-alpha",
        )
        self.assertGreater(native.DEFAULT_MAX_WORK_UNITS, 0)

    def test_zip_metadata_codecs_batch_integrity_and_callbacks(self) -> None:
        cases = [
            (zipfile.ZIP_STORED, "stored"),
            (zipfile.ZIP_DEFLATED, "deflate"),
            (zipfile.ZIP_BZIP2, "bzip2"),
            (zipfile.ZIP_LZMA, "lzma"),
        ]
        for compression, method in cases:
            with self.subTest(method=method):
                encoded = zip_archive(
                    [
                        ("same.txt", b"first"),
                        ("same.txt", b"second"),
                        ("empty", b""),
                    ],
                    compression,
                )
                archive = unpackio.open_zip_bytes(encoded)
                self.assertIsInstance(archive, unpackio.ZipArchive)
                self.assertEqual(len(archive), 3)
                self.assertEqual([entry.name for entry in archive.entries()], [
                    "same.txt",
                    "same.txt",
                    "empty",
                ])
                self.assertEqual(archive.entry(0).raw_name, b"same.txt")
                self.assertEqual(archive.entry(0).compression_method, method)
                self.assertTrue(archive.entry(0).is_safe_path)

                writer = io.BytesIO()
                self.assertEqual(archive.extract_entry_to(1, writer), 6)
                self.assertEqual(writer.getvalue(), b"second")

                sink = CollectEntrySink()
                self.assertEqual(archive.extract_entries_to(sink), 11)
                self.assertEqual(bytes(sink.entries[0]), b"first")
                self.assertEqual(bytes(sink.entries[1]), b"second")
                self.assertEqual(bytes(sink.entries[2]), b"")
                self.assertEqual(
                    [event[0] for event in sink.events if event[0] in ("begin", "finish")],
                    ["begin", "finish", "begin", "finish", "begin", "finish"],
                )

        unsafe = unpackio.open_zip_bytes(zip_archive([("../escape", b"x")], zipfile.ZIP_STORED))
        self.assertFalse(unsafe.entry(0).is_safe_path)
        self.assertEqual(unsafe.entry(0).unsafe_path_reason, "traversal")

        class MarkerError(Exception):
            pass

        archive = unpackio.open_zip_bytes(
            zip_archive([("callback", b"callback data")], zipfile.ZIP_STORED)
        )

        def fail(_chunk: bytes) -> None:
            raise MarkerError("ZIP callback marker")

        with self.assertRaisesRegex(MarkerError, "ZIP callback marker"):
            archive.stream_entry(0, fail)

        encoded = bytearray(
            zip_archive([("integrity", b"integrity-data-unique")], zipfile.ZIP_STORED)
        )
        offset = encoded.find(b"integrity-data-unique")
        self.assertGreaterEqual(offset, 0)
        encoded[offset] ^= 1
        corrupt = unpackio.open_zip_bytes(bytes(encoded))
        with self.assertRaises(unpackio.ChecksumError) as caught:
            corrupt.extract_entry_to(0, io.BytesIO())
        self.assertEqual(caught.exception.format, "zip")

        limited = unpackio.Limits(max_entry_output_bytes=2)
        with self.assertRaises(unpackio.LimitExceededError):
            unpackio.open_zip_bytes(
                zip_archive([("large", b"three")], zipfile.ZIP_STORED),
                limits=limited,
            )

    def test_rpm_headers_metadata_batch_integrity_and_callbacks(self) -> None:
        encoded = rpm_archive()
        archive = unpackio.open_rpm_bytes(encoded)
        self.assertIsInstance(archive, unpackio.RpmArchive)
        self.assertEqual(archive.payload_compression, "none")
        self.assertEqual(archive.lead_name, b"fixture")
        self.assertEqual(archive.lead_version, (3, 0))
        self.assertEqual(archive.lead_package_type, 0)
        self.assertEqual(archive.lead_architecture, 1)
        self.assertEqual(archive.lead_operating_system, 1)
        self.assertEqual(archive.lead_signature_type, 5)
        self.assertEqual(archive.lead_reserved, bytes(range(16)))
        self.assertEqual(len(archive), 3)
        self.assertEqual([entry.raw_name for entry in archive.entries()], [
            b"./same.txt",
            b"./same.txt",
            b"./empty",
        ])
        self.assertEqual(archive.entry(0).permissions, 0o644)
        self.assertEqual(archive.entry(0).checksum, sum(b"first"))
        self.assertEqual(archive.header.value(1000), b"fixture")
        self.assertEqual(archive.header.as_dict()[1125], b"none")
        named = archive.header.as_named_dict()
        self.assertEqual(named["name"], b"fixture")
        self.assertEqual(named["summary"], b"fixture summary")
        self.assertEqual(named["buildtime"], 1_700_000_000)
        self.assertEqual(named["filemodes"], [0o100644, 0o100600, 0o100644])
        self.assertEqual(named["bugurl"], b"https://bugs.example.invalid")
        self.assertEqual(named[6000], b"unknown-tag")
        self.assertEqual(
            archive.signature_header.as_named_dict(signature=True)["payloadsize"],
            11,
        )

        writer = io.BytesIO()
        self.assertEqual(archive.extract_entry_to(1, writer), 6)
        self.assertEqual(writer.getvalue(), b"second")
        sink = CollectEntrySink()
        self.assertEqual(archive.extract_entries_to(sink), 11)
        self.assertEqual(bytes(sink.entries[0]), b"first")
        self.assertEqual(bytes(sink.entries[1]), b"second")
        self.assertEqual(bytes(sink.entries[2]), b"")

        class MarkerError(Exception):
            pass

        def fail(_chunk: bytes) -> None:
            raise MarkerError("RPM callback marker")

        with self.assertRaisesRegex(MarkerError, "RPM callback marker"):
            archive.stream_entry(0, fail)

        corrupt = bytearray(encoded)
        offset = corrupt.find(b"first")
        self.assertGreaterEqual(offset, 0)
        corrupt[offset] ^= 1
        with self.assertRaises(unpackio.ChecksumError) as caught:
            unpackio.open_rpm_bytes(bytes(corrupt))
        self.assertEqual(caught.exception.format, "rpm")

        with self.assertRaises(unpackio.LimitExceededError):
            unpackio.open_rpm_bytes(encoded, limits=unpackio.Limits(max_files=2))

    def test_cpio_layout_metadata_batch_integrity_and_callbacks(self) -> None:
        encoded = cpio_archive()
        archive = unpackio.open_cpio_bytes(encoded)
        self.assertIsInstance(archive, unpackio.CpioArchive)
        self.assertEqual(archive.format, "mixed")
        self.assertEqual(len(archive), 3)
        self.assertEqual(
            [entry.raw_name for entry in archive.entries()],
            [b"./same.txt", b"./same.txt", b"./empty"],
        )
        self.assertEqual(archive.entry(0).format, "crc_newc")
        self.assertEqual(archive.entry(0).permissions, 0o644)
        self.assertEqual(archive.entry(0).checksum, sum(b"first"))

        writer = io.BytesIO()
        self.assertEqual(archive.extract_entry_to(1, writer), 6)
        self.assertEqual(writer.getvalue(), b"second")
        sink = CollectEntrySink()
        self.assertEqual(archive.extract_entries_to(sink), 11)
        self.assertEqual(bytes(sink.entries[0]), b"first")
        self.assertEqual(bytes(sink.entries[1]), b"second")
        self.assertEqual(bytes(sink.entries[2]), b"")

        class MarkerError(Exception):
            pass

        marker = MarkerError("CPIO callback marker")

        def fail(_chunk: bytes) -> None:
            raise marker

        with self.assertRaises(MarkerError) as callback:
            archive.stream_entry(0, fail)
        self.assertIs(callback.exception, marker)

        corrupt = bytearray(encoded)
        payload_offset = corrupt.find(b"first")
        self.assertGreaterEqual(payload_offset, 0)
        corrupt[payload_offset] ^= 1
        with self.assertRaises(unpackio.ChecksumError) as checksum:
            unpackio.open_cpio_bytes(bytes(corrupt))
        self.assertEqual(checksum.exception.format, "cpio")

        cancelled = unpackio.CancellationToken()
        cancelled.cancel()
        with self.assertRaises(unpackio.CancelledError):
            archive.verify(cancellation=cancelled)
        with self.assertRaises(unpackio.LimitExceededError):
            unpackio.open_cpio_bytes(
                encoded,
                limits=unpackio.Limits(max_files=2),
            )

    def test_debian_outer_inner_metadata_integrity_and_callbacks(self) -> None:
        encoded = deb_archive()
        archive = unpackio.open_deb_bytes(encoded)
        self.assertIsInstance(archive, unpackio.DebArchive)
        self.assertEqual(len(archive), 4)
        self.assertEqual(
            [member.kind for member in archive.members()],
            ["debian_binary", "control_archive", "data_archive"],
        )
        self.assertEqual(archive.member(1).compression, "none")
        self.assertEqual(
            [(entry.section, entry.raw_name) for entry in archive.entries()],
            [
                ("control", b"control"),
                ("data", b"usr/bin/tool"),
                ("data", b"usr/bin/link"),
                ("data", b"empty"),
            ],
        )
        self.assertEqual(archive.entry(2).kind, "symlink")
        self.assertEqual(archive.entry(2).raw_link_name, b"tool")

        writer = io.BytesIO()
        self.assertEqual(archive.extract_entry_to(1, writer), 7)
        self.assertEqual(writer.getvalue(), b"payload")
        outer = io.BytesIO()
        self.assertEqual(archive.extract_member_to(0, outer), 4)
        self.assertEqual(outer.getvalue(), b"2.0\n")
        sink = CollectEntrySink()
        self.assertEqual(archive.extract_entries_to(sink), 24)
        self.assertEqual(bytes(sink.entries[0]), b"Package: fixture\n")
        self.assertEqual(bytes(sink.entries[1]), b"payload")
        self.assertEqual(bytes(sink.entries[2]), b"")
        self.assertEqual(bytes(sink.entries[3]), b"")

        class MarkerError(Exception):
            pass

        marker = MarkerError("Debian callback marker")

        def fail(_chunk: bytes) -> None:
            raise marker

        with self.assertRaises(MarkerError) as callback:
            archive.stream_entry(1, fail)
        self.assertIs(callback.exception, marker)

        corrupt = bytearray(encoded)
        magic = corrupt.find(b"ustar\0")
        self.assertGreaterEqual(magic, 257)
        corrupt[magic - 257] ^= 1
        with self.assertRaises(unpackio.ChecksumError) as checksum:
            unpackio.open_deb_bytes(bytes(corrupt))
        self.assertEqual(checksum.exception.format, "deb")

        with self.assertRaises(unpackio.LimitExceededError):
            unpackio.open_deb_bytes(
                encoded,
                limits=unpackio.Limits(max_files=3),
            )

    def test_arj_metadata_crc_password_limits_and_callbacks(self) -> None:
        encoded = arj_archive()
        archive = unpackio.open_arj_bytes(encoded)
        self.assertIsInstance(archive, unpackio.ArjArchive)
        self.assertEqual(archive.raw_name, b"fixture.arj")
        self.assertEqual(archive.raw_comment, b"generated")
        self.assertEqual(archive.sfx_offset, 0)
        self.assertEqual(len(archive), 1)
        entry = archive.entry(0)
        self.assertEqual(entry.raw_name, b"hello.txt")
        self.assertEqual(entry.compression_method, "stored")
        self.assertEqual(entry.compression_method_id, 0)
        self.assertEqual(entry.crc32, crc32(b"hello ARJ"))

        writer = io.BytesIO()
        self.assertEqual(archive.extract_entry_to(0, writer), 9)
        self.assertEqual(writer.getvalue(), b"hello ARJ")
        sink = CollectEntrySink()
        self.assertEqual(archive.extract_entries_to(sink), 9)
        self.assertEqual(bytes(sink.entries[0]), b"hello ARJ")

        class MarkerError(Exception):
            pass

        marker = MarkerError("ARJ callback marker")

        def fail(_chunk: bytes) -> None:
            raise marker

        with self.assertRaises(MarkerError) as callback:
            archive.stream_entry(0, fail)
        self.assertIs(callback.exception, marker)

        corrupt = bytearray(encoded)
        payload_offset = corrupt.find(b"hello ARJ")
        self.assertGreaterEqual(payload_offset, 0)
        corrupt[payload_offset] ^= 1
        corrupt_archive = unpackio.open_arj_bytes(bytes(corrupt))
        corrupt_output = io.BytesIO()
        with self.assertRaises(unpackio.ChecksumError) as checksum:
            corrupt_archive.extract_entry_to(0, corrupt_output)
        self.assertEqual(checksum.exception.format, "arj")
        self.assertEqual(corrupt_output.getvalue(), b"")

        encrypted = unpackio.open_arj_bytes(arj_archive(flags=1))
        self.assertTrue(encrypted.entry(0).is_encrypted)
        with self.assertRaises(unpackio.PasswordRequiredError):
            encrypted.extract_entry_to(0, io.BytesIO())

        with self.assertRaises(unpackio.LimitExceededError):
            unpackio.open_arj_bytes(
                encoded,
                limits=unpackio.Limits(max_entry_output_bytes=8),
            )

    def test_cpio_debian_and_arj_path_opening(self) -> None:
        fixtures = [
            ("payload.cpio", cpio_archive(), unpackio.open_cpio_path, b"first"),
            ("package.deb", deb_archive(), unpackio.open_deb_path, b"Package: fixture\n"),
            ("archive.arj", arj_archive(), unpackio.open_arj_path, b"hello ARJ"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name, encoded, opener, expected in fixtures:
                path = root / name
                path.write_bytes(encoded)
                archive = opener(path)
                output = io.BytesIO()
                self.assertEqual(archive.extract_entry_to(0, output), len(expected))
                self.assertEqual(output.getvalue(), expected)
                archive.verify()

    def test_ales_zip_data_contract(self) -> None:
        encoded = zip_metadata_archive()
        with zipfile.ZipFile(io.BytesIO(encoded)) as reference_archive:
            reference_entries = reference_archive.infolist()
            reference_comment = reference_archive.comment
        archive = unpackio.open_zip_bytes(encoded)
        self.assertEqual(archive.comment, reference_comment)
        self.assertEqual(len(archive), 3)
        first, second, empty = archive.entries()
        reference_first = reference_entries[0]
        self.assertEqual([entry.name for entry in archive.entries()], [
            "same.txt",
            "same.txt",
            "empty",
        ])
        self.assertEqual(first.name, reference_first.filename)
        self.assertEqual(first.raw_comment, reference_first.comment)
        self.assertEqual(first.extra_fields, reference_first.extra)
        self.assertEqual(first.size, reference_first.file_size)
        self.assertEqual(first.compressed_size, reference_first.compress_size)
        self.assertEqual(first.crc32, reference_first.CRC)
        self.assertEqual(first.modified, reference_first.date_time)
        self.assertEqual(first.compression_method_id, reference_first.compress_type)
        self.assertEqual(first.flags, reference_first.flag_bits)
        self.assertEqual(first.version_made_by >> 8, reference_first.create_system)
        self.assertEqual(first.version_made_by & 0xFF, reference_first.create_version)
        self.assertEqual(first.version_needed & 0xFF, reference_first.extract_version)
        self.assertEqual(first.local_header_offset, reference_first.header_offset)
        self.assertEqual(first.internal_attributes, reference_first.internal_attr)
        self.assertEqual(first.external_attributes, reference_first.external_attr)
        self.assertEqual(first.encryption, "none")
        self.assertEqual(first.is_directory, reference_first.is_dir())

        def extract(selected_archive: unpackio.ZipArchive, index: int) -> bytes:
            output = io.BytesIO()
            selected_archive.extract_entry_to(index, output)
            return output.getvalue()

        self.assertEqual(extract(archive, first.index), b"first")
        self.assertEqual(extract(archive, second.index), b"second")
        self.assertEqual(extract(archive, empty.index), b"")
        reader = io.BytesIO(extract(archive, first.index))
        self.assertEqual(reader.read(1), b"f")
        self.assertEqual(reader.read(), b"irst")

        encrypted = zipcrypto_archive(b"secret.txt", b"secret bytes", b"infected")
        encrypted_archive = unpackio.open_zip_bytes(encrypted)
        self.assertEqual(encrypted_archive.entry(0).encryption, "zipcrypto")
        with self.assertRaises(unpackio.PasswordRequiredError):
            extract(encrypted_archive, 0)
        wrong_archive = unpackio.open_zip_bytes(encrypted, password=b"wrong")
        with self.assertRaises(unpackio.WrongPasswordOrCorruptError):
            extract(wrong_archive, 0)
        password_archive = unpackio.open_zip_bytes(encrypted, password=b"infected")
        self.assertEqual(extract(password_archive, 0), b"secret bytes")

        aes_archive = unpackio.open_zip_bytes(
            AES256_AE2_ARCHIVE,
            password=b"correct horse battery staple",
        )
        aes_entry = aes_archive.entry(0)
        self.assertIsNotNone(aes_entry)
        self.assertEqual(aes_entry.encryption, "winzip_aes")
        self.assertEqual(aes_entry.aes_key_bits, 256)
        self.assertEqual(extract(aes_archive, 0), b"authenticated payload")
        wrong_aes = unpackio.open_zip_bytes(AES256_AE2_ARCHIVE, password=b"wrong")
        with self.assertRaises(unpackio.WrongPasswordOrCorruptError):
            extract(wrong_aes, 0)

        corrupt = bytearray(
            zip_archive([("bad.txt", b"distinct corruption payload")], zipfile.ZIP_STORED)
        )
        payload_offset = corrupt.find(b"distinct corruption payload")
        self.assertGreaterEqual(payload_offset, 0)
        corrupt[payload_offset] ^= 1
        corrupt_archive = unpackio.open_zip_bytes(bytes(corrupt))
        with self.assertRaises(unpackio.ChecksumError):
            extract(corrupt_archive, 0)

    def test_ales_rpm_data_contract(self) -> None:
        encoded = rpm_archive()
        archive = unpackio.open_rpm_bytes(encoded)
        signature = archive.signature_header.as_named_dict(signature=True)
        main = archive.header.as_named_dict()
        self.assertEqual(signature["payloadsize"], 11)
        self.assertEqual(main["name"], b"fixture")
        self.assertEqual(main["summary"], b"fixture summary")
        self.assertEqual(main["buildtime"], 1_700_000_000)
        self.assertEqual(main["requirename"], [b"python", b"libc"])
        self.assertEqual(main["requireflags"], [8, 12])
        self.assertEqual(main["filemodes"], [0o100644, 0o100600, 0o100644])
        self.assertEqual(main["bugurl"], b"https://bugs.example.invalid")
        self.assertEqual(main[6000], b"unknown-tag")

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "fixture.rpm")
            path.write_bytes(encoded)
            path_archive = unpackio.open_rpm_path(path)
            members = [entry for entry in path_archive.entries() if not entry.is_directory]
            self.assertEqual(
                [member.name for member in members],
                ["./same.txt", "./same.txt", "./empty"],
            )
            self.assertEqual(members[0].permissions, 0o644)
            outputs = []
            for member in members:
                output = io.BytesIO()
                path_archive.extract_entry_to(member.index, output)
                outputs.append(output.getvalue())
            self.assertEqual(outputs, [b"first", b"second", b""])

    def test_standalone_stream_info_and_bounded_extraction(self) -> None:
        lz4_payload = b"standalone lz4 " * 2_000
        cases = [
            (raw_lz4_frame(lz4_payload), "lz4", lz4_payload),
            (raw_zstandard_frame(b"standalone zstandard"), "zstandard", b"standalone zstandard"),
            (HELLO_DOT_Z, "unix-compress", b"hello unix compress\n"),
        ]
        for encoded, expected_format, expected in cases:
            with self.subTest(format=expected_format):
                stream = unpackio.open_stream_bytes(encoded)
                self.assertIsInstance(stream, unpackio.CompressedStream)
                self.assertEqual(stream.info.format, expected_format)
                self.assertEqual(stream.info.compressed_size, len(encoded))
                self.assertEqual(stream.retained_input_bytes, len(encoded))

                writer = io.BytesIO()
                self.assertEqual(stream.extract_to(writer), len(expected))
                self.assertEqual(writer.getvalue(), expected)

                chunks: list[bytes] = []
                self.assertEqual(stream.stream(lambda chunk: chunks.append(chunk)), len(expected))
                self.assertEqual(b"".join(chunks), expected)
                self.assertLessEqual(max(map(len, chunks)), 8 * 1024)
                self.assertIsNone(stream.verify())

        lz4_info = unpackio.open_stream_bytes(cases[0][0]).info
        self.assertEqual(lz4_info.frame_count, 1)
        self.assertEqual(lz4_info.maximum_block_bytes, 64 * 1024)
        self.assertIsNone(lz4_info.uncompressed_size)
        zstandard_info = unpackio.open_stream_bytes(cases[1][0]).info
        self.assertEqual(zstandard_info.uncompressed_size, len(cases[1][2]))
        self.assertEqual(zstandard_info.maximum_window_bytes, len(cases[1][2]))
        compress_info = unpackio.open_stream_bytes(cases[2][0]).info
        self.assertEqual(compress_info.maximum_code_bits, 16)
        self.assertTrue(compress_info.block_mode)
        self.assertEqual(compress_info.decoder_dictionary_bytes, 256 * 1024)

    def test_standalone_stream_explicit_formats_paths_and_failures(self) -> None:
        zstandard = raw_zstandard_frame(b"path stream")
        self.assertEqual(
            unpackio.open_stream_bytes(zstandard, format="zstd").info.format,
            "zstandard",
        )
        self.assertEqual(
            unpackio.open_stream_bytes(HELLO_DOT_Z, format="z").info.format,
            "unix-compress",
        )
        with self.assertRaises(ValueError):
            unpackio.open_stream_bytes(zstandard, format="zip")
        with self.assertRaises(unpackio.FormatError) as caught:
            unpackio.open_stream_bytes(zstandard, format="lz4")
        self.assertEqual(caught.exception.format, "lz4")

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "input.zst"
            path.write_bytes(zstandard)
            stream = unpackio.open_stream_path(path)
            writer = io.BytesIO()
            self.assertEqual(stream.extract_to(writer), len(b"path stream"))
            self.assertEqual(writer.getvalue(), b"path stream")
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [path])

        limited = unpackio.Limits(max_total_output_bytes=4)
        with self.assertRaises(unpackio.LimitExceededError) as caught:
            unpackio.open_stream_bytes(zstandard, limits=limited)
        self.assertEqual(caught.exception.limit, "total_output_bytes")

        stream = unpackio.open_stream_bytes(HELLO_DOT_Z, limits=limited)
        with self.assertRaises(unpackio.LimitExceededError):
            stream.verify()
        with self.assertRaises(unpackio.LimitExceededError) as caught:
            unpackio.open_stream_bytes(
                HELLO_DOT_Z,
                limits=unpackio.Limits(max_stream_frames=0),
            )
        self.assertEqual(caught.exception.limit, "stream_frames")
        with self.assertRaises(unpackio.LimitExceededError) as caught:
            unpackio.open_stream_bytes(zstandard, max_work_units=1)
        self.assertEqual(caught.exception.limit, "work_units")

        class MarkerError(Exception):
            pass

        stream = unpackio.open_stream_bytes(raw_lz4_frame(b"callback"))

        def fail(_chunk: bytes) -> None:
            raise MarkerError("stream callback marker")

        with self.assertRaisesRegex(MarkerError, "stream callback marker"):
            stream.stream(fail)
        with self.assertRaises(unpackio.CancelledError):
            stream.stream(lambda _chunk: False)

        cancellation = unpackio.CancellationToken()
        cancellation.cancel()
        with self.assertRaises(unpackio.CancelledError):
            stream.verify(cancellation=cancellation)

    def test_open_list_raw_metadata_and_resources(self) -> None:
        payload = b"python binding"
        raw_name = [ord(character) for character in "directory/member.bin"]
        archive = unpackio.open_bytes(copy_archive(payload, raw_name))
        self.assertEqual(len(archive), 1)
        entry = archive.entries()[0]
        self.assertEqual(entry.index, 0)
        self.assertEqual(entry.raw_name, raw_name)
        self.assertEqual(entry.name, "directory/member.bin")
        self.assertEqual(entry.kind, "file")
        self.assertEqual(entry.size, len(payload))
        self.assertEqual(entry.crc32, crc32(payload))
        self.assertTrue(entry.is_safe_path)
        self.assertIsNone(entry.unsafe_path_reason)
        self.assertIsNone(archive.entry(1))
        self.assertGreater(archive.resources.metadata_bytes, 0)
        self.assertEqual(archive.resources.password_bytes, 0)
        self.assertGreaterEqual(archive.resources.retained_bytes, len(payload))

    def test_raw_utf16_and_unsafe_path_are_preserved(self) -> None:
        cases = [
            ([ord("."), ord("."), ord("/"), 0xD800], "traversal"),
            ([ord(character) for character in "/absolute"], "absolute"),
            ([ord(character) for character in "C:\\drive"], "drive"),
            ([ord(character) for character in "\\\\server\\share"], "unc"),
        ]
        for raw_name, reason in cases:
            with self.subTest(reason=reason):
                entry = unpackio.open_bytes(copy_archive(b"x", raw_name)).entry(0)
                self.assertIsNotNone(entry)
                assert entry is not None
                self.assertEqual(entry.raw_name, raw_name)
                self.assertFalse(entry.is_safe_path)
                self.assertEqual(entry.unsafe_path_reason, reason)

    def test_writer_and_callback_finish_before_success(self) -> None:
        payload = b"bounded callback output" * 2_000
        archive = unpackio.open_bytes(copy_archive(payload))
        writer = io.BytesIO()
        self.assertEqual(archive.extract_entry_to(0, writer), len(payload))
        self.assertEqual(writer.getvalue(), payload)

        chunks: list[bytes] = []
        count = archive.stream_entry(0, lambda chunk: chunks.append(chunk))
        self.assertEqual(count, len(payload))
        self.assertEqual(b"".join(chunks), payload)
        self.assertGreater(len(chunks), 1)
        self.assertLessEqual(max(map(len, chunks)), 8 * 1024)

        class PartialWriter:
            def __init__(self) -> None:
                self.output = bytearray()

            def write(self, chunk: bytes) -> int:
                count = max(1, len(chunk) // 2)
                self.output.extend(chunk[:count])
                return count

        partial = PartialWriter()
        self.assertEqual(archive.extract_entry_to(0, partial), len(payload))
        self.assertEqual(partial.output, payload)

        class ImpossibleWriter:
            def write(self, chunk: bytes) -> int:
                return len(chunk) + 1

        with self.assertRaises(ValueError):
            archive.extract_entry_to(0, ImpossibleWriter())

    def test_callback_exception_and_cancellation_are_preserved(self) -> None:
        archive = unpackio.open_bytes(copy_archive(b"callback"))

        class MarkerError(Exception):
            pass

        marker = MarkerError("marker")

        def fail(_: bytes) -> None:
            raise marker

        with self.assertRaises(MarkerError) as raised:
            archive.stream_entry(0, fail)
        self.assertIs(raised.exception, marker)

        class FailingWriter:
            def write(self, _: bytes) -> int:
                raise marker

        with self.assertRaises(MarkerError) as writer_raised:
            archive.extract_entry_to(0, FailingWriter())
        self.assertIs(writer_raised.exception, marker)

        with self.assertRaises(unpackio.CancelledError) as cancelled:
            archive.stream_entry(0, lambda _: False)
        self.assertEqual(cancelled.exception.kind, "cancelled")

        reentered = [False]

        def reenter(_: bytes) -> bool:
            archive.verify()
            reentered[0] = True
            return True

        self.assertEqual(archive.stream_entry(0, reenter), len(b"callback"))
        self.assertTrue(reentered[0])

    def test_batch_sink_preserves_natural_entry_boundaries(self) -> None:
        first = b"a" * 9_000
        second = b"b" * 9_000
        archive = unpackio.open_bytes(
            solid_copy_archive(
                [("duplicate.bin", first), ("empty.bin", None), ("duplicate.bin", second)]
            )
        )
        sink = CollectEntrySink()
        self.assertEqual(archive.extract_entries_to(sink), len(first) + len(second))
        self.assertEqual(bytes(sink.entries[0]), first)
        self.assertEqual(bytes(sink.entries[1]), b"")
        self.assertEqual(bytes(sink.entries[2]), second)
        self.assertTrue(sink.chunks)
        self.assertLessEqual(max(sink.chunks), 8 * 1024)
        self.assertEqual(
            [event for event in sink.events if event[0] != "write"],
            [
                ("begin", 0, "duplicate.bin", len(first)),
                ("finish", 0),
                ("begin", 1, "empty.bin", 0),
                ("finish", 1),
                ("begin", 2, "duplicate.bin", len(second)),
                ("finish", 2),
            ],
        )

    def test_batch_crc_callback_and_cancellation_failures_stop_boundaries(self) -> None:
        entries = [("first.bin", b"first"), ("second.bin", b"second")]
        corrupt = unpackio.open_bytes(solid_copy_archive(entries, corrupt_stream_index=1))
        corrupt_sink = CollectEntrySink()
        with self.assertRaises(unpackio.ChecksumError) as checksum:
            corrupt.extract_entries_to(corrupt_sink)
        self.assertEqual(checksum.exception.scope, "member")
        self.assertEqual(checksum.exception.member_index, 1)
        self.assertIn(("finish", 0), corrupt_sink.events)
        self.assertNotIn(("finish", 1), corrupt_sink.events)

        archive = unpackio.open_bytes(solid_copy_archive(entries))

        class MarkerError(Exception):
            pass

        begin_marker = MarkerError("begin callback marker")

        class BeginFailingSink(CollectEntrySink):
            def begin_entry(self, entry: unpackio.Entry, size: int) -> None:
                raise begin_marker

        with self.assertRaises(MarkerError) as begin_callback:
            archive.extract_entries_to(BeginFailingSink())
        self.assertIs(begin_callback.exception, begin_marker)

        marker = MarkerError("batch callback marker")

        class FailingSink(CollectEntrySink):
            def write_entry(self, index: int, chunk: bytes) -> None:
                if index == 1:
                    raise marker
                super().write_entry(index, chunk)

        with self.assertRaises(MarkerError) as callback:
            archive.extract_entries_to(FailingSink())
        self.assertIs(callback.exception, marker)

        finish_marker = MarkerError("finish callback marker")

        class FinishFailingSink(CollectEntrySink):
            def finish_entry(self, index: int) -> None:
                if index == 0:
                    raise finish_marker
                super().finish_entry(index)

        with self.assertRaises(MarkerError) as finish_callback:
            archive.extract_entries_to(FinishFailingSink())
        self.assertIs(finish_callback.exception, finish_marker)

        token = unpackio.CancellationToken()

        class CancellingSink(CollectEntrySink):
            def write_entry(self, index: int, chunk: bytes) -> None:
                super().write_entry(index, chunk)
                token.cancel()

        cancelled_sink = CancellingSink()
        with self.assertRaises(unpackio.CancelledError):
            archive.extract_entries_to(cancelled_sink, cancellation=token)
        self.assertNotIn(("finish", 0), cancelled_sink.events)

        class FalseSink(CollectEntrySink):
            def begin_entry(self, entry: unpackio.Entry, size: int) -> bool:
                super().begin_entry(entry, size)
                return False

        with self.assertRaises(unpackio.CancelledError):
            archive.extract_entries_to(FalseSink())

    def test_batch_output_limit_and_shared_work_budget(self) -> None:
        first = b"a" * 9_000
        second = b"b" * 9_000
        archive_bytes = solid_copy_archive([("first.bin", first), ("second.bin", second)])
        limited = unpackio.open_bytes(
            archive_bytes,
            limits=unpackio.Limits(max_entry_output_bytes=len(first) - 1),
        )
        limited_sink = CollectEntrySink()
        with self.assertRaises(unpackio.LimitExceededError) as output_limit:
            limited.extract_entries_to(limited_sink)
        self.assertEqual(output_limit.exception.limit, "entry_output_bytes")
        self.assertEqual(limited_sink.events, [])

        archive = unpackio.open_bytes(archive_bytes)

        def minimum_work(operation: object) -> int:
            if not callable(operation):
                raise TypeError("test operation must be callable")
            lower = -1
            upper = 1
            while True:
                try:
                    operation(upper)
                    break
                except unpackio.LimitExceededError as error:
                    if error.limit != "work_units":
                        raise
                    upper *= 2
            while upper - lower > 1:
                middle = (upper + lower) // 2
                try:
                    operation(middle)
                    upper = middle
                except unpackio.LimitExceededError as error:
                    if error.limit != "work_units":
                        raise
                    lower = middle
            return upper

        first_work = minimum_work(
            lambda maximum: archive.extract_entry_to(
                0, io.BytesIO(), max_work_units=maximum
            )
        )
        second_work = minimum_work(
            lambda maximum: archive.extract_entry_to(
                1, io.BytesIO(), max_work_units=maximum
            )
        )
        batch_work = minimum_work(
            lambda maximum: archive.extract_entries_to(
                CollectEntrySink(), max_work_units=maximum
            )
        )
        self.assertGreater(batch_work, max(first_work, second_work))
        self.assertLess(batch_work, first_work + second_work)

        with self.assertRaises(unpackio.LimitExceededError) as shared:
            archive.extract_entries_to(
                CollectEntrySink(),
                max_work_units=max(first_work, second_work),
            )
        self.assertEqual(shared.exception.limit, "work_units")

    def test_corrupt_member_never_reports_success(self) -> None:
        archive_bytes = bytearray(copy_archive(b"checksum"))
        archive_bytes[32] ^= 1
        archive = unpackio.open_bytes(bytes(archive_bytes))
        output = io.BytesIO()
        with self.assertRaises(unpackio.ChecksumError) as raised:
            archive.extract_entry_to(0, output)
        self.assertEqual(raised.exception.kind, "checksum")
        self.assertIn(raised.exception.scope, {"folder", "member"})

    def test_structured_format_limit_work_and_cancellation_errors(self) -> None:
        with self.assertRaises(unpackio.FormatError) as malformed:
            unpackio.open_bytes(b"not a 7z archive")
        self.assertEqual(malformed.exception.kind, "format")
        self.assertTrue(malformed.exception.detail)

        limits = unpackio.Limits(max_total_input_bytes=1)
        with self.assertRaises(unpackio.LimitExceededError) as limited:
            unpackio.open_bytes(copy_archive(b"x"), limits=limits)
        self.assertEqual(limited.exception.limit, "total_input_bytes")
        self.assertEqual(limited.exception.maximum, 1)

        with self.assertRaises(unpackio.LimitExceededError) as work:
            unpackio.open_bytes(copy_archive(b"x"), max_work_units=0)
        self.assertEqual(work.exception.limit, "work_units")

        token = unpackio.CancellationToken()
        token.cancel()
        self.assertTrue(token.is_cancelled)
        with self.assertRaises(unpackio.CancelledError):
            unpackio.open_bytes(copy_archive(b"x"), cancellation=token)

    def test_every_limit_is_exposed_and_password_is_archive_scoped(self) -> None:
        limits = unpackio.Limits(
            max_header_bytes=1,
            max_files=2,
            max_folders=3,
            max_coders_per_folder=4,
            max_total_coders=5,
            max_streams_per_folder=6,
            max_total_streams=7,
            max_stream_frames=8,
            max_substreams=9,
            max_header_properties=10,
            max_coder_property_bytes=11,
            max_name_bytes_per_entry=12,
            max_total_name_bytes=13,
            max_dictionary_bytes=14,
            max_entry_output_bytes=15,
            max_total_output_bytes=16,
            max_volumes=17,
            max_total_input_bytes=18,
            max_kdf_power=19,
            max_recursion_depth=20,
            sfx_scan_limit=21,
        )
        self.assertEqual(limits.max_header_bytes, 1)
        self.assertEqual(limits.max_total_input_bytes, 18)
        self.assertEqual(limits.max_stream_frames, 8)
        self.assertEqual(limits.sfx_scan_limit, 21)

        archive = unpackio.open_bytes(copy_archive(b"secret state"), password="temporary")
        self.assertGreater(archive.resources.password_bytes, 0)

    def test_path_and_python_volume_provider(self) -> None:
        archive_bytes = copy_archive(b"volumes")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "sample.7z")
            path.write_bytes(archive_bytes)
            self.assertEqual(len(unpackio.open_path(path)), 1)

        split = len(archive_bytes) // 2
        parts = [archive_bytes[:split], archive_bytes[split:]]

        class Provider:
            def __init__(self) -> None:
                self.requests: list[tuple[int, str]] = []

            def open_volume(self, index: int, expected: str) -> bytes | None:
                self.requests.append((index, expected))
                return parts[index] if index < len(parts) else None

        provider = Provider()
        archive = unpackio.open_volumes(provider, "memory.001")
        self.assertEqual(len(archive), 1)
        self.assertEqual(provider.requests[:2], [(0, "memory.001"), (1, "memory.002")])

        with self.assertRaises(unpackio.MissingVolumeError) as missing:
            unpackio.open_volumes(lambda index, _: parts[0] if index == 0 else None, "lost.001")
        self.assertEqual(missing.exception.expected, "lost.002")

        with self.assertRaises(unpackio.LimitExceededError) as volume_limit:
            unpackio.open_volumes(
                lambda index, _: archive_bytes if index == 0 else None,
                "limited.001",
                limits=unpackio.Limits(max_total_input_bytes=1),
            )
        self.assertEqual(volume_limit.exception.limit, "total_input_bytes")
        self.assertEqual(volume_limit.exception.requested, len(archive_bytes))
        self.assertEqual(volume_limit.exception.maximum, 1)

        provider_error = RuntimeError("provider marker")

        def fail_provider(_: int, __: str) -> bytes:
            raise provider_error

        with self.assertRaises(RuntimeError) as provider_raised:
            unpackio.open_volumes(fail_provider, "failed.001")
        self.assertIs(provider_raised.exception, provider_error)

    def test_rust_only_verification_releases_the_gil(self) -> None:
        archive = unpackio.open_bytes(copy_archive(b"g" * (8 * 1024 * 1024)))
        ready = threading.Event()
        stop = threading.Event()
        counter = [0]

        def spin() -> None:
            ready.set()
            while not stop.is_set():
                counter[0] += 1

        worker = threading.Thread(target=spin)
        worker.start()
        self.assertTrue(ready.wait(timeout=5))
        time.sleep(0.01)
        before = counter[0]
        archive.verify()
        after = counter[0]
        stop.set()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertGreater(after, before)


if __name__ == "__main__":
    unittest.main()
