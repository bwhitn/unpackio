from __future__ import annotations

import os
from collections.abc import Callable
from typing import Protocol

DEFAULT_MAX_WORK_UNITS: int
IMPLEMENTATION_STATUS: str


class UnpackioError(Exception):
    kind: str


class FormatError(UnpackioError):
    detail: str
    format: str


class ChecksumError(UnpackioError):
    scope: str
    member_index: int | None
    format: str
    frame_index: int | None


class UnsupportedMethodError(UnpackioError):
    method_id: bytes
    method_id_hex: str


class UnsupportedFeatureError(UnpackioError):
    feature: str
    format: str


class LimitExceededError(UnpackioError):
    limit: str
    requested: int
    maximum: int


class MissingVolumeError(UnpackioError):
    expected: str


class PasswordRequiredError(UnpackioError): ...
class WrongPasswordOrCorruptError(UnpackioError): ...
class CancelledError(UnpackioError): ...


class ArchiveIoError(UnpackioError):
    io_kind: str
    raw_os_error: int | None
    detail: str


class InternalError(UnpackioError): ...


class Limits:
    def __init__(
        self,
        *,
        max_header_bytes: int | None = ...,
        max_files: int | None = ...,
        max_folders: int | None = ...,
        max_coders_per_folder: int | None = ...,
        max_total_coders: int | None = ...,
        max_streams_per_folder: int | None = ...,
        max_total_streams: int | None = ...,
        max_stream_frames: int | None = ...,
        max_substreams: int | None = ...,
        max_header_properties: int | None = ...,
        max_coder_property_bytes: int | None = ...,
        max_name_bytes_per_entry: int | None = ...,
        max_total_name_bytes: int | None = ...,
        max_dictionary_bytes: int | None = ...,
        max_entry_output_bytes: int | None = ...,
        max_total_output_bytes: int | None = ...,
        max_volumes: int | None = ...,
        max_total_input_bytes: int | None = ...,
        max_kdf_power: int | None = ...,
        max_recursion_depth: int | None = ...,
        sfx_scan_limit: int | None = ...,
    ) -> None: ...
    @property
    def max_header_bytes(self) -> int: ...
    @property
    def max_files(self) -> int: ...
    @property
    def max_folders(self) -> int: ...
    @property
    def max_coders_per_folder(self) -> int: ...
    @property
    def max_total_coders(self) -> int: ...
    @property
    def max_streams_per_folder(self) -> int: ...
    @property
    def max_total_streams(self) -> int: ...
    @property
    def max_stream_frames(self) -> int: ...
    @property
    def max_substreams(self) -> int: ...
    @property
    def max_header_properties(self) -> int: ...
    @property
    def max_coder_property_bytes(self) -> int: ...
    @property
    def max_name_bytes_per_entry(self) -> int: ...
    @property
    def max_total_name_bytes(self) -> int: ...
    @property
    def max_dictionary_bytes(self) -> int: ...
    @property
    def max_entry_output_bytes(self) -> int: ...
    @property
    def max_total_output_bytes(self) -> int: ...
    @property
    def max_volumes(self) -> int: ...
    @property
    def max_total_input_bytes(self) -> int: ...
    @property
    def max_kdf_power(self) -> int: ...
    @property
    def max_recursion_depth(self) -> int: ...
    @property
    def sfx_scan_limit(self) -> int: ...


class CancellationToken:
    def __init__(self) -> None: ...
    def cancel(self) -> None: ...
    @property
    def is_cancelled(self) -> bool: ...


class Entry:
    @property
    def index(self) -> int: ...
    @property
    def raw_name(self) -> list[int] | None: ...
    @property
    def name(self) -> str | None: ...
    @property
    def kind(self) -> str: ...
    @property
    def has_stream(self) -> bool: ...
    @property
    def is_empty_file(self) -> bool: ...
    @property
    def is_anti_item(self) -> bool: ...
    @property
    def size(self) -> int | None: ...
    @property
    def crc32(self) -> int | None: ...
    @property
    def creation_time(self) -> int | None: ...
    @property
    def access_time(self) -> int | None: ...
    @property
    def modification_time(self) -> int | None: ...
    @property
    def windows_attributes(self) -> int | None: ...
    @property
    def start_position(self) -> int | None: ...
    @property
    def unix_mode(self) -> int | None: ...
    @property
    def is_symlink(self) -> bool: ...
    @property
    def is_safe_path(self) -> bool: ...
    @property
    def unsafe_path_reason(self) -> str | None: ...


class ArchiveResources:
    @property
    def input_bytes(self) -> int: ...
    @property
    def metadata_bytes(self) -> int: ...
    @property
    def password_bytes(self) -> int: ...
    @property
    def retained_bytes(self) -> int: ...


class Archive:
    def __len__(self) -> int: ...
    def entries(self) -> list[Entry]: ...
    def entry(self, index: int) -> Entry | None: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def resources(self) -> ArchiveResources: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_entry_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_entries_to(
        self,
        sink: _EntrySink,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_entry(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class ZipEntry:
    @property
    def index(self) -> int: ...
    @property
    def raw_name(self) -> bytes: ...
    @property
    def name(self) -> str: ...
    @property
    def raw_comment(self) -> bytes: ...
    @property
    def extra_fields(self) -> bytes: ...
    @property
    def compression_method(self) -> str: ...
    @property
    def compression_method_id(self) -> int: ...
    @property
    def encryption(self) -> str: ...
    @property
    def aes_vendor_version(self) -> int | None: ...
    @property
    def aes_key_bits(self) -> int | None: ...
    @property
    def compressed_size(self) -> int: ...
    @property
    def size(self) -> int: ...
    @property
    def crc32(self) -> int | None: ...
    @property
    def is_directory(self) -> bool: ...
    @property
    def is_symlink(self) -> bool: ...
    @property
    def unix_mode(self) -> int | None: ...
    @property
    def modified(self) -> tuple[int, int, int, int, int, int] | None: ...
    @property
    def modified_time_raw(self) -> int: ...
    @property
    def modified_date_raw(self) -> int: ...
    @property
    def version_made_by(self) -> int: ...
    @property
    def version_needed(self) -> int: ...
    @property
    def flags(self) -> int: ...
    @property
    def internal_attributes(self) -> int: ...
    @property
    def external_attributes(self) -> int: ...
    @property
    def local_header_offset(self) -> int: ...
    @property
    def is_safe_path(self) -> bool: ...
    @property
    def unsafe_path_reason(self) -> str | None: ...


class ZipArchive:
    def __len__(self) -> int: ...
    def entries(self) -> list[ZipEntry]: ...
    def entry(self, index: int) -> ZipEntry | None: ...
    @property
    def comment(self) -> bytes: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def retained_input_bytes(self) -> int: ...
    @property
    def retained_password_bytes(self) -> int: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_entry_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_entries_to(
        self,
        sink: _ZipEntrySink,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_entry(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class RpmEntry:
    @property
    def index(self) -> int: ...
    @property
    def raw_name(self) -> bytes: ...
    @property
    def name(self) -> str: ...
    @property
    def kind(self) -> str: ...
    @property
    def inode(self) -> int: ...
    @property
    def mode(self) -> int: ...
    @property
    def permissions(self) -> int: ...
    @property
    def uid(self) -> int: ...
    @property
    def gid(self) -> int: ...
    @property
    def link_count(self) -> int: ...
    @property
    def modified_time(self) -> int: ...
    @property
    def size(self) -> int: ...
    @property
    def device_major(self) -> int: ...
    @property
    def device_minor(self) -> int: ...
    @property
    def rdev_major(self) -> int: ...
    @property
    def rdev_minor(self) -> int: ...
    @property
    def checksum(self) -> int | None: ...
    @property
    def is_directory(self) -> bool: ...
    @property
    def is_symlink(self) -> bool: ...
    @property
    def is_safe_path(self) -> bool: ...
    @property
    def unsafe_path_reason(self) -> str | None: ...


class RpmHeaderEntry:
    @property
    def tag(self) -> int: ...
    @property
    def value_type(self) -> str: ...
    @property
    def value(self) -> object: ...


class RpmHeader:
    def __len__(self) -> int: ...
    @property
    def raw_size(self) -> int: ...
    def entries(self) -> list[RpmHeaderEntry]: ...
    def value(self, tag: int) -> object | None: ...
    def as_dict(self) -> dict[int, object]: ...
    def as_named_dict(self, *, signature: bool = ...) -> dict[str | int, object]: ...


class RpmArchive:
    def __len__(self) -> int: ...
    def entries(self) -> list[RpmEntry]: ...
    def entry(self, index: int) -> RpmEntry | None: ...
    @property
    def payload_compression(self) -> str: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def retained_payload_bytes(self) -> int: ...
    @property
    def lead_name(self) -> bytes: ...
    @property
    def lead_version(self) -> tuple[int, int]: ...
    @property
    def lead_package_type(self) -> int: ...
    @property
    def lead_architecture(self) -> int: ...
    @property
    def lead_operating_system(self) -> int: ...
    @property
    def lead_signature_type(self) -> int: ...
    @property
    def lead_reserved(self) -> bytes: ...
    @property
    def signature_header(self) -> RpmHeader: ...
    @property
    def header(self) -> RpmHeader: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_entry_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_entries_to(
        self,
        sink: _RpmEntrySink,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_entry(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class CpioEntry:
    index: int
    format: str
    raw_name: bytes
    name: str
    kind: str
    inode: int
    mode: int
    permissions: int
    uid: int
    gid: int
    link_count: int
    modified_time: int
    size: int
    device_major: int
    device_minor: int
    rdev_major: int
    rdev_minor: int
    checksum: int | None
    is_directory: bool
    is_symlink: bool
    is_safe_path: bool
    unsafe_path_reason: str | None


class CpioArchive:
    def __len__(self) -> int: ...
    def entries(self) -> list[CpioEntry]: ...
    def entry(self, index: int) -> CpioEntry | None: ...
    @property
    def format(self) -> str: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def retained_input_bytes(self) -> int: ...
    def symlink_target(self, index: int) -> bytes | None: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_entry_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_entry(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_entries_to(
        self,
        sink: _CpioEntrySink,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class DebMember:
    index: int
    raw_name: bytes
    name: str
    kind: str
    compression: str | None
    modified_time: int
    uid: int
    gid: int
    mode: int
    size: int


class DebEntry:
    index: int
    section: str
    raw_name: bytes
    name: str
    raw_link_name: bytes | None
    kind: str
    mode: int
    permissions: int
    uid: int
    gid: int
    modified_time: int | None
    size: int
    user_name: bytes | None
    group_name: bytes | None
    device_major: int | None
    device_minor: int | None
    header_checksum: int
    is_safe_path: bool
    unsafe_path_reason: str | None


class DebArchive:
    def __len__(self) -> int: ...
    def members(self) -> list[DebMember]: ...
    def member(self, index: int) -> DebMember | None: ...
    def entries(self) -> list[DebEntry]: ...
    def entry(self, index: int) -> DebEntry | None: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def retained_input_bytes(self) -> int: ...
    @property
    def retained_control_bytes(self) -> int: ...
    @property
    def retained_data_bytes(self) -> int: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_entry_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_entry(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_member_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_member(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_entries_to(
        self,
        sink: _DebEntrySink,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class ArjEntry:
    index: int
    raw_name: bytes
    name: str
    raw_comment: bytes
    archiver_version: int
    minimum_version: int
    host_os: int
    flags: int
    compression_method: str
    compression_method_id: int
    kind: str
    modified_time_raw: int
    compressed_size: int
    size: int
    crc32: int | None
    file_spec_position: int
    access_mode: int
    is_encrypted: bool
    is_safe_path: bool
    unsafe_path_reason: str | None


class ArjArchive:
    def __len__(self) -> int: ...
    def entries(self) -> list[ArjEntry]: ...
    def entry(self, index: int) -> ArjEntry | None: ...
    @property
    def raw_name(self) -> bytes: ...
    @property
    def raw_comment(self) -> bytes: ...
    @property
    def sfx_offset(self) -> int: ...
    @property
    def archiver_version(self) -> int: ...
    @property
    def minimum_version(self) -> int: ...
    @property
    def host_os(self) -> int: ...
    @property
    def flags(self) -> int: ...
    @property
    def creation_time_raw(self) -> int: ...
    @property
    def modification_time_raw(self) -> int: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def retained_input_bytes(self) -> int: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_entry_to(
        self,
        index: int,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream_entry(
        self,
        index: int,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def extract_entries_to(
        self,
        sink: _ArjEntrySink,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class StreamInfo:
    @property
    def format(self) -> str: ...
    @property
    def compressed_size(self) -> int: ...
    @property
    def uncompressed_size(self) -> int | None: ...
    @property
    def frame_count(self) -> int | None: ...
    @property
    def skippable_frame_count(self) -> int | None: ...
    @property
    def content_checksum_frame_count(self) -> int | None: ...
    @property
    def block_checksum_frame_count(self) -> int | None: ...
    @property
    def dictionary_frame_count(self) -> int | None: ...
    @property
    def legacy_frame_count(self) -> int | None: ...
    @property
    def maximum_block_bytes(self) -> int | None: ...
    @property
    def maximum_window_bytes(self) -> int | None: ...
    @property
    def maximum_code_bits(self) -> int | None: ...
    @property
    def block_mode(self) -> bool | None: ...
    @property
    def decoder_dictionary_bytes(self) -> int | None: ...


class CompressedStream:
    @property
    def info(self) -> StreamInfo: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def retained_input_bytes(self) -> int: ...
    def verify(
        self,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> None: ...
    def extract_to(
        self,
        writer: _Writer,
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...
    def stream(
        self,
        callback: Callable[[bytes], bool | None],
        *,
        cancellation: CancellationToken | None = ...,
        max_work_units: int = ...,
    ) -> int: ...


class _Writer(Protocol):
    def write(self, data: bytes, /) -> int: ...


class _EntrySink(Protocol):
    def begin_entry(self, entry: Entry, size: int, /) -> bool | None: ...
    def write_entry(self, index: int, data: bytes, /) -> bool | None: ...
    def finish_entry(self, index: int, /) -> bool | None: ...


class _ZipEntrySink(Protocol):
    def begin_entry(self, entry: ZipEntry, size: int, /) -> bool | None: ...
    def write_entry(self, index: int, data: bytes, /) -> bool | None: ...
    def finish_entry(self, index: int, /) -> bool | None: ...


class _RpmEntrySink(Protocol):
    def begin_entry(self, entry: RpmEntry, size: int, /) -> bool | None: ...
    def write_entry(self, index: int, data: bytes, /) -> bool | None: ...
    def finish_entry(self, index: int, /) -> bool | None: ...


class _CpioEntrySink(Protocol):
    def begin_entry(self, entry: CpioEntry, size: int, /) -> bool | None: ...
    def write_entry(self, index: int, data: bytes, /) -> bool | None: ...
    def finish_entry(self, index: int, /) -> bool | None: ...


class _DebEntrySink(Protocol):
    def begin_entry(self, entry: DebEntry, size: int, /) -> bool | None: ...
    def write_entry(self, index: int, data: bytes, /) -> bool | None: ...
    def finish_entry(self, index: int, /) -> bool | None: ...


class _ArjEntrySink(Protocol):
    def begin_entry(self, entry: ArjEntry, size: int, /) -> bool | None: ...
    def write_entry(self, index: int, data: bytes, /) -> bool | None: ...
    def finish_entry(self, index: int, /) -> bool | None: ...


class VolumeProvider(Protocol):
    def open_volume(self, index: int, expected_name: str, /) -> bytes | None: ...


def open_bytes(
    data: bytes,
    *,
    limits: Limits | None = ...,
    password: str | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> Archive: ...


def open_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    limits: Limits | None = ...,
    password: str | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> Archive: ...


def open_volumes(
    provider: VolumeProvider | Callable[[int, str], bytes | None],
    first_volume_name: str,
    *,
    limits: Limits | None = ...,
    password: str | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> Archive: ...


def open_zip_bytes(
    data: bytes,
    *,
    limits: Limits | None = ...,
    password: bytes | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> ZipArchive: ...


def open_zip_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    limits: Limits | None = ...,
    password: bytes | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> ZipArchive: ...


def open_rpm_bytes(
    data: bytes,
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> RpmArchive: ...


def open_rpm_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> RpmArchive: ...


def open_cpio_bytes(
    data: bytes,
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> CpioArchive: ...


def open_cpio_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> CpioArchive: ...


def open_deb_bytes(
    data: bytes,
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> DebArchive: ...


def open_deb_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> DebArchive: ...


def open_arj_bytes(
    data: bytes,
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> ArjArchive: ...


def open_arj_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> ArjArchive: ...


def open_stream_bytes(
    data: bytes,
    *,
    format: str | None = ...,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> CompressedStream: ...


def open_stream_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    format: str | None = ...,
    limits: Limits | None = ...,
    cancellation: CancellationToken | None = ...,
    max_work_units: int = ...,
) -> CompressedStream: ...
