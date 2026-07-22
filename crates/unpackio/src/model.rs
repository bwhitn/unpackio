//! Validated metadata produced by the archive parser.

/// The version recorded in a 7z signature header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveVersion {
    major: u8,
    minor: u8,
}

impl ArchiveVersion {
    pub(crate) const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Returns the major format version.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[must_use]
    pub const fn major(self) -> u8 {
        self.major
    }

    /// Returns the minor format version.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[must_use]
    pub const fn minor(self) -> u8 {
        self.minor
    }
}

/// The outer kind byte of the stored next header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NextHeaderKind {
    /// A plain 7z header beginning with the Header identifier.
    Header,
    /// A streams description whose decoded output is the real header.
    EncodedHeader,
}

/// A signature and next-header range that passed structural and CRC checks.
///
/// This is not a parsed archive directory and conveys no decoder or member
/// compatibility. All offsets are absolute within the supplied byte slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderEnvelope {
    signature_offset: u64,
    version: ArchiveVersion,
    next_header_offset: u64,
    next_header_size: u64,
    next_header_crc: u32,
    next_header_kind: NextHeaderKind,
}

impl HeaderEnvelope {
    pub(crate) const fn new(
        signature_offset: u64,
        version: ArchiveVersion,
        next_header_offset: u64,
        next_header_size: u64,
        next_header_crc: u32,
        next_header_kind: NextHeaderKind,
    ) -> Self {
        Self {
            signature_offset,
            version,
            next_header_offset,
            next_header_size,
            next_header_crc,
            next_header_kind,
        }
    }

    /// Returns the absolute offset of the six-byte 7z signature.
    #[must_use]
    pub const fn signature_offset(self) -> u64 {
        self.signature_offset
    }

    /// Returns the signature-header version.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[must_use]
    pub const fn version(self) -> ArchiveVersion {
        self.version
    }

    /// Returns the absolute start of the stored next-header bytes.
    #[must_use]
    pub const fn next_header_offset(self) -> u64 {
        self.next_header_offset
    }

    /// Returns the validated stored next-header length.
    #[must_use]
    pub const fn next_header_size(self) -> u64 {
        self.next_header_size
    }

    /// Returns the expected CRC-32 of the stored next-header bytes.
    #[cfg(feature = "unstable-internals")]
    #[must_use]
    pub const fn next_header_crc(self) -> u32 {
        self.next_header_crc
    }

    /// Returns whether the stored next header is plain or encoded.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[must_use]
    pub const fn next_header_kind(self) -> NextHeaderKind {
        self.next_header_kind
    }
}

/// A completely parsed and validated stored next header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedArchive {
    envelope: HeaderEnvelope,
    next_header: ParsedNextHeader,
}

impl ParsedArchive {
    pub(crate) const fn new(envelope: HeaderEnvelope, next_header: ParsedNextHeader) -> Self {
        Self {
            envelope,
            next_header,
        }
    }

    /// Returns the verified signature and next-header envelope.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[must_use]
    pub const fn envelope(&self) -> HeaderEnvelope {
        self.envelope
    }

    /// Returns the validated stored next-header model.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[must_use]
    pub const fn next_header(&self) -> &ParsedNextHeader {
        &self.next_header
    }

    pub(crate) fn into_parts(self) -> (HeaderEnvelope, ParsedNextHeader) {
        (self.envelope, self.next_header)
    }
}

/// The validated form of a plain or encoded stored next header.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParsedNextHeader {
    /// A plain archive header whose directory and streams are directly available.
    Header(ArchiveHeader),
    /// A validated stream descriptor whose decoded bytes contain the real header.
    EncodedHeader(StreamsInfo),
    /// A plain header whose main folder records reside in an additional stream.
    ///
    /// This staging form is exposed only with the documentation-hidden
    /// `unstable-internals` feature. [`crate::Archive`] resolves it before
    /// returning an archive session.
    PendingExternalFolders(PendingExternalFolderHeader),
}

/// A validated staging record for externally stored main-folder definitions.
///
/// The additional streams and data index are validated before any decoder is
/// entered. The bounded header copy is reparsed after the selected additional
/// folder output has been decoded and checksum-verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingExternalFolderHeader {
    additional_streams: StreamsInfo,
    data_index: u64,
    header_bytes: Box<[u8]>,
}

impl PendingExternalFolderHeader {
    pub(crate) const fn new(
        additional_streams: StreamsInfo,
        data_index: u64,
        header_bytes: Box<[u8]>,
    ) -> Self {
        Self {
            additional_streams,
            data_index,
            header_bytes,
        }
    }

    pub(crate) const fn additional_streams(&self) -> &StreamsInfo {
        &self.additional_streams
    }

    pub(crate) const fn data_index(&self) -> u64 {
        self.data_index
    }

    pub(crate) const fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

/// A validated plain archive header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveHeader {
    archive_properties: Box<[StoredProperty]>,
    additional_streams: Option<StreamsInfo>,
    main_streams: Option<StreamsInfo>,
    files: Option<FilesInfo>,
}

impl ArchiveHeader {
    pub(crate) const fn new(
        archive_properties: Box<[StoredProperty]>,
        additional_streams: Option<StreamsInfo>,
        main_streams: Option<StreamsInfo>,
        files: Option<FilesInfo>,
    ) -> Self {
        Self {
            archive_properties,
            additional_streams,
            main_streams,
            files,
        }
    }

    /// Returns bounded archive-level properties that are not interpreted yet.
    #[must_use]
    pub const fn archive_properties(&self) -> &[StoredProperty] {
        &self.archive_properties
    }

    /// Returns streams used by external properties, when present.
    #[must_use]
    pub const fn additional_streams(&self) -> Option<&StreamsInfo> {
        self.additional_streams.as_ref()
    }

    /// Returns the main member-data streams, when present.
    #[must_use]
    pub const fn main_streams(&self) -> Option<&StreamsInfo> {
        self.main_streams.as_ref()
    }

    /// Returns file records, when present.
    #[must_use]
    pub const fn files(&self) -> Option<&FilesInfo> {
        self.files.as_ref()
    }

    pub(crate) fn files_mut(&mut self) -> Option<&mut FilesInfo> {
        self.files.as_mut()
    }
}

/// A bounded property retained without interpreting its contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredProperty {
    id: u8,
    data: Box<[u8]>,
}

impl StoredProperty {
    pub(crate) const fn new(id: u8, data: Box<[u8]>) -> Self {
        Self { id, data }
    }

    /// Returns the 7z property identifier.
    #[cfg(feature = "unstable-internals")]
    #[must_use]
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// Returns the exact bounded property payload.
    #[must_use]
    pub const fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A metadata property whose contents reside in an additional stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalProperty {
    property_id: u8,
    data_index: u64,
    defined_entries: Box<[bool]>,
}

impl ExternalProperty {
    pub(crate) const fn new(
        property_id: u8,
        data_index: u64,
        defined_entries: Box<[bool]>,
    ) -> Self {
        Self {
            property_id,
            data_index,
            defined_entries,
        }
    }

    /// Returns the property identifier whose bytes are external.
    #[must_use]
    pub const fn property_id(&self) -> u8 {
        self.property_id
    }

    /// Returns the validated additional-substream index.
    #[must_use]
    pub const fn data_index(&self) -> u64 {
        self.data_index
    }

    /// Returns which file records have a value in the external stream.
    #[must_use]
    pub const fn defined_entries(&self) -> &[bool] {
        &self.defined_entries
    }
}

/// Validated file records and their metadata property locations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesInfo {
    entries: Box<[FileEntry]>,
    external_properties: Box<[ExternalProperty]>,
    unknown_properties: Box<[StoredProperty]>,
}

impl FilesInfo {
    pub(crate) const fn new(
        entries: Box<[FileEntry]>,
        external_properties: Box<[ExternalProperty]>,
        unknown_properties: Box<[StoredProperty]>,
    ) -> Self {
        Self {
            entries,
            external_properties,
            unknown_properties,
        }
    }

    /// Returns all entries in archive order.
    #[must_use]
    pub const fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    /// Returns known metadata properties backed by additional streams.
    #[must_use]
    pub const fn external_properties(&self) -> &[ExternalProperty] {
        &self.external_properties
    }

    /// Returns bounded file properties that are not interpreted yet.
    #[must_use]
    pub const fn unknown_properties(&self) -> &[StoredProperty] {
        &self.unknown_properties
    }

    pub(crate) fn entries_and_external_mut(&mut self) -> (&mut [FileEntry], &[ExternalProperty]) {
        (&mut self.entries, &self.external_properties)
    }
}

/// The semantic kind of one archive entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file, including a zero-length streamless file.
    File,
    /// A directory record.
    Directory,
    /// A symbolic-link record identified by its stored Unix mode.
    SymbolicLink,
    /// An anti-item deletion marker.
    AntiItem,
}

/// One validated archive directory entry.
///
/// Names remain exact UTF-16 metadata and may be unsafe as filesystem paths.
/// Size and CRC are optional because 7z can omit either value; `None` is never
/// a sentinel for zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEntry {
    raw_name: Option<Box<[u16]>>,
    has_stream: bool,
    empty_file: bool,
    anti_item: bool,
    creation_time: Option<u64>,
    access_time: Option<u64>,
    modification_time: Option<u64>,
    windows_attributes: Option<u32>,
    start_position: Option<u64>,
    stream: Option<FileStream>,
}

impl FileEntry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        raw_name: Option<Box<[u16]>>,
        has_stream: bool,
        empty_file: bool,
        anti_item: bool,
        creation_time: Option<u64>,
        access_time: Option<u64>,
        modification_time: Option<u64>,
        windows_attributes: Option<u32>,
        start_position: Option<u64>,
        stream: Option<FileStream>,
    ) -> Self {
        Self {
            raw_name,
            has_stream,
            empty_file,
            anti_item,
            creation_time,
            access_time,
            modification_time,
            windows_attributes,
            start_position,
            stream,
        }
    }

    /// Returns the exact UTF-16 code units, including unpaired surrogates.
    #[must_use]
    pub fn raw_name(&self) -> Option<&[u16]> {
        self.raw_name.as_deref()
    }

    /// Returns a lossy Unicode rendering for display only.
    ///
    /// Use [`FileEntry::raw_name`] when exact code units or path policy matter.
    #[must_use]
    pub fn name_lossy(&self) -> Option<String> {
        self.raw_name.as_deref().map(String::from_utf16_lossy)
    }

    /// Returns whether the entry consumes one archive substream.
    #[must_use]
    pub const fn has_stream(&self) -> bool {
        self.has_stream
    }

    /// Returns whether a streamless entry is an empty file rather than a directory.
    #[must_use]
    pub const fn is_empty_file(&self) -> bool {
        self.empty_file
    }

    /// Returns whether this record is an anti-item.
    #[must_use]
    pub const fn is_anti_item(&self) -> bool {
        self.anti_item
    }

    /// Returns the semantic entry kind without interpreting its raw name.
    #[must_use]
    pub const fn kind(&self) -> EntryKind {
        if self.anti_item {
            EntryKind::AntiItem
        } else if self.is_symlink() {
            EntryKind::SymbolicLink
        } else if self.has_stream || self.empty_file {
            EntryKind::File
        } else {
            EntryKind::Directory
        }
    }

    /// Returns the unpacked member size, preserving an unknown size as `None`.
    ///
    /// A streamless empty file has the known size `Some(0)`. Directories and
    /// anti-items return `None`; use [`FileEntry::has_stream`] to distinguish
    /// those records from a streamed member whose size is unknown.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        match self.stream {
            Some(stream) => stream.size(),
            None if self.empty_file && !self.anti_item => Some(0),
            None => None,
        }
    }

    /// Returns the member CRC-32, or `None` when no member CRC is stored.
    #[must_use]
    pub const fn crc32(&self) -> Option<u32> {
        match self.stream {
            Some(stream) => stream.crc(),
            None => None,
        }
    }

    /// Returns the raw Windows FILETIME creation timestamp, when defined.
    #[must_use]
    pub const fn creation_time(&self) -> Option<u64> {
        self.creation_time
    }

    /// Returns the raw Windows FILETIME access timestamp, when defined.
    #[must_use]
    pub const fn access_time(&self) -> Option<u64> {
        self.access_time
    }

    /// Returns the raw Windows FILETIME modification timestamp, when defined.
    #[must_use]
    pub const fn modification_time(&self) -> Option<u64> {
        self.modification_time
    }

    /// Returns raw Windows attributes, when defined.
    #[must_use]
    pub const fn windows_attributes(&self) -> Option<u32> {
        self.windows_attributes
    }

    /// Returns the optional StartPos value.
    #[must_use]
    pub const fn start_position(&self) -> Option<u64> {
        self.start_position
    }

    #[cfg(feature = "unstable-internals")]
    #[doc(hidden)]
    #[must_use]
    pub const fn stream(&self) -> Option<FileStream> {
        self.stream
    }

    #[cfg(not(feature = "unstable-internals"))]
    pub(crate) const fn stream(&self) -> Option<FileStream> {
        self.stream
    }

    /// Returns a stored POSIX mode when the 7z Unix-extension attribute is set.
    #[must_use]
    pub const fn unix_mode(&self) -> Option<u32> {
        match self.windows_attributes {
            Some(attributes) if attributes & 0x8000 != 0 => Some(attributes >> 16),
            Some(_) | None => None,
        }
    }

    /// Returns whether the stored POSIX mode identifies a symbolic link.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        matches!(self.unix_mode(), Some(mode) if mode & 0o170_000 == 0o120_000)
    }

    pub(crate) fn set_raw_name(&mut self, value: Box<[u16]>) {
        self.raw_name = Some(value);
    }

    pub(crate) const fn set_creation_time(&mut self, value: u64) {
        self.creation_time = Some(value);
    }

    pub(crate) const fn set_access_time(&mut self, value: u64) {
        self.access_time = Some(value);
    }

    pub(crate) const fn set_modification_time(&mut self, value: u64) {
        self.modification_time = Some(value);
    }

    pub(crate) const fn set_windows_attributes(&mut self, value: u32) {
        self.windows_attributes = Some(value);
    }

    pub(crate) const fn set_start_position(&mut self, value: u64) {
        self.start_position = Some(value);
    }
}

/// A validated mapping from a file record to one folder substream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStream {
    folder_index: u64,
    substream_index: u64,
    size: Option<u64>,
    crc: Option<u32>,
}

impl FileStream {
    pub(crate) const fn new(
        folder_index: u64,
        substream_index: u64,
        size: Option<u64>,
        crc: Option<u32>,
    ) -> Self {
        Self {
            folder_index,
            substream_index,
            size,
            crc,
        }
    }

    /// Returns the main-stream folder index.
    #[must_use]
    pub const fn folder_index(self) -> u64 {
        self.folder_index
    }

    /// Returns the substream index within that folder.
    #[must_use]
    pub const fn substream_index(self) -> u64 {
        self.substream_index
    }

    /// Returns the unpacked size, or `None` when the header marks it unknown.
    #[must_use]
    pub const fn size(self) -> Option<u64> {
        self.size
    }

    /// Returns the member CRC, or `None` when no member CRC is present.
    #[must_use]
    pub const fn crc(self) -> Option<u32> {
        self.crc
    }
}

/// A validated StreamsInfo section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamsInfo {
    pack_position: u64,
    pack_streams: Box<[PackStream]>,
    folders: Box<[Folder]>,
    substream_count: u64,
}

impl StreamsInfo {
    pub(crate) const fn new(
        pack_position: u64,
        pack_streams: Box<[PackStream]>,
        folders: Box<[Folder]>,
        substream_count: u64,
    ) -> Self {
        Self {
            pack_position,
            pack_streams,
            folders,
            substream_count,
        }
    }

    /// Returns the packed-data position relative to the fixed header's end.
    #[cfg(feature = "unstable-internals")]
    #[must_use]
    pub const fn pack_position(&self) -> u64 {
        self.pack_position
    }

    /// Returns packed byte ranges in stream order.
    #[must_use]
    pub const fn pack_streams(&self) -> &[PackStream] {
        &self.pack_streams
    }

    /// Returns validated folder graphs.
    #[must_use]
    pub const fn folders(&self) -> &[Folder] {
        &self.folders
    }

    /// Returns the number of logical unpacked substreams.
    #[must_use]
    pub const fn substream_count(&self) -> u64 {
        self.substream_count
    }
}

/// One packed input stream and its validated archive range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackStream {
    offset: u64,
    size: Option<u64>,
    crc: Option<u32>,
}

impl PackStream {
    pub(crate) const fn new(offset: u64, size: Option<u64>, crc: Option<u32>) -> Self {
        Self { offset, size, crc }
    }

    /// Returns the absolute byte offset in the supplied archive.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Returns the packed length, or `None` when explicitly unknown.
    #[must_use]
    pub const fn size(self) -> Option<u64> {
        self.size
    }

    /// Returns the packed-stream CRC, when present.
    #[must_use]
    pub const fn crc(self) -> Option<u32> {
        self.crc
    }
}

/// One validated coder graph and its logical substreams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Folder {
    coders: Box<[Coder]>,
    bind_pairs: Box<[BindPair]>,
    packed_input_indices: Box<[u64]>,
    unpack_sizes: Box<[Option<u64>]>,
    root_output_index: u64,
    topological_coder_order: Box<[u64]>,
    crc: Option<u32>,
    substreams: Box<[Substream]>,
    dictionary_bytes: u64,
    first_pack_stream: u64,
}

impl Folder {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        coders: Box<[Coder]>,
        bind_pairs: Box<[BindPair]>,
        packed_input_indices: Box<[u64]>,
        unpack_sizes: Box<[Option<u64>]>,
        root_output_index: u64,
        topological_coder_order: Box<[u64]>,
        crc: Option<u32>,
        substreams: Box<[Substream]>,
        dictionary_bytes: u64,
        first_pack_stream: u64,
    ) -> Self {
        Self {
            coders,
            bind_pairs,
            packed_input_indices,
            unpack_sizes,
            root_output_index,
            topological_coder_order,
            crc,
            substreams,
            dictionary_bytes,
            first_pack_stream,
        }
    }

    /// Returns coders in stored order with validated port ranges.
    #[must_use]
    pub const fn coders(&self) -> &[Coder] {
        &self.coders
    }

    /// Returns validated one-to-one output-to-input bindings.
    #[must_use]
    pub const fn bind_pairs(&self) -> &[BindPair] {
        &self.bind_pairs
    }

    /// Returns all and only unbound input ports in packed-stream order.
    #[must_use]
    pub const fn packed_input_indices(&self) -> &[u64] {
        &self.packed_input_indices
    }

    /// Returns output sizes, preserving unknown values as `None`.
    #[must_use]
    pub const fn unpack_sizes(&self) -> &[Option<u64>] {
        &self.unpack_sizes
    }

    /// Returns the unique unbound output port.
    #[must_use]
    pub const fn root_output_index(&self) -> u64 {
        self.root_output_index
    }

    /// Returns a dependency-respecting coder order.
    #[must_use]
    pub const fn topological_coder_order(&self) -> &[u64] {
        &self.topological_coder_order
    }

    /// Returns the folder output CRC, when present.
    #[must_use]
    pub const fn crc(&self) -> Option<u32> {
        self.crc
    }

    /// Returns logical member substreams in order.
    #[must_use]
    pub const fn substreams(&self) -> &[Substream] {
        &self.substreams
    }

    /// Returns memory accounted from known coder properties.
    #[must_use]
    pub const fn dictionary_bytes(&self) -> u64 {
        self.dictionary_bytes
    }

    /// Returns the first packed-stream index assigned to this folder.
    #[must_use]
    pub const fn first_pack_stream(&self) -> u64 {
        self.first_pack_stream
    }
}

/// One coder with validated global input and output port ranges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coder {
    method_id: Box<[u8]>,
    input_start: u64,
    input_count: u64,
    output_start: u64,
    output_count: u64,
    properties: Box<[u8]>,
    dictionary_bytes: Option<u64>,
}

impl Coder {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        method_id: Box<[u8]>,
        input_start: u64,
        input_count: u64,
        output_start: u64,
        output_count: u64,
        properties: Box<[u8]>,
        dictionary_bytes: Option<u64>,
    ) -> Self {
        Self {
            method_id,
            input_start,
            input_count,
            output_start,
            output_count,
            properties,
            dictionary_bytes,
        }
    }

    /// Returns the exact method identifier.
    #[must_use]
    pub const fn method_id(&self) -> &[u8] {
        &self.method_id
    }

    /// Returns the first input port owned by this coder.
    #[must_use]
    pub const fn input_start(&self) -> u64 {
        self.input_start
    }

    /// Returns this coder's input-port count.
    #[must_use]
    pub const fn input_count(&self) -> u64 {
        self.input_count
    }

    /// Returns the first output port owned by this coder.
    #[must_use]
    pub const fn output_start(&self) -> u64 {
        self.output_start
    }

    /// Returns this coder's output-port count.
    #[must_use]
    pub const fn output_count(&self) -> u64 {
        self.output_count
    }

    /// Returns the exact coder property bytes.
    #[must_use]
    pub const fn properties(&self) -> &[u8] {
        &self.properties
    }

    /// Returns dictionary memory derived from known properties, when applicable.
    #[cfg(feature = "unstable-internals")]
    #[must_use]
    pub const fn dictionary_bytes(&self) -> Option<u64> {
        self.dictionary_bytes
    }
}

/// One validated coder output-to-input binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindPair {
    input_index: u64,
    output_index: u64,
}

impl BindPair {
    pub(crate) const fn new(input_index: u64, output_index: u64) -> Self {
        Self {
            input_index,
            output_index,
        }
    }

    /// Returns the bound input port.
    #[must_use]
    pub const fn input_index(self) -> u64 {
        self.input_index
    }

    /// Returns the bound output port.
    #[must_use]
    pub const fn output_index(self) -> u64 {
        self.output_index
    }
}

/// One logical unpacked substream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Substream {
    size: Option<u64>,
    crc: Option<u32>,
}

impl Substream {
    pub(crate) const fn new(size: Option<u64>, crc: Option<u32>) -> Self {
        Self { size, crc }
    }

    /// Returns the unpacked size, preserving an unknown size as `None`.
    #[must_use]
    pub const fn size(self) -> Option<u64> {
        self.size
    }

    /// Returns the substream CRC, when present.
    #[must_use]
    pub const fn crc(self) -> Option<u32> {
        self.crc
    }
}

#[cfg(test)]
mod tests {
    use super::{EntryKind, FileEntry};

    #[test]
    fn unix_extension_attributes_identify_symlinks() {
        let symlink = FileEntry::new(
            None,
            true,
            false,
            false,
            None,
            None,
            None,
            Some(0xa1ff_8000),
            None,
            None,
        );
        assert_eq!(symlink.unix_mode(), Some(0o120_777));
        assert!(symlink.is_symlink());

        let windows_only = FileEntry::new(
            None,
            true,
            false,
            false,
            None,
            None,
            None,
            Some(0x20),
            None,
            None,
        );
        assert_eq!(windows_only.unix_mode(), None);
        assert!(!windows_only.is_symlink());
    }

    #[test]
    fn entry_kind_and_empty_size_do_not_use_sentinels() {
        let empty = FileEntry::new(None, false, true, false, None, None, None, None, None, None);
        assert_eq!(empty.kind(), EntryKind::File);
        assert_eq!(empty.size(), Some(0));
        assert_eq!(empty.crc32(), None);

        let directory = FileEntry::new(
            None, false, false, false, None, None, None, None, None, None,
        );
        assert_eq!(directory.kind(), EntryKind::Directory);
        assert_eq!(directory.size(), None);
    }
}
