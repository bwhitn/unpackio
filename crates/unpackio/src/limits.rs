//! Configurable resource limits checked before allocation or expensive work.

/// Per-archive resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    max_header_bytes: u64,
    max_files: u64,
    max_folders: u64,
    max_coders_per_folder: u64,
    max_total_coders: u64,
    max_streams_per_folder: u64,
    max_total_streams: u64,
    max_stream_frames: u64,
    max_substreams: u64,
    max_header_properties: u64,
    max_coder_property_bytes: u64,
    max_name_bytes_per_entry: u64,
    max_total_name_bytes: u64,
    max_dictionary_bytes: u64,
    max_entry_output_bytes: u64,
    max_total_output_bytes: u64,
    max_volumes: u64,
    max_total_input_bytes: u64,
    max_kdf_power: u8,
    max_recursion_depth: u64,
    sfx_scan_limit: u64,
}

impl Limits {
    /// The required default limit set.
    pub const DEFAULT: Self = Self {
        max_header_bytes: 64 * 1024 * 1024,
        max_files: 100_000,
        max_folders: 100_000,
        max_coders_per_folder: 32,
        max_total_coders: 100_000,
        max_streams_per_folder: 1024,
        max_total_streams: 200_000,
        max_stream_frames: 100_000,
        max_substreams: 100_000,
        max_header_properties: 100_000,
        max_coder_property_bytes: 1024 * 1024,
        max_name_bytes_per_entry: 1024 * 1024,
        max_total_name_bytes: 64 * 1024 * 1024,
        max_dictionary_bytes: 256 * 1024 * 1024,
        max_entry_output_bytes: 2 * 1024 * 1024 * 1024,
        max_total_output_bytes: 8 * 1024 * 1024 * 1024,
        max_volumes: 1024,
        max_total_input_bytes: 64 * 1024 * 1024 * 1024,
        max_kdf_power: 24,
        max_recursion_depth: 64,
        sfx_scan_limit: 1024 * 1024,
    };

    /// Starts a builder initialized with the required defaults.
    #[must_use]
    pub const fn builder() -> LimitsBuilder {
        LimitsBuilder {
            limits: Self::DEFAULT,
        }
    }

    /// Maximum raw or decoded header bytes.
    #[must_use]
    pub const fn max_header_bytes(self) -> u64 {
        self.max_header_bytes
    }

    /// Maximum file records.
    #[must_use]
    pub const fn max_files(self) -> u64 {
        self.max_files
    }

    /// Maximum folders.
    #[must_use]
    pub const fn max_folders(self) -> u64 {
        self.max_folders
    }

    /// Maximum coders in one folder.
    #[must_use]
    pub const fn max_coders_per_folder(self) -> u64 {
        self.max_coders_per_folder
    }

    /// Maximum coders across the archive.
    #[must_use]
    pub const fn max_total_coders(self) -> u64 {
        self.max_total_coders
    }

    /// Maximum input plus output stream ports in one folder.
    #[must_use]
    pub const fn max_streams_per_folder(self) -> u64 {
        self.max_streams_per_folder
    }

    /// Maximum input plus output stream ports across parsed stream sections.
    #[must_use]
    pub const fn max_total_streams(self) -> u64 {
        self.max_total_streams
    }

    /// Maximum data and skippable frames in one compressed stream.
    #[must_use]
    pub const fn max_stream_frames(self) -> u64 {
        self.max_stream_frames
    }

    /// Maximum substreams across parsed stream sections.
    #[must_use]
    pub const fn max_substreams(self) -> u64 {
        self.max_substreams
    }

    /// Maximum length-delimited properties across one next header.
    #[must_use]
    pub const fn max_header_properties(self) -> u64 {
        self.max_header_properties
    }

    /// Maximum property bytes for one coder.
    #[must_use]
    pub const fn max_coder_property_bytes(self) -> u64 {
        self.max_coder_property_bytes
    }

    /// Maximum encoded name bytes for one entry.
    #[must_use]
    pub const fn max_name_bytes_per_entry(self) -> u64 {
        self.max_name_bytes_per_entry
    }

    /// Maximum encoded name bytes across the archive.
    #[must_use]
    pub const fn max_total_name_bytes(self) -> u64 {
        self.max_total_name_bytes
    }

    /// Maximum accounted decoder dictionary bytes.
    #[must_use]
    pub const fn max_dictionary_bytes(self) -> u64 {
        self.max_dictionary_bytes
    }

    /// Maximum decoded bytes for one entry.
    #[must_use]
    pub const fn max_entry_output_bytes(self) -> u64 {
        self.max_entry_output_bytes
    }

    /// Maximum decoded bytes across an operation.
    #[must_use]
    pub const fn max_total_output_bytes(self) -> u64 {
        self.max_total_output_bytes
    }

    /// Maximum number of archive volumes.
    #[must_use]
    pub const fn max_volumes(self) -> u64 {
        self.max_volumes
    }

    /// Maximum bytes across all archive volumes.
    #[must_use]
    pub const fn max_total_input_bytes(self) -> u64 {
        self.max_total_input_bytes
    }

    /// Maximum AES key-derivation exponent.
    #[must_use]
    pub const fn max_kdf_power(self) -> u8 {
        self.max_kdf_power
    }

    /// Maximum nested parser or encoded-header recursion depth.
    #[must_use]
    pub const fn max_recursion_depth(self) -> u64 {
        self.max_recursion_depth
    }

    /// Maximum bytes searched for an embedded 7z signature.
    #[must_use]
    pub const fn sfx_scan_limit(self) -> u64 {
        self.sfx_scan_limit
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Builder for overriding every [`Limits`] field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitsBuilder {
    limits: Limits,
}

impl LimitsBuilder {
    /// Overrides the raw or decoded header-byte limit.
    #[must_use]
    pub const fn max_header_bytes(mut self, value: u64) -> Self {
        self.limits.max_header_bytes = value;
        self
    }

    /// Overrides the file-record limit.
    #[must_use]
    pub const fn max_files(mut self, value: u64) -> Self {
        self.limits.max_files = value;
        self
    }

    /// Overrides the folder limit.
    #[must_use]
    pub const fn max_folders(mut self, value: u64) -> Self {
        self.limits.max_folders = value;
        self
    }

    /// Overrides the per-folder coder limit.
    #[must_use]
    pub const fn max_coders_per_folder(mut self, value: u64) -> Self {
        self.limits.max_coders_per_folder = value;
        self
    }

    /// Overrides the archive-wide coder limit.
    #[must_use]
    pub const fn max_total_coders(mut self, value: u64) -> Self {
        self.limits.max_total_coders = value;
        self
    }

    /// Overrides the per-folder stream-port limit.
    #[must_use]
    pub const fn max_streams_per_folder(mut self, value: u64) -> Self {
        self.limits.max_streams_per_folder = value;
        self
    }

    /// Overrides the total stream-port limit.
    #[must_use]
    pub const fn max_total_streams(mut self, value: u64) -> Self {
        self.limits.max_total_streams = value;
        self
    }

    /// Overrides the compressed-stream frame-count limit.
    #[must_use]
    pub const fn max_stream_frames(mut self, value: u64) -> Self {
        self.limits.max_stream_frames = value;
        self
    }

    /// Overrides the total substream limit.
    #[must_use]
    pub const fn max_substreams(mut self, value: u64) -> Self {
        self.limits.max_substreams = value;
        self
    }

    /// Overrides the length-delimited header-property count limit.
    #[must_use]
    pub const fn max_header_properties(mut self, value: u64) -> Self {
        self.limits.max_header_properties = value;
        self
    }

    /// Overrides the per-coder property-byte limit.
    #[must_use]
    pub const fn max_coder_property_bytes(mut self, value: u64) -> Self {
        self.limits.max_coder_property_bytes = value;
        self
    }

    /// Overrides the per-entry encoded-name limit.
    #[must_use]
    pub const fn max_name_bytes_per_entry(mut self, value: u64) -> Self {
        self.limits.max_name_bytes_per_entry = value;
        self
    }

    /// Overrides the archive-wide encoded-name limit.
    #[must_use]
    pub const fn max_total_name_bytes(mut self, value: u64) -> Self {
        self.limits.max_total_name_bytes = value;
        self
    }

    /// Overrides the accounted decoder dictionary limit.
    #[must_use]
    pub const fn max_dictionary_bytes(mut self, value: u64) -> Self {
        self.limits.max_dictionary_bytes = value;
        self
    }

    /// Overrides the per-entry decoded-output limit.
    #[must_use]
    pub const fn max_entry_output_bytes(mut self, value: u64) -> Self {
        self.limits.max_entry_output_bytes = value;
        self
    }

    /// Overrides the operation-wide decoded-output limit.
    #[must_use]
    pub const fn max_total_output_bytes(mut self, value: u64) -> Self {
        self.limits.max_total_output_bytes = value;
        self
    }

    /// Overrides the volume-count limit.
    #[must_use]
    pub const fn max_volumes(mut self, value: u64) -> Self {
        self.limits.max_volumes = value;
        self
    }

    /// Overrides the byte limit across all volumes.
    #[must_use]
    pub const fn max_total_input_bytes(mut self, value: u64) -> Self {
        self.limits.max_total_input_bytes = value;
        self
    }

    /// Overrides the AES key-derivation exponent limit.
    #[must_use]
    pub const fn max_kdf_power(mut self, value: u8) -> Self {
        self.limits.max_kdf_power = value;
        self
    }

    /// Overrides the parser and encoded-header recursion-depth limit.
    #[must_use]
    pub const fn max_recursion_depth(mut self, value: u64) -> Self {
        self.limits.max_recursion_depth = value;
        self
    }

    /// Overrides the SFX signature scan limit.
    #[must_use]
    pub const fn sfx_scan_limit(mut self, value: u64) -> Self {
        self.limits.sfx_scan_limit = value;
        self
    }

    /// Returns the configured limits.
    #[must_use]
    pub const fn build(self) -> Limits {
        self.limits
    }
}

impl Default for LimitsBuilder {
    fn default() -> Self {
        Limits::builder()
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn required_defaults_are_exact() {
        let limits = Limits::default();
        assert_eq!(limits.max_header_bytes(), 64 * 1024 * 1024);
        assert_eq!(limits.max_files(), 100_000);
        assert_eq!(limits.max_folders(), 100_000);
        assert_eq!(limits.max_coders_per_folder(), 32);
        assert_eq!(limits.max_total_coders(), 100_000);
        assert_eq!(limits.max_streams_per_folder(), 1024);
        assert_eq!(limits.max_total_streams(), 200_000);
        assert_eq!(limits.max_stream_frames(), 100_000);
        assert_eq!(limits.max_substreams(), 100_000);
        assert_eq!(limits.max_header_properties(), 100_000);
        assert_eq!(limits.max_coder_property_bytes(), 1024 * 1024);
        assert_eq!(limits.max_name_bytes_per_entry(), 1024 * 1024);
        assert_eq!(limits.max_total_name_bytes(), 64 * 1024 * 1024);
        assert_eq!(limits.max_dictionary_bytes(), 256 * 1024 * 1024);
        assert_eq!(limits.max_entry_output_bytes(), 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_total_output_bytes(), 8 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_volumes(), 1024);
        assert_eq!(limits.max_total_input_bytes(), 64 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_kdf_power(), 24);
        assert_eq!(limits.max_recursion_depth(), 64);
        assert_eq!(limits.sfx_scan_limit(), 1024 * 1024);
    }

    #[test]
    fn every_limit_has_a_builder_override() {
        let limits = Limits::builder()
            .max_header_bytes(1)
            .max_files(2)
            .max_folders(3)
            .max_coders_per_folder(4)
            .max_total_coders(5)
            .max_streams_per_folder(6)
            .max_total_streams(7)
            .max_stream_frames(8)
            .max_substreams(9)
            .max_header_properties(10)
            .max_coder_property_bytes(11)
            .max_name_bytes_per_entry(12)
            .max_total_name_bytes(13)
            .max_dictionary_bytes(14)
            .max_entry_output_bytes(15)
            .max_total_output_bytes(16)
            .max_volumes(17)
            .max_total_input_bytes(18)
            .max_kdf_power(19)
            .max_recursion_depth(20)
            .sfx_scan_limit(21)
            .build();

        assert_eq!(limits.max_header_bytes(), 1);
        assert_eq!(limits.max_files(), 2);
        assert_eq!(limits.max_folders(), 3);
        assert_eq!(limits.max_coders_per_folder(), 4);
        assert_eq!(limits.max_total_coders(), 5);
        assert_eq!(limits.max_streams_per_folder(), 6);
        assert_eq!(limits.max_total_streams(), 7);
        assert_eq!(limits.max_stream_frames(), 8);
        assert_eq!(limits.max_substreams(), 9);
        assert_eq!(limits.max_header_properties(), 10);
        assert_eq!(limits.max_coder_property_bytes(), 11);
        assert_eq!(limits.max_name_bytes_per_entry(), 12);
        assert_eq!(limits.max_total_name_bytes(), 13);
        assert_eq!(limits.max_dictionary_bytes(), 14);
        assert_eq!(limits.max_entry_output_bytes(), 15);
        assert_eq!(limits.max_total_output_bytes(), 16);
        assert_eq!(limits.max_volumes(), 17);
        assert_eq!(limits.max_total_input_bytes(), 18);
        assert_eq!(limits.max_kdf_power(), 19);
        assert_eq!(limits.max_recursion_depth(), 20);
        assert_eq!(limits.sfx_scan_limit(), 21);
    }
}
