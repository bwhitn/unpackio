//! Filesystem-path policy kept separate from archive metadata and stream mapping.

use std::fmt;

/// Why a raw archive name is unsafe for automatic filesystem use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnsafePathReason {
    /// The name is empty.
    Empty,
    /// The name contains a NUL character.
    Nul,
    /// The name starts at a POSIX or Windows root.
    Absolute,
    /// The name has a Windows UNC or device-path prefix.
    Unc,
    /// The name has a Windows drive prefix, including drive-relative paths.
    Drive,
    /// A component is exactly `..`.
    Traversal,
}

impl fmt::Display for UnsafePathReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "archive path is empty",
            Self::Nul => "archive path contains NUL",
            Self::Absolute => "archive path is absolute",
            Self::Unc => "archive path has a UNC or device prefix",
            Self::Drive => "archive path has a drive prefix",
            Self::Traversal => "archive path contains a parent component",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for UnsafePathReason {}

const fn is_byte_separator(byte: u8) -> bool {
    byte == b'/' || byte == b'\\'
}

fn is_u16_separator(unit: u16) -> bool {
    unit == u16::from(b'/') || unit == u16::from(b'\\')
}

/// Validates a decoded archive path without normalizing or changing it.
///
/// Both slash styles are treated as separators so the result is portable to
/// Windows. This function never participates in file-to-stream mapping.
pub fn validate_safe_path(path: &str) -> Result<(), UnsafePathReason> {
    if path.is_empty() {
        return Err(UnsafePathReason::Empty);
    }
    if path.bytes().any(|byte| byte == 0) {
        return Err(UnsafePathReason::Nul);
    }

    let mut bytes = path.bytes();
    let Some(first) = bytes.next() else {
        return Err(UnsafePathReason::Empty);
    };
    let second = bytes.next();

    if is_byte_separator(first) {
        return if second.is_some_and(is_byte_separator) {
            Err(UnsafePathReason::Unc)
        } else {
            Err(UnsafePathReason::Absolute)
        };
    }
    if first.is_ascii_alphabetic() && second == Some(b':') {
        return Err(UnsafePathReason::Drive);
    }
    if path
        .as_bytes()
        .split(|byte| is_byte_separator(*byte))
        .any(|component| component == b"..")
    {
        return Err(UnsafePathReason::Traversal);
    }

    Ok(())
}

/// Validates raw UTF-16 archive-name code units without lossy conversion.
///
/// Unpaired surrogates remain metadata and are not rewritten. This check only
/// classifies path structure; a later filesystem adapter must additionally
/// determine whether a safe name is representable on its target platform.
pub fn validate_safe_utf16_path(path: &[u16]) -> Result<(), UnsafePathReason> {
    if path.is_empty() {
        return Err(UnsafePathReason::Empty);
    }
    if path.contains(&0) {
        return Err(UnsafePathReason::Nul);
    }

    let mut units = path.iter().copied();
    let Some(first) = units.next() else {
        return Err(UnsafePathReason::Empty);
    };
    let second = units.next();

    if is_u16_separator(first) {
        return if second.is_some_and(is_u16_separator) {
            Err(UnsafePathReason::Unc)
        } else {
            Err(UnsafePathReason::Absolute)
        };
    }
    let ascii_a = u16::from(b'a');
    let ascii_z = u16::from(b'z');
    let ascii_upper_a = u16::from(b'A');
    let ascii_upper_z = u16::from(b'Z');
    let is_ascii_letter =
        (ascii_a..=ascii_z).contains(&first) || (ascii_upper_a..=ascii_upper_z).contains(&first);
    if is_ascii_letter && second == Some(u16::from(b':')) {
        return Err(UnsafePathReason::Drive);
    }

    let parent = [u16::from(b'.'), u16::from(b'.')];
    if path
        .split(|unit| is_u16_separator(*unit))
        .any(|component| component == parent)
    {
        return Err(UnsafePathReason::Traversal);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UnsafePathReason, validate_safe_path, validate_safe_utf16_path};

    #[test]
    fn accepts_relative_unicode_without_rewriting() {
        assert_eq!(validate_safe_path("資料/naïve.txt"), Ok(()));
        assert_eq!(validate_safe_path("dir\\file.txt"), Ok(()));
    }

    #[test]
    fn rejects_required_dangerous_path_classes() {
        let cases = [
            ("", UnsafePathReason::Empty),
            ("../escape", UnsafePathReason::Traversal),
            ("safe/../../escape", UnsafePathReason::Traversal),
            ("safe\\..\\escape", UnsafePathReason::Traversal),
            ("/absolute", UnsafePathReason::Absolute),
            ("\\absolute", UnsafePathReason::Absolute),
            ("C:\\drive", UnsafePathReason::Drive),
            ("c:drive-relative", UnsafePathReason::Drive),
            ("\\\\server\\share", UnsafePathReason::Unc),
            ("//server/share", UnsafePathReason::Unc),
            ("nul\0name", UnsafePathReason::Nul),
        ];

        for (path, reason) in cases {
            assert_eq!(validate_safe_path(path), Err(reason), "{path:?}");
        }
    }

    #[test]
    fn utf16_validation_preserves_unpaired_surrogates_as_metadata() {
        let unpaired_surrogate = [0xd800_u16];
        assert_eq!(validate_safe_utf16_path(&unpaired_surrogate), Ok(()));

        let traversal = [
            u16::from(b'a'),
            u16::from(b'/'),
            u16::from(b'.'),
            u16::from(b'.'),
            u16::from(b'/'),
            u16::from(b'b'),
        ];
        assert_eq!(
            validate_safe_utf16_path(&traversal),
            Err(UnsafePathReason::Traversal)
        );
    }
}
