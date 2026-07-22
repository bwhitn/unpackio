//! Per-archive zeroizing password storage.

use std::io;

use zeroize::Zeroizing;

use crate::{Error, Result, parse_util::format_error};

pub(crate) struct Password {
    utf16le: Zeroizing<Vec<u8>>,
}

impl Password {
    pub(crate) fn new(password: &str) -> Result<Self> {
        let capacity = password
            .encode_utf16()
            .count()
            .checked_mul(2)
            .ok_or_else(|| format_error("password UTF-16 length overflows"))?;
        let mut utf16le = Vec::new();
        utf16le.try_reserve_exact(capacity).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "password allocation failed",
            ))
        })?;
        for unit in password.encode_utf16() {
            utf16le.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(Self {
            utf16le: Zeroizing::new(utf16le),
        })
    }

    pub(crate) fn utf16le(&self) -> &[u8] {
        &self.utf16le
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.utf16le.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::Password;
    use crate::Result;

    #[test]
    fn password_uses_utf16_little_endian() -> Result<()> {
        let password = Password::new("A\u{1f642}")?;
        assert_eq!(password.utf16le(), [0x41, 0, 0x3d, 0xd8, 0x42, 0xde]);
        Ok(())
    }
}
