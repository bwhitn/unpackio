#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use unpackio::{validate_safe_path, validate_safe_utf16_path};

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = validate_safe_path(path);
    }

    let mut units = Vec::with_capacity(data.len() / 2);
    for pair in data.chunks_exact(2) {
        let mut bytes = pair.iter().copied();
        if let (Some(low), Some(high)) = (bytes.next(), bytes.next()) {
            units.push(u16::from_le_bytes([low, high]));
        }
    }
    let _ = validate_safe_utf16_path(&units);
});
