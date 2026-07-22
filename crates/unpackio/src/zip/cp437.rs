//! IBM code page 437 decoding for ZIP names without the UTF-8 flag.

use std::io;

use crate::{Error, Result};

const HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', ' ',
];

pub(super) fn decode(bytes: &[u8]) -> Result<String> {
    let mut decoded = String::new();
    decoded.try_reserve(bytes.len()).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "ZIP name allocation failed",
        ))
    })?;
    for byte in bytes.iter().copied() {
        if byte < 0x80 {
            decoded.push(char::from(byte));
            continue;
        }
        let index = usize::from(byte.checked_sub(0x80).ok_or_else(|| Error::Format {
            detail: String::from("ZIP CP437 name byte is out of range"),
        })?);
        let character = HIGH.get(index).copied().ok_or_else(|| Error::Format {
            detail: String::from("ZIP CP437 name byte is out of range"),
        })?;
        decoded.push(character);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_ascii_and_high_cp437() -> crate::Result<()> {
        assert_eq!(decode(b"plain.txt")?, "plain.txt");
        assert_eq!(decode(&[0x82, b'.', b't', b'x', b't'])?, "é.txt");
        Ok(())
    }
}
