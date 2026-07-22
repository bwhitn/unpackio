//! 7z AES-256-CBC and SHA-256 key derivation.

use aes::{
    Aes256,
    cipher::{Block, BlockModeDecrypt, KeyIvInit},
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, format_error, usize_to_u64},
    password::Password,
};

const BLOCK_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
const DIRECT_KDF_POWER: u8 = 0x3f;

struct AesProperties<'properties> {
    kdf_power: u8,
    salt: &'properties [u8],
    iv: Zeroizing<[u8; BLOCK_BYTES]>,
}

fn parse_properties(properties: &[u8], limits: Limits) -> Result<AesProperties<'_>> {
    let first = properties
        .first()
        .copied()
        .ok_or_else(|| format_error("AES properties are missing the first byte"))?;
    let second = properties
        .get(1)
        .copied()
        .ok_or_else(|| format_error("AES properties are missing the second byte"))?;
    let salt_size = usize::from((first >> 7) & 1)
        .checked_add(usize::from(second >> 4))
        .ok_or_else(|| format_error("AES salt size overflows"))?;
    let iv_size = usize::from((first >> 6) & 1)
        .checked_add(usize::from(second & 0x0f))
        .ok_or_else(|| format_error("AES IV size overflows"))?;
    let salt_start = 2_usize;
    let salt_end = salt_start
        .checked_add(salt_size)
        .ok_or_else(|| format_error("AES salt range overflows"))?;
    let iv_end = salt_end
        .checked_add(iv_size)
        .ok_or_else(|| format_error("AES IV range overflows"))?;
    if iv_end != properties.len() {
        return Err(format_error("AES properties were not consumed exactly"));
    }
    let salt = properties
        .get(salt_start..salt_end)
        .ok_or_else(|| format_error("AES salt range is truncated"))?;
    let source_iv = properties
        .get(salt_end..iv_end)
        .ok_or_else(|| format_error("AES IV range is truncated"))?;
    let mut iv = Zeroizing::new([0_u8; BLOCK_BYTES]);
    iv.get_mut(..iv_size)
        .ok_or_else(|| format_error("AES IV is longer than one block"))?
        .copy_from_slice(source_iv);
    let kdf_power = first & 0x3f;
    if kdf_power != DIRECT_KDF_POWER && kdf_power > limits.max_kdf_power() {
        return Err(Error::LimitExceeded {
            limit: LimitKind::KdfPower,
            requested: u64::from(kdf_power),
            maximum: u64::from(limits.max_kdf_power()),
        });
    }
    Ok(AesProperties {
        kdf_power,
        salt,
        iv,
    })
}

fn copy_key_material(destination: &mut [u8], material: &[u8], written: &mut usize) -> Result<()> {
    if *written >= destination.len() || material.is_empty() {
        return Ok(());
    }
    let remaining = destination
        .len()
        .checked_sub(*written)
        .ok_or_else(|| format_error("AES key position exceeds its buffer"))?;
    let count = remaining.min(material.len());
    let end = (*written)
        .checked_add(count)
        .ok_or_else(|| format_error("AES key position overflows"))?;
    destination
        .get_mut(*written..end)
        .ok_or_else(|| format_error("AES key destination range is invalid"))?
        .copy_from_slice(
            material
                .get(..count)
                .ok_or_else(|| format_error("AES key source range is invalid"))?,
        );
    *written = end;
    Ok(())
}

fn derive_key(
    properties: &AesProperties<'_>,
    password: &Password,
    control: &mut ParseControl<'_>,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    if properties.kdf_power == DIRECT_KDF_POWER {
        let mut written = 0_usize;
        copy_key_material(&mut *key, properties.salt, &mut written)?;
        copy_key_material(&mut *key, password.utf16le(), &mut written)?;
        control.checkpoint(usize_to_u64(
            written,
            "direct AES KDF work is not representable as u64",
        )?)?;
        return Ok(key);
    }
    let rounds = 1_u64
        .checked_shl(u32::from(properties.kdf_power))
        .ok_or_else(|| format_error("AES KDF round count overflows"))?;
    let round_work = properties
        .salt
        .len()
        .checked_add(password.utf16le().len())
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or_else(|| format_error("AES KDF work accounting overflows"))?;
    let round_work = usize_to_u64(round_work, "AES KDF work is not representable as u64")?;
    let mut hash = Sha256::new();
    for counter in 0..rounds {
        control.checkpoint(round_work)?;
        hash.update(properties.salt);
        hash.update(password.utf16le());
        hash.update(counter.to_le_bytes());
    }
    let mut digest = hash.finalize();
    key.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Ok(key)
}

pub(crate) fn decode_aes(
    mut input: Vec<u8>,
    properties: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    password: Option<&Password>,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let password = password.ok_or(Error::PasswordRequired)?;
    let properties = parse_properties(properties, limits)?;
    let expected = expected.ok_or_else(|| Error::UnsupportedFeature {
        feature: String::from("aes-unknown-unpacked-size"),
    })?;
    check_limit(expected, maximum, LimitKind::TotalOutputBytes)?;
    let expected_length = usize::try_from(expected)
        .map_err(|_| format_error("AES output size is not representable on this platform"))?;
    if expected_length > input.len() {
        return Err(format_error("AES output size exceeds its encrypted input"));
    }
    if input.len() % BLOCK_BYTES != 0 {
        return Err(format_error("AES encrypted input is not block aligned"));
    }
    let key = derive_key(&properties, password, control)?;
    let mut decryptor = cbc::Decryptor::<Aes256>::new_from_slices(&*key, &*properties.iv)
        .map_err(|_| format_error("AES key or IV length is invalid"))?;
    for chunk in input.chunks_exact_mut(BLOCK_BYTES) {
        control.checkpoint(BLOCK_BYTES as u64)?;
        let block: &mut Block<cbc::Decryptor<Aes256>> = chunk
            .try_into()
            .map_err(|_| format_error("AES block has the wrong length"))?;
        decryptor.decrypt_block(block);
    }
    input.truncate(expected_length);
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::{DIRECT_KDF_POWER, decode_aes, derive_key, parse_properties};
    use crate::{
        CancellationToken, Error, LimitKind, Limits, Result, WorkBudget, parse_util::ParseControl,
    };
    use zeroize::Zeroize;

    #[test]
    fn direct_kdf_concatenates_salt_and_utf16_password() -> Result<()> {
        let password = crate::password::Password::new("ab")?;
        let properties = [DIRECT_KDF_POWER | 0x80, 0x10, 0x55, 0x66];
        let parsed = parse_properties(&properties, Limits::default())?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let mut key = derive_key(&parsed, &password, &mut control)?;
        assert_eq!(key.get(..6), Some(&[0x55, 0x66, b'a', 0, b'b', 0][..]));
        key.zeroize();
        Ok(())
    }

    #[test]
    fn kdf_power_limit_precedes_hash_work() -> Result<()> {
        let password = crate::password::Password::new("secret")?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = decode_aes(
            vec![0; 16],
            &[25, 0],
            Some(16),
            16,
            Limits::builder().max_kdf_power(24).build(),
            Some(&password),
            &mut control,
        );
        assert!(matches!(
            result,
            Err(Error::LimitExceeded {
                limit: LimitKind::KdfPower,
                requested: 25,
                maximum: 24,
            })
        ));
        Ok(())
    }

    #[test]
    fn missing_password_and_block_truncation_are_typed() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let missing = decode_aes(
            vec![0; 16],
            &[DIRECT_KDF_POWER, 0],
            Some(16),
            16,
            Limits::default(),
            None,
            &mut control,
        );
        assert!(matches!(missing, Err(Error::PasswordRequired)));

        let password = crate::password::Password::new("secret")?;
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let truncated = decode_aes(
            vec![0; 15],
            &[DIRECT_KDF_POWER, 0],
            Some(15),
            15,
            Limits::default(),
            Some(&password),
            &mut control,
        );
        assert!(matches!(truncated, Err(Error::Format { .. })));
        Ok(())
    }
}
