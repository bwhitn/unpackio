//! ZIP encryption adapters. No primitive is implemented here.

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{KeyIvInit, StreamCipher},
};
use ctr::Ctr128LE;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{CONTROL_CHUNK_SIZE, ParseControl, check_limit, try_reserve, usize_to_u64},
};

const ZIP_CRYPTO_HEADER_BYTES: usize = 12;
const WINZIP_AES_ROUNDS: u64 = 1_000;
const WINZIP_AES_AUTH_BYTES: usize = 10;
const WINZIP_AES_VERIFIER_BYTES: usize = 2;
const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

pub(super) struct ZipPassword {
    bytes: Zeroizing<Vec<u8>>,
}

impl ZipPassword {
    pub(super) fn new(password: &[u8]) -> Result<Self> {
        let mut bytes = Vec::new();
        try_reserve(&mut bytes, password.len())?;
        bytes.extend_from_slice(password);
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.bytes.capacity()
    }
}

struct ZipCryptoKeys {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl ZipCryptoKeys {
    fn new(password: &[u8], control: &mut ParseControl<'_>) -> Result<Self> {
        let mut keys = Self {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        };
        for chunk in password.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "ZIP password length is not representable as u64",
            )?)?;
            for byte in chunk.iter().copied() {
                keys.update(byte);
            }
        }
        Ok(keys)
    }

    fn update(&mut self, byte: u8) {
        self.key0 = crc32_byte(self.key0, byte);
        self.key1 = self
            .key1
            .wrapping_add(self.key0 & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        let [high, _, _, _] = self.key1.to_be_bytes();
        self.key2 = crc32_byte(self.key2, high);
    }

    fn decrypt_byte(&mut self, byte: u8) -> u8 {
        let temporary = self.key2 | 2;
        let [_, mask, _, _] = temporary.wrapping_mul(temporary ^ 1).to_le_bytes();
        let plaintext = byte ^ mask;
        self.update(plaintext);
        plaintext
    }
}

impl Drop for ZipCryptoKeys {
    fn drop(&mut self) {
        self.key0.zeroize();
        self.key1.zeroize();
        self.key2.zeroize();
    }
}

fn crc32_byte(mut value: u32, byte: u8) -> u32 {
    value ^= u32::from(byte);
    for _ in 0..8 {
        value = if value & 1 == 0 {
            value >> 1
        } else {
            (value >> 1) ^ CRC32_POLYNOMIAL
        };
    }
    value
}

pub(super) fn decrypt_zipcrypto(
    input: &[u8],
    password: Option<&ZipPassword>,
    check_byte: u8,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let password = password.ok_or(Error::PasswordRequired)?;
    let header = input
        .get(..ZIP_CRYPTO_HEADER_BYTES)
        .ok_or_else(|| zip_format("traditional encryption header is truncated"))?;
    let payload = input
        .get(ZIP_CRYPTO_HEADER_BYTES..)
        .ok_or_else(|| zip_format("traditional encryption payload is truncated"))?;
    let mut keys = ZipCryptoKeys::new(password.as_bytes(), control)?;
    let mut last = None;
    for byte in header.iter().copied() {
        control.checkpoint(1)?;
        last = Some(keys.decrypt_byte(byte));
    }
    if last != Some(check_byte) {
        return Err(Error::WrongPasswordOrCorrupt);
    }
    let mut output = Vec::new();
    try_reserve(&mut output, payload.len())?;
    for chunk in payload.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "ZIP encrypted chunk length is not representable as u64",
        )?)?;
        output.extend(chunk.iter().copied().map(|byte| keys.decrypt_byte(byte)));
    }
    Ok(output)
}

fn check_winzip_kdf_limit(limits: Limits) -> Result<()> {
    let maximum =
        1_u64
            .checked_shl(u32::from(limits.max_kdf_power()))
            .ok_or(Error::LimitExceeded {
                limit: LimitKind::KdfPower,
                requested: WINZIP_AES_ROUNDS,
                maximum: u64::MAX,
            })?;
    check_limit(WINZIP_AES_ROUNDS, maximum, LimitKind::KdfPower)
}

fn apply_stream_cipher(
    mut cipher: impl StreamCipher,
    plaintext: &mut [u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    for chunk in plaintext.chunks_mut(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "WinZip AES decryption chunk is not representable as u64",
        )?)?;
        cipher.apply_keystream(chunk);
    }
    Ok(())
}

fn apply_aes_ctr(key: &[u8], plaintext: &mut [u8], control: &mut ParseControl<'_>) -> Result<()> {
    let mut counter = [0_u8; 16];
    if let Some(first) = counter.first_mut() {
        *first = 1;
    }
    match key.len() {
        16 => apply_stream_cipher(
            Ctr128LE::<Aes128>::new_from_slices(key, &counter)
                .map_err(|_| zip_format("WinZip AES-128 key has an invalid length"))?,
            plaintext,
            control,
        )?,
        24 => apply_stream_cipher(
            Ctr128LE::<Aes192>::new_from_slices(key, &counter)
                .map_err(|_| zip_format("WinZip AES-192 key has an invalid length"))?,
            plaintext,
            control,
        )?,
        32 => apply_stream_cipher(
            Ctr128LE::<Aes256>::new_from_slices(key, &counter)
                .map_err(|_| zip_format("WinZip AES-256 key has an invalid length"))?,
            plaintext,
            control,
        )?,
        _ => return Err(zip_format("WinZip AES key strength is invalid")),
    }
    Ok(())
}

pub(super) fn decrypt_winzip_aes(
    input: &[u8],
    password: Option<&ZipPassword>,
    key_bytes: usize,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let password = password.ok_or(Error::PasswordRequired)?;
    let salt_bytes = key_bytes
        .checked_div(2)
        .ok_or_else(|| zip_format("WinZip AES salt length calculation failed"))?;
    let overhead = salt_bytes
        .checked_add(WINZIP_AES_VERIFIER_BYTES)
        .and_then(|size| size.checked_add(WINZIP_AES_AUTH_BYTES))
        .ok_or_else(|| zip_format("WinZip AES overhead overflows"))?;
    if input.len() < overhead {
        return Err(zip_format("WinZip AES payload is truncated"));
    }
    let verifier_start = salt_bytes;
    let ciphertext_start = verifier_start
        .checked_add(WINZIP_AES_VERIFIER_BYTES)
        .ok_or_else(|| zip_format("WinZip AES payload offset overflows"))?;
    let auth_start = input
        .len()
        .checked_sub(WINZIP_AES_AUTH_BYTES)
        .ok_or_else(|| zip_format("WinZip AES authentication offset underflows"))?;
    let salt = input
        .get(..salt_bytes)
        .ok_or_else(|| zip_format("WinZip AES salt is truncated"))?;
    let verifier = input
        .get(verifier_start..ciphertext_start)
        .ok_or_else(|| zip_format("WinZip AES password verifier is truncated"))?;
    let ciphertext = input
        .get(ciphertext_start..auth_start)
        .ok_or_else(|| zip_format("WinZip AES ciphertext range is invalid"))?;
    let authentication = input
        .get(auth_start..)
        .ok_or_else(|| zip_format("WinZip AES authentication code is truncated"))?;

    check_winzip_kdf_limit(limits)?;
    let derived_bytes = key_bytes
        .checked_mul(2)
        .and_then(|size| size.checked_add(WINZIP_AES_VERIFIER_BYTES))
        .ok_or_else(|| zip_format("WinZip AES derived-key length overflows"))?;
    let mut derived = Zeroizing::new(Vec::new());
    try_reserve(&mut derived, derived_bytes)?;
    derived.resize(derived_bytes, 0);
    control.checkpoint(
        WINZIP_AES_ROUNDS
            .checked_mul(4)
            .ok_or_else(|| zip_format("WinZip AES work accounting overflows"))?,
    )?;
    pbkdf2_hmac::<Sha1>(
        password.as_bytes(),
        salt,
        u32::try_from(WINZIP_AES_ROUNDS)
            .map_err(|_| zip_format("WinZip AES round count is not representable"))?,
        &mut derived,
    );
    let authentication_start = key_bytes;
    let verifier_key_start = key_bytes
        .checked_mul(2)
        .ok_or_else(|| zip_format("WinZip AES key offset overflows"))?;
    let encryption_key = derived
        .get(..authentication_start)
        .ok_or_else(|| zip_format("WinZip AES encryption key is truncated"))?;
    let authentication_key = derived
        .get(authentication_start..verifier_key_start)
        .ok_or_else(|| zip_format("WinZip AES authentication key is truncated"))?;
    let derived_verifier = derived
        .get(verifier_key_start..)
        .ok_or_else(|| zip_format("WinZip AES password verifier is truncated"))?;
    if derived_verifier != verifier {
        return Err(Error::WrongPasswordOrCorrupt);
    }

    control.checkpoint(usize_to_u64(
        ciphertext.len(),
        "WinZip AES ciphertext length is not representable as u64",
    )?)?;
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(authentication_key)
        .map_err(|_| zip_format("WinZip AES authentication key is invalid"))?;
    mac.update(ciphertext);
    if mac.verify_truncated_left(authentication).is_err() {
        return Err(Error::WrongPasswordOrCorrupt);
    }

    let mut plaintext = Vec::new();
    try_reserve(&mut plaintext, ciphertext.len())?;
    plaintext.extend_from_slice(ciphertext);
    apply_aes_ctr(encryption_key, &mut plaintext, control)?;
    Ok(plaintext)
}

fn zip_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("ZIP: {detail}"),
    }
}
