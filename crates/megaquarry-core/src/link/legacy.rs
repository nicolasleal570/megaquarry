//! MegaDownloader `mega://enc?` / `mega://fenc?` links: AES-256-CBC with
//! well-known keys.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};

use super::LinkError;
use crate::crypto::b64url_decode;

const IV: [u8; 16] = [
    0x79, 0xF1, 0x0A, 0x01, 0x84, 0x4A, 0x0B, 0x27, 0xFF, 0x5B, 0x2D, 0x4E, 0x0E, 0xD3, 0x16, 0x3E,
];
const KEY_ENC: [u8; 32] = *b"k1o6Al-1kz?!z05yXXXXXXXXXXXXXXXX";
const KEY_ENC2: [u8; 32] = [
    0xED, 0x1F, 0x4C, 0x20, 0x0B, 0x35, 0x13, 0x98, 0x06, 0xB2, 0x60, 0x56, 0x3B, 0x3D, 0x38, 0x76,
    0xF0, 0x11, 0xB4, 0x75, 0x0F, 0x3A, 0x1A, 0x4A, 0x5E, 0xFD, 0x0B, 0xBE, 0x67, 0x55, 0x4B, 0x44,
];

pub(super) fn is_encrypted(text: &str) -> bool {
    text.starts_with("mega://enc") || text.starts_with("mega://fenc")
}

/// Decrypts the link into its legacy `https://mega.nz/#...` form.
pub(super) fn decrypt(text: &str) -> Result<String, LinkError> {
    let body = text
        .strip_prefix("mega://")
        .ok_or(LinkError::Unrecognized)?;
    let (folder, body) = match body.strip_prefix('f') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    let (kind, payload) = body.split_once('?').ok_or(LinkError::Unrecognized)?;
    let key = match kind {
        "enc" => &KEY_ENC,
        "enc2" => &KEY_ENC2,
        _ => return Err(LinkError::Unrecognized),
    };

    let mut data = b64url_decode(payload).map_err(|_| LinkError::Unrecognized)?;
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(LinkError::Unrecognized);
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut prev = IV;
    for block in data.chunks_exact_mut(16) {
        let current: [u8; 16] = block.try_into().expect("16 bytes");
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        prev = current;
    }

    let plain = String::from_utf8(data).map_err(|_| LinkError::Unrecognized)?;
    let plain = plain.trim_matches(|c: char| c.is_whitespace() || c.is_control());
    Ok(format!(
        "https://mega.nz/#{}{plain}",
        if folder { "F" } else { "" }
    ))
}
