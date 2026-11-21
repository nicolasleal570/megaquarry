use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

use super::CryptoError;

/// Encodes bytes as URL-safe base64 without padding, as MEGA does.
pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes URL-safe base64, accepting input with or without padding.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, CryptoError> {
    let trimmed = text.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(text))
        .map_err(|e| CryptoError::Base64(e.to_string()))
}

/// Splits bytes into big-endian 32-bit words, zero-padding the last word.
pub fn a32_from_bytes(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_be_bytes(word)
        })
        .collect()
}

/// Joins big-endian 32-bit words into bytes.
pub fn a32_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_be_bytes()).collect()
}
