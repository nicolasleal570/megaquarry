use serde_json::{Map, Value};

use super::CryptoError;
use super::cipher::{cbc_decrypt_zero_iv, cbc_encrypt_zero_iv};

const PREFIX: &[u8] = b"MEGA";

/// Decrypted node attributes: a JSON object whose `n` key holds the name.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Attributes(Map<String, Value>);

impl Attributes {
    /// Attributes holding only a node name.
    pub fn with_name(name: &str) -> Self {
        let mut map = Map::new();
        map.insert("n".into(), Value::String(name.into()));
        Self(map)
    }

    /// The node name, when present.
    pub fn name(&self) -> Option<&str> {
        self.0.get("n").and_then(Value::as_str)
    }
}

/// Encrypts attributes as `"MEGA" + json`, zero-padded, AES-CBC with a zero IV.
pub fn encrypt_attributes(attrs: &Attributes, key: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
    let json = serde_json::to_vec(&attrs.0).expect("a JSON map always serializes");
    let mut plain = PREFIX.to_vec();
    plain.extend_from_slice(&json);
    plain.resize(plain.len().div_ceil(16) * 16, 0);
    cbc_encrypt_zero_iv(key, &plain)
}

/// Decrypts attributes; fails when the key is wrong or the payload malformed.
pub fn decrypt_attributes(data: &[u8], key: &[u8; 16]) -> Result<Attributes, CryptoError> {
    let plain = cbc_decrypt_zero_iv(key, data).map_err(|_| CryptoError::BadAttributes)?;
    let body = plain
        .strip_prefix(PREFIX)
        .ok_or(CryptoError::BadAttributes)?;
    let end = body.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    match serde_json::from_slice::<Value>(&body[..end]) {
        Ok(Value::Object(map)) => Ok(Attributes(map)),
        _ => Err(CryptoError::BadAttributes),
    }
}
