//! Encryption at rest for account secrets.
//!
//! Each blob is authenticated (encrypt-then-MAC):
//! `"MQV1" || IV(16) || AES-256-CBC-PKCS7 || HMAC-SHA256(32)`.
//!
//! One 32-byte PBKDF2 block (600000 iterations, current OWASP
//! guidance) is split into the encryption and authentication keys with
//! HMAC, so checking a password guess costs an attacker a full derivation.

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::StoreError;

const MAGIC: &[u8; 4] = b"MQV1";
const ITERATIONS: u32 = 600_000;
const TAG_LEN: usize = 32;
/// Salt length for master-password derivation.
pub const SALT_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Opens and seals secrets; a vault without a key stores them as is.
#[derive(Clone)]
pub struct Vault {
    keys: Option<Keys>,
}

#[derive(Clone)]
struct Keys {
    encryption: [u8; 32],
    authentication: [u8; 32],
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("encrypted", &self.keys.is_some())
            .finish()
    }
}

impl Vault {
    /// A vault that stores secrets without encryption (no master password).
    pub fn plain() -> Self {
        Self { keys: None }
    }

    /// Derives the vault of a master password.
    pub fn derive(password: &str, salt: &[u8]) -> Self {
        let mut prk = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut prk);
        Self {
            keys: Some(Keys {
                encryption: tag(&prk, &[b"megaquarry vault encryption"]),
                authentication: tag(&prk, &[b"megaquarry vault authentication"]),
            }),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.keys.is_some()
    }

    /// A value proving knowledge of the password, safe to store.
    pub(super) fn verifier(&self) -> Option<Vec<u8>> {
        self.keys
            .as_ref()
            .map(|k| tag(&k.authentication, &[b"verifier"]).to_vec())
    }

    /// Seals `data` (a copy of it when the vault has no key).
    pub fn seal(&self, data: &[u8]) -> Vec<u8> {
        let Some(keys) = &self.keys else {
            return data.to_vec();
        };
        let iv: [u8; 16] = rand::random();
        let ciphertext = cbc::Encryptor::<Aes256>::new(&keys.encryption.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(data);
        let mut blob = Vec::with_capacity(4 + 16 + ciphertext.len() + TAG_LEN);
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ciphertext);
        let tag = tag(&keys.authentication, &[&blob]);
        blob.extend_from_slice(&tag);
        blob
    }

    /// Opens a sealed blob; fails on a wrong key or tampered data.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, StoreError> {
        let Some(keys) = &self.keys else {
            if blob.starts_with(MAGIC) {
                return Err(StoreError::Locked);
            }
            return Ok(blob.to_vec());
        };
        if blob.len() < 4 + 16 + 16 + TAG_LEN || !blob.starts_with(MAGIC) {
            return Err(StoreError::Corrupt("not a sealed value".into()));
        }
        let (body, expected) = blob.split_at(blob.len() - TAG_LEN);
        let mut mac = HmacSha256::new_from_slice(&keys.authentication).expect("any key length");
        mac.update(body);
        mac.verify_slice(expected).map_err(|_| {
            StoreError::Corrupt("authentication failed (wrong key or tampered data)".into())
        })?;
        let iv: [u8; 16] = body[4..20].try_into().expect("16 bytes");
        cbc::Decryptor::<Aes256>::new(&keys.encryption.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&body[20..])
            .map_err(|_| StoreError::Corrupt("bad padding".into()))
    }
}

fn tag(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
