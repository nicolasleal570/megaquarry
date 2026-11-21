//! Cryptographic primitives used by the MEGA protocol.

mod attributes;
mod cipher;
mod encoding;
mod keys;
mod password;

pub use attributes::{Attributes, decrypt_attributes, encrypt_attributes};
pub use cipher::{cbc_decrypt_zero_iv, cbc_encrypt_zero_iv, ctr_apply, ecb_decrypt, ecb_encrypt};
pub use encoding::{a32_from_bytes, a32_to_bytes, b64url_decode, b64url_encode};
pub use keys::{AesKey, FileKey, Nonce};
pub use password::{derive_v2, prepare_key_v1, user_hash_v1};

/// Errors raised by the crypto layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid base64: {0}")]
    Base64(String),
    #[error("data length {0} is not a multiple of 16 bytes")]
    UnalignedLength(usize),
    #[error("invalid key length {0}")]
    KeyLength(usize),
    #[error("attributes could not be decrypted with this key")]
    BadAttributes,
}
