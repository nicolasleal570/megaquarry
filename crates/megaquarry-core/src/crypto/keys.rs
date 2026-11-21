use super::CryptoError;

/// A 128-bit AES key.
pub type AesKey = [u8; 16];
/// The 64-bit CTR nonce of a file.
pub type Nonce = [u8; 8];

/// A 256-bit MEGA file node key: `k0..k7` as big-endian words.
///
/// The AES key is `k0^k4 .. k3^k7`, the nonce is `k4, k5` and the expected
/// meta-MAC is `k6, k7`.
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey([u8; 32]);

impl FileKey {
    /// Builds a file key from exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::KeyLength(bytes.len()))?;
        Ok(Self(raw))
    }

    /// Packs an upload key and its computed meta-MAC into a node key:
    /// `[u0^u4, u1^u5, u2^m0, u3^m1, u4, u5, m0, m1]`.
    pub fn pack(aes_key: &AesKey, nonce: &Nonce, meta_mac: &[u8; 8]) -> Self {
        let mut raw = [0u8; 32];
        let tail: Vec<u8> = nonce.iter().chain(meta_mac).copied().collect();
        for i in 0..16 {
            raw[i] = aes_key[i] ^ tail[i];
        }
        raw[16..].copy_from_slice(&tail);
        Self(raw)
    }

    /// The folded AES-128 key.
    pub fn aes_key(&self) -> AesKey {
        let mut key = [0u8; 16];
        for (i, k) in key.iter_mut().enumerate() {
            *k = self.0[i] ^ self.0[i + 16];
        }
        key
    }

    /// The CTR nonce (`k4, k5`).
    pub fn nonce(&self) -> Nonce {
        self.0[16..24].try_into().expect("8 bytes")
    }

    /// The expected condensed MAC (`k6, k7`).
    pub fn meta_mac(&self) -> [u8; 8] {
        self.0[24..32].try_into().expect("8 bytes")
    }

    /// The raw 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(..)")
    }
}
