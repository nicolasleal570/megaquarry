use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use sha2::Sha512;

use super::encoding::{a32_from_bytes, a32_to_bytes, b64url_encode};

const V1_SEED: [u32; 4] = [0x93C4_67E3, 0x7DB0_C7A4, 0xD1BE_3F81, 0x0152_CB56];
const V1_ROUNDS: usize = 0x10000;
const V1_HASH_ROUNDS: usize = 0x4000;
const V2_ITERATIONS: u32 = 100_000;

/// Derives the password key of a version 1 account (`prepare_key`).
pub fn prepare_key_v1(password: &str) -> [u8; 16] {
    let words = a32_from_bytes(password.as_bytes());
    let ciphers: Vec<Aes128> = words
        .chunks(4)
        .map(|slice| {
            let mut key = [0u32; 4];
            key[..slice.len()].copy_from_slice(slice);
            Aes128::new(GenericArray::from_slice(&a32_to_bytes(&key)))
        })
        .collect();

    let mut block = GenericArray::clone_from_slice(&a32_to_bytes(&V1_SEED));
    for _ in 0..V1_ROUNDS {
        for cipher in &ciphers {
            cipher.encrypt_block(&mut block);
        }
    }
    block.into()
}

/// Computes the user hash (`uh`) of a version 1 account.
///
/// The email is lowercased; the result is `b64url(h0 || h2)`.
pub fn user_hash_v1(email: &str, password_key: &[u8; 16]) -> String {
    let mut h = [0u32; 4];
    for (i, word) in a32_from_bytes(email.to_lowercase().as_bytes())
        .iter()
        .enumerate()
    {
        h[i % 4] ^= word;
    }
    let cipher = Aes128::new(GenericArray::from_slice(password_key));
    let mut block = GenericArray::clone_from_slice(&a32_to_bytes(&h));
    for _ in 0..V1_HASH_ROUNDS {
        cipher.encrypt_block(&mut block);
    }
    let words = a32_from_bytes(&block);
    b64url_encode(&a32_to_bytes(&[words[0], words[2]]))
}

/// Derives the password key and user hash of a version 2 account:
/// PBKDF2-HMAC-SHA512 with 100000 iterations and 32 output bytes.
pub fn derive_v2(password: &str, salt: &[u8]) -> ([u8; 16], String) {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, V2_ITERATIONS, &mut out);
    let key: [u8; 16] = out[..16].try_into().expect("16 bytes");
    (key, b64url_encode(&out[16..]))
}
