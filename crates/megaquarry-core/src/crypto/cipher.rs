use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};

use super::CryptoError;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

fn check_aligned(data: &[u8]) -> Result<(), CryptoError> {
    if data.len() % 16 == 0 {
        Ok(())
    } else {
        Err(CryptoError::UnalignedLength(data.len()))
    }
}

/// AES-128-ECB encryption without padding (MEGA key wrapping).
pub fn ecb_encrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_aligned(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    Ok(out)
}

/// AES-128-ECB decryption without padding (MEGA key unwrapping).
pub fn ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_aligned(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    Ok(out)
}

/// AES-128-CBC encryption with an all-zero IV and no padding.
pub fn cbc_encrypt_zero_iv(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_aligned(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = [0u8; 16];
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        prev.copy_from_slice(block);
    }
    Ok(out)
}

/// AES-128-CBC decryption with an all-zero IV and no padding.
pub fn cbc_decrypt_zero_iv(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_aligned(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = [0u8; 16];
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        let mut current = [0u8; 16];
        current.copy_from_slice(block);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        prev = current;
    }
    Ok(out)
}

/// Applies AES-128-CTR in place, starting at byte `offset` of the stream.
///
/// The counter block is `nonce (8 bytes) || BE64(offset / 16)`, so encryption
/// and decryption are the same operation.
pub fn ctr_apply(key: &[u8; 16], nonce: &[u8; 8], offset: u64, data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(nonce);
    let mut cipher = Aes128Ctr::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    cipher.seek(offset);
    cipher.apply_keystream(data);
}
