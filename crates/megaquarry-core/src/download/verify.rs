use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::chunk::{ChunkPlan, MAC_CHUNK_MULTIPLIER, MacAccumulator};
use crate::crypto::FileKey;

/// Streams a plaintext file and computes its meta-MAC (blocking).
pub(super) fn meta_mac_of_file(path: &Path, key: &FileKey) -> std::io::Result<[u8; 8]> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut acc = MacAccumulator::new(key.aes_key(), key.nonce());
    let mut buffer = Vec::new();
    for chunk in ChunkPlan::new(size, MAC_CHUNK_MULTIPLIER).iter() {
        buffer.resize(chunk.size as usize, 0);
        reader.read_exact(&mut buffer)?;
        let mac = acc.chunk_mac(&buffer);
        acc.absorb(&mac);
    }
    Ok(acc.meta_mac())
}
