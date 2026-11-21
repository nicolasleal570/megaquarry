//! MEGA chunk geometry and the chunk/file MAC.

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};

use crate::crypto::{AesKey, Nonce};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
/// Offsets (KiB) of chunks 1..=7; chunk `i` is `i * 128 KiB` long.
const SMALL_CHUNK_OFFSETS_KIB: [u64; 7] = [0, 128, 384, 768, 1280, 1920, 2688];
const FIRST_LARGE_CHUNK_OFFSET: u64 = 3584 * KIB;

/// The MAC, uploads and single-connection downloads always use 1 MiB chunks.
pub const MAC_CHUNK_MULTIPLIER: u64 = 1;
/// Multi-connection downloads use 20 MiB chunks after the seventh chunk.
pub const DOWNLOAD_CHUNK_MULTIPLIER: u64 = 20;

/// One chunk of a file. Ids start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub id: u64,
    pub offset: u64,
    pub size: u64,
}

impl Chunk {
    /// The offset just past the chunk.
    pub fn end(&self) -> u64 {
        self.offset + self.size
    }
}

/// The chunk layout of a file of a given size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlan {
    file_size: u64,
    multiplier: u64,
}

impl ChunkPlan {
    /// `multiplier` scales chunks 8 and later (1 MiB each when 1).
    pub fn new(file_size: u64, multiplier: u64) -> Self {
        Self {
            file_size,
            multiplier: multiplier.max(1),
        }
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// The chunk with this id, or `None` past the end of the file.
    /// An empty file has exactly one empty chunk.
    pub fn chunk(&self, id: u64) -> Option<Chunk> {
        if id == 0 {
            return None;
        }
        let (offset, nominal) = if id <= 7 {
            (
                SMALL_CHUNK_OFFSETS_KIB[(id - 1) as usize] * KIB,
                id * 128 * KIB,
            )
        } else {
            let large = MIB * self.multiplier;
            (FIRST_LARGE_CHUNK_OFFSET + (id - 8) * large, large)
        };
        if offset >= self.file_size && !(self.file_size == 0 && id == 1) {
            return None;
        }
        Some(Chunk {
            id,
            offset,
            size: nominal.min(self.file_size - offset),
        })
    }

    /// All chunks in order.
    pub fn iter(&self) -> impl Iterator<Item = Chunk> + '_ {
        (1..).map_while(|id| self.chunk(id))
    }

    /// Number of chunks.
    pub fn count(&self) -> u64 {
        self.iter().count() as u64
    }

    /// How many leading chunks are fully covered by the first `bytes` bytes.
    pub fn completed_chunks(&self, bytes: u64) -> u64 {
        self.iter().take_while(|c| c.end() <= bytes).count() as u64
    }
}

/// The transfer URL of a chunk: `base/start-end` (inclusive end), or
/// `base/start` for the last chunk.
pub fn chunk_url(base: &str, chunk: &Chunk, plan: &ChunkPlan) -> String {
    if chunk.end() >= plan.file_size() {
        format!("{base}/{}", chunk.offset)
    } else {
        format!("{base}/{}-{}", chunk.offset, chunk.end() - 1)
    }
}

/// Incremental CBC-MAC over a file's chunks.
#[derive(Clone)]
pub struct MacAccumulator {
    cipher: Aes128,
    nonce: Nonce,
    file_mac: [u8; 16],
}

impl MacAccumulator {
    pub fn new(key: AesKey, nonce: Nonce) -> Self {
        Self::restore(key, nonce, [0; 16])
    }

    /// Resumes from a checkpoint returned by [`MacAccumulator::state`].
    pub fn restore(key: AesKey, nonce: Nonce, file_mac: [u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(&key)),
            nonce,
            file_mac,
        }
    }

    /// The MAC of one chunk's plaintext (chunk boundaries must use
    /// [`MAC_CHUNK_MULTIPLIER`]).
    pub fn chunk_mac(&self, data: &[u8]) -> [u8; 16] {
        let mut mac = GenericArray::from([0u8; 16]);
        mac[..8].copy_from_slice(&self.nonce);
        mac[8..].copy_from_slice(&self.nonce);
        for block in data.chunks(16) {
            for (m, b) in mac.iter_mut().zip(block) {
                *m ^= b;
            }
            self.cipher.encrypt_block(&mut mac);
        }
        mac.into()
    }

    /// Folds the next chunk MAC (in file order) into the file MAC.
    pub fn absorb(&mut self, chunk_mac: &[u8; 16]) {
        let mut block = GenericArray::from(self.file_mac);
        for (f, c) in block.iter_mut().zip(chunk_mac) {
            *f ^= c;
        }
        self.cipher.encrypt_block(&mut block);
        self.file_mac = block.into();
    }

    /// Checkpoint of the file MAC so far.
    pub fn state(&self) -> [u8; 16] {
        self.file_mac
    }

    /// The condensed 8-byte meta-MAC: `[f0^f1, f2^f3]`.
    pub fn meta_mac(&self) -> [u8; 8] {
        let f = &self.file_mac;
        let mut out = [0u8; 8];
        for i in 0..4 {
            out[i] = f[i] ^ f[i + 4];
            out[i + 4] = f[i + 8] ^ f[i + 12];
        }
        out
    }
}

/// The meta-MAC of a whole in-memory plaintext.
pub fn meta_mac_of(key: &AesKey, nonce: &Nonce, data: &[u8]) -> [u8; 8] {
    let plan = ChunkPlan::new(data.len() as u64, MAC_CHUNK_MULTIPLIER);
    let mut acc = MacAccumulator::new(*key, *nonce);
    for chunk in plan.iter() {
        let mac = acc.chunk_mac(&data[chunk.offset as usize..chunk.end() as usize]);
        acc.absorb(&mac);
    }
    acc.meta_mac()
}
