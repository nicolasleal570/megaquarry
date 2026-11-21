use megaquarry_core::chunk::{
    Chunk, ChunkPlan, MAC_CHUNK_MULTIPLIER, MacAccumulator, chunk_url, meta_mac_of,
};
use megaquarry_core::crypto::{FileKey, b64url_decode};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;

fn key() -> FileKey {
    FileKey::from_bytes(&b64url_decode("AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw").unwrap())
        .unwrap()
}

#[test]
fn first_seven_chunks_grow_by_128_kib() {
    let plan = ChunkPlan::new(100 * MIB, 1);
    let firsts: Vec<(u64, u64)> = (1..=8)
        .map(|id| {
            let c = plan.chunk(id).unwrap();
            (c.offset / KIB, c.size / KIB)
        })
        .collect();
    assert_eq!(
        firsts,
        vec![
            (0, 128),
            (128, 256),
            (384, 384),
            (768, 512),
            (1280, 640),
            (1920, 768),
            (2688, 896),
            (3584, 1024)
        ]
    );
}

#[test]
fn multiplier_scales_chunks_after_the_seventh() {
    let plan = ChunkPlan::new(100 * MIB, 20);
    assert_eq!(
        plan.chunk(8).unwrap(),
        Chunk {
            id: 8,
            offset: 3584 * KIB,
            size: 20 * MIB
        }
    );
    assert_eq!(plan.chunk(9).unwrap().offset, 3584 * KIB + 20 * MIB);
    // The seventh chunk is unaffected.
    assert_eq!(plan.chunk(7).unwrap().size, 896 * KIB);
}

#[test]
fn last_chunk_is_truncated_and_plan_ends() {
    let size = 3584 * KIB + MIB + 10;
    let plan = ChunkPlan::new(size, 1);
    assert_eq!(plan.chunk(9).unwrap().size, 10);
    assert!(plan.chunk(10).is_none());
    assert_eq!(plan.count(), 9);
    let total: u64 = plan.iter().map(|c| c.size).sum();
    assert_eq!(total, size);
}

#[test]
fn empty_file_has_a_single_empty_chunk() {
    let plan = ChunkPlan::new(0, 1);
    assert_eq!(
        plan.chunk(1).unwrap(),
        Chunk {
            id: 1,
            offset: 0,
            size: 0
        }
    );
    assert!(plan.chunk(2).is_none());
    assert!(plan.chunk(0).is_none());
}

#[test]
fn chunks_completed_by_a_byte_count_resume_from_a_boundary() {
    let plan = ChunkPlan::new(100 * MIB, 1);
    assert_eq!(plan.completed_chunks(0), 0);
    assert_eq!(plan.completed_chunks(128 * KIB - 1), 0);
    assert_eq!(plan.completed_chunks(128 * KIB), 1);
    assert_eq!(plan.completed_chunks(500 * KIB), 2);
    assert_eq!(plan.completed_chunks(768 * KIB), 3);
    assert_eq!(plan.completed_chunks(3584 * KIB + 3 * MIB + 1), 10);
    assert_eq!(plan.completed_chunks(100 * MIB), plan.count());
}

#[test]
fn chunk_urls_omit_the_end_on_the_last_chunk() {
    let plan = ChunkPlan::new(300 * KIB, 1);
    let first = plan.chunk(1).unwrap();
    let last = plan.chunk(2).unwrap();
    assert_eq!(
        chunk_url("http://x/dl", &first, &plan),
        "http://x/dl/0-131071"
    );
    assert_eq!(chunk_url("http://x/dl", &last, &plan), "http://x/dl/131072");
}

#[test]
fn meta_mac_matches_reference_for_multi_chunk_data() {
    let data: Vec<u8> = (0..5 * MIB as usize + 123)
        .map(|i| ((i * 31 + 7) % 256) as u8)
        .collect();
    let key = key();
    assert_eq!(
        hex::encode(meta_mac_of(&key.aes_key(), &key.nonce(), &data)),
        "1e444a30f53315e8"
    );
    assert_eq!(
        hex::encode(meta_mac_of(&key.aes_key(), &key.nonce(), b"hello world")),
        "3b85aeda540d732a"
    );
    assert_eq!(
        hex::encode(meta_mac_of(&key.aes_key(), &key.nonce(), b"")),
        "6445f1f966d14b1e"
    );
}

#[test]
fn accumulator_can_absorb_chunks_incrementally() {
    let data: Vec<u8> = (0..2 * MIB as usize).map(|i| (i % 253) as u8).collect();
    let key = key();
    let plan = ChunkPlan::new(data.len() as u64, MAC_CHUNK_MULTIPLIER);
    let mut acc = MacAccumulator::new(key.aes_key(), key.nonce());
    for chunk in plan.iter() {
        let slice = &data[chunk.offset as usize..(chunk.offset + chunk.size) as usize];
        let mac = acc.chunk_mac(slice);
        acc.absorb(&mac);
    }
    assert_eq!(
        acc.meta_mac(),
        meta_mac_of(&key.aes_key(), &key.nonce(), &data)
    );

    // State can be checkpointed and restored mid-file.
    let restored = MacAccumulator::restore(key.aes_key(), key.nonce(), acc.state());
    assert_eq!(restored.meta_mac(), acc.meta_mac());
}

#[test]
fn packed_upload_key_round_trips_through_file_key() {
    let aes_key = [0x11u8; 16];
    let nonce = [0x22u8; 8];
    let mac = [0x33u8; 8];
    let key = FileKey::pack(&aes_key, &nonce, &mac);
    assert_eq!(key.aes_key(), aes_key);
    assert_eq!(key.nonce(), nonce);
    assert_eq!(key.meta_mac(), mac);
}
