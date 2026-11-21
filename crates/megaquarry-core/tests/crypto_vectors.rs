//! Known-answer tests. Expected values come from `tools/gen_vectors.py`,
//! an independent implementation built on Python `cryptography`.

use megaquarry_core::crypto::{
    self, Attributes, FileKey, a32_from_bytes, a32_to_bytes, b64url_decode, b64url_encode,
    derive_v2, prepare_key_v1, user_hash_v1,
};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn base64url_round_trips_without_padding() {
    assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
    assert_eq!(b64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
    // Padded input is accepted too.
    assert_eq!(b64url_decode("-_8=").unwrap(), vec![0xfb, 0xff]);
    assert!(b64url_decode("not base64!").is_err());
}

#[test]
fn a32_zero_pads_partial_words() {
    assert_eq!(
        a32_from_bytes(&[1, 2, 3, 4, 5]),
        vec![0x0102_0304, 0x0500_0000]
    );
    assert_eq!(a32_to_bytes(&[0x0102_0304]), vec![1, 2, 3, 4]);
}

#[test]
fn v1_password_key_and_user_hash_match_reference() {
    let key = crypto::prepare_key_v1("correct horse battery staple");
    assert_eq!(key.to_vec(), h("57d978ef82e99ea50ab00045e8614d7b"));
    // The email is lowercased before hashing.
    assert_eq!(
        crypto::user_hash_v1("Test.User@Example.com", &key),
        "XVqGcHLIrJ4"
    );
}

#[test]
fn v2_password_derivation_matches_reference() {
    let salt = b64url_decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
    let (key, user_hash) = crypto::derive_v2("correct horse battery staple", &salt);
    assert_eq!(key.to_vec(), h("88aa99bab648e0a15a6dcfd127cb7d9f"));
    assert_eq!(user_hash, "F9Gj-gyqbKnMl-KglgC7wA");
}

#[test]
fn attributes_encrypt_and_decrypt_match_reference() {
    let key: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let attrs = Attributes::with_name("hello.txt");
    let encrypted = crypto::encrypt_attributes(&attrs, &key).unwrap();
    assert_eq!(
        b64url_encode(&encrypted),
        "PXKaKROX-3KfhCRae1zd6qp8ZOUIggiCiWGYp_LR_DE"
    );

    let decrypted = crypto::decrypt_attributes(&encrypted, &key).unwrap();
    assert_eq!(decrypted.name(), Some("hello.txt"));
}

#[test]
fn attributes_with_quotes_survive_a_round_trip() {
    let key = [7u8; 16];
    let attrs = Attributes::with_name("say \"hi\".txt");
    let encrypted = crypto::encrypt_attributes(&attrs, &key).unwrap();
    let decrypted = crypto::decrypt_attributes(&encrypted, &key).unwrap();
    assert_eq!(decrypted.name(), Some("say \"hi\".txt"));
}

#[test]
fn attributes_with_wrong_key_are_rejected() {
    let key: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let encrypted = crypto::encrypt_attributes(&Attributes::with_name("x"), &key).unwrap();
    assert!(crypto::decrypt_attributes(&encrypted, &[0u8; 16]).is_err());
}

#[test]
fn file_key_folds_into_aes_key_nonce_and_meta_mac() {
    let raw = b64url_decode("AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw").unwrap();
    let key = FileKey::from_bytes(&raw).unwrap();
    assert_eq!(
        key.aes_key().to_vec(),
        h("7070909090b0b09090f0f0909090b0b0")
    );
    assert_eq!(key.nonce().to_vec(), h("737a81888f969da4"));
    assert_eq!(key.meta_mac().to_vec(), raw[24..32].to_vec());
    assert_eq!(key.to_bytes().to_vec(), raw);
    assert!(FileKey::from_bytes(&raw[..16]).is_err());
}

#[test]
fn ctr_encrypts_from_an_arbitrary_offset() {
    let raw = b64url_decode("AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw").unwrap();
    let key = FileKey::from_bytes(&raw).unwrap();
    let plain = h(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263",
    );
    let expected = h(
        "a9899255b6dde99ff775aecc40343ac9cc59d4320e7df926208e7b4835f61bb6f656359536995ad7d587806d034d826e1ddd29a4b868301db6112f9545a1dbec4bc329c2ce494d4c27ccc5f1ecf49b6043644a6b4c4cb02990afabeeb23c452b7a99be10",
    );

    let mut buf = plain.clone();
    crypto::ctr_apply(&key.aes_key(), &key.nonce(), 48, &mut buf);
    assert_eq!(buf, expected);

    // Offsets that are not block-aligned continue the same keystream.
    let mut tail = plain[5..].to_vec();
    crypto::ctr_apply(&key.aes_key(), &key.nonce(), 48 + 5, &mut tail);
    assert_eq!(tail, expected[5..].to_vec());
}

#[test]
fn ecb_key_wrap_round_trips() {
    let master = [9u8; 16];
    let node_key = [1u8; 32];
    let wrapped = crypto::ecb_encrypt(&master, &node_key).unwrap();
    assert_ne!(wrapped, node_key.to_vec());
    assert_eq!(
        crypto::ecb_decrypt(&master, &wrapped).unwrap(),
        node_key.to_vec()
    );
    assert!(crypto::ecb_encrypt(&master, &[0u8; 15]).is_err());
}

/// Vectors from the independent verification (Python `cryptography`):
/// empty, short, non-ASCII and long passwords; non-ASCII emails.
#[test]
fn key_derivation_matches_an_independent_reference_on_unusual_inputs() {
    assert_eq!(
        prepare_key_v1(""),
        [
            147, 196, 103, 227, 125, 176, 199, 164, 209, 190, 63, 129, 1, 82, 203, 86
        ],
        "v1 key ''"
    );
    assert_eq!(
        prepare_key_v1("a"),
        [
            109, 217, 247, 236, 178, 70, 137, 196, 53, 161, 79, 124, 81, 218, 67, 77
        ],
        "v1 key 'a'"
    );
    assert_eq!(
        prepare_key_v1("abc"),
        [
            45, 243, 172, 41, 50, 175, 179, 20, 28, 89, 24, 87, 60, 50, 116, 128
        ],
        "v1 key 'abc'"
    );
    assert_eq!(
        prepare_key_v1("abcd"),
        [
            174, 239, 3, 42, 96, 92, 57, 138, 212, 100, 153, 200, 44, 14, 66, 120
        ],
        "v1 key 'abcd'"
    );
    assert_eq!(
        prepare_key_v1("contraseña"),
        [
            199, 233, 169, 137, 46, 1, 212, 254, 163, 73, 156, 237, 193, 200, 55, 180
        ],
        "v1 key 'contraseña'"
    );
    assert_eq!(
        prepare_key_v1("abcdefghijklmnopq"),
        [
            192, 66, 7, 187, 191, 155, 135, 45, 146, 113, 49, 70, 231, 189, 249, 213
        ],
        "v1 key 'abcdefghijklmnopq'"
    );
    assert_eq!(
        prepare_key_v1("pässwörd-über-lång-🔑-ñ"),
        [
            28, 72, 237, 179, 180, 242, 180, 126, 117, 26, 125, 101, 37, 219, 106, 199
        ],
        "v1 key 'pässwörd-über-lång-🔑-ñ'"
    );
    assert_eq!(
        prepare_key_v1("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        [
            239, 243, 123, 38, 210, 7, 58, 8, 133, 11, 114, 91, 188, 111, 34, 140
        ],
        "v1 key 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
    );
    assert_eq!(
        user_hash_v1(
            "Ünïcødé@Example.COM",
            &[
                199, 233, 169, 137, 46, 1, 212, 254, 163, 73, 156, 237, 193, 200, 55, 180
            ]
        ),
        "5ij93g0tNSg",
        "uh 'Ünïcødé@Example.COM'"
    );
    assert_eq!(
        user_hash_v1(
            "a@b.c",
            &[
                192, 66, 7, 187, 191, 155, 135, 45, 146, 113, 49, 70, 231, 189, 249, 213
            ]
        ),
        "yqtu2ofcUeg",
        "uh 'a@b.c'"
    );
    assert_eq!(
        user_hash_v1(
            "ÀBÇ@ÐÉF.org",
            &[
                28, 72, 237, 179, 180, 242, 180, 126, 117, 26, 125, 101, 37, 219, 106, 199
            ]
        ),
        "VpKXphzZswc",
        "uh 'ÀBÇ@ÐÉF.org'"
    );
    assert_eq!(
        user_hash_v1(
            "user@example.com",
            &[
                239, 243, 123, 38, 210, 7, 58, 8, 133, 11, 114, 91, 188, 111, 34, 140
            ]
        ),
        "MD6kubcBINo",
        "uh 'user@example.com'"
    );
    assert_eq!(
        user_hash_v1(
            "İSTANBUL@X.TR",
            &[
                147, 196, 103, 227, 125, 176, 199, 164, 209, 190, 63, 129, 1, 82, 203, 86
            ]
        ),
        "8ALddboHdMI",
        "uh 'İSTANBUL@X.TR'"
    );
    assert_eq!(
        derive_v2(
            "contraseña",
            &[
                191, 137, 65, 230, 164, 18, 37, 155, 87, 179, 120, 183, 180, 224, 242, 252, 217,
                210, 105, 237, 210, 203, 183, 58, 101, 121, 86, 1, 222, 200, 88, 49
            ]
        ),
        (
            [
                214, 212, 165, 226, 224, 128, 153, 88, 25, 88, 143, 230, 63, 193, 194, 205
            ],
            "vIQT3ODVhyB7MuLNecuBtQ".to_string()
        ),
        "v2 'contraseña'"
    );
    assert_eq!(
        derive_v2(
            "🔑🔑",
            &[
                108, 43, 176, 238, 82, 233, 82, 88, 68, 93, 30, 76, 6, 211, 213, 27, 55, 128, 211,
                39, 157, 71, 248, 44, 136, 44, 244, 58, 206, 26, 110, 116
            ]
        ),
        (
            [
                222, 159, 137, 158, 170, 70, 10, 75, 245, 26, 200, 58, 177, 169, 17, 196
            ],
            "WAM5z-WH8ulq4nH_H3E3qQ".to_string()
        ),
        "v2 '🔑🔑'"
    );
    assert_eq!(
        derive_v2(
            "abc",
            &[
                15, 233, 128, 230, 18, 247, 71, 135, 16, 93, 24, 158, 14, 119, 147, 69, 213, 12,
                48, 164, 156, 220, 94, 89, 161, 23, 53, 178, 166, 1, 219, 94
            ]
        ),
        (
            [
                149, 243, 121, 154, 67, 119, 23, 147, 36, 164, 176, 49, 222, 151, 134, 37
            ],
            "HEhXRkPOFNUKRKlzv0lLEg".to_string()
        ),
        "v2 'abc'"
    );
    assert_eq!(
        derive_v2(
            "",
            &[
                96, 220, 137, 4, 13, 106, 98, 19, 246, 0, 189, 3, 195, 219, 89, 4, 72, 134, 47,
                200, 168, 241, 83, 164, 140, 203, 203, 166, 236, 155, 121, 139
            ]
        ),
        (
            [
                207, 186, 139, 146, 156, 109, 84, 134, 146, 147, 173, 125, 168, 44, 233, 86
            ],
            "hGU-k2CGDuv6yospJcFO2g".to_string()
        ),
        "v2 ''"
    );
}
