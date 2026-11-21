mod common;

use common::{FakeTransport, api, ok};
use megaquarry_core::api::{ApiError, ErrorCode};
use megaquarry_core::crypto::{
    b64url_decode, b64url_encode, ecb_encrypt, prepare_key_v1, user_hash_v1,
};
use megaquarry_core::session::{self, Credentials, LoginError};
use serde_json::json;

// Fixture from tools/gen_vectors.py (login_fixture): a v2 account with a
// real 1024-bit RSA key; the RSA plaintext fills the modulus minus one byte.
const PASSWORD: &str = "correct horse battery staple";
const SALT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const K_V2: &str = "iZXa7xpP8Fh16l2tNeOc5w";
const PRIVK: &str = "QcIHAXzqXGYTP-Ew_m4azfUXoQ-WuGyctHe4hTSa4fVMnMmNa5emXorWJi2-xwSSTSuODmCQwxLt1IrZdjW-yvLk8-Eo75oiG2cDfj3wvnAnIIaBGm5gBs36MaFeT-Q095SnQAIPg5lAbzElo3W5Mbu9KlGIwpKCQ1atGApidWX9j_xu374ZX3qS836cHk84yqAoZLoh95vbwJ2zpy2SU9-A16G90LjdEJdcZyVZ9X3NsOnE4wz0YDzkJ4xhBhDvFtuE0GStnTO5aDzyQJUYEdV2_bfiPxIzOeuF2JZ0XR-fuOlhfQ1XpCxsdgtjZj14us0kSd807QaAZRSo_mSVWryIji-1V-eKeiNV9pBOb5JVvVIcjcgy_c6bBNGILGILUznBPs4mwQszb38TQd2o2a7-m3htKlwbaCAIPBHaFdiMiPvDYnKKaDr8-ENVVexm";
const CSID: &str = "BADF_EeFFJi3Eo2wr2fpaIDX_J6xwAPWy73hr88QozVZc9YTC2ra-akJ0IWaUXtOjSzeZS-3OzhUVv5-qihIKOP0WXmaM0VnWhwvfCgGbxTYppPo-rfnl-t7a7u1fULaJ3BIwhek5hJ-rXSUpGTcByFeLIWyMONZa33QE7ewEVl_yw";
const MASTER: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const SID: &str = "AT5CZIW-Gp1JDYsiIXQM6kg14p-DoksL7M9hM8oHQuOn2H-PioyDijHS8g";
const USER_HASH_V2: &str = "F9Gj-gyqbKnMl-KglgC7wA";

fn us_reply(k: &str) -> String {
    json!([{"k": k, "privk": PRIVK, "csid": CSID, "u": "USERHANDLE"}]).to_string()
}

#[tokio::test]
async fn logs_into_a_v2_account() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[0]"),
        ok(&us_reply(K_V2)),
    ]));
    let session = session::login(&api, "User@Example.com", PASSWORD, None)
        .await
        .unwrap();

    assert_eq!(session.sid, SID);
    assert_eq!(session.master_key, MASTER);
    assert_eq!(session.user_handle, "USERHANDLE");
    assert_eq!(session.credentials.email, "user@example.com");
    assert_eq!(session.credentials.user_hash, USER_HASH_V2);
    assert_eq!(api.session_id().as_deref(), Some(SID));

    let bodies = api.transport().bodies();
    assert_eq!(bodies[0], json!([{"a": "us0", "user": "user@example.com"}]));
    assert_eq!(bodies[1], json!([{"a": "mfag", "e": "user@example.com"}]));
    assert_eq!(
        bodies[2],
        json!([{"a": "us", "user": "user@example.com", "uh": USER_HASH_V2}])
    );
}

#[tokio::test]
async fn logs_into_a_v1_account() {
    let email = "old.user@example.com";
    let password_key = prepare_key_v1(PASSWORD);
    let k = b64url_encode(&ecb_encrypt(&password_key, &MASTER).unwrap());
    let api = api(FakeTransport::with(vec![
        ok(r#"[{"v": 1}]"#),
        ok("[0]"),
        ok(&us_reply(&k)),
    ]));
    let session = session::login(&api, email, PASSWORD, None).await.unwrap();
    assert_eq!(session.sid, SID);
    assert_eq!(session.master_key, MASTER);
    assert_eq!(
        api.transport().bodies()[2][0]["uh"],
        json!(user_hash_v1(email, &password_key))
    );
}

#[tokio::test]
async fn strips_the_email_alias_suffix() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[0]"),
        ok(&us_reply(K_V2)),
    ]));
    let session = session::login(&api, " User@Example.com # work ", PASSWORD, None)
        .await
        .unwrap();
    assert_eq!(session.credentials.email, "user@example.com");
}

#[tokio::test]
async fn asks_for_a_code_when_two_factor_is_enabled() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[1]"),
    ]));
    assert_eq!(
        session::login(&api, "user@example.com", PASSWORD, None).await,
        Err(LoginError::MfaRequired)
    );
    assert_eq!(api.transport().requests().len(), 2);
}

#[tokio::test]
async fn sends_the_two_factor_code() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok(&us_reply(K_V2)),
    ]));
    session::login(&api, "user@example.com", PASSWORD, Some("123456"))
        .await
        .unwrap();
    assert_eq!(api.transport().bodies()[1][0]["mfa"], json!("123456"));
}

#[tokio::test]
async fn reports_wrong_credentials() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[0]"),
        ok("[-9]"),
    ]));
    assert_eq!(
        session::login(&api, "user@example.com", "wrong", None).await,
        Err(LoginError::BadCredentials)
    );
    assert_eq!(api.session_id(), None);
}

#[tokio::test]
async fn reports_a_password_that_does_not_decrypt_the_session() {
    // `us` accepted but the master key was encrypted with another password.
    let k = b64url_encode(&ecb_encrypt(&[7; 16], &MASTER).unwrap());
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[0]"),
        ok(&us_reply(&k)),
    ]));
    assert!(matches!(
        session::login(&api, "user@example.com", PASSWORD, None).await,
        Err(LoginError::Malformed(_))
    ));
}

#[tokio::test]
async fn rejects_accounts_with_the_unsupported_key_format() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[0]"),
        ok(r#"[{"keys": "xyz", "csid": "abc"}]"#),
    ]));
    assert_eq!(
        session::login(&api, "user@example.com", PASSWORD, None).await,
        Err(LoginError::UnsupportedAccount)
    );
}

#[tokio::test]
async fn logs_in_again_from_stored_credentials_without_the_password() {
    let api = api(FakeTransport::with(vec![ok("[0]"), ok(&us_reply(K_V2))]));
    let password_aes: [u8; 16] = {
        let (key, _) = megaquarry_core::crypto::derive_v2(PASSWORD, &b64url_decode(SALT).unwrap());
        key
    };
    let credentials = Credentials {
        email: "user@example.com".into(),
        password_aes,
        user_hash: USER_HASH_V2.into(),
    };
    let session = session::login_with_credentials(&api, &credentials, None)
        .await
        .unwrap();
    assert_eq!(session.sid, SID);
    assert_eq!(api.transport().bodies()[0][0]["a"], json!("mfag"));
}

#[tokio::test]
async fn passes_through_other_api_errors() {
    let api = api(FakeTransport::with(vec![ok("[-16]")]));
    assert_eq!(
        session::login(&api, "user@example.com", PASSWORD, None).await,
        Err(LoginError::Api(ApiError::Mega(ErrorCode::Blocked)))
    );
}

// 2048-bit RSA fixtures from the independent verification. Layout A: the
// RSA plaintext is `00 || sid || random`; layout B: the same but the sid
// itself starts with 0x00 (a stripped-all-zeros rule gets this wrong).
const RSA_MASTER: [u8; 16] = [
    72, 142, 245, 232, 170, 204, 101, 33, 42, 149, 21, 11, 215, 91, 188, 32,
];
const PRIVK_U_PINV: &str = "nu23tdDIaqAbsnGgnIMt0P7PUMi-6cgAFMomtoYZhTLPdI0IWDgGT93LzGy_cxZTBrbd-7SDEGX2gQZpJaOY5iHq72PIsMbp1RsRQui6HkVuqZwlQpcpHIFMAYeWwJTWadO0HdNWA-9zOFpShgvN2XzeFWzJ7nJJ90Y5uZyOeJiehM2nJ98tugRDgornvJUYogs-eEDYZfxAAEKN7XZMGCCjIwUgwSDkDYhmzi095diQ8QwLFe3CTNIodhsteACyKkFSaagvKCWEG51gqajQuTVPDEKxVg8_htDZwcGJTCfo98m-l6j6kQSGVPMkYCvKMwSBqKbxOIfcQXzMiTztjBrb6qKtz6GOgJKBvGNI6FPC4FYSSlrsRLP93RKS0xRAaY0pOiUtOSJfwe2N78N5muJMzZisgbLHiuP0mxIwpk64cb8jqvqArcP_1CC9mX_4wQRtYjMMSKno0B3scNVaxN1_yXqZ2Ge14osvnzrsgLfvDj-W-XjOO00gylThe5W7FnvTM-7h7AlgpZJwwzBOvxU7Vi8I6Cq9lfcWe7AA9zHa06epOd0SSCg-MWbu5WRpfGE6Woc0AZzWHSk8Km_0Irv6D0qfF4GbwBt4yHBc-6nHoNKPHYzSUS2UvNq1eOFsrRp2B85G2s4UfM_0QSavHYRUSIcU0QdO5Io0v8rspXgr2pX_kV0yxVzNHipDSbvtDHmzpi6w4nr7fvEKUJPT_4N9FAMbWMjHISA5ScU6lDNHiiCnhjMmUjXphp7bNX35cXH-nD8uSRn-ETo-odD9H53QJb6u1qK4mDJRXi5OtuW3ih4FZNb2ozfp-Dj3kIGZyLNalLhB8Vbno-TdqXus1KgFeX-rdbnNi5ZoIo5iYT0";
const PRIVK_U_QINV: &str = "nu23tdDIaqAbsnGgnIMt0P7PUMi-6cgAFMomtoYZhTLPdI0IWDgGT93LzGy_cxZTBrbd-7SDEGX2gQZpJaOY5iHq72PIsMbp1RsRQui6HkVuqZwlQpcpHIFMAYeWwJTWadO0HdNWA-9zOFpShgvN2XzeFWzJ7nJJ90Y5uZyOeJiehM2nJ98tugRDgornvJUYogs-eEDYZfxAAEKN7XZMGCCjIwUgwSDkDYhmzi095diQ8QwLFe3CTNIodhsteACyKkFSaagvKCWEG51gqajQuTVPDEKxVg8_htDZwcGJTCfo98m-l6j6kQSGVPMkYCvKMwSBqKbxOIfcQXzMiTztjBrb6qKtz6GOgJKBvGNI6FPC4FYSSlrsRLP93RKS0xRAaY0pOiUtOSJfwe2N78N5muJMzZisgbLHiuP0mxIwpk64cb8jqvqArcP_1CC9mX_4wQRtYjMMSKno0B3scNVaxN1_yXqZ2Ge14osvnzrsgLfvDj-W-XjOO00gylThe5W7FnvTM-7h7AlgpZJwwzBOvxU7Vi8I6Cq9lfcWe7AA9zHa06epOd0SSCg-MWbu5WRpfGE6Woc0AZzWHSk8Km_0Irv6D0qfF4GbwBt4yHBc-6nHoNKPHYzSUS2UvNq1eOFsrRp2B85G2s4UfM_0QSavHYRUSIcU0QdO5Io0v8rspXiZ0tOyCal8YIHauU6a5DPwnqJpEReCAKLw3Tha05lkrjdRNMQDYg3AkLMna4P2XNvV_fV1IjPDT7rkRaiU_W_GwCl1dAyVnD9Os_tFRYVNPfIop8Plmr0hGMA1hsrs7ea1DLmZIfnBlcWhvycrgdUJP4X6z-uIAeXNt9w14pXfNP5hedI_UsyA-au145Smm0k";
const CSID_LAYOUT_A: &str = "CAC4ETm8-iWMlm-uB6c6Pz5LqXQrg6s0PbzP3ZRaxrsNkCArt-lBramjpS5ZRbeifvwUDJsrjxjKzdZ2NOJcdXUMQZWyR1pAGY1AKoHcUaqmNHvFm3aFaUo52v9_236gM3wui5RL-lv0ybcCFTxApG_vFSqsU61eaH4sZXvzWzNj0nrEHsnJ61tMsvrHD4dJR_eGdnk6B6TPlbTuRh3tSX2WrAPLxUNendRigcd7A_Vl1JMiKCE_W86wKxOWiPHmVowliG_QILndl7i61COGPsyIHHsHijQcoJdhk3qJ7i_phSYvop5lSIuHNFkpKiAHELy6b0uaGaKltv3NJUt_ZE1V";
const CSID_LAYOUT_B: &str = "CACXHwtJgmynDaPHhkhEJNULLqbfB-bylA5QC07-YLDmYZyier1zrA_vYKAZ0IWmhH07wkXZWTuSGXwQ4VStQGzVQ4m8tqZCx3-_uO-1Jx4bMXaeDTw-mR6EAwWRWBx0K6zD22kDG-k3cMnaXNXQH4hjhTi82svXyID0bzLXCvI4infKLrmgC4agMA69OySnMNynoYDD4Qqnhe2w3s__Pdrhvv7ZCw7-DhnM79BDnCWJ39BqJdC5kwUUijNGfhUdGfFCbm_ccNJLItm0ilJhAHDGeAZ3KTwk-XTu1_2Q5UWaOqE9uUFSO_BO67CgGGsUrYPIFum-aQBcvPjfjQdQwk2I";

async fn sid_for(privk: &str, csid: &str) -> Result<String, LoginError> {
    let password_aes = [7u8; 16];
    let k = b64url_encode(&ecb_encrypt(&password_aes, &RSA_MASTER).unwrap());
    let credentials = Credentials {
        email: "e@x.y".into(),
        password_aes,
        user_hash: "uh".into(),
    };
    let reply = json!([{"k": k, "privk": privk, "csid": csid, "u": "U"}]).to_string();
    let api = api(FakeTransport::with(vec![ok(&reply)]));
    session::login_with_credentials(&api, &credentials, Some("000000"))
        .await
        .map(|s| s.sid)
}

#[tokio::test]
async fn extracts_the_session_id_from_the_fixed_length_rsa_output() {
    for privk in [PRIVK_U_PINV, PRIVK_U_QINV] {
        assert_eq!(
            sid_for(privk, CSID_LAYOUT_A).await.unwrap(),
            "Wn3Q0qLjNtjbrOdjrA_QKRXguBcIC4ZTNVT0ENjKE6Mb57bnuPq42JHNZg"
        );
        assert_eq!(
            sid_for(privk, CSID_LAYOUT_B).await.unwrap(),
            "AJWyehnhmmzNuk3UHA3fX3mPn0-HZCDkYDzwJVlMPn9F81nnkFdC1MJhVA"
        );
    }
}

#[tokio::test]
async fn maps_the_two_factor_error_code_of_the_mega_sdk() {
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[-26]"),
    ]));
    assert_eq!(
        session::login(&api, "user@example.com", PASSWORD, Some("000000")).await,
        Err(LoginError::MfaRequired)
    );
}

#[tokio::test]
async fn reports_unknown_users_as_wrong_credentials() {
    let api = api(FakeTransport::with(vec![
        ok("[-9]"),
        ok(&json!([{"v": 2, "s": SALT}]).to_string()),
        ok("[-9]"),
    ]));
    for _ in 0..2 {
        assert_eq!(
            session::login(&api, "nobody@example.com", PASSWORD, None).await,
            Err(LoginError::BadCredentials)
        );
    }
}

#[tokio::test]
async fn rejects_an_empty_email_without_requests() {
    let api = api(FakeTransport::with(vec![]));
    assert_eq!(
        session::login(&api, " # alias", PASSWORD, None).await,
        Err(LoginError::InvalidEmail)
    );
    assert!(api.transport().requests().is_empty());
}

#[tokio::test]
async fn a_new_login_does_not_reuse_or_keep_an_old_session() {
    let api = api(FakeTransport::with(vec![ok("[-9]")]));
    api.set_session_id(Some("OLD".into()));
    assert!(
        session::login(&api, "user@example.com", PASSWORD, None)
            .await
            .is_err()
    );
    assert!(!api.transport().requests()[0].url.contains("sid=OLD"));
    assert_eq!(api.session_id(), None);
}

#[tokio::test]
async fn infers_the_account_version_when_prelogin_omits_it() {
    // A salt means a v2 account even without `v`.
    let api = api(FakeTransport::with(vec![
        ok(&json!([{"s": SALT}]).to_string()),
        ok("[0]"),
        ok(&us_reply(K_V2)),
    ]));
    let session = session::login(&api, "user@example.com", PASSWORD, None)
        .await
        .unwrap();
    assert_eq!(session.sid, SID);
}

#[tokio::test]
async fn rejects_rsa_keys_of_unreasonable_size() {
    // A consistent but huge key: p = 2^9000 + 1, q = 2^9000, u = 1, so the
    // CRT check passes and only the size cap can reject it.
    fn mpi(bytes: &[u8]) -> Vec<u8> {
        let bits = bytes.len() * 8 - bytes[0].leading_zeros() as usize;
        let mut out = (bits as u16).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }
    let mut q = vec![0u8; 1126];
    q[0] = 0x01; // 2^9000 occupies 1126 bytes with the top byte 0x01
    let mut p = q.clone();
    *p.last_mut().unwrap() = 1;
    let mut privk = [mpi(&p), mpi(&q), mpi(&[3]), mpi(&[1])].concat();
    privk.resize(privk.len().div_ceil(16) * 16, 0);
    let password_aes = [7u8; 16];
    let master = [3u8; 16];
    let reply = json!([{
        "k": b64url_encode(&ecb_encrypt(&password_aes, &master).unwrap()),
        "privk": b64url_encode(&ecb_encrypt(&master, &privk).unwrap()),
        "csid": b64url_encode(&mpi(&[5])),
        "u": "U",
    }])
    .to_string();
    let api = api(FakeTransport::with(vec![ok(&reply)]));
    let credentials = Credentials {
        email: "e@x.y".into(),
        password_aes,
        user_hash: "uh".into(),
    };
    assert!(matches!(
        session::login_with_credentials(&api, &credentials, Some("1")).await,
        Err(LoginError::Malformed(m)) if m.contains("too large")
    ));
}
