use std::path::Path;

use megaquarry_core::crypto::b64url_encode;
use megaquarry_core::session::{Credentials, Session};
use megaquarry_core::store::{
    KNOWN_SETTINGS, QueueKind, Settings, Store, StoreError, Vault, validate_setting,
};
use serde_json::json;

fn credentials(email: &str) -> Credentials {
    Credentials {
        email: email.into(),
        password_aes: [0x11; 16],
        user_hash: "USERHASH-SECRET".into(),
    }
}

fn session(email: &str) -> Session {
    Session {
        sid: "SESSION-ID-SECRET".into(),
        master_key: [0x22; 16],
        user_handle: "HANDLE".into(),
        credentials: credentials(email),
    }
}

fn raw_db(dir: &tempfile::TempDir) -> Vec<u8> {
    let mut bytes = std::fs::read(dir.path().join("db.sqlite")).unwrap();
    if let Ok(wal) = std::fs::read(dir.path().join("db.sqlite-wal")) {
        bytes.extend(wal);
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn settings_use_defaults_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    {
        let store = Store::open(&path).unwrap();
        let settings = Settings::load(&store).unwrap();
        assert_eq!(settings, Settings::default());
        assert_eq!(settings.download_workers, 6);
        assert_eq!(settings.max_downloads, 4);
        assert_eq!(settings.max_uploads, 4);
        assert!(settings.verify_downloads);
        assert!(settings.multi_slot_downloads);
        assert_eq!(settings.download_speed_limit, None);

        store.set_setting("download_connections", "12").unwrap();
        store.set_setting("verify_downloads", "no").unwrap();
        store.set_setting("download_speed_limit", "250").unwrap();
        store.set_setting("max_downloads", "not a number").unwrap();
    }
    let store = Store::open(&path).unwrap();
    let settings = Settings::load(&store).unwrap();
    assert_eq!(settings.download_workers, 12);
    assert!(!settings.verify_downloads);
    // The stored value is in KiB/s.
    assert_eq!(settings.download_speed_limit, Some(250 * 1024));
    // Unparsable values fall back to the default.
    assert_eq!(settings.max_downloads, 4);
    assert_eq!(
        store.setting("verify_downloads").unwrap().as_deref(),
        Some("no")
    );
}

#[test]
fn settings_clamp_out_of_range_values() {
    let store = Store::open_in_memory().unwrap();
    store.set_setting("download_connections", "99").unwrap();
    store.set_setting("max_uploads", "0").unwrap();
    let settings = Settings::load(&store).unwrap();
    assert_eq!(settings.download_workers, 20);
    assert_eq!(settings.max_uploads, 1);
}

#[test]
fn stores_accounts_and_sessions_without_a_master_password() {
    let store = Store::open_in_memory().unwrap();
    let vault = store.unlock(None).unwrap();
    store.save_account(&vault, &credentials("a@x.y")).unwrap();
    store.save_account(&vault, &credentials("b@x.y")).unwrap();
    store.save_session(&vault, &session("a@x.y")).unwrap();

    assert_eq!(store.account_emails().unwrap(), vec!["a@x.y", "b@x.y"]);
    assert_eq!(
        store.account(&vault, "a@x.y").unwrap(),
        Some(credentials("a@x.y"))
    );
    assert_eq!(
        store.session(&vault, "a@x.y").unwrap(),
        Some(session("a@x.y"))
    );
    assert_eq!(store.session(&vault, "b@x.y").unwrap(), None);

    store.delete_account("a@x.y").unwrap();
    assert_eq!(store.account(&vault, "a@x.y").unwrap(), None);
    assert_eq!(
        store.session(&vault, "a@x.y").unwrap(),
        None,
        "session goes too"
    );
}

#[test]
fn a_master_password_encrypts_secrets_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    {
        let store = Store::open(&path).unwrap();
        let plain = store.unlock(None).unwrap();
        store.save_account(&plain, &credentials("a@x.y")).unwrap();
        store.save_session(&plain, &session("a@x.y")).unwrap();
        assert!(!store.has_master_password().unwrap());

        let vault = store.set_master_password(&plain, Some("hunter2")).unwrap();
        assert!(store.has_master_password().unwrap());
        assert_eq!(
            store.account(&vault, "a@x.y").unwrap(),
            Some(credentials("a@x.y"))
        );
        store.checkpoint().unwrap();
    }
    let raw = raw_db(&dir);
    assert!(!contains(&raw, b"USERHASH-SECRET"));
    assert!(!contains(&raw, b"SESSION-ID-SECRET"));

    let store = Store::open(&path).unwrap();
    assert!(matches!(store.unlock(None), Err(StoreError::Locked)));
    assert!(matches!(
        store.unlock(Some("wrong")),
        Err(StoreError::WrongPassword)
    ));
    let vault = store.unlock(Some("hunter2")).unwrap();
    assert_eq!(
        store.session(&vault, "a@x.y").unwrap(),
        Some(session("a@x.y"))
    );
}

#[test]
fn changing_or_removing_the_master_password_reencrypts() {
    let store = Store::open_in_memory().unwrap();
    let plain = store.unlock(None).unwrap();
    store.save_account(&plain, &credentials("a@x.y")).unwrap();
    let first = store.set_master_password(&plain, Some("one")).unwrap();
    let second = store.set_master_password(&first, Some("two")).unwrap();

    assert!(matches!(
        store.unlock(Some("one")),
        Err(StoreError::WrongPassword)
    ));
    assert!(
        store.account(&first, "a@x.y").is_err(),
        "old key no longer opens rows"
    );
    assert_eq!(
        store.account(&second, "a@x.y").unwrap(),
        Some(credentials("a@x.y"))
    );

    let cleared = store.set_master_password(&second, None).unwrap();
    assert!(!store.has_master_password().unwrap());
    assert_eq!(
        store.account(&cleared, "a@x.y").unwrap(),
        Some(credentials("a@x.y"))
    );
    assert!(store.unlock(None).is_ok());
}

#[test]
fn vault_blobs_detect_tampering() {
    let vault = Vault::derive("pw", &[5; 16]);
    let blob = vault.seal(b"secret data");
    assert!(blob.starts_with(b"MQV1"));
    assert_eq!(vault.open(&blob).unwrap(), b"secret data");
    // Two seals of the same data differ (random IV).
    assert_ne!(vault.seal(b"secret data"), blob);

    let mut tampered = blob.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(vault.open(&tampered).is_err());
    assert!(Vault::derive("other", &[5; 16]).open(&blob).is_err());
}

#[test]
fn the_transfer_queue_keeps_order_and_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let (first, second);
    {
        let store = Store::open(&path).unwrap();
        first = store
            .enqueue(QueueKind::Download, &json!({"link": "L1"}))
            .unwrap();
        second = store
            .enqueue(QueueKind::Download, &json!({"link": "L2"}))
            .unwrap();
        store
            .enqueue(QueueKind::Upload, &json!({"path": "/tmp/x"}))
            .unwrap();
        store
            .update_entry(first, &json!({"link": "L1", "done": 10}))
            .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let downloads = store.entries(QueueKind::Download).unwrap();
    assert_eq!(downloads.len(), 2);
    assert_eq!(downloads[0].id, first);
    assert_eq!(downloads[0].payload, json!({"link": "L1", "done": 10}));
    assert_eq!(downloads[1].id, second);
    assert_eq!(store.entries(QueueKind::Upload).unwrap().len(), 1);

    store.remove_entry(first).unwrap();
    assert_eq!(store.entries(QueueKind::Download).unwrap()[0].id, second);
    assert!(matches!(
        store.update_entry(first, &json!({})),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn refuses_databases_from_a_newer_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    drop(Store::open(&path).unwrap());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::UnsupportedSchema(99))
    ));
}

/// Which secrets appear in the on-disk files (from the independent
/// verification of the store).
fn leaks(dir: &Path) -> Vec<String> {
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("user_hash", b"USERHASH-SECRET".to_vec()),
        ("sid", b"SESSION-ID-SECRET".to_vec()),
        ("password_aes", b64url_encode(&[0x11; 16]).into_bytes()),
        ("master_key", b64url_encode(&[0x22; 16]).into_bytes()),
    ];
    let mut out = vec![];
    for f in ["db.sqlite", "db.sqlite-wal", "db.sqlite-journal"] {
        if let Ok(bytes) = std::fs::read(dir.join(f)) {
            for (name, needle) in &needles {
                if contains(&bytes, needle) {
                    out.push(format!("{f}:{name}"));
                }
            }
        }
    }
    out
}

/// Copies the database files as a killed process would leave them.
fn snapshot(dir: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for f in ["db.sqlite", "db.sqlite-wal", "db.sqlite-shm"] {
        let _ = std::fs::copy(dir.join(f), to.join(f));
    }
}

#[test]
fn no_plaintext_secret_survives_a_crash_after_setting_a_master_password() {
    // Plaintext written in the same session (still in the WAL)...
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("db.sqlite")).unwrap();
    let plain = store.unlock(None).unwrap();
    store.save_account(&plain, &credentials("a@x.y")).unwrap();
    store.save_session(&plain, &session("a@x.y")).unwrap();
    store.set_master_password(&plain, Some("hunter2")).unwrap();
    let crashed = dir.path().join("crash");
    snapshot(dir.path(), &crashed);
    std::mem::forget(store);
    assert_eq!(leaks(&crashed), Vec::<String>::new());

    // ...and plaintext already checkpointed into the main file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    {
        let store = Store::open(&path).unwrap();
        let plain = store.unlock(None).unwrap();
        store.save_account(&plain, &credentials("a@x.y")).unwrap();
        store.save_session(&plain, &session("a@x.y")).unwrap();
    }
    let store = Store::open(&path).unwrap();
    let plain = store.unlock(None).unwrap();
    store.set_master_password(&plain, Some("hunter2")).unwrap();
    let crashed = dir.path().join("crash");
    snapshot(dir.path(), &crashed);
    std::mem::forget(store);
    assert_eq!(leaks(&crashed), Vec::<String>::new());
}

#[test]
fn saving_with_the_wrong_vault_is_refused() {
    let store = Store::open_in_memory().unwrap();
    let plain = store.unlock(None).unwrap();
    let vault = store.set_master_password(&plain, Some("pw")).unwrap();
    assert!(matches!(
        store.save_account(&plain, &credentials("a@x.y")),
        Err(StoreError::WrongPassword)
    ));
    assert!(matches!(
        store.save_session(&Vault::derive("other", &[0; 16]), &session("a@x.y")),
        Err(StoreError::WrongPassword)
    ));
    store.save_account(&vault, &credentials("a@x.y")).unwrap();
    assert_eq!(
        store.account(&vault, "a@x.y").unwrap(),
        Some(credentials("a@x.y"))
    );
}

#[test]
fn an_empty_master_password_turns_encryption_off() {
    let store = Store::open_in_memory().unwrap();
    let plain = store.unlock(None).unwrap();
    let vault = store.set_master_password(&plain, Some("")).unwrap();
    assert!(!vault.is_encrypted());
    assert!(!store.has_master_password().unwrap());
}

#[test]
fn concurrent_first_opens_of_a_new_database_succeed() {
    for _ in 0..10 {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("db.sqlite"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    Store::open(&path).map(|_| ())
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
    }
}

#[test]
fn removing_a_missing_queue_entry_is_reported() {
    let store = Store::open_in_memory().unwrap();
    assert!(matches!(store.remove_entry(42), Err(StoreError::NotFound)));
}

#[test]
fn flags_are_true_only_for_yes() {
    let store = Store::open_in_memory().unwrap();
    store.set_setting("verify_downloads", "maybe").unwrap();
    store.set_setting("upload_public_links", "YES").unwrap();
    let settings = Settings::load(&store).unwrap();
    // Invalid flags fall back to their defaults.
    assert!(settings.verify_downloads);
    assert!(!settings.generate_upload_links);
}

#[test]
fn defaults_match_the_documented_contract() {
    let settings = Settings::default();
    assert!(
        !settings.generate_upload_links,
        "uploads are private by default"
    );
    assert_eq!(settings.download_account, None);
    assert_eq!(settings.upload_speed_limit, None);
    let keys: Vec<_> = KNOWN_SETTINGS.iter().map(|s| s.key).collect();
    assert_eq!(
        keys,
        [
            "download_dir",
            "download_connections",
            "max_downloads",
            "upload_connections",
            "max_uploads",
            "verify_downloads",
            "download_speed_limit",
            "upload_speed_limit",
            "upload_public_links",
            "download_account",
            "app_key",
            "egress_cooldown_fallback",
            "egress_max_attempts",
            "egress_reconnect_timeout",
        ]
    );
}

#[test]
fn one_download_connection_is_single_connection_mode() {
    let store = Store::open_in_memory().unwrap();
    store.set_setting("download_connections", "1").unwrap();
    let settings = Settings::load(&store).unwrap();
    assert_eq!(settings.download_workers, 1);
    assert!(!settings.multi_slot_downloads);
    assert!(Settings::default().multi_slot_downloads);
}

#[test]
fn a_zero_speed_limit_is_unlimited() {
    let store = Store::open_in_memory().unwrap();
    store.set_setting("upload_speed_limit", "0").unwrap();
    store.set_setting("download_speed_limit", "5").unwrap();
    let settings = Settings::load(&store).unwrap();
    assert_eq!(settings.upload_speed_limit, None);
    assert_eq!(settings.download_speed_limit, Some(5 * 1024));
}

#[test]
fn the_download_account_is_used_when_set() {
    let store = Store::open_in_memory().unwrap();
    store
        .set_setting("download_account", "me@example.com")
        .unwrap();
    let settings = Settings::load(&store).unwrap();
    assert_eq!(settings.download_account.as_deref(), Some("me@example.com"));
}

#[test]
fn validation_names_the_allowed_values() {
    assert_eq!(
        validate_setting("max_downloads", "abc")
            .unwrap_err()
            .to_string(),
        r#"max_downloads must be a number from 1 to 50 (got "abc")"#
    );
    assert_eq!(
        validate_setting("max_downloads", "51")
            .unwrap_err()
            .to_string(),
        r#"max_downloads must be a number from 1 to 50 (got "51")"#
    );
    assert_eq!(
        validate_setting("verify_downloads", "true")
            .unwrap_err()
            .to_string(),
        r#"verify_downloads must be yes or no (got "true")"#
    );
    assert_eq!(
        validate_setting("nope", "1").unwrap_err().to_string(),
        "unknown setting `nope` (see `megaquarry config list`)"
    );
    assert!(validate_setting("max_downloads", "50").is_ok());
    assert!(validate_setting("verify_downloads", "no").is_ok());
    assert!(validate_setting("download_speed_limit", "0").is_ok());
    assert!(validate_setting("download_dir", "/tmp/x").is_ok());
}

#[test]
fn bad_stored_values_are_reported_when_loading() {
    let store = Store::open_in_memory().unwrap();
    store.set_setting("max_downloads", "abc").unwrap();
    store.set_setting("max_uploads", "500").unwrap();
    store.set_setting("verify_downloads", "true").unwrap();
    let (settings, warnings) = Settings::load_with_warnings(&store).unwrap();
    assert_eq!(settings.max_downloads, 4);
    assert_eq!(settings.max_uploads, 50);
    assert!(settings.verify_downloads);
    assert_eq!(
        warnings,
        [
            r#"max_downloads must be a number from 1 to 50 (got "abc"); using 4"#,
            r#"max_uploads must be a number from 1 to 50 (got "500"); using 50"#,
            r#"verify_downloads must be yes or no (got "true"); using yes"#,
        ]
    );
    let (_, none) = Settings::load_with_warnings(&Store::open_in_memory().unwrap()).unwrap();
    assert!(none.is_empty());
}

#[cfg(unix)]
#[test]
fn database_files_are_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data/db.sqlite");
    let store = Store::open(&path).unwrap();
    let plain = store.unlock(None).unwrap();
    store.save_account(&plain, &credentials("a@x.y")).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir.path().join("data")), 0o700);
    assert_eq!(mode(&dir.path().join("data/db.sqlite-wal")), 0o600);
}

#[test]
fn a_password_for_an_unencrypted_store_is_reported() {
    let store = Store::open_in_memory().unwrap();
    assert!(matches!(
        store.unlock(Some("pw")),
        Err(StoreError::NotEncrypted)
    ));
    assert!(store.unlock(None).is_ok());
}

#[test]
fn entry_fields_are_updated_without_clobbering_others() {
    let store = Store::open_in_memory().unwrap();
    let id = store
        .enqueue(QueueKind::Upload, &json!({"path": "/x"}))
        .unwrap();
    store
        .set_entry_field(id, "state", &json!("paused"))
        .unwrap();
    store
        .set_entry_field(id, "checkpoint", &json!({"url": "u"}))
        .unwrap();
    assert_eq!(
        store.entry(id).unwrap().unwrap().payload,
        json!({"path": "/x", "state": "paused", "checkpoint": {"url": "u"}})
    );
    store.remove_entry_field(id, "state").unwrap();
    assert_eq!(
        store.entry(id).unwrap().unwrap().payload,
        json!({"path": "/x", "checkpoint": {"url": "u"}})
    );
    assert!(matches!(
        store.set_entry_field(99, "state", &json!("x")),
        Err(StoreError::NotFound)
    ));
}
