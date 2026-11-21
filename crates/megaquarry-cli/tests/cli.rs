//! End-to-end tests of the `megaquarry` binary against a local fake MEGA
//! server (API at `/cs`, storage at `/dl/<handle>/<range>`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use assert_cmd::Command;
use megaquarry_core::chunk::meta_mac_of;
use megaquarry_core::crypto::{
    Attributes, FileKey, b64url_encode, ctr_apply, ecb_encrypt, encrypt_attributes,
};
use megaquarry_core::link::MegaLink;
use serde_json::{Value, json};

#[path = "../../megaquarry-core/tests/common/gluetun.rs"]
mod gluetun;
use gluetun::FakeGluetun;

// Login fixture (tools/gen_vectors.py, as in the core login tests).
const SALT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const PASSWORD: &str = "correct horse battery staple";

struct RemoteFile {
    plain: Vec<u8>,
    ciphertext: Vec<u8>,
    key: FileKey,
    name: &'static str,
}

fn remote_file(name: &'static str, size: usize, seed: u8) -> RemoteFile {
    let plain: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(seed)).collect();
    let (aes_key, nonce) = ([seed; 16], [seed ^ 0x55; 8]);
    let key = FileKey::pack(&aes_key, &nonce, &meta_mac_of(&aes_key, &nonce, &plain));
    let mut ciphertext = plain.clone();
    ctr_apply(&aes_key, &nonce, 0, &mut ciphertext);
    RemoteFile {
        plain,
        ciphertext,
        key,
        name,
    }
}

fn attr(name: &str, key: &[u8; 16]) -> String {
    b64url_encode(&encrypt_attributes(&Attributes::with_name(name), key).unwrap())
}

struct Fake {
    base: String,
    files: HashMap<String, RemoteFile>,
    folder_key: [u8; 16],
    login: Option<Value>,
    /// Every API command received, in order.
    commands: std::sync::Mutex<Vec<Value>>,
    /// Number of initial `uq` calls answered with ESID (-15).
    expired_sessions: std::sync::atomic::AtomicUsize,
    uploads: std::sync::Mutex<HashMap<String, usize>>,
    /// Storage answers 509 (with MEGA's wait) while set.
    quota: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Fake {
    fn file_link(&self, handle: &str) -> String {
        MegaLink::File {
            handle: handle.into(),
            key: self.files[handle].key.clone(),
        }
        .to_url()
    }

    fn folder_link(&self) -> String {
        MegaLink::Folder {
            handle: "FOLDER".into(),
            key: self.folder_key,
            subfolder: None,
        }
        .to_url()
    }
}

/// Starts the fake server on a background thread.
fn start(login: Option<Value>) -> std::sync::Arc<Fake> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut files = HashMap::new();
    files.insert(
        "SINGLE".to_string(),
        remote_file("report.pdf", 300 * 1024, 7),
    );
    files.insert("FA".to_string(), remote_file("a.txt", 1000, 3));
    files.insert("FB".to_string(), remote_file("b.bin", 5000, 5));
    let fake = std::sync::Arc::new(Fake {
        base,
        files,
        folder_key: [0x42; 16],
        login,
        commands: std::sync::Mutex::default(),
        expired_sessions: std::sync::atomic::AtomicUsize::new(0),
        uploads: std::sync::Mutex::default(),
        quota: std::sync::Arc::default(),
    });
    let server = fake.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let server = server.clone();
            std::thread::spawn(move || handle(&server, stream));
        }
    });
    fake
}

fn handle(fake: &Fake, mut stream: TcpStream) {
    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    let (head, body) = loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return;
        }
        data.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length: usize = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                break (
                    text[..end].to_owned(),
                    data[end + 4..end + 4 + length].to_vec(),
                );
            }
        }
    };
    let target = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    if target.starts_with("/dl/") && fake.quota.load(std::sync::atomic::Ordering::SeqCst) {
        let _ = write!(
            stream,
            "HTTP/1.1 509 Bandwidth Limit Exceeded\r\nX-MEGA-Time-Left: 600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        return;
    }
    let reply = if target.starts_with("/cs") {
        api_reply(fake, &target, &body).into_bytes()
    } else if let Some(rest) = target.strip_prefix("/dl/") {
        let (handle, range) = rest.split_once('/').unwrap();
        let cipher = &fake.files[handle].ciphertext;
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (s.parse::<usize>().unwrap(), e.parse::<usize>().unwrap() + 1),
            None => (range.parse().unwrap(), cipher.len()),
        };
        cipher[start..end].to_vec()
    } else if let Some(rest) = target.strip_prefix("/ul/") {
        // Upload storage: answer a completion token once all bytes arrived.
        let (upload, _offset) = rest.split_once('/').unwrap();
        let (size, received) = upload.split_once('-').unwrap();
        let mut uploads = fake.uploads.lock().unwrap();
        let total = uploads.entry(received.to_owned()).or_insert(0);
        *total += body.len();
        if *total >= size.parse::<usize>().unwrap() {
            format!("TOKEN-{received}").into_bytes()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.len()
    );
    let _ = stream.write_all(&reply);
}

fn api_reply(fake: &Fake, target: &str, body: &[u8]) -> String {
    let commands: Value = serde_json::from_slice(body).unwrap();
    let command = &commands[0];
    fake.commands.lock().unwrap().push(command.clone());
    let reply = match command["a"].as_str().unwrap_or_default() {
        "g" => {
            let handle = command["p"].as_str().or(command["n"].as_str()).unwrap();
            let file = &fake.files[handle];
            let mut reply = json!({
                "s": file.plain.len(),
                "at": attr(file.name, &file.key.aes_key()),
            });
            if command.get("g").is_some() {
                reply["g"] = json!(format!("{}/dl/{handle}", fake.base));
            }
            reply
        }
        "f" if target.contains("&n=FOLDER") => {
            let wrap = |k: &[u8]| {
                format!(
                    "O:{}",
                    b64url_encode(&ecb_encrypt(&fake.folder_key, k).unwrap())
                )
            };
            let (root, sub) = ([1u8; 16], [2u8; 16]);
            let (a, b) = (&fake.files["FA"], &fake.files["FB"]);
            json!({"f": [
                {"h": "ROOT", "p": "X", "t": 1, "k": wrap(&root), "a": attr("Shared", &root)},
                {"h": "SUB", "p": "ROOT", "t": 1, "k": wrap(&sub), "a": attr("Sub", &sub)},
                {"h": "FA", "p": "ROOT", "t": 0, "s": a.plain.len(), "k": wrap(&a.key.to_bytes()), "a": attr(a.name, &a.key.aes_key())},
                {"h": "FB", "p": "SUB", "t": 0, "s": b.plain.len(), "k": wrap(&b.key.to_bytes()), "a": attr(b.name, &b.key.aes_key())},
            ]})
        }
        "us0" => json!({"v": 2, "s": SALT}),
        "mfag" => json!(0),
        "us" => fake.login.clone().unwrap_or(json!(-9)),
        "uq" => {
            let expired = &fake.expired_sessions;
            if expired.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                expired.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return "-15".into();
            }
            json!({"cstrg": 0, "mstrg": 1})
        }
        "f" => json!({"f": [{"h": "ROOT", "t": 2}, {"h": "INBOX", "t": 3}]}),
        "u" => {
            let id = fake.commands.lock().unwrap().len();
            json!({"p": format!("{}/ul/{}-{id}", fake.base, command["s"])})
        }
        "p" => {
            let id = fake.commands.lock().unwrap().len();
            json!({"f": [{"h": format!("NODE{id}"), "t": command["n"][0]["t"]}]})
        }
        "l" => json!("PUBLIC"),
        _ => json!(0),
    };
    json!([reply]).to_string()
}

fn cli(home: &Path, fake: &Fake) -> Command {
    let mut command = Command::cargo_bin("megaquarry").unwrap();
    command
        .env("MEGAQUARRY_HOME", home)
        .env("MEGAQUARRY_API_URL", &fake.base)
        .env_remove("MEGAQUARRY_PASSWORD")
        .env_remove("MEGAQUARRY_MASTER_PASSWORD")
        .env_remove("MEGAQUARRY_NEW_MASTER_PASSWORD");
    command
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn downloads_a_file_link() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let out = home.path().join("out");
    let output = cli(home.path(), &fake)
        .args(["download", &fake.file_link("SINGLE"), "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("queued 1 file(s)"));
    assert!(stdout(&output).contains("1 completed, 0 failed"));
    assert_eq!(
        std::fs::read(out.join("report.pdf")).unwrap(),
        fake.files["SINGLE"].plain
    );
}

#[test]
fn lists_and_downloads_a_folder_through_the_queue() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let out = home.path().join("out");

    let listing = cli(home.path(), &fake)
        .args(["ls", &fake.folder_link()])
        .output()
        .unwrap();
    assert!(listing.status.success(), "{}", stderr(&listing));
    let text = stdout(&listing);
    assert!(text.contains("1000 B  Shared/a.txt"), "{text}");
    assert!(text.contains("4.9 KiB  Shared/Sub/b.bin"), "{text}");
    assert!(text.contains("2 file(s), 5.9 KiB"), "{text}");

    let queued = cli(home.path(), &fake)
        .args(["download", "--no-start", &fake.folder_link(), "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(queued.status.success(), "{}", stderr(&queued));
    let list = stdout(
        &cli(home.path(), &fake)
            .args(["queue", "list"])
            .output()
            .unwrap(),
    );
    let ids: Vec<String> = list
        .lines()
        .map(|l| l.split_whitespace().next().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 2, "{list}");
    assert!(list.contains("queued"));

    cli(home.path(), &fake)
        .args(["queue", "pause", &ids[0]])
        .assert()
        .success();
    let list = stdout(
        &cli(home.path(), &fake)
            .args(["queue", "list"])
            .output()
            .unwrap(),
    );
    assert!(list.contains("paused"), "{list}");

    // A run skips the paused entry...
    let run = cli(home.path(), &fake)
        .args(["queue", "run"])
        .output()
        .unwrap();
    assert!(stdout(&run).contains("1 completed"), "{}", stdout(&run));
    assert!(out.join("Shared/Sub/b.bin").exists());
    assert!(!out.join("Shared/a.txt").exists());

    // ...until it is resumed.
    cli(home.path(), &fake)
        .args(["queue", "resume", &ids[0]])
        .assert()
        .success();
    let run = cli(home.path(), &fake)
        .args(["queue", "run"])
        .output()
        .unwrap();
    assert!(run.status.success(), "{}", stderr(&run));
    assert_eq!(
        std::fs::read(out.join("Shared/a.txt")).unwrap(),
        fake.files["FA"].plain
    );
    let list = stdout(
        &cli(home.path(), &fake)
            .args(["queue", "list"])
            .output()
            .unwrap(),
    );
    assert!(list.trim().is_empty(), "{list}");
}

#[test]
fn manages_settings() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    cli(home.path(), &fake)
        .args(["config", "set", "max_downloads", "2"])
        .assert()
        .success();
    let value = cli(home.path(), &fake)
        .args(["config", "get", "max_downloads"])
        .output()
        .unwrap();
    assert_eq!(stdout(&value).trim(), "2");
    let list = stdout(
        &cli(home.path(), &fake)
            .args(["config", "list"])
            .output()
            .unwrap(),
    );
    assert!(list.contains("max_downloads = 2    #"));
    assert!(list.contains("verify_downloads = yes (default)"));
    cli(home.path(), &fake)
        .args(["config", "unset", "max_downloads"])
        .assert()
        .success();
    let value = cli(home.path(), &fake)
        .args(["config", "get", "max_downloads"])
        .output()
        .unwrap();
    assert_eq!(stdout(&value).trim(), "4");

    let unknown = cli(home.path(), &fake)
        .args(["config", "set", "nope", "1"])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(stderr(&unknown).contains("unknown setting `nope`"));

    for (key, value, message) in [
        (
            "max_downloads",
            "abc",
            r#"max_downloads must be a number from 1 to 50 (got "abc")"#,
        ),
        (
            "verify_downloads",
            "true",
            r#"verify_downloads must be yes or no (got "true")"#,
        ),
    ] {
        let invalid = cli(home.path(), &fake)
            .args(["config", "set", key, value])
            .output()
            .unwrap();
        assert_eq!(invalid.status.code(), Some(2), "{}", stderr(&invalid));
        assert!(stderr(&invalid).contains(message), "{}", stderr(&invalid));
    }
    let value = cli(home.path(), &fake)
        .args(["config", "get", "verify_downloads"])
        .output()
        .unwrap();
    assert_eq!(
        stdout(&value).trim(),
        "yes",
        "rejected values are not stored"
    );
}

#[test]
fn warns_about_bad_stored_settings() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    megaquarry_core::store::Store::open(&home.path().join("megaquarry.db"))
        .unwrap()
        .set_setting("max_downloads", "abc")
        .unwrap();
    let output = cli(home.path(), &fake)
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        stderr(&output).contains(
            r#"warning: max_downloads must be a number from 1 to 50 (got "abc"); using 4"#
        ),
        "{}",
        stderr(&output)
    );
}

#[test]
fn settings_as_json() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    cli(home.path(), &fake)
        .args(["config", "set", "max_downloads", "2"])
        .assert()
        .success();
    let list: Value = serde_json::from_str(&stdout(
        &cli(home.path(), &fake)
            .args(["config", "list", "--json"])
            .output()
            .unwrap(),
    ))
    .unwrap();
    let settings = list["settings"].as_array().unwrap();
    assert_eq!(settings.len(), 14);
    assert_eq!(
        settings[2],
        json!({
            "key": "max_downloads",
            "value": "2",
            "default": "4",
            "is_default": false,
            "description": "downloads running at once",
        })
    );
    let one: Value = serde_json::from_str(&stdout(
        &cli(home.path(), &fake)
            .args(["config", "get", "verify_downloads", "--json"])
            .output()
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(one["value"], "yes");
    assert_eq!(one["is_default"], true);
}

#[test]
fn logs_in_and_protects_accounts_with_a_master_password() {
    // `us` reply of the login fixture (tests/login.rs in the core crate).
    let login = serde_json::from_str::<Value>(include_str!("fixtures/us_reply.json")).unwrap();
    let fake = start(Some(login));
    let home = tempfile::tempdir().unwrap();

    let output = cli(home.path(), &fake)
        .env("MEGAQUARRY_PASSWORD", PASSWORD)
        .args(["login", "User@Example.com"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("logged in as user@example.com"));
    let accounts = cli(home.path(), &fake).arg("accounts").output().unwrap();
    assert_eq!(stdout(&accounts).trim(), "user@example.com");

    cli(home.path(), &fake)
        .env("MEGAQUARRY_NEW_MASTER_PASSWORD", "s3cret")
        .args(["master-password", "set"])
        .assert()
        .success();
    // Without the master password, account secrets cannot be read.
    let locked = cli(home.path(), &fake)
        .env("MEGAQUARRY_PASSWORD", PASSWORD)
        .args(["login", "user@example.com"])
        .output()
        .unwrap();
    assert!(!locked.status.success());
    assert!(
        stderr(&locked).contains("MEGAQUARRY_MASTER_PASSWORD"),
        "{}",
        stderr(&locked)
    );
    let wrong = cli(home.path(), &fake)
        .env("MEGAQUARRY_MASTER_PASSWORD", "nope")
        .args(["master-password", "remove"])
        .output()
        .unwrap();
    assert!(stderr(&wrong).contains("wrong master password"));
    cli(home.path(), &fake)
        .env("MEGAQUARRY_MASTER_PASSWORD", "s3cret")
        .args(["master-password", "remove", "--yes"])
        .assert()
        .success();
    let accounts: Value = serde_json::from_str(&stdout(
        &cli(home.path(), &fake)
            .args(["accounts", "--json"])
            .output()
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(
        accounts,
        json!({"accounts": [{"email": "user@example.com"}]})
    );

    let wrong_password = cli(home.path(), &start(None))
        .env("MEGAQUARRY_PASSWORD", "bad")
        .args(["login", "user@example.com"])
        .output()
        .unwrap();
    assert!(stderr(&wrong_password).contains("wrong email or password"));
}

#[test]
fn rejects_invalid_links() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let output = cli(home.path(), &fake)
        .args(["download", "https://example.com/not-mega"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a recognized MEGA link"),
        "{}",
        stderr(&output)
    );
}

fn login(home: &Path, fake: &Fake) {
    let output = cli(home, fake)
        .env("MEGAQUARRY_PASSWORD", PASSWORD)
        .args(["login", "user@example.com"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
}

fn login_fake() -> std::sync::Arc<Fake> {
    start(Some(
        serde_json::from_str(include_str!("fixtures/us_reply.json")).unwrap(),
    ))
}

#[test]
fn uploads_a_directory_tree() {
    let fake = login_fake();
    let home = tempfile::tempdir().unwrap();
    login(home.path(), &fake);
    let tree = home.path().join("photos");
    std::fs::create_dir_all(tree.join("2024")).unwrap();
    std::fs::write(tree.join("a.jpg"), vec![1u8; 2000]).unwrap();
    std::fs::write(tree.join("2024/b.jpg"), vec![2u8; 3000]).unwrap();

    let output = cli(home.path(), &fake)
        .args(["upload", "--account", "user@example.com", "--public-link"])
        .arg(&tree)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("queued 2 file(s)"), "{text}");
    assert!(text.contains("2 completed, 0 failed"), "{text}");
    assert!(text.contains("https://mega.nz/file/PUBLIC#"), "{text}");

    // Folders `photos` (in the Cloud Drive) and `photos/2024` were created.
    let commands = fake.commands.lock().unwrap().clone();
    let folders: Vec<&Value> = commands
        .iter()
        .filter(|c| c["a"] == "p" && c["n"][0]["t"] == 1)
        .collect();
    assert_eq!(folders.len(), 2);
    assert_eq!(folders[0]["t"], json!("ROOT"));
    let files = commands
        .iter()
        .filter(|c| c["a"] == "p" && c["n"][0]["t"] == 0)
        .count();
    assert_eq!(files, 2);
}

#[test]
fn uploads_are_private_by_default_and_use_the_only_account() {
    let fake = login_fake();
    let home = tempfile::tempdir().unwrap();
    login(home.path(), &fake);
    let file = home.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let output = cli(home.path(), &fake)
        .arg("upload")
        .arg(&file)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("1 completed"),
        "{}",
        stdout(&output)
    );
    assert!(!stdout(&output).contains("https://mega.nz/file/"));
    let exports = fake
        .commands
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c["a"] == "l")
        .count();
    assert_eq!(exports, 0, "no public link was created");
}

#[test]
fn a_queued_upload_keeps_its_public_link_choice() {
    let fake = login_fake();
    let home = tempfile::tempdir().unwrap();
    login(home.path(), &fake);
    let file = home.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();
    cli(home.path(), &fake)
        .args(["upload", "--no-start", "--public-link"])
        .arg(&file)
        .assert()
        .success();
    let output = cli(home.path(), &fake)
        .args(["queue", "run", "--account", "user@example.com"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("https://mega.nz/file/PUBLIC#"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn uploading_without_an_account_says_how_to_add_one() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let file = home.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();
    let output = cli(home.path(), &fake)
        .arg("upload")
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no stored account: run `megaquarry login EMAIL` first"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn downloading_does_not_fail_queued_uploads() {
    let fake = login_fake();
    let home = tempfile::tempdir().unwrap();
    login(home.path(), &fake);
    let file = home.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();
    cli(home.path(), &fake)
        .args(["upload", "--no-start", "--account", "user@example.com"])
        .arg(&file)
        .assert()
        .success();

    let output = cli(home.path(), &fake)
        .args(["download", &fake.file_link("SINGLE"), "-o"])
        .arg(home.path().join("out"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let list = stdout(
        &cli(home.path(), &fake)
            .args(["queue", "list"])
            .output()
            .unwrap(),
    );
    assert!(list.contains("upload    queued"), "{list}");

    let run = cli(home.path(), &fake)
        .args(["queue", "run", "--account", "user@example.com"])
        .output()
        .unwrap();
    assert!(stdout(&run).contains("1 completed"), "{}", stdout(&run));
}

#[test]
fn an_expired_cached_session_logs_in_again() {
    let fake = login_fake();
    let home = tempfile::tempdir().unwrap();
    login(home.path(), &fake);
    fake.expired_sessions
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let file = home.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();
    let output = cli(home.path(), &fake)
        .args(["upload", "--account", "user@example.com"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let logins = fake
        .commands
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c["a"] == "us")
        .count();
    assert_eq!(logins, 2, "the first login plus a fresh one");
}

// --- exit IP rotation ------------------------------------------------------

const KEY: &str = "test-api-key";

/// A fake gluetun whose reconnects clear the fake MEGA's quota.
fn gluetun(fake: &Fake, ip: &str, next_ips: &[&str]) -> std::sync::Arc<FakeGluetun> {
    let gluetun = FakeGluetun::start(KEY, ip, next_ips);
    let quota = fake.quota.clone();
    *gluetun.on_start.lock().unwrap() = Some(Box::new(move || {
        quota.store(false, std::sync::atomic::Ordering::SeqCst);
    }));
    gluetun
}

/// The CLI with rotation through `gluetun`; the key file lives in `home`.
fn rotating_cli(home: &Path, fake: &Fake, gluetun: &FakeGluetun) -> Command {
    let key_file = home.join("gluetun.key");
    std::fs::write(&key_file, format!("{KEY}\n")).unwrap();
    let mut command = cli(home, fake);
    command
        .env("MEGAQUARRY_EGRESS_URL", &gluetun.base)
        .env("MEGAQUARRY_EGRESS_KEY_FILE", &key_file);
    command
}

fn queue_list(home: &Path, fake: &Fake) -> String {
    stdout(&cli(home, fake).args(["queue", "list"]).output().unwrap())
}

#[test]
fn rotates_the_exit_ip_when_a_download_hits_the_quota() {
    let fake = start(None);
    fake.quota.store(true, std::sync::atomic::Ordering::SeqCst);
    let gluetun = gluetun(&fake, "1.1.1.1", &["2.2.2.2", "3.3.3.3"]);
    let home = tempfile::tempdir().unwrap();
    let out = home.path().join("out");

    let output = rotating_cli(home.path(), &fake, &gluetun)
        .args(["download", &fake.file_link("SINGLE"), "-o"])
        .arg(&out)
        .output()
        .unwrap();

    let err = stderr(&output);
    assert!(output.status.success(), "{err}");
    assert!(err.contains("downloading through exit IP 1.1.1.1"), "{err}");
    assert!(err.contains("quota hit on 1.1.1.1"), "{err}");
    assert!(err.contains("now on 2.2.2.2 (cooling: 1)"), "{err}");
    assert_eq!(
        std::fs::read(out.join("report.pdf")).unwrap(),
        fake.files["SINGLE"].plain
    );

    // The cooldown survives the process: a later run that starts on the
    // resting IP moves away from it before downloading.
    {
        let mut state = gluetun.state.lock().unwrap();
        state.ip = "1.1.1.1".into();
    }
    let output = rotating_cli(home.path(), &fake, &gluetun)
        .args(["download", &fake.file_link("FA"), "-o"])
        .arg(&out)
        .output()
        .unwrap();
    let err = stderr(&output);
    assert!(output.status.success(), "{err}");
    assert!(err.contains("1.1.1.1 is still resting"), "{err}");
    assert!(err.contains("downloading through exit IP 3.3.3.3"), "{err}");
}

#[test]
fn refuses_a_vpn_control_that_accepts_requests_without_a_key() {
    let fake = start(None);
    let gluetun = gluetun(&fake, "1.1.1.1", &[]);
    gluetun.state.lock().unwrap().open = true;
    let home = tempfile::tempdir().unwrap();

    let output = rotating_cli(home.path(), &fake, &gluetun)
        .args(["download", &fake.file_link("SINGLE")])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("accepts requests without an API key"),
        "{}",
        stderr(&output)
    );
    assert!(
        fake.commands.lock().unwrap().is_empty(),
        "nothing reached MEGA"
    );
    assert!(queue_list(home.path(), &fake).is_empty());
}

#[test]
fn stops_at_startup_when_the_vpn_is_not_up() {
    let fake = start(None);
    let gluetun = gluetun(&fake, "", &[]);
    gluetun.state.lock().unwrap().status = "stopped".into();
    let home = tempfile::tempdir().unwrap();
    cli(home.path(), &fake)
        .args(["config", "set", "egress_reconnect_timeout", "1"])
        .assert()
        .success();

    let output = rotating_cli(home.path(), &fake, &gluetun)
        .args(["download", &fake.file_link("SINGLE")])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("docker compose logs vpn"),
        "{}",
        stderr(&output)
    );
    assert!(
        fake.commands.lock().unwrap().is_empty(),
        "nothing reached MEGA"
    );
}

#[test]
fn a_missing_api_key_file_is_reported() {
    let fake = start(None);
    let gluetun = gluetun(&fake, "1.1.1.1", &[]);
    let home = tempfile::tempdir().unwrap();

    let output = cli(home.path(), &fake)
        .env("MEGAQUARRY_EGRESS_URL", &gluetun.base)
        .env(
            "MEGAQUARRY_EGRESS_KEY_FILE",
            home.path().join("missing.key"),
        )
        .args(["download", &fake.file_link("SINGLE")])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("missing.key"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn downloads_through_an_account_do_not_rotate() {
    let fake = login_fake();
    let gluetun = gluetun(&fake, "1.1.1.1", &["2.2.2.2"]);
    let home = tempfile::tempdir().unwrap();
    login(home.path(), &fake);
    cli(home.path(), &fake)
        .args(["config", "set", "download_account", "user@example.com"])
        .assert()
        .success();

    let output = rotating_cli(home.path(), &fake, &gluetun)
        .args(["download", &fake.file_link("SINGLE"), "-o"])
        .arg(home.path().join("out"))
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("downloads through an account do not rotate"),
        "{}",
        stderr(&output)
    );
    assert!(gluetun.requests().is_empty());
}

#[test]
fn only_one_transfer_runs_at_a_time() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let lock =
        megaquarry_core::store::TransferLock::try_acquire(&home.path().join("transfer.lock"))
            .unwrap()
            .expect("the lock is free");

    let output = cli(home.path(), &fake)
        .args(["download", &fake.file_link("SINGLE")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        stderr(&output).contains("another megaquarry transfer is running"),
        "{}",
        stderr(&output)
    );
    assert!(
        queue_list(home.path(), &fake).is_empty(),
        "nothing was queued"
    );
    assert!(
        fake.commands.lock().unwrap().is_empty(),
        "nothing reached MEGA"
    );

    let output = cli(home.path(), &fake)
        .args(["queue", "run"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));

    // Commands that do not transfer keep working.
    cli(home.path(), &fake)
        .args(["download", "--no-start", &fake.file_link("SINGLE"), "-o"])
        .arg(home.path().join("out"))
        .assert()
        .success();
    assert!(queue_list(home.path(), &fake).contains("queued"));

    drop(lock);
    let output = cli(home.path(), &fake)
        .args(["queue", "run"])
        .output()
        .unwrap();
    assert!(
        stdout(&output).contains("1 completed"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn help_documents_the_rotation_options() {
    for command in [["download", "--help"], ["queue", "run"]] {
        let mut args: Vec<&str> = command.to_vec();
        if args[0] == "queue" {
            args.push("--help");
        }
        let output = Command::cargo_bin("megaquarry")
            .unwrap()
            .args(&args)
            .output()
            .unwrap();
        let help = stdout(&output);
        assert!(help.contains("--egress-url"), "{help}");
        assert!(help.contains("--egress-key-file"), "{help}");
    }
    let output = Command::cargo_bin("megaquarry")
        .unwrap()
        .args(["login", "--help"])
        .output()
        .unwrap();
    assert!(
        !stdout(&output).contains("--egress-url"),
        "{}",
        stdout(&output)
    );
}

fn help(args: &[&str]) -> String {
    let output = Command::cargo_bin("megaquarry")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    stdout(&output)
}

#[test]
fn help_describes_the_tool_with_examples_and_exit_codes() {
    let top = help(&["--help"]);
    assert!(
        top.contains("Download and upload MEGA files from the command line."),
        "{top}"
    );
    assert!(top.contains("Exit codes:"), "{top}");
    assert!(top.contains("another transfer is already running"), "{top}");
    for command in [
        &["download", "--help"][..],
        &["ls", "--help"],
        &["upload", "--help"],
        &["queue", "--help"],
    ] {
        let text = help(command);
        assert!(text.contains("Examples:"), "{command:?}: {text}");
        assert!(text.contains("megaquarry "), "{command:?}: {text}");
    }
}

#[test]
fn unknown_queue_entries_are_named() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    for action in ["pause", "resume", "remove"] {
        let output = cli(home.path(), &fake)
            .args(["queue", action, "99999"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).contains("no queue entry 99999 (see `megaquarry queue list`)"),
            "{action}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn a_run_with_failed_transfers_exits_with_4() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let out = home.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("report.pdf"), b"already here").unwrap();
    let output = cli(home.path(), &fake)
        .args(["download", &fake.file_link("SINGLE"), "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("0 completed, 1 failed"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn bad_usage_exits_with_2() {
    let output = Command::cargo_bin("megaquarry")
        .unwrap()
        .args(["download"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn quiet_hides_progress_but_keeps_results() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let output = cli(home.path(), &fake)
        .args(["-q", "download", &fake.file_link("SINGLE"), "-o"])
        .arg(home.path().join("out"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    assert!(stdout(&output).contains("queued 1 file(s)"));
    assert!(stdout(&output).contains("1 completed, 0 failed"));
}

#[test]
fn progress_is_quiet_when_stderr_is_not_a_terminal() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let output = cli(home.path(), &fake)
        .args(["download", &fake.file_link("SINGLE"), "-o"])
        .arg(home.path().join("out"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("started download"), "{err}");
    assert!(!err.contains('%'), "no percentage lines in logs: {err}");
}

#[test]
fn links_and_the_queue_as_json() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    let listing: Value = serde_json::from_str(&stdout(
        &cli(home.path(), &fake)
            .args(["ls", "--json", &fake.folder_link()])
            .output()
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(listing["count"], 2);
    assert_eq!(listing["total_size"], 6000);
    let paths: Vec<&str> = listing["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["Shared/a.txt", "Shared/Sub/b.bin"]);
    assert_eq!(listing["files"][0]["name"], "a.txt");
    assert_eq!(listing["files"][0]["size"], 1000);
    assert!(
        listing["files"][0]["link"]
            .as_str()
            .unwrap()
            .starts_with("https://mega.nz/")
    );

    cli(home.path(), &fake)
        .args(["download", "--no-start", &fake.folder_link(), "-o"])
        .arg(home.path().join("out"))
        .assert()
        .success();
    let queue: Value = serde_json::from_str(&stdout(
        &cli(home.path(), &fake)
            .args(["queue", "list", "--json"])
            .output()
            .unwrap(),
    ))
    .unwrap();
    let entries = queue["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries[0]["id"].is_i64());
    assert_eq!(entries[0]["kind"], "download");
    assert_eq!(entries[0]["state"], "queued");
    assert_eq!(entries[0]["error"], Value::Null);
    assert!(entries[0]["target"].as_str().unwrap().ends_with("a.txt"));
}

#[test]
fn prints_shell_completions_without_a_data_directory() {
    let home = tempfile::tempdir().unwrap();
    let never = home.path().join("never");
    for (shell, marker) in [
        ("bash", "_megaquarry"),
        ("zsh", "#compdef megaquarry"),
        ("fish", "complete -c megaquarry"),
    ] {
        let output = Command::cargo_bin("megaquarry")
            .unwrap()
            .env("MEGAQUARRY_HOME", &never)
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).contains(marker), "{shell}");
    }
    assert!(!never.exists());
}

#[test]
fn queue_list_keeps_its_aligned_columns() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    megaquarry_core::store::Store::open(&home.path().join("megaquarry.db"))
        .unwrap()
        .enqueue(
            megaquarry_core::store::QueueKind::Download,
            &json!({"destination": "out/a.txt"}),
        )
        .unwrap();
    let list = queue_list(home.path(), &fake);
    assert!(
        list.starts_with("    1  download  queued   out/a.txt"),
        "{list:?}"
    );
}

#[test]
fn an_invalid_link_shows_what_links_look_like() {
    let fake = start(None);
    let home = tempfile::tempdir().unwrap();
    for command in ["ls", "download"] {
        let output = cli(home.path(), &fake)
            .args([command, "notalink"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).contains(
                "notalink: not a recognized MEGA link (links look like https://mega.nz/file/ID#KEY or https://mega.nz/folder/ID#KEY)"
            ),
            "{command}: {}",
            stderr(&output)
        );
    }
}
