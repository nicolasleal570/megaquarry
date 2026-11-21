mod common;

use common::{FakeTransport, api, ok};
use megaquarry_core::api::{ApiError, ErrorCode};
use megaquarry_core::crypto::{
    Attributes, FileKey, b64url_encode, ecb_encrypt, encrypt_attributes,
};
use megaquarry_core::link::{MegaLink, parse_link};
use megaquarry_core::public::{self, PublicError};
use serde_json::json;

const FOLDER_KEY: [u8; 16] = [0x42; 16];

fn file_key(seed: u8) -> FileKey {
    FileKey::from_bytes(
        &[seed; 32]
            .map(|b| b.wrapping_mul(3))
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ i as u8)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn attr(name: &str, key: &[u8; 16]) -> String {
    b64url_encode(&encrypt_attributes(&Attributes::with_name(name), key).unwrap())
}

fn wrapped(key: &[u8]) -> String {
    format!(
        "OWNER:{}",
        b64url_encode(&ecb_encrypt(&FOLDER_KEY, key).unwrap())
    )
}

/// A folder listing reply: Root/{a.txt, Sub/b.bin} plus one undecryptable node.
fn folder_reply() -> String {
    let root_key = [1u8; 16];
    let sub_key = [2u8; 16];
    let a = file_key(3);
    let b = file_key(4);
    json!({"f": [
        {"h": "ROOT", "p": "OWNERROOT", "t": 1, "k": wrapped(&root_key), "a": attr("Root", &root_key)},
        {"h": "SUB", "p": "ROOT", "t": 1, "k": wrapped(&sub_key), "a": attr("Sub", &sub_key)},
        {"h": "FA", "p": "ROOT", "t": 0, "s": 5, "k": format!("BAD:xx/{}", wrapped(&a.to_bytes())), "a": attr("a.txt", &a.aes_key())},
        {"h": "FB", "p": "SUB", "t": 0, "s": 7, "k": wrapped(&b.to_bytes()), "a": attr("b.bin", &b.aes_key())},
        {"h": "FC", "p": "SUB", "t": 0, "s": 9, "k": "OWNER:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "a": attr("c.bin", &[9; 16])},
    ]})
    .to_string()
}

fn folder_link(subfolder: Option<&str>) -> MegaLink {
    MegaLink::Folder {
        handle: "FOLDER".into(),
        key: FOLDER_KEY,
        subfolder: subfolder.map(Into::into),
    }
}

#[tokio::test]
async fn reads_public_file_metadata() {
    let key = file_key(7);
    let reply = json!([{"s": 1234, "at": attr("movie.mkv", &key.aes_key())}]).to_string();
    let api = api(FakeTransport::with(vec![ok(&reply)]));
    let link = MegaLink::File {
        handle: "HANDLE".into(),
        key: key.clone(),
    };

    let file = public::file_info(&api, &link).await.unwrap();
    assert_eq!(file.name, "movie.mkv");
    assert_eq!(file.size, 1234);
    assert_eq!(file.key, key);
    assert_eq!(
        api.transport().bodies()[0],
        json!([{"a": "g", "p": "HANDLE"}])
    );
}

#[tokio::test]
async fn sanitizes_remote_names() {
    let key = file_key(7);
    let reply = json!([{"s": 1, "at": attr("../evil/name..txt", &key.aes_key())}]).to_string();
    let api = api(FakeTransport::with(vec![ok(&reply)]));
    let link = MegaLink::File {
        handle: "H".into(),
        key,
    };
    assert_eq!(
        public::file_info(&api, &link).await.unwrap().name,
        ".evilname.txt"
    );
}

#[tokio::test]
async fn reports_wrong_keys_and_missing_files() {
    let reply = json!([{"s": 1, "at": attr("x", &[0; 16])}]).to_string();
    let api = api(FakeTransport::with(vec![ok(&reply), ok("[-9]")]));
    let link = MegaLink::File {
        handle: "H".into(),
        key: file_key(1),
    };
    assert_eq!(
        public::file_info(&api, &link).await,
        Err(PublicError::BadKey)
    );
    assert_eq!(
        public::file_info(&api, &link).await,
        Err(PublicError::Api(ApiError::Mega(ErrorCode::NotFound)))
    );
}

#[tokio::test]
async fn requests_download_urls_for_files_and_folder_nodes() {
    let key = file_key(5);
    let api = api(FakeTransport::with(vec![
        ok(r#"[{"g": "http://gfs.example/dl/abc", "s": 10}]"#),
        ok(r#"[{"g": "http://gfs.example/dl/def", "s": 10}]"#),
        ok(r#"[{"s": 10}]"#),
    ]));
    let file = MegaLink::File {
        handle: "H".into(),
        key: key.clone(),
    };
    let node = MegaLink::FolderNode {
        folder: "FOLDER".into(),
        node: "N".into(),
        key,
    };

    assert_eq!(
        public::download_url(&api, &file).await.unwrap(),
        "http://gfs.example/dl/abc"
    );
    assert_eq!(
        public::download_url(&api, &node).await.unwrap(),
        "http://gfs.example/dl/def"
    );
    assert_eq!(
        public::download_url(&api, &file).await,
        Err(PublicError::NoDownloadUrl)
    );

    let requests = api.transport().requests();
    assert_eq!(
        api.transport().bodies()[0],
        json!([{"a": "g", "g": 1, "p": "H"}])
    );
    assert_eq!(
        api.transport().bodies()[1],
        json!([{"a": "g", "g": 1, "n": "N"}])
    );
    assert!(requests[1].url.ends_with("&n=FOLDER"));
}

#[tokio::test]
async fn lists_folder_files_with_relative_paths_without_session() {
    let api = api(FakeTransport::with(vec![ok(&format!(
        "[{}]",
        folder_reply()
    ))]));
    api.set_session_id(Some("SID".into()));

    let listing = public::list_folder(&api, &folder_link(None)).await.unwrap();
    let files: Vec<(String, u64, String)> = listing
        .files()
        .into_iter()
        .map(|f| (f.path, f.file.size, f.file.name))
        .collect();
    assert_eq!(
        files,
        vec![
            ("Root/a.txt".to_string(), 5, "a.txt".to_string()),
            ("Root/Sub/b.bin".to_string(), 7, "b.bin".to_string()),
        ]
    );
    assert_eq!(listing.skipped(), 1);

    let request = &api.transport().requests()[0];
    assert!(!request.url.contains("sid="), "{}", request.url);
    assert!(request.url.ends_with("&n=FOLDER"));
    assert_eq!(
        api.transport().bodies()[0],
        json!([{"a": "f", "c": 1, "r": 1, "ca": 1}])
    );
}

#[tokio::test]
async fn folder_files_become_downloadable_node_links() {
    let api = api(FakeTransport::with(vec![ok(&format!(
        "[{}]",
        folder_reply()
    ))]));
    let listing = public::list_folder(&api, &folder_link(Some("SUB")))
        .await
        .unwrap();
    let files = listing.files();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "Sub/b.bin");
    assert_eq!(
        files[0].file.link,
        MegaLink::FolderNode {
            folder: "FOLDER".into(),
            node: "FB".into(),
            key: file_key(4)
        }
    );
}

#[tokio::test]
async fn resolves_every_link_kind_to_files() {
    let key = file_key(7);
    let file_reply = json!([{"s": 3, "at": attr("one.txt", &key.aes_key())}]).to_string();
    let listing = format!("[{}]", folder_reply());
    let api = api(FakeTransport::with(vec![
        ok(&file_reply),
        ok(&listing),
        ok(&listing),
    ]));

    let single = public::resolve(
        &api,
        &MegaLink::File {
            handle: "H".into(),
            key,
        },
    )
    .await
    .unwrap();
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].path, "one.txt");

    let all = public::resolve(&api, &folder_link(None)).await.unwrap();
    assert_eq!(all.len(), 2);

    let inside = parse_link(&format!(
        "https://mega.nz/folder/FOLDER#{}/file/FB",
        b64url_encode(&FOLDER_KEY)
    ))
    .unwrap();
    let found = public::resolve(&api, &inside).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, "b.bin");
    assert_eq!(found[0].file.size, 7);
}

#[tokio::test]
async fn falls_back_to_the_handle_when_a_name_is_unusable() {
    let key = file_key(7);
    let api = api(FakeTransport::with(
        ["", "..", "/ /"]
            .iter()
            .map(|name| ok(&json!([{"s": 1, "at": attr(name, &key.aes_key())}]).to_string()))
            .collect(),
    ));
    let link = MegaLink::File {
        handle: "HANDLE".into(),
        key,
    };
    for _ in 0..3 {
        assert_eq!(public::file_info(&api, &link).await.unwrap().name, "HANDLE");
    }
}

#[tokio::test]
async fn surfaces_the_error_code_of_a_refused_download() {
    let api = api(FakeTransport::with(vec![ok(r#"[{"e": -16, "s": 10}]"#)]));
    let link = MegaLink::File {
        handle: "H".into(),
        key: file_key(1),
    };
    assert_eq!(
        public::download_url(&api, &link).await,
        Err(PublicError::Api(ApiError::Mega(ErrorCode::Blocked)))
    );
}

#[tokio::test]
async fn reports_a_wrong_folder_key() {
    let api = api(FakeTransport::with(vec![ok(&format!(
        "[{}]",
        folder_reply()
    ))]));
    let link = MegaLink::Folder {
        handle: "FOLDER".into(),
        key: [0x13; 16],
        subfolder: None,
    };
    assert!(matches!(
        public::list_folder(&api, &link).await,
        Err(PublicError::BadKey)
    ));
}

#[tokio::test]
async fn picks_the_root_deterministically_when_the_top_folder_is_unreadable() {
    let mut reply: serde_json::Value = serde_json::from_str(&folder_reply()).unwrap();
    reply["f"][0]["k"] = json!("OWNER:AAAAAAAAAAAAAAAAAAAAAA");
    let reply = format!("[{reply}]");
    for _ in 0..20 {
        let api = api(FakeTransport::with(vec![ok(&reply)]));
        let listing = public::list_folder(&api, &folder_link(None)).await.unwrap();
        let paths: Vec<String> = listing.files().into_iter().map(|f| f.path).collect();
        // SUB is the first node (in reply order) whose parent is unknown.
        assert_eq!(paths, vec!["Sub/b.bin".to_string()]);
    }
}
