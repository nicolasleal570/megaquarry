use megaquarry_core::crypto::b64url_decode;
use megaquarry_core::link::{LinkError, MegaLink, clean_filename, parse_link};

const FILE_KEY: &str = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw";
const FOLDER_KEY: &str = "AAECAwQFBgcICQoLDA0ODw";

fn file(handle: &str) -> MegaLink {
    MegaLink::File {
        handle: handle.into(),
        key: megaquarry_core::crypto::FileKey::from_bytes(&b64url_decode(FILE_KEY).unwrap())
            .unwrap(),
    }
}

fn folder_key() -> [u8; 16] {
    b64url_decode(FOLDER_KEY).unwrap().try_into().unwrap()
}

#[test]
fn parses_new_and_legacy_file_links() {
    let expected = file("AbCdEfGh");
    for url in [
        format!("https://mega.nz/file/AbCdEfGh#{FILE_KEY}"),
        format!("https://mega.nz/#!AbCdEfGh!{FILE_KEY}"),
        format!("https://mega.co.nz/#!AbCdEfGh!{FILE_KEY}"),
        format!("mega://#!AbCdEfGh!{FILE_KEY}"),
        format!("  https://mega.nz/file/AbCdEfGh#{FILE_KEY}\n"),
    ] {
        assert_eq!(parse_link(&url).unwrap(), expected, "{url}");
    }
}

#[test]
fn parses_folder_links_with_and_without_subfolder() {
    let root = MegaLink::Folder {
        handle: "FoLdEr12".into(),
        key: folder_key(),
        subfolder: None,
    };
    assert_eq!(
        parse_link(&format!("https://mega.nz/folder/FoLdEr12#{FOLDER_KEY}")).unwrap(),
        root
    );
    assert_eq!(
        parse_link(&format!("https://mega.nz/#F!FoLdEr12!{FOLDER_KEY}")).unwrap(),
        root
    );

    let sub = MegaLink::Folder {
        handle: "FoLdEr12".into(),
        key: folder_key(),
        subfolder: Some("SuBfOlDr".into()),
    };
    assert_eq!(
        parse_link(&format!(
            "https://mega.nz/folder/FoLdEr12#{FOLDER_KEY}/folder/SuBfOlDr"
        ))
        .unwrap(),
        sub
    );
    assert_eq!(
        parse_link(&format!(
            "https://mega.nz/#F!FoLdEr12@SuBfOlDr!{FOLDER_KEY}"
        ))
        .unwrap(),
        sub
    );
}

#[test]
fn parses_file_inside_folder_links() {
    let expected = MegaLink::FolderFile {
        folder: "FoLdEr12".into(),
        folder_key: folder_key(),
        file: "FiLeInFo".into(),
    };
    assert_eq!(
        parse_link(&format!(
            "https://mega.nz/folder/FoLdEr12#{FOLDER_KEY}/file/FiLeInFo"
        ))
        .unwrap(),
        expected
    );
    assert_eq!(
        parse_link(&format!(
            "https://mega.nz/#F*FiLeInFo!FoLdEr12!{FOLDER_KEY}"
        ))
        .unwrap(),
        expected
    );
}

#[test]
fn parses_resolved_folder_node_links() {
    let link = format!("https://mega.nz/#N!NoDe1234!{FILE_KEY}###n=FoLdEr12");
    let parsed = parse_link(&link).unwrap();
    assert!(matches!(
        &parsed,
        MegaLink::FolderNode { folder, node, .. } if folder == "FoLdEr12" && node == "NoDe1234"
    ));
    assert_eq!(parsed.to_url(), link);
}

#[test]
fn decrypts_megadownloader_links() {
    assert_eq!(
        parse_link("mega://enc?NViNSL1tzJqMKtAkgk5sJzGX9fvA4QwaOBQ4uUPzdMwUyQN7niCLTXyyitHJ15zS3GwbDJ66WQQnqdwETlHd7A")
            .unwrap(),
        file("AbCdEfGh")
    );
    assert_eq!(
        parse_link("mega://fenc2?mmRdWI4wC-0BFGQqh8jytKONKKDhTb4TfPyAwdyqMNY").unwrap(),
        MegaLink::Folder {
            handle: "FoLdEr12".into(),
            key: folder_key(),
            subfolder: None
        }
    );
}

#[test]
fn rejects_unknown_links_and_bad_keys() {
    assert_eq!(
        parse_link("https://example.com/file/abc#def"),
        Err(LinkError::Unrecognized)
    );
    assert_eq!(
        parse_link(&format!("https://mega.nz/file/AbCdEfGh#{FOLDER_KEY}")),
        Err(LinkError::BadKey)
    );
    assert_eq!(
        parse_link("https://mega.nz/folder/FoLdEr12#!!!"),
        Err(LinkError::BadKey)
    );
}

#[test]
fn renders_canonical_new_format_urls() {
    assert_eq!(
        file("AbCdEfGh").to_url(),
        format!("https://mega.nz/file/AbCdEfGh#{FILE_KEY}")
    );
    let sub = parse_link(&format!(
        "https://mega.nz/#F!FoLdEr12@SuBfOlDr!{FOLDER_KEY}"
    ))
    .unwrap();
    assert_eq!(
        sub.to_url(),
        format!("https://mega.nz/folder/FoLdEr12#{FOLDER_KEY}/folder/SuBfOlDr")
    );
    let inside = parse_link(&format!(
        "https://mega.nz/#F*FiLeInFo!FoLdEr12!{FOLDER_KEY}"
    ))
    .unwrap();
    assert_eq!(
        inside.to_url(),
        format!("https://mega.nz/folder/FoLdEr12#{FOLDER_KEY}/file/FiLeInFo")
    );
}

#[test]
fn clean_filename_removes_unsafe_parts() {
    assert_eq!(clean_filename("1. Hello World..mp4"), "1. Hello World.mp4");
    assert_eq!(clean_filename("../../etc/passwd"), ".etcpasswd");
    assert_eq!(clean_filename(" tab\there\u{1}.txt "), "tabhere.txt");

    let long = format!("{}.mkv", "a".repeat(300));
    let cleaned = clean_filename(&long);
    assert_eq!(cleaned.chars().count(), 250);
    assert!(cleaned.ends_with(".mkv"));
}

#[test]
fn rejects_handles_with_characters_outside_base64url() {
    for url in [
        format!("https://mega.nz/folder/AB&x=1#{FOLDER_KEY}"),
        format!("https://mega.nz/file/A?b#{FILE_KEY}"),
        format!("https://mega.nz/#!A%20B!{FILE_KEY}"),
        format!("https://mega.nz/#F!FoLdEr12@S/../x!{FOLDER_KEY}"),
        format!("https://mega.nz/#N!NoDe!{FILE_KEY}###n=F&sid=x"),
    ] {
        assert_eq!(parse_link(&url), Err(LinkError::Unrecognized), "{url}");
    }
}
