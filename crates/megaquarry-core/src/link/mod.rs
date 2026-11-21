//! MEGA link parsing and rendering.

mod filename;
mod legacy;

pub use filename::clean_filename;

use crate::crypto::{AesKey, FileKey, b64url_decode, b64url_encode};

const HOSTS: [&str; 3] = ["mega.nz", "mega.co.nz", "mega.io"];

/// A parsed MEGA link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MegaLink {
    /// A public file link.
    File { handle: String, key: FileKey },
    /// A public folder link, optionally pointing at one of its subfolders.
    Folder {
        handle: String,
        key: AesKey,
        subfolder: Option<String>,
    },
    /// A file inside a public folder, known only by its node handle.
    FolderFile {
        folder: String,
        folder_key: AesKey,
        file: String,
    },
    /// A file node of a public folder with its decrypted key (`#N!` links).
    FolderNode {
        folder: String,
        node: String,
        key: FileKey,
    },
}

/// Why a link could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("not a recognized MEGA link")]
    Unrecognized,
    #[error("the link key is missing or malformed")]
    BadKey,
}

impl MegaLink {
    /// Renders the link in the current `mega.nz` URL format.
    ///
    /// `FolderNode` links have no public equivalent and keep their
    /// `#N!handle!key###n=folder` form.
    pub fn to_url(&self) -> String {
        match self {
            Self::File { handle, key } => {
                format!(
                    "https://mega.nz/file/{handle}#{}",
                    b64url_encode(&key.to_bytes())
                )
            }
            Self::Folder {
                handle,
                key,
                subfolder,
            } => {
                let base = format!("https://mega.nz/folder/{handle}#{}", b64url_encode(key));
                match subfolder {
                    Some(sub) => format!("{base}/folder/{sub}"),
                    None => base,
                }
            }
            Self::FolderFile {
                folder,
                folder_key,
                file,
            } => format!(
                "https://mega.nz/folder/{folder}#{}/file/{file}",
                b64url_encode(folder_key)
            ),
            Self::FolderNode { folder, node, key } => format!(
                "https://mega.nz/#N!{node}!{}###n={folder}",
                b64url_encode(&key.to_bytes())
            ),
        }
    }
}

/// Parses any supported MEGA link format.
///
/// Handles must be non-empty base64url strings, so they can be embedded in
/// URLs and query strings unchanged.
pub fn parse_link(input: &str) -> Result<MegaLink, LinkError> {
    let link = parse_unchecked(input)?;
    let handles_ok = match &link {
        MegaLink::File { handle, .. } => is_handle(handle),
        MegaLink::Folder {
            handle, subfolder, ..
        } => is_handle(handle) && subfolder.as_deref().is_none_or(is_handle),
        MegaLink::FolderFile { folder, file, .. } => is_handle(folder) && is_handle(file),
        MegaLink::FolderNode { folder, node, .. } => is_handle(folder) && is_handle(node),
    };
    if handles_ok {
        Ok(link)
    } else {
        Err(LinkError::Unrecognized)
    }
}

fn is_handle(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse_unchecked(input: &str) -> Result<MegaLink, LinkError> {
    let text = input.trim();
    let decrypted;
    let text = if legacy::is_encrypted(text) {
        decrypted = legacy::decrypt(text)?;
        decrypted.as_str()
    } else {
        text
    };

    let rest = if let Some(rest) = text.strip_prefix("mega://") {
        rest
    } else {
        let without_scheme = text
            .strip_prefix("https://")
            .or_else(|| text.strip_prefix("http://"))
            .ok_or(LinkError::Unrecognized)?;
        let (host, rest) = without_scheme.split_at(
            without_scheme
                .find(['/', '#'])
                .unwrap_or(without_scheme.len()),
        );
        let host = host.strip_prefix("www.").unwrap_or(host);
        if !HOSTS.contains(&host) {
            return Err(LinkError::Unrecognized);
        }
        rest
    };

    let (path, fragment) = rest.split_once('#').ok_or(LinkError::Unrecognized)?;
    let path = path.trim_matches('/');

    if let Some(handle) = path.strip_prefix("file/") {
        return Ok(MegaLink::File {
            handle: handle.to_owned(),
            key: file_key(fragment)?,
        });
    }
    if let Some(handle) = path.strip_prefix("folder/") {
        return parse_new_folder(handle, fragment);
    }
    if path.is_empty() {
        return parse_legacy_fragment(fragment);
    }
    Err(LinkError::Unrecognized)
}

fn parse_new_folder(handle: &str, fragment: &str) -> Result<MegaLink, LinkError> {
    let mut parts = fragment.splitn(3, '/');
    let key = folder_key(parts.next().unwrap_or_default())?;
    match (parts.next(), parts.next()) {
        (None, _) => Ok(MegaLink::Folder {
            handle: handle.to_owned(),
            key,
            subfolder: None,
        }),
        (Some("folder"), Some(sub)) if !sub.is_empty() => Ok(MegaLink::Folder {
            handle: handle.to_owned(),
            key,
            subfolder: Some(sub.to_owned()),
        }),
        (Some("file"), Some(file)) if !file.is_empty() => Ok(MegaLink::FolderFile {
            folder: handle.to_owned(),
            folder_key: key,
            file: file.to_owned(),
        }),
        _ => Err(LinkError::Unrecognized),
    }
}

fn parse_legacy_fragment(fragment: &str) -> Result<MegaLink, LinkError> {
    if let Some(rest) = fragment.strip_prefix('!') {
        let (handle, key) = split_handle_key(rest)?;
        return Ok(MegaLink::File {
            handle: handle.to_owned(),
            key: file_key(key)?,
        });
    }
    if let Some(rest) = fragment
        .strip_prefix("F!")
        .or_else(|| fragment.strip_prefix("f!"))
    {
        let (handle, key) = split_handle_key(rest)?;
        let (handle, subfolder) = match handle.split_once('@') {
            Some((h, sub)) => (h, Some(sub.to_owned())),
            None => (handle, None),
        };
        return Ok(MegaLink::Folder {
            handle: handle.to_owned(),
            key: folder_key(key)?,
            subfolder,
        });
    }
    if let Some(rest) = fragment.strip_prefix("F*") {
        let (file, rest) = rest.split_once('!').ok_or(LinkError::Unrecognized)?;
        let (folder, key) = split_handle_key(rest)?;
        return Ok(MegaLink::FolderFile {
            folder: folder.to_owned(),
            folder_key: folder_key(key)?,
            file: file.to_owned(),
        });
    }
    if let Some(rest) = fragment.strip_prefix("N!") {
        let (node, rest) = split_handle_key(rest)?;
        let (key, folder) = rest.split_once("###n=").ok_or(LinkError::Unrecognized)?;
        return Ok(MegaLink::FolderNode {
            folder: folder.to_owned(),
            node: node.to_owned(),
            key: file_key(key)?,
        });
    }
    Err(LinkError::Unrecognized)
}

fn split_handle_key(text: &str) -> Result<(&str, &str), LinkError> {
    match text.split_once('!') {
        Some((handle, key)) if !handle.is_empty() => Ok((handle, key)),
        _ => Err(LinkError::Unrecognized),
    }
}

fn file_key(text: &str) -> Result<FileKey, LinkError> {
    let bytes = b64url_decode(text).map_err(|_| LinkError::BadKey)?;
    FileKey::from_bytes(&bytes).map_err(|_| LinkError::BadKey)
}

fn folder_key(text: &str) -> Result<AesKey, LinkError> {
    let bytes = b64url_decode(text).map_err(|_| LinkError::BadKey)?;
    bytes.try_into().map_err(|_| LinkError::BadKey)
}
