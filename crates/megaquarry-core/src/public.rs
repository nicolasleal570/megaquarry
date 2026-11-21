//! Public links: file metadata, download URLs and folder listings.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::api::{ApiError, ApiTransport, ErrorCode, MegaApi};
use crate::crypto::{AesKey, Attributes, FileKey, b64url_decode, decrypt_attributes, ecb_decrypt};
use crate::link::{MegaLink, clean_filename};

/// Errors while resolving public links.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("the link key does not decrypt this file (wrong or corrupted key)")]
    BadKey,
    #[error("MEGA returned no download URL")]
    NoDownloadUrl,
    #[error("node {0} not found in the folder")]
    NodeNotFound(String),
    #[error("unexpected reply: {0}")]
    Malformed(String),
    #[error("this link kind cannot be used here")]
    UnsupportedLink,
}

/// A downloadable remote file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    /// The name, already made safe for the local filesystem.
    pub name: String,
    pub size: u64,
    pub key: FileKey,
    /// A `File` or `FolderNode` link that downloads this file.
    pub link: MegaLink,
}

/// A file found while resolving a link, with its path relative to the
/// download directory (`/`-separated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFile {
    pub path: String,
    pub file: RemoteFile,
}

#[derive(Debug, Clone)]
enum NodeKind {
    File { size: u64, key: FileKey },
    Folder,
}

#[derive(Debug, Clone)]
struct Node {
    parent: String,
    name: String,
    kind: NodeKind,
}

/// The decrypted contents of a public folder.
#[derive(Debug, Clone)]
pub struct FolderListing {
    folder: String,
    root: String,
    nodes: HashMap<String, Node>,
    skipped: usize,
}

impl FolderListing {
    /// Nodes whose keys could not be decrypted (ignored).
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Every file under the listing root, sorted case-insensitively by path.
    /// Paths start with
    /// the root folder's name.
    pub fn files(&self) -> Vec<ResolvedFile> {
        let mut files: Vec<ResolvedFile> = self
            .nodes
            .iter()
            .filter_map(|(handle, node)| match &node.kind {
                NodeKind::File { size, key } => Some(ResolvedFile {
                    path: self.path_of(handle)?,
                    file: self.remote_file(handle, node, *size, key),
                }),
                NodeKind::Folder => None,
            })
            .collect();
        files.sort_by_cached_key(|f| (f.path.to_lowercase(), f.path.clone()));
        files
    }

    /// One file by node handle, with just its name as path.
    pub fn file(&self, handle: &str) -> Option<ResolvedFile> {
        let node = self.nodes.get(handle)?;
        match &node.kind {
            NodeKind::File { size, key } => Some(ResolvedFile {
                path: node.name.clone(),
                file: self.remote_file(handle, node, *size, key),
            }),
            NodeKind::Folder => None,
        }
    }

    fn remote_file(&self, handle: &str, node: &Node, size: u64, key: &FileKey) -> RemoteFile {
        RemoteFile {
            name: node.name.clone(),
            size,
            key: key.clone(),
            link: MegaLink::FolderNode {
                folder: self.folder.clone(),
                node: handle.to_owned(),
                key: key.clone(),
            },
        }
    }

    /// Path from the root (inclusive) to `handle`, or `None` outside the root.
    fn path_of(&self, handle: &str) -> Option<String> {
        let mut parts = Vec::new();
        let mut current = handle;
        loop {
            let node = self.nodes.get(current)?;
            parts.push(node.name.as_str());
            if current == self.root {
                break;
            }
            current = &node.parent;
            if parts.len() > self.nodes.len() {
                return None; // cycle guard
            }
        }
        parts.reverse();
        Some(parts.join("/"))
    }
}

/// Reads the name, size and key of a `File` or `FolderNode` link.
pub async fn file_info<T: ApiTransport>(
    api: &MegaApi<T>,
    link: &MegaLink,
) -> Result<RemoteFile, PublicError> {
    let (reply, key) = match link {
        MegaLink::File { handle, key } => (api.call(json!({"a": "g", "p": handle})).await?, key),
        MegaLink::FolderNode { folder, node, key } => (
            api.call_with_query(json!({"a": "g", "n": node}), &[("n", folder)])
                .await?,
            key,
        ),
        _ => return Err(PublicError::UnsupportedLink),
    };
    let size = reply["s"]
        .as_u64()
        .ok_or_else(|| PublicError::Malformed(format!("missing size in {reply}")))?;
    let attributes = decode_attributes(&reply["at"], &key.aes_key())?;
    let handle = match link {
        MegaLink::FolderNode { node, .. } => node,
        MegaLink::File { handle, .. } => handle,
        _ => unreachable!("checked above"),
    };
    Ok(RemoteFile {
        name: local_name(attributes.name(), handle),
        size,
        key: key.clone(),
        link: link.clone(),
    })
}

/// Requests a temporary download URL for a `File` or `FolderNode` link.
pub async fn download_url<T: ApiTransport>(
    api: &MegaApi<T>,
    link: &MegaLink,
) -> Result<String, PublicError> {
    let reply = match link {
        MegaLink::File { handle, .. } => api.call(json!({"a": "g", "g": 1, "p": handle})).await?,
        MegaLink::FolderNode { folder, node, .. } => {
            api.call_with_query(json!({"a": "g", "g": 1, "n": node}), &[("n", folder)])
                .await?
        }
        _ => return Err(PublicError::UnsupportedLink),
    };
    match reply["g"].as_str() {
        Some(url) if !url.is_empty() => Ok(url.to_owned()),
        _ => match reply["e"].as_i64() {
            Some(code) if code < 0 => Err(ApiError::Mega(ErrorCode::from_code(code)).into()),
            _ => Err(PublicError::NoDownloadUrl),
        },
    }
}

/// Lists and decrypts a public folder (or one of its subfolders).
pub async fn list_folder<T: ApiTransport>(
    api: &MegaApi<T>,
    link: &MegaLink,
) -> Result<FolderListing, PublicError> {
    let MegaLink::Folder {
        handle,
        key,
        subfolder,
    } = link
    else {
        return Err(PublicError::UnsupportedLink);
    };
    let reply = api
        .call_anonymous(json!({"a": "f", "c": 1, "r": 1, "ca": 1}), &[("n", handle)])
        .await?;
    let raw_nodes = reply["f"]
        .as_array()
        .ok_or_else(|| PublicError::Malformed("missing node list".into()))?;

    let mut nodes = HashMap::new();
    let mut order = Vec::new();
    let mut skipped = 0;
    for raw in raw_nodes {
        match decrypt_node(raw, key) {
            Some((handle, node)) => {
                order.push(handle.clone());
                nodes.insert(handle, node);
            }
            None => skipped += 1,
        }
    }
    if nodes.is_empty() {
        return Err(if raw_nodes.is_empty() {
            PublicError::Malformed("empty folder".into())
        } else {
            PublicError::BadKey
        });
    }

    // The root is the requested subfolder, or else the first node (in reply
    // order, which MEGA starts with the shared root) whose parent is unknown.
    let root = match subfolder {
        Some(sub) => sub.clone(),
        None => order
            .iter()
            .find(|h| !nodes.contains_key(&nodes[*h].parent))
            .cloned()
            .expect("a non-empty forest has a node without a known parent"),
    };
    if !nodes.contains_key(&root) {
        return Err(PublicError::NodeNotFound(root));
    }
    Ok(FolderListing {
        folder: handle.clone(),
        root,
        nodes,
        skipped,
    })
}

/// Resolves any link to the files it designates.
pub async fn resolve<T: ApiTransport>(
    api: &MegaApi<T>,
    link: &MegaLink,
) -> Result<Vec<ResolvedFile>, PublicError> {
    match link {
        MegaLink::File { .. } | MegaLink::FolderNode { .. } => {
            let file = file_info(api, link).await?;
            Ok(vec![ResolvedFile {
                path: file.name.clone(),
                file,
            }])
        }
        MegaLink::Folder { .. } => Ok(list_folder(api, link).await?.files()),
        MegaLink::FolderFile {
            folder,
            folder_key,
            file,
        } => {
            let folder_link = MegaLink::Folder {
                handle: folder.clone(),
                key: *folder_key,
                subfolder: None,
            };
            let listing = list_folder(api, &folder_link).await?;
            listing
                .file(file)
                .map(|f| vec![f])
                .ok_or_else(|| PublicError::NodeNotFound(file.clone()))
        }
    }
}

fn decode_attributes(value: &Value, key: &AesKey) -> Result<Attributes, PublicError> {
    let encoded = value
        .as_str()
        .ok_or_else(|| PublicError::Malformed("missing attributes".into()))?;
    let bytes = b64url_decode(encoded).map_err(|_| PublicError::BadKey)?;
    decrypt_attributes(&bytes, key).map_err(|_| PublicError::BadKey)
}

/// Decrypts one folder node; `None` when no key candidate works.
fn decrypt_node(raw: &Value, folder_key: &AesKey) -> Option<(String, Node)> {
    let handle = raw["h"].as_str()?.to_owned();
    let parent = raw["p"].as_str().unwrap_or_default().to_owned();
    let is_folder = raw["t"].as_u64()? == 1;
    let encoded_attributes = b64url_decode(raw["a"].as_str()?).ok()?;

    // `k` is a list of `owner:key` pairs; the first that decrypts wins.
    raw["k"].as_str()?.split('/').find_map(|pair| {
        let wrapped = b64url_decode(pair.rsplit(':').next()?).ok()?;
        let unwrapped = ecb_decrypt(folder_key, &wrapped).ok()?;
        let (kind, aes_key) = if is_folder {
            let key: AesKey = unwrapped.try_into().ok()?;
            (NodeKind::Folder, key)
        } else {
            let key = FileKey::from_bytes(&unwrapped).ok()?;
            let aes_key = key.aes_key();
            let size = raw["s"].as_u64().unwrap_or(0);
            (NodeKind::File { size, key }, aes_key)
        };
        let attributes = decrypt_attributes(&encoded_attributes, &aes_key).ok()?;
        let name = local_name(attributes.name(), &handle);
        Some((
            handle.clone(),
            Node {
                parent: parent.clone(),
                name,
                kind,
            },
        ))
    })
}

/// A safe local name for a node, falling back to its handle when the remote
/// name is missing or cleans down to nothing usable (empty, `.` or `..`).
fn local_name(remote: Option<&str>, handle: &str) -> String {
    let cleaned = clean_filename(remote.unwrap_or_default());
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        handle.to_owned()
    } else {
        cleaned
    }
}
