use std::future::Future;
use std::sync::Arc;

use crate::api::{ApiTransport, MegaApi, TransportError};
use crate::link::MegaLink;
use crate::public;

use super::DownloadError;

/// A streamed HTTP response body.
pub trait ChunkBody: Send {
    /// The next piece of the body, or `None` at the end.
    fn next_piece(
        &mut self,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, TransportError>> + Send;

    /// A response header, matched case-insensitively.
    fn header(&self, _name: &str) -> Option<String> {
        None
    }
}

/// Port: GETs chunk URLs from MEGA storage servers.
pub trait DownloadTransport: Send + Sync + 'static {
    type Body: ChunkBody;

    /// Returns the HTTP status and the body stream.
    fn get(
        &self,
        url: &str,
    ) -> impl Future<Output = Result<(u16, Self::Body), TransportError>> + Send;

    /// Drops pooled connections, e.g. after the exit IP changed.
    fn reset_connections(&self) {}
}

/// Port: obtains a fresh temporary download URL for one file.
pub trait UrlSource: Send + Sync + 'static {
    fn fresh_url(&self) -> impl Future<Output = Result<String, DownloadError>> + Send;

    /// Drops pooled connections, e.g. after the exit IP changed.
    fn reset_connections(&self) {}
}

/// Gets download URLs from the MEGA API for a file or folder-node link.
pub struct ApiUrlSource<T> {
    api: Arc<MegaApi<T>>,
    link: MegaLink,
}

impl<T> ApiUrlSource<T> {
    pub fn new(api: Arc<MegaApi<T>>, link: MegaLink) -> Self {
        Self { api, link }
    }
}

impl<T: ApiTransport + 'static> UrlSource for ApiUrlSource<T> {
    async fn fresh_url(&self) -> Result<String, DownloadError> {
        Ok(public::download_url(&self.api, &self.link).await?)
    }

    fn reset_connections(&self) {
        self.api.transport().reset_connections();
    }
}
