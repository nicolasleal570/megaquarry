//! Typed view of the settings table.

use std::path::PathBuf;
use std::time::Duration;

use super::{Store, StoreError};

/// Every known setting: key, default, meaning.
pub const KNOWN_SETTINGS: &[(&str, &str, &str)] = &[
    ("default_down_dir", ".", "download directory"),
    (
        "default_slots_down",
        "6",
        "parallel connections per download (1-20)",
    ),
    (
        "use_slots_down",
        "yes",
        "use several connections per download",
    ),
    ("max_downloads", "4", "simultaneous downloads (1-50)"),
    ("max_uploads", "4", "simultaneous uploads (1-50)"),
    (
        "default_slots_up",
        "6",
        "parallel connections per upload (1-20)",
    ),
    (
        "verify_down_file",
        "yes",
        "check the file MAC after downloading",
    ),
    (
        "limit_download_speed",
        "no",
        "limit the total download speed",
    ),
    ("max_download_speed", "5", "download speed limit in KiB/s"),
    ("limit_upload_speed", "no", "limit the total upload speed"),
    ("max_upload_speed", "5", "upload speed limit in KiB/s"),
    (
        "upload_generate_file_links",
        "yes",
        "print a public link after each upload",
    ),
    (
        "use_mega_account_down",
        "no",
        "download through a logged-in account",
    ),
    ("mega_account_down", "", "account email used for downloads"),
    ("mega_api_key", "", "custom MEGA application key"),
    (
        "egress_cooldown_fallback",
        "3600",
        "seconds an exit IP rests after a quota hit when MEGA gives no wait (60-86400)",
    ),
    (
        "egress_max_attempts",
        "5",
        "VPN reconnects per rotation before waiting (1-20)",
    ),
    (
        "egress_reconnect_timeout",
        "90",
        "seconds to wait for the VPN after a reconnect (1-600)",
    ),
];

/// Settings with defaults applied and values clamped to their ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub download_dir: PathBuf,
    pub download_workers: usize,
    pub multi_slot_downloads: bool,
    pub max_downloads: usize,
    pub max_uploads: usize,
    pub upload_workers: usize,
    pub verify_downloads: bool,
    /// Bytes per second, `None` when unlimited.
    pub download_speed_limit: Option<u64>,
    pub upload_speed_limit: Option<u64>,
    pub generate_upload_links: bool,
    /// Account used for downloads, when enabled.
    pub download_account: Option<String>,
    pub app_key: Option<String>,
    /// Exit IP cooldown when MEGA does not say how long to wait.
    pub egress_cooldown_fallback: Duration,
    pub egress_max_attempts: u32,
    pub egress_reconnect_timeout: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            download_dir: PathBuf::from("."),
            download_workers: 6,
            multi_slot_downloads: true,
            max_downloads: 4,
            max_uploads: 4,
            upload_workers: 6,
            verify_downloads: true,
            download_speed_limit: None,
            upload_speed_limit: None,
            generate_upload_links: true,
            download_account: None,
            app_key: None,
            egress_cooldown_fallback: Duration::from_secs(3600),
            egress_max_attempts: 5,
            egress_reconnect_timeout: Duration::from_secs(90),
        }
    }
}

struct Reader<'a>(&'a Store);

impl Reader<'_> {
    fn text(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.0.setting(key)?.filter(|v| !v.trim().is_empty()))
    }

    fn flag(&self, key: &str, default: bool) -> Result<bool, StoreError> {
        // A stored value is true only when it is exactly "yes".
        Ok(self.text(key)?.map_or(default, |v| v.trim() == "yes"))
    }

    fn number(&self, key: &str, default: u64, min: u64, max: u64) -> Result<u64, StoreError> {
        Ok(self
            .text(key)?
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(default, |v| v.clamp(min, max)))
    }

    /// `limit_*` flag plus a KiB/s value; 0 means unlimited.
    fn speed(&self, flag: &str, key: &str) -> Result<Option<u64>, StoreError> {
        if !self.flag(flag, false)? {
            return Ok(None);
        }
        let kib = self.number(key, 5, 0, u64::MAX / 1024)?;
        Ok((kib > 0).then_some(kib * 1024))
    }
}

impl Settings {
    /// Reads the settings table, falling back to defaults.
    pub fn load(store: &Store) -> Result<Self, StoreError> {
        let r = Reader(store);
        let d = Self::default();
        let download_account = if r.flag("use_mega_account_down", false)? {
            r.text("mega_account_down")?
        } else {
            None
        };
        Ok(Self {
            download_dir: r
                .text("default_down_dir")?
                .map_or(d.download_dir, PathBuf::from),
            download_workers: r.number("default_slots_down", 6, 1, 20)? as usize,
            multi_slot_downloads: r.flag("use_slots_down", d.multi_slot_downloads)?,
            max_downloads: r.number("max_downloads", 4, 1, 50)? as usize,
            max_uploads: r.number("max_uploads", 4, 1, 50)? as usize,
            upload_workers: r.number("default_slots_up", 6, 1, 20)? as usize,
            verify_downloads: r.flag("verify_down_file", d.verify_downloads)?,
            download_speed_limit: r.speed("limit_download_speed", "max_download_speed")?,
            upload_speed_limit: r.speed("limit_upload_speed", "max_upload_speed")?,
            generate_upload_links: r.flag("upload_generate_file_links", d.generate_upload_links)?,
            download_account,
            app_key: r.text("mega_api_key")?,
            egress_cooldown_fallback: Duration::from_secs(r.number(
                "egress_cooldown_fallback",
                3600,
                60,
                86400,
            )?),
            egress_max_attempts: r.number("egress_max_attempts", 5, 1, 20)? as u32,
            egress_reconnect_timeout: Duration::from_secs(r.number(
                "egress_reconnect_timeout",
                90,
                1,
                600,
            )?),
        })
    }
}
