//! Typed view of the settings table.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use super::{Store, StoreError};

/// What values a setting accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKind {
    /// Any text; empty means "not set".
    Text,
    /// `yes` or `no`.
    Flag,
    /// A whole number in `min..=max`.
    Number { min: u64, max: u64 },
    /// A speed in KiB/s; `0` means unlimited.
    Speed,
}

/// One known setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingSpec {
    pub key: &'static str,
    pub default: &'static str,
    pub kind: SettingKind,
    pub meaning: &'static str,
}

const fn spec(
    key: &'static str,
    default: &'static str,
    kind: SettingKind,
    meaning: &'static str,
) -> SettingSpec {
    SettingSpec {
        key,
        default,
        kind,
        meaning,
    }
}

const fn number(min: u64, max: u64) -> SettingKind {
    SettingKind::Number { min, max }
}

/// Every known setting, in display order.
pub const KNOWN_SETTINGS: &[SettingSpec] = &[
    spec(
        "download_dir",
        ".",
        SettingKind::Text,
        "folder downloads are saved in",
    ),
    spec(
        "download_connections",
        "6",
        number(1, 20),
        "connections per download; 1 is single-connection mode",
    ),
    spec(
        "max_downloads",
        "4",
        number(1, 50),
        "downloads running at once",
    ),
    spec(
        "upload_connections",
        "6",
        number(1, 20),
        "connections per upload",
    ),
    spec("max_uploads", "4", number(1, 50), "uploads running at once"),
    spec(
        "verify_downloads",
        "yes",
        SettingKind::Flag,
        "check each file's MAC after downloading",
    ),
    spec(
        "download_speed_limit",
        "0",
        SettingKind::Speed,
        "total download speed limit in KiB/s; 0 is unlimited",
    ),
    spec(
        "upload_speed_limit",
        "0",
        SettingKind::Speed,
        "total upload speed limit in KiB/s; 0 is unlimited",
    ),
    spec(
        "upload_public_links",
        "no",
        SettingKind::Flag,
        "create and print a public link for each uploaded file",
    ),
    spec(
        "download_account",
        "",
        SettingKind::Text,
        "stored account to download through; empty downloads anonymously",
    ),
    spec(
        "app_key",
        "",
        SettingKind::Text,
        "custom MEGA application key",
    ),
    spec(
        "egress_cooldown_fallback",
        "3600",
        number(60, 86400),
        "seconds an exit IP rests after a quota hit when MEGA gives no wait",
    ),
    spec(
        "egress_max_attempts",
        "5",
        number(1, 20),
        "VPN reconnects per rotation before waiting",
    ),
    spec(
        "egress_reconnect_timeout",
        "90",
        number(1, 600),
        "seconds to wait for the VPN after a reconnect",
    ),
];

/// The largest speed limit, so that KiB/s to bytes/s cannot overflow.
const MAX_SPEED_KIB: u64 = u64::MAX / 1024;

/// The spec of a known setting.
pub fn setting_spec(key: &str) -> Option<&'static SettingSpec> {
    KNOWN_SETTINGS.iter().find(|s| s.key == key)
}

/// Why a setting value is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingError {
    Unknown(String),
    Invalid {
        key: &'static str,
        kind: SettingKind,
        value: String,
    },
}

impl fmt::Display for SettingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(key) => {
                write!(f, "unknown setting `{key}` (see `megaquarry config list`)")
            }
            Self::Invalid { key, kind, value } => {
                let expected = match kind {
                    SettingKind::Text => "text".to_owned(),
                    SettingKind::Flag => "yes or no".to_owned(),
                    SettingKind::Number { min, max } => {
                        format!("a number from {min} to {max}")
                    }
                    SettingKind::Speed => "a whole number of KiB/s (0 is unlimited)".to_owned(),
                };
                write!(f, "{key} must be {expected} (got {value:?})")
            }
        }
    }
}

impl std::error::Error for SettingError {}

/// Checks a value before it is stored.
pub fn validate_setting(key: &str, value: &str) -> Result<(), SettingError> {
    let spec = setting_spec(key).ok_or_else(|| SettingError::Unknown(key.to_owned()))?;
    let valid = match spec.kind {
        SettingKind::Text => true,
        SettingKind::Flag => matches!(value.trim(), "yes" | "no"),
        SettingKind::Number { min, max } => value
            .trim()
            .parse::<u64>()
            .is_ok_and(|v| (min..=max).contains(&v)),
        SettingKind::Speed => value
            .trim()
            .parse::<u64>()
            .is_ok_and(|v| v <= MAX_SPEED_KIB),
    };
    if valid {
        Ok(())
    } else {
        Err(SettingError::Invalid {
            key: spec.key,
            kind: spec.kind,
            value: value.to_owned(),
        })
    }
}

/// Settings with defaults applied and values clamped to their ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub download_dir: PathBuf,
    pub download_workers: usize,
    /// Several connections per download (`download_connections` above 1).
    pub multi_slot_downloads: bool,
    pub max_downloads: usize,
    pub max_uploads: usize,
    pub upload_workers: usize,
    pub verify_downloads: bool,
    /// Bytes per second, `None` when unlimited.
    pub download_speed_limit: Option<u64>,
    pub upload_speed_limit: Option<u64>,
    pub generate_upload_links: bool,
    /// Account used for downloads, when set.
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
            generate_upload_links: false,
            download_account: None,
            app_key: None,
            egress_cooldown_fallback: Duration::from_secs(3600),
            egress_max_attempts: 5,
            egress_reconnect_timeout: Duration::from_secs(90),
        }
    }
}

/// Reads stored values, noting every one that is not valid.
struct Reader<'a> {
    store: &'a Store,
    warnings: Vec<String>,
}

impl Reader<'_> {
    fn spec(key: &str) -> &'static SettingSpec {
        setting_spec(key).expect("settings are read by their known keys")
    }

    fn warn(&mut self, key: &str, value: &str, using: impl fmt::Display) {
        let error = validate_setting(key, value).expect_err("only invalid values are reported");
        self.warnings.push(format!("{error}; using {using}"));
    }

    fn text(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.store.setting(key)?.filter(|v| !v.trim().is_empty()))
    }

    fn flag(&mut self, key: &str) -> Result<bool, StoreError> {
        let default = Self::spec(key).default == "yes";
        Ok(match self.text(key)? {
            None => default,
            Some(v) => match v.trim() {
                "yes" => true,
                "no" => false,
                _ => {
                    self.warn(key, &v, if default { "yes" } else { "no" });
                    default
                }
            },
        })
    }

    fn number(&mut self, key: &str) -> Result<u64, StoreError> {
        let spec = Self::spec(key);
        let SettingKind::Number { min, max } = spec.kind else {
            unreachable!("{key} is not a number setting");
        };
        let default: u64 = spec.default.parse().expect("number defaults parse");
        let Some(v) = self.text(key)? else {
            return Ok(default);
        };
        Ok(match v.trim().parse::<u64>() {
            Ok(n) if (min..=max).contains(&n) => n,
            Ok(n) => {
                let clamped = n.clamp(min, max);
                self.warn(key, &v, clamped);
                clamped
            }
            Err(_) => {
                self.warn(key, &v, default);
                default
            }
        })
    }

    /// A KiB/s limit as bytes per second; `None` when unlimited.
    fn speed(&mut self, key: &str) -> Result<Option<u64>, StoreError> {
        let Some(v) = self.text(key)? else {
            return Ok(None);
        };
        let kib = match v.trim().parse::<u64>() {
            Ok(n) if n <= MAX_SPEED_KIB => n,
            _ => {
                self.warn(key, &v, "0 (unlimited)");
                0
            }
        };
        Ok((kib > 0).then_some(kib * 1024))
    }
}

impl Settings {
    /// Reads the settings table, falling back to defaults.
    pub fn load(store: &Store) -> Result<Self, StoreError> {
        Ok(Self::load_with_warnings(store)?.0)
    }

    /// Like [`Settings::load`], also describing every stored value that
    /// was not valid and what is used instead.
    pub fn load_with_warnings(store: &Store) -> Result<(Self, Vec<String>), StoreError> {
        let mut r = Reader {
            store,
            warnings: Vec::new(),
        };
        let d = Self::default();
        let download_workers = r.number("download_connections")? as usize;
        let settings = Self {
            download_dir: r
                .text("download_dir")?
                .map_or(d.download_dir, PathBuf::from),
            download_workers,
            multi_slot_downloads: download_workers > 1,
            max_downloads: r.number("max_downloads")? as usize,
            upload_workers: r.number("upload_connections")? as usize,
            max_uploads: r.number("max_uploads")? as usize,
            verify_downloads: r.flag("verify_downloads")?,
            download_speed_limit: r.speed("download_speed_limit")?,
            upload_speed_limit: r.speed("upload_speed_limit")?,
            generate_upload_links: r.flag("upload_public_links")?,
            download_account: r.text("download_account")?.map(|v| v.trim().to_owned()),
            app_key: r.text("app_key")?,
            egress_cooldown_fallback: Duration::from_secs(r.number("egress_cooldown_fallback")?),
            egress_max_attempts: r.number("egress_max_attempts")? as u32,
            egress_reconnect_timeout: Duration::from_secs(r.number("egress_reconnect_timeout")?),
        };
        Ok((settings, r.warnings))
    }
}
