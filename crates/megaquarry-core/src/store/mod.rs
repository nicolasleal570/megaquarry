//! SQLite persistence: settings, accounts, sessions and the transfer queue.
//!
//! The schema is versioned with `PRAGMA user_version`. Account passwords are never stored: only
//! the derived password key and user hash, which suffice to log in again.

mod lock;
mod settings;
mod vault;

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use lock::TransferLock;
pub use settings::{
    KNOWN_SETTINGS, SettingError, SettingKind, SettingSpec, Settings, setting_spec,
    validate_setting,
};
pub use vault::{SALT_LEN, Vault};

use crate::crypto::{b64url_decode, b64url_encode};
use crate::session::{Credentials, Session};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE vault (id INTEGER PRIMARY KEY CHECK (id = 1), salt BLOB NOT NULL, verifier BLOB NOT NULL);
CREATE TABLE accounts (email TEXT PRIMARY KEY, secret BLOB NOT NULL);
CREATE TABLE sessions (email TEXT PRIMARY KEY, secret BLOB NOT NULL);
CREATE TABLE transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    position INTEGER NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX transfers_by_kind ON transfers (kind, position);
";

/// Tables added after schema version 1. Created when missing, without bumping
/// `user_version`, so older builds still open the database (they ignore them).
const ADDED_TABLES: &str = "
CREATE TABLE IF NOT EXISTS egress_cooldowns (ip TEXT PRIMARY KEY, until INTEGER NOT NULL);
";

/// Persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the database uses schema version {0}, newer than this program supports")]
    UnsupportedSchema(i64),
    #[error("a master password is set: unlock the store first")]
    Locked,
    #[error("wrong master password")]
    WrongPassword,
    #[error("stored data is unreadable: {0}")]
    Corrupt(String),
    #[error("no such queue entry")]
    NotFound,
    #[error("the database is in use by another process; close it and retry")]
    Busy,
    #[error("no master password is set")]
    NotEncrypted,
}

/// Which queue an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueKind {
    Download,
    Upload,
}

impl QueueKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }
}

/// A persisted transfer; the payload is owned by the transfer layer.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueEntry {
    pub id: i64,
    pub kind: QueueKind,
    pub payload: Value,
}

#[derive(Serialize, Deserialize)]
struct StoredCredentials {
    password_aes: String,
    user_hash: String,
}

#[derive(Serialize, Deserialize)]
struct StoredSession {
    sid: String,
    master_key: String,
    user_handle: String,
}

/// The SQLite store. All access is serialized through one connection.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Opens (creating if needed) the database at `path`.
    /// The file and its directory are made private to the user (0600/0700
    /// on Unix; SQLite gives the WAL and SHM files the database's mode),
    /// since secrets are stored unencrypted without a master password.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                restrict(parent, 0o700)?;
            }
        }
        let created = !path.exists();
        if created {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(path) {
                // Another process created it first: fine, it is restricted below.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                other => {
                    other?;
                }
            }
        }
        // Tighten an existing file too, but do not refuse to open it on
        // filesystems without Unix permissions (vfat, some network mounts).
        match restrict(path, 0o600) {
            Err(e) if created => return Err(e.into()),
            _ => {}
        }
        let conn = Connection::open(path)?;
        // Switching a new database to WAL needs an exclusive lock and SQLite
        // reports a concurrent switch as busy without waiting: retry briefly.
        let mut attempts = 0;
        loop {
            match conn.pragma_update(None, "journal_mode", "WAL") {
                Ok(()) => break,
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::DatabaseBusy && attempts < 100 =>
                {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Self::init(conn)
    }

    /// An in-memory database (tests, dry runs).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self, StoreError> {
        // Overwritten secrets (e.g. after setting a master password) must not
        // linger in free pages.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Read the version under the write lock so two first opens of a new
        // file cannot both create the schema.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match version {
            0 => {
                tx.execute_batch(&format!("{SCHEMA} PRAGMA user_version = {SCHEMA_VERSION};"))?;
            }
            SCHEMA_VERSION => {}
            newer => return Err(StoreError::UnsupportedSchema(newer)),
        }
        tx.execute_batch(ADDED_TABLES)?;
        tx.commit()?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store lock poisoned")
    }

    /// Flushes the write-ahead log into the main database file.
    pub fn checkpoint(&self) -> Result<(), StoreError> {
        checkpoint(&self.conn())
    }

    // --- settings ---------------------------------------------------------

    pub fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn unset_setting(&self, key: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }

    /// Every stored setting, sorted by key.
    pub fn settings(&self) -> Result<Vec<(String, String)>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // --- master password --------------------------------------------------

    pub fn has_master_password(&self) -> Result<bool, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT 1 FROM vault WHERE id = 1", [], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Returns the vault for `password` (`None` when no master password is
    /// set; passing one for an unencrypted store is an error).
    pub fn unlock(&self, password: Option<&str>) -> Result<Vault, StoreError> {
        let stored: Option<(Vec<u8>, Vec<u8>)> = self
            .conn()
            .query_row("SELECT salt, verifier FROM vault WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let Some((salt, verifier)) = stored else {
            return match password {
                Some(_) => Err(StoreError::NotEncrypted),
                None => Ok(Vault::plain()),
            };
        };
        let password = password.ok_or(StoreError::Locked)?;
        let vault = Vault::derive(password, &salt);
        if !constant_time_eq(&vault.verifier().unwrap_or_default(), &verifier) {
            return Err(StoreError::WrongPassword);
        }
        Ok(vault)
    }

    /// Sets, changes or (with `None`) removes the master password,
    /// re-sealing every stored secret. `current` must be the unlocked vault.
    pub fn set_master_password(
        &self,
        current: &Vault,
        new_password: Option<&str>,
    ) -> Result<Vault, StoreError> {
        // Derive first: the slow KDF must not hold the store and write locks.
        // An empty password turns encryption off.
        let (next, salt) = match new_password.filter(|p| !p.is_empty()) {
            Some(password) => {
                let salt: [u8; SALT_LEN] = rand::random();
                (Vault::derive(password, &salt), Some(salt))
            }
            None => (Vault::plain(), None),
        };
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_vault(&tx, current)?;

        for table in ["accounts", "sessions"] {
            let rows: Vec<(String, Vec<u8>)> = {
                let mut stmt = tx.prepare(&format!("SELECT email, secret FROM {table}"))?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            for (email, secret) in rows {
                let plain = current.open(&secret)?;
                tx.execute(
                    &format!("UPDATE {table} SET secret = ?1 WHERE email = ?2"),
                    params![next.seal(&plain), email],
                )?;
            }
        }
        tx.execute("DELETE FROM vault", [])?;
        if let (Some(salt), Some(verifier)) = (salt, next.verifier()) {
            tx.execute(
                "INSERT INTO vault (id, salt, verifier) VALUES (1, ?1, ?2)",
                params![salt.to_vec(), verifier],
            )?;
        }
        tx.commit()?;
        // Push the re-sealed pages into the main file and truncate the WAL,
        // which otherwise keeps the old plaintext until a later checkpoint.
        // The change is already committed: if another reader blocks the
        // checkpoint now, it is retried when the store is dropped.
        match checkpoint(&conn) {
            Ok(()) | Err(StoreError::Busy) => Ok(next),
            Err(e) => Err(e),
        }
    }

    // --- accounts and sessions --------------------------------------------

    pub fn save_account(&self, vault: &Vault, credentials: &Credentials) -> Result<(), StoreError> {
        let stored = StoredCredentials {
            password_aes: b64url_encode(&credentials.password_aes),
            user_hash: credentials.user_hash.clone(),
        };
        self.put_secret("accounts", &credentials.email, vault, &to_json(&stored))
    }

    pub fn account(&self, vault: &Vault, email: &str) -> Result<Option<Credentials>, StoreError> {
        let Some(secret) = self.get_secret("accounts", email)? else {
            return Ok(None);
        };
        let stored: StoredCredentials = from_json(&vault.open(&secret)?)?;
        Ok(Some(Credentials {
            email: email.to_owned(),
            password_aes: decode_key(&stored.password_aes)?,
            user_hash: stored.user_hash,
        }))
    }

    pub fn account_emails(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT email FROM accounts ORDER BY email")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Deletes an account and its cached session.
    pub fn delete_account(&self, email: &str) -> Result<(), StoreError> {
        let conn = self.conn();
        conn.execute("DELETE FROM accounts WHERE email = ?1", [email])?;
        conn.execute("DELETE FROM sessions WHERE email = ?1", [email])?;
        Ok(())
    }

    pub fn save_session(&self, vault: &Vault, session: &Session) -> Result<(), StoreError> {
        let stored = StoredSession {
            sid: session.sid.clone(),
            master_key: b64url_encode(&session.master_key),
            user_handle: session.user_handle.clone(),
        };
        self.put_secret(
            "sessions",
            &session.credentials.email,
            vault,
            &to_json(&stored),
        )
    }

    /// The cached session of an account (needs the account row too).
    pub fn session(&self, vault: &Vault, email: &str) -> Result<Option<Session>, StoreError> {
        let (Some(secret), Some(credentials)) = (
            self.get_secret("sessions", email)?,
            self.account(vault, email)?,
        ) else {
            return Ok(None);
        };
        let stored: StoredSession = from_json(&vault.open(&secret)?)?;
        Ok(Some(Session {
            sid: stored.sid,
            master_key: decode_key(&stored.master_key)?,
            user_handle: stored.user_handle,
            credentials,
        }))
    }

    pub fn delete_session(&self, email: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM sessions WHERE email = ?1", [email])?;
        Ok(())
    }

    /// Seals and stores a secret; the vault must be the store's current one
    /// so no row is written with a stale or wrong key (or in plaintext).
    fn put_secret(
        &self,
        table: &str,
        email: &str,
        vault: &Vault,
        plain: &[u8],
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_vault(&tx, vault)?;
        tx.execute(
            &format!(
                "INSERT INTO {table} (email, secret) VALUES (?1, ?2)
                 ON CONFLICT (email) DO UPDATE SET secret = excluded.secret"
            ),
            params![email, vault.seal(plain)],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn get_secret(&self, table: &str, email: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT secret FROM {table} WHERE email = ?1"),
                [email],
                |r| r.get(0),
            )
            .optional()?)
    }

    // --- transfer queue ---------------------------------------------------

    /// Appends an entry at the end of its queue; returns its id.
    pub fn enqueue(&self, kind: QueueKind, payload: &Value) -> Result<i64, StoreError> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO transfers (kind, position, payload)
             VALUES (?1, (SELECT COALESCE(MAX(position), 0) + 1 FROM transfers WHERE kind = ?1), ?2)",
            params![kind.as_str(), payload.to_string()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_entry(&self, id: i64, payload: &Value) -> Result<(), StoreError> {
        let changed = self.conn().execute(
            "UPDATE transfers SET payload = ?1 WHERE id = ?2",
            params![payload.to_string(), id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Sets one top-level payload field atomically (other fields, possibly
    /// written meanwhile by another process, are kept).
    pub fn set_entry_field(&self, id: i64, field: &str, value: &Value) -> Result<(), StoreError> {
        let changed = self.conn().execute(
            "UPDATE transfers SET payload = json_set(payload, ?1, json(?2)) WHERE id = ?3",
            params![format!("$.{field}"), value.to_string(), id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Removes one top-level payload field atomically.
    pub fn remove_entry_field(&self, id: i64, field: &str) -> Result<(), StoreError> {
        let changed = self.conn().execute(
            "UPDATE transfers SET payload = json_remove(payload, ?1) WHERE id = ?2",
            params![format!("$.{field}"), id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn remove_entry(&self, id: i64) -> Result<(), StoreError> {
        let changed = self
            .conn()
            .execute("DELETE FROM transfers WHERE id = ?1", [id])?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// One entry by id.
    pub fn entry(&self, id: i64) -> Result<Option<QueueEntry>, StoreError> {
        let row: Option<(String, String)> = self
            .conn()
            .query_row(
                "SELECT kind, payload FROM transfers WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((kind, payload)) = row else {
            return Ok(None);
        };
        let kind = match kind.as_str() {
            "download" => QueueKind::Download,
            "upload" => QueueKind::Upload,
            other => return Err(StoreError::Corrupt(format!("unknown queue kind {other}"))),
        };
        Ok(Some(QueueEntry {
            id,
            kind,
            payload: serde_json::from_str(&payload)
                .map_err(|e| StoreError::Corrupt(format!("queue entry {id}: {e}")))?,
        }))
    }

    /// Entries of one queue in order.
    pub fn entries(&self, kind: QueueKind) -> Result<Vec<QueueEntry>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, payload FROM transfers WHERE kind = ?1 ORDER BY position, id")?;
        let rows = stmt.query_map([kind.as_str()], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, payload) = row?;
            Ok(QueueEntry {
                id,
                kind,
                payload: serde_json::from_str(&payload)
                    .map_err(|e| StoreError::Corrupt(format!("queue entry {id}: {e}")))?,
            })
        })
        .collect()
    }

    // --- exit IP cooldowns ------------------------------------------------

    /// Marks `ip` as cooling down until `until`. A shorter wait never
    /// shortens an existing cooldown.
    pub fn cool_down_ip(&self, ip: &str, until: SystemTime) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO egress_cooldowns (ip, until) VALUES (?1, ?2)
             ON CONFLICT (ip) DO UPDATE SET until = max(until, excluded.until)",
            params![ip, unix_seconds(until)],
        )?;
        Ok(())
    }

    /// When `ip` stops cooling down, or `None` if it is usable at `now`.
    pub fn ip_cooling_until(
        &self,
        ip: &str,
        now: SystemTime,
    ) -> Result<Option<SystemTime>, StoreError> {
        let until: Option<i64> = self
            .conn()
            .query_row(
                "SELECT until FROM egress_cooldowns WHERE ip = ?1 AND until > ?2",
                params![ip, unix_seconds(now)],
                |r| r.get(0),
            )
            .optional()?;
        Ok(until.map(|s| UNIX_EPOCH + Duration::from_secs(s.max(0) as u64)))
    }

    /// How many IPs are cooling down at `now`.
    pub fn cooling_ips(&self, now: SystemTime) -> Result<usize, StoreError> {
        let count: i64 = self.conn().query_row(
            "SELECT count(*) FROM egress_cooldowns WHERE until > ?1",
            [unix_seconds(now)],
            |r| r.get(0),
        )?;
        Ok(count as usize)
    }

    /// Forgets expired cooldowns; returns how many were removed.
    pub fn prune_cooldowns(&self, now: SystemTime) -> Result<usize, StoreError> {
        Ok(self.conn().execute(
            "DELETE FROM egress_cooldowns WHERE until <= ?1",
            [unix_seconds(now)],
        )?)
    }
}

/// Whole seconds since the Unix epoch (0 for earlier times).
fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64)
}

impl Drop for Store {
    fn drop(&mut self) {
        if let Ok(conn) = self.conn.lock() {
            let _ = checkpoint(&conn);
        }
    }
}

/// Sets Unix permission bits (no-op elsewhere).
fn restrict(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// Fails unless `vault` is the one the stored verifier belongs to.
fn check_vault(conn: &Connection, vault: &Vault) -> Result<(), StoreError> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT verifier FROM vault WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    let matches = match (stored, vault.verifier()) {
        (None, None) => true,
        (Some(stored), Some(given)) => constant_time_eq(&stored, &given),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StoreError::WrongPassword)
    }
}

/// `wal_checkpoint(TRUNCATE)`, reporting a checkpoint blocked by a reader.
fn checkpoint(conn: &Connection) -> Result<(), StoreError> {
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    if busy != 0 {
        return Err(StoreError::Busy);
    }
    Ok(())
}

fn to_json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("plain structs always serialize")
}

fn from_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StoreError> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn decode_key(text: &str) -> Result<[u8; 16], StoreError> {
    b64url_decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| StoreError::Corrupt("invalid stored key".into()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
