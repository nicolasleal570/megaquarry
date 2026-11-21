//! An exclusive lock held while a process transfers files.
//!
//! It is an exclusive SQLite transaction on a separate small database file:
//! SQLite's file locking already has to work wherever the store lives, the
//! operating system releases it when the process dies, and two processes on
//! the same bind mount (e.g. two containers) see each other's lock.

use std::path::Path;

use rusqlite::Connection;

use super::{StoreError, restrict};

/// Held while transferring; dropping it releases the lock.
pub struct TransferLock {
    _conn: Connection,
}

impl TransferLock {
    /// Takes the lock at `path`, or returns `None` when another process (or
    /// another holder in this one) has it.
    pub fn try_acquire(path: &Path) -> Result<Option<Self>, StoreError> {
        if !path.exists() {
            let mut options = std::fs::OpenOptions::new();
            options.create(true).truncate(false).write(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options.open(path)?;
        }
        let _ = restrict(path, 0o600);
        let conn = Connection::open(path)?;
        // Refuse at once instead of waiting for the holder.
        conn.busy_timeout(std::time::Duration::ZERO)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        match conn.execute_batch("BEGIN EXCLUSIVE") {
            Ok(()) => Ok(Some(Self { _conn: conn })),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }
}
