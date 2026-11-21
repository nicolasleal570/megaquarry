//! The lock that keeps a second transferring process from running.

use megaquarry_core::store::TransferLock;

#[test]
fn a_second_holder_is_refused_until_the_first_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.lock");

    let first = TransferLock::try_acquire(&path).unwrap();
    assert!(first.is_some());
    assert!(TransferLock::try_acquire(&path).unwrap().is_none());

    drop(first);
    assert!(TransferLock::try_acquire(&path).unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn the_lock_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.lock");

    let _lock = TransferLock::try_acquire(&path).unwrap().unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
