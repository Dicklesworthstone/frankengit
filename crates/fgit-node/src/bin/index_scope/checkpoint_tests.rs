use super::*;
#[cfg(unix)]
fn private() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "fg-index-candidate-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
#[test]
#[cfg(unix)]
fn candidate_is_exclusive_private_and_survives_reopen_without_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let root = private();
    let path = root.join("candidate.json");
    let bytes = b"{\"publication_evidence\":false}\n";
    record(&path, bytes).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        record(&path, b"replacement").unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    fs::remove_dir_all(root).unwrap();
}
#[test]
#[cfg(unix)]
fn unsafe_parent_and_symlink_destinations_refuse_without_changing_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = private();
    let target = root.join("target");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, root.join("link")).unwrap();
    assert!(record(&root.join("link"), b"change").is_err());
    let alias = root.with_extension("alias");
    symlink(&root, &alias).unwrap();
    assert!(record(&alias.join("new"), b"change").is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(record(&root.join("new"), b"change").is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_file(alias).unwrap();
    fs::remove_dir_all(root).unwrap();
}
#[test]
#[cfg(unix)]
fn exact_record_byte_limit_is_a_success_twin_and_overflow_creates_nothing() {
    let root = private();
    let path = root.join("candidate");
    assert!(record(&path, &vec![b'x'; MAX_RECORD_BYTES + 1]).is_err());
    assert!(!path.exists());
    assert!(record(&path, &[]).is_err());
    assert!(!path.exists());
    record(&path, &vec![b'x'; MAX_RECORD_BYTES]).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), MAX_RECORD_BYTES as u64);
    fs::remove_dir_all(root).unwrap();
}
