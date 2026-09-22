use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-multihead-custody-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf { self.0.join("restore") }
    fn reserve(&self) -> Custody {
        Custody::acquire(&self.root(), [7; 32], StoreInstanceId::from_raw(42), false).unwrap()
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn resume(root: &Path) -> Result<Custody, String> {
    Custody::acquire(root, [7; 32], StoreInstanceId::from_raw(42), true)
}
fn opaque_image(custody: &Custody, wal: bool) -> PathBuf {
    // These test files exercise path ordering, not database semantics.
    let path = custody.quarantine().unwrap();
    fs::write(path.join(DATABASE), b"closed-database-fixture").unwrap();
    if wal { fs::write(path.join(WAL), b"closed-WAL-fixture").unwrap(); }
    path
}

#[test]
fn intent_is_exactly_framed_and_cannot_change_format_pin_or_instance() {
    let scratch = Scratch::new();
    let custody = scratch.reserve();
    let marker = scratch.root().join(INTENT);
    let original = fs::read(&marker).unwrap();
    assert_eq!(original.len(), 48);
    assert_eq!(&original[..8], b"FGARM002");
    assert!(scratch.root().join(QUARANTINE).is_dir());
    drop(custody);
    for length in 0..48 {
        fs::write(&marker, &original[..length]).unwrap();
        assert!(resume(&scratch.root()).is_err(), "prefix {length}");
    }
    for field in [0, 8, 40] {
        let mut changed = original.clone(); changed[field] ^= 1;
        fs::write(&marker, changed).unwrap();
        assert!(resume(&scratch.root()).is_err());
    }
    let mut trailing = original.clone(); trailing.push(0);
    fs::write(&marker, trailing).unwrap(); assert!(resume(&scratch.root()).is_err());
    fs::write(&marker, original).unwrap(); assert!(resume(&scratch.root()).is_ok());
}

#[test]
fn lock_is_exclusive_and_released_by_handle_drop_without_unlinking() {
    let scratch = Scratch::new(); let first = scratch.reserve();
    assert!(resume(&scratch.root()).unwrap_err().contains("lock unavailable"));
    assert!(Custody::acquire(&scratch.root(), [7; 32], StoreInstanceId::from_raw(42), false).is_err());
    drop(first);
    let second = resume(&scratch.root()).unwrap();
    assert!(scratch.root().join(LOCK).is_file());
    drop(second);
    assert!(resume(&scratch.root()).is_ok());
}

#[test]
fn wal_move_interruption_normalizes_before_database_open_and_can_repeat() {
    let scratch = Scratch::new(); let custody = scratch.reserve();
    let quarantine = opaque_image(&custody, true);
    let error = custody.publish(|| Err("stop after WAL".into())).unwrap_err();
    assert_eq!(error, "stop after WAL");
    assert!(!custody.published().unwrap());
    assert!(scratch.root().join(WAL).exists());
    assert!(!quarantine.join(WAL).exists());
    drop(custody);
    let custody = resume(&scratch.root()).unwrap();
    assert_eq!(custody.quarantine().unwrap(), quarantine);
    assert_eq!(fs::read(quarantine.join(WAL)).unwrap(), b"closed-WAL-fixture");
    assert!(!scratch.root().join(WAL).exists());
    custody.quarantine().unwrap();
    custody.publish(|| Ok(())).unwrap();
    assert!(custody.published().unwrap());
    assert!(quarantine.join(DATABASE).exists(), "publication must retain evidence");
    custody.cleanup().unwrap();
    assert!(!quarantine.exists());
    assert_eq!(fs::read(scratch.root().join(DATABASE)).unwrap(), b"closed-database-fixture");
    assert_eq!(fs::read(scratch.root().join(WAL)).unwrap(), b"closed-WAL-fixture");
}

#[test]
fn conflicts_and_hot_journals_refuse_before_moving_any_path() {
    let scratch = Scratch::new(); let custody = scratch.reserve();
    let quarantine = opaque_image(&custody, true);
    fs::write(scratch.root().join(WAL), b"different").unwrap();
    assert!(custody.quarantine().unwrap_err().contains("conflicting"));
    assert_eq!(fs::read(quarantine.join(WAL)).unwrap(), b"closed-WAL-fixture");
    fs::remove_file(scratch.root().join(WAL)).unwrap();
    fs::write(quarantine.join(JOURNAL), b"unresolved").unwrap();
    assert!(custody.publish(|| Ok(())).unwrap_err().contains("rollback journal"));
    assert!(!scratch.root().join(WAL).exists());
    assert!(!custody.published().unwrap());
    fs::write(quarantine.join(JOURNAL), b"").unwrap();
    custody.publish(|| Ok(())).unwrap();
}

#[test]
fn no_replace_publication_preserves_a_racing_destination_and_private_image() {
    let scratch = Scratch::new(); let custody = scratch.reserve();
    let quarantine = opaque_image(&custody, false);
    assert!(custody.publish(|| {
        fs::write(scratch.root().join(DATABASE), b"winner").unwrap(); Ok(())
    }).is_err());
    assert_eq!(fs::read(scratch.root().join(DATABASE)).unwrap(), b"winner");
    assert_eq!(fs::read(quarantine.join(DATABASE)).unwrap(), b"closed-database-fixture");
}

#[test]
fn cleanup_never_erases_unknown_files_and_missing_both_images_cannot_reinitialize() {
    let scratch = Scratch::new(); let custody = scratch.reserve();
    let quarantine = opaque_image(&custody, false);
    custody.publish(|| Ok(())).unwrap();
    fs::write(quarantine.join("unrecognized-evidence"), b"retain").unwrap();
    assert!(custody.cleanup().is_err());
    assert_eq!(fs::read(quarantine.join("unrecognized-evidence")).unwrap(), b"retain");
    fs::remove_file(quarantine.join("unrecognized-evidence")).unwrap();
    custody.cleanup().unwrap();
    // Losing a finished public database must not make its old intent look new.
    fs::remove_file(scratch.root().join(DATABASE)).unwrap();
    assert!(custody.quarantine().unwrap_err().contains("refusing to recreate"));
    assert!(!quarantine.exists());
}

#[test]
fn unowned_legacy_or_source_restore_directories_are_never_adopted() {
    let scratch = Scratch::new(); let root = scratch.root(); fs::create_dir(&root).unwrap();
    fs::write(root.join(LOCK), b"").unwrap();
    fs::write(root.join(".restore-intent"), binding([7; 32], StoreInstanceId::from_raw(42))).unwrap();
    assert!(resume(&root).unwrap_err().contains("missing original intent"));
    assert!(!root.join(QUARANTINE).exists());
}

#[cfg(unix)]
#[test]
fn symlinks_are_refusals_not_missing_marker_or_sidecar() {
    let scratch = Scratch::new(); let custody = scratch.reserve();
    let quarantine = opaque_image(&custody, false);
    std::os::unix::fs::symlink("missing", quarantine.join(WAL)).unwrap();
    assert!(custody.quarantine().is_err());
    assert!(custody.publish(|| Ok(())).is_err());
    assert!(!custody.published().unwrap());
}
