use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
const PIN: [u8; 32] = [9; 32];
fn instance() -> StoreInstanceId {
    StoreInstanceId::from_raw(991)
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-resume-paths-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn root(&self) -> PathBuf {
        self.0.join("target")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn immutable_binding_is_exact_versioned_and_specific_to_pin_and_instance() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let bytes = fs::read(root.join(INTENT)).unwrap();
    assert_eq!(bytes.len(), 48);
    assert_eq!(&bytes[..8], b"FGRES001");
    assert_eq!(&bytes[8..40], &PIN);
    assert_eq!(&bytes[40..], &991_u64.to_be_bytes());
    assert!(Intent::reserve(&root, PIN, instance()).is_err());
    drop(intent);
    assert!(
        Intent::open(&root, [8; 32], instance())
            .unwrap_err()
            .contains("intent does not match")
    );
    assert!(
        Intent::open(&root, PIN, StoreInstanceId::from_raw(992))
            .unwrap_err()
            .contains("intent does not match")
    );
    assert_eq!(fs::read(root.join(INTENT)).unwrap(), bytes);
    assert!(!root.join(".restore-quarantine").exists());
    assert!(Intent::open(&root, PIN, instance()).is_ok());
}

#[test]
fn live_owner_excludes_a_second_handle_and_drop_releases_without_breaking_a_lock_file() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let owner = Intent::reserve(&root, PIN, instance()).unwrap();
    assert!(
        Intent::open(&root, PIN, instance())
            .unwrap_err()
            .contains("lock unavailable")
    );
    let other = Intent::reserve(&scratch.0.join("independent"), PIN, instance()).unwrap();
    drop(other);
    drop(owner);
    assert!(root.join(LOCK).is_file());
    let next = Intent::open(&root, PIN, instance()).unwrap();
    assert!(Intent::open(&root, PIN, instance()).is_err());
    drop(next);
    assert!(Intent::open(&root, PIN, instance()).is_ok());
}

#[test]
fn truncated_extended_and_unknown_markers_and_legacy_roots_refuse() {
    let scratch = Scratch::new();
    let root = scratch.root();
    fs::create_dir(&root).unwrap();
    assert!(
        Intent::open(&root, PIN, instance())
            .unwrap_err()
            .contains("missing restore intent")
    );
    let good = binding(PIN, instance());
    for length in 0..good.len() {
        fs::write(root.join(INTENT), &good[..length]).unwrap();
        assert!(Intent::open(&root, PIN, instance()).is_err());
    }
    let mut extra = good.to_vec();
    extra.push(0);
    fs::write(root.join(INTENT), extra).unwrap();
    assert!(Intent::open(&root, PIN, instance()).is_err());
    let mut version = good;
    version[7] = b'2';
    fs::write(root.join(INTENT), version).unwrap();
    assert!(Intent::open(&root, PIN, instance()).is_err());
    assert!(!root.join(".restore-quarantine").exists());
    assert!(!root.join("authority.fsqlite").exists());
}

#[test]
fn every_object_and_wal_move_prefix_normalizes_idempotently() {
    for moved_objects in [false, true] {
        for moved_wal in [false, true] {
            let scratch = Scratch::new();
            let root = scratch.root();
            let intent = Intent::reserve(&root, PIN, instance()).unwrap();
            let q = intent.quarantine().unwrap();
            fs::write(q.join("authority.fsqlite"), b"closed database fixture").unwrap();
            fs::create_dir(q.join("objects")).unwrap();
            fs::write(q.join("objects/body"), b"object fixture").unwrap();
            fs::write(q.join("authority.fsqlite-wal"), b"closed WAL fixture").unwrap();
            if moved_objects {
                fs::rename(q.join("objects"), root.join("objects")).unwrap();
            }
            if moved_wal {
                fs::rename(
                    q.join("authority.fsqlite-wal"),
                    root.join("authority.fsqlite-wal"),
                )
                .unwrap();
            }
            for _ in 0..2 {
                assert_eq!(intent.quarantine().unwrap(), q);
                assert_eq!(fs::read(q.join("objects/body")).unwrap(), b"object fixture");
                assert_eq!(
                    fs::read(q.join("authority.fsqlite-wal")).unwrap(),
                    b"closed WAL fixture"
                );
                assert!(!root.join("objects").exists());
                assert!(!root.join("authority.fsqlite-wal").exists());
                assert!(!intent.published().unwrap());
            }
        }
    }
}

#[test]
fn conflicting_locations_refuse_before_moving_even_an_uncontested_wal() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let q = intent.quarantine().unwrap();
    fs::write(q.join("authority.fsqlite"), b"database fixture").unwrap();
    fs::create_dir(q.join("objects")).unwrap();
    fs::create_dir(root.join("objects")).unwrap();
    fs::write(q.join("objects/body"), b"quarantine").unwrap();
    fs::write(root.join("objects/body"), b"public").unwrap();
    fs::write(root.join("authority.fsqlite-wal"), b"WAL fixture").unwrap();
    assert!(
        intent
            .quarantine()
            .unwrap_err()
            .contains("conflicting data locations")
    );
    assert_eq!(fs::read(q.join("objects/body")).unwrap(), b"quarantine");
    assert_eq!(fs::read(root.join("objects/body")).unwrap(), b"public");
    assert!(root.join("authority.fsqlite-wal").exists());
    assert!(!q.join("authority.fsqlite-wal").exists());
}

#[test]
fn orphan_wal_and_published_authority_are_not_treated_as_empty_recovery_state() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let q = intent.quarantine().unwrap();
    fs::write(root.join("authority.fsqlite-wal"), b"WAL without database").unwrap();
    assert!(
        intent
            .quarantine()
            .unwrap_err()
            .contains("without its database")
    );
    fs::write(root.join("authority.fsqlite"), b"published fixture").unwrap();
    assert!(intent.published().unwrap());
    assert!(intent.quarantine().is_err());
    assert!(root.join("authority.fsqlite-wal").exists());
    assert!(q.exists());
}

#[test]
fn cleanup_waits_for_published_authority_and_keeps_the_immutable_retry_binding() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let q = intent.quarantine().unwrap();
    fs::write(q.join("owned-evidence"), b"evidence").unwrap();
    assert!(intent.cleanup().is_err());
    assert!(q.exists());
    // Opaque file-ordering fixture only; production additionally verifies the
    // real authority and every object before it calls this cleanup method.
    fs::write(root.join("authority.fsqlite"), b"published fixture").unwrap();
    intent.cleanup().unwrap();
    assert!(!q.exists());
    assert_eq!(
        fs::read(root.join(INTENT)).unwrap(),
        binding(PIN, instance())
    );
    assert!(root.join(LOCK).exists());
    intent.cleanup().unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_intent_or_data_never_becomes_a_resume_source() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let q = intent.quarantine().unwrap();
    let outside = scratch.0.join("outside");
    fs::write(&outside, b"keep").unwrap();
    symlink(&outside, q.join("authority.fsqlite-wal")).unwrap();
    assert!(intent.quarantine().unwrap_err().contains("path kind"));
    assert_eq!(fs::read(&outside).unwrap(), b"keep");
    drop(intent);
    fs::remove_file(root.join(INTENT)).unwrap();
    symlink(&outside, root.join(INTENT)).unwrap();
    assert!(
        Intent::open(&root, PIN, instance())
            .unwrap_err()
            .contains("path kind")
    );
}

/// A crash between the publishing link and the alias removal leaves two links
/// to one database; fsqlite >= 0.4 refuses to open such a path. Settling
/// removes only an alias proven to be the published file.
#[cfg(unix)]
#[test]
fn a_surviving_quarantine_alias_is_settled_only_when_it_is_the_published_file() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let quarantine = intent.quarantine().unwrap();
    fs::write(quarantine.join("authority.fsqlite"), b"verified image").unwrap();
    fs::hard_link(
        quarantine.join("authority.fsqlite"),
        root.join("authority.fsqlite"),
    )
    .unwrap();
    assert!(intent.published().unwrap());
    intent.settle_publication().unwrap();
    assert!(!quarantine.join("authority.fsqlite").exists());
    assert_eq!(
        fs::read(root.join("authority.fsqlite")).unwrap(),
        b"verified image"
    );
    intent.settle_publication().unwrap();

    fs::write(quarantine.join("authority.fsqlite"), b"a different image").unwrap();
    assert!(
        intent
            .settle_publication()
            .unwrap_err()
            .contains("differs from the published authority")
    );
    assert_eq!(
        fs::read(quarantine.join("authority.fsqlite")).unwrap(),
        b"a different image"
    );
}
