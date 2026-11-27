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
fn signed_intent_requires_the_same_exact_approval_and_cannot_downgrade() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let approved = [0x41; 32];
    drop(Intent::reserve_bound(&root, PIN, instance(), Some(approved)).unwrap());
    let original = fs::read(root.join(INTENT)).unwrap();
    assert_eq!(original.len(), SIGNED_INTENT_BYTES);
    assert_eq!(&original[..8], b"FGRES002");
    assert_eq!(&original[8..40], &PIN);
    assert_eq!(&original[40..48], &instance().raw().to_be_bytes());
    assert_eq!(&original[48..], &approved);
    let untouched = root.join("unrelated");
    fs::write(&untouched, b"preserve").unwrap();
    for binding in [None, Some([0x42; 32])] {
        let error = Intent::open_bound(&root, PIN, instance(), binding).unwrap_err();
        assert!(
            error.contains("exact signed approval/trust policy"),
            "{error}"
        );
        assert_eq!(fs::read(root.join(INTENT)).unwrap(), original);
        assert_eq!(fs::read(&untouched).unwrap(), b"preserve");
        assert!(!root.join(".restore-quarantine").exists());
    }
    assert!(Intent::open_bound(&root, PIN, instance(), Some(approved)).is_ok());
}

#[test]
fn unsigned_intent_cannot_be_reinterpreted_as_signed_and_signed_length_is_exact() {
    let scratch = Scratch::new();
    let unsigned = scratch.0.join("unsigned");
    drop(Intent::reserve(&unsigned, PIN, instance()).unwrap());
    assert!(Intent::open_bound(&unsigned, PIN, instance(), Some([1; 32])).is_err());
    assert!(Intent::open(&unsigned, PIN, instance()).is_ok());
    let root = scratch.root();
    drop(Intent::reserve_bound(&root, PIN, instance(), Some([2; 32])).unwrap());
    let good = fs::read(root.join(INTENT)).unwrap();
    for length in 0..good.len() {
        fs::write(root.join(INTENT), &good[..length]).unwrap();
        assert!(Intent::open_bound(&root, PIN, instance(), Some([2; 32])).is_err());
    }
    let mut extra = good;
    extra.push(0);
    fs::write(root.join(INTENT), extra).unwrap();
    assert!(Intent::open_bound(&root, PIN, instance(), Some([2; 32])).is_err());
    assert!(!root.join(".restore-quarantine").exists());
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
fn every_object_manifest_and_wal_move_combination_normalizes_idempotently() {
    for moved_objects in [false, true] {
        for moved_manifests in [false, true] {
            for moved_wal in [false, true] {
                let scratch = Scratch::new();
                let root = scratch.root();
                let intent = Intent::reserve(&root, PIN, instance()).unwrap();
                let q = intent.quarantine().unwrap();
                fs::write(q.join("authority.fsqlite"), b"closed database fixture").unwrap();
                fs::create_dir(q.join("objects")).unwrap();
                fs::write(q.join("objects/body"), b"object fixture").unwrap();
                fs::create_dir(q.join("manifests")).unwrap();
                fs::write(q.join("manifests/root"), b"manifest fixture").unwrap();
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
                if moved_manifests {
                    fs::rename(q.join("manifests"), root.join("manifests")).unwrap();
                }
                for _ in 0..2 {
                    assert_eq!(intent.quarantine().unwrap(), q);
                    assert_eq!(fs::read(q.join("objects/body")).unwrap(), b"object fixture");
                    assert_eq!(
                        fs::read(q.join("authority.fsqlite-wal")).unwrap(),
                        b"closed WAL fixture"
                    );
                    assert!(!root.join("objects").exists());
                    assert!(!root.join("manifests").exists());
                    assert_eq!(
                        fs::read(q.join("manifests/root")).unwrap(),
                        b"manifest fixture"
                    );
                    assert!(!root.join("authority.fsqlite-wal").exists());
                    assert!(!intent.published().unwrap());
                }
            }
        }
    }
}

#[test]
fn conflicting_manifest_locations_refuse_before_moving_objects_or_wal() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve(&root, PIN, instance()).unwrap();
    let q = intent.quarantine().unwrap();
    fs::write(q.join("authority.fsqlite"), b"database fixture").unwrap();
    fs::create_dir(root.join("objects")).unwrap();
    fs::write(root.join("objects/body"), b"object fixture").unwrap();
    fs::write(root.join("authority.fsqlite-wal"), b"WAL fixture").unwrap();
    fs::create_dir(q.join("manifests")).unwrap();
    fs::create_dir(root.join("manifests")).unwrap();
    assert!(
        intent
            .quarantine()
            .unwrap_err()
            .contains("conflicting data locations")
    );
    assert!(root.join("objects/body").exists());
    assert!(root.join("authority.fsqlite-wal").exists());
    assert!(!q.join("objects").exists());
    assert!(!q.join("authority.fsqlite-wal").exists());
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

#[test]
fn companion_intents_extend_without_reinterpreting_either_legacy_encoding() {
    let approved = [0x41; 32];
    let companion = [0x51; 32];
    assert_eq!(
        complete_binding(PIN, instance(), None, None),
        binding(PIN, instance())
    );
    assert_eq!(
        complete_binding(PIN, instance(), Some(approved), None),
        bound_binding(PIN, instance(), Some(approved))
    );
    for (approval, magic, length, offset) in [
        (None, b"FGRES003", 80, 48),
        (Some(approved), b"FGRES004", 112, 80),
    ] {
        let scratch = Scratch::new();
        let root = scratch.root();
        drop(Intent::reserve_complete(&root, PIN, instance(), approval, Some(companion)).unwrap());
        let bytes = fs::read(root.join(INTENT)).unwrap();
        assert_eq!(bytes.len(), length);
        assert_eq!(&bytes[..8], magic);
        assert_eq!(&bytes[8..40], &PIN);
        assert_eq!(&bytes[40..48], &instance().raw().to_be_bytes());
        if let Some(approval) = approval {
            assert_eq!(&bytes[48..80], &approval);
        }
        assert_eq!(&bytes[offset..], &companion);
        assert!(Intent::open_complete(&root, PIN, instance(), approval, Some(companion)).is_ok());
    }
    // Unsigned custody and signed source-only intents have equal lengths but
    // different semantic domains, even when their final 32 bytes are identical.
    assert_ne!(
        complete_binding(PIN, instance(), None, Some(companion)),
        complete_binding(PIN, instance(), Some(companion), None)
    );
}

#[test]
fn companion_addition_omission_replacement_and_approval_swap_refuse_before_any_path_moves() {
    let approved = [0x41; 32];
    let companion = [0x51; 32];
    for approval in [None, Some(approved)] {
        for selected in [None, Some(companion)] {
            let scratch = Scratch::new();
            let root = scratch.root();
            let intent =
                Intent::reserve_complete(&root, PIN, instance(), approval, selected).unwrap();
            let quarantine = intent.quarantine().unwrap();
            fs::write(
                quarantine.join("authority.fsqlite"),
                b"unpublished authority",
            )
            .unwrap();
            fs::create_dir(root.join("objects")).unwrap();
            fs::write(root.join("objects/body"), b"still at the root").unwrap();
            let original = fs::read(root.join(INTENT)).unwrap();
            drop(intent);
            for changed in [None, Some(companion), Some([0x52; 32])] {
                if changed == selected {
                    continue;
                }
                let error =
                    Intent::open_complete(&root, PIN, instance(), approval, changed).unwrap_err();
                assert!(error.contains("LFS companion checksum"), "{error}");
                assert_eq!(fs::read(root.join(INTENT)).unwrap(), original);
                assert_eq!(
                    fs::read(quarantine.join("authority.fsqlite")).unwrap(),
                    b"unpublished authority"
                );
                assert_eq!(
                    fs::read(root.join("objects/body")).unwrap(),
                    b"still at the root"
                );
                assert!(!quarantine.join("objects").exists());
                assert!(!root.join("authority.fsqlite").exists());
            }
            assert!(Intent::open_complete(&root, PIN, instance(), approval, selected).is_ok());
        }
    }
    let scratch = Scratch::new();
    let root = scratch.root();
    drop(
        Intent::reserve_complete(&root, PIN, instance(), Some(approved), Some(companion)).unwrap(),
    );
    assert!(
        Intent::open_complete(&root, PIN, instance(), Some(companion), Some(approved)).is_err()
    );
    assert!(Intent::open_complete(&root, PIN, instance(), None, Some(companion)).is_err());
    assert!(
        Intent::open_complete(&root, PIN, instance(), Some([0x42; 32]), Some(companion)).is_err()
    );
    assert!(!root.join(".restore-quarantine").exists());
}

#[test]
fn companion_intent_truncation_or_extension_never_creates_recovery_state() {
    for approval in [None, Some([0x41; 32])] {
        let scratch = Scratch::new();
        let root = scratch.root();
        let companion = Some([0x51; 32]);
        drop(Intent::reserve_complete(&root, PIN, instance(), approval, companion).unwrap());
        let original = fs::read(root.join(INTENT)).unwrap();
        for length in 0..original.len() {
            fs::write(root.join(INTENT), &original[..length]).unwrap();
            assert!(Intent::open_complete(&root, PIN, instance(), approval, companion).is_err());
        }
        let mut extended = original.clone();
        extended.push(0);
        fs::write(root.join(INTENT), extended).unwrap();
        assert!(Intent::open_complete(&root, PIN, instance(), approval, companion).is_err());
        assert!(!root.join(".restore-quarantine").exists());
        assert!(!root.join("authority.fsqlite").exists());
        fs::write(root.join(INTENT), original).unwrap();
        assert!(Intent::open_complete(&root, PIN, instance(), approval, companion).is_ok());
    }
}

#[test]
fn every_native_and_lfs_partial_move_combination_normalizes_before_authority_reopen() {
    // Opaque filesystem fixtures: the native restore separately verifies both
    // archive pins, all payloads, and the closed authority image.
    for moved in 0_u8..16 {
        let scratch = Scratch::new();
        let root = scratch.root();
        let intent =
            Intent::reserve_complete(&root, PIN, instance(), None, Some([0x51; 32])).unwrap();
        let quarantine = intent.quarantine().unwrap();
        let marker = fs::read(root.join(INTENT)).unwrap();
        fs::write(quarantine.join("authority.fsqlite"), b"closed authority").unwrap();
        let paths = ["objects", "manifests", "lfs"];
        for name in paths {
            fs::create_dir(quarantine.join(name)).unwrap();
            fs::write(quarantine.join(name).join("body"), name.as_bytes()).unwrap();
        }
        fs::write(quarantine.join("authority.fsqlite-wal"), b"closed WAL").unwrap();
        for (bit, name) in ["objects", "manifests", "lfs", "authority.fsqlite-wal"]
            .into_iter()
            .enumerate()
        {
            if moved & (1 << bit) != 0 {
                fs::rename(quarantine.join(name), root.join(name)).unwrap();
            }
        }
        for _ in 0..2 {
            assert_eq!(intent.quarantine().unwrap(), quarantine);
            for name in paths {
                assert_eq!(
                    fs::read(quarantine.join(name).join("body")).unwrap(),
                    name.as_bytes()
                );
                assert!(!root.join(name).exists());
            }
            assert_eq!(
                fs::read(quarantine.join("authority.fsqlite-wal")).unwrap(),
                b"closed WAL"
            );
            assert!(!root.join("authority.fsqlite-wal").exists());
            assert!(!intent.published().unwrap());
            assert_eq!(fs::read(root.join(INTENT)).unwrap(), marker);
        }
    }
}

#[test]
fn conflicting_lfs_locations_refuse_before_any_native_data_or_wal_move() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve_complete(&root, PIN, instance(), None, Some([0x51; 32])).unwrap();
    let quarantine = intent.quarantine().unwrap();
    fs::write(quarantine.join("authority.fsqlite"), b"closed authority").unwrap();
    fs::create_dir(root.join("objects")).unwrap();
    fs::write(root.join("objects/body"), b"moved native object").unwrap();
    fs::write(root.join("authority.fsqlite-wal"), b"moved WAL").unwrap();
    for (location, body) in [
        (&root, b"published location".as_slice()),
        (&quarantine, b"quarantine location".as_slice()),
    ] {
        fs::create_dir(location.join("lfs")).unwrap();
        fs::write(location.join("lfs/payload"), body).unwrap();
    }
    let error = intent.quarantine().unwrap_err();
    assert!(error.contains("conflicting data locations"), "{error}");
    assert_eq!(
        fs::read(root.join("objects/body")).unwrap(),
        b"moved native object"
    );
    assert_eq!(
        fs::read(root.join("authority.fsqlite-wal")).unwrap(),
        b"moved WAL"
    );
    assert_eq!(
        fs::read(root.join("lfs/payload")).unwrap(),
        b"published location"
    );
    assert_eq!(
        fs::read(quarantine.join("lfs/payload")).unwrap(),
        b"quarantine location"
    );
    assert!(!quarantine.join("objects").exists());
    assert!(!quarantine.join("authority.fsqlite-wal").exists());
    assert!(!intent.published().unwrap());
}

#[test]
fn source_only_intent_does_not_adopt_unowned_custody_in_either_location() {
    for at_root in [false, true] {
        let scratch = Scratch::new();
        let root = scratch.root();
        let intent = Intent::reserve(&root, PIN, instance()).unwrap();
        let quarantine = intent.quarantine().unwrap();
        fs::write(quarantine.join("authority.fsqlite"), b"closed authority").unwrap();
        fs::create_dir(root.join("objects")).unwrap();
        fs::write(root.join("objects/body"), b"keep native data").unwrap();
        let location = if at_root { &root } else { &quarantine };
        fs::create_dir(location.join("lfs")).unwrap();
        fs::write(location.join("lfs/payload"), b"unowned custody").unwrap();
        assert!(
            intent
                .quarantine()
                .unwrap_err()
                .contains("unowned LFS custody")
        );
        assert_eq!(
            fs::read(root.join("objects/body")).unwrap(),
            b"keep native data"
        );
        assert_eq!(
            fs::read(location.join("lfs/payload")).unwrap(),
            b"unowned custody"
        );
        assert!(!quarantine.join("objects").exists());
        assert!(!intent.published().unwrap());
    }
}

#[test]
fn moved_lfs_without_quarantine_is_retained_and_never_used_to_infer_authority() {
    let scratch = Scratch::new();
    let root = scratch.root();
    let intent = Intent::reserve_complete(&root, PIN, instance(), None, Some([0x51; 32])).unwrap();
    fs::create_dir(root.join("lfs")).unwrap();
    fs::write(root.join("lfs/payload"), b"retained orphan evidence").unwrap();
    assert!(
        intent
            .quarantine()
            .unwrap_err()
            .contains("without its quarantine")
    );
    assert_eq!(
        fs::read(root.join("lfs/payload")).unwrap(),
        b"retained orphan evidence"
    );
    assert!(!root.join(".restore-quarantine").exists());
    assert!(!intent.published().unwrap());
}
