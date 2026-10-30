//! Focused failure and verification tests. Copying bytes into the verification
//! helper is not a claim that the host supports reflinks; real ioctl behavior
//! is exercised separately by the public shared-workspace integration tests.
use super::*;
use fgit_resource::{
    LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, TerminalEvidence,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, DomainTag};
use std::cell::Cell;
use std::fs as std_fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let base = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!(
            "fgit-shared-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std_fs::create_dir(&path).unwrap();
        std_fs::set_permissions(&path, std_fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn root(&self) -> File {
        File::open(&self.0).unwrap()
    }

    fn source(&self, body: &[u8]) -> File {
        let mut file = anonymous(&self.root()).expect("Linux anonymous source fixture");
        file.write_all(body).unwrap();
        fs::fchmod(&file, Mode::RUSR).unwrap();
        file
    }

    fn target(&self, name: &[u8], body: &[u8]) -> File {
        let mut file = create_target(
            &self.root(),
            &TreePath::parse_default(name).unwrap(),
            Mode::RUSR | Mode::WUSR,
        )
        .unwrap();
        file.write_all(body).unwrap();
        file
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std_fs::remove_dir_all(&self.0).unwrap();
    }
}

fn plan(bytes: u64, entries: u64) -> SharedInputCachePlan {
    SharedInputCachePlan {
        reservation: SharedInputCacheReservation {
            scope: [7; 32],
            max_bytes: bytes,
            max_entries: entries,
            policy: SharedInputPolicy::PreferReflink,
        },
    }
}

fn cache(scratch: &Scratch, plan: SharedInputCachePlan) -> (SharedInputCache, ObligationLedger) {
    let ledger = ObligationLedger::root(
        RegionId::new(80),
        LeakDisposition::RecordAndContinue,
        plan.budget(),
    );
    let reservation = ledger
        .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
        .unwrap();
    let cache = SharedInputCache::create(plan, scratch.root(), reservation, &|| false).unwrap();
    (cache, ledger)
}

fn close(cache: SharedInputCache, ledger: ObligationLedger) -> SharedInputCacheClosed {
    let TerminalEvidence::Acknowledged(receipt, _) = cache.close().unwrap().into_evidence() else {
        panic!("source descriptors must settle through explicit close");
    };
    assert_eq!(receipt.stats.resident_bytes, 0);
    assert_eq!(receipt.stats.resident_entries, 0);
    assert_eq!(
        ledger.snapshot().consumed(),
        ResourceVector::from_grades(&[
            (Grade::Bytes, receipt.stats.seeded_bytes),
            (
                Grade::Objects,
                receipt.stats.seeded_entries + receipt.stats.probe_entries
            ),
        ])
    );
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    receipt
}

#[test]
fn source_requires_anonymous_regular_exact_length_sealed_mode() {
    let scratch = Scratch::new();
    let source = scratch.source(b"source");
    validate_source(&source, 6).unwrap();
    assert_eq!(
        validate_source(&source, 5),
        Err(HostRefusal::SharedInputCorrupt)
    );
    fs::fchmod(&source, Mode::RUSR | Mode::WUSR).unwrap();
    assert_eq!(
        validate_source(&source, 6),
        Err(HostRefusal::SharedInputCorrupt)
    );
    let linked = scratch.target(b"linked", b"source");
    fs::fchmod(&linked, Mode::RUSR).unwrap();
    assert_eq!(
        validate_source(&linked, 6),
        Err(HostRefusal::SharedInputCorrupt)
    );
    assert_eq!(
        validate_source(&scratch.root(), 0),
        Err(HostRefusal::SharedInputCorrupt)
    );
}

#[test]
fn verification_requires_distinct_inode_exact_bytes_length_and_single_link() {
    let scratch = Scratch::new();
    let body: Vec<_> = (0..(CHUNK * 3 + 17)).map(|i| (i % 251) as u8).collect();
    let source = scratch.source(&body);
    let mut target = scratch.target(b"target", &body);
    verify_clone(&target, &source, &body, &|| Ok(())).unwrap();
    assert_eq!(
        verify_clone(&target, &target, &body, &|| Ok(())),
        Err(HostRefusal::SharedInputCorrupt)
    );

    target
        .write_all_at(&[body[CHUNK] ^ 1], CHUNK as u64)
        .unwrap();
    assert_eq!(
        verify_clone(&target, &source, &body, &|| Ok(())),
        Err(HostRefusal::SharedInputCorrupt)
    );
    target.write_all_at(&[body[CHUNK]], CHUNK as u64).unwrap();
    target.write_all(b"trailing").unwrap();
    assert_eq!(
        verify_clone(&target, &source, &body, &|| Ok(())),
        Err(HostRefusal::SharedInputCorrupt)
    );
    target.set_len(body.len() as u64 - 1).unwrap();
    assert_eq!(
        verify_clone(&target, &source, &body, &|| Ok(())),
        Err(HostRefusal::SharedInputCorrupt)
    );
    target.set_len(body.len() as u64).unwrap();
    target.write_all_at(&body, 0).unwrap();
    std_fs::hard_link(scratch.0.join("target"), scratch.0.join("alias")).unwrap();
    assert_eq!(
        verify_clone(&target, &source, &body, &|| Ok(())),
        Err(HostRefusal::SharedInputCorrupt)
    );
}

#[test]
fn verification_checkpoints_during_bounded_chunk_reads_and_empty_files() {
    let scratch = Scratch::new();
    let body = vec![9; CHUNK * 4 + 1];
    let source = scratch.source(&body);
    let target = scratch.target(b"target", &body);
    let calls = Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        if calls.get() == 3 {
            Err(HostRefusal::Cancelled(HostEpoch::Writing(5)))
        } else {
            Ok(())
        }
    };
    assert_eq!(
        verify_clone(&target, &source, &body, &check),
        Err(HostRefusal::Cancelled(HostEpoch::Writing(5)))
    );
    assert_eq!(calls.get(), 3);
    let source = scratch.source(b"");
    let target = scratch.target(b"empty", b"");
    verify_clone(&target, &source, b"", &|| Ok(())).unwrap();
}

#[test]
fn scope_frames_every_internal_identity_component() {
    fn digest(algorithm: u16, domain: &'static str, major: u16, minor: u16, byte: u8) -> [u8; 32] {
        let id = InternalObjectId::new(
            DigestAlgorithmId::try_new(algorithm).unwrap(),
            DomainTag::from_static(domain),
            CodecVersion::new(major, minor),
            DigestBytes::try_new(&[byte; 32]).unwrap(),
        );
        let mut hash = Sha256Hasher::new();
        frame_internal_id(&mut hash, &id);
        hash.finish()
    }
    let values = [
        digest(1, "repository-commit", 1, 0, 9),
        digest(2, "repository-commit", 1, 0, 9),
        digest(1, "candidate-commit", 1, 0, 9),
        digest(1, "repository-commit", 2, 0, 9),
        digest(1, "repository-commit", 1, 1, 9),
        digest(1, "repository-commit", 1, 0, 8),
    ];
    assert_eq!(
        values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        values.len()
    );
}

#[test]
fn empty_source_cache_reserves_custody_but_never_spends_source_bytes() {
    let scratch = Scratch::new();
    let plan = plan(0, 2);
    assert_eq!(plan.reservation().max_bytes, 0);
    assert_eq!(plan.budget().get(Grade::Bytes), 1);
    assert_eq!(plan.budget().get(Grade::FileDescriptors), 3);
    let (cache, ledger) = cache(&scratch, plan);
    let receipt = close(cache, ledger);
    assert_eq!(receipt.stats.seeded_bytes, 0);
    assert_eq!(receipt.stats.seeded_entries, 0);
}

#[test]
fn interrupted_seed_is_charged_once_and_poisoned_until_explicit_close() {
    let scratch = Scratch::new();
    let body = vec![11; CHUNK * 3 + 1];
    let (mut cache, ledger) = cache(&scratch, plan(body.len() as u64, 3));
    // Reach the seeding failure boundary on any host. Cancellation occurs
    // before the real clone ioctl, so this is not simulated sharing evidence.
    cache.stats.reflink_supported = true;
    let calls = Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        if calls.get() == 8 {
            Err(HostRefusal::Cancelled(HostEpoch::Writing(0)))
        } else {
            Ok(())
        }
    };
    let path = TreePath::parse_default(b"cancelled").unwrap();
    assert!(matches!(
        cache.write_input(&scratch.root(), &path, &body, Mode::RUSR, &check),
        Err(HostRefusal::Cancelled(HostEpoch::Writing(0)))
    ));
    assert!(!scratch.0.join("cancelled").exists());
    assert_eq!(cache.stats.seeded_bytes, body.len() as u64);
    assert_eq!(cache.stats.seeded_entries, 1);
    assert_eq!(cache.stats.resident_entries, 0);
    assert_eq!(cache.stats.cloned_bytes, 0);
    let after = cache.stats();
    assert!(matches!(
        cache.write_input(&scratch.root(), &path, &body, Mode::RUSR, &|| Ok(())),
        Err(HostRefusal::SharedInputCacheUnusable)
    ));
    assert_eq!(cache.stats(), after);
    close(cache, ledger);
}

#[test]
fn full_cache_obeys_copy_or_refuse_without_seeding_or_claiming_sharing() {
    let scratch = Scratch::new();
    let body = b"bounded source";
    let (mut cache, ledger) = cache(&scratch, plan(body.len() as u64, 2));
    // Capacity is checked before a source or clone is created. This boundary
    // does not rely on or claim the filesystem's actual reflink capability.
    cache.stats.reflink_supported = true;
    let path = TreePath::parse_default(b"copied").unwrap();
    let (_, shared) = cache
        .write_input(&scratch.root(), &path, body, Mode::RUSR, &|| Ok(()))
        .unwrap();
    assert!(!shared);
    assert_eq!(std_fs::read(scratch.0.join("copied")).unwrap(), body);
    assert_eq!(cache.stats.capacity_files, 1);
    assert_eq!(cache.stats.fallback_bytes, body.len() as u64);
    assert_eq!(cache.stats.seeded_entries, 0);
    assert_eq!(cache.stats.clone_operations, 0);
    cache.plan.reservation.policy = SharedInputPolicy::RequireReflink;
    let before = cache.stats();
    assert!(matches!(
        cache.write_input(
            &scratch.root(),
            &TreePath::parse_default(b"refused").unwrap(),
            body,
            Mode::RUSR,
            &|| Ok(())
        ),
        Err(HostRefusal::SharedInputUnavailable(
            SharedInputFallback::Capacity
        ))
    ));
    assert_eq!(cache.stats(), before);
    assert!(!scratch.0.join("refused").exists());
    close(cache, ledger);
}

#[test]
fn unsupported_classifier_does_not_hide_io_permission_or_storage_failure() {
    assert!(unsupported(rustix::io::Errno::OPNOTSUPP));
    assert!(unsupported(rustix::io::Errno::NOTTY));
    assert!(!unsupported(rustix::io::Errno::IO));
    assert!(!unsupported(rustix::io::Errno::NOSPC));
    assert!(!unsupported(rustix::io::Errno::ACCESS));
    assert!(!unsupported(rustix::io::Errno::PERM));
}
