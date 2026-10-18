#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactPut, ArtifactScope, ArtifactStorageError as Error,
    LocalArtifactStore,
};
use fgit_object_fabric::{ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::cell::Cell;
use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "fg-artifact-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
    fn input(&self, bytes: &[u8]) -> File {
        let path = self.0.join("input");
        fs::write(&path, bytes).unwrap();
        File::open(path).unwrap()
    }
    fn store(&self) -> LocalArtifactStore {
        LocalArtifactStore::open(&self.0, scope(1, "trusted")).unwrap()
    }
    fn objects(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.0)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("scope-"))
            .flat_map(|e| {
                fs::read_dir(e.path())
                    .unwrap()
                    .flatten()
                    .map(|e| e.path())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn scope(n: u8, trust: &str) -> ArtifactScope {
    ArtifactScope::new(
        TenantId::from_bytes([n; 16]),
        RepositoryId::from_bytes([2; 16]),
        RepositoryIncarnationId::from_bytes([3; 16]),
        trust,
    )
    .unwrap()
}
fn sha(bytes: &[u8]) -> Digest {
    let mut h = Sha256Hasher::new();
    DigestHasher::update(&mut h, bytes);
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&DigestHasher::finish(h)).unwrap(),
    )
}
fn identity(bytes: &[u8], capsule: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity::new(
        sha(bytes),
        bytes.len() as u64,
        MediaType::parse("application/octet-stream").unwrap(),
        ArtifactPayloadKind::CiArtifact,
        Some(sha(capsule)),
        Some(sha(b"receipt")),
        Some(sha(b"rcr")),
        RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
    )
}
fn op() -> ArtifactOperation<'static> {
    ArtifactOperation::new(16 * 1024 * 1024, Duration::from_secs(20), &|| true).unwrap()
}
fn hex(d: &Digest) -> String {
    d.bytes()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn real_payloads_roundtrip_after_source_removal_and_reopen() {
    for len in [0, 1, 65_537, 3 * 1024 * 1024] {
        let t = Temp::new();
        let bytes = (0..len).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let id = identity(&bytes, b"capsule");
        assert_eq!(
            t.store().put(&id, &mut t.input(&bytes), &op()).unwrap(),
            ArtifactPut::Created
        );
        fs::remove_file(t.0.join("input")).unwrap();
        let store = t.store();
        assert_eq!(store.inspect(id.artifact_id(), &op()).unwrap(), id);
        let out = t.0.join("export");
        assert_eq!(store.export(id.artifact_id(), &out, &op()).unwrap(), id);
        assert_eq!(fs::read(out).unwrap(), bytes);
        assert_eq!(t.objects().len(), 1);
        assert_eq!(fs::metadata(&t.objects()[0]).unwrap().mode() & 0o777, 0o600);
    }
}
#[test]
fn every_metadata_field_survives_persistence_and_binds_identity() {
    let t = Temp::new();
    let bytes = b"same bytes";
    for (n, retention) in [
        RetentionProfile::HotEphemeral { ttl_seconds: 1 },
        RetentionProfile::StandardLog { retain_days: 2 },
        RetentionProfile::ReleasePermanent,
        RetentionProfile::LegalHold {
            hold_id: 9,
            reason: "reason\nwith unicode λ".to_owned(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let id = ArtifactIdentity::new(
            sha(bytes),
            bytes.len() as u64,
            MediaType::parse("text/plain").unwrap(),
            ArtifactPayloadKind::BuildLog,
            if n % 2 == 0 {
                Some(sha(b"capsule"))
            } else {
                None
            },
            None,
            Some(sha(b"rcr")),
            retention,
        );
        t.store().put(&id, &mut t.input(bytes), &op()).unwrap();
        assert_eq!(t.store().inspect(id.artifact_id(), &op()).unwrap(), id);
    }
    assert_eq!(t.objects().len(), 4);
    assert_ne!(
        identity(bytes, b"a").artifact_id(),
        identity(bytes, b"b").artifact_id()
    );
}
#[test]
fn retries_and_concurrent_writers_never_replace_an_exact_object() {
    let t = Temp::new();
    let bytes = b"immutable";
    let id = identity(bytes, b"capsule");
    t.input(bytes);
    let outcomes = std::thread::scope(|threads| {
        let handles = (0..8)
            .map(|_| {
                let store = t.store();
                let id = id.clone();
                let input = t.0.join("input");
                threads.spawn(move || {
                    store
                        .put(&id, &mut File::open(input).unwrap(), &op())
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == ArtifactPut::Created)
            .count(),
        1
    );
    assert_eq!(t.objects().len(), 1);
    let path = &t.objects()[0];
    let before = fs::read(path).unwrap();
    assert_eq!(
        t.store().put(&id, &mut t.input(bytes), &op()).unwrap(),
        ArtifactPut::AlreadyPresent
    );
    assert_eq!(fs::read(path).unwrap(), before);
}
#[test]
fn tenant_repository_incarnation_and_trust_domains_do_not_alias() {
    let t = Temp::new();
    let id = identity(b"private", b"capsule");
    t.store().put(&id, &mut t.input(b"private"), &op()).unwrap();
    let other_scopes = [
        scope(2, "trusted"),
        scope(1, "untrusted"),
        ArtifactScope::new(
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([8; 16]),
            RepositoryIncarnationId::from_bytes([3; 16]),
            "trusted",
        )
        .unwrap(),
        ArtifactScope::new(
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            RepositoryIncarnationId::from_bytes([8; 16]),
            "trusted",
        )
        .unwrap(),
    ];
    for s in other_scopes {
        let other = LocalArtifactStore::open(&t.0, s.clone()).unwrap();
        assert!(matches!(
            other.inspect(id.artifact_id(), &op()),
            Err(Error::NotFound)
        ));
        let path = t.0.join(format!("scope-{}", hex(&s.commitment())));
        assert!(!path.exists());
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::copy(&t.objects()[0], path.join(hex(id.artifact_id()))).unwrap();
        assert!(matches!(
            other.inspect(id.artifact_id(), &op()),
            Err(Error::ScopeMismatch)
        ));
        fs::remove_dir_all(path).unwrap();
    }
}
#[test]
fn corrupt_payload_metadata_and_truncation_never_export_or_overwrite() {
    let t = Temp::new();
    let id = identity(b"verified", b"capsule");
    t.store()
        .put(&id, &mut t.input(b"verified"), &op())
        .unwrap();
    let path = t.objects()[0].clone();
    let original = fs::read(&path).unwrap();
    for offset in [0, 12, original.len() - 1] {
        let mut corrupt = original.clone();
        corrupt[offset] ^= 1;
        fs::write(&path, &corrupt).unwrap();
        assert!(t.store().inspect(id.artifact_id(), &op()).is_err());
        assert!(
            t.store()
                .export(id.artifact_id(), &t.0.join("absent"), &op())
                .is_err()
        );
        assert!(!t.0.join("absent").exists());
        assert!(
            t.store()
                .put(&id, &mut t.input(b"verified"), &op())
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    }
    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(t.store().inspect(id.artifact_id(), &op()).is_err());
    fs::write(&path, &original).unwrap();
    t.store()
        .export(id.artifact_id(), &t.0.join("valid"), &op())
        .unwrap();
    assert_eq!(fs::read(t.0.join("valid")).unwrap(), b"verified");
}
#[test]
fn wrong_length_digest_algorithm_and_limits_refuse_without_installing() {
    let t = Temp::new();
    let id = identity(b"right", b"capsule");
    for input in [b"wrong".as_slice(), b"righ", b"right!"] {
        assert!(t.store().put(&id, &mut t.input(input), &op()).is_err());
        assert!(t.objects().is_empty());
    }
    let small = ArtifactOperation::new(4, Duration::from_secs(10), &|| true).unwrap();
    assert!(matches!(
        t.store().put(&id, &mut t.input(b"right"), &small),
        Err(Error::PayloadLimit)
    ));
    let alias = Digest::new(
        DigestAlgorithmId::try_new(3).unwrap(),
        *id.payload_digest().bytes(),
    );
    let bad = ArtifactIdentity::new(
        alias,
        5,
        MediaType::parse("text/plain").unwrap(),
        ArtifactPayloadKind::BuildLog,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );
    assert!(matches!(
        t.store().put(&bad, &mut t.input(b"right"), &op()),
        Err(Error::InvalidIdentity)
    ));
    assert!(t.objects().is_empty());
    t.store().put(&id, &mut t.input(b"right"), &op()).unwrap();
    assert!(matches!(
        t.store().inspect(id.artifact_id(), &small),
        Err(Error::PayloadLimit)
    ));
}
#[test]
fn cancellation_at_each_chunk_boundary_leaves_no_partial_final_name() {
    let data = vec![7; 140_000];
    let id = identity(&data, b"capsule");
    let mut saw_success = false;
    for stop in 1..60 {
        let t = Temp::new();
        let calls = Cell::new(0);
        let live = || {
            calls.set(calls.get() + 1);
            calls.get() < stop
        };
        let budget = ArtifactOperation::new(1_000_000, Duration::from_secs(20), &live).unwrap();
        match t.store().put(&id, &mut t.input(&data), &budget) {
            Ok(_) => {
                saw_success = true;
                assert_eq!(t.objects().len(), 1);
            }
            Err(Error::Cancelled) => assert!(t.objects().is_empty()),
            other => panic!("{other:?}"),
        }
        assert!(
            t.objects()
                .iter()
                .all(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.'))
        );
    }
    assert!(saw_success);
}
#[test]
fn cancelled_export_and_expired_budget_preserve_destination_absence() {
    let t = Temp::new();
    let data = vec![8; 140_000];
    let id = identity(&data, b"capsule");
    t.store().put(&id, &mut t.input(&data), &op()).unwrap();
    for stop in 1..30 {
        let out = t.0.join(format!("export-{stop}"));
        let count = Cell::new(0);
        let live = || {
            count.set(count.get() + 1);
            count.get() < stop
        };
        let op = ArtifactOperation::new(1_000_000, Duration::from_secs(10), &live).unwrap();
        match t.store().export(id.artifact_id(), &out, &op) {
            Err(Error::Cancelled) => assert!(!out.exists()),
            Ok(_) => assert_eq!(fs::read(&out).unwrap(), data),
            other => panic!("{other:?}"),
        }
    }
    let expired = ArtifactOperation::new(1_000_000, Duration::from_nanos(1), &|| true).unwrap();
    std::thread::sleep(Duration::from_millis(1));
    assert!(matches!(
        t.store().inspect(id.artifact_id(), &expired),
        Err(Error::Deadline)
    ));
    assert!(
        fs::read_dir(&t.0)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".fg-artifact"))
    );
}
#[test]
fn symlinks_public_roots_and_occupied_exports_are_never_followed_or_overwritten() {
    let t = Temp::new();
    let link = t.0.join("alias");
    symlink(&t.0, &link).unwrap();
    assert!(LocalArtifactStore::open(&link, scope(1, "trusted")).is_err());
    fs::set_permissions(&t.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(LocalArtifactStore::open(&t.0, scope(1, "trusted")).is_err());
    fs::set_permissions(&t.0, fs::Permissions::from_mode(0o700)).unwrap();
    let id = identity(b"data", b"capsule");
    t.store().put(&id, &mut t.input(b"data"), &op()).unwrap();
    let out = t.0.join("occupied");
    fs::write(&out, b"keep").unwrap();
    assert!(matches!(
        t.store().export(id.artifact_id(), &out, &op()),
        Err(Error::DestinationExists)
    ));
    assert_eq!(fs::read(out).unwrap(), b"keep");
    let stored = t.objects()[0].clone();
    let moved = t.0.join("relocated");
    fs::rename(&stored, &moved).unwrap();
    symlink(&moved, &stored).unwrap();
    assert!(matches!(
        t.store().inspect(id.artifact_id(), &op()),
        Err(Error::UnsafePath)
    ));
}
#[test]
fn stale_stage_files_are_not_recovery_roots_and_callback_unwind_cleans_its_stage() {
    let t = Temp::new();
    let id = identity(&vec![1; 140_000], b"capsule");
    let stale = t.0.join(".fg-artifact-old");
    fs::write(&stale, b"torn").unwrap();
    let count = Cell::new(0);
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let live = || {
            count.set(count.get() + 1);
            assert!(count.get() != 8, "fixture interruption");
            true
        };
        let budget = ArtifactOperation::new(1_000_000, Duration::from_secs(10), &live).unwrap();
        let _ = t.store().put(&id, &mut t.input(&vec![1; 140_000]), &budget);
    }));
    assert!(stopped.is_err());
    assert!(t.objects().is_empty());
    assert_eq!(fs::read(stale).unwrap(), b"torn");
}
