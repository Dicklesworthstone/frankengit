#![forbid(unsafe_code)]
//! Actual filesystem batch publication and typed obligation settlement.
use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{LocalCrashPoint, LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, OpaqueHandle, RegionId, ResourceVector,
};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, PublicationEpoch};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-batch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn fabric(&self, crash: Option<LocalCrashPoint>) -> LocalFilesystemFabric {
        let mut config = LocalFilesystemConfig::new(
            self.0.clone(),
            b"batch".to_vec(),
            OpaqueHandle::new(b"disk").unwrap(),
            OpaqueHandle::new(b"key").unwrap(),
            128 * 1024 * 1024,
            SegmentLimits::default(),
        );
        if let Some(point) = crash {
            config = config.with_crash_injection(point);
        }
        LocalFilesystemFabric::open(config).unwrap()
    }
    fn path(&self, object: &VerifiedObject) -> PathBuf {
        self.0
            .join("objects")
            .join("6261746368")
            .join(format!(
                "{:04x}",
                object.identity().algorithm().code_point()
            ))
            .join(object.identity().to_string())
    }
    fn clean(&self) {
        assert_eq!(fs::read_dir(self.0.join("staging")).unwrap().count(), 0);
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn object(format: GitHashAlgorithm, payload: &[u8], namespace: &[u8]) -> VerifiedObject {
    let identity = git_object_id(format, GitObjectKind::Blob, payload);
    let commitment = git_payload_commitment(GitObjectKind::Blob, payload, CANONICAL_CODEC_VERSION);
    let bytes: [u8; 32] = commitment.digest().as_bytes().try_into().unwrap();
    let envelope = ObjectEnvelope::new(
        namespace.to_vec(),
        identity,
        ObjectKind::Blob,
        payload.len() as u64,
        bytes,
        b"raw".to_vec(),
        bytes,
        None,
        &SegmentLimits::default(),
    )
    .unwrap();
    VerifiedObject::new(envelope, payload.to_vec()).unwrap()
}
fn objects(format: GitHashAlgorithm, count: usize) -> Vec<VerifiedObject> {
    let mut result: Vec<_> = (0..count)
        .map(|i| object(format, format!("payload-{i}").as_bytes(), b"batch"))
        .collect();
    result.sort_by_key(VerifiedObject::identity);
    result
}
fn run(
    store: &LocalFilesystemFabric,
    objects: &[VerifiedObject],
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<PutIfAbsent>, StoreRefusal> {
    let amount = ResourceVector::from_grades(&[
        (
            Grade::Bytes,
            objects
                .iter()
                .map(|o| (o.payload().len() as u64).max(1))
                .sum(),
        ),
        (Grade::Objects, objects.len() as u64),
    ]);
    let ledger = ObligationLedger::root(RegionId::new(1), LeakDisposition::FailFast, amount);
    let budget = ledger.grant(amount).unwrap();
    let result = store.put_batch_if_absent(objects, PlacementAdmission::new(&ledger, budget), live);
    assert!(
        ledger.close().is_quiescent(),
        "all successful and failed batch responsibilities must settle"
    );
    result
}

#[test]
fn both_domains_round_trip_reopen_and_repeat_without_replacing_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Root::new();
        let store = root.fabric(None);
        let objects = objects(format, 256);
        let result = run(&store, &objects, &mut || true).unwrap();
        assert_eq!(result.len(), 256);
        for row in result {
            match row {
                PutIfAbsent::Created { epochs, .. } => {
                    assert!(epochs.contains(PublicationEpoch::Durable));
                    assert!(!epochs.contains(PublicationEpoch::Visible));
                }
                _ => panic!("new object was not created"),
            }
        }
        let original: Vec<_> = objects
            .iter()
            .map(|o| fs::read(root.path(o)).unwrap())
            .collect();
        let reopened = root.fabric(None);
        let repeated = run(&reopened, &objects, &mut || true).unwrap();
        assert!(
            repeated
                .iter()
                .all(|r| matches!(r, PutIfAbsent::AlreadyPresent { .. }))
        );
        for (i, object) in objects.iter().enumerate() {
            assert_eq!(
                reopened.read_whole(object.identity()).unwrap().object,
                *object
            );
            assert_eq!(fs::read(root.path(object)).unwrap(), original[i]);
        }
        root.clean();
    }
}

#[test]
fn a_batch_can_contain_both_native_hash_domains_and_zero_length_payloads() {
    let root = Root::new();
    let store = root.fabric(None);
    let mut entries = vec![
        object(GitHashAlgorithm::Sha1, b"", b"batch"),
        object(GitHashAlgorithm::Sha256, b"", b"batch"),
    ];
    entries.sort_by_key(VerifiedObject::identity);
    assert_eq!(run(&store, &entries, &mut || true).unwrap().len(), 2);
    for o in entries {
        assert!(
            store
                .read_whole(o.identity())
                .unwrap()
                .object
                .payload()
                .is_empty()
        );
    }
    assert!(run(&store, &[], &mut || true).unwrap().is_empty());
    root.clean();
}

#[test]
fn preflight_refuses_invalid_order_duplicate_namespace_count_and_budget_before_writes() {
    let root = Root::new();
    let store = root.fabric(None);
    let valid = objects(GitHashAlgorithm::Sha1, 2);
    let mut reverse = valid.clone();
    reverse.reverse();
    assert_eq!(
        run(&store, &reverse, &mut || true),
        Err(StoreRefusal::NonCanonicalObjectOrder)
    );
    assert_eq!(
        run(&store, &[valid[0].clone(), valid[0].clone()], &mut || true),
        Err(StoreRefusal::DuplicateObjectIdentity)
    );
    assert_eq!(
        run(&store, &objects(GitHashAlgorithm::Sha1, 257), &mut || true),
        Err(StoreRefusal::TooManyEntries)
    );
    assert_eq!(
        run(
            &store,
            &[object(GitHashAlgorithm::Sha1, b"x", b"foreign")],
            &mut || true
        ),
        Err(StoreRefusal::NamespaceMismatch)
    );
    let ledger = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::FailFast,
        ResourceVector::single(Grade::Objects, 2),
    );
    let grant = ledger
        .grant(ResourceVector::single(Grade::Objects, 2))
        .unwrap();
    assert!(matches!(
        store.put_batch_if_absent(&valid, PlacementAdmission::new(&ledger, grant), &mut || {
            true
        }),
        Err(StoreRefusal::Resource(_))
    ));
    assert!(ledger.close().is_quiescent());
    for o in &valid {
        assert!(matches!(
            store.read_whole(o.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
    assert_eq!(run(&store, &valid, &mut || true).unwrap().len(), 2);
    root.clean();
}

#[test]
fn every_publication_fault_aborts_custody_and_can_be_reopened_without_overwrite() {
    for point in [
        LocalCrashPoint::BeforeStageWrite,
        LocalCrashPoint::AfterStageWrite,
        LocalCrashPoint::AfterStageSync,
        LocalCrashPoint::BeforeImmutablePublish,
        LocalCrashPoint::AfterImmutablePublish,
        LocalCrashPoint::AfterPublishDirectorySync,
        LocalCrashPoint::BeforeStageCleanup,
    ] {
        let root = Root::new();
        let store = root.fabric(Some(point));
        let objects = objects(GitHashAlgorithm::Sha256, 3);
        assert!(
            matches!(
                run(&store, &objects, &mut || true),
                Err(StoreRefusal::StorageIo {
                    kind: std::io::ErrorKind::Interrupted,
                    ..
                })
            ),
            "{point:?}"
        );
        root.clean();
        let reopened = root.fabric(None);
        for o in &objects {
            match reopened.read_whole(o.identity()) {
                Ok(read) => assert_eq!(read.object, *o),
                Err(StoreRefusal::ObjectAbsent) => {}
                Err(e) => panic!("partial object: {e}"),
            }
        }
        assert_eq!(run(&reopened, &objects, &mut || true).unwrap().len(), 3);
        root.clean();
    }
}

#[test]
fn a_refusal_while_staging_links_no_name_of_the_batch() {
    // The batch writes every staged file, syncs them all, and only then links
    // names (frankengit-pc9g). A refusal at the third of four objects (a
    // corrupt existing copy) therefore leaves the two staged before it
    // unlinked; one-object-at-a-time placement had already linked them.
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 4);
    run(&store, &input[2..3], &mut || true).unwrap();
    let path = root.path(&input[2]);
    let mut poisoned = fs::read(&path).unwrap();
    *poisoned.last_mut().unwrap() ^= 1;
    fs::write(&path, &poisoned).unwrap();
    assert!(run(&store, &input, &mut || true).is_err());
    root.clean();
    for o in [&input[0], &input[1], &input[3]] {
        assert!(
            matches!(
                store.read_whole(o.identity()),
                Err(StoreRefusal::ObjectAbsent)
            ),
            "no name of the refused batch is linked"
        );
    }
    // Twin: the same batch without the corrupt member places everything.
    let clean = [input[0].clone(), input[1].clone(), input[3].clone()];
    assert_eq!(run(&store, &clean, &mut || true).unwrap().len(), 3);
    for o in &clean {
        assert_eq!(store.read_whole(o.identity()).unwrap().object, *o);
    }
    root.clean();
}

#[test]
fn cancellation_at_every_checkpoint_aborts_all_pending_obligations() {
    let input = objects(GitHashAlgorithm::Sha1, 4);
    for stop_at in 0..=12 {
        let root = Root::new();
        let store = root.fabric(None);
        let mut polls = 0;
        let result = run(&store, &input, &mut || {
            let live = polls != stop_at;
            polls += 1;
            live
        });
        if stop_at < polls {
            assert_eq!(result, Err(StoreRefusal::RuntimeCheckpointRejected));
        } else {
            assert_eq!(result.unwrap().len(), 4);
        }
        root.clean();
        assert_eq!(run(&store, &input, &mut || true).unwrap().len(), 4);
    }
}

#[test]
fn corrupt_existing_objects_never_get_healed_and_earlier_placements_settle() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha256, 4);
    run(&store, &input[2..3], &mut || true).unwrap();
    let path = root.path(&input[2]);
    let mut poisoned = fs::read(&path).unwrap();
    *poisoned.last_mut().unwrap() ^= 1;
    fs::write(&path, &poisoned).unwrap();
    assert!(matches!(
        run(&store, &input, &mut || true),
        Err(StoreRefusal::NativeObjectIdentityMismatch | StoreRefusal::PayloadCommitmentMismatch)
    ));
    assert_eq!(fs::read(path).unwrap(), poisoned);
    root.clean();
    // The batch syncs every staged file before it links any name
    // (frankengit-pc9g), so objects staged before the refusal may or may not be
    // linked. Whatever is present is exact; nothing is partial.
    for o in &input[..2] {
        match store.read_whole(o.identity()) {
            Ok(read) => assert_eq!(read.object, *o),
            Err(StoreRefusal::ObjectAbsent) => {}
            Err(e) => panic!("partial object: {e}"),
        }
    }
    assert!(matches!(
        store.read_whole(input[3].identity()),
        Err(StoreRefusal::ObjectAbsent)
    ));
}

#[test]
fn concurrent_batches_verify_each_other_and_leave_no_reservations_or_staging() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 32);
    std::thread::scope(|scope| {
        let one = scope.spawn(|| run(&store, &input, &mut || true).unwrap());
        let two = scope.spawn(|| run(&store, &input, &mut || true).unwrap());
        let (one, two) = (one.join().unwrap(), two.join().unwrap());
        assert_eq!(
            one.iter()
                .chain(&two)
                .filter(|r| matches!(r, PutIfAbsent::Created { .. }))
                .count(),
            32
        );
    });
    root.clean();
    for o in input {
        assert_eq!(store.read_whole(o.identity()).unwrap().object, o);
    }
}

#[test]
fn single_object_reuse_establishes_its_own_directory_fence_after_partial_batch() {
    let root = Root::new();
    let input = objects(GitHashAlgorithm::Sha1, 1);
    let partial = root.fabric(Some(LocalCrashPoint::AfterImmutablePublish));
    assert!(run(&partial, &input, &mut || true).is_err());
    let store = root.fabric(Some(LocalCrashPoint::AfterPublishDirectorySync));
    let resources = ResourceVector::from_grades(&[(Grade::Bytes, 64), (Grade::Objects, 1)]);
    let ledger = ObligationLedger::root(RegionId::new(1), LeakDisposition::FailFast, resources);
    let grant = ledger.grant(resources).unwrap();
    let result = store.put_if_absent(input[0].clone(), PlacementAdmission::new(&ledger, grant));
    assert!(matches!(
        result,
        Err(StoreRefusal::StorageIo {
            operation: fgit_object_fabric::fabric::StorageOperation::SyncDirectory,
            ..
        })
    ));
    assert!(ledger.close().is_quiescent());
    assert!(matches!(
        run(&root.fabric(None), &input, &mut || true).unwrap()[0],
        PutIfAbsent::AlreadyPresent { .. }
    ));
    root.clean();
}

#[test]
fn full_batch_byte_limit_and_per_file_framing_limit_refuse_before_any_link() {
    let root = Root::new();
    let store = root.fabric(None);
    let mut input = vec![
        object(
            GitHashAlgorithm::Sha1,
            &vec![b'a'; 32 * 1024 * 1024],
            b"batch",
        ),
        object(
            GitHashAlgorithm::Sha1,
            &vec![b'b'; 32 * 1024 * 1024 + 1],
            b"batch",
        ),
    ];
    input.sort_by_key(VerifiedObject::identity);
    assert!(matches!(
        run(&store, &input, &mut || true),
        Err(StoreRefusal::StreamingBudgetExceeded {
            maximum: 67_108_864,
            ..
        })
    ));
    for item in &input {
        assert!(matches!(
            store.read_whole(item.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
    root.clean();
    let small = Root::new();
    let config = LocalFilesystemConfig::new(
        small.0.clone(),
        b"batch".to_vec(),
        OpaqueHandle::new(b"disk").unwrap(),
        OpaqueHandle::new(b"key").unwrap(),
        1,
        SegmentLimits::default(),
    );
    let small_store = LocalFilesystemFabric::open(config).unwrap();
    let empty = object(GitHashAlgorithm::Sha1, b"", b"batch");
    assert!(matches!(
        run(&small_store, &[empty], &mut || true),
        Err(StoreRefusal::StoredObjectTooLarge { maximum: 1, .. })
    ));
    small.clean();
    assert_eq!(
        run(&store, &objects(GitHashAlgorithm::Sha1, 2), &mut || true)
            .unwrap()
            .len(),
        2
    );
}
