#![forbid(unsafe_code)]
//! Actual filesystem batch publication and typed obligation settlement.

#[path = "local_batch/bounded_compare.rs"]
mod bounded_compare;

use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{
    LocalCrashPoint, LocalFilesystemConfig, LocalFilesystemFabric, StagedBatch, SyncedBatch,
};
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
    // 1,000 ends in a partial sync group; 1,024 is four full groups.
    for (format, count) in [
        (GitHashAlgorithm::Sha1, 1000),
        (GitHashAlgorithm::Sha256, 1024),
    ] {
        let root = Root::new();
        let store = root.fabric(None);
        let objects = objects(format, count);
        let result = run(&store, &objects, &mut || true).unwrap();
        assert_eq!(result.len(), count);
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
        run(&store, &objects(GitHashAlgorithm::Sha1, 1025), &mut || true),
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

fn ledger_for(
    objects: &[VerifiedObject],
    leaks: LeakDisposition,
) -> (ObligationLedger, ResourceVector) {
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
    (
        ObligationLedger::root(RegionId::new(1), leaks, amount),
        amount,
    )
}

fn stage(
    store: &LocalFilesystemFabric,
    objects: &[VerifiedObject],
    ledger: &ObligationLedger,
    amount: ResourceVector,
) -> StagedBatch {
    let budget = ledger.grant(amount).unwrap();
    store
        .stage_batch_if_absent(
            objects.to_vec(),
            PlacementAdmission::new(ledger, budget),
            &mut || true,
        )
        .unwrap()
}

/// Stages and publishes through the split form with a fail-fast ledger.
fn run_split(
    store: &LocalFilesystemFabric,
    objects: &[VerifiedObject],
) -> Result<Vec<PutIfAbsent>, StoreRefusal> {
    let (ledger, amount) = ledger_for(objects, LeakDisposition::FailFast);
    let batch = stage(store, objects, &ledger, amount);
    let result = store.publish_staged_batch(batch, &mut || true);
    assert!(ledger.close().is_quiescent());
    result
}

fn stored_files(root: &Root) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.push((
                    path.strip_prefix(base).unwrap().to_path_buf(),
                    fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.0.join("objects"), &root.0, &mut out);
    out.sort();
    out
}

/// The split form stores exactly what the blocking form stores and returns
/// identical outcomes: fresh batches in both hash domains, a repeated batch
/// and a batch mixing stored and new objects (frankengit-ai60).
#[test]
fn staging_then_publishing_stores_and_reports_exactly_what_one_blocking_batch_does() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = objects(format, 64);
        let (blocking_root, split_root) = (Root::new(), Root::new());
        let (blocking, split) = (blocking_root.fabric(None), split_root.fabric(None));
        // Half stored first, then the full batch (mixed), then it again (repeated).
        let first: Vec<_> = input.iter().step_by(2).cloned().collect();
        for batch in [&first[..], &input[..], &input[..]] {
            let expected = run(&blocking, batch, &mut || true).unwrap();
            assert_eq!(run_split(&split, batch).unwrap(), expected);
        }
        assert_eq!(stored_files(&split_root), stored_files(&blocking_root));
        assert_eq!(stored_files(&split_root).len(), 64);
        split_root.clean();
        blocking_root.clean();
    }
}

/// A staged batch links no name before it is published. Abandoning it
/// removes every staged file and settles every reservation under a
/// fail-fast ledger; the same objects then publish normally.
#[test]
fn a_staged_batch_links_nothing_until_published_and_abandoning_it_settles_everything() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha256, 8);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage(&store, &input, &ledger, amount);
    assert_eq!(fs::read_dir(root.0.join("staging")).unwrap().count(), 8);
    for o in &input {
        assert!(matches!(
            store.read_whole(o.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
    batch.abandon().unwrap();
    assert!(ledger.close().is_quiescent());
    root.clean();
    for o in &input {
        assert!(matches!(
            store.read_whole(o.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
    assert_eq!(run_split(&store, &input).unwrap().len(), 8);
    for o in &input {
        assert_eq!(store.read_whole(o.identity()).unwrap().object, *o);
    }
    root.clean();
}

/// Publication polls cancellation before each link exactly as the blocking
/// form does: a cancelled publication links nothing, removes every staged
/// file and settles every reservation.
#[test]
fn a_cancelled_publication_links_nothing_and_settles_every_reservation() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 8);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage(&store, &input, &ledger, amount);
    assert_eq!(
        store.publish_staged_batch(batch, &mut || false),
        Err(StoreRefusal::RuntimeCheckpointRejected)
    );
    assert!(ledger.close().is_quiescent());
    root.clean();
    for o in &input {
        assert!(matches!(
            store.read_whole(o.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
}

/// Dropping a staged batch unsettled still joins its syncs and removes its
/// staged files, but its reservations are reported as leaks: an unsettled
/// batch can never pass for a settled one.
#[test]
fn an_unsettled_staged_batch_is_reported_as_leaked_and_leaves_no_staged_file() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 4);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::RecordAndContinue);
    drop(stage(&store, &input, &ledger, amount));
    assert!(!ledger.close().is_quiescent());
    root.clean();
    for o in &input {
        assert!(matches!(
            store.read_whole(o.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
}

/// The overlapped form keeps every staged file open until publication, so it
/// takes at most one sync group (256 objects) and refuses more before any
/// write; a refused batch settles under a fail-fast ledger (frankengit-pc9g).
#[test]
fn the_overlapped_form_takes_at_most_one_sync_group() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 257);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let budget = ledger.grant(amount).unwrap();
    assert!(matches!(
        store.stage_batch_if_absent(
            input.clone(),
            PlacementAdmission::new(&ledger, budget),
            &mut || true,
        ),
        Err(StoreRefusal::TooManyEntries)
    ));
    assert!(ledger.close().is_quiescent());
    root.clean();
    assert!(stored_files(&root).is_empty());
    assert_eq!(run_split(&store, &input[..256]).unwrap().len(), 256);
    root.clean();
}

/// A full blocking batch holds at most one sync group of staged files open.
/// With all 1,024 open at once, a large push was refused under the common
/// 1,024 soft `RLIMIT_NOFILE` (frankengit-pc9g).
#[cfg(target_os = "linux")]
#[test]
fn a_full_blocking_batch_holds_at_most_one_sync_group_of_staged_files_open() {
    let root = Root::new();
    let store = root.fabric(None);
    let staging = root.0.join("staging");
    let input = objects(GitHashAlgorithm::Sha1, 1024);
    let mut most = 0;
    let result = run(&store, &input, &mut || {
        most = most.max(open_staged_files(&staging));
        true
    });
    assert_eq!(result.unwrap().len(), 1024);
    assert_eq!(most, 256, "staged files open at once");
    root.clean();
}

#[cfg(target_os = "linux")]
fn open_staged_files(staging: &std::path::Path) -> usize {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .filter(|target| {
            target.starts_with(staging) && target.extension().is_some_and(|e| e == "stage")
        })
        .count()
}

fn stage_synced(
    store: &LocalFilesystemFabric,
    objects: &[VerifiedObject],
    ledger: &ObligationLedger,
    amount: ResourceVector,
) -> SyncedBatch {
    let budget = ledger.grant(amount).unwrap();
    store
        .stage_synced_batch_if_absent(
            objects,
            PlacementAdmission::new(ledger, budget),
            &mut || true,
        )
        .unwrap()
}

fn staged_count(root: &Root) -> usize {
    fs::read_dir(root.0.join("staging")).unwrap().count()
}

/// A synced batch links no name and holds no descriptor: every staged file is
/// on disk and closed. Publishing it stores exactly what one blocking batch
/// stores, with the same receipts, in both hash domains (frankengit-tz5z).
#[test]
fn a_synced_batch_links_nothing_holds_no_descriptor_and_publishes_like_a_blocking_batch() {
    for (format, count) in [
        (GitHashAlgorithm::Sha1, 700),
        (GitHashAlgorithm::Sha256, 1024),
    ] {
        let input = objects(format, count);
        let (blocking_root, synced_root) = (Root::new(), Root::new());
        let (blocking, synced) = (blocking_root.fabric(None), synced_root.fabric(None));
        let expected = run(&blocking, &input, &mut || true).unwrap();
        let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
        let batch = stage_synced(&synced, &input, &ledger, amount);
        assert_eq!(batch.identities().len(), count);
        assert_eq!(staged_count(&synced_root), count);
        #[cfg(target_os = "linux")]
        assert_eq!(open_staged_files(&synced_root.0.join("staging")), 0);
        for object in &input {
            assert!(matches!(
                synced.read_whole(object.identity()),
                Err(StoreRefusal::ObjectAbsent)
            ));
        }
        let published = synced.publish_synced_batch(batch, &mut || true).unwrap();
        assert!(ledger.close().is_quiescent());
        assert_eq!(published, expected);
        assert_eq!(stored_files(&synced_root), stored_files(&blocking_root));
        synced_root.clean();
        blocking_root.clean();
    }
}

#[test]
fn an_overlapped_batch_can_release_its_buffers_before_admission_without_publishing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = objects(format, 64);
        let (blocking_root, deferred_root) = (Root::new(), Root::new());
        let (blocking, deferred) = (blocking_root.fabric(None), deferred_root.fabric(None));
        let first: Vec<_> = input.iter().step_by(2).cloned().collect();
        // Fresh, mixed-existing and identical-retry cases retain exact receipts.
        for offered in [&first[..], &input[..], &input[..]] {
            let expected = run(&blocking, offered, &mut || true).unwrap();
            let before = stored_files(&deferred_root);
            let (ledger, amount) = ledger_for(offered, LeakDisposition::FailFast);
            let batch = stage(&deferred, offered, &ledger, amount)
                .synchronize(&mut || true)
                .unwrap();
            assert_eq!(stored_files(&deferred_root), before);
            assert_eq!(
                batch.identities(),
                offered
                    .iter()
                    .map(VerifiedObject::identity)
                    .collect::<Vec<_>>()
            );
            #[cfg(target_os = "linux")]
            assert_eq!(open_staged_files(&deferred_root.0.join("staging")), 0);
            assert_eq!(
                deferred.publish_synced_batch(batch, &mut || true).unwrap(),
                expected
            );
            assert!(ledger.close().is_quiescent());
            deferred_root.clean();
        }
        assert_eq!(stored_files(&deferred_root), stored_files(&blocking_root));
    }
}

#[test]
fn cancellation_before_or_after_sync_aborts_only_the_owned_private_files() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for stop_after in [0, 1] {
            let root = Root::new();
            let store = root.fabric(None);
            let input = objects(format, 8);
            run(&store, &input[..2], &mut || true).unwrap();
            let before = stored_files(&root);
            let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
            let batch = stage(&store, &input, &ledger, amount);
            let mut probes = 0;
            let result = batch.synchronize(&mut || {
                probes += 1;
                probes <= stop_after
            });
            assert!(matches!(
                result,
                Err(StoreRefusal::RuntimeCheckpointRejected)
            ));
            assert!(ledger.close().is_quiescent());
            assert_eq!(stored_files(&root), before);
            root.clean();
            // Cancellation did not poison an immutable identity or its ledger.
            assert_eq!(run_split(&store, &input).unwrap().len(), input.len());
        }
    }
}

#[test]
fn abandoning_a_synchronized_batch_preserves_an_identical_concurrent_publication() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha256, 8);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage(&store, &input, &ledger, amount)
        .synchronize(&mut || true)
        .unwrap();
    assert_eq!(staged_count(&root), input.len());
    // Another operation publishes an identity while this operation still owns
    // private custody. Abandonment may unlink only the latter's stage file.
    run(&store, &input[..1], &mut || true).unwrap();
    batch.abandon().unwrap();
    assert!(ledger.close().is_quiescent());
    root.clean();
    assert_eq!(
        store.read_whole(input[0].identity()).unwrap().object,
        input[0]
    );
    for object in &input[1..] {
        assert!(matches!(
            store.read_whole(object.identity()),
            Err(StoreRefusal::ObjectAbsent)
        ));
    }
}

/// Abandoning a synced batch removes every staged file, links nothing and
/// settles every reservation; dropping one unsettled still removes its files
/// but reports the reservations as leaked.
#[test]
fn abandoning_or_dropping_a_synced_batch_removes_its_staged_files_and_links_nothing() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 300);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    assert_eq!(staged_count(&root), 300);
    batch.abandon().unwrap();
    assert!(ledger.close().is_quiescent());
    root.clean();
    assert!(stored_files(&root).is_empty());

    let (leaky, amount) = ledger_for(&input, LeakDisposition::RecordAndContinue);
    drop(stage_synced(&store, &input, &leaky, amount));
    root.clean();
    assert!(stored_files(&root).is_empty());
    assert!(
        !leaky.close().is_quiescent(),
        "unsettled reservations are leaks"
    );

    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    assert_eq!(
        store
            .publish_synced_batch(batch, &mut || true)
            .unwrap()
            .len(),
        300
    );
    assert!(ledger.close().is_quiescent());
    assert_eq!(stored_files(&root).len(), 300);
    root.clean();
}

/// Another writer may place the same object between staging and publication.
/// Equal bytes make the name AlreadyPresent; different bytes under the name
/// are a collision, refused before any later name is linked.
#[test]
fn publishing_a_synced_batch_accepts_an_equal_racing_object_and_refuses_a_collision() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 8);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    assert_eq!(run(&store, &input[..1], &mut || true).unwrap().len(), 1);
    let published = store.publish_synced_batch(batch, &mut || true).unwrap();
    assert!(ledger.close().is_quiescent());
    assert!(matches!(published[0], PutIfAbsent::AlreadyPresent { .. }));
    assert!(
        published[1..]
            .iter()
            .all(|row| matches!(row, PutIfAbsent::Created { .. }))
    );
    root.clean();

    let collided = Root::new();
    let store = collided.fabric(None);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    let first = collided.path(&input[0]);
    fs::create_dir_all(first.parent().unwrap()).unwrap();
    fs::write(&first, b"not the staged object").unwrap();
    assert_eq!(
        store.publish_synced_batch(batch, &mut || true),
        Err(StoreRefusal::StoredObjectIdentityCollision)
    );
    assert!(ledger.close().is_quiescent());
    collided.clean();
    for object in &input[1..] {
        assert!(!collided.path(object).exists(), "no later name was linked");
    }
}

/// Cancellation at any publication checkpoint settles every reservation and
/// leaves no staged file; the staged objects can be staged and published again.
#[test]
fn a_cancelled_synced_publication_settles_and_can_be_retried() {
    let input = objects(GitHashAlgorithm::Sha256, 4);
    for stop_at in 0..8 {
        let root = Root::new();
        let store = root.fabric(None);
        let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
        let batch = stage_synced(&store, &input, &ledger, amount);
        let mut polls = 0;
        let result = store.publish_synced_batch(batch, &mut || {
            let live = polls != stop_at;
            polls += 1;
            live
        });
        assert!(ledger.close().is_quiescent());
        root.clean();
        if result.is_err() {
            assert_eq!(result, Err(StoreRefusal::RuntimeCheckpointRejected));
            let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
            let batch = stage_synced(&store, &input, &ledger, amount);
            assert_eq!(
                store
                    .publish_synced_batch(batch, &mut || true)
                    .unwrap()
                    .len(),
                4
            );
            assert!(ledger.close().is_quiescent());
        }
        assert_eq!(stored_files(&root).len(), 4);
    }
}

fn only_private_stage(root: &Root) -> PathBuf {
    let mut files = fs::read_dir(root.0.join("staging")).unwrap();
    let path = files.next().unwrap().unwrap().path();
    assert!(files.next().is_none());
    path
}

fn stored_encoding(object: &VerifiedObject) -> Vec<u8> {
    let root = Root::new();
    let store = root.fabric(None);
    run(&store, std::slice::from_ref(object), &mut || true).unwrap();
    fs::read(root.path(object)).unwrap()
}

#[test]
fn private_reads_verify_owned_bytes_without_linking_and_keep_both_settlement_paths() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for publish in [false, true] {
            let root = Root::new();
            let store = root.fabric(None);
            let existing = object(format, b"already present", b"batch");
            let private = object(format, b"private candidate", b"batch");
            let empty = object(format, b"", b"batch");
            let unowned = object(format, b"unowned dependency", b"batch");
            let mut before = vec![existing.clone(), unowned.clone()];
            before.sort_by_key(VerifiedObject::identity);
            run(&store, &before, &mut || true).unwrap();
            let mut input = vec![existing.clone(), private.clone(), empty.clone()];
            input.sort_by_key(VerifiedObject::identity);
            let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
            let batch = stage_synced(&store, &input, &ledger, amount);
            assert_eq!(staged_count(&root), 2);
            for entry in &input {
                assert_eq!(
                    batch
                        .read_object_bounded(&store, entry.identity(), entry.payload().len() as u64)
                        .unwrap(),
                    Some(entry.clone())
                );
            }
            assert_eq!(
                batch
                    .read_object_bounded(&store, unowned.identity(), 0)
                    .unwrap(),
                None,
                "only identities owned by this batch may be read here"
            );
            assert!(matches!(
                batch.read_object_bounded(&store, private.identity(), private.payload().len() as u64 - 1),
                Err(StoreRefusal::StreamingBudgetExceeded { offered, maximum })
                    if offered == private.payload().len() as u64 && maximum + 1 == offered
            ));
            for entry in [&private, &empty] {
                assert!(matches!(
                    store.read_whole(entry.identity()),
                    Err(StoreRefusal::ObjectAbsent)
                ));
            }
            #[cfg(target_os = "linux")]
            assert_eq!(open_staged_files(&root.0.join("staging")), 0);
            if publish {
                let receipts = store.publish_synced_batch(batch, &mut || true).unwrap();
                assert_eq!(receipts.len(), input.len());
                for entry in &input {
                    assert_eq!(store.read_whole(entry.identity()).unwrap().object, *entry);
                }
            } else {
                batch.abandon().unwrap();
                for entry in [&private, &empty] {
                    assert!(matches!(
                        store.read_whole(entry.identity()),
                        Err(StoreRefusal::ObjectAbsent)
                    ));
                }
            }
            assert!(ledger.close().is_quiescent());
            assert_eq!(
                store.read_whole(existing.identity()).unwrap().object,
                existing
            );
            assert_eq!(
                store.read_whole(unowned.identity()).unwrap().object,
                unowned
            );
            root.clean();
        }
    }
}

#[test]
fn an_owned_corrupt_missing_or_swapped_stage_never_uses_a_valid_permanent_copy() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for fault in ["payload", "truncated", "swapped", "missing"] {
            let root = Root::new();
            let store = root.fabric(None);
            let original = object(format, b"original private payload", b"batch");
            let input = std::slice::from_ref(&original);
            let (ledger, amount) = ledger_for(input, LeakDisposition::FailFast);
            let batch = stage_synced(&store, input, &ledger, amount);
            let path = only_private_stage(&root);
            let original_bytes = fs::read(&path).unwrap();
            assert_eq!(
                batch
                    .read_object_bounded(&store, original.identity(), 4096)
                    .unwrap(),
                Some(original.clone())
            );
            // A concurrent successful receive cannot mask this owner's damaged custody.
            run(&store, input, &mut || true).unwrap();
            match fault {
                "payload" => {
                    let mut bytes = original_bytes.clone();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(&path, bytes).unwrap();
                }
                "truncated" => fs::write(&path, &original_bytes[..7]).unwrap(),
                "swapped" => fs::write(
                    &path,
                    stored_encoding(&object(format, b"different native identity", b"batch")),
                )
                .unwrap(),
                "missing" => fs::remove_file(&path).unwrap(),
                _ => unreachable!(),
            }
            let error = batch
                .read_object_bounded(&store, original.identity(), 4096)
                .unwrap_err();
            match fault {
                "payload" => assert_eq!(error, StoreRefusal::PayloadCommitmentMismatch),
                "truncated" => assert_eq!(error, StoreRefusal::MalformedStoredObject),
                "swapped" => assert!(matches!(
                    error,
                    StoreRefusal::StoredObjectReconstructionMismatch { requested, .. }
                        if requested == original.identity()
                )),
                "missing" => assert_eq!(error, StoreRefusal::ObjectAbsent),
                _ => unreachable!(),
            }
            assert_eq!(
                store.read_whole(original.identity()).unwrap().object,
                original
            );
            // Restoring exactly the original owned bytes is the permitted twin.
            fs::write(&path, &original_bytes).unwrap();
            assert_eq!(
                batch
                    .read_object_bounded(&store, original.identity(), 4096)
                    .unwrap(),
                Some(original.clone())
            );
            batch.abandon().unwrap();
            assert!(ledger.close().is_quiescent());
            assert_eq!(
                store.read_whole(original.identity()).unwrap().object,
                original
            );
            root.clean();
        }
    }
}

#[test]
fn synced_reads_require_the_original_envelope_even_for_a_self_consistent_same_oid() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for existing in [false, true] {
            let root = Root::new();
            let store = root.fabric(None);
            let original = object(format, b"same native bytes", b"batch");
            let envelope = original.envelope();
            let changed = VerifiedObject::new(
                ObjectEnvelope::new(
                    envelope.namespace().to_vec(),
                    original.identity(),
                    envelope.object_kind(),
                    envelope.declared_length(),
                    envelope.payload_commitment(),
                    b"other-codec".to_vec(),
                    envelope.logical_content_identity(),
                    envelope.manifest_reference(),
                    &SegmentLimits::default(),
                )
                .unwrap(),
                original.payload().to_vec(),
            )
            .unwrap();
            assert_eq!(changed.identity(), original.identity());
            assert_ne!(changed, original);
            let input = std::slice::from_ref(&original);
            if existing {
                run(&store, input, &mut || true).unwrap();
            }
            let (ledger, amount) = ledger_for(input, LeakDisposition::FailFast);
            let batch = stage_synced(&store, input, &ledger, amount);
            let path = if existing {
                root.path(&original)
            } else {
                only_private_stage(&root)
            };
            let bytes = fs::read(&path).unwrap();
            fs::write(&path, stored_encoding(&changed)).unwrap();
            assert_eq!(
                batch.read_object_bounded(&store, original.identity(), 4096),
                Err(StoreRefusal::StoredObjectIdentityCollision)
            );
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                batch
                    .read_object_bounded(&store, original.identity(), 4096)
                    .unwrap(),
                Some(original.clone())
            );
            batch.abandon().unwrap();
            assert!(ledger.close().is_quiescent());
            if existing {
                assert_eq!(
                    store.read_whole(original.identity()).unwrap().object,
                    original
                );
            } else {
                assert!(matches!(
                    store.read_whole(original.identity()),
                    Err(StoreRefusal::ObjectAbsent)
                ));
            }
            root.clean();
        }
    }
}

#[test]
fn private_reads_enforce_the_supplied_namespace_without_consuming_custody() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Root::new();
        let foreign_root = Root::new();
        let store = root.fabric(None);
        let foreign = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            foreign_root.0.clone(),
            b"foreign".to_vec(),
            OpaqueHandle::new(b"disk").unwrap(),
            OpaqueHandle::new(b"key").unwrap(),
            128 * 1024 * 1024,
            SegmentLimits::default(),
        ))
        .unwrap();
        let original = object(format, b"namespace-owned candidate", b"batch");
        let input = std::slice::from_ref(&original);
        let (ledger, amount) = ledger_for(input, LeakDisposition::FailFast);
        let batch = stage_synced(&store, input, &ledger, amount);
        assert_eq!(
            batch.read_object_bounded(&foreign, original.identity(), 4096),
            Err(StoreRefusal::NamespaceMismatch)
        );
        assert_eq!(
            batch
                .read_object_bounded(&store, original.identity(), 4096)
                .unwrap(),
            Some(original.clone())
        );
        store.publish_synced_batch(batch, &mut || true).unwrap();
        assert!(ledger.close().is_quiescent());
        assert_eq!(
            store.read_whole(original.identity()).unwrap().object,
            original
        );
        root.clean();
    }
}
