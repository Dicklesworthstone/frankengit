//! Synced publication races must retain exactness and bounded storage reads.

use super::*;
use fgit_object_fabric::fabric::StorageOperation;
use std::io::{self, Seek, SeekFrom, Write};

fn only_stage(root: &Root) -> PathBuf {
    let paths: Vec<_> = fs::read_dir(root.0.join("staging"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(paths.len(), 1);
    paths[0].clone()
}

#[test]
fn large_equal_racing_objects_are_exact_and_durable_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Root::new();
        let store = root.fabric(None);
        let input = [object(format, &vec![91; 128 * 1024 + 37], b"batch")];
        let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
        let batch = stage_synced(&store, &input, &ledger, amount);
        run(&store, &input, &mut || true).unwrap();
        let published = store.publish_synced_batch(batch, &mut || true).unwrap();
        assert!(matches!(
            published.as_slice(),
            [PutIfAbsent::AlreadyPresent { epochs, .. }]
                if epochs.contains(PublicationEpoch::Durable)
                    && !epochs.contains(PublicationEpoch::Visible)
        ));
        assert!(ledger.close().is_quiescent());
        assert_eq!(
            store.read_whole(input[0].identity()).unwrap().object,
            input[0]
        );
        root.clean();
    }
}

#[test]
fn same_length_collision_after_multiple_chunks_refuses_and_preserves_the_target() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = [object(
        GitHashAlgorithm::Sha256,
        &vec![91; 128 * 1024 + 37],
        b"batch",
    )];
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    run(&store, &input, &mut || true).unwrap();
    let path = root.path(&input[0]);
    let original_length = fs::metadata(&path).unwrap().len();
    let mut target = fs::OpenOptions::new().write(true).open(&path).unwrap();
    target.seek(SeekFrom::End(-1)).unwrap();
    target.write_all(&[90]).unwrap();
    drop(target);
    let corrupted = fs::read(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), original_length);
    assert_eq!(
        store.publish_synced_batch(batch, &mut || true),
        Err(StoreRefusal::StoredObjectIdentityCollision)
    );
    assert!(ledger.close().is_quiescent());
    assert_eq!(fs::read(&path).unwrap(), corrupted);
    root.clean();
}

#[test]
fn oversized_sparse_stages_and_targets_are_refused_before_comparison() {
    const MAXIMUM: u64 = 4096;
    const OVERSIZED: u64 = 1024 * 1024;
    for (grow_stage, grow_target) in [(true, false), (false, true), (true, true)] {
        let root = Root::new();
        let store = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            root.0.clone(),
            b"batch".to_vec(),
            OpaqueHandle::new(b"disk").unwrap(),
            OpaqueHandle::new(b"key").unwrap(),
            MAXIMUM,
            SegmentLimits::default(),
        ))
        .unwrap();
        let input = objects(GitHashAlgorithm::Sha1, 1);
        let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
        let batch = stage_synced(&store, &input, &ledger, amount);
        run(&store, &input, &mut || true).unwrap();
        let target = root.path(&input[0]);
        let original_length = fs::metadata(&target).unwrap().len();
        for (grow, path) in [
            (grow_stage, only_stage(&root)),
            (grow_target, target.clone()),
        ] {
            if grow {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_len(OVERSIZED)
                    .unwrap();
            }
        }
        assert_eq!(
            store.publish_synced_batch(batch, &mut || true),
            Err(StoreRefusal::StoredObjectTooLarge {
                offered: OVERSIZED,
                maximum: MAXIMUM,
            })
        );
        assert!(ledger.close().is_quiescent());
        assert_eq!(
            fs::metadata(&target).unwrap().len(),
            if grow_target {
                OVERSIZED
            } else {
                original_length
            }
        );
        if !grow_target {
            assert_eq!(
                store.read_whole(input[0].identity()).unwrap().object,
                input[0]
            );
        }
        root.clean();
    }
}

#[test]
fn a_directory_at_the_immutable_name_is_a_typed_publication_refusal() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha1, 1);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    fs::create_dir(root.path(&input[0])).unwrap();
    assert_eq!(
        store.publish_synced_batch(batch, &mut || true),
        Err(StoreRefusal::StorageIo {
            operation: StorageOperation::PublishImmutableBody,
            kind: io::ErrorKind::InvalidInput,
        })
    );
    assert!(ledger.close().is_quiescent());
    assert!(root.path(&input[0]).is_dir());
    root.clean();
}

#[cfg(unix)]
#[test]
fn equal_bytes_through_a_symlink_never_satisfy_a_publication_race() {
    use std::os::unix::fs::symlink;

    for replace_stage in [false, true] {
        let root = Root::new();
        let store = root.fabric(None);
        let input = objects(GitHashAlgorithm::Sha1, 1);
        let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
        let batch = stage_synced(&store, &input, &ledger, amount);
        let stage = only_stage(&root);
        let target = root.path(&input[0]);
        if replace_stage {
            run(&store, &input, &mut || true).unwrap();
            let moved_stage = root.0.join("moved-stage");
            fs::rename(&stage, &moved_stage).unwrap();
            symlink(moved_stage, &stage).unwrap();
        } else {
            symlink(&stage, &target).unwrap();
        }
        assert_eq!(
            store.publish_synced_batch(batch, &mut || true),
            Err(StoreRefusal::StorageIo {
                operation: StorageOperation::PublishImmutableBody,
                kind: io::ErrorKind::InvalidInput,
            })
        );
        assert!(ledger.close().is_quiescent());
        if replace_stage {
            assert_eq!(
                store.read_whole(input[0].identity()).unwrap().object,
                input[0]
            );
        } else {
            assert!(
                fs::symlink_metadata(&target)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        root.clean();
    }
}

#[test]
fn matching_racing_bytes_still_cannot_bypass_the_directory_durability_fence() {
    let root = Root::new();
    let store = root.fabric(None);
    let input = objects(GitHashAlgorithm::Sha256, 1);
    let (ledger, amount) = ledger_for(&input, LeakDisposition::FailFast);
    let batch = stage_synced(&store, &input, &ledger, amount);
    run(&store, &input, &mut || true).unwrap();
    let faulted = root.fabric(Some(LocalCrashPoint::AfterPublishDirectorySync));
    assert_eq!(
        faulted.publish_synced_batch(batch, &mut || true),
        Err(StoreRefusal::StorageIo {
            operation: StorageOperation::SyncDirectory,
            kind: io::ErrorKind::Interrupted,
        })
    );
    assert!(ledger.close().is_quiescent());
    assert_eq!(
        store.read_whole(input[0].identity()).unwrap().object,
        input[0]
    );
    root.clean();
}
