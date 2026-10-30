//! The verified Git source keeps caller size refusals and post-read liveness
//! distinct from missing objects while using the real filesystem fabric.
use super::*;

#[test]
fn verified_object_reads_enforce_payload_budgets_in_both_native_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let directory = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(directory.path().to_path_buf()).with_object_format(format))
                .unwrap();
        let body = b"exact source bytes\n";
        let id = put_object(&node, ObjectType::Blob, body.to_vec());
        let empty = put_object(&node, ObjectType::Blob, Vec::new());
        let context = FsqliteCx::new();
        let exhaustion = Cell::new(None);
        let mut source = crate::VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: body.len(),
            database_context: &context,
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        assert_eq!(
            source.read_object(&id).unwrap(),
            (ObjectType::Blob, body.to_vec())
        );
        source.maximum_object_bytes -= 1;
        assert!(
            matches!(source.read_object(&id), Err(fgit_pack::PackWriteError::Pack(
            fgit_pack::PackError::ObjectSizeLimit { actual, limit }
        )) if actual == body.len() && limit == body.len() - 1)
        );
        assert!(exhaustion.get().is_none());
        source.maximum_object_bytes = 0;
        assert_eq!(
            source.read_object(&empty).unwrap(),
            (ObjectType::Blob, Vec::new())
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn post_read_session_expiry_still_precedes_a_storage_budget_refusal() {
    let directory = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(directory.path().to_path_buf())).unwrap();
    let id = put_object(
        &node,
        ObjectType::Blob,
        b"larger than the caller permits".to_vec(),
    );
    let context = FsqliteCx::new();
    let exhaustion = Cell::new(None);
    let probes = Cell::new(0);
    let expires_after_read = || {
        let next = probes.get() + 1;
        probes.set(next);
        next == 1
    };
    let source = crate::VerifiedFabricPackSource {
        fabric: &node.fabric,
        object_format: node.object_format,
        maximum_object_bytes: 1,
        database_context: &context,
        database_exhaustion: &exhaustion,
        session_is_live: Some(&expires_after_read),
    };
    assert!(matches!(
        source.read_object(&id),
        Err(fgit_pack::PackWriteError::Pack(
            fgit_pack::PackError::DeadlineExceeded
        ))
    ));
    assert_eq!(probes.get(), 2);
    node.shutdown().unwrap();
}

#[test]
fn private_candidate_source_reads_owned_bytes_and_retains_publication_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let directory = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(directory.path().to_path_buf()).with_object_format(format))
                .unwrap();
        let body = b"private candidate bytes";
        let object = node
            .verified_git_object(ObjectType::Blob, body.to_vec())
            .unwrap();
        let id = object.identity();
        let existing = put_object(&node, ObjectType::Blob, b"existing dependency".to_vec());
        let staging = crate::receive_staging::ReceiveStaging::default();
        staging.stage(&node, &[object], &mut || true).unwrap();
        assert!(matches!(
            node.fabric.read_whole_bounded(id, 1024),
            Err(StoreRefusal::ObjectAbsent)
        ));
        let context = FsqliteCx::new();
        let exhaustion = Cell::new(None);
        let source = crate::VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: body.len(),
            database_context: &context,
            database_exhaustion: &exhaustion,
            session_is_live: None,
        }
        .with_staging(&staging);
        assert_eq!(
            source.read_object(&id).unwrap(),
            (ObjectType::Blob, body.to_vec())
        );
        assert_eq!(
            source.read_object(&existing).unwrap(),
            (ObjectType::Blob, b"existing dependency".to_vec())
        );
        assert!(matches!(
            node.fabric.read_whole_bounded(id, 1024),
            Err(StoreRefusal::ObjectAbsent)
        ));
        let narrow = crate::VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: body.len() - 1,
            database_context: &context,
            database_exhaustion: &exhaustion,
            session_is_live: None,
        }
        .with_staging(&staging);
        assert!(matches!(narrow.read_object(&id),
            Err(fgit_pack::PackWriteError::Pack(fgit_pack::PackError::ObjectSizeLimit { actual, limit }))
                if actual == body.len() && limit == body.len() - 1));
        staging.publish(&node.fabric, &mut || true).unwrap();
        // The same holder remains a valid source while an authority-CAS retry
        // revalidates objects already placed by its first attempt.
        assert_eq!(
            source.read_object(&id).unwrap(),
            (ObjectType::Blob, body.to_vec())
        );
        assert_eq!(node.read_git_object(id).unwrap().payload(), body);
        drop(staging);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_corrupt_owned_candidate_never_falls_back_and_post_read_cancellation_still_wins() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let directory = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(directory.path().to_path_buf()).with_object_format(format))
                .unwrap();
        let body = b"private original commitment";
        let object = node
            .verified_git_object(ObjectType::Blob, body.to_vec())
            .unwrap();
        let id = object.identity();
        let staging = crate::receive_staging::ReceiveStaging::default();
        staging.stage(&node, &[object], &mut || true).unwrap();
        let private = std::fs::read_dir(node.storage_root().join("staging"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        // An independent operation publishes the same identity. That permanent
        // copy cannot make a corrupt owned stage appear verified.
        assert_eq!(put_object(&node, ObjectType::Blob, body.to_vec()), id);
        std::fs::write(private, b"corrupt private framing").unwrap();
        let context = FsqliteCx::new();
        let exhaustion = Cell::new(None);
        let source = crate::VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: 1024,
            database_context: &context,
            database_exhaustion: &exhaustion,
            session_is_live: None,
        }
        .with_staging(&staging);
        assert!(matches!(source.read_object(&id),
            Err(fgit_pack::PackWriteError::MissingCanonicalObject(missing)) if missing == id));
        let probes = Cell::new(0);
        let live = || {
            let next = probes.get() + 1;
            probes.set(next);
            next == 1
        };
        let interrupted = crate::VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: 1024,
            database_context: &context,
            database_exhaustion: &exhaustion,
            session_is_live: Some(&live),
        }
        .with_staging(&staging);
        assert!(matches!(
            interrupted.read_object(&id),
            Err(fgit_pack::PackWriteError::Pack(
                fgit_pack::PackError::DeadlineExceeded
            ))
        ));
        assert_eq!(probes.get(), 2);
        drop(staging);
        assert_eq!(
            std::fs::read_dir(node.storage_root().join("staging"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(node.read_git_object(id).unwrap().payload(), body);
        node.shutdown().unwrap();
    }
}
