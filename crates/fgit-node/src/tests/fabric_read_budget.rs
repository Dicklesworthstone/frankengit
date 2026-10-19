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
