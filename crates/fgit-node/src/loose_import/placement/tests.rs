use super::*;
use crate::NodeConfig;
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::ImmutableObjectFabric;
use fgit_types::{GitHashAlgorithm, RepositoryId, TenantId};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn node(format: GitHashAlgorithm) -> (OneNode, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "fg-placement-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let node = OneNode::init(
        NodeConfig::new(
            path.clone(),
            TenantId::from_bytes([71; 16]),
            RepositoryId::from_bytes([72; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2),
    )
    .unwrap()
    .0;
    (node, path)
}
fn close(node: OneNode, root: std::path::PathBuf) {
    node.shutdown().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn batched_envelopes_equal_the_single_object_encoder_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (node, root) = node(format);
        let placement = Placements::new(&node);
        for (kind, body) in [
            (ObjectType::Blob, vec![]),
            (ObjectType::Blob, vec![0, 255, 1, 2]),
            (ObjectType::Tree, vec![]),
        ] {
            let stored = node.put_git_object(kind, body.clone()).unwrap();
            let verified = placement
                .verify(
                    stored.identity(),
                    LooseObject {
                        object_type: kind,
                        declared_size: body.len(),
                        body,
                    },
                )
                .unwrap();
            assert_eq!(
                node.fabric.read_whole(stored.identity()).unwrap().object,
                verified
            );
        }
        close(node, root);
    }
}

#[test]
fn import_chunks_flush_at_object_and_payload_bounds_before_next_spool_read() {
    let (node, root) = node(GitHashAlgorithm::Sha1);
    let mut deadline = || true;
    let control = ImportControl::new(&mut deadline);
    let mut placement = Placements::new(&node);
    let mut input: Vec<_> = (0..257)
        .map(|i| {
            let body = format!("{i}").into_bytes();
            (
                git_object_id(
                    GitHashAlgorithm::Sha1,
                    fgit_crypto::GitObjectKind::Blob,
                    &body,
                ),
                body,
            )
        })
        .collect();
    input.sort_by_key(|(id, _)| *id);
    for (id, body) in input.iter().take(256) {
        placement
            .push(
                *id,
                LooseObject {
                    object_type: ObjectType::Blob,
                    declared_size: body.len(),
                    body: body.clone(),
                },
                &control,
            )
            .unwrap();
    }
    assert_eq!(placement.objects.len(), 256);
    placement.prepare(input[256].1.len(), &control).unwrap();
    assert!(placement.objects.is_empty());
    placement
        .push(
            input[256].0,
            LooseObject {
                object_type: ObjectType::Blob,
                declared_size: input[256].1.len(),
                body: input[256].1.clone(),
            },
            &control,
        )
        .unwrap();
    placement.prepare(CHUNK_BYTES + 1, &control).unwrap();
    assert!(placement.objects.is_empty());
    for (id, body) in input {
        assert_eq!(node.fabric.read_whole(id).unwrap().object.payload(), body);
    }
    let body = vec![b'x'; CHUNK_BYTES + 1];
    let id = git_object_id(
        GitHashAlgorithm::Sha1,
        fgit_crypto::GitObjectKind::Blob,
        &body,
    );
    placement
        .push(
            id,
            LooseObject {
                object_type: ObjectType::Blob,
                declared_size: body.len(),
                body: body.clone(),
            },
            &control,
        )
        .unwrap();
    assert!(placement.objects.is_empty());
    assert_eq!(node.fabric.read_whole(id).unwrap().object.payload(), body);
    close(node, root);
}

#[test]
fn a_cancelled_pending_chunk_does_not_create_any_placement() {
    let (node, root) = node(GitHashAlgorithm::Sha256);
    let mut placement = Placements::new(&node);
    let mut active = || true;
    let control = ImportControl::new(&mut active);
    let body = b"pending".to_vec();
    let id = git_object_id(
        GitHashAlgorithm::Sha256,
        fgit_crypto::GitObjectKind::Blob,
        &body,
    );
    placement
        .push(
            id,
            LooseObject {
                object_type: ObjectType::Blob,
                declared_size: body.len(),
                body,
            },
            &control,
        )
        .unwrap();
    let mut stopped = || false;
    let cancelled = ImportControl::new(&mut stopped);
    assert!(matches!(
        placement.flush(&cancelled),
        Err(LooseGitImportRefusal::Interrupted { .. })
    ));
    assert!(matches!(
        node.fabric.read_whole(id),
        Err(StoreRefusal::ObjectAbsent)
    ));
    placement.flush(&control).unwrap();
    assert_eq!(
        node.fabric.read_whole(id).unwrap().object.payload(),
        b"pending"
    );
    close(node, root);
}
