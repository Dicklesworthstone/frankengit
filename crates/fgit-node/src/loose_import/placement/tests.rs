use super::*;
use crate::NodeConfig;
use fgit_crypto::git_object_id;
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::ImmutableObjectFabric;
use fgit_object_fabric::fabric::StoreRefusal;
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
                    IdentifiedGitObject::identify(format, kind, body),
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
                IdentifiedGitObject::identify(
                    GitHashAlgorithm::Sha1,
                    ObjectType::Blob,
                    body.clone(),
                ),
                &control,
            )
            .unwrap();
    }
    assert_eq!(placement.objects.len(), 256);
    placement.prepare(input[256].1.len(), &control).unwrap();
    assert!(placement.objects.is_empty());
    // The full chunk is staged and syncing; no name is linked until it
    // settles (frankengit-ai60).
    assert!(placement.in_flight.is_some());
    assert!(matches!(
        node.fabric.read_whole(input[0].0),
        Err(StoreRefusal::ObjectAbsent)
    ));
    placement
        .push(
            input[256].0,
            IdentifiedGitObject::identify(
                GitHashAlgorithm::Sha1,
                ObjectType::Blob,
                input[256].1.clone(),
            ),
            &control,
        )
        .unwrap();
    placement.prepare(CHUNK_BYTES + 1, &control).unwrap();
    assert!(placement.objects.is_empty());
    // Staging the second chunk settled the first; the second is in flight.
    for (id, body) in input.iter().take(256) {
        assert_eq!(node.fabric.read_whole(*id).unwrap().object.payload(), *body);
    }
    assert!(matches!(
        node.fabric.read_whole(input[256].0),
        Err(StoreRefusal::ObjectAbsent)
    ));
    let body = vec![b'x'; CHUNK_BYTES + 1];
    let id = git_object_id(
        GitHashAlgorithm::Sha1,
        fgit_crypto::GitObjectKind::Blob,
        &body,
    );
    placement
        .push(
            id,
            IdentifiedGitObject::identify(GitHashAlgorithm::Sha1, ObjectType::Blob, body.clone()),
            &control,
        )
        .unwrap();
    // Placing an oversized object directly first settled the chunk in flight.
    assert!(placement.objects.is_empty());
    assert!(placement.in_flight.is_none());
    for (id, body) in input {
        assert_eq!(node.fabric.read_whole(id).unwrap().object.payload(), body);
    }
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
            IdentifiedGitObject::identify(GitHashAlgorithm::Sha256, ObjectType::Blob, body),
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
    placement.finish(&control).unwrap();
    assert_eq!(
        node.fabric.read_whole(id).unwrap().object.payload(),
        b"pending"
    );
    close(node, root);
}

/// Placement still compares the custody read's identity with the one it was
/// asked to place, and refuses a proof for another object before sealing
/// anything (frankengit-fhh5).
#[test]
fn a_proof_for_another_identity_is_refused_before_sealing() {
    let (node, root) = node(GitHashAlgorithm::Sha1);
    let placement = Placements::new(&node);
    let proven = git_object_id(GitHashAlgorithm::Sha1, ObjectType::Blob, b"proof");
    let other = git_object_id(GitHashAlgorithm::Sha1, ObjectType::Blob, b"other");
    let object =
        IdentifiedGitObject::identify(GitHashAlgorithm::Sha1, ObjectType::Blob, b"proof".to_vec());
    assert!(matches!(
        placement.verify(other, object),
        Err(LooseGitImportRefusal::ObjectIdentityMismatch { expected, observed })
            if expected == other && observed == proven
    ));
    close(node, root);
}

/// A batch in flight is staged but unlinked. Abandoning it after a refusal,
/// or settling it once the import is cancelled, links no name, removes every
/// staged file and settles every reservation; the refusal survives. The same
/// objects then place normally (frankengit-ai60).
#[test]
fn an_in_flight_batch_links_nothing_when_abandoned_or_cancelled() {
    let (node, root) = node(GitHashAlgorithm::Sha1);
    let mut active = || true;
    let control = ImportControl::new(&mut active);
    let mut stopped = || false;
    let cancelled = ImportControl::new(&mut stopped);
    let mut blobs: Vec<_> = (0..3)
        .map(|i| {
            let body = format!("in flight {i}").into_bytes();
            (
                git_object_id(GitHashAlgorithm::Sha1, ObjectType::Blob, &body),
                body,
            )
        })
        .collect();
    blobs.sort_by_key(|(id, _)| *id);
    let staging = root.join("staging");
    let stage = |placement: &mut Placements<'_>| {
        for (id, body) in &blobs {
            placement
                .push(
                    *id,
                    IdentifiedGitObject::identify(
                        GitHashAlgorithm::Sha1,
                        ObjectType::Blob,
                        body.clone(),
                    ),
                    &control,
                )
                .unwrap();
        }
        placement.flush(&control).unwrap();
        assert!(placement.in_flight.is_some());
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 3);
    };
    let unlinked = || {
        for (id, _) in &blobs {
            assert!(matches!(
                node.fabric.read_whole(*id),
                Err(StoreRefusal::ObjectAbsent)
            ));
        }
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    };

    let mut placement = Placements::new(&node);
    stage(&mut placement);
    let refusal = placement.abandon(LooseGitImportRefusal::ObjectLimitExceeded { limit: 7 });
    assert!(matches!(
        refusal,
        LooseGitImportRefusal::ObjectLimitExceeded { limit: 7 }
    ));
    assert!(placement.in_flight.is_none());
    unlinked();

    stage(&mut placement);
    assert!(matches!(
        placement.settle(&cancelled),
        Err(LooseGitImportRefusal::Interrupted { .. })
    ));
    assert!(placement.in_flight.is_none());
    unlinked();

    stage(&mut placement);
    placement.finish(&control).unwrap();
    for (id, body) in &blobs {
        assert_eq!(node.fabric.read_whole(*id).unwrap().object.payload(), *body);
    }
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    close(node, root);
}
