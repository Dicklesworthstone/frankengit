#![forbid(unsafe_code)]
//! Durable creation recovery and stale-incarnation refusal at the node boundary.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::OutcomeFailure;
use fgit_node::{NodeConfig, NodeInitialization, NodeRefusal, OneNode, RepositoryResolutionInput};
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-fg059-incarnation-lifecycle-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x59; 16]),
        RepositoryId::from_bytes([0x60; 16]),
    )
}

fn recovery_config(root: PathBuf, key: &[u8]) -> NodeConfig {
    config(root).with_creation_idempotency_key(key.to_vec())
}

#[test]
fn a_lost_creation_response_recovers_the_first_minted_incarnation() {
    let scratch = ScratchDirectory::new();
    let key = b"fg059-first-writer";

    let (first, first_initialization) = OneNode::init(recovery_config(scratch.0.clone(), key))
        .expect("the first writer stores its immutable creation attempt");
    assert_eq!(first_initialization, NodeInitialization::Created);
    let first_incarnation = first.repository_incarnation_id();
    first.shutdown().expect("first node closes cleanly");

    let (retry, retry_initialization) = OneNode::init(recovery_config(scratch.0.clone(), key))
        .expect("the retry recovers the first writer's canonical incarnation");
    assert_eq!(retry_initialization, NodeInitialization::IdenticalRetry);
    assert_eq!(
        retry.repository_incarnation_id(),
        first_incarnation,
        "a retry may mint a local candidate but must use the immutable stored result"
    );
    retry.shutdown().expect("recovered node closes cleanly");
}

#[test]
fn a_creation_key_cannot_be_reused_with_different_fixed_fields() {
    let scratch = ScratchDirectory::new();
    let key = b"fg059-fixed-fields";

    let (first, _) = OneNode::init(
        recovery_config(scratch.0.clone(), key).with_object_format(GitHashAlgorithm::Sha1),
    )
    .expect("the initial fixed request creates");
    let first_incarnation = first.repository_incarnation_id();
    first.shutdown().expect("first node closes cleanly");

    assert!(
        matches!(
            OneNode::init(
                recovery_config(scratch.0.clone(), key).with_object_format(GitHashAlgorithm::Sha256)
            ),
            Err(NodeRefusal::Authority(error))
                if matches!(error.as_ref(), OutcomeFailure::CreationAttemptFixedFieldsMismatch)
        ),
        "a key reused for a different permanent object domain refuses rather than minting again"
    );

    let reopened = OneNode::open_existing(config(scratch.0.clone()))
        .expect("the original repository remains authoritative after refusal");
    assert_eq!(reopened.repository_incarnation_id(), first_incarnation);
    reopened.shutdown().expect("reopened node closes cleanly");
}

#[test]
fn every_existing_resolution_input_refuses_a_stale_incarnation_with_a_current_twin() {
    let scratch = ScratchDirectory::new();
    let (created, _) = OneNode::init(recovery_config(scratch.0.clone(), b"fg059-stale-corpus"))
        .expect("the canonical repository creates");
    let current = created.repository_incarnation_id();
    let stale = RepositoryIncarnationId::from_bytes([0xD3; 16]);
    assert_ne!(current, stale);
    created.shutdown().expect("creator closes cleanly");

    let stale_inputs = [
        RepositoryResolutionInput::DirectOpen(stale),
        RepositoryResolutionInput::CapabilityToken(stale),
        RepositoryResolutionInput::CacheEntry(stale),
        RepositoryResolutionInput::ObjectLocation(stale),
        RepositoryResolutionInput::TransportTarget(stale),
    ];
    let current_inputs = [
        RepositoryResolutionInput::DirectOpen(current),
        RepositoryResolutionInput::CapabilityToken(current),
        RepositoryResolutionInput::CacheEntry(current),
        RepositoryResolutionInput::ObjectLocation(current),
        RepositoryResolutionInput::TransportTarget(current),
    ];

    for (stale_input, current_input) in stale_inputs.into_iter().zip(current_inputs) {
        assert!(
            matches!(
                OneNode::open_existing(config(scratch.0.clone()).with_resolution_input(stale_input)),
                Err(NodeRefusal::RepositoryIncarnationMismatch { expected, observed })
                    if expected == stale && observed == current
            ),
            "every stale resolution carrier refuses before opening an object namespace"
        );

        let permitted =
            OneNode::open_existing(config(scratch.0.clone()).with_resolution_input(current_input))
                .expect("the near-identical current resolution carrier opens");
        assert_eq!(permitted.repository_incarnation_id(), current);
        permitted.shutdown().expect("permitted node closes cleanly");
    }
}

#[test]
fn creation_refuses_to_resolve_a_caller_supplied_incarnation() {
    let scratch = ScratchDirectory::new();
    let refusal = OneNode::init(
        recovery_config(scratch.0.clone(), b"fg059-create-resolution").with_resolution_input(
            RepositoryResolutionInput::CapabilityToken(RepositoryIncarnationId::from_bytes(
                [0x61; 16],
            )),
        ),
    )
    .expect_err("creation establishes its incarnation before accepting any resolution input");
    assert!(matches!(refusal, NodeRefusal::CreationWithResolutionInput));
}
