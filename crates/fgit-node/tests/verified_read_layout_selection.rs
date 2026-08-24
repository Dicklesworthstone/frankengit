#![forbid(unsafe_code)]
//! Public creation selects the authenticated layout that verified reads use.
//!
//! This is intentionally an integration test: it must not construct a
//! repository configuration body or reach into node internals to obtain a
//! proof-capable repository.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{NodeConfig, OneNode, VerifiedReadQuery, VerifiedReadServingRefusal};
use fgit_types::{
    CellState, CellTransitionCause, HeadGeneration, RefName, RepositoryId, RootLayoutVersion,
    TenantId,
};
use fgit_verified_read::{
    PinnedAuthorityHead, ReadResponse, UnprovenReadAnswer, VerifiedMembership,
    VerifiedReadCapability, VerifiedReadConfiguration, verify_envelope,
};
use fgit_wire::visibility::RefVisibility;

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-lmc3-verified-read-layout-{}-{sequence}",
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
        TenantId::from_bytes([0x71; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
}

fn enable_verified_reads(node: &mut OneNode) {
    node.transition_cell_state(
        CellState::VerifiedReadOnly,
        CellTransitionCause::AuthorityObservation,
        HeadGeneration::FIRST,
    )
    .expect("a freshly initialized node can enter its verified-read serving state");
}

fn absent_ref() -> RefName {
    RefName::try_new(b"refs/heads/public-layout-proof").expect("the fixed absent ref name is valid")
}

#[test]
fn public_merkle_selection_reopens_and_serves_a_verified_ref_absence() {
    let scratch = ScratchDirectory::new();
    let creation = config(scratch.0.clone()).with_root_layout(RootLayoutVersion::RefStateMerkleV1);
    let (node, _) = OneNode::init(creation)
        .expect("the public creation API persists the selected proof-capable layout");
    node.shutdown()
        .expect("the initializer closes before the persisted configuration is reopened");

    let mut node = OneNode::open_existing(config(scratch.0.clone()))
        .expect("an unspecified opener reads the authenticated stored layout");
    enable_verified_reads(&mut node);
    let name = absent_ref();
    let request = node.request_context();

    let unproven = node
        .runtime()
        .block_on(node.serve_current_verified_read_in(
            &request,
            &RefVisibility::new(),
            fgit_types::ReadLabel::current(),
            VerifiedReadCapability::Unproven,
            VerifiedReadQuery::Ref(name.clone()),
        ))
        .expect("a client that does not request a proof still receives a valid answer");
    assert!(matches!(
        unproven.response(),
        ReadResponse::Unproven(answer)
            if matches!(answer.as_ref(), UnprovenReadAnswer::Ref { name: answered, oid: None } if answered == &name)
    ));

    let verified = node
        .runtime()
        .block_on(node.serve_current_verified_read_in(
            &request,
            &RefVisibility::new(),
            fgit_types::ReadLabel::current(),
            VerifiedReadCapability::EnvelopeV1,
            VerifiedReadQuery::Ref(name),
        ))
        .expect("the selected V1 ref Merkle layout makes a public verified read reachable");
    let ReadResponse::Verified(envelope) = verified.response() else {
        panic!("a proof-capable client must receive a verified envelope");
    };
    assert!(matches!(
        envelope.exact_configuration(),
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2_1(_))
    ));
    assert_eq!(
        envelope
            .exact_configuration()
            .expect("a ref proof carries its authenticated selected configuration")
            .root_layout(),
        RootLayoutVersion::RefStateMerkleV1,
        "the served envelope exposes the selected authenticated root layout"
    );
    assert_eq!(
        verify_envelope(
            &PinnedAuthorityHead::new(verified.authority_head().clone()),
            envelope,
        )
        .expect("the public server response verifies against its selected head"),
        VerifiedMembership::RefAbsence
    );

    node.shutdown().expect("the reopened node closes cleanly");
}

#[test]
fn legacy_default_reopens_for_unproven_reads_and_refuses_ref_proofs() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(config(scratch.0.clone()))
        .expect("the existing legacy-default creation path remains supported");
    node.shutdown()
        .expect("the legacy initializer closes before reopen");

    let mut node = OneNode::open_existing(config(scratch.0.clone()))
        .expect("an existing legacy repository opens through its stored configuration");
    enable_verified_reads(&mut node);
    let name = absent_ref();
    let request = node.request_context();

    let unproven = node
        .runtime()
        .block_on(node.serve_current_verified_read_in(
            &request,
            &RefVisibility::new(),
            fgit_types::ReadLabel::current(),
            VerifiedReadCapability::Unproven,
            VerifiedReadQuery::Ref(name.clone()),
        ))
        .expect("legacy repositories still serve valid unproven reads");
    assert!(matches!(unproven.response(), ReadResponse::Unproven(_)));

    let refusal = node.runtime().block_on(node.serve_current_verified_read_in(
        &request,
        &RefVisibility::new(),
        fgit_types::ReadLabel::current(),
        VerifiedReadCapability::EnvelopeV1,
        VerifiedReadQuery::Ref(name),
    ));
    assert!(matches!(
        refusal,
        Err(VerifiedReadServingRefusal::RefLayoutUnavailable {
            layout: RootLayoutVersion::LegacyWholeBody
        })
    ));

    node.shutdown().expect("the legacy node closes cleanly");
}
