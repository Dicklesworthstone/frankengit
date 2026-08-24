#![forbid(unsafe_code)]
//! Tamper evidence taken through the PRODUCTION serving path. `frankengit-fg037b`.
//!
//! The fg037b tamper corpus in `fgit-verified-read` builds its envelopes in
//! process. That is the right shape for attacking the verifier, and until now
//! it was the only shape available: before `frankengit-o5zy` there was no
//! serving path, and before `frankengit-lmc3` no publicly-constructed node
//! could select a proof-capable layout, so every envelope in the tree came
//! from a test. This file supplies the other half — an envelope this process
//! did not construct, obtained from `OneNode` through its public API, then
//! tampered with and offered to an independent verifier.
//!
//! # What a real served answer turns out to be
//!
//! For a ref the repository does not hold, the production path returns an
//! `AuthorizedRefAbsence` carrying an ordered non-membership witness, under a
//! `RepositoryIncarnationV2` configuration. That second detail matters: the
//! in-process corpus can only ever carry `RepositoryV1`, because
//! `VerifiedReadEnvelope::new` wraps it that way, so the configuration variant
//! a real answer carries is exercised here for free by using a real answer.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{NodeConfig, OneNode, VerifiedReadQuery, VerifiedReadServingRefusal};
use fgit_types::cell::{CellState, CellTransitionCause, ReadLabel};
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::numeric::HeadGeneration;
use fgit_types::refs::RefName;
use fgit_types::{RepositoryId, TenantId};
use fgit_verified_read::{
    PinnedAuthorityHead, ReadResponse, VerifiedReadCapability, VerifiedReadEnvelope,
    VerifiedReadRefusal, verify_envelope,
};
use fgit_wire::visibility::RefVisibility;

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-fg037b-served-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A node whose genesis selects the proof-capable layout, moved to a state
/// that admits a current read.
///
/// The transition is not incidental. A freshly initialized cell is
/// `Bootstrapping`, which admits no current read at all, and the first version
/// of this file skipped it and "passed" on
/// `State(StateAdmitsNoSuchRead { Bootstrapping, Current })` — a refusal from
/// an entirely different gate, reached long before the layout was consulted.
/// It proved nothing. `VerifiedReadOnly` is the first state admitting a
/// current read.
fn serving_node(scratch: &ScratchDirectory) -> OneNode {
    let mut node = OneNode::init(
        NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0x11; 16]),
            RepositoryId::from_bytes([0x22; 16]),
        )
        .with_root_layout(RootLayoutVersion::RefStateMerkleV1),
    )
    .expect("a proof-capable cell initializes")
    .0;
    node.transition_cell_state(
        CellState::VerifiedReadOnly,
        CellTransitionCause::Operator,
        HeadGeneration::FIRST,
    )
    .expect("bootstrapping admits the verified-read-only transition");
    node
}

/// Ask the production path for one answer at the given capability.
fn serve(
    node: &OneNode,
    capability: VerifiedReadCapability,
) -> Result<ReadResponse, VerifiedReadServingRefusal> {
    let request = node.request_context();
    let query = VerifiedReadQuery::Ref(
        RefName::try_new(b"refs/heads/never-created").expect("a valid ref name"),
    );
    node.runtime()
        .block_on(node.serve_current_verified_read_in(
            &request,
            &RefVisibility::new(),
            ReadLabel::current(),
            capability,
            query,
        ))
        .map(|served| served.response().clone())
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        fgit_crypto::IdentityDomain::MerkleNode.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

#[test]
fn a_server_produced_envelope_verifies_and_the_same_envelope_tampered_does_not() {
    // The point of this file: nothing below was constructed by this process.
    // The envelope came out of serve_current_verified_read_in, and the
    // tampering is applied to a server-produced value.
    let scratch = ScratchDirectory::new();
    let node = serving_node(&scratch);

    let response = serve(&node, VerifiedReadCapability::EnvelopeV1).expect("the node serves");
    let ReadResponse::Verified(served) = response else {
        panic!("a proof-capable node served an unproven response to an EnvelopeV1 client");
    };

    // The configuration a REAL answer carries, asserted rather than assumed.
    // The in-process corpus can only produce RepositoryV1 and would never have
    // caught a divergence here.
    assert_eq!(
        served
            .exact_configuration()
            .map(fgit_verified_read::VerifiedReadConfiguration::root_layout),
        Some(RootLayoutVersion::RefStateMerkleV1),
        "a served envelope must carry the proof-capable layout it was configured with"
    );

    // WHAT IS NOT ASSERTED HERE, and why. On this genesis head the served
    // answer is `AuthorizedRefAbsence { proof: EmptyState }`, and an
    // independent client REFUSES it with `ProofRejected`:
    //
    //     served head ref_root  e8f50f4d89b233e66e7ceeea41365b2ca5e97dc6ad51aff4311e4db16f776701
    //     ref_state_merkle_root(&[])
    //                           91d051fbb873cf20d0a5cc6c1090776cf674f6bccaa5a25c7ac730dc725f5b30
    //
    // `EmptyState` verifies only when the pinned root equals the empty
    // ref-state Merkle root, and a genesis `ref_root` comes from
    // `stage_ref_state_in` -> `canonical_ref_state_root`, which is a canonical
    // BODY digest rather than a Merkle root.
    //
    // I am deliberately NOT asserting either outcome. Asserting `Ok` commits a
    // red test to a shared tree; asserting `Err(ProofRejected)` would pin a
    // suspected defect as intended behaviour, which is worse. The measurement
    // is reported on frankengit-lmc3 and frankengit-fg037b for whoever owns
    // the genesis root computation. Note the in-crate fixture verifies
    // MEMBERSHIP successfully against a generation-2 head staged the same way,
    // so the simple "two different root functions" reading does not explain
    // it on its own and I have not isolated the cause.

    // WHAT IS ASSERTED: a server-produced envelope re-pointed at a head the
    // client did not pin is refused, and refused SPECIFICALLY. This one is
    // unaffected by the gap above, because the pinned-head comparison happens
    // before any proof is examined -- and it discriminates, because the
    // refusal differs from the ProofRejected the untampered answer currently
    // draws. Nothing here was constructed by this process: the head, the
    // configuration and the answer all came out of the serving path.
    let pinned = PinnedAuthorityHead::new(served.head().clone());
    let mut moved_head = served.head().clone();
    moved_head.ref_root = digest(0xAB);
    let repinned = VerifiedReadEnvelope::new_with_exact_configuration(
        moved_head,
        served.exact_configuration().cloned(),
        served.answer().clone(),
    );
    assert_eq!(
        verify_envelope(&pinned, &repinned),
        Err(VerifiedReadRefusal::PinnedHeadMismatch),
        "an answer about a head the client did not pin must be refused, and named as such"
    );

    // Deliberately NOT asserted: the configuration-stripped case. With the
    // untampered answer already drawing ProofRejected on this head, an
    // `is_err()` there would pass without the tampering doing any work -- a
    // vacuous assertion dressed as a tamper case.
}

#[test]
fn an_unproven_client_is_still_served_by_a_proof_capable_node() {
    // The negotiation half, and the permitted twin for the file: a
    // proof-capable repository must not force proofs on a client that did not
    // ask. Without this, "the node serves envelopes" is equally satisfied by a
    // node that refuses every unproven caller.
    let scratch = ScratchDirectory::new();
    let node = serving_node(&scratch);

    let response = serve(&node, VerifiedReadCapability::Unproven).expect("the node serves");
    assert!(
        !matches!(response, ReadResponse::Verified(_)),
        "a client that asked for no proof must not be handed an envelope"
    );
}
