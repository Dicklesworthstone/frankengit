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

use fgit_authority::{AuthorityVersionToken, HeadRead, HeadReadReceipt};
use fgit_codec::DecodeLimits;
use fgit_crypto::MerkleRefusal;
use fgit_node::{NodeConfig, OneNode, VerifiedReadQuery, VerifiedReadServingRefusal};
use fgit_types::cell::{CellState, CellTransitionCause, ReadLabel};
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::numeric::HeadGeneration;
use fgit_types::refs::RefName;
use fgit_types::{RepositoryId, TenantId};
use fgit_verified_read::freshness::{FreshnessRefusal, FreshnessVerdict, HeadChainFloor};
use fgit_verified_read::{
    PinnedAuthorityHead, ReadResponse, VerifiedMembership, VerifiedReadCapability,
    VerifiedReadEnvelope, VerifiedReadRefusal, decode_verified_read_envelope,
    encode_verified_read_envelope, verify_envelope,
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

    // PERMITTED, and this one is the whole chain working end to end: the
    // server's own honest answer verifies against a client pin.
    //
    // It did NOT when this file was first committed. The genesis ref_root was
    // e8f50f4d..., an unverifiable answer, because `stage_ref_state_in`
    // computed a canonical BODY digest regardless of the layout the head
    // declared, while `EmptyState` verifies only against the empty ref-state
    // MERKLE root. I reported it without asserting either outcome, since
    // asserting Ok would have committed a red test and asserting the failure
    // would have pinned a defect as intended behaviour. `7ccaf8b`
    // ("fgit-lmc3 select ref roots by authenticated layout") added the
    // layout-aware `ref_state_root`, and the genesis root is now
    // 91d051fb... == ref_state_merkle_root(&[]). Asserted here so it stays
    // fixed.
    //
    // A real client authenticates its own head rather than trusting the served
    // one; pinning the served body grants the server every benefit of the
    // doubt, which is what makes the refusals below meaningful.
    let pinned = PinnedAuthorityHead::new(served.head().clone());
    assert_eq!(
        verify_envelope(&pinned, &served),
        Ok(VerifiedMembership::RefAbsence),
        "the server's own honest answer must verify against a client pin"
    );

    // A CLIENT IS BOTH CHECKS, NOT ONE. Review point on d89db78: nothing
    // composed HeadChainFloor with verify_envelope, so the two halves of a
    // verifying client were only ever exercised apart. The floor answers "is
    // this the moment I should be looking at" (§5.5) and verify_envelope
    // answers "is this proof valid against that moment"; a client that runs
    // only the second accepts a replayed-but-genuine answer.
    let mut floor = HeadChainFloor::anchored_to(served.head()).expect("the served head anchors");
    assert_eq!(
        floor
            .accept(served.head())
            .expect("re-offering the pinned head is permitted"),
        FreshnessVerdict::Reaffirms,
        "polling twice must be ordinary, or the floor breaks normal operation"
    );

    // TAMPERED 1: the same answer re-pointed at a head the client did not pin
    // — the mirror replaying a genuine proof from a different moment. Refused
    // before any proof is examined, so it is named rather than merely an Err.
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

    // AND THE FLOOR CATCHES IT INDEPENDENTLY, which is the point of composing
    // them. The forged head keeps the real generation and changes ref_root, so
    // it is a second distinct head claiming one generation — a fork, not
    // staleness. Asserted by name: an operator reading "stale" looks at
    // caching, one reading "forked" looks at the authority.
    assert_eq!(
        floor.judge(repinned.head()),
        Err(FreshnessRefusal::ForkedAtGeneration {
            generation: served.head().generation
        }),
        "a rival head at the pinned generation must be refused as a fork"
    );
    assert_eq!(
        floor.generation(),
        served.head().generation,
        "and a refused head must leave the floor exactly where it was"
    );

    // TAMPERED 2: the pinned head with its configuration stripped, so the
    // layout reads as legacy and admits no v1 proof.
    //
    // This case was omitted while the honest answer above still failed: an
    // is_err() would have passed without the tampering doing any work. Now
    // that the honest answer verifies, the refusal is attributable, so it is
    // asserted by NAME rather than as a bare error.
    let stripped = VerifiedReadEnvelope::new_with_exact_configuration(
        served.head().clone(),
        None,
        served.answer().clone(),
    );
    // Asserted to the exact refusal, not the family. `RefLayout(_)` would pass
    // for any layout complaint; the specific one is that a head with no carried
    // configuration reads as LegacyWholeBody, which admits no v1 proof at all.
    assert!(
        matches!(
            verify_envelope(&pinned, &stripped),
            Err(VerifiedReadRefusal::RefLayout(ref refusal))
                if matches!(**refusal, MerkleRefusal::LayoutAdmitsNoProof {
                    version: RootLayoutVersion::LegacyWholeBody
                })
        ),
        "stripping the configuration must fail as LayoutAdmitsNoProof(LegacyWholeBody)"
    );
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

#[test]
fn a_fabricated_receipt_is_refused_by_authentication_before_anything_is_materialized() {
    // `frankengit-fg036b` names this in its scope: "adversarial cells
    // (replaying old heads, fabricating receipts — authenticated verification
    // must reject)". `serve_snapshot_verified_read_in` is the production path
    // that takes a caller-supplied receipt, and its doc promises it
    // "authenticates the caller-supplied receipt before materializing it".
    //
    // That promise had no test. `authenticate_head_receipt` itself is well
    // covered (55 hits across the suite), but `SnapshotAuthentication` — the
    // refusal this serving path raises when that check fails — is produced by
    // nothing in the tree. A well-tested primitive says nothing about whether
    // a caller reached for it.
    let scratch = ScratchDirectory::new();
    let node = serving_node(&scratch);
    let request = node.request_context();

    let genuine = match node
        .runtime()
        .block_on(node.read_authority_head_in(&request))
        .expect("the genesis head reads")
    {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("a proof-capable genesis must have published a head"),
    };

    // The forgery: the real key, generation and body, with a token the store
    // never issued. This is the shape that matters — a cell that saw a genuine
    // answer and mints a token for it, rather than obviously malformed input
    // that any parser would reject.
    let forged = HeadReadReceipt::new(
        genuine.key().clone(),
        AuthorityVersionToken::from_opaque_bytes([0x5A; 16]),
        genuine.generation(),
        genuine.body().to_vec(),
    );
    assert_ne!(
        forged.token(),
        genuine.token(),
        "the forgery must differ from the issued token, or this proves nothing"
    );

    let refusal = node
        .runtime()
        .block_on(node.serve_snapshot_verified_read_in(
            &request,
            &forged,
            &RefVisibility::new(),
            ReadLabel::snapshot(),
            VerifiedReadCapability::EnvelopeV1,
            VerifiedReadQuery::Ref(
                RefName::try_new(b"refs/heads/never-created").expect("a valid ref name"),
            ),
        ))
        .expect_err("a fabricated receipt must not be served");

    // REFUSED ON AUTHENTICATION, by name. Asserting merely that it errored
    // would pass if the forgery were caught later — during materialization, or
    // by the proof failing to verify — and the whole point of the documented
    // ordering is that nothing is materialized for an unauthenticated pin.
    assert!(
        matches!(
            refusal,
            VerifiedReadServingRefusal::SnapshotAuthentication(_)
        ),
        "a forged token must be refused by authentication, not downstream: {refusal:?}"
    );

    // THE PERMITTED TWIN. The genuine receipt is served, so the refusal above
    // is attributable to the forgery and not to this path refusing everything
    // — the snapshot mode, the cell state and the query are all identical.
    node.runtime()
        .block_on(node.serve_snapshot_verified_read_in(
            &request,
            &genuine,
            &RefVisibility::new(),
            ReadLabel::snapshot(),
            VerifiedReadCapability::EnvelopeV1,
            VerifiedReadQuery::Ref(
                RefName::try_new(b"refs/heads/never-created").expect("a valid ref name"),
            ),
        ))
        .expect("the authentic receipt is served");
}

#[test]
fn a_relayed_envelope_crosses_the_wire_and_the_client_runs_both_checks_on_the_decoded_form() {
    // The last half of BlackOx's d89db78 item: "no serialized proxy/product-client
    // boundary composes HeadChainFloor with verify_envelope."
    //
    // It was not constructible when reported — a verified read had no wire form
    // anywhere in the workspace. `frankengit-ptoe` (bdd7752) added one, and its
    // own wire.rs covers encode/decode, relay parsing and hostile bytes. What it
    // does not cover is the FRESHNESS half: `grep HeadChainFloor` in that file
    // returns zero. So the two client checks still met only on in-process
    // values, never on bytes.
    //
    // This closes the chain end to end: real node -> production serve -> canonical
    // encode -> independent decode -> floor AND verifier, on the decoded form.
    let scratch = ScratchDirectory::new();
    let node = serving_node(&scratch);

    let response = serve(&node, VerifiedReadCapability::EnvelopeV1).expect("the node serves");
    let ReadResponse::Verified(served) = response else {
        panic!("a proof-capable node served an unproven response to an EnvelopeV1 client");
    };

    // THE WIRE HOP. From here on the client touches only bytes and what it
    // decodes from them; the server-side object is dropped so nothing downstream
    // can accidentally consult it.
    let relay_bytes = encode_verified_read_envelope(&served).expect("the answer encodes");
    let pinned = PinnedAuthorityHead::new(served.head().clone());
    drop(served);

    let decoded = decode_verified_read_envelope(&relay_bytes, DecodeLimits::DEFAULT)
        .expect("a client decodes canonical relay bytes");

    // BOTH CHECKS, on the decoded form. Freshness first: it answers "is this the
    // moment I should be looking at", and a client that skips it accepts a
    // replayed-but-genuine answer no proof check can reject.
    let mut floor = HeadChainFloor::anchored_to(decoded.head()).expect("the decoded head anchors");
    assert_eq!(
        floor
            .accept(decoded.head())
            .expect("re-offering the decoded head is permitted"),
        FreshnessVerdict::Reaffirms
    );
    assert_eq!(
        verify_envelope(&pinned, &decoded),
        Ok(VerifiedMembership::RefAbsence),
        "an answer that crossed the wire must still verify against the client's own pin"
    );

    // AND THE FLOOR STILL DISCRIMINATES AFTER THE ROUND TRIP. A rival head at
    // the same generation, rebuilt from the decoded value, is a fork rather than
    // staleness — proving the freshness check survived encoding rather than
    // being satisfied by whatever the wire happened to carry.
    let mut rival_head = decoded.head().clone();
    rival_head.ref_root = digest(0xC3);
    assert_eq!(
        floor.judge(&rival_head),
        Err(FreshnessRefusal::ForkedAtGeneration {
            generation: decoded.head().generation
        }),
        "a rival head at the pinned generation must be refused as a fork after decoding"
    );
}
