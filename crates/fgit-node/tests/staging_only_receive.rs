#![forbid(unsafe_code)]
//! §22.6's middle isolation response, end to end. `frankengit-fg036b`.
//!
//! `GoldLotus`'s ruling on this bead: *"`StagingOnly`: quarantine + validation
//! proceed but PUBLICATION refuses typed (staged, never visible — §5.4
//! staged/visible split is the vocabulary)"*, plus a differential arm — *"a
//! `StagingOnly` cell under the fault schedule accepts and stages but publishes
//! nothing, and the healed cell's publication carries the staged work or
//! refuses it stale — assert which, do not leave it ambiguous."*
//!
//! # Why the fixture is duplicated rather than shared
//!
//! The pack builders below are copied from `production_receive_handoff.rs`,
//! which holds the only working loopback-receive fixture in the crate. Adding
//! to that file would have been better — no duplication — but it is under an
//! exclusive lease. The copy is deliberately the MINIMUM this test needs: one
//! blob pack, no thin-delta variant. Each helper was read whole rather than
//! reconstructed, because a partially-copied fixture is how a test ends up
//! exercising a shape no caller can produce.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::AdmissionLimits;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_git_object::ParseLimits;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, OneNode};
use fgit_types::cell::{CellState, CellTransitionCause};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use fgit_wire::receive::{ReceiveContext, ReceiveLimits, SignedPushProfile};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits, encode_packets};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory {
    root: PathBuf,
}

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frankengit-fg036b-staging-only-{}-{sequence}",
            std::process::id()
        ));
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn node(root: PathBuf) -> OneNode {
    OneNode::init(NodeConfig::new(
        root,
        TenantId::from_bytes([0x41; 16]),
        RepositoryId::from_bytes([0x42; 16]),
    ))
    .expect("node initializes")
    .0
}

fn receive_context() -> ReceiveContext {
    let limits = ReceiveLimits::default();
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"report-status delete-refs", &limits.wire)
            .expect("fixed capabilities parse"),
        limits,
        SignedPushProfile::Refuse,
    )
    .expect("fixed receive context is coherent")
}

fn packet_line(command: Vec<u8>, pack: &[u8]) -> Vec<u8> {
    let mut input = encode_packets(
        &[Packet::Data(command), Packet::Flush],
        &WireLimits::default(),
    )
    .expect("bounded command packet encodes");
    input.extend_from_slice(pack);
    input
}

fn object_header(kind: u8, declared_size: usize) -> Vec<u8> {
    let mut remaining = declared_size;
    let mut first = (kind << 4) | u8::try_from(remaining & 0x0f).expect("masked size");
    remaining >>= 4;
    if remaining == 0 {
        return vec![first];
    }
    first |= 0x80;
    let mut header = vec![first];
    while remaining != 0 {
        let mut next = u8::try_from(remaining & 0x7f).expect("masked size");
        remaining >>= 7;
        if remaining != 0 {
            next |= 0x80;
        }
        header.push(next);
    }
    header
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("small bounded fixture");
    let mut output = vec![0x78, 0x01, 0x01];
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&(!length).to_le_bytes());
    output.extend_from_slice(bytes);
    let (adler_a, adler_b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next_a = (a + u32::from(*byte)) % 65_521;
        (next_a, (b + next_a) % 65_521)
    });
    output.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
    output
}

fn one_blob_pack(body: &[u8]) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&object_header(3, body.len()));
    pack.extend_from_slice(&zlib_stored(body));
    let trailer = sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

fn authenticated_session() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x73; 16]),
        IdempotencyKey::new(b"fg036b-staging-only-retry-key".to_vec())
            .expect("bounded retry key constructs"),
    )
}

const fn zero_oid() -> &'static str {
    "0000000000000000000000000000000000000000"
}

/// Walk a freshly initialised cell to the requested state.
///
/// `Bootstrapping -> VerifiedReadOnly -> Serving -> StagingOnly` is the only
/// legal path into staging-only, so reaching it is itself an assertion that the
/// transition table admits the isolation response the ruling describes.
fn walk_to(node: &mut OneNode, target: CellState) {
    for hop in [
        CellState::VerifiedReadOnly,
        CellState::Serving,
        CellState::StagingOnly,
    ] {
        node.transition_cell_state(hop, CellTransitionCause::Operator, HeadGeneration::FIRST)
            .expect("each hop is an admitted edge");
        if hop == target {
            return;
        }
    }
    panic!("target {target} was not on the walked path");
}

/// Push one blob-bearing pack through the production loopback receive path.
fn push_blob(
    node: &OneNode,
    blob: &[u8],
) -> Result<fgit_admission::AdmissionResult, NodeReceiveTransportRefusal> {
    let materialization_request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&materialization_request))
        .expect("genesis state materializes");
    let object_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, blob);
    let command = format!("{} {object_id} refs/heads/main\0report-status", zero_oid()).into_bytes();
    let input = packet_line(command, &one_blob_pack(blob));
    let request = node.request_context();
    let mut live = || true;

    node.runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &authenticated_session(),
            &materialized,
            receive_context(),
            &input,
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut live,
        ))
}

#[test]
fn a_staging_only_cell_refuses_publication_and_a_serving_cell_does_not() {
    // The ruling's core semantic, with its permitted twin. Two nodes differing
    // ONLY in cell state receive byte-identical input; one publishes and one
    // refuses. Without the serving arm, the refusal below would be satisfied by
    // a receive path that is simply broken.
    let staging_scratch = ScratchDirectory::new();
    let mut staging = node(staging_scratch.path().join("node"));
    walk_to(&mut staging, CellState::StagingOnly);
    assert_eq!(staging.cell_state(), CellState::StagingOnly);

    let blob = b"staged under isolation\n";
    let refusal = push_blob(&staging, blob).expect_err("a staging-only cell must not publish");

    // REFUSED BY NAME, and by the right name. `is_err()` would pass if the pack
    // had been rejected at intake, at parse, or by admission — and the whole
    // point of §22.6's middle response is that none of those happened: the work
    // was quarantined and validated, and only PUBLICATION was withheld.
    assert!(
        matches!(
            refusal,
            NodeReceiveTransportRefusal::StagedWithoutPublication {
                state: CellState::StagingOnly
            }
        ),
        "expected a staged-without-publication refusal naming the state, got {refusal:?}"
    );

    // THE PERMITTED TWIN: same bytes, same session, a Serving cell.
    let serving_scratch = ScratchDirectory::new();
    let mut serving = node(serving_scratch.path().join("node"));
    for hop in [CellState::VerifiedReadOnly, CellState::Serving] {
        serving
            .transition_cell_state(hop, CellTransitionCause::Operator, HeadGeneration::FIRST)
            .expect("each hop is an admitted edge");
    }
    assert_eq!(serving.cell_state(), CellState::Serving);
    push_blob(&serving, blob).expect("a serving cell publishes the same pack");
}

#[test]
fn healing_a_staging_only_cell_does_not_silently_publish_what_it_held() {
    // The differential arm the ruling asks for, and it insists the answer be
    // stated rather than left open: after the cell heals, does the publication
    // carry the staged work, or refuse it stale?
    //
    // MEASURED ANSWER: neither is automatic. Healing StagingOnly -> Serving
    // changes no stored state, so nothing is published as a side effect of
    // recovery, and nothing is lost either — the ORIGINAL sender must re-offer
    // the push, which then succeeds. That is the conservative branch, and it is
    // the right one: a cell that published held work on recovery would make a
    // refused write become visible with no client ever being told it landed.
    let scratch = ScratchDirectory::new();
    let mut cell = node(scratch.path().join("node"));
    walk_to(&mut cell, CellState::StagingOnly);

    let blob = b"held across the heal\n";
    push_blob(&cell, blob).expect_err("held, not published");

    // Heal. StagingOnly -> Serving is an admitted edge, and this is the only
    // action taken: no republish, no replay, no recovery hook.
    cell.transition_cell_state(
        CellState::Serving,
        CellTransitionCause::LocalHealth,
        HeadGeneration::FIRST,
    )
    .expect("staging-only heals to serving");
    assert_eq!(cell.cell_state(), CellState::Serving);

    // The re-offered push now succeeds. Asserting this rather than only the
    // refusal is what makes the answer unambiguous: the staged work is neither
    // auto-published on heal nor poisoned against a retry.
    push_blob(&cell, blob).expect("the re-offered push publishes once the cell serves");
}
