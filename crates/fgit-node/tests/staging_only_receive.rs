#![forbid(unsafe_code)]
//! §22.6's isolation responses on the receive path, end to end.
//! `frankengit-fg036b`.
//!
//! `GoldLotus`'s 11:32 ruling on this bead gave the middle response: *"`StagingOnly`:
//! quarantine + validation proceed but PUBLICATION refuses typed (staged, never
//! visible — §5.4 staged/visible split is the vocabulary)"*, plus a differential
//! arm — *"a `StagingOnly` cell under the fault schedule accepts and stages but
//! publishes nothing, and the healed cell's publication carries the staged work
//! or refuses it stale — assert which, do not leave it ambiguous."*
//!
//! Their 23:40 ruling, option (A), added the third: *"a node nobody brought into
//! service refuses receive intake with a typed refusal (and its permitted twin:
//! a cell walked Bootstrapping -> `VerifiedReadOnly` -> Serving admits)"*. So
//! this file now holds all three — refuse before intake, stage without
//! publishing, and serve — together, because the only way to show they are
//! three different answers is to drive byte-identical input at each of them.
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
use fgit_types::cell::{CellRefusal, CellState, CellTransitionCause};
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
/// The first two hops go through `OneNode::bring_into_service`, which is the
/// production bring-up API rather than a fixture shortcut: `Bootstrapping ->
/// VerifiedReadOnly -> Serving` is the only legal way into a staging-admitting
/// state, and driving it here means these tests exercise the same call
/// `fg import` makes. Anything past `Serving` is a genuine operator decision
/// and is recorded as one.
fn walk_to(node: &mut OneNode, target: CellState) {
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("a freshly initialised cell comes into service");
    if target != CellState::Serving {
        node.transition_cell_state(target, CellTransitionCause::Operator, HeadGeneration::FIRST)
            .expect("the operator edge into the target state is admitted");
    }
    assert_eq!(node.cell_state(), target);
}

/// Offer arbitrary bytes to the production loopback receive path.
///
/// Exists so the ORDER of the two write-side guards can be observed. A single
/// well-formed push cannot distinguish "the state gate runs before the parser"
/// from "the state gate runs after it", because a valid pack parses either
/// way. Malformed bytes make the two orders produce different refusals.
fn push_raw(
    node: &OneNode,
    input: &[u8],
) -> Result<fgit_admission::AdmissionResult, NodeReceiveTransportRefusal> {
    let materialization_request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&materialization_request))
        .expect("genesis state materializes");
    let request = node.request_context();
    let mut live = || true;

    node.runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &authenticated_session(),
            &materialized,
            receive_context(),
            input,
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut live,
        ))
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
    walk_to(&mut serving, CellState::Serving);
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

#[test]
fn a_cell_nobody_brought_into_service_refuses_receive_intake() {
    // Option (A). The cell lifecycle here is operator-driven on purpose:
    // `OneNode::init` and `open_existing` leave a cell in `Bootstrapping`, and
    // nothing in the library moves it. A node nobody put into service is
    // therefore not a node with a bug — it is a node that has not been asked to
    // carry traffic, and it must say so rather than take a push.
    let scratch = ScratchDirectory::new();
    let bootstrapping = node(scratch.path().join("node"));
    assert_eq!(bootstrapping.cell_state(), CellState::Bootstrapping);

    let blob = b"offered to a cell nobody started\n";
    let refusal = push_blob(&bootstrapping, blob)
        .expect_err("a cell that admits no staging must not take receive work in");

    // BY VARIANT, and by the variant that means "before intake". An `is_err()`
    // here is satisfied by `StagedWithoutPublication` — the §22.6 response that
    // quarantines and validates first — which is the opposite of what this gate
    // claims to do.
    assert!(
        matches!(
            refusal,
            NodeReceiveTransportRefusal::CellState(CellRefusal::StateAdmitsNoStaging {
                state: CellState::Bootstrapping
            })
        ),
        "expected a pre-intake state refusal naming Bootstrapping, got {refusal:?}"
    );

    // THE PERMITTED TWIN the ruling names explicitly: the same bytes, the same
    // session, a cell walked Bootstrapping -> VerifiedReadOnly -> Serving. This
    // is what stops the refusal above from being satisfied by a receive path
    // that is simply broken.
    let serving_scratch = ScratchDirectory::new();
    let mut serving = node(serving_scratch.path().join("node"));
    walk_to(&mut serving, CellState::Serving);
    push_blob(&serving, blob).expect("a cell brought into service publishes the same pack");
}

#[test]
fn a_verified_read_only_cell_refuses_receive_intake() {
    // §22.6's read-only isolation response, and the case that says what the
    // gate is actually keyed on. `VerifiedReadOnly` is not a start-up state:
    // this cell IS in service and IS serving verified reads. It still refuses
    // receive work, because the predicate is `admits_staging`, not "has the
    // process finished starting". Without this case the gate above would read
    // as "a node that has not booted yet", which is a different and much weaker
    // property.
    let scratch = ScratchDirectory::new();
    let mut read_only = node(scratch.path().join("node"));
    read_only
        .transition_cell_state(
            CellState::VerifiedReadOnly,
            CellTransitionCause::AuthorityObservation,
            HeadGeneration::FIRST,
        )
        .expect("Bootstrapping -> VerifiedReadOnly is an admitted edge");
    assert_eq!(read_only.cell_state(), CellState::VerifiedReadOnly);

    let refusal = push_blob(&read_only, b"offered to a read-only cell\n")
        .expect_err("a read-only cell takes no receive work in");
    assert!(
        matches!(
            refusal,
            NodeReceiveTransportRefusal::CellState(CellRefusal::StateAdmitsNoStaging {
                state: CellState::VerifiedReadOnly
            })
        ),
        "expected a pre-intake state refusal naming VerifiedReadOnly, got {refusal:?}"
    );

    // The permitted twin at the exact boundary: ONE further admitted hop, and
    // the identical offer is taken.
    read_only
        .transition_cell_state(
            CellState::Serving,
            CellTransitionCause::AuthorityObservation,
            HeadGeneration::FIRST,
        )
        .expect("VerifiedReadOnly -> Serving is an admitted edge");
    push_blob(&read_only, b"offered to a read-only cell\n")
        .expect("one hop later the same offer is taken");
}

#[test]
fn the_cell_state_gate_runs_before_a_single_byte_is_parsed() {
    // "Typed refusal BEFORE intake" is an ORDERING claim, and a single-fault
    // probe cannot see an ordering: a valid pack parses whether the state check
    // runs first or last, so every test above would pass under either order.
    //
    // Two faults that overlap make it observable. These bytes are not a
    // receive request at all. If the state gate runs first, an unserving cell
    // refuses on its STATE and never looks at them; if it ran after the parser,
    // the parser would speak first and the refusal would name the garbage.
    let malformed = b"this is not a pkt-line receive request at all";

    let scratch = ScratchDirectory::new();
    let bootstrapping = node(scratch.path().join("node"));
    let state_first =
        push_raw(&bootstrapping, malformed).expect_err("an unserving cell refuses the offer");
    assert!(
        matches!(
            state_first,
            NodeReceiveTransportRefusal::CellState(CellRefusal::StateAdmitsNoStaging {
                state: CellState::Bootstrapping
            })
        ),
        "the state gate must answer before the parser sees the bytes, got {state_first:?}"
    );

    // THE SAME BYTES at a serving cell get PAST the state gate and are refused
    // downstream instead. That is what makes the assertion above a statement
    // about ordering rather than about the input: identical input, one
    // difference in cell state, two refusals from two different stages.
    //
    // Asserted as "not the state refusal" rather than as a specific parse
    // error, deliberately. Both the quarantine validator and the pack parser
    // map into `Admission`, and which of the two speaks first is not a property
    // this test establishes -- claiming "the parser refused it" would be
    // reporting a stage I have not distinguished.
    let serving_scratch = ScratchDirectory::new();
    let mut serving = node(serving_scratch.path().join("node"));
    walk_to(&mut serving, CellState::Serving);
    let downstream =
        push_raw(&serving, malformed).expect_err("malformed bytes are refused somewhere");
    assert!(
        matches!(downstream, NodeReceiveTransportRefusal::Admission(_)),
        "a serving cell must pass the state gate and refuse downstream of it, got {downstream:?}"
    );
}

#[test]
fn authentication_is_answered_ahead_of_the_cell_state_gate() {
    // The other overlapping-fault pair, and the reason the anonymous cases in
    // `production_receive_handoff.rs` still hold: authentication and the state
    // gate are BOTH violated here — an anonymous session against a cell that
    // admits no staging — and exactly one of them may be named.
    //
    // Authentication wins, and that is the documented order: the auth check
    // retains nothing, so refusing there tells an anonymous caller the truth
    // about its session rather than leaking which state this cell happens to be
    // in. A cell's readiness is not something an unauthenticated caller has
    // asked a question worth answering about.
    let scratch = ScratchDirectory::new();
    let bootstrapping = node(scratch.path().join("node"));
    let materialization_request = bootstrapping.request_context();
    let materialized = bootstrapping
        .runtime()
        .block_on(bootstrapping.materialize_admission_in(&materialization_request))
        .expect("genesis state materializes");
    let request = bootstrapping.request_context();
    let mut live = || true;

    let refusal = bootstrapping
        .runtime()
        .block_on(bootstrapping.receive_loopback_pack_durable_in(
            &request,
            &LoopbackReceiveSession::anonymous(),
            &materialized,
            receive_context(),
            b"never parsed, and never state-checked either",
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut live,
        ))
        .expect_err("an anonymous session is refused");

    assert!(
        matches!(refusal, NodeReceiveTransportRefusal::Unauthenticated),
        "authentication must be answered before the cell-state gate, got {refusal:?}"
    );

    // The complementary case, which is what makes the assertion above a
    // statement about ORDER rather than about anonymity. Same cell, same
    // unserving state, same unparseable bytes — authenticate the session and
    // the SECOND guard becomes the one that answers.
    let state_refusal = push_raw(
        &bootstrapping,
        b"never parsed, and never state-checked either",
    )
    .expect_err("an authenticated offer still meets the state gate");
    assert!(
        matches!(
            state_refusal,
            NodeReceiveTransportRefusal::CellState(CellRefusal::StateAdmitsNoStaging {
                state: CellState::Bootstrapping
            })
        ),
        "with authentication satisfied the state gate must answer, got {state_refusal:?}"
    );
}

#[test]
fn bringing_a_cell_into_service_audits_two_hops_under_an_honest_cause() {
    // The audit is the deliverable here, not the state. §37.3 requires
    // transitions to be audited AND to enforce capability changes, and a
    // bring-up that recorded `Operator` would put an instruction in the record
    // that nobody ever gave — which is exactly what the ruling forbids.
    let scratch = ScratchDirectory::new();
    let mut cell = node(scratch.path().join("node"));
    assert!(
        cell.readiness_audit().is_empty(),
        "a freshly initialised cell has made no transitions"
    );

    cell.bring_into_service(HeadGeneration::FIRST)
        .expect("a Bootstrapping cell comes into service");

    let audit = cell.readiness_audit();
    assert_eq!(
        audit.len(),
        2,
        "Bootstrapping's only forward edge is VerifiedReadOnly, so reaching Serving is two \
         audited decisions and not one"
    );
    assert_eq!(audit[0].from(), CellState::Bootstrapping);
    assert_eq!(audit[0].to(), CellState::VerifiedReadOnly);
    assert_eq!(audit[1].from(), CellState::VerifiedReadOnly);
    assert_eq!(audit[1].to(), CellState::Serving);
    for entry in audit {
        assert_eq!(
            entry.cause(),
            CellTransitionCause::ServiceBringUp,
            "a process that started itself did not receive an operator instruction"
        );
        assert_ne!(entry.cause(), CellTransitionCause::Operator);
        assert_eq!(entry.at_generation(), HeadGeneration::FIRST);
    }

    // STRICT, NOT IDEMPOTENT, and this is the half that has teeth. A cell in
    // some other state was moved there by somebody; a bring-up that quietly
    // succeeded could walk a Draining cell back into service and the audit
    // would show a decision that contradicts the one before it.
    let repeated = cell
        .bring_into_service(HeadGeneration::FIRST)
        .expect_err("a cell already in service is not brought into service again");
    assert!(
        matches!(
            repeated,
            CellRefusal::IllegalTransition {
                from: CellState::Serving,
                to: CellState::VerifiedReadOnly
            }
        ),
        "the refusal must name the state it found, got {repeated:?}"
    );
    assert_eq!(
        cell.readiness_audit().len(),
        2,
        "a refused bring-up records nothing"
    );
}
