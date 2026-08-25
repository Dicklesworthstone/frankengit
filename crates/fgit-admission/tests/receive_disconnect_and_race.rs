#![forbid(unsafe_code)]
//! FG-019c acceptance lines 2 and 3, at the layer that can actually answer them.
//!
//! Independent adversary over `fgit-admission`, which this file does not own.
//! Nothing here
//! modifies `crates/fgit-admission/src/**`; every probe drives the public API.
//!
//! ## What the wire layer could not decide, and why this file exists
//!
//! The structural half of the disconnect matrix lives in
//! `crates/fgit-wire/tests/receivepack_adversarial.rs`: cancel at each
//! checkpoint, assert `Err(Cancelled)`, phase `Refused`, quarantine empty.
//! The wire owner was explicit that the machine stops there — it has no
//! `TxId` and no outcome-discovery surface, so "leaves no seal, a retryable
//! seal, or a terminal outcome" is not a question it can be asked.
//!
//! `fgit-admission` can be asked, because a disconnect there is an *authority*
//! event: `admit_validated_receive` seals, evaluates, and publishes through the
//! exact-head CAS, and `fgit_authority::resolve_outcome` reads the authenticated
//! decision stream. The three permitted post-disconnect states are therefore
//! literally three values of one function, which is what makes the acceptance
//! line decidable rather than rhetorical:
//!
//! | acceptance wording   | decided by                                    |
//! |----------------------|-----------------------------------------------|
//! | "no seal"            | no `TxId` was ever minted                     |
//! | "a retryable seal"   | `OutcomeLookup::Undecided` (§5.3, by name)    |
//! | "a terminal outcome" | `OutcomeLookup::Decided(_)`                   |
//! | *stuck intermediate* | `Err(OutcomeFailure)` — cannot answer at all  |
//!
//! The fourth row is the one the bead forbids, and it is a real reachable
//! state, not a straw man: `reconcile_outcome` fails closed when the
//! accelerator and the authenticated stream disagree, because preferring
//! either side would make the accelerator a second source of truth. A
//! transaction in that state can be neither retried nor reported.
//!
//! ## The adapters here are NOT conforming projections, and that bounds this file
//!
//! An earlier version of this file argued that quantifying over several
//! *conforming* projections made its results independent of any one of them.
//! **The crate owner refuted that and the argument is withdrawn.** Two defects:
//!
//! * [`UnboundAdapter::snapshot`] ignores both the `PublicationBasis` and the
//!   `AuthenticatedHead` it is handed. The trait requires a projection "rooted
//!   in exactly this authenticated head" and forbids a local ref table as the
//!   basis for a decision; a fixed map returned regardless of which head was
//!   asked about is that forbidden shape.
//! * `materialize_commit` mints roots from seed bytes, derived from nothing.
//!
//! I also claimed `validate_commit_materialization` meant "admission does not
//! trust the projection". **Overstated.** It binds *identity* — `tx_id`,
//! request digest, closure root — and checks the record is self-consistent
//! with the roots supplied beside it. It cannot check that those roots describe
//! the projection's state, so it does not cure the missing head-binding.
//!
//! Three unbound adapters are three variants of *one* unbound adapter, so
//! quantifying over them buys nothing about ref semantics. Every claim that
//! rested on ref state, or on one session observing the successor basis, is
//! withdrawn. What survives never depended on the adapter: **faults are
//! injected in the store, below it entirely**, and the assertions are about
//! whether a transaction can be *resolved* and whether it is *decided once* —
//! never about what was decided.
//!
//! ## Non-claims, stated so nothing here is later cited as more than it is
//!
//! * **This is a bounded-model result, not an invariant.** It ranges over the
//!   fault directives in [`directives`], crossed with every operation position
//!   a clean admission reaches. It does not quantify over all schedules.
//! * **Acceptance line 3 now has four probes, and this note has been wrong
//!   twice.** It first said the line needed a head-bound projection, after that
//!   projection already existed; it then said a CONCURRENT schedule was
//!   impossible because `StagingStore` held an `Rc`, after that double had been
//!   converted. Both readings are dead. What is actually covered:
//!   [`two_sessions_deleting_one_ref_yield_exactly_one_commit_and_a_typed_loser`]
//!   (deterministic order, typed loser),
//!   [`two_concurrent_sessions_deleting_one_ref_yield_exactly_one_commit`]
//!   (real threads, interleaving measured),
//!   [`a_scheduled_push_race_forces_the_stale_cas_window_and_still_yields_one_winner`]
//!   (`fgit-lab`, worst window forced by construction), and
//!   [`a_basis_bound_loser_is_refused_authority_receipt_stale_not_expected_old_ref_mismatch`]
//!   (the production entrypoint's own loser status). A note that goes stale
//!   behind its own fixes is worse than none, so it names the probes rather
//!   than describing a gap.
//! * **No adapter here is the production projection**, so no ref-policy
//!   question — whether a losing push is refused `ExpectedOldRefMismatch` or
//!   permitted — is answered.
//! * **Backend applicability: every result here is against
//!   [`MemoryAuthorityStore`], the reference backend, and says nothing about
//!   `FsqliteAuthorityStore`, which is the production one.** No *exported*
//!   faultable production backend exists: `FaultableAuthorityStore` has one
//!   implementor in `src` (`MemoryAuthorityStore`). A per-crate test-local
//!   wrapper is the established workaround — `fgit-authority-fsqlite`'s own
//!   `fault_conformance.rs` implements the trait for a `FaultingStore` defined
//!   inside that test file — but a `tests/` item in another crate is not a
//!   surface this corpus can import. So "no disconnect leaves a stuck
//!   intermediate" is a statement about the reference implementation of the
//!   authority contract. The production backend has its own crash suite and its
//!   own applicability limits.
//! * Hidden-ref probes remain unwritten and unwritable:
//!   `RefusalCode::HiddenRefUnauthorized` (0x0206) is defined in `fgit-types`
//!   and classified in `fgit-reference` but produced by nothing in the tree.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use std::sync::{Arc, Mutex};

use fgit_lab::{LabSchedule, StepCursor, StepId};

use fgit_admission::{
    AdmissionContext, AdmissionEvidence, AdmissionLimits, AdmissionProjection, AdmissionSnapshot,
    AdmissionSnapshotProjection, CanonicalAdmissionProjection, CanonicalAdmissionStore,
    CanonicalRefState, CommitEvidence, CommitMaterialization, PermittedObjectClosure,
    ProjectionFailure, QuarantineValidator, RefusalMaterialization, ValidatedClosure,
    ValidatedReceive, admit_basis_bound_validated_receive, admit_validated_receive,
    canonical_ref_state_root, permitted_object_closure_root, validate_receive,
    validate_receive_at_basis,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, DuplicateDelivery, FaultDirective, FaultKind, FaultPosition,
    FaultableAuthorityStore, HeadKey, HeadRead, IdempotencyKey, MemoryAuthorityStore, OpIndex,
    OutcomeFailure, OutcomeLookup, StoreInstanceId, TerminalOutcome, initialize_repository,
    reconcile_outcome, resolve_outcome,
};
use fgit_chronicle::{PublicationBasis, ResultingRoots};
use fgit_codec::attest::body_id;
use fgit_codec::bridge::CryptoBodyIdentity;
use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryCommitRecord};
use fgit_reference::effect::FoldOutcome;
use fgit_reference::intent::{
    ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey, RetentionRoot, TransactionRequest,
};
use fgit_txn::TransactionFoldReport;
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitOid, HeadGeneration, PolicyEpoch,
    PrincipalId, PrincipalSnapshotId, RefName, RefusalCode, RegistryEpoch, RepositoryId,
    RepositorySequence, TenantId, TxId,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveEvent, ReceiveLimits, ReceivePack, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const MAIN_OID: &str = "2222222222222222222222222222222222222222";
const MAIN_REF: &[u8] = b"refs/heads/main";

fn live_deadline() -> impl FnMut() -> bool {
    || true
}

type ForgeMap = BTreeMap<ForgeStreamId, ForgeStreamPosition>;
type OutboxMap = BTreeMap<OutboxDeliveryKey, Digest>;
type RetentionSet = BTreeSet<RetentionRoot>;

// ---------------------------------------------------------------------------
// The unbound adapters
// ---------------------------------------------------------------------------

/// A conforming [`AdmissionProjection`] that is deliberately not the production
/// one.
///
/// Members differ in ref state, in every digest they mint (via `seed`), and in
/// whether they permit a commit at all. Nothing asserted in this file may
/// depend on which member produced it.
#[derive(Clone)]
struct UnboundAdapter {
    label: &'static str,
    refs: BTreeMap<RefName, GitOid>,
    forge_positions: ForgeMap,
    retention: RetentionSet,
    outbox: OutboxMap,
    /// When set, `materialize_commit` refuses, so a folded transaction still
    /// reaches a terminal *refusal* rather than a commit.
    commit_refusal: Option<RefusalCode>,
    hidden_refs: fgit_wire::visibility::RefVisibility,
    seed: u8,
}

impl UnboundAdapter {
    const fn new(label: &'static str, seed: u8) -> Self {
        Self {
            label,
            refs: BTreeMap::new(),
            forge_positions: ForgeMap::new(),
            retention: RetentionSet::new(),
            outbox: OutboxMap::new(),
            commit_refusal: None,
            hidden_refs: fgit_wire::visibility::RefVisibility::new(),
            seed,
        }
    }

    /// A projection whose basis already carries `refs/heads/main`.
    fn with_main(label: &'static str, seed: u8) -> Self {
        let mut member = Self::new(label, seed);
        member.refs.insert(
            RefName::try_new(MAIN_REF).expect("fixture ref name"),
            oid(MAIN_OID),
        );
        member
    }

    const fn refusing_commit(mut self, code: RefusalCode) -> Self {
        self.commit_refusal = Some(code);
        self
    }

    /// Publishes a hide rule through the snapshot this projection returns, so
    /// the admission path sees a non-empty visibility policy.
    fn hiding(mut self, rule: &[u8]) -> Self {
        self.hidden_refs
            .push_rule(rule, &fgit_wire::WireLimits::default())
            .expect("a fixture hide rule is valid");
        self
    }
}

impl AdmissionSnapshotProjection for UnboundAdapter {
    fn snapshot(
        &self,
        _basis: &PublicationBasis,
        _authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        Ok(AdmissionSnapshot {
            refs: self.refs.clone(),
            forge_positions: self.forge_positions.clone(),
            retention: self.retention.clone(),
            outbox: self.outbox.clone(),
            hidden_refs: self.hidden_refs.clone(),
            ..AdmissionSnapshot::default()
        })
    }
}

impl AdmissionProjection for UnboundAdapter {
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        if let Some(code) = self.commit_refusal {
            return Err(ProjectionFailure::Refuse(code));
        }
        if !matches!(fold.outcome, FoldOutcome::Folded(_)) {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ConflictingSemanticEffects,
            ));
        }
        // `005fd92` made admission validate these carried-forward roots against
        // the authenticated basis. This fixture is deliberately ref-only, so
        // it must continue that basis rather than minting forge, retention, or
        // outbox roots from `seed`; otherwise every fault-free probe refuses
        // before it reaches the disconnect/race behavior under test.
        let roots = ResultingRoots {
            ref_root: self.digest(2),
            forge_position_root: basis.body().forge_position_root,
            retention_root: basis.body().retention_root,
            outbox_root: basis.body().outbox_root,
            policy_epoch: basis.body().policy_epoch,
            compaction_generation_link: None,
        };
        Ok(CommitMaterialization {
            record: RepositoryCommitRecord {
                repository_id: request.repository,
                repository_sequence: RepositorySequence::FIRST,
                parent_rcr_id: None,
                tx_id: request.tx_id,
                principal_snapshot_id: principal_snapshot(),
                canonical_request_digest: request.canonical_request_digest,
                ref_delta_root: self.digest(7),
                resulting_ref_root: roots.ref_root,
                object_closure_root: closure.object_closure_root,
                forge_event_batch_root: self.digest(8),
                resulting_forge_position_root: roots.forge_position_root,
                policy_epoch: roots.policy_epoch,
                policy_decision_root: self.digest(9),
                invariant_evidence_root: self.digest(10),
                outbox_effect_root: self.digest(11),
                retention_delta_root: self.digest(12),
            },
            roots,
        })
    }

    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        _tx_id: TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: format!("{} policy refusal", self.label),
            evidence_root: self.digest(13),
        })
    }
}

impl UnboundAdapter {
    fn digest(&self, offset: u8) -> Digest {
        digest(self.seed.wrapping_add(offset))
    }
}

/// The adapters the store-level probes are driven through.
///
/// They take different routes through `admit_one`, which is useful for
/// exercising the publication paths beneath them. It is **not** an independence
/// argument: they are three variants of one unbound adapter, so agreement
/// between them is not evidence about projection semantics.
///
/// The three differ in starting ref table and in whether a folded transaction
/// may commit, so they drive genuinely different paths
/// through `admit_one`: commit-and-publish, fold-abort-and-refuse, and
/// materializer-refuse-and-publish-refusal.
fn adapters() -> Vec<UnboundAdapter> {
    vec![
        UnboundAdapter::with_main("main-present", 0x20),
        UnboundAdapter::new("main-absent", 0x50),
        UnboundAdapter::with_main("commit-refused", 0x80)
            .refusing_commit(RefusalCode::ProtectedRefTransitionDenied),
    ]
}

// ---------------------------------------------------------------------------
// Fixtures, built only from public API
// ---------------------------------------------------------------------------

fn digest(seed: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[seed; 32]).expect("32-byte corpus fixture body"),
    )
}

fn principal_snapshot() -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        fgit_types::CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[15; 32]).expect("32-byte corpus fixture body"),
    )
}

fn oid(hex: &str) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha1, hex).expect("fixture oid")
}

fn context(session: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/fg019c-disconnect".to_vec()).expect("valid head key"),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(session.to_vec()).expect("bounded key"),
        object_format: GitObjectFormat::Sha1,
    }
}

fn genesis(context: &AdmissionContext) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(16),
        outcome_index_root: digest(17),
        retention_root: digest(18),
        outbox_root: digest(19),
        configuration_root: digest(20),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn store_with_genesis(context: &AdmissionContext) -> MemoryAuthorityStore {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(19));
    initialize_repository(&store, &context.head_key, &genesis(context))
        .expect("genesis head initializes");
    store
}

/// A validator that reports the closure it was told to.
///
/// `QuarantineValidator` is a public trait whose own documentation says the
/// real implementation "belongs beside the pack/object store; this crate never
/// parses a pack". Implementing it in a test uses the seam as intended. Every
/// session below is delete-only, so the closure is legitimately empty and this
/// stub makes no claim about pack contents at all.
struct DeleteOnlyValidator;

impl QuarantineValidator for DeleteOnlyValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
        _deadline: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        // The root must be the CANONICAL root of the closure this validator
        // declares, not an arbitrary digest. `materialize_commit` recomputes
        // `permitted_object_closure_root` over `objects` and refuses
        // `ObjectClosureIncomplete` when the two disagree — so `digest(14)`
        // beside an empty set made every production-projection admission refuse,
        // which is the second reason the head-bound race probe was vacuous. The
        // unbound adapters never caught it because they mint roots instead of
        // checking them.
        let objects = BTreeSet::new();
        let object_closure_root =
            permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone()))?;
        Ok(ValidatedClosure {
            object_closure_root,
            objects,
        })
    }
}

fn wire_context() -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"delete-refs report-status atomic", &WireLimits::default())
            .expect("fixture capabilities"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("fixture receive context")
}

/// A delete of `refs/heads/main`, parsed by the real wire state machine.
///
/// Built through `ReceivePack` rather than by assembling a `ReceiveRequest`
/// literal, so the admission layer sees a request the wire layer would actually
/// produce. Delete-only is deliberate: it is the documented path that needs no
/// pack, which keeps a fabricated pack out of a corpus about authority
/// sequencing.
fn delete_main_request() -> ReceiveRequest {
    let mut line = format!("{MAIN_OID} {ZERO} {}", String::from_utf8_lossy(MAIN_REF)).into_bytes();
    line.push(0);
    line.extend_from_slice(b"report-status delete-refs atomic");

    let mut machine = ReceivePack::new(wire_context()).expect("machine");
    machine
        .push_packet(Packet::Data(line))
        .expect("delete command must parse");
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    (**request).clone()
}

fn delete_main() -> ValidatedReceive {
    let request = delete_main_request();
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    validate_receive(
        &request,
        None,
        &receipt,
        &DeleteOnlyValidator,
        &mut live_deadline(),
    )
    .expect("a delete-only receive is admissible without a pack")
}

// ---------------------------------------------------------------------------
// The classifier the acceptance line is really about
// ---------------------------------------------------------------------------

/// Where one transaction stands after a disconnect, as the authenticated
/// decision stream reports it.
///
/// The acceptance line names three permitted states — "no seal, a retryable
/// seal, or a terminal outcome". **At this layer the first two are one answer,
/// and that is the correct reading rather than a gap in the corpus.**
/// `resolve_outcome` returns `Undecided` both for a transaction that was never
/// sealed and for one sealed before publication, and §5.3 names `Undecided` as a
/// real answer rather than an error. The client action is identical in both
/// cases — retry with the same idempotency key, which re-derives the same
/// identity — so nothing a caller may do depends on telling them apart. An
/// earlier draft of this enum carried a separate `NoSeal` arm that no code path
/// could ever produce; it is removed rather than left to imply coverage that
/// does not exist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Standing {
    /// `Undecided`: no seal, or a seal with no decision yet. Retryable (§5.3).
    Retryable,
    /// One authenticated terminal decision.
    Terminal,
    /// The forbidden state: resolution cannot answer at all.
    Stuck,
}

/// Classifies a transaction from the authenticated decision stream.
///
/// `Stuck` is produced by an `Err` from resolution, never by a missing record:
/// a missing record is `Undecided`, which is retryable and permitted.
fn standing(store: &MemoryAuthorityStore, context: &AdmissionContext, tx_id: TxId) -> Standing {
    match resolve_outcome(
        store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    ) {
        Ok(OutcomeLookup::Decided(_)) => Standing::Terminal,
        Ok(OutcomeLookup::Undecided) => Standing::Retryable,
        Err(_) => Standing::Stuck,
    }
}

/// The `TxId` a session seals, derived the way admission derives it.
///
/// Taken from a clean, fault-free run so that a faulted run can be interrogated
/// for the *same* identity. This is legitimate because the identity is a pure
/// function of the sealed request and the session idempotency key — it does not
/// depend on whether the faulted run got far enough to publish anything.
fn session_tx_id(
    context: &AdmissionContext,
    validated: &ValidatedReceive,
    member: &UnboundAdapter,
) -> TxId {
    let store = store_with_genesis(context);
    admit_validated_receive(
        &store,
        context,
        validated,
        AdmissionLimits::default(),
        member,
    )
    .expect("a fault-free admission reaches a terminal decision")
    .session
    .tx_ids[0]
}

/// How many store operations a clean admission reaches.
///
/// Discovered rather than assumed, so the fault matrix covers every position
/// the real call sequence visits instead of a hand-guessed prefix.
fn clean_operation_span(
    context: &AdmissionContext,
    validated: &ValidatedReceive,
    member: &UnboundAdapter,
) -> u64 {
    let store = store_with_genesis(context);
    let before = store.operations_started();
    admit_validated_receive(
        &store,
        context,
        validated,
        AdmissionLimits::default(),
        member,
    )
    .expect("a fault-free admission reaches a terminal decision");
    store.operations_started() - before
}

/// The disconnect corpus: one directive per way a push can be interrupted.
fn directives() -> Vec<(&'static str, FaultKind)> {
    vec![
        ("lost-request", FaultKind::LoseRequest),
        ("lost-response", FaultKind::LoseResponse),
        (
            "crash-before-effect",
            FaultKind::Crash {
                position: FaultPosition::BeforeEffect,
            },
        ),
        (
            "crash-after-effect",
            FaultKind::Crash {
                position: FaultPosition::AfterEffect,
            },
        ),
        (
            "duplicate-delivering-first",
            FaultKind::DuplicateRequest {
                deliver: DuplicateDelivery::First,
            },
        ),
        (
            "duplicate-delivering-second",
            FaultKind::DuplicateRequest {
                deliver: DuplicateDelivery::Second,
            },
        ),
        ("throttle", FaultKind::Throttle),
    ]
}

// ---------------------------------------------------------------------------
// Acceptance line 2: the disconnect matrix
// ---------------------------------------------------------------------------

/// Every interruption, at every operation a push reaches, leaves the
/// transaction in one of the three permitted states — never stuck.
///
/// This is the acceptance line stated as an executable predicate. The matrix is
/// projection × directive × operation position, and the assertion is the same
/// for all of them, which is the point: the permitted-state set is a property
/// of authority sequencing, not of what any projection decided.
#[test]
fn every_disconnect_at_every_phase_leaves_a_resolvable_transaction() {
    let context = context(b"fg019c-disconnect-session");
    let validated = delete_main();
    let mut examined = 0_usize;
    let mut observed = BTreeSet::new();
    let mut undelivered: Vec<String> = Vec::new();

    for member in adapters() {
        let tx_id = session_tx_id(&context, &validated, &member);
        let span = clean_operation_span(&context, &validated, &member);
        assert!(
            span > 1,
            "{}: a push must reach more than one store operation for the matrix to mean anything, saw {span}",
            member.label
        );

        for (name, kind) in directives() {
            for position in 0..span {
                let store = store_with_genesis(&context);
                store.install_fault_plan(fgit_authority::FaultPlan::explicit(vec![
                    FaultDirective::new(OpIndex::from_raw(position), kind),
                ]));

                // The call may succeed or fail; a disconnect is allowed to be
                // visible to the caller. What it may not do is leave a seal
                // that nobody can resolve.
                let _ = admit_validated_receive(
                    &store,
                    &context,
                    &validated,
                    AdmissionLimits::default(),
                    &member,
                );

                // A crashed endpoint refuses every later read, including the
                // one that resolves the outcome. Restarting is the operator
                // action the acceptance line presumes: the question is what
                // the store holds, not whether it is currently reachable.
                store.restart();

                // FAULT-DELIVERY WITNESS. Without this the matrix cannot tell
                // "the fault fired and the transaction stayed resolvable" from
                // "the fault never fired at all" — a directive that selected
                // nothing would leave every admission clean, every cell
                // non-stuck, and the whole matrix green while testing nothing.
                //
                // Every directive here is `FaultDirective::new`, which leaves
                // `applies_to` as `None`: an UNFILTERED directive that must fire
                // on whatever operation kind occupies its position. That is
                // exactly the arm `FaultDirective::selects` handles by falling
                // through its `is_some_and` guard, and the arm least exercised
                // by suites that build directives with `only_for`.
                if store.fault_log().is_empty() {
                    undelivered.push(format!("{} / {name} at op {position}", member.label));
                }

                let standing = standing(&store, &context, tx_id);
                assert_ne!(
                    standing,
                    Standing::Stuck,
                    "{} / {name} at op {position}: transaction {tx_id:?} is a stuck intermediate",
                    member.label
                );
                observed.insert(standing);
                examined += 1;
            }
        }
    }

    assert!(
        examined >= 60,
        "the matrix must actually be a matrix; only {examined} cells ran"
    );
    // Non-vacuity, as two separate requirements rather than one count. A corpus
    // in which every cell reached a terminal decision would prove the injected
    // faults never interrupted anything; a corpus in which none did would prove
    // the push never got as far as deciding. Both must occur or the matrix is
    // asserting the absence of a state it never had a chance to reach.
    assert!(
        observed.contains(&Standing::Terminal),
        "no cell reached a terminal decision, so the corpus never gets past sealing: {observed:?}"
    );
    assert!(
        observed.contains(&Standing::Retryable),
        "no cell was left retryable, so no injected fault actually interrupted a push: {observed:?}"
    );
    // Every position in the matrix is one a clean admission demonstrably
    // reaches, so an unfiltered directive placed there must be delivered. A cell
    // that recorded no fault means the directive selected nothing — the failure
    // this witness exists to make loud rather than green.
    assert!(
        undelivered.is_empty(),
        "{} of {examined} cells injected a directive that never fired, so those cells \
         asserted resolvability of an UNFAULTED push: {undelivered:?}",
        undelivered.len()
    );
}

/// The fault-delivery witness can distinguish a delivered fault from an
/// undelivered one.
///
/// The matrix above asserts that **every** cell delivered its directive. That
/// is an absence assertion — "no cell went unfaulted" — and it is only worth
/// something if `fault_log()` would actually come back empty when a directive
/// selects nothing. This pairs the two cases over one session:
///
/// * an **unfiltered** directive (`applies_to == None`) at a position a clean
///   admission demonstrably reaches must fire;
/// * the same kind of directive parked past the end of the operation sequence
///   must not.
///
/// The first half is the load-bearing one for `FaultDirective::selects`, whose
/// `applies_to` guard falls through for `None`. Suites that build directives
/// with `only_for` never exercise that arm; this corpus only ever builds
/// unfiltered ones, so it is the arm it exercises most.
#[test]
fn an_unfiltered_directive_fires_where_it_lands_and_nowhere_else() {
    let context = context(b"fg019c-fault-delivery");
    let validated = delete_main();
    let member = UnboundAdapter::with_main("commits", 0x20);
    let span = clean_operation_span(&context, &validated, &member);
    assert!(span > 1, "the span must be a real sequence, saw {span}");

    // Reachable: an unfiltered directive on the first operation.
    let delivered = {
        let store = store_with_genesis(&context);
        store.install_fault_plan(fgit_authority::FaultPlan::explicit(vec![
            FaultDirective::new(OpIndex::from_raw(0), FaultKind::LoseResponse),
        ]));
        let _ = admit_validated_receive(
            &store,
            &context,
            &validated,
            AdmissionLimits::default(),
            &member,
        );
        store.restart();
        store.fault_log().len()
    };
    assert!(
        delivered > 0,
        "an unfiltered directive on operation 0 was never delivered, so \
         FaultDirective::selects no longer fires for applies_to == None"
    );

    // Unreachable: the same directive parked well past the last operation.
    let not_delivered = {
        let store = store_with_genesis(&context);
        store.install_fault_plan(fgit_authority::FaultPlan::explicit(vec![
            FaultDirective::new(OpIndex::from_raw(span + 50), FaultKind::LoseResponse),
        ]));
        let _ = admit_validated_receive(
            &store,
            &context,
            &validated,
            AdmissionLimits::default(),
            &member,
        );
        store.restart();
        store.fault_log().len()
    };
    assert_eq!(
        not_delivered, 0,
        "a directive parked past the end of the sequence was delivered anyway, so an \
         empty fault log does not mean what the matrix reads it to mean"
    );
}

/// The `Stuck` arm is reachable and the classifier recognises it.
///
/// Without this the matrix above would be the classic false green: an assertion
/// that cannot fail in the direction that matters. It does not synthesise a
/// fake state — it drives the real, exported `reconcile_outcome`, whose
/// documented job is to fail closed when the accelerator and the authenticated
/// stream disagree, and shows that the failure it returns is exactly what
/// [`standing`] classifies as stuck.
#[test]
fn a_transaction_that_cannot_be_resolved_is_classified_stuck() {
    let indexed = OutcomeLookup::Decided(TerminalOutcome {
        decision_sequence: fgit_types::DecisionSequence::FIRST,
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id: fgit_types::RefusalRecordId::from_digest(
                DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                    .expect("nonzero corpus fixture algorithm slot"),
                fgit_types::CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[41; 32]).expect("32-byte corpus fixture body"),
            ),
        },
    });
    let replayed = OutcomeLookup::Decided(TerminalOutcome {
        decision_sequence: fgit_types::DecisionSequence::FIRST,
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::ProtectedRefTransitionDenied,
            refusal_record_id: fgit_types::RefusalRecordId::from_digest(
                DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                    .expect("nonzero corpus fixture algorithm slot"),
                fgit_types::CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[42; 32]).expect("32-byte corpus fixture body"),
            ),
        },
    });

    // `is_err()` alone would not say *why* it failed. `OutcomeFailure` has
    // several variants, so a future validation step that rejected these inputs
    // for an unrelated reason — a malformed refusal record, say — would keep
    // this test green while it silently stopped testing conflict detection at
    // all. Today `AcceleratorConflict` is the only reachable `Err` arm for two
    // `Decided` inputs, but that is a property of the current implementation,
    // not of this assertion, which is exactly the gap worth closing.
    let conflict = reconcile_outcome(indexed, replayed);
    let Err(OutcomeFailure::AcceleratorConflict {
        indexed: reported_indexed,
        replayed: reported_replayed,
    }) = conflict
    else {
        panic!(
            "an accelerator that disagrees with the stream must fail closed as \
             AcceleratorConflict, not pick a side; got {conflict:?}"
        );
    };

    // And the failure must name the disagreement it actually saw, rather than
    // reporting some other pair — which is what makes it actionable to a
    // repair path instead of a bare "something was inconsistent".
    assert_eq!(
        OutcomeLookup::Decided(*reported_indexed),
        indexed,
        "the conflict names an indexed outcome that is not the one supplied"
    );
    assert_eq!(
        OutcomeLookup::Decided(*reported_replayed),
        replayed,
        "the conflict names a replayed outcome that is not the one supplied"
    );
    // The permitted twin: agreement resolves, so the arm above is a genuine
    // discrimination rather than a resolver that refuses everything.
    assert_eq!(
        reconcile_outcome(indexed, indexed),
        Ok(indexed),
        "agreeing reads must resolve"
    );
}

/// A push whose decision landed while the caller was left ambiguous is not
/// decided a second time when the client retries.
///
/// This is the §5.2 property on the push path. `LoseResponse` is the exact
/// shape: the effect linearizes and the caller never learns, so the client
/// retries with the same idempotency key and therefore the same identity. The
/// retry must *discover* the existing decision rather than make a new one —
/// which is why `admit_one` consults `resolve_outcome` before re-planning.
///
/// The comparison is against the authenticated decision stream, not against
/// what the first call returned. That is forced rather than chosen: under a
/// lost response the caller is never answered, so "what the caller saw" does
/// not exist. An earlier version of this test compared the two return values
/// and passed while that comparison ran in **zero** cells; the counters below
/// exist because that failure is invisible without them.
#[test]
fn a_decision_that_landed_during_a_lost_response_is_not_decided_twice() {
    let context = context(b"fg019c-retry-session");
    let validated = delete_main();
    let mut retried = 0_usize;
    let mut landed = 0_usize;
    let mut pending = 0_usize;

    for member in adapters() {
        let tx_id = session_tx_id(&context, &validated, &member);
        let span = clean_operation_span(&context, &validated, &member);

        for position in 0..span {
            let store = store_with_genesis(&context);
            store.install_fault_plan(fgit_authority::FaultPlan::explicit(vec![
                FaultDirective::new(OpIndex::from_raw(position), FaultKind::LoseResponse),
            ]));

            // The caller is left ambiguous by construction; its return value is
            // deliberately unused.
            let _ambiguous = admit_validated_receive(
                &store,
                &context,
                &validated,
                AdmissionLimits::default(),
                &member,
            );
            store.restart();
            store.install_fault_plan(fgit_authority::FaultPlan::none());

            // What actually landed, read before the retry so the retry cannot
            // be the thing that produced it.
            let before_retry = resolve_outcome(
                &store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} / lost-response at op {position}: {tx_id:?} became unresolvable: {error}",
                    member.label
                )
            });

            // The retry: identical session, same idempotency key, same TxId.
            let retry = admit_validated_receive(
                &store,
                &context,
                &validated,
                AdmissionLimits::default(),
                &member,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} / lost-response at op {position}: a retry after a lost response must reach a decision, got {error}",
                    member.label
                )
            });

            assert_eq!(
                retry.session.tx_ids,
                vec![tx_id],
                "{} / lost-response at op {position}: the retry sealed a different transaction",
                member.label
            );

            match before_retry {
                OutcomeLookup::Decided(terminal) => {
                    landed += 1;
                    assert_eq!(
                        retry.commands[0].terminal, terminal,
                        "{} / lost-response at op {position}: a decision had already landed and the retry decided again",
                        member.label
                    );
                }
                OutcomeLookup::Undecided => pending += 1,
            }

            // Idempotency does not depend on having observed anything: a third
            // drive must agree with the second.
            let again = admit_validated_receive(
                &store,
                &context,
                &validated,
                AdmissionLimits::default(),
                &member,
            )
            .expect("a settled transaction resolves");
            assert_eq!(
                retry.commands, again.commands,
                "{}: re-driving a settled transaction changed its decision",
                member.label
            );
            retried += 1;
        }
    }

    assert!(retried >= 20, "only {retried} retry cells ran");
    // Both arms must occur or the test is about one path only. Without
    // `landed` the equality assertion never runs and nothing about
    // decide-once is proven; without `pending` every fault landed a decision
    // and the retry never had to make one.
    assert!(
        landed > 0,
        "no injected lost response ever left a landed decision, so the decide-once assertion never ran"
    );
    assert!(
        pending > 0,
        "every injected lost response landed a decision, so the retry never had to decide anything"
    );
}

// ---------------------------------------------------------------------------
// Acceptance line 3: the race corpus
// ---------------------------------------------------------------------------

/// A duplicated head CAS that reports predecessor-mismatch to the caller must
/// not produce a second terminal decision for the same transaction.
///
/// This is the hostile race the injection vocabulary names by hand:
/// `DuplicateDelivery::Second` is documented as the shape where "after a
/// duplicated conditional replacement the caller can observe a predecessor
/// mismatch even though its own effect linearized". A machine that trusted its
/// own CAS answer would re-plan and decide the transaction twice. The
/// one-terminal-decision-per-TxId invariant is what forbids it, and it is
/// checked here through the push path rather than directly against the store.
#[test]
fn a_duplicated_head_cas_does_not_decide_one_push_twice() {
    let context = context(b"fg019c-duplicate-cas");
    let validated = delete_main();
    let mut fired_on_cas = 0_usize;
    let mut compared = 0_usize;
    let mut never_fired_on_a_cas = Vec::new();

    for member in adapters() {
        let tx_id = session_tx_id(&context, &validated, &member);
        let store = store_with_genesis(&context);

        // TARGETED at the head CAS by KIND, not by absolute position. Audit
        // 4530.6 was right that sweeping `0..span` with an unfiltered directive
        // duplicates requests at whatever operation happens to sit at each
        // index -- reads and put-if-absents included -- so `compared > 0` was
        // satisfiable without a single CAS ever being duplicated, in the test
        // named for duplicating one.
        //
        // `OpCounting`'s own documentation names this failure: absolute
        // addressing "becomes the wrong one when a test means 'the operation
        // that transitions the head' rather than 'operation 2'", and warns that
        // the campaign then "truthfully reports a publication it expected to
        // interrupt and did not, which reads as an assertion problem and is a
        // targeting problem". `nth_of_kind` is the primitive that exists for it.
        store.install_fault_plan(fgit_authority::FaultPlan::explicit(vec![
            FaultDirective::nth_of_kind(
                0,
                fgit_authority::AuthorityOpKind::CompareExchangeHead,
                FaultKind::DuplicateRequest {
                    deliver: DuplicateDelivery::Second,
                },
            ),
        ]));

        let result = admit_validated_receive(
            &store,
            &context,
            &validated,
            AdmissionLimits::default(),
            &member,
        );

        // Ground truth, read BEFORE `restart()` clears nothing but is the point
        // at which the log is unambiguous: the duplicate must have fired
        // against a `CompareExchangeHead`. Without this the directive could
        // fire nowhere and every assertion below would still pass.
        let log = store.fault_log();
        let on_cas = log
            .records()
            .iter()
            .filter(|record| record.op_kind == fgit_authority::AuthorityOpKind::CompareExchangeHead)
            .count();
        if on_cas == 0 {
            never_fired_on_a_cas.push(member.label);
        }
        fired_on_cas += on_cas;

        store.restart();

        // Whatever the caller saw, the authenticated stream must hold at most
        // one terminal decision for this identity, and resolution must answer.
        let resolved = resolve_outcome(
            &store,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            tx_id,
        );
        assert!(
            resolved.is_ok(),
            "{} / duplicated head CAS: {tx_id:?} became unresolvable",
            member.label
        );

        if let (Ok(result), Ok(OutcomeLookup::Decided(terminal))) = (&result, &resolved) {
            compared += 1;
            assert_eq!(
                result.commands[0].terminal, *terminal,
                "{} / duplicated head CAS: the caller was told a decision the stream does not hold",
                member.label
            );
        }
    }

    assert!(
        never_fired_on_a_cas.is_empty(),
        "the duplicate never fired against a head CAS for {never_fired_on_a_cas:?}, so those \
         cells proved nothing about duplicating the operation this test is named for"
    );
    assert!(
        fired_on_cas > 0,
        "no duplicate fired against any head CAS, so this probe never exercised its subject"
    );
    assert!(
        compared > 0,
        "the caller and the stream were never both answered, so nothing was ever compared"
    );
}

/// Two sessions seal distinct transactions, and each is answered from its own
/// authenticated decision.
///
/// **This test used to claim more and was wrong to.** It asserted that exactly
/// one of two sessions deleting the same ref may commit it, and its own comment
/// said the second session was "evaluated against a projection rooted in the
/// head the first one produced". It was not: the adapter ignores the head it is
/// handed, so the second session saw a different ref table only because this
/// test passed it one. Exactly-one-winner was *staged by the fixture*, not
/// demonstrated by the system, and the crate owner was right to refuse it.
///
/// What is left is what never depended on the adapter: two sessions with
/// different idempotency keys are different transactions, and each one's
/// reported outcome is the one the authenticated decision stream holds for its
/// own `TxId`. Ref contention is not tested here -- it is tested by
/// [`two_sessions_deleting_one_ref_yield_exactly_one_commit_and_a_typed_loser`],
/// against the head-bound projection this test's adapter deliberately is not.
#[test]
fn two_sessions_seal_distinct_transactions_each_answered_from_its_own_decision() {
    let first_context = context(b"fg019c-session-a");
    let second_context = context(b"fg019c-session-b");
    let validated = delete_main();
    let store = store_with_genesis(&first_context);
    let adapter = UnboundAdapter::with_main("commits", 0x20);

    let first = admit_validated_receive(
        &store,
        &first_context,
        &validated,
        AdmissionLimits::default(),
        &adapter,
    )
    .expect("the first session reaches a terminal decision");

    // The same adapter drives both. Handing the second a different ref table
    // would stage the outcome rather than observe it, which is the error this
    // test was narrowed to remove.
    let second = admit_validated_receive(
        &store,
        &second_context,
        &validated,
        AdmissionLimits::default(),
        &adapter,
    )
    .expect("the second session reaches a terminal decision");

    assert_ne!(
        first.session.tx_ids[0], second.session.tx_ids[0],
        "two sessions with different idempotency keys must be different transactions"
    );

    for (label, result, context) in [
        ("first", &first, &first_context),
        ("second", &second, &second_context),
    ] {
        let tx_id = result.session.tx_ids[0];
        let resolved = resolve_outcome(
            &store,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            tx_id,
        )
        .unwrap_or_else(|error| panic!("{label}: {tx_id:?} must resolve, got {error}"));
        assert_eq!(
            resolved,
            OutcomeLookup::Decided(result.commands[0].terminal),
            "{label}: the reported outcome is not the one the authenticated stream holds"
        );
    }

    // Each session reports exactly one status, and it is derived from that
    // session's own authenticated terminal decision. WHICH status it is depends
    // on ref policy, which THIS test's unbound adapter does not model -- the
    // head-bound projection that does is exercised by
    // `two_sessions_deleting_one_ref_yield_exactly_one_commit_and_a_typed_loser`
    // instead. ("absent" was the old wording here and is no longer true.) That
    // one command yields one status derived from a decision at all is a
    // property of `command_statuses`, which deliberately has no route from a
    // pack receipt.
    assert_eq!(first.command_statuses().len(), 1, "one command, one status");
    assert_eq!(
        second.command_statuses().len(),
        1,
        "one command, one status"
    );
}

/// The session mechanics hold whichever adapter drove them.
///
/// **This is deliberately no longer described as an independence argument.**
/// Three unbound adapters are three variants of one unbound adapter, so their
/// agreement is not evidence about projection semantics — the crate owner's point,
/// and it is correct. What the test still earns is narrower and real: the
/// session shape and the agreement between a reported outcome and the
/// authenticated stream survive all three routes through `admit_one`
/// (commit-and-publish, fold-abort-and-refuse, materializer-refuse), so those
/// properties are not artefacts of one publication path.
#[test]
fn the_authority_mechanics_do_not_depend_on_which_adapter_drove_them() {
    let validated = delete_main();
    let mut shapes = BTreeSet::new();

    for member in adapters() {
        let first_context = context(b"fg019c-invariance-a");
        let second_context = context(b"fg019c-invariance-b");
        let store = store_with_genesis(&first_context);

        let first = admit_validated_receive(
            &store,
            &first_context,
            &validated,
            AdmissionLimits::default(),
            &member,
        )
        .expect("first session decides");
        let second = admit_validated_receive(
            &store,
            &second_context,
            &validated,
            AdmissionLimits::default(),
            &member,
        )
        .expect("second session decides");

        assert_ne!(
            first.session.tx_ids[0], second.session.tx_ids[0],
            "{}: distinct sessions must seal distinct transactions",
            member.label
        );

        for (result, context) in [(&first, &first_context), (&second, &second_context)] {
            let tx_id = result.session.tx_ids[0];
            assert_eq!(
                resolve_outcome(
                    &store,
                    &context.head_key,
                    context.tenant_id,
                    context.repository_id,
                    tx_id,
                ),
                Ok(OutcomeLookup::Decided(result.commands[0].terminal)),
                "{}: reported outcome disagrees with the authenticated stream",
                member.label
            );
        }

        shapes.insert((
            first.session.tx_ids.len(),
            second.session.tx_ids.len(),
            first.commands.len(),
            second.commands.len(),
            first.session.atomic,
            second.session.atomic,
        ));
    }

    assert_eq!(
        shapes.len(),
        1,
        "the publication routes disagreed about the session shape: {shapes:?}"
    );
}

// ---------------------------------------------------------------------------
// Head-bound production projection: the ref-contention probe this file owed
// ---------------------------------------------------------------------------

/// Staging store behind [`CanonicalAdmissionProjection`].
///
/// Deliberately a plain map: the projection under test is production code, and
/// what this supplies is the commitment storage it resolves roots against. It is
/// duplicated from `pinned_snapshot_toctou.rs` rather than shared because each
/// `tests/*.rs` compiles to its own binary and `fgit-admission` publishes no
/// test-support module. Forty lines of map is cheaper than asking the crate
/// owner to widen a public surface for one consumer.
///
/// `Arc`/`Mutex` rather than `Rc`/`RefCell` so this double is `Send + Sync` and
/// two sessions can be driven from real threads. That was the fixture limit
/// audit 4530.1 identified: the race probe could only run its admissions back
/// to back. The store beneath it was never the obstacle -- `MemoryAuthorityStore`
/// already holds a `Mutex<State>` -- so nothing in production needed changing,
/// which is why the orchestrator ruled this a test change.
#[derive(Default)]
struct CommitmentStore {
    refs: Mutex<BTreeMap<Digest, CanonicalRefState>>,
    closures: Mutex<BTreeMap<Digest, PermittedObjectClosure>>,
}

#[derive(Clone, Default)]
struct StagingStore(Arc<CommitmentStore>);

impl CanonicalAdmissionStore for StagingStore {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.0
            .refs
            .lock()
            .expect("the staging mutex is never poisoned by these tests")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        self.0
            .refs
            .lock()
            .expect("the staging mutex is never poisoned by these tests")
            .insert(root, state);
        Ok(())
    }

    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.0
            .closures
            .lock()
            .expect("the staging mutex is never poisoned by these tests")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        self.0
            .closures
            .lock()
            .expect("the staging mutex is never poisoned by these tests")
            .insert(root, closure);
        Ok(())
    }
}

struct StubEvidence;

impl AdmissionEvidence for StubEvidence {
    fn commit_evidence(
        &self,
        _basis: &PublicationBasis,
        _request: &TransactionRequest,
        _fold: &fgit_txn::TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        Ok(CommitEvidence {
            principal_snapshot_id: principal_snapshot(),
            forge_event_batch_root: digest(8),
            policy_decision_root: digest(9),
            invariant_evidence_root: digest(10),
            outbox_effect_root: digest(11),
            retention_delta_root: digest(12),
        })
    }

    fn refusal_evidence(
        &self,
        basis: &PublicationBasis,
        _tx_id: TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: "fg019c head-bound one-winner probe".to_owned(),
            evidence_root: digest(13),
        })
    }
}

/// An authority store whose genesis head names a ref root the projection can
/// actually resolve, plus the production projection rooted in that store.
///
/// The genesis `ref_root` is `canonical_ref_state_root` of the staged state, not
/// an arbitrary digest. That is the whole difference from [`store_with_genesis`]:
/// a head whose root resolves to nothing would make every snapshot refuse
/// `EvidenceMissing`, and the probe would pass for the wrong reason.
fn head_bound_setup(
    context: &AdmissionContext,
) -> (
    MemoryAuthorityStore,
    CanonicalAdmissionProjection<StagingStore, StubEvidence>,
) {
    let mut refs = BTreeMap::new();
    refs.insert(
        RefName::try_new(MAIN_REF).expect("fixture ref name"),
        // MUST be MAIN_OID: `delete_main_request` sends it as the expected-old,
        // and admission refuses `ExpectedOldRefMismatch` when the staged ref
        // does not carry exactly that predecessor. Staging any other value makes
        // every session refuse, which is what left the race probe vacuous.
        oid(MAIN_OID),
    );
    let state = CanonicalRefState::new(refs);
    let ref_root =
        canonical_ref_state_root(&state).expect("genesis ref state has a canonical root");

    let staging = StagingStore::default();
    staging
        .stage_ref_state(ref_root, state)
        .expect("genesis ref state stages");

    let body = RepositoryAuthorityHeadBody {
        ref_root,
        ..genesis(context)
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(23));
    initialize_repository(&store, &context.head_key, &body).expect("genesis head initializes");

    (
        store,
        CanonicalAdmissionProjection::new(staging, StubEvidence),
    )
}

/// The permitted twin: one session alone deleting the same ref **does** commit.
///
/// Without this, [`two_sessions_deleting_one_ref_yield_exactly_one_commit_and_a_typed_loser`] is vacuous
/// in a way its own non-vacuity guard does not catch. That guard asserts a
/// session *reached a terminal decision*, and a refusal reaches one — so a
/// harness where nothing can ever commit yields `committed == 0`, which is
/// `<= 1`, and the probe passes while demonstrating nothing about one-winner
/// semantics.
///
/// The distinction is between a test that *agrees* with a property and one that
/// would *notice* the property breaking. The race probe agrees with one-winner
/// semantics; on its own it cannot discriminate them from a broken fixture. This twin supplies the missing half, so a
/// zero-commit race outcome is attributable to the race rather than to a setup
/// that could never commit anything.
#[test]
fn one_session_alone_deleting_that_ref_does_commit() {
    let context = context(b"fg019c-headbound-solo");
    let validated = delete_main();
    let (store, projection) = head_bound_setup(&context);

    let result = admit_validated_receive(
        &store,
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    )
    .expect("an uncontended delete against a resolvable genesis basis reaches a decision");

    let tx_id = result.session.tx_ids[0];
    let resolved = resolve_outcome(
        &store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .unwrap_or_else(|error| panic!("{tx_id:?} must resolve, got {error}"));

    let OutcomeLookup::Decided(terminal) = resolved else {
        panic!("an uncontended delete left {tx_id:?} undecided: {resolved:?}");
    };
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "an uncontended delete of a ref present in the genesis state did not commit \
         ({:?}), so this harness cannot commit at all and the two-session probe's \
         zero-commit outcome would prove nothing",
        terminal.outcome
    );
}

/// Two sessions delete the same ref against a head-bound projection, and the
/// authenticated stream holds **exactly one** commit and one typed refusal.
///
/// This is the claim
/// [`two_sessions_seal_distinct_transactions_each_answered_from_its_own_decision`]
/// was narrowed to remove. That narrowing was correct: the adapter ignored the
/// head it was handed, so the second session saw a different ref table only
/// because the fixture passed it one, and exactly-one-winner was *staged*.
///
/// `CanonicalAdmissionProjection` (`frankengit-o0pq`) removes that objection. Its
/// `snapshot` resolves ref state from `authenticated.body().ref_root` and refuses
/// `AuthorityReceiptStale` when the authenticated body disagrees with the basis,
/// so the second session is evaluated against whatever head the first one
/// actually published — by the projection, not by this test.
///
/// # What is asserted, and what is not
///
/// Strengthened for `frankengit-fg019c` after audit 4530, which was right that
/// the previous form did not reach acceptance line 3. Two of that audit's three
/// objections are now answered and one is not, so the scope is restated rather
/// than left as it was.
///
/// Asserted now: **exactly one** of the two sessions commits, **both** reach a
/// terminal decision, and the loser carries a terminal refusal naming
/// `ExpectedOldRefMismatch` — the predecessor mismatch the winning delete
/// created. The earlier form asserted only *at most one* commit, which zero
/// winners also satisfies, and it skipped any loser that errored, so a session
/// that never admitted at all was indistinguishable from one correctly refused.
///
/// **The earlier doc's two hedges are disproved for this schedule, and that is
/// why they are gone.** It recorded that demanding exactly one success "would
/// fail the run for a legal schedule" because the loser might exhaust its
/// replan budget, and that the loser's refusal was policy this file should not
/// pin. Measured: with the head-bound projection, the loser is refused
/// `ExpectedOldRefMismatch` every run, and pinning it is discriminating — with
/// a different code pinned, this test and only this test fails, and the failure
/// reports the real observed code rather than a constant.
///
/// SCOPE: these two admissions run **sequentially**, so this is
/// exactly-one-winner under a deterministic ordering and is not evidence about
/// interleavings. That is now a division of labour rather than a limit -- the
/// concurrent and lab-scheduled probes below cover the other schedules, and the
/// claim that concurrency was *impossible* here (an `Rc`-bound fixture) stopped
/// being true when that double became `Arc`/`Mutex`.
#[test]
fn two_sessions_deleting_one_ref_yield_exactly_one_commit_and_a_typed_loser() {
    let first_context = context(b"fg019c-headbound-a");
    let second_context = context(b"fg019c-headbound-b");
    let validated = delete_main();
    let (store, projection) = head_bound_setup(&first_context);

    let first = admit_validated_receive(
        &store,
        &first_context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    );
    let second = admit_validated_receive(
        &store,
        &second_context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    );

    // BOTH sessions must reach admission. The earlier form of this probe
    // accepted `reached > 0`, which is satisfied when one session never
    // admitted at all -- and a single admission trivially yields at most one
    // commit, so the arithmetic below would have proven nothing about
    // contention.
    assert!(
        first.is_ok() && second.is_ok(),
        "both sessions must reach a terminal decision for this to be a race at \
         all: first={first:?} second={second:?}"
    );

    // Classify EVERY session. The earlier form skipped losers with
    // `let Ok(..) else { continue }` and counted only commits, so a loser that
    // errored, stalled undecided, or was refused for an unrelated reason was
    // indistinguishable from a correctly-refused one.
    let mut committed: Vec<&str> = Vec::new();
    let mut refused: Vec<(&str, RefusalCode)> = Vec::new();
    let mut unresolved: Vec<(&str, String)> = Vec::new();
    for (label, result, session_context) in [
        ("first", &first, &first_context),
        ("second", &second, &second_context),
    ] {
        let Ok(result) = result else {
            unresolved.push((label, format!("admission refused outright: {result:?}")));
            continue;
        };
        let tx_id = result.session.tx_ids[0];
        let resolved = resolve_outcome(
            &store,
            &session_context.head_key,
            session_context.tenant_id,
            session_context.repository_id,
            tx_id,
        )
        .unwrap_or_else(|error| panic!("{label}: {tx_id:?} must resolve, got {error}"));
        match resolved {
            OutcomeLookup::Decided(terminal) => match terminal.outcome {
                DecisionOutcome::Committed { .. } => committed.push(label),
                DecisionOutcome::Refused { code, .. } => refused.push((label, code)),
            },
            OutcomeLookup::Undecided => {
                unresolved.push((label, "undecided in the authenticated stream".to_owned()));
            }
        }
    }

    // EXACTLY one winner, not at most one. `<= 1` is also satisfied by zero
    // winners, which is the failure mode a contended delete is most likely to
    // produce if the head binding is wrong.
    assert_eq!(
        committed.len(),
        1,
        "exactly one session must commit a delete of the same ref from one \
         lineage; committed={committed:?} refused={refused:?} unresolved={unresolved:?}"
    );

    // The loser needs a TYPED status, which is the half of acceptance line 3
    // that "never both commit" does not reach. A loser that errored or sat
    // undecided is not a correct per-loser status.
    assert_eq!(
        refused.len(),
        1,
        "the losing session must carry a terminal refusal rather than an error \
         or an undecided seal; committed={committed:?} refused={refused:?} \
         unresolved={unresolved:?}"
    );
    assert!(
        unresolved.is_empty(),
        "every session in a two-session race must reach a terminal decision; \
         unresolved={unresolved:?}"
    );

    // And the refusal must name the contention rather than some unrelated
    // condition. Pinning the code is what separates "the loser was refused"
    // from "the loser was refused for the reason this race creates".
    let (_, loser_code) = refused[0];
    assert_eq!(
        loser_code,
        RefusalCode::ExpectedOldRefMismatch,
        "the loser of a contended delete was refused {loser_code:?}, not for the \
         predecessor mismatch the winning delete created"
    );
}

/// The same one-winner property under a GENUINELY CONCURRENT schedule.
///
/// This is the half of acceptance line 3 that audit 4530.1 correctly said was
/// missing. The sequential probe above establishes exactly-one-winner for a
/// deterministic ordering, where the first admission completes before the
/// second begins; it says nothing about interleavings, which is where a
/// compare-and-exchange discipline actually earns its keep.
///
/// # Why this could not be written before, and what changed
///
/// The obstacle was never production. `MemoryAuthorityStore` already holds a
/// `Mutex<State>`. It was this file's own `StagingStore`, which wrapped an
/// `Rc<CommitmentStore>` of `RefCell` maps and so was neither `Send` nor
/// `Sync`. The orchestrator ruled that double a test artifact, and it is now
/// `Arc`/`Mutex`. No production type needed a bound added, and none blocked
/// this.
///
/// # What is asserted
///
/// Over many rounds, each with a fresh genesis: both sessions reach a terminal
/// decision, exactly one commits, and the loser carries a terminal refusal.
/// Repetition is the point -- a concurrency probe that runs one interleaving
/// and passes has sampled one schedule and proven almost nothing, so the rounds
/// are what turn this from an anecdote into evidence.
///
/// # Evidence that the schedule actually interleaves
///
/// A "concurrent" probe whose threads serialise proves nothing the sequential
/// twin did not, so this was measured rather than assumed. Instrumenting the
/// winner per round at `c79175e`+ on this machine: **first won 50, second won
/// 14 of 64**. Both orderings occur, so the sessions genuinely contend.
///
/// That distribution is a MEASUREMENT, not an invariant, and is deliberately
/// not asserted: a loaded machine could legitimately produce 64/0 and a test
/// that failed for it would be flaky. The consequence is stated plainly instead
/// -- if a future run were to serialise completely, this test would still pass
/// while quietly degrading to the sequential case, and the interleaving claim
/// would need re-measuring the same way.
///
/// The loser's refusal CODE is deliberately not pinned here, unlike the
/// sequential twin. Under a real race the loser may lose its CAS and be refused
/// for the predecessor mismatch, or lose and replan; fixing one code would be
/// asserting one schedule. What must hold on every schedule is the arithmetic:
/// one winner, one typed refusal, no unresolved seal.
#[test]
fn two_concurrent_sessions_deleting_one_ref_yield_exactly_one_commit() {
    const ROUNDS: usize = 64;

    let first_context = context(b"fg019c-concurrent-a");
    let second_context = context(b"fg019c-concurrent-b");
    let validated = delete_main();

    for round in 0..ROUNDS {
        let (store, projection) = head_bound_setup(&first_context);

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                admit_validated_receive(
                    &store,
                    &first_context,
                    &validated,
                    AdmissionLimits::default(),
                    &projection,
                )
            });
            let second = scope.spawn(|| {
                admit_validated_receive(
                    &store,
                    &second_context,
                    &validated,
                    AdmissionLimits::default(),
                    &projection,
                )
            });
            (
                first
                    .join()
                    .expect("the first session thread must not panic"),
                second
                    .join()
                    .expect("the second session thread must not panic"),
            )
        });

        let mut committed = 0_usize;
        let mut refused = 0_usize;
        let mut unresolved: Vec<String> = Vec::new();

        for (label, result, session_context) in [
            ("first", &first, &first_context),
            ("second", &second, &second_context),
        ] {
            let Ok(result) = result else {
                unresolved.push(format!("{label}: admission refused outright: {result:?}"));
                continue;
            };
            let tx_id = result.session.tx_ids[0];
            let resolved = resolve_outcome(
                &store,
                &session_context.head_key,
                session_context.tenant_id,
                session_context.repository_id,
                tx_id,
            )
            .unwrap_or_else(|error| {
                panic!("round {round} / {label}: {tx_id:?} must resolve, got {error}")
            });
            match resolved {
                OutcomeLookup::Decided(terminal) => match terminal.outcome {
                    DecisionOutcome::Committed { .. } => committed += 1,
                    DecisionOutcome::Refused { .. } => refused += 1,
                },
                OutcomeLookup::Undecided => {
                    unresolved.push(format!("{label}: undecided in the authenticated stream"));
                }
            }
        }

        assert!(
            unresolved.is_empty(),
            "round {round}: every session in a concurrent race must reach a terminal \
             decision; unresolved={unresolved:?}"
        );
        assert_eq!(
            committed, 1,
            "round {round}: {committed} sessions committed a delete of the same ref from \
             one lineage under a concurrent schedule; exactly-one-winner does not hold"
        );
        assert_eq!(
            refused, 1,
            "round {round}: the losing session must carry a terminal refusal, got \
             {refused} refusals alongside {committed} commits"
        );
    }

    // Audit 4658.1 was right that the old form here was tautological: it pushed
    // `committed`, which the loop body had already asserted equals 1, then
    // checked the vector's LENGTH -- so it re-checked an asserted constant and
    // could only have caught an early `break` that the asserting body makes
    // impossible anyway. Removed rather than dressed up; the per-round
    // assertions are the evidence.
}

/// The canonical bytes of the declared race schedule, measured from the run
/// rather than predicted.
const SCHEDULED_RACE_CANONICAL_LINE: &str =
    "fgit-lab-schedule-v1|seed=none|participants=push-a,push-b|steps=3|order=push-a,push-b,push-a";

/// The rival session a scheduled race admits inline.
struct ScheduledRival<'a> {
    context: &'a AdmissionContext,
    validated: &'a ValidatedReceive,
}

/// A schedule gate wrapped around the head-bound production projection.
///
/// Session A has already read its authenticated basis when `snapshot` runs. The
/// first gate lets A obtain that snapshot; the second runs session B's ENTIRE
/// admission inline; the third releases A to issue its CAS against a token that
/// is now provably stale. On A's replan no gate runs, so the production
/// projection observes B's published ref state and the real staleness check
/// decides A's terminal.
///
/// Single-threaded on purpose. The point is not concurrency -- the thread probe
/// above supplies that -- it is DETERMINISM about which window was exercised.
struct ScheduledPushProjection<'schedule, 'rival> {
    production: &'rival CanonicalAdmissionProjection<StagingStore, StubEvidence>,
    cursor: RefCell<StepCursor<'schedule>>,
    raced: Cell<bool>,
    store: &'rival MemoryAuthorityStore,
    rival: ScheduledRival<'rival>,
    rival_committed: Cell<bool>,
}

impl ScheduledPushProjection<'_, '_> {
    fn step(&self, expected_actor: &str) {
        let mut cursor = self.cursor.borrow_mut();
        let actual = cursor
            .next_step()
            .expect("the lab schedule declares every race boundary");
        assert_eq!(
            actual.as_str(),
            expected_actor,
            "the scheduled race reached a boundary out of declared order"
        );
    }
}

impl AdmissionSnapshotProjection for ScheduledPushProjection<'_, '_> {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        let first_snapshot = !self.raced.replace(true);
        if first_snapshot {
            self.step("push-a");
        }
        let snapshot = self.production.snapshot(basis, authenticated)?;
        if first_snapshot {
            self.step("push-b");
            let rival = admit_validated_receive(
                self.store,
                self.rival.context,
                self.rival.validated,
                AdmissionLimits::default(),
                self.production,
            )
            .expect("the scheduled rival reaches one terminal decision");
            let committed = matches!(
                rival.commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            );
            self.rival_committed.set(committed);
            self.step("push-a");
        }
        Ok(snapshot)
    }
}

impl AdmissionProjection for ScheduledPushProjection<'_, '_> {
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<fgit_admission::CommitMaterialization, ProjectionFailure> {
        self.production
            .materialize_commit(basis, request, fold, closure)
    }

    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        self.production.materialize_refusal(basis, tx_id, code)
    }
}

/// The stale-CAS window, forced rather than waited for.
///
/// # Why this exists alongside the thread probe
///
/// The concurrent probe above samples interleavings and measures that both
/// orderings occur (first 50, second 14 of 64). What sampling CANNOT promise is
/// that the one dangerous window was ever entered: session A reading its
/// snapshot, session B committing underneath it, and A then issuing a CAS
/// against a token that is already stale. A scheduler is free never to produce
/// that ordering, and the probe would still pass and still report contention.
///
/// This forces it by construction. B's entire admission runs INSIDE A's first
/// `snapshot`, so A's token is stale by the time it reaches the CAS -- not
/// probably, but on every run. Deterministic and reproducible, which is what
/// `fgit-lab` is for and what the orchestrator's ruling named.
///
/// Together the two probes cover both halves: the thread probe shows real
/// concurrent contention across many schedules; this one shows the worst
/// schedule is survived.
#[test]
fn a_scheduled_push_race_forces_the_stale_cas_window_and_still_yields_one_winner() {
    let schedule = LabSchedule::explicit(
        vec![StepId::new("push-a"), StepId::new("push-b")],
        vec![
            StepId::new("push-a"),
            StepId::new("push-b"),
            StepId::new("push-a"),
        ],
    )
    .expect("a declared three-boundary race schedule");

    let a_context = context(b"fg019c-scheduled-a");
    let b_context = context(b"fg019c-scheduled-b");
    let validated = delete_main();
    let (store, production) = head_bound_setup(&a_context);

    let scheduled = ScheduledPushProjection {
        production: &production,
        cursor: RefCell::new(schedule.cursor()),
        raced: Cell::new(false),
        store: &store,
        rival: ScheduledRival {
            context: &b_context,
            validated: &validated,
        },
        rival_committed: Cell::new(false),
    };

    let a_result = admit_validated_receive(
        &store,
        &a_context,
        &validated,
        AdmissionLimits::default(),
        &scheduled,
    );

    // The window was actually entered. Without this the test could pass having
    // never run the rival at all, which is the same "fired nowhere" failure the
    // duplicated-CAS probe had.
    assert!(
        scheduled.raced.get(),
        "session A never took a snapshot, so the scheduled window was never entered"
    );
    assert!(
        scheduled.rival_committed.get(),
        "the rival did not commit inside A's snapshot, so A's token was never made \
         stale and this probe did not exercise the window it exists for"
    );

    let a = a_result.expect("session A reaches a terminal decision");
    let a_committed = matches!(
        a.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    );

    // Exactly one winner across the two sessions, with B having won by
    // construction, so A must not also commit the same delete.
    assert!(
        !a_committed,
        "both sessions committed a delete of the same ref from one lineage: the rival \
         committed inside A's snapshot and A committed against its stale token"
    );
    // The EXACT code, not merely "some refusal". This probe drives the generic
    // non-basis-bound entrypoint, whose stale-loser code is
    // `ExpectedOldRefMismatch`; the production basis-bound path answers
    // `AuthorityReceiptStale` and has its own probe. Pinning both is what keeps
    // the two entrypoints from being conflated.
    assert!(
        matches!(
            a.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        ),
        "A lost the scheduled race and must carry the generic entrypoint's \
         predecessor-mismatch refusal, got {:?}",
        a.commands[0].terminal.outcome
    );
    // The EXACT reported status, not merely one of them. Audit 4707 was right
    // that `len() == 1` is satisfied by `Ok` and by any wrong message, so a
    // mutation that reported success to the client would have passed. This is
    // the byte the client actually sees.
    assert_eq!(
        a.command_statuses(),
        vec![fgit_wire::receive::ReceiveCommandStatus::Rejected {
            message: b"stale info".to_vec()
        }],
        "the generic entrypoint's stale loser must report the predecessor-mismatch \
         bytes to the client"
    );

    // Every declared boundary ran. Audit 4658.1 asked for this and the precedent
    // asserts it: without exhaustion a schedule that fired only its first gate
    // would leave the later boundaries unexercised while every assertion above
    // still passed.
    assert!(
        scheduled.cursor.borrow().is_exhausted(),
        "the declared three-boundary schedule was not exhausted, so at least one \
         race boundary never ran"
    );

    // The schedule itself is witnessed, not just consumed. Exhaustion alone
    // cannot tell a three-boundary schedule from a shorter one that also ran to
    // its end, so the canonical bytes pin WHICH schedule was declared.
    assert_eq!(
        schedule.canonical_line(),
        SCHEDULED_RACE_CANONICAL_LINE,
        "the declared race schedule changed; the recorded canonical bytes are the \
         witness for which interleaving this evidence is about"
    );
}

/// The production basis-bound path driven through the SCHEDULED race, so A holds
/// its binding across B's commit instead of being handed a stale one.
///
/// # Why the sequential basis-bound probe was not enough
///
/// Audit 4707 was right about the difference. In
/// [`a_basis_bound_loser_is_refused_authority_receipt_stale_not_expected_old_ref_mismatch`]
/// session B finishes entirely before A begins admission, so A is simply handed
/// a witness that is already stale -- that proves first-plan stale-witness
/// refusal, which is a real property but not a race. Here A ENTERS admission
/// first, holds its basis-bound witness across the gate, and B's whole admission
/// runs inside A's snapshot. A then continues with a binding that went stale
/// underneath it.
///
/// The generic scheduled race covers the same window for
/// `admit_validated_receive`; this one covers it for the entrypoint production
/// receive-pack actually uses, and the two answer with DIFFERENT codes.
#[test]
fn a_scheduled_race_through_the_basis_bound_entrypoint_refuses_the_stale_witness() {
    let schedule = LabSchedule::explicit(
        vec![StepId::new("push-a"), StepId::new("push-b")],
        vec![
            StepId::new("push-a"),
            StepId::new("push-b"),
            StepId::new("push-a"),
        ],
    )
    .expect("a declared three-boundary race schedule");

    let a_context = context(b"fg019c-bb-sched-a");
    let b_context = context(b"fg019c-bb-sched-b");
    let validated = delete_main();
    let (store, production) = head_bound_setup(&a_context);

    // A binds BEFORE the race, then carries that binding through the gate.
    let basis_a = basis_for(&authenticated_head_body(&store, &a_context.head_key));
    let request = delete_main_request();
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    let bound_a = validate_receive_at_basis(
        &request,
        None,
        &receipt,
        &basis_a,
        &DeleteOnlyValidator,
        &mut live_deadline(),
    )
    .expect("a delete-only receive binds to its authenticated basis");

    let scheduled = ScheduledPushProjection {
        production: &production,
        cursor: RefCell::new(schedule.cursor()),
        raced: Cell::new(false),
        store: &store,
        rival: ScheduledRival {
            context: &b_context,
            validated: &validated,
        },
        rival_committed: Cell::new(false),
    };

    let a = admit_basis_bound_validated_receive(
        &store,
        &a_context,
        &bound_a,
        AdmissionLimits::default(),
        &scheduled,
    )
    .expect("the basis-bound session reaches a terminal decision");

    // The window was entered and B won inside it, or this proves nothing.
    assert!(
        scheduled.raced.get(),
        "session A never took a snapshot, so the scheduled window was never entered"
    );
    assert!(
        scheduled.rival_committed.get(),
        "the rival did not commit inside A's snapshot, so A's binding never went \
         stale underneath it"
    );

    assert!(
        matches!(
            a.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::AuthorityReceiptStale,
                ..
            }
        ),
        "the production basis-bound path must refuse a binding that went stale \
         DURING the race as AuthorityReceiptStale, got {:?}",
        a.commands[0].terminal.outcome
    );
    assert_eq!(
        a.command_statuses(),
        vec![fgit_wire::receive::ReceiveCommandStatus::Rejected {
            message: b"admission refused".to_vec()
        }],
        "the raced basis-bound loser must report its own bytes to the client"
    );

    assert!(
        scheduled.cursor.borrow().is_exhausted(),
        "the declared three-boundary schedule was not exhausted, so at least one \
         race boundary never ran"
    );
    assert_eq!(
        schedule.canonical_line(),
        SCHEDULED_RACE_CANONICAL_LINE,
        "the declared race schedule changed; the recorded canonical bytes are the \
         witness for which interleaving this evidence is about"
    );
}

/// The PRODUCTION basis-bound loser status, which is not the one the other
/// probes in this file observe.
///
/// # Why this exists
///
/// Audit 4658.2 caught a gap I would not have found: every other race probe
/// here drives [`admit_validated_receive`], and production receive-pack does
/// not. The raw path binds its validation to the exact authority basis that
/// authorized it (`validate_receive_at_basis`) and admits through
/// [`admit_basis_bound_validated_receive`], and when the head has moved under
/// that binding the refusal is `AuthorityReceiptStale` -- a DIFFERENT code from
/// the `ExpectedOldRefMismatch` the non-basis-bound entrypoint produces for the
/// same physical situation.
///
/// So "the loser carries the right status" was being asserted against a path
/// production does not take. This pins it on the path production does.
///
/// # Why no schedule is needed
///
/// Staleness here is created by CONSTRUCTION rather than by timing: session A's
/// receive is bound to basis A, session B then commits and moves the head, and
/// only then is A admitted. There is no window to hit and nothing to interleave,
/// so a deterministic sequence is the honest instrument -- the lab-gated probe
/// above is what covers the timing-dependent window.
#[test]
fn a_basis_bound_loser_is_refused_authority_receipt_stale_not_expected_old_ref_mismatch() {
    let a_context = context(b"fg019c-basisbound-a");
    let b_context = context(b"fg019c-basisbound-b");
    let (store, projection) = head_bound_setup(&a_context);

    // Bind session A's receive to the CURRENT basis, before B moves the head.
    let basis_a = basis_for(&authenticated_head_body(&store, &a_context.head_key));
    let request = delete_main_request();
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    let bound_a = validate_receive_at_basis(
        &request,
        None,
        &receipt,
        &basis_a,
        &DeleteOnlyValidator,
        &mut live_deadline(),
    )
    .expect("a delete-only receive binds to its authenticated basis");

    // B commits and moves the head out from under A's binding.
    let b = admit_validated_receive(
        &store,
        &b_context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("session B reaches a terminal decision");
    assert!(
        matches!(
            b.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ),
        "this probe needs B to WIN so that A's binding is genuinely stale; got {:?}",
        b.commands[0].terminal.outcome
    );

    // A now admits against a basis the head has moved past.
    let a = admit_basis_bound_validated_receive(
        &store,
        &a_context,
        &bound_a,
        AdmissionLimits::default(),
        &projection,
    )
    .expect("the stale basis-bound session reaches a terminal decision");

    assert!(
        matches!(
            a.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::AuthorityReceiptStale,
                ..
            }
        ),
        "the production basis-bound path must refuse a stale binding as \
         AuthorityReceiptStale rather than by ref-predecessor comparison; got {:?}",
        a.commands[0].terminal.outcome
    );

    // One command, one status, so the per-loser status is reported and not
    // merely derivable.
    // The EXACT reported status. Note it differs from the generic entrypoint's
    // loser bytes: AuthorityReceiptStale is not one of the codes that share the
    // deliberately generic "stale info" message, so the two paths are
    // distinguishable on the wire as well as in the refusal code.
    assert_eq!(
        a.command_statuses(),
        vec![fgit_wire::receive::ReceiveCommandStatus::Rejected {
            message: b"admission refused".to_vec()
        }],
        "the basis-bound stale-witness loser must report its own bytes to the client"
    );
}

/// The head-binding property itself: a basis that disagrees with the
/// authenticated head is refused, and one that agrees is not.
///
/// # Why this exists, and what it replaces
///
/// [`two_sessions_deleting_one_ref_yield_exactly_one_commit_and_a_typed_loser`] was believed to rest on
/// head-binding and does not. Mutation testing settled it: making
/// `CanonicalAdmissionProjection::snapshot` ignore its `AuthenticatedHead` —
/// dropping the staleness check *and* resolving from `basis.body().ref_root` —
/// left every test in this file passing. The reason is that the race fixture
/// never makes the basis and the head **diverge**, so the two roots are equal,
/// resolving from either is identical, and the check cannot fire. Exactly-one-
/// winner there is real but comes from the authority head CAS, not from the
/// projection being head-bound.
///
/// `AuthorityReceiptStale` was asserted nowhere in this suite before this test —
/// it appeared once, in a doc comment claiming the behaviour.
///
/// # The pair
///
/// Both halves use the same store-issued `AuthenticatedHead`, so the only
/// variable is the basis:
///
/// * **permitted** — a basis whose body equals the authenticated head's resolves;
/// * **forbidden** — a basis naming a different `ref_root` is refused
///   `AuthorityReceiptStale`.
///
/// The head id is derived with `body_id` exactly as `admit_validated_receive`
/// derives it, so these bases are the same shape admission builds rather than a
/// test-invented pairing.
///
/// # What this pins, and what it does not
///
/// Measured by mutation rather than argued: deleting the staleness check at
/// `fgit-admission/src/lib.rs:712` fails this test and only this test, and so
/// does the weaker mutation that removes *only* that check while leaving ref
/// resolution reading from `authenticated_body.ref_root`. So it pins
/// `AuthorityReceiptStale` specifically, not merely "the head was ignored".
///
/// **It exercises exactly one field.** The check compares the *whole* body
/// (`authenticated_body != *basis.body()`); this varies `ref_root` alone. One
/// field is enough to kill the mutation, and widening it for its own sake would
/// add cost without evidence. But a future narrowing of that comparison from
/// whole-body to `ref_root`-only would be **invisible here** — this test would
/// still pass. Stated so the next reader does not inherit the stronger reading.
#[test]
fn a_basis_that_disagrees_with_the_authenticated_head_is_refused_as_stale() {
    let context = context(b"fg019c-stale-basis");
    let (store, projection) = head_bound_setup(&context);

    let HeadRead::Present(receipt) = store
        .read_head(&context.head_key)
        .expect("the genesis head reads back")
    else {
        panic!("head_bound_setup initializes a head, so it must be present");
    };
    let authenticated = store
        .authenticate_head_receipt(&receipt)
        .expect("a store authenticates a receipt it issued itself");
    let head_body = authenticated
        .body()
        .expect("the authenticated receipt carries a decodable head body");

    // PERMITTED. Agreement resolves, so the refusal below is discrimination
    // rather than a projection that refuses every basis it is handed.
    projection
        .snapshot(&basis_for(&head_body), &authenticated)
        .expect("a basis equal to the authenticated head must resolve");

    // FORBIDDEN. Same head, a basis naming a different ref root. This is the
    // divergence the race fixture never produces.
    let divergent = RepositoryAuthorityHeadBody {
        ref_root: canonical_ref_state_root(&CanonicalRefState::new(BTreeMap::new()))
            .expect("the empty ref state has a canonical root"),
        ..head_body
    };
    assert_ne!(
        divergent.ref_root, head_body.ref_root,
        "the divergent basis must actually differ, or this asserts nothing"
    );

    let refusal = projection
        .snapshot(&basis_for(&divergent), &authenticated)
        .expect_err("a basis disagreeing with the authenticated head must be refused");
    assert_eq!(
        refusal,
        RefusalCode::AuthorityReceiptStale,
        "a stale basis was refused {refusal:?} rather than AuthorityReceiptStale, so the \
         projection is not rejecting it for the head-binding reason this test exists to pin"
    );
}

/// A publication basis for `body`, with its id derived the way admission derives
/// it (`body_id` over the head body), not invented here.
fn basis_for(body: &RepositoryAuthorityHeadBody) -> PublicationBasis {
    let internal =
        body_id(&CryptoBodyIdentity, body).expect("a head body has a canonical identity");
    let id = fgit_types::RepositoryAuthorityHeadId::from_internal_object_id(internal)
        .expect("the head identity is a valid head id");
    PublicationBasis::new(id, body.clone())
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

// ---------------------------------------------------------------------------
// Hidden-ref refusals on the PUSH path (frankengit-fg019c acceptance line 1).
//
// `frankengit-eeb8` covers the advertisement side -- a hidden ref never
// reaches a principal's push advertisement. What neither that work nor
// anything else asserts is the push itself: `hides_any_target` at
// fgit-admission refuses a ref command whose target is hidden, and until now
// no test drove it. The refusal was raised by production code and observed by
// nobody.
// ---------------------------------------------------------------------------

/// A push whose target is hidden from the principal is refused, and refused
/// with the code that names the reason.
///
/// Asserting merely "refused" would pass against any of the dozen other
/// refusal codes this path can produce, so the code itself is pinned.
#[test]
fn a_push_targeting_a_hidden_ref_is_refused_as_hidden_ref_unauthorized() {
    let context = context(b"fg019c-hidden-target");
    let store = store_with_genesis(&context);
    let projection = UnboundAdapter::with_main("hidden-target", 0x40).hiding(MAIN_REF);

    let result = admit_validated_receive(
        &store,
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("a hidden target still reaches a terminal decision rather than failing open");

    let outcome = &result.commands[0].terminal.outcome;
    assert!(
        matches!(
            outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ),
        "a push to a hidden ref must be refused as HiddenRefUnauthorized, got {outcome:?}"
    );
}

/// The permitted twin: the identical request under a policy that hides a
/// DIFFERENT ref must not be refused for the hidden-ref reason.
///
/// Without this the test above would pass against a build that refused every
/// push as `HiddenRefUnauthorized`, which is indistinguishable from a working
/// guard by the refusal alone. Only the hide rule differs between the two.
#[test]
fn the_permitted_twin_a_push_to_a_visible_ref_commits() {
    let context = context(b"fg019c-visible-target");
    let store = store_with_genesis(&context);
    let projection =
        UnboundAdapter::with_main("visible-target", 0x41).hiding(b"refs/internal/secret");

    let result = admit_validated_receive(
        &store,
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("a visible target reaches a terminal decision");

    // COMMITTED, not merely "not refused as hidden". Audit 4530.5 was right
    // that the weaker form is nearly free: `!matches!(.., HiddenRefUnauthorized)`
    // is satisfied by a refusal for ANY other reason, so a projection that
    // refused every push would still pass and the twin would prove nothing
    // about discrimination. The point of a permitted twin is that the visible
    // ref gets all the way through.
    let outcome = &result.commands[0].terminal.outcome;
    assert!(
        matches!(outcome, DecisionOutcome::Committed { .. }),
        "a push to a ref the policy does not hide must COMMIT, not merely avoid \
         the hidden-ref refusal; got {outcome:?}"
    );
}

/// A structurally valid, empty SHA-1 pack that has crossed quarantine parsing.
///
/// Needed because `validate_receive` refuses any non-delete command with no
/// pack, so an OBJECT-BEARING probe cannot reach the hidden-ref policy without
/// one. The pack carries no entries: what is under test is which refusal the
/// admission path reaches, not pack contents.
fn quarantined_empty_pack() -> fgit_pack::QuarantinedPack {
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let checksum = fgit_crypto::sha1_digest(&bytes);
    bytes.extend_from_slice(checksum.as_slice());
    fgit_pack::read_verified_pack(
        &bytes,
        fgit_pack::ObjectFormat::Sha1,
        &fgit_pack::PackLimits::default(),
        &mut live_deadline(),
        &fgit_pack::NativeChecksumVerifier,
    )
    .expect("an empty pack is structurally valid and crosses quarantine parsing")
}

/// A validator that DECLARES a closure covering the target, so containment does
/// not refuse before ref visibility is consulted.
///
/// It ignores the pack and the receipt. That is the point -- it isolates the
/// ordering question -- and it is also exactly why nothing downstream of it may
/// be described as object-bearing evidence: a permissive validator can name an
/// object the pack does not contain.
struct DeclaredClosureValidator(GitOid);

impl QuarantineValidator for DeclaredClosureValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
        _deadline: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        let objects = BTreeSet::from([self.0]);
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))?,
            objects,
        })
    }
}

/// One NON-DELETE create of `target_ref`, validated and ready to admit.
///
/// # What this fixture is and is not
///
/// It is a non-delete command that gets *past* the pack-presence and
/// closure-containment gates, so admission reaches ref-visibility policy. It is
/// NOT an object-bearing push: the pack carries zero entries and the validator
/// DECLARES a closure covering the target rather than deriving one from those
/// bytes. Nothing here proves an object was transferred, staged, or retained.
///
/// That limit is deliberate and structural. Deriving a closure from real pack
/// contents is what `ProductionQuarantineValidator` does, and it lives in
/// `fgit-node`; this crate can only supply a double. Real object-bearing
/// evidence therefore belongs in a `fgit-node` test, not here.
fn non_delete_receive_with_declared_closure(target_ref: &[u8], new_oid: &str) -> ValidatedReceive {
    let mut line = format!("{ZERO} {new_oid} {}", String::from_utf8_lossy(target_ref)).into_bytes();
    line.push(0);
    line.extend_from_slice(b"report-status atomic");

    let mut machine = ReceivePack::new(wire_context()).expect("machine");
    machine
        .push_packet(Packet::Data(line))
        .expect("create command must parse");
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    let request = (**request).clone();

    let pack = quarantined_empty_pack();
    // The receipt tells the truth about the pack. An earlier version of this
    // fixture claimed `object_count: 1` beside a zero-entry pack, which is a
    // fixture asserting something the bytes do not support.
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 32,
        delete_only: false,
    };
    validate_receive(
        &request,
        Some(&pack),
        &receipt,
        &DeclaredClosureValidator(oid(new_oid)),
        &mut live_deadline(),
    )
    .expect("an object-bearing receive whose closure covers its target validates")
}

/// Ref visibility is consulted AFTER the gates a non-delete command crosses, and
/// still refuses.
///
/// # The claim, narrowed after audit 4702
///
/// This was first written as an "object-bearing push" probe. It is not one, and
/// the audit was right to say so: the pack has zero entries and the validator
/// declares a covering closure instead of deriving one, so no object is
/// transferred and the permitted twin would happily commit a ref aimed at an
/// object absent from the pack. Calling that object-bearing evidence would be a
/// fixture presented as live proof.
///
/// What it does establish is ORDERING, which is still worth having and was still
/// unproven: a non-delete command travels a longer road than a delete --
/// `validate_receive` demands a pack, then closure containment runs -- and
/// EITHER can refuse before ref visibility is consulted. Both answer
/// `ObjectClosureIncomplete`. So a permissive validator could have let a hidden
/// target through, or an earlier gate could have masked the visibility check
/// entirely, and every other hidden-ref probe here is delete-only and skips that
/// road. This pins that visibility still decides, with the exact code.
///
/// NOT established here, and left open on acceptance line 1: that a real
/// uploaded object behind such a refusal is excluded from retention, disclosure
/// or canonical fabric. That needs production closure validation
/// (`fgit-node`'s `ProductionQuarantineValidator`) plus the owner's policy
/// ruling on comment 4617.
#[test]
fn ref_visibility_is_checked_after_the_pack_and_closure_gates_a_non_delete_crosses() {
    let context = context(b"fg019c-hidden-objects");
    let store = store_with_genesis(&context);
    let projection =
        UnboundAdapter::with_main("hidden-objects", 0x51).hiding(b"refs/internal/secret");

    let result = admit_validated_receive(
        &store,
        &context,
        &non_delete_receive_with_declared_closure(b"refs/internal/secret", MAIN_OID),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("an object-bearing push to a hidden ref reaches a terminal decision");

    let outcome = &result.commands[0].terminal.outcome;
    assert!(
        matches!(
            outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ),
        "an object-bearing push to a hidden ref must be refused as hidden rather than \
         by the pack or closure gates it crosses first, got {outcome:?}"
    );
}

/// The permitted twin: same shape, visible target, and it must NOT be refused as
/// hidden.
///
/// Without this the test above passes equally against an admission path that
/// refuses every non-delete command for some unrelated reason, which is the
/// failure mode a twin exists to exclude.
///
/// It deliberately asserts "not refused as hidden" rather than "commits". This
/// fixture's closure is declared rather than derived, so a commit here would
/// publish a ref pointing at an object no pack carried -- an outcome this test
/// should not be in the business of blessing.
#[test]
fn the_permitted_twin_a_non_delete_to_a_visible_ref_is_not_refused_as_hidden() {
    let context = context(b"fg019c-visible-objects");
    let store = store_with_genesis(&context);
    let projection =
        UnboundAdapter::with_main("visible-objects", 0x52).hiding(b"refs/internal/secret");

    let result = admit_validated_receive(
        &store,
        &context,
        &non_delete_receive_with_declared_closure(b"refs/heads/feature", MAIN_OID),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("an object-bearing push to a visible ref reaches a terminal decision");

    let outcome = &result.commands[0].terminal.outcome;
    assert!(
        !matches!(
            outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ),
        "a non-delete command aimed at a ref the policy does not hide must not be \
         refused as hidden, got {outcome:?}"
    );
}

/// A hide rule that matches by PREFIX refuses a push beneath it.
///
/// The rule here never names the pushed ref exactly, so this separates "the
/// policy is consulted as a prefix matcher" from "the policy happens to hold
/// this exact name" -- the two are indistinguishable when the fixture rule and
/// the pushed ref are the same string, as in the first test above.
#[test]
fn a_prefix_hide_rule_refuses_a_push_beneath_it() {
    let context = context(b"fg019c-hidden-prefix");
    let store = store_with_genesis(&context);
    let projection = UnboundAdapter::with_main("hidden-prefix", 0x42).hiding(b"refs/heads");

    let result = admit_validated_receive(
        &store,
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("a prefix-hidden target still reaches a terminal decision");

    let outcome = &result.commands[0].terminal.outcome;
    assert!(
        matches!(
            outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ),
        "a push beneath a hidden prefix must be refused as HiddenRefUnauthorized, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// What the CLIENT sees for a hidden-ref push (frankengit-fg019c acceptance
// line 1, first half: "zero unauthorized DISCLOSURE").
//
// The three probes above pin the internal `RefusalCode`. That is not the
// disclosure property. `RefusalCode::HiddenRefUnauthorized` documents itself as
// "the request touched a ref hidden from this principal"; emitted to a client
// that announces the ref exists and turns a push into an enumeration oracle for
// the hidden namespace. A corpus that pins only the code passes while the wire
// leaks.
//
// This is NOT already covered by fgit-admission's own
// `the_emitted_status_for_a_hidden_target_matches_an_unknown_one_byte_for_byte`
// (src/lib.rs, `frankengit-eeb8`). That test hands `status_from_terminal` a
// hand-built `DecisionOutcome`, so it establishes the CODE-TO-BYTES MAPPING; it
// does not establish that an admitted hidden-ref push takes that mapping, and it
// lives in the lib target, which this bead's registered lane does not run.
// Composing the two facts is an argument. This drives both cases through the
// real admission path and compares what admission emits.
// ---------------------------------------------------------------------------

/// The client-visible status bytes for a push to a HIDDEN ref are identical to
/// those for a push to a ref the principal's view does not carry.
///
/// # Why the equality alone would prove nothing
///
/// An emit route returning one constant for every refusal satisfies it. The
/// third case is the control: `ProtectedRefTransitionDenied` reaches its
/// terminal decision on the same admission path, through the same emit route,
/// and its bytes must still DIFFER. Without that, "indistinguishable" is free.
///
/// The two indistinguishable cases are refused by DIFFERENT guards -- the
/// hidden one before the fold by `hides_any_target`, the unknown one by the
/// fold itself on an unsatisfied expected-old -- so this is byte agreement
/// across two genuinely different code paths, not one path observed twice.
#[test]
fn a_hidden_ref_push_reports_the_same_client_bytes_as_a_push_to_a_ref_the_principal_cannot_see() {
    // Hidden: the projection's ref table carries `refs/heads/main` and the
    // policy hides it, so `hides_any_target` refuses before the fold.
    let hidden = admitted_statuses(
        b"fg019c-disclosure-hidden",
        UnboundAdapter::with_main("disclosure-hidden", 0x60).hiding(MAIN_REF),
    );
    // Unknown: no hide rule at all, and the ref table does not carry
    // `refs/heads/main`, so the delete's expected-old is unsatisfied and the
    // FOLD refuses `ExpectedOldRefMismatch`.
    let unknown = admitted_statuses(
        b"fg019c-disclosure-unknown",
        UnboundAdapter::new("disclosure-unknown", 0x61),
    );

    assert_eq!(
        hidden, unknown,
        "a push to a hidden ref must report the same bytes as a push to a ref the \
         principal's view does not carry; a difference lets a client enumerate the \
         hidden namespace one push at a time"
    );
    assert_eq!(
        hidden,
        vec![fgit_wire::receive::ReceiveCommandStatus::Rejected {
            message: b"stale info".to_vec()
        }],
        "and both must be the ordinary stale-info rejection rather than some third \
         shape that merely happens to be shared between these two cases"
    );

    // The control.
    let protected = admitted_statuses(
        b"fg019c-disclosure-control",
        UnboundAdapter::with_main("disclosure-control", 0x62)
            .refusing_commit(RefusalCode::ProtectedRefTransitionDenied),
    );
    assert_ne!(
        hidden, protected,
        "genuinely different refusals must stay distinguishable on the wire, or the \
         byte identity above is satisfied by an emit route that says one thing to \
         every client"
    );
}

/// Admits `delete_main()` through `projection` and returns exactly the statuses
/// admission would hand `report-status`.
///
/// `AdmissionResult::command_statuses` documents itself as the sole route from
/// admission to `report-status`, and `AdmissionResult::report_packets` encodes
/// these same values into the `ng <ref> <message>` lines, so these are the
/// client-visible payloads rather than an internal projection of them.
fn admitted_statuses(
    session: &[u8],
    projection: UnboundAdapter,
) -> Vec<fgit_wire::receive::ReceiveCommandStatus> {
    let context = context(session);
    let store = store_with_genesis(&context);
    let result = admit_validated_receive(
        &store,
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("every case here reaches a terminal decision rather than failing open");
    assert_eq!(
        result.commands.len(),
        1,
        "the fixture pushes one command, so exactly one status is expected"
    );
    result.command_statuses()
}

// ---------------------------------------------------------------------------
// The retention boundary on the PUSH path (frankengit-fg019c acceptance line 1,
// second half: "zero unauthorized disclosure/RETENTION").
//
// The disclosure half is covered above. The retention half was asserted by
// nothing: a repository-wide search for a test tying a refusal or a commit to
// retention state returned no assertions at all. The only mentions were a
// comment in `fgit-wire`'s adversarial target and two *fixtures* that return
// `ConflictingSemanticEffects` -- fixtures producing a code, not tests checking
// a guard fires.
//
// WHAT I DID NOT WRITE, AND WHY. The obvious target was the guard at
// fgit-admission `prepare_canonical_commit`, which refuses when a fold carries
// forge, retention, or outbox effects. Reading `model_request` first showed
// that guard is UNREACHABLE from a push: receive-pack lowering maps
// `semantic.ref_commands()` to `Intent::Ref(..)` and to nothing else, so a
// push cannot express a retention intent and `effects.retention` is always
// empty on this path. A test driving that guard directly would have passed
// while proving nothing about push behaviour, and reporting it as push
// coverage would have been the stronger claim the evidence did not support.
//
// So the property is structural, and this pins the structural consequence
// end to end instead: a push moves refs and NOTHING else. If someone later
// teaches receive-pack lowering to emit a forge, retention, or outbox intent,
// the equalities below start failing.
// ---------------------------------------------------------------------------

/// Reads back the current authenticated head body.
fn authenticated_head_body(
    store: &MemoryAuthorityStore,
    head_key: &HeadKey,
) -> RepositoryAuthorityHeadBody {
    let HeadRead::Present(receipt) = store
        .read_head(head_key)
        .expect("an initialized head reads back")
    else {
        panic!("head_bound_setup initializes a head, so it must be present");
    };
    store
        .authenticate_head_receipt(&receipt)
        .expect("a store authenticates a receipt it issued itself")
        .body()
        .expect("the authenticated receipt carries a decodable head body")
}

/// A committed DELETE-ONLY push advances the ref root and leaves the retention,
/// forge and outbox roots exactly as it found them.
///
/// # What this exercises, which is narrower than the property
///
/// `delete_main` carries zero objects and no pack, so this is ONE authorized
/// delete rather than a survey of push shapes. The general claim -- that no
/// push can touch retention -- rests on the structural argument in the section
/// header above (receive-pack lowering emits `Intent::Ref` and nothing else),
/// and this test pins the observable consequence for the single shape it
/// drives. An object-bearing push would need real pack fixtures this crate does
/// not have. Named for the delete so the name cannot be read as the broader
/// claim, which is the form the evidence does not support on its own.
///
/// The `assert_ne!` on the ref root is not decoration: it is the control that
/// makes the three equalities mean something. A push that committed nothing --
/// or a harness that could not commit at all -- would satisfy every equality
/// below while proving the opposite of what this test claims. Ordering it
/// first states that dependency rather than leaving it to be noticed.
#[test]
fn a_committed_delete_only_push_moves_the_ref_root_and_leaves_retention_forge_and_outbox_untouched()
{
    let context = context(b"fg019c-retention-boundary");
    let validated = delete_main();
    let (store, projection) = head_bound_setup(&context);

    let before = authenticated_head_body(&store, &context.head_key);

    let result = admit_validated_receive(
        &store,
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    )
    .expect("an uncontended delete against a resolvable genesis basis reaches a decision");

    let tx_id = result.session.tx_ids[0];
    let resolved = resolve_outcome(
        &store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .unwrap_or_else(|error| panic!("{tx_id:?} must resolve, got {error}"));
    let OutcomeLookup::Decided(terminal) = resolved else {
        panic!("an uncontended delete left {tx_id:?} undecided: {resolved:?}");
    };
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "this probe needs a COMMITTED push to be meaningful; got {:?}",
        terminal.outcome
    );

    let after = authenticated_head_body(&store, &context.head_key);

    assert_ne!(
        after.ref_root, before.ref_root,
        "the committed push did not move the ref root, so the three equalities below would \
         hold for a push that did nothing and this test would assert nothing"
    );
    assert_eq!(
        after.retention_root, before.retention_root,
        "a push minted or removed a retention root; receive-pack lowering emits ref intents \
         only, so retention state must cross a push untouched"
    );
    assert_eq!(
        after.forge_position_root, before.forge_position_root,
        "a push moved forge positions, which receive-pack lowering cannot express"
    );
    assert_eq!(
        after.outbox_root, before.outbox_root,
        "a push created an outbox obligation, which receive-pack lowering cannot express"
    );
}
