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
//! * **Acceptance line 3 is NOT discharged here.** Exactly-one-winner over ref
//!   state needs a head-bound projection. What these probes cover is the
//!   narrower decide-once property: one sealed transaction acquires at most one
//!   terminal decision under a duplicated CAS or a lost response.
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

use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionProjection, AdmissionSnapshot,
    CommitMaterialization, QuarantineValidator, RefusalMaterialization, ValidatedClosure,
    ValidatedReceive, admit_validated_receive, validate_receive,
};
use fgit_authority::{
    AuthenticatedHead, DuplicateDelivery, FaultDirective, FaultKind, FaultPosition,
    FaultableAuthorityStore, HeadKey, IdempotencyKey, MemoryAuthorityStore, OpIndex,
    OutcomeFailure, OutcomeLookup, StoreInstanceId, TerminalOutcome, initialize_repository,
    reconcile_outcome, resolve_outcome,
};
use fgit_chronicle::{PublicationBasis, ResultingRoots};
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
}

impl AdmissionProjection for UnboundAdapter {
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
        })
    }

    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, RefusalCode> {
        if let Some(code) = self.commit_refusal {
            return Err(code);
        }
        if !matches!(fold.outcome, FoldOutcome::Folded(_)) {
            return Err(RefusalCode::ConflictingSemanticEffects);
        }
        let roots = ResultingRoots {
            ref_root: self.digest(2),
            forge_position_root: self.digest(3),
            outcome_index_root: self.digest(4),
            retention_root: basis.body().retention_root,
            outbox_root: self.digest(5),
            policy_epoch: basis.body().policy_epoch,
            batch_evidence_root: self.digest(6),
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
        DigestAlgorithmId::try_new(1).expect("non-zero algorithm id"),
        DigestBytes::try_new(&[seed; 32]).expect("32-byte test digest"),
    )
}

fn principal_snapshot() -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(1).expect("non-zero algorithm id"),
        fgit_types::CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[15; 32]).expect("32-byte test digest"),
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
    ) -> Result<ValidatedClosure, RefusalCode> {
        Ok(ValidatedClosure {
            object_closure_root: digest(14),
            objects: BTreeSet::new(),
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
    validate_receive(&request, None, &receipt, &DeleteOnlyValidator)
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
                DigestAlgorithmId::try_new(1).expect("non-zero algorithm id"),
                fgit_types::CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[41; 32]).expect("32-byte test digest"),
            ),
        },
    });
    let replayed = OutcomeLookup::Decided(TerminalOutcome {
        decision_sequence: fgit_types::DecisionSequence::FIRST,
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::ProtectedRefTransitionDenied,
            refusal_record_id: fgit_types::RefusalRecordId::from_digest(
                DigestAlgorithmId::try_new(1).expect("non-zero algorithm id"),
                fgit_types::CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[42; 32]).expect("32-byte test digest"),
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
    let mut raced = 0_usize;
    let mut compared = 0_usize;

    for member in adapters() {
        let tx_id = session_tx_id(&context, &validated, &member);
        let span = clean_operation_span(&context, &validated, &member);

        for position in 0..span {
            let store = store_with_genesis(&context);
            store.install_fault_plan(fgit_authority::FaultPlan::explicit(vec![
                FaultDirective::new(
                    OpIndex::from_raw(position),
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
            store.restart();

            // Whatever the caller saw, the authenticated stream must hold at
            // most one terminal decision for this identity, and resolution must
            // be able to answer.
            let resolved = resolve_outcome(
                &store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            );
            assert!(
                resolved.is_ok(),
                "{} / duplicate CAS at op {position}: {tx_id:?} became unresolvable",
                member.label
            );

            if let (Ok(result), Ok(OutcomeLookup::Decided(terminal))) = (&result, &resolved) {
                compared += 1;
                assert_eq!(
                    result.commands[0].terminal, *terminal,
                    "{} / duplicate CAS at op {position}: the caller was told a decision the stream does not hold",
                    member.label
                );
            }
            raced += 1;
        }
    }

    assert!(raced >= 20, "only {raced} duplicate-CAS cells ran");
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
/// own `TxId`. Ref contention is not tested here and needs a head-bound
/// projection.
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
    // on ref policy owned by the absent head-bound projection, so it is not
    // asserted; that one command yields one status derived from a decision at
    // all is a property of `command_statuses`, which deliberately has no route
    // from a pack receipt.
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
