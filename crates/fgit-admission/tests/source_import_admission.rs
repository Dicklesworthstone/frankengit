#![forbid(unsafe_code)]
//! Source-import admission: a verified closure with no pack (`frankengit-e4en`).
//!
//! A node importing an existing repository has already established its refs and
//! object closure by its own means and has no pack to quarantine.
//! `validate_receive` refuses any non-delete command without a
//! [`QuarantinedPack`], and `ValidatedReceive`'s fields are private so a caller
//! cannot manufacture one. That guard is correct, and this bead does not touch
//! it — it adds a second, honestly typed way in.
//!
//! # The claim, and how it is tested
//!
//! **A source import of a given set of refs must produce exactly the decision a
//! push of those refs would.** Not a similar one: the same transaction
//! identity, the same commit record, the same authority head. Anything less
//! would mean canonical history remembers how a repository arrived, which it
//! must not.
//!
//! [`a_source_import_and_a_push_of_the_same_refs_leave_identical_authority_heads`]
//! asserts that by running both paths over two identically-constructed stores
//! and comparing the **whole authority head body** afterwards — which carries
//! `latest_committed_rcr_id`, so RCR identity is compared rather than merely
//! the ref state.
//!
//! # Why the comparison deletes rather than creates
//!
//! A create through receive-pack legitimately requires a `QuarantinedPack`, and
//! `QuarantinedPack` has no public constructor — it comes from real pack bytes
//! read in quarantine. Fabricating one in a test would be the same counterfeit
//! this bead exists to avoid, one layer down.
//!
//! A delete needs no pack on **either** path, so it is the shape where the two
//! are genuinely comparable, and the comparison is real rather than staged.
//! The create — the shape `fg028a` actually imports — is covered on its own by
//! [`a_source_import_creates_a_ref_with_no_pack_at_all`], with no push twin
//! because a packless push of a create is precisely what stays forbidden.
//!
//! # Discrimination
//!
//! Both paths reaching the same answer is *entailed* by the shared core
//! (`lower_ref_update`, `plan_session`, `plan_publication`, the publication
//! helpers), and entailment is not discrimination. The experiment that would
//! discriminate is recorded on `frankengit-e4en`: mutate one branch of the
//! shared core and **both** this suite and the receive-pack corpus must fail. A
//! mutation that breaks only one would show the paths had forked. That
//! experiment belongs to the central batch verify; nothing here claims it has
//! been observed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionEvidence, AdmissionLimits,
    CanonicalAdmissionProjection, CanonicalAdmissionStore, CanonicalRefState, CommitEvidence,
    PermittedObjectClosure, QuarantineValidator, RefusalMaterialization, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, ValidatedReceive,
    ValidatedSourceImport, admit_validated_receive, admit_validated_source_import,
    canonical_ref_state_root, permitted_object_closure_root, validate_receive,
    validate_source_import,
};
use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, IdempotencyKey, MemoryAuthorityStore, OutcomeLookup,
    StoreInstanceId, initialize_repository, resolve_outcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_reference::intent::TransactionRequest;
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitOid, HeadGeneration, PolicyEpoch,
    PrincipalId, PrincipalSnapshotId, RefName, RefusalCode, RegistryEpoch, RepositoryId, TenantId,
    TxId,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveEvent, ReceiveLimits, ReceivePack, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const MAIN_OID: &str = "2222222222222222222222222222222222222222";
const IMPORTED_OID: &str = "4444444444444444444444444444444444444444";
const MAIN_REF: &[u8] = b"refs/heads/main";

fn live_deadline() -> impl FnMut() -> bool {
    || true
}

const IMPORTED_REF: &[u8] = b"refs/heads/imported";

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

// ---------------------------------------------------------------------------
// Fixtures
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
        head_key: HeadKey::new(b"fg/head/e4en-source-import".to_vec()).expect("valid head key"),
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

struct DeleteOnlyValidator;

impl QuarantineValidator for DeleteOnlyValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
        _deadline: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        empty_closure()
    }
}

fn empty_closure() -> Result<ValidatedClosure, RefusalCode> {
    let objects = BTreeSet::new();
    let object_closure_root =
        permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone()))?;
    Ok(ValidatedClosure {
        object_closure_root,
        objects,
    })
}

/// A closure that covers exactly the objects an import established.
fn closure_over(objects: &[GitOid]) -> ValidatedClosure {
    let objects: BTreeSet<GitOid> = objects.iter().copied().collect();
    let object_closure_root =
        permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone()))
            .expect("closure root");
    ValidatedClosure {
        object_closure_root,
        objects,
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

fn parse_request(line: Vec<u8>) -> ReceiveRequest {
    let mut machine = ReceivePack::new(wire_context()).expect("machine");
    machine
        .push_packet(Packet::Data(line))
        .expect("command must parse");
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    (**request).clone()
}

fn command_line(old: &str, new: &str, name: &[u8]) -> Vec<u8> {
    let mut line = format!("{old} {new} {}", String::from_utf8_lossy(name)).into_bytes();
    line.push(0);
    line.extend_from_slice(b"report-status delete-refs atomic");
    line
}

/// A push deleting `refs/heads/main`. Needs no pack, which is what makes it
/// comparable against the source-import path.
fn push_deleting_main() -> ValidatedReceive {
    let request = parse_request(command_line(MAIN_OID, ZERO, MAIN_REF));
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

/// The same delete, arriving as a source import.
fn import_deleting_main() -> ValidatedSourceImport {
    let updates = vec![SourceRefUpdate {
        old: oid(MAIN_OID),
        new: oid(ZERO),
        ref_name: MAIN_REF.to_vec(),
    }];
    let receipt = SourceImportReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        delete_only: true,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    validate_source_import(&updates, &receipt, empty_closure().expect("empty closure"))
        .expect("a source import over a covering closure is admissible")
}

struct CommitmentStore {
    refs: Mutex<BTreeMap<Digest, CanonicalRefState>>,
    closures: Mutex<BTreeMap<Digest, PermittedObjectClosure>>,
}

impl Default for CommitmentStore {
    fn default() -> Self {
        Self {
            refs: Mutex::new(BTreeMap::new()),
            closures: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Clone, Default)]
struct StagingStore(Arc<CommitmentStore>);

impl CanonicalAdmissionStore for StagingStore {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.0
            .refs
            .lock()
            .expect("fixture staging mutex")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        self.0
            .refs
            .lock()
            .expect("fixture staging mutex")
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
            .expect("fixture staging mutex")
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
            .expect("fixture staging mutex")
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
            detail: "e4en source-import corpus".to_owned(),
            evidence_root: digest(13),
        })
    }
}

/// A store whose genesis head names a resolvable ref root, plus the production
/// projection rooted in it. Two calls produce independent stores holding
/// identical state.
fn setup(
    context: &AdmissionContext,
    standing: &[(&[u8], GitOid)],
) -> (
    MemoryAuthorityStore,
    CanonicalAdmissionProjection<StagingStore, StubEvidence>,
) {
    let mut refs = BTreeMap::new();
    for (name, oid) in standing {
        refs.insert(RefName::try_new(name).expect("fixture ref name"), *oid);
    }
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(57));
    initialize_repository(&store, &context.head_key, &body).expect("genesis head initializes");
    (
        store,
        CanonicalAdmissionProjection::new(staging, StubEvidence),
    )
}

/// The authority head as it stands, read back through authentication.
fn head_body(store: &MemoryAuthorityStore, key: &HeadKey) -> RepositoryAuthorityHeadBody {
    let HeadRead::Present(receipt) = store.read_head(key).expect("head reads") else {
        panic!("the repository head must be present");
    };
    store
        .authenticate_head_receipt(&receipt)
        .expect("the store authenticates its own receipt")
        .body()
        .expect("the authenticated head decodes")
}

fn committed_terminal(store: &MemoryAuthorityStore, context: &AdmissionContext, tx_id: TxId) {
    let resolved = resolve_outcome(
        store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .unwrap_or_else(|error| panic!("{tx_id:?} must resolve, got {error}"));
    let OutcomeLookup::Decided(terminal) = resolved else {
        panic!("{tx_id:?} was left undecided: {resolved:?}");
    };
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "expected a committed decision, got {:?}",
        terminal.outcome
    );
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

/// A source import and a push of the same refs leave the authority in
/// **byte-identical** states.
///
/// The whole head body is compared, not just the ref root, so this covers
/// `latest_committed_rcr_id` — the identity of the commit record each path
/// produced — along with the decision sequence and every evidence root. If the
/// two paths lowered differently, sealed differently, or materialized
/// differently, one of those fields would diverge.
///
/// The transaction identities are compared too, and that is the sharper half:
/// `TxId` derives from the sealed semantic request, so equal identities mean
/// the two paths built the *same request*, not merely requests that happened to
/// have the same effect.
#[test]
fn a_source_import_and_a_push_of_the_same_refs_leave_identical_authority_heads() {
    let context = context(b"e4en-equivalence");
    let standing = [(MAIN_REF, oid(MAIN_OID))];

    let (push_store, push_projection) = setup(&context, &standing);
    let pushed = admit_validated_receive(
        &push_store,
        &context,
        &push_deleting_main(),
        AdmissionLimits::default(),
        &push_projection,
    )
    .expect("the packless delete is admissible over receive-pack");

    let (import_store, import_projection) = setup(&context, &standing);
    let imported = admit_validated_source_import(
        &import_store,
        &context,
        &import_deleting_main(),
        AdmissionLimits::default(),
        &import_projection,
    )
    .expect("the same delete is admissible as a source import");

    assert_eq!(
        pushed.session.tx_ids, imported.session.tx_ids,
        "the two paths sealed different transaction identities for the same refs, so \
         they did not build the same semantic request and one canonical history has \
         been split in two"
    );
    committed_terminal(&push_store, &context, pushed.session.tx_ids[0]);
    committed_terminal(&import_store, &context, imported.session.tx_ids[0]);

    let after_push = head_body(&push_store, &context.head_key);
    let after_import = head_body(&import_store, &context.head_key);
    assert_eq!(
        after_push, after_import,
        "the two paths left different authority heads for the same refs; canonical \
         history must record what the repository holds, not how it arrived"
    );
    assert_ne!(
        after_push.ref_root,
        genesis(&context).ref_root,
        "neither path moved the ref root off its genesis value, so the heads could be \
         equal merely because nothing happened"
    );
}

/// A source import creates a ref with no pack anywhere in sight.
///
/// This is the shape `fg028a` imports and the one receive-pack cannot express:
/// a create carrying objects the import path already established. There is no
/// push twin here **by design** — a packless push of a create is exactly what
/// stays forbidden, and the test below asserts it still is.
#[test]
fn a_source_import_creates_a_ref_with_no_pack_at_all() {
    let context = context(b"e4en-create");
    let (store, projection) = setup(&context, &[]);

    let updates = vec![SourceRefUpdate {
        old: oid(ZERO),
        new: oid(IMPORTED_OID),
        ref_name: IMPORTED_REF.to_vec(),
    }];
    let receipt = SourceImportReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 1,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(&updates, &receipt, closure_over(&[oid(IMPORTED_OID)]))
        .expect("an import whose closure covers the object it names is admissible");

    let result = admit_validated_source_import(
        &store,
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    )
    .expect("a source-import create reaches a decision");

    committed_terminal(&store, &context, result.session.tx_ids[0]);
}

/// The provenance is a distinct type, and it says where the objects came from.
///
/// The strong form of this is enforced by the compiler and cannot be asserted
/// at runtime: [`ValidatedSourceImport::receipt`] returns a
/// [`SourceImportReceipt`], there is no conversion from one receipt to the
/// other, and nothing in the crate can produce a `ValidatedReceive` from an
/// import. What is checkable here is that the provenance survives admission
/// intact rather than being flattened into a quarantine-shaped claim.
#[test]
fn a_source_import_carries_its_own_provenance() {
    let imported = import_deleting_main();
    assert_eq!(
        imported.receipt().origin,
        SourceImportOrigin::LocalGitDirectory,
        "the import lost the origin it was constructed with"
    );
    assert_eq!(
        imported.receipt().object_format,
        GitObjectFormat::Sha1,
        "the import lost its object format"
    );
    assert_eq!(imported.updates().len(), 1, "the import lost its updates");
}

/// The forbidden case: receive-pack still refuses a create with no pack.
///
/// This is the guard `e4en` must not weaken. If adding the source-import
/// constructor had made this pass, the new path would be a hole in the old one
/// rather than a second door.
#[test]
fn receive_pack_still_refuses_a_create_with_no_quarantined_pack() {
    let request = parse_request(command_line(ZERO, IMPORTED_OID, IMPORTED_REF));
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: false,
    };
    let refused = validate_receive(
        &request,
        None,
        &receipt,
        &DeleteOnlyValidator,
        &mut live_deadline(),
    );
    assert_eq!(
        refused.expect_err("a create with no quarantined pack must be refused"),
        RefusalCode::ObjectClosureIncomplete,
        "the receive-pack quarantine requirement changed"
    );
}

/// The permitted twin of the case above: a delete-only push still admits with
/// no pack.
///
/// Paired with it deliberately. A refusal test alone cannot distinguish "the
/// guard works" from "this path refuses everything now".
#[test]
fn a_delete_only_push_still_admits_with_no_pack() {
    let request = parse_request(command_line(MAIN_OID, ZERO, MAIN_REF));
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
    .expect("a delete-only receive must still be admissible without a pack");
}

/// A source import is not "trust the caller": a ref naming an object the
/// closure does not cover is refused.
///
/// This is what stops the new constructor from being a way to publish a ref
/// pointing at an object no evidence covers — the exact failure quarantine
/// validation exists to prevent. Without it, the typed provenance would be
/// honest labelling on an unchecked path.
#[test]
fn a_source_import_whose_closure_misses_a_named_object_is_refused() {
    let updates = vec![SourceRefUpdate {
        old: oid(ZERO),
        new: oid(IMPORTED_OID),
        ref_name: IMPORTED_REF.to_vec(),
    }];
    let receipt = SourceImportReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    // The closure covers a different object than the ref names.
    let refused = validate_source_import(&updates, &receipt, closure_over(&[oid(MAIN_OID)]));
    assert_eq!(
        refused.expect_err("an import naming an uncovered object must be refused"),
        RefusalCode::ObjectClosureIncomplete,
        "the source-import constructor accepted a ref whose object no closure covers"
    );

    // The permitted twin: the same update with a covering closure is admitted,
    // so the refusal above is attributable to coverage rather than to a
    // constructor that refuses everything.
    validate_source_import(&updates, &receipt, closure_over(&[oid(IMPORTED_OID)]))
        .expect("the same update with a covering closure must be admissible");
}

/// A source import whose declared shape disagrees with its updates is refused
/// before the authority is touched.
///
/// The store is left with no head, so any path that reached it would fail
/// loudly and differently.
#[test]
fn a_source_import_whose_receipt_contradicts_its_updates_is_refused() {
    let context = context(b"e4en-shape-mismatch");
    let headless = MemoryAuthorityStore::new(StoreInstanceId::from_raw(58));
    let (_, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);

    let updates = vec![SourceRefUpdate {
        old: oid(MAIN_OID),
        new: oid(ZERO),
        ref_name: MAIN_REF.to_vec(),
    }];
    // The updates delete, but the receipt claims otherwise.
    let receipt = SourceImportReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(&updates, &receipt, empty_closure().expect("closure"))
        .expect("closure coverage is satisfied; the shape disagreement is caught at admission");

    let refused = admit_validated_source_import(
        &headless,
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    );
    let error = refused.expect_err("a receipt that contradicts its own updates must be refused");
    assert!(
        matches!(
            error,
            AdmissionError::MaterializationMismatch("source-import delete-only receipt")
        ),
        "the refusal must name WHICH receipt claim disagreed, got {error:?}. This assertion was \
         originally an is_err() check, which could not tell this apart from HeadAbsent, \
         InvalidLimit, or any other error the path might start returning — and the store here is \
         headless precisely so a reordering that reached the authority would produce a different \
         one. AdmissionError is not PartialEq, which is why the weak form was reached for; \
         matches! names the variant and its static label without needing it"
    );
}

// ---------------------------------------------------------------------------
// AdmissionLimits — three refusal axes in one condition (frankengit-dw7i)
// ---------------------------------------------------------------------------
//
// `AdmissionLimits::validate` is the first thing `plan_session` calls, before
// any store contact. Every probe below therefore runs against a **headless**
// store: if the limit check were ever reordered after the authority read, these
// would fail with `HeadAbsent` instead, which is a louder and more useful
// failure than a silent reordering.

/// Limits that are valid apart from the one field under test.
const fn limits(max_commands: usize, max_cas_replans: usize) -> AdmissionLimits {
    AdmissionLimits {
        max_commands,
        max_cas_replans,
    }
}

/// A store that was never initialized, so any authority contact fails loudly.
fn headless() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(71))
}

#[test]
fn a_zero_command_limit_is_refused() {
    let context = context(b"dw7i-zero-commands");
    let (_, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    let refusal = admit_validated_source_import(
        &headless(),
        &context,
        &import_deleting_main(),
        limits(0, 16),
        &projection,
    )
    .expect_err("a session permitted to carry no commands must be refused");
    assert!(
        matches!(refusal, AdmissionError::InvalidLimit),
        "a zero command limit must refuse as an invalid limit, before any authority contact, \
         got {refusal:?}"
    );
}

#[test]
fn a_command_limit_above_the_intent_slice_is_refused() {
    let context = context(b"dw7i-over-64");
    let (_, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    let refusal = admit_validated_source_import(
        &headless(),
        &context,
        &import_deleting_main(),
        limits(65, 16),
        &projection,
    )
    .expect_err("a command limit past the 64-intent slice must be refused");
    assert!(
        matches!(refusal, AdmissionError::InvalidLimit),
        "a command limit past the intent slice must refuse as an invalid limit, got {refusal:?}"
    );
}

#[test]
fn a_zero_replan_budget_is_refused() {
    let context = context(b"dw7i-zero-replans");
    let (_, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    let refusal = admit_validated_source_import(
        &headless(),
        &context,
        &import_deleting_main(),
        limits(64, 0),
        &projection,
    )
    .expect_err("a session with no replan budget cannot survive a lost CAS and must be refused");
    assert!(
        matches!(refusal, AdmissionError::InvalidLimit),
        "the replan budget is the third axis of one condition and must refuse on its own, \
         got {refusal:?}"
    );
}

/// **The permitted twin at the exact boundary.** A 64-command limit is
/// admissible — it is the largest session the intent slice can express.
///
/// Stated honestly: this boundary is **already** exercised incidentally, because
/// `AdmissionLimits::default()` *is* `max_commands: 64`, so essentially every
/// other test in the crate would fail if the guard were tightened to `>= 64`.
/// What this test adds is **diagnosis, not detection** — a failure here names
/// the boundary, where the incidental failures name unrelated properties. The
/// same distinction applies as on `frankengit-33ib`, where the byte-budget
/// boundary turned out to be protected by a shared fixture sitting on it.
#[test]
fn a_command_limit_at_exactly_the_intent_slice_is_admitted() {
    let context = context(b"dw7i-exactly-64");
    let (store, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    admit_validated_source_import(
        &store,
        &context,
        &import_deleting_main(),
        limits(64, 16),
        &projection,
    )
    .expect("a limit of exactly the intent-slice width must be expressible");
}

/// The other end of both ranges, so the boundary case above is not passing
/// merely because the validator accepts any non-zero pair it is handed.
#[test]
fn the_smallest_workable_limits_are_admitted() {
    let context = context(b"dw7i-smallest");
    let (store, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    admit_validated_source_import(
        &store,
        &context,
        &import_deleting_main(),
        limits(1, 1),
        &projection,
    )
    .expect("one command with one replan attempt must be expressible");
}

// ---------------------------------------------------------------------------
// HeadAbsent — the authority has no head at all
// ---------------------------------------------------------------------------

/// An admission against a repository that was never initialized is refused as
/// `HeadAbsent`.
///
/// This is the *second* stage of the ordering the limit probes above rely on:
/// with valid limits and a well-formed input, the session gets past planning,
/// seals, finds no decision, and then fails reading the basis. Together the two
/// sets pin that limits are checked before the authority and the basis read
/// after it.
#[test]
fn an_admission_against_an_uninitialized_repository_is_refused() {
    let context = context(b"dw7i-head-absent");
    let (_, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    let refusal = admit_validated_source_import(
        &headless(),
        &context,
        &import_deleting_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect_err("a repository with no authority head cannot admit anything");
    assert!(
        matches!(refusal, AdmissionError::HeadAbsent),
        "an uninitialized repository must refuse as HeadAbsent rather than by any later failure, \
         got {refusal:?}"
    );
}

/// The permitted twin: the identical import against an initialized repository
/// reaches a decision.
///
/// Without it, the refusal above is attributable to the import rather than to
/// the missing head.
#[test]
fn the_same_import_against_an_initialized_repository_is_admitted() {
    let context = context(b"dw7i-head-present");
    let (store, projection) = setup(&context, &[(MAIN_REF, oid(MAIN_OID))]);
    let result = admit_validated_source_import(
        &store,
        &context,
        &import_deleting_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("the same import against an initialized repository reaches a decision");
    committed_terminal(&store, &context, result.session.tx_ids[0]);
}
