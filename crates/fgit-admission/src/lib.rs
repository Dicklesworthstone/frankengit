#![forbid(unsafe_code)]
//! Receive-pack admission from a validated quarantine to one authenticated
//! terminal decision per sealed transaction.
//!
//! This crate owns the sequencing boundary between `fgit-wire`'s SANS-I/O
//! receive-pack parser and the repository authority head.  It deliberately
//! owns neither a ref database nor pack-object storage.  A caller supplies an
//! [`AdmissionProjection`] that is rooted in the authenticated head it was
//! asked to evaluate.  That is the narrow seam for the still-separate ref-tree
//! materializer; it prevents a gateway-local map from becoming a second source
//! of repository truth.
//!
//! An atomic receive session seals one request containing every command.  A
//! non-atomic session derives one bounded child idempotency key per wire-order
//! command and returns that ordered mapping, so retries reconstruct the same
//! per-ref transactions.  In both cases a report is formed only after
//! [`fgit_authority::resolve_outcome`] has authenticated a terminal decision.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore, CumulativeOutcomes,
    HeadKey, HeadRead, IdempotencyKey, OutcomeFailure, OutcomeLookup, SealAttempt, SealFailure,
    collect_cumulative_outcomes, collect_cumulative_outcomes_async, initialize_repository,
    seal_request,
};
use fgit_chronicle::{
    PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots, publish,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, RefusalRecordBody,
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, body_id, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_pack::QuarantinedPack;
use fgit_reference::effect::{FoldBasis, FoldOutcome, RefEffect};
use fgit_reference::intent::{
    DurabilityProfile, IdempotencyKey as ModelIdempotencyKey, Intent, RefIntent, Statement,
    TransactionRequest,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_txn::{IntentEvaluator, TransactionFoldReport};
use fgit_types::{
    AsciiSlug, DecisionOutcome, Digest, DomainTag, PrincipalId, PrincipalSnapshotId, RefName,
    RefusalCode, RefusalRecordId, RepositoryId, RepositorySequence, SchemaFamily, SchemaId,
    TenantId, TransactionSealId, TxId,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveCommandStatus, ReceiveError, ReceiveRequest, UnpackStatus,
    report_status,
};
use fgit_wire::{AnyGitOid, GitObjectFormat, Packet};

pub mod evidence;

/// Schema for a receive-pack ref transaction produced by this admission layer.
pub const RECEIVE_ADMISSION_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static("receive-admission"), 1, 0);

/// Bounds enforced before creating per-command work or retrying a stale plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
    /// Largest receive command list this layer lowers into transaction intents.
    ///
    /// The current `fgit-txn` request vocabulary has a 64-intent final slice,
    /// so accepting more here would only defer a resource refusal until after
    /// allocation and sealing.
    pub max_commands: usize,
    /// Largest number of re-plans after losing a head compare-and-exchange.
    pub max_cas_replans: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_commands: 64,
            max_cas_replans: 16,
        }
    }
}

impl AdmissionLimits {
    const fn validate(self) -> Result<(), AdmissionError> {
        if self.max_commands == 0 || self.max_commands > 64 || self.max_cas_replans == 0 {
            return Err(AdmissionError::InvalidLimit);
        }
        Ok(())
    }
}

/// Repository and authenticated-principal fields that do not arrive in the
/// receive wire protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionContext {
    /// Authority slot for the one repository head this call may publish.
    pub head_key: HeadKey,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Target repository.
    pub repository_id: RepositoryId,
    /// Principal authenticated by the gateway before this call.
    pub principal_id: PrincipalId,
    /// Client retry key for the whole receive session.
    pub idempotency_key: IdempotencyKey,
    /// Repository-native object identity format.
    pub object_format: GitObjectFormat,
}

#[derive(Clone, Debug)]
struct LoweredRequest {
    semantic: fgit_authority::SemanticRequest,
    idempotency_key: IdempotencyKey,
}

/// Evidence that the quarantined pack's object closure was validated.
///
/// The receipt intentionally has no pack bytes.  A pack reader/object-store
/// adapter retains its own quarantine ownership and exposes only the bounded
/// closure commitment needed for a decision record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedClosure {
    /// Root over the validated closure available to the proposed ref updates.
    pub object_closure_root: Digest,
    /// Native object identities available to the transaction evaluator.
    pub objects: BTreeSet<fgit_types::GitOid>,
}

/// Validates a structural `fgit-wire` quarantine for a ref decision.
///
/// The implementation belongs beside the pack/object store; this crate never
/// parses a pack or reaches into quarantine bytes.
pub trait QuarantineValidator {
    /// Returns a closure witness, or a terminal admission refusal.
    fn validate(
        &self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
    ) -> Result<ValidatedClosure, RefusalCode>;
}

/// Receive-pack input after a pack-aware validator produced the closure witness.
///
/// The fields are private so callers cannot turn a mere structural receive
/// completion into an authority-admissible input.  Construct it with
/// [`validate_receive`], while `fgit-wire` still owns the `QuarantinedPack`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReceive {
    request: ReceiveRequest,
    receipt: QuarantineReceipt,
    closure: ValidatedClosure,
}

impl ValidatedReceive {
    /// The command request whose semantics were validated.
    #[must_use]
    pub const fn request(&self) -> &ReceiveRequest {
        &self.request
    }

    /// The structural receipt from the same validation handoff.
    #[must_use]
    pub const fn receipt(&self) -> &QuarantineReceipt {
        &self.receipt
    }
}

/// Validates closure and object availability for a quarantined pack.
///
/// Non-delete commands without that pack are refused before a seal exists;
/// deleting refs is the permitted near-identical path.
pub fn validate_receive<Validator>(
    request: &ReceiveRequest,
    pack: Option<&QuarantinedPack>,
    receipt: &QuarantineReceipt,
    validator: &Validator,
) -> Result<ValidatedReceive, RefusalCode>
where
    Validator: QuarantineValidator + ?Sized,
{
    if request.requires_pack() && pack.is_none() {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    let closure = validator.validate(request, pack, receipt)?;
    if request
        .commands
        .iter()
        .any(|command| !command.new.is_zero() && !closure.objects.contains(&command.new))
    {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    Ok(ValidatedReceive {
        request: request.clone(),
        receipt: receipt.clone(),
        closure,
    })
}

// --- source-import admission ------------------------------------------------
//
// A node importing an existing repository has already proven its refs and
// object closure by its own means, and has no pack to quarantine. Receive-pack
// admission cannot express that: `validate_receive` requires a
// `QuarantinedPack` for any non-delete command, and `ValidatedReceive`'s fields
// are private precisely so a caller cannot manufacture one.
//
// That guard is correct and stays. What was missing is a second, honestly typed
// way in — not a hole in the first. So the provenance is a distinct type rather
// than a synthesized `QuarantineReceipt`: an audit trail that reported
// "quarantine validated this" about objects no quarantine ever saw would be a
// counterfeit witness, and the guard would be intact in form while defeated in
// substance.
//
// What the two paths DO share is the decision: the same lowering, the same
// seal, the same fold, the same materialization, the same CAS. A source import
// of a given set of refs produces the same decision record as a push of those
// refs, because after admission there is nothing left to distinguish them —
// canonical history records what the repository holds, not how it arrived.

/// Where an imported source came from.
///
/// Typed so the provenance is recorded rather than inferred. Non-exhaustive
/// because new import origins are expected and must not be a breaking change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceImportOrigin {
    /// An ordinary local Git directory, bare or with a worktree, whose native
    /// objects the import path read and verified before placing them in the
    /// node's fabric.
    ///
    /// Deliberately *not* "a store this node already controls". The two differ
    /// in who did the verifying, and that is the entire content of a
    /// provenance label: a directory the node merely has filesystem access to
    /// has vouched for nothing, so the import path's own verification is what
    /// this origin records. Naming it after the destination rather than the
    /// source would overstate the evidence in exactly the way a forged
    /// quarantine receipt would.
    LocalGitDirectory,
}

/// Evidence that an import path established a source's object closure by its
/// own means, with no pack to quarantine.
///
/// The deliberate sibling of [`QuarantineReceipt`], and deliberately **not**
/// convertible into one. Both record what an admission's closure evidence
/// rests on; they disagree about what did the establishing, and that
/// disagreement is the point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceImportReceipt {
    /// The repository-native object domain of the imported objects.
    pub object_format: GitObjectFormat,
    /// Number of objects the import path established.
    pub object_count: u32,
    /// Whether the update list is expected to delete every ref it names.
    ///
    /// Carried for the same reason the quarantine receipt carries it: admission
    /// cross-checks the declared shape against the updates, so a caller whose
    /// receipt and update list disagree is refused rather than believed.
    pub delete_only: bool,
    /// Where the objects came from.
    pub origin: SourceImportOrigin,
}

/// One ref update in a source import.
///
/// The same `(old, new, name)` shape the authority lowers from, in its own type
/// so an import never presents itself as a wire command. A `ReceiveRequest`
/// carries client capabilities and push options; a source import is not a
/// client request, and synthesizing one would be the same counterfeit as
/// forging a quarantine receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRefUpdate {
    /// Expected predecessor, or all-zero to require the ref be absent.
    pub old: AnyGitOid,
    /// Proposed new object, or all-zero to delete the ref.
    pub new: AnyGitOid,
    /// Full Git ref name, validated during lowering.
    pub ref_name: Vec<u8>,
}

/// Source-import input after the import path established its closure.
///
/// The fields are private for the same reason [`ValidatedReceive`]'s are: a
/// caller must not be able to turn a set of refs it merely holds into an
/// authority-admissible input. Construct it with [`validate_source_import`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSourceImport {
    updates: Vec<SourceRefUpdate>,
    receipt: SourceImportReceipt,
    closure: ValidatedClosure,
}

impl ValidatedSourceImport {
    /// The ref updates whose semantics were validated.
    #[must_use]
    pub fn updates(&self) -> &[SourceRefUpdate] {
        &self.updates
    }

    /// The source-import provenance from the same validation handoff.
    ///
    /// Returns a [`SourceImportReceipt`], never a [`QuarantineReceipt`]: a
    /// caller reading provenance off an admission learns which path admitted
    /// it from the type alone.
    #[must_use]
    pub const fn receipt(&self) -> &SourceImportReceipt {
        &self.receipt
    }
}

/// Bind an already-verified closure and its ref updates into an admissible
/// source import.
///
/// The closure is supplied rather than computed: establishing it is the import
/// path's job, and this crate never reads objects. What is enforced here is the
/// same completeness rule `validate_receive` enforces — **every ref this import
/// proposes must name an object the closure actually covers.** Without it a
/// caller could publish a ref pointing at an object no evidence covers, which
/// is the exact failure quarantine validation exists to prevent, and the reason
/// this constructor is not simply "trust the caller".
///
/// This does not weaken receive-pack admission in any way:
/// [`validate_receive`] still refuses a non-delete command with no
/// [`QuarantinedPack`], and nothing here can produce a [`ValidatedReceive`].
pub fn validate_source_import(
    updates: &[SourceRefUpdate],
    receipt: &SourceImportReceipt,
    closure: ValidatedClosure,
) -> Result<ValidatedSourceImport, RefusalCode> {
    if updates
        .iter()
        .any(|update| !update.new.is_zero() && !closure.objects.contains(&update.new))
    {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    Ok(ValidatedSourceImport {
        updates: updates.to_vec(),
        receipt: receipt.clone(),
        closure,
    })
}

/// One ref update, viewed uniformly regardless of which path supplied it.
#[derive(Clone, Copy, Debug)]
struct RefUpdateView<'a> {
    old: AnyGitOid,
    new: AnyGitOid,
    ref_name: &'a [u8],
}

impl RefUpdateView<'_> {
    /// The receive-pack zero-sentinel rule: an all-zero new ID deletes.
    fn deletes(&self) -> bool {
        self.new.is_zero() && !self.old.is_zero()
    }
}

/// What the decision core needs from an admission input, with the provenance
/// already reduced to the facts that bear on the decision.
///
/// This is the seam that lets receive-pack and source-import admission share
/// one core. Everything that differs between the paths — how the closure was
/// established, what type carries it, what a caller had to prove — has been
/// settled by the time an input exists. What remains is identical, and that is
/// why the two produce identical decisions for the same refs.
struct AdmissionInput<'a> {
    updates: Vec<RefUpdateView<'a>>,
    push_options: &'a [Vec<u8>],
    object_format: GitObjectFormat,
    atomic: bool,
    deletes_only: bool,
    declared_delete_only: bool,
    /// Names the receipt whose declared shape disagreed, so a mismatch refusal
    /// says which provenance made the claim.
    delete_only_label: &'static str,
    closure: &'a ValidatedClosure,
}

/// View a validated receive-pack session as an admission input.
fn receive_input(validated: &ValidatedReceive) -> AdmissionInput<'_> {
    let updates: Vec<RefUpdateView<'_>> = validated
        .request
        .commands
        .iter()
        .map(|command| RefUpdateView {
            old: command.old,
            new: command.new,
            ref_name: &command.ref_name,
        })
        .collect();
    AdmissionInput {
        updates,
        push_options: &validated.request.push_options,
        object_format: validated.receipt.object_format,
        atomic: validated.request.has_capability(b"atomic"),
        deletes_only: validated.request.deletes_only(),
        declared_delete_only: validated.receipt.delete_only,
        delete_only_label: "quarantine delete-only receipt",
        closure: &validated.closure,
    }
}

/// View a validated source import as an admission input.
///
/// Atomic by construction: an import publishes a repository's refs as one
/// state, and admitting them as independent transactions would allow a partial
/// import to become canonical. There is no client capability negotiation to
/// consult, so the choice is made here rather than read from a request — and
/// made in the safe direction.
fn source_import_input(validated: &ValidatedSourceImport) -> AdmissionInput<'_> {
    let updates: Vec<RefUpdateView<'_>> = validated
        .updates
        .iter()
        .map(|update| RefUpdateView {
            old: update.old,
            new: update.new,
            ref_name: &update.ref_name,
        })
        .collect();
    let deletes_only = !updates.is_empty() && updates.iter().all(RefUpdateView::deletes);
    AdmissionInput {
        updates,
        // A source import carries no client push options; there is no client.
        push_options: &[],
        object_format: validated.receipt.object_format,
        atomic: true,
        deletes_only,
        declared_delete_only: validated.receipt.delete_only,
        delete_only_label: "source-import delete-only receipt",
        closure: &validated.closure,
    }
}

/// Admit a verified source import against the authority.
///
/// The source-import sibling of [`admit_validated_receive`], and it reaches the
/// authority through the same driver. For the same refs and the same closure it
/// produces the same lowered request, the same transaction identity, the same
/// commit record, and the same head transition as a push would — because after
/// admission the two are the same event, and canonical history records what the
/// repository holds rather than how it arrived.
pub fn admit_validated_source_import<S, Projection>(
    store: &S,
    context: &AdmissionContext,
    validated: &ValidatedSourceImport,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<AdmissionResult, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    admit_input(
        store,
        context,
        &source_import_input(validated),
        limits,
        projection,
    )
}

/// Admit a verified source import against the authority, asynchronously.
///
/// The asynchronous sibling of [`admit_validated_source_import`], for a backend
/// that implements [`AsyncAuthorityStore`] only. This is the entrypoint
/// `fgit-node`'s import path uses.
pub async fn admit_validated_source_import_async<S, Projection>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    validated: &ValidatedSourceImport,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<AdmissionResult, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    admit_input_async(
        store,
        cx,
        context,
        &source_import_input(validated),
        limits,
        projection,
    )
    .await
}

/// A read-only, head-pinned view of the materialized repository state.
///
/// All fields are immutable copies resolved from the supplied authenticated
/// head.  Owning the values is deliberate: a durable state store may return a
/// decoded immutable body rather than a borrow into a process-local map, and
/// admission must never turn such a map into a second source of truth.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdmissionSnapshot {
    /// Ref state at the authenticated basis.
    pub refs: BTreeMap<RefName, fgit_types::GitOid>,
    /// Forge stream positions at that same basis.
    pub forge_positions: BTreeMap<
        fgit_reference::intent::ForgeStreamId,
        fgit_reference::intent::ForgeStreamPosition,
    >,
    /// Retention roots at that same basis.
    pub retention: BTreeSet<fgit_reference::intent::RetentionRoot>,
    /// External-effect delivery keys at that same basis.
    pub outbox: BTreeMap<fgit_reference::intent::OutboxDeliveryKey, Digest>,
}

impl AdmissionSnapshot {
    const fn as_fold_basis(&self) -> FoldBasis<'_> {
        FoldBasis {
            refs: &self.refs,
            forge_positions: &self.forge_positions,
            retention: &self.retention,
            outbox: &self.outbox,
        }
    }
}

/// Material produced by the canonical ref-tree/policy materializer for a
/// committing transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitMaterialization {
    /// The record whose immutable identity will be bound by the decision.
    /// Its sequence and parent are assigned by `PublicationPlan`, never here.
    pub record: RepositoryCommitRecord,
    /// Resulting roots to place in the decision batch and authority head.
    pub roots: ResultingRoots,
}

/// Canonical successor bodies prepared from one folded transaction.
///
/// A caller must stage both immutable bodies before it consumes the enclosed
/// [`CommitMaterialization`].  The type keeps ref folding and RCR construction
/// in this crate while allowing an asynchronous owner of durable storage to
/// await those staging writes without rebuilding the semantic request or fold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCanonicalCommit {
    next_ref_state: CanonicalRefState,
    object_closure: PermittedObjectClosure,
    materialization: CommitMaterialization,
}

impl PreparedCanonicalCommit {
    /// Immutable successor ref state whose root is named by the materialization.
    #[must_use]
    pub const fn next_ref_state(&self) -> &CanonicalRefState {
        &self.next_ref_state
    }

    /// Immutable closure body whose root is bound by the RCR.
    #[must_use]
    pub const fn object_closure(&self) -> &PermittedObjectClosure {
        &self.object_closure
    }

    /// Root the materialization binds to [`Self::next_ref_state`].
    #[must_use]
    pub const fn ref_root(&self) -> Digest {
        self.materialization.roots.ref_root
    }

    /// Root the RCR binds to [`Self::object_closure`].
    #[must_use]
    pub const fn object_closure_root(&self) -> Digest {
        self.materialization.record.object_closure_root
    }

    /// The record and resulting roots to publish after both bodies were staged.
    #[must_use]
    pub fn into_materialization(self) -> CommitMaterialization {
        self.materialization
    }
}

/// Evidence used to construct one immutable terminal refusal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefusalMaterialization {
    /// Policy epoch that evaluated the refusal.
    pub policy_epoch: fgit_types::PolicyEpoch,
    /// Bounded, stable explanation for the record.
    pub detail: String,
    /// Root over the evidence that supports the refusal.
    pub evidence_root: Digest,
}

/// The read-only integration seam for an admission attempt.
///
/// Every method receives a [`PublicationBasis`] derived from an authenticated
/// authority receipt.  Implementors therefore must not use an advertisement,
/// a connection-local cache, or a mutable local ref table as the basis for an
/// admission decision.  Snapshotting is deliberately distinct from successor
/// materialization: a node may safely expose this exact-head read view while
/// only its asynchronous driver can stage a successor.
pub trait AdmissionSnapshotProjection {
    /// Opens a read-only projection rooted in exactly this authenticated head.
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode>;
}

/// The synchronous materialization seam for a blocking admission caller.
///
/// This trait is intentionally separate from [`AsyncAdmissionProjection`]. A
/// projection that needs asynchronous durable staging must not type-check at a
/// blocking entrypoint, where a typed staging refusal would otherwise become a
/// permanent canonical terminal decision for a retryable request.
pub trait AdmissionProjection: AdmissionSnapshotProjection {
    /// Materializes a committed fold into an RCR and its successor roots.
    ///
    /// A refusal is an evaluated terminal decision for this exact basis. An
    /// unavailable result means staging or resolving immutable material failed
    /// after the request was sealed but before a head CAS; callers must leave
    /// that transaction undecided so the same request can retry.
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure>;

    /// Supplies the policy evidence for a terminal refusal.
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode>;
}

/// Asynchronous materialization capability for an admission driver.
///
/// This trait intentionally does not extend [`AdmissionProjection`] or
/// [`AdmissionSnapshotProjection`]. An asynchronous durable projection must
/// not type-check at a blocking entrypoint, where a staging refusal would
/// otherwise become a permanent canonical terminal decision. It also loads
/// the snapshot asynchronously from the exact authenticated basis selected by
/// each CAS attempt, so a normal CAS replan cannot reuse a stale cache entry
/// or turn that race into a terminal refusal.
///
/// `Authority` and its request context are passed explicitly rather than
/// captured in a projection cache. An implementation therefore loads and
/// stages immutable bodies through the same authority operation that will
/// later select them by exact-head publication; no local materialization
/// becomes authority.
pub trait AsyncAdmissionProjection<Authority>: Sync
where
    Authority: AsyncAuthorityStore + ?Sized,
{
    /// Opens a read-only snapshot at the exact authenticated basis for this
    /// attempt. The driver invokes this again after every CAS replan.
    fn snapshot_async<'a>(
        &'a self,
        authority: &'a Authority,
        cx: &'a Authority::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a;

    /// Materializes a committing fold after the async driver has authenticated
    /// its publication basis.
    fn materialize_commit_async<'a>(
        &'a self,
        authority: &'a Authority,
        cx: &'a Authority::Context,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a;

    /// Materializes evidence for a terminal refusal before its decision can
    /// become visible through the authority-head replacement.
    fn materialize_refusal_async<'a>(
        &'a self,
        authority: &'a Authority,
        cx: &'a Authority::Context,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a;
}

/// The outcome of a projection operation before a terminal decision is
/// published.
///
/// [`Self::Refuse`] is an evaluated terminal policy result. [`Self::Unavailable`]
/// says the projection could not acquire or verify the material required to
/// decide; the driver returns an [`AdmissionError`] and publishes nothing.
/// In particular, a cancellation or durable I/O failure must not become a
/// canonical refusal solely because it occurred before publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// The projection evaluated a terminal refusal for this exact basis.
    Refuse(RefusalCode),
    /// Required material was unavailable before any terminal decision.
    Unavailable(RefusalCode),
}

/// Compatibility name for projection failures returned through the async
/// admission surface.
pub type AsyncProjectionFailure = ProjectionFailure;

/// The one canonical immutable ref-state body selected by an authority head's
/// `ref_root`.
///
/// The payload is a canonical map from validated ref names to native Git
/// object identities.  [`Encoder::write_canonical_map`] sorts by each key's
/// encoded bytes and refuses duplicate keys; the explicit codec operation is
/// the ordering rule, rather than an incidental property of `BTreeMap`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalRefState {
    refs: BTreeMap<RefName, fgit_types::GitOid>,
}

impl CanonicalRefState {
    /// Builds an immutable ref state from uniquely keyed validated refs.
    #[must_use]
    pub const fn new(refs: BTreeMap<RefName, fgit_types::GitOid>) -> Self {
        Self { refs }
    }

    /// The resolved ref map.
    #[must_use]
    pub const fn refs(&self) -> &BTreeMap<RefName, fgit_types::GitOid> {
        &self.refs
    }

    fn apply(&self, effects: &BTreeMap<RefName, RefEffect>) -> Self {
        let mut refs = self.refs.clone();
        for (name, effect) in effects {
            match effect {
                RefEffect::Set(oid) => {
                    refs.insert(name.clone(), *oid);
                }
                RefEffect::Delete => {
                    refs.remove(name);
                }
            }
        }
        Self { refs }
    }
}

impl CanonicalBody for CanonicalRefState {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/ref-state/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("ref-state");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        let entries = self
            .refs
            .iter()
            .map(|(name, oid)| (name.clone(), *oid))
            .collect::<Vec<_>>();
        out.write_canonical_map(
            "ref-state.refs",
            &entries,
            |encoder, name| encoder.write_ref_name(name),
            |encoder, oid| {
                encoder.write_git_oid(oid);
                Ok(())
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let refs = input
            .read_canonical_map(
                "ref-state.refs",
                Decoder::read_ref_name,
                Decoder::read_git_oid,
            )?
            .into_iter()
            .collect();
        Ok(Self { refs })
    }
}

/// The canonical immutable set of native objects a validated receive may use.
///
/// Elements are canonical-set encoded by their full native-object encoding,
/// including the Git hash algorithm; a SHA-1 and SHA-256 OID with overlapping
/// bytes therefore cannot alias this commitment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PermittedObjectClosure {
    objects: BTreeSet<fgit_types::GitOid>,
}

impl PermittedObjectClosure {
    /// Builds a closure from exactly the validated native object identities.
    #[must_use]
    pub const fn new(objects: BTreeSet<fgit_types::GitOid>) -> Self {
        Self { objects }
    }

    /// The native object identities permitted by this closure.
    #[must_use]
    pub const fn objects(&self) -> &BTreeSet<fgit_types::GitOid> {
        &self.objects
    }
}

impl CanonicalBody for PermittedObjectClosure {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/admission-object-closure/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("admission-object-closure");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        let objects = self.objects.iter().copied().collect::<Vec<_>>();
        out.write_canonical_set(
            "permitted-object-closure.objects",
            &objects,
            |encoder, oid| {
                encoder.write_git_oid(oid);
                Ok(())
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let objects = input
            .read_canonical_set("permitted-object-closure.objects", Decoder::read_git_oid)?
            .into_iter()
            .collect();
        Ok(Self { objects })
    }
}

/// The canonical ref delta recorded by one commit materialization.
///
/// A `None` value means deletion; a present OID means replacement.  It has a
/// separate domain from the resulting state so an old state cannot be replayed
/// where the audit trail expects a change set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalRefDelta {
    changes: BTreeMap<RefName, Option<fgit_types::GitOid>>,
}

impl CanonicalRefDelta {
    fn from_effects(effects: &BTreeMap<RefName, RefEffect>) -> Self {
        let changes = effects
            .iter()
            .map(|(name, effect)| {
                let value = match effect {
                    RefEffect::Set(oid) => Some(*oid),
                    RefEffect::Delete => None,
                };
                (name.clone(), value)
            })
            .collect();
        Self { changes }
    }
}

impl CanonicalBody for CanonicalRefDelta {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/admission-ref-delta/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("admission-ref-delta");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        let entries = self
            .changes
            .iter()
            .map(|(name, oid)| (name.clone(), *oid))
            .collect::<Vec<_>>();
        out.write_canonical_map(
            "ref-delta.changes",
            &entries,
            |encoder, name| encoder.write_ref_name(name),
            |encoder, oid| {
                encoder.write_option(oid.as_ref(), |encoder, oid| {
                    encoder.write_git_oid(oid);
                    Ok(())
                })
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let changes = input
            .read_canonical_map("ref-delta.changes", Decoder::read_ref_name, |decoder| {
                decoder.read_option("ref-delta.value", Decoder::read_git_oid)
            })?
            .into_iter()
            .collect();
        Ok(Self { changes })
    }
}

/// Computes the domain-pinned commitment used in an authority head's
/// `ref_root`.
pub fn canonical_ref_state_root(state: &CanonicalRefState) -> Result<Digest, RefusalCode> {
    canonical_body_root(state)
}

/// Computes the domain-pinned commitment recorded as an RCR object closure.
pub fn permitted_object_closure_root(
    closure: &PermittedObjectClosure,
) -> Result<Digest, RefusalCode> {
    canonical_body_root(closure)
}

fn canonical_ref_delta_root(delta: &CanonicalRefDelta) -> Result<Digest, RefusalCode> {
    canonical_body_root(delta)
}

fn canonical_body_root<Body>(body: &Body) -> Result<Digest, RefusalCode>
where
    Body: CanonicalBody,
{
    let identity =
        body_id(&CryptoBodyIdentity, body).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// Immutable backing for canonical admission commitments.
///
/// The backing is an object store, not an authority source: it stages and
/// resolves content-addressed bodies, while only the authenticated authority
/// head selects which ref-state root is canonical.  Implementations must
/// return the body named by `root`; [`CanonicalAdmissionProjection`] verifies
/// that relationship again before evaluating a request.
pub trait CanonicalAdmissionStore {
    /// Resolves a staged ref-state body by its canonical root.
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode>;

    /// Stages a ref-state body under the supplied canonical root.
    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode>;

    /// Resolves a staged permitted-object closure by its canonical root.
    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode>;

    /// Stages a permitted-object closure under its canonical root.
    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode>;
}

/// Immutable non-ref evidence consumed by admission materialization.
///
/// This is supplied by the policy/invariant/outbox owners.  The projection
/// computes the ref state, delta, and closure itself; accepting an unrelated
/// bare digest here would make this layer invent policy or effect evidence it
/// does not own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitEvidence {
    /// Principal/capability snapshot that authorized this commit.
    pub principal_snapshot_id: PrincipalSnapshotId,
    /// Root over forge events (empty for the receive-only slice).
    pub forge_event_batch_root: Digest,
    /// Root over policy evaluation evidence.
    pub policy_decision_root: Digest,
    /// Root over invariant checks for the candidate.
    pub invariant_evidence_root: Digest,
    /// Root over external-effect obligations created by this candidate.
    pub outbox_effect_root: Digest,
    /// Root over retention changes created by this candidate.
    pub retention_delta_root: Digest,
}

/// Policy and evidence owner used by the production projection.
pub trait AdmissionEvidence {
    /// Produces evidence for a committing fold at this exact basis.
    fn commit_evidence(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode>;

    /// Produces the immutable refusal evidence for this exact basis and code.
    fn refusal_evidence(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode>;
}

/// Prepare the canonical successor bodies and RCR for one folded commit.
///
/// This is pure over the exact folded request, authenticated basis, resolved
/// current ref state, validated closure, and evidence.  It does not stage or
/// publish anything.  A synchronous projection and an asynchronous durable
/// adapter therefore share the only code that turns effects into a successor
/// ref root, closure root, ref-delta root, and RCR fields.
pub fn prepare_canonical_commit(
    basis: &PublicationBasis,
    request: &TransactionRequest,
    fold: &TransactionFoldReport,
    closure: &ValidatedClosure,
    current: CanonicalRefState,
    evidence: CommitEvidence,
) -> Result<PreparedCanonicalCommit, RefusalCode> {
    let effects = fold
        .effects()
        .ok_or(RefusalCode::ConflictingSemanticEffects)?;
    if !effects.forge.is_empty() || !effects.retention.is_empty() || !effects.outbox.is_empty() {
        return Err(RefusalCode::ConflictingSemanticEffects);
    }

    let next_ref_state = current.apply(&effects.refs);
    let ref_root = canonical_ref_state_root(&next_ref_state)?;
    let object_closure = PermittedObjectClosure::new(closure.objects.clone());
    let object_closure_root = permitted_object_closure_root(&object_closure)?;
    if object_closure_root != closure.object_closure_root {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }

    let ref_delta_root = canonical_ref_delta_root(&CanonicalRefDelta::from_effects(&effects.refs))?;
    let roots = ResultingRoots {
        ref_root,
        forge_position_root: basis.body().forge_position_root,
        retention_root: basis.body().retention_root,
        outbox_root: basis.body().outbox_root,
        policy_epoch: basis.body().policy_epoch,
        compaction_generation_link: None,
    };
    let materialization = CommitMaterialization {
        record: RepositoryCommitRecord {
            repository_id: request.repository,
            // `PublicationPlan` owns final sequence and predecessor stamping.
            // These values only satisfy the complete RCR shape before it is
            // handed to that plan; they are never identified.
            repository_sequence: RepositorySequence::FIRST,
            parent_rcr_id: None,
            tx_id: request.tx_id,
            principal_snapshot_id: evidence.principal_snapshot_id,
            canonical_request_digest: request.canonical_request_digest,
            ref_delta_root,
            resulting_ref_root: roots.ref_root,
            object_closure_root,
            forge_event_batch_root: evidence.forge_event_batch_root,
            resulting_forge_position_root: roots.forge_position_root,
            policy_epoch: roots.policy_epoch,
            policy_decision_root: evidence.policy_decision_root,
            invariant_evidence_root: evidence.invariant_evidence_root,
            outbox_effect_root: evidence.outbox_effect_root,
            retention_delta_root: evidence.retention_delta_root,
        },
        roots,
    };
    Ok(PreparedCanonicalCommit {
        next_ref_state,
        object_closure,
        materialization,
    })
}

/// Production implementation of [`AdmissionProjection`].
///
/// It resolves the state selected by the supplied authenticated head, verifies
/// its content-addressed root, applies the folded ref effects, then stages the
/// successor body before returning the same successor root to chronicle.  It
/// never reads a connection-local ref map or treats staged objects as
/// canonical visibility.
#[derive(Clone, Debug)]
pub struct CanonicalAdmissionProjection<Store, Evidence> {
    store: Store,
    evidence: Evidence,
}

impl<Store, Evidence> CanonicalAdmissionProjection<Store, Evidence> {
    /// Connects a canonical immutable object store to its policy/evidence
    /// provider.  Authority-head publication remains the caller's CAS path.
    #[must_use]
    pub const fn new(store: Store, evidence: Evidence) -> Self {
        Self { store, evidence }
    }

    /// Stages canonical genesis/import state and returns the corresponding
    /// ref and closure roots.  [`initialize_canonical_repository`] is the
    /// matching root-last authority publication path.
    pub fn stage_initial_state(
        &self,
        refs: CanonicalRefState,
        closure: PermittedObjectClosure,
    ) -> Result<CanonicalCommitments, RefusalCode>
    where
        Store: CanonicalAdmissionStore,
    {
        let ref_root = canonical_ref_state_root(&refs)?;
        let object_closure_root = permitted_object_closure_root(&closure)?;
        self.store.stage_ref_state(ref_root, refs)?;
        self.store
            .stage_permitted_object_closure(object_closure_root, closure)?;
        Ok(CanonicalCommitments {
            ref_root,
            object_closure_root,
        })
    }

    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode>
    where
        Store: CanonicalAdmissionStore,
    {
        let state = self.store.resolve_ref_state(root)?;
        if canonical_ref_state_root(&state)? == root {
            Ok(state)
        } else {
            Err(RefusalCode::InternalInvariantBreach)
        }
    }
}

/// The two canonical commitments produced together for import or a validated
/// receive.  The ref root enters the authority head; the closure root enters
/// the RCR that commits the receive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalCommitments {
    /// Root selected by an authority head.
    pub ref_root: Digest,
    /// Root recorded in the committing RCR.
    pub object_closure_root: Digest,
}

/// First authority head plus the canonical commitments staged before it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalGenesis {
    /// The exact initial head published through authority initialization.
    pub head: RepositoryAuthorityHeadBody,
    /// The separately recorded ref and closure commitments.
    pub commitments: CanonicalCommitments,
}

/// Stages canonical import state, computes the initial `ref_root` with the
/// same code used for later commits, then publishes the first authority head.
///
/// The closure root has no head field by design: it belongs to the RCR for a
/// validated receive.  It is staged here so import and steady-state use one
/// canonical closure format rather than two incompatible definitions.
pub fn initialize_canonical_repository<Authority, Store, Evidence>(
    authority: &Authority,
    head_key: &HeadKey,
    mut head: RepositoryAuthorityHeadBody,
    projection: &CanonicalAdmissionProjection<Store, Evidence>,
    refs: CanonicalRefState,
    closure: PermittedObjectClosure,
) -> Result<CanonicalGenesis, CanonicalGenesisFailure>
where
    Authority: AuthorityStore + ?Sized,
    Store: CanonicalAdmissionStore,
{
    let commitments = projection
        .stage_initial_state(refs, closure)
        .map_err(CanonicalGenesisFailure::Refusal)?;
    head.ref_root = commitments.ref_root;
    initialize_repository(authority, head_key, &head)
        .map_err(CanonicalGenesisFailure::Authority)?;
    Ok(CanonicalGenesis { head, commitments })
}

/// Failure while staging import commitments or publishing the initial head.
#[derive(Debug)]
pub enum CanonicalGenesisFailure {
    /// A canonical state or closure could not be staged.
    Refusal(RefusalCode),
    /// Authority refused the initial root-last publication.
    Authority(OutcomeFailure),
}

impl Display for CanonicalGenesisFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refusal(code) => write!(formatter, "canonical genesis refused: {code:?}"),
            Self::Authority(failure) => {
                write!(formatter, "canonical genesis authority failure: {failure}")
            }
        }
    }
}

impl Error for CanonicalGenesisFailure {}

impl<Store, Evidence> AdmissionSnapshotProjection for CanonicalAdmissionProjection<Store, Evidence>
where
    Store: CanonicalAdmissionStore,
{
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        let authenticated_body = authenticated
            .body()
            .map_err(|_| RefusalCode::AuthorityReceiptInvalid)?;
        if authenticated_body != *basis.body() {
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let state = self.resolve_ref_state(authenticated_body.ref_root)?;
        Ok(AdmissionSnapshot {
            refs: state.refs,
            forge_positions: BTreeMap::new(),
            retention: BTreeSet::new(),
            outbox: BTreeMap::new(),
        })
    }
}

impl<Store, Evidence> AdmissionProjection for CanonicalAdmissionProjection<Store, Evidence>
where
    Store: CanonicalAdmissionStore,
    Evidence: AdmissionEvidence,
{
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        let current = self
            .resolve_ref_state(basis.body().ref_root)
            .map_err(ProjectionFailure::Unavailable)?;
        let evidence = self
            .evidence
            .commit_evidence(basis, request, fold)
            .map_err(ProjectionFailure::Refuse)?;
        let prepared = prepare_canonical_commit(basis, request, fold, closure, current, evidence)
            .map_err(ProjectionFailure::Refuse)?;
        let ref_root = canonical_ref_state_root(prepared.next_ref_state())
            .map_err(ProjectionFailure::Refuse)?;
        self.store
            .stage_ref_state(ref_root, prepared.next_ref_state().clone())
            .map_err(ProjectionFailure::Unavailable)?;
        let object_closure_root = permitted_object_closure_root(prepared.object_closure())
            .map_err(ProjectionFailure::Refuse)?;
        self.store
            .stage_permitted_object_closure(object_closure_root, prepared.object_closure().clone())
            .map_err(ProjectionFailure::Unavailable)?;
        Ok(prepared.into_materialization())
    }

    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        self.evidence.refusal_evidence(basis, tx_id, code)
    }
}

impl<Authority, Store, Evidence> AsyncAdmissionProjection<Authority>
    for CanonicalAdmissionProjection<Store, Evidence>
where
    Authority: AsyncAuthorityStore + ?Sized,
    Store: CanonicalAdmissionStore + Sync,
    Evidence: AdmissionEvidence + Sync,
{
    fn snapshot_async<'a>(
        &'a self,
        _authority: &'a Authority,
        _cx: &'a Authority::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        std::future::ready(
            AdmissionSnapshotProjection::snapshot(self, basis, authenticated)
                .map_err(ProjectionFailure::Refuse),
        )
    }

    fn materialize_commit_async<'a>(
        &'a self,
        _authority: &'a Authority,
        _cx: &'a Authority::Context,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        std::future::ready(self.materialize_commit(basis, request, fold, closure))
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        _authority: &'a Authority,
        _cx: &'a Authority::Context,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        std::future::ready(
            self.materialize_refusal(basis, tx_id, code)
                .map_err(ProjectionFailure::Refuse),
        )
    }
}

/// The stable session-to-transaction mapping returned by admission.
///
/// `tx_ids` are in original wire command order, even though the sealed
/// semantic request sorts its ref commands canonically.  That distinction is
/// intentional: request identity is order-independent for independent ref
/// targets, while report-status is wire-order observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMapping {
    /// Whether the receive session is one all-or-nothing transaction.
    pub atomic: bool,
    /// One `TxId` for an atomic session, or one `TxId` per command otherwise.
    pub tx_ids: Vec<TxId>,
}

/// A terminal outcome attached to one receive command in wire order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandOutcome {
    /// The `TxId` whose authenticated decision controls this status.
    pub tx_id: TxId,
    /// Authenticated terminal decision.  This is never inferred from pack
    /// receipt or from a successful staging write.
    pub terminal: fgit_authority::TerminalOutcome,
}

/// Authenticated outcome of one receive session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionResult {
    /// Explicit atomic/non-atomic transaction mapping.
    pub session: SessionMapping,
    /// Per-command terminal outcomes in receive wire order.
    pub commands: Vec<CommandOutcome>,
}

impl AdmissionResult {
    /// Converts only authenticated terminal outcomes into receive-pack status
    /// records.  This method is intentionally the sole route from admission
    /// to `report-status`; a successful pack handoff has no corresponding API.
    #[must_use]
    pub fn command_statuses(&self) -> Vec<ReceiveCommandStatus> {
        self.commands
            .iter()
            .map(|command| status_from_terminal(command.terminal.outcome))
            .collect()
    }

    /// Produces report-status packets after every command has a terminal
    /// authority outcome.  The caller retains ownership of the receive limits
    /// selected at protocol admission.
    pub fn report_packets(
        &self,
        request: &ReceiveRequest,
        limits: &fgit_wire::receive::ReceiveLimits,
    ) -> Result<Vec<Packet>, ReceiveError> {
        report_status(request, UnpackStatus::Ok, &self.command_statuses(), limits)
    }
}

/// Typed failure before a reportable terminal outcome exists.
#[derive(Debug)]
pub enum AdmissionError {
    /// The configured command or retry bound is invalid.
    InvalidLimit,
    /// The receive request does not match the configured repository format.
    ObjectFormatMismatch,
    /// The receive request exceeds the bounded transaction lowerer.
    CommandLimitExceeded { limit: usize },
    /// The parser handed over an invalid zero/zero command; production receive
    /// parsing refuses this before handoff, but this public boundary is total.
    InvalidZeroPair,
    /// Conversion from validated wire ref bytes unexpectedly failed.
    RefName(fgit_types::TypeRefusal),
    /// Request canonicalization refused the lowered semantic request.
    Request(fgit_authority::RequestRefusal),
    /// Sealing/refusal-record staging failed.
    Seal(Box<SealFailure>),
    /// Canonical transaction identity derivation refused an input.
    Identity(Box<fgit_authority::IdentityRefusal>),
    /// Authority did not have a repository head to authenticate.
    HeadAbsent,
    /// Authority head authentication or reading failed.
    Authority(AuthorityFailure),
    /// Authority head bytes were not a canonical head body.
    HeadCodec(fgit_codec::CodecRefusal),
    /// An authenticated head receipt and its decoded body name different
    /// generations, so no materializer is allowed to treat either as a basis.
    HeadGenerationMismatch {
        /// Generation declared by the authenticated receipt.
        receipt: fgit_types::HeadGeneration,
        /// Generation carried by the decoded head body.
        body: fgit_types::HeadGeneration,
    },
    /// The head identity could not be computed or did not have its pinned type.
    HeadIdentity(fgit_codec::CodecRefusal),
    /// Chronicle refused a batch/head pair before it reached the CAS.
    Chronicle(fgit_chronicle::ChronicleRefusal),
    /// Publication or replay refused to answer.
    Outcome(Box<OutcomeFailure>),
    /// Asynchronous projection material was unavailable before a terminal
    /// decision could be published.
    AsyncProjectionUnavailable(RefusalCode),
    /// Synchronous projection material was unavailable after sealing but
    /// before head CAS, so this exact transaction remains undecided and
    /// retryable.
    ProjectionUnavailable {
        /// The sealed transaction that was left undecided.
        tx_id: Box<TxId>,
        /// The unavailable material's typed refusal code.
        code: RefusalCode,
    },
    /// A materializer gave a commit record inconsistent with the sealed request.
    MaterializationMismatch(&'static str),
    /// A terminal decision published but its `TxId` could not be resolved.
    PublishedOutcomeMissing,
    /// A pre-CAS duplicate verdict omitted the terminal outcome for this request.
    AlreadyDecidedOutcomeMissing,
    /// Bounded re-planning made no terminal decision.
    CasReplanLimitExceeded { limit: usize },
}

impl Display for AdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("invalid receive admission limit"),
            Self::ObjectFormatMismatch => {
                formatter.write_str("receive quarantine format differs from repository format")
            }
            Self::CommandLimitExceeded { limit } => {
                write!(
                    formatter,
                    "receive command count exceeds admission limit {limit}"
                )
            }
            Self::InvalidZeroPair => {
                formatter.write_str("receive command has zero old and new ids")
            }
            Self::RefName(refusal) => write!(formatter, "receive ref name refused: {refusal}"),
            Self::Request(refusal) => write!(formatter, "semantic request refused: {refusal}"),
            Self::Seal(failure) => {
                write!(formatter, "sealing or refusal staging failed: {failure}")
            }
            Self::Identity(refusal) => write!(formatter, "transaction identity refused: {refusal}"),
            Self::HeadAbsent => formatter.write_str("repository authority head is absent"),
            Self::Authority(failure) => write!(formatter, "authority failure: {failure}"),
            Self::HeadCodec(refusal) => {
                write!(formatter, "authority head decode refused: {refusal}")
            }
            Self::HeadGenerationMismatch { receipt, body } => write!(
                formatter,
                "authority head receipt generation {} disagrees with decoded body generation {}",
                receipt.get(),
                body.get()
            ),
            Self::HeadIdentity(refusal) => {
                write!(formatter, "authority head identity refused: {refusal}")
            }
            Self::Chronicle(refusal) => {
                write!(formatter, "chronicle publication refused: {refusal}")
            }
            Self::Outcome(failure) => {
                write!(formatter, "terminal outcome resolution failed: {failure}")
            }
            Self::AsyncProjectionUnavailable(code) => write!(
                formatter,
                "asynchronous admission projection was unavailable before publication: {code:?}"
            ),
            Self::ProjectionUnavailable { tx_id, code } => write!(
                formatter,
                "admission projection was unavailable for sealed transaction {tx_id:?} before publication: {code:?}"
            ),
            Self::MaterializationMismatch(field) => {
                write!(formatter, "materializer supplied inconsistent {field}")
            }
            Self::PublishedOutcomeMissing => {
                formatter.write_str("published transaction has no authenticated terminal outcome")
            }
            Self::AlreadyDecidedOutcomeMissing => formatter
                .write_str("pre-CAS duplicate verdict omitted the authenticated terminal outcome"),
            Self::CasReplanLimitExceeded { limit } => {
                write!(formatter, "head CAS re-plan limit {limit} exhausted")
            }
        }
    }
}

impl Error for AdmissionError {}

impl From<AuthorityFailure> for AdmissionError {
    fn from(failure: AuthorityFailure) -> Self {
        Self::Authority(failure)
    }
}

impl From<fgit_authority::RequestRefusal> for AdmissionError {
    fn from(refusal: fgit_authority::RequestRefusal) -> Self {
        Self::Request(refusal)
    }
}

impl From<SealFailure> for AdmissionError {
    fn from(failure: SealFailure) -> Self {
        Self::Seal(Box::new(failure))
    }
}

impl From<fgit_authority::IdentityRefusal> for AdmissionError {
    fn from(refusal: fgit_authority::IdentityRefusal) -> Self {
        Self::Identity(Box::new(refusal))
    }
}

impl From<fgit_chronicle::ChronicleRefusal> for AdmissionError {
    fn from(refusal: fgit_chronicle::ChronicleRefusal) -> Self {
        Self::Chronicle(refusal)
    }
}

impl From<OutcomeFailure> for AdmissionError {
    fn from(failure: OutcomeFailure) -> Self {
        Self::Outcome(Box::new(failure))
    }
}

/// Lowers a structurally validated receive session, seals each resulting
/// request, evaluates it against a fresh authenticated basis, and publishes
/// only through the exact-head CAS.
pub fn admit_validated_receive<S, Projection>(
    store: &S,
    context: &AdmissionContext,
    validated: &ValidatedReceive,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<AdmissionResult, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    admit_input(
        store,
        context,
        &receive_input(validated),
        limits,
        projection,
    )
}

/// Admit one already-planned session against the authority.
///
/// The single blocking driver. Both public entrypoints reach the authority
/// through it, so receive-pack and source-import admission share not only the
/// per-attempt decisions but the session's control flow — the atomic/per-command
/// split, the order of attempts, and how their outcomes are assembled.
fn admit_input<S, Projection>(
    store: &S,
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<AdmissionResult, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    let plan = plan_session(context, input, limits)?;
    let terminals = if plan.atomic {
        SessionTerminals::Atomic(admit_one(
            store,
            context,
            input.closure,
            &plan.lowered[0],
            projection,
            limits,
        )?)
    } else {
        let mut outcomes = Vec::with_capacity(plan.lowered.len());
        for request in &plan.lowered {
            outcomes.push(admit_one(
                store,
                context,
                input.closure,
                request,
                projection,
                limits,
            )?);
        }
        SessionTerminals::PerCommand(outcomes)
    };
    Ok(assemble_result(plan, terminals))
}

// --- the shared decision core ---------------------------------------------
//
// Everything in this section is synchronous and touches no `AuthorityStore`.
// It is what the blocking and asynchronous admission surfaces have in common:
// the order the checks run in, which refusal code each branch selects, what
// becomes canonical, and what a losing candidate may conclude. The two
// surfaces differ only in how they wait for the store.
//
// This split is load-bearing rather than stylistic. AGENTS.md §10 requires a
// normative rule to live in one authoritative location, and §5.2's terminality
// and replan rules are exactly such rules. A mechanical `async fn` + `.await`
// sweep over the publication path would have produced a second copy of each,
// free to drift.

/// The plan for a single admission attempt, decided before any publication.
///
/// A refusal and a commit are the only two outcomes an attempt can plan, and
/// the choice between them is made once, here, for both surfaces.
#[derive(Debug)]
enum PlannedPublication {
    /// Publish a terminal refusal carrying this code.
    Refuse(RefusalCode),
    /// Publish the commit this materialization describes.
    ///
    /// Boxed because a materialization carries an RCR and its successor roots
    /// while the refusing arm carries one code; inlining it would make every
    /// refusal pay for the width of a commit.
    Commit(Box<CommitMaterialization>),
}

/// A folded commit whose successor bodies still need materialization.
///
/// The request and fold were derived from one authenticated basis by the
/// shared planner.  The asynchronous driver may await immutable staging for
/// this value, but it must not redo snapshot selection, intent evaluation, or
/// refusal-code selection around that wait.
struct PreparedCommit {
    request: TransactionRequest,
    fold: TransactionFoldReport,
}

/// The part of a publication decision that does not perform successor-body
/// materialization.
enum PublicationPreparation {
    /// Snapshot or fold selected this terminal refusal.
    Refuse(RefusalCode),
    /// The fold committed; a projection must now materialize its immutable
    /// successor bodies before the authority driver can publish it.
    ///
    /// Boxed for the same reason [`PlannedPublication::Commit`] is: a prepared
    /// commit carries a whole `TransactionRequest` and its fold report — 616
    /// bytes against the refusing arm's one — so inlining it would make every
    /// refusal pay the width of a commit.
    Commit(Box<PreparedCommit>),
}

/// Derive the publication basis from an authenticated head.
///
/// The basis identity is derived from the head body itself, so a basis can
/// never name a head that was not authenticated. Shared so that both surfaces
/// bind the same identity to the same bytes.
fn basis_from_authenticated(
    authenticated: &AuthenticatedHead,
) -> Result<PublicationBasis, AdmissionError> {
    let body = authenticated.body().map_err(|failure| match failure {
        fgit_authority::HeadBodyRefusal::Codec(refusal) => AdmissionError::HeadCodec(refusal),
        fgit_authority::HeadBodyRefusal::GenerationMismatch { receipt, body } => {
            AdmissionError::HeadGenerationMismatch { receipt, body }
        }
    })?;
    let id = body_id(&CryptoBodyIdentity, &body)
        .map_err(AdmissionError::HeadIdentity)
        .and_then(|id| {
            fgit_types::RepositoryAuthorityHeadId::from_internal_object_id(id)
                .map_err(|refusal| AdmissionError::HeadIdentity(refusal.into()))
        })?;
    Ok(PublicationBasis::new(id, body))
}

/// Open a projection at one authenticated basis and evaluate the sealed
/// request to its pre-materialization decision.
///
/// Snapshot and fold refusal codes are selected here, once, before either
/// blocking or asynchronous materialization starts.  This is the load-bearing
/// portion of the shared decision core: moving it into an async caller would
/// let receive-pack and source import drift on §5.2 terminality rules.
fn prepare_publication<Projection>(
    projection: &Projection,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    authenticated: &AuthenticatedHead,
    lowered: &LoweredRequest,
    closure: &ValidatedClosure,
    tx_id: TxId,
) -> Result<PublicationPreparation, AdmissionError>
where
    Projection: AdmissionSnapshotProjection + ?Sized,
{
    let snapshot = match projection.snapshot(basis, authenticated) {
        Ok(snapshot) => snapshot,
        Err(code) => return Ok(PublicationPreparation::Refuse(code)),
    };
    prepare_publication_from_snapshot(context, lowered, closure, tx_id, snapshot)
}

/// Evaluate one exact admission snapshot with the shared transaction model.
///
/// The blocking and asynchronous projection surfaces both call this after
/// obtaining an immutable snapshot. Keeping fold evaluation here means their
/// only difference is how that snapshot was loaded and successor frames were
/// staged.
fn prepare_publication_from_snapshot(
    context: &AdmissionContext,
    lowered: &LoweredRequest,
    closure: &ValidatedClosure,
    tx_id: TxId,
    snapshot: AdmissionSnapshot,
) -> Result<PublicationPreparation, AdmissionError> {
    let model_request = model_request(context, &lowered.semantic, tx_id, closure)?;
    let fold = IntentEvaluator::new().evaluate(snapshot.as_fold_basis(), &model_request);
    match &fold.outcome {
        FoldOutcome::Aborted { code, .. } => Ok(PublicationPreparation::Refuse(*code)),
        FoldOutcome::Folded(_) => Ok(PublicationPreparation::Commit(Box::new(PreparedCommit {
            request: model_request,
            fold,
        }))),
    }
}

/// Open and evaluate an exact authenticated basis through an asynchronous
/// projection. The driver calls this once per CAS attempt, including every
/// replan, rather than treating a cache mismatch as a terminal refusal.
async fn prepare_publication_async<S, Projection>(
    projection: &Projection,
    authority: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    authenticated: &AuthenticatedHead,
    lowered: &LoweredRequest,
    closure: &ValidatedClosure,
    tx_id: TxId,
) -> Result<PublicationPreparation, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    let snapshot = match projection
        .snapshot_async(authority, cx, basis, authenticated)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(AsyncProjectionFailure::Refuse(code)) => {
            return Ok(PublicationPreparation::Refuse(code));
        }
        Err(AsyncProjectionFailure::Unavailable(code)) => {
            return Err(AdmissionError::AsyncProjectionUnavailable(code));
        }
    };
    prepare_publication_from_snapshot(context, lowered, closure, tx_id, snapshot)
}

/// Translate one projection materialization result into the shared publication
/// vocabulary.
///
/// The blocking driver uses this classifier; the asynchronous sibling uses
/// [`complete_async_commit_materialization`]. Both preserve the distinction
/// between a terminal projection refusal and unavailable pre-CAS material.
fn complete_commit_materialization(
    materialization: Result<CommitMaterialization, ProjectionFailure>,
    tx_id: TxId,
) -> Result<PlannedPublication, AdmissionError> {
    match materialization {
        Ok(materialization) => Ok(PlannedPublication::Commit(Box::new(materialization))),
        Err(ProjectionFailure::Refuse(code)) => Ok(PlannedPublication::Refuse(code)),
        Err(ProjectionFailure::Unavailable(code)) => Err(AdmissionError::ProjectionUnavailable {
            tx_id: Box::new(tx_id),
            code,
        }),
    }
}

/// Translate an asynchronous materialization result without converting an
/// unavailable durable dependency into a terminal refusal.
fn complete_async_commit_materialization(
    materialization: Result<CommitMaterialization, ProjectionFailure>,
) -> Result<PlannedPublication, AdmissionError> {
    match materialization {
        Ok(materialization) => Ok(PlannedPublication::Commit(Box::new(materialization))),
        Err(ProjectionFailure::Refuse(code)) => Ok(PlannedPublication::Refuse(code)),
        Err(ProjectionFailure::Unavailable(code)) => {
            Err(AdmissionError::AsyncProjectionUnavailable(code))
        }
    }
}

/// Decide and synchronously materialize one publication attempt.
///
/// This is the blocking sibling of the asynchronous driver's prepare/await/
/// completion sequence.  It intentionally uses the same preparation and
/// completion functions, so the only difference between the two surfaces is
/// how successor-body materialization waits.
fn plan_publication<Projection>(
    projection: &Projection,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    authenticated: &AuthenticatedHead,
    lowered: &LoweredRequest,
    closure: &ValidatedClosure,
    tx_id: TxId,
) -> Result<PlannedPublication, AdmissionError>
where
    Projection: AdmissionProjection + ?Sized,
{
    let preparation = prepare_publication(
        projection,
        context,
        basis,
        authenticated,
        lowered,
        closure,
        tx_id,
    )?;
    Ok(match preparation {
        PublicationPreparation::Refuse(code) => PlannedPublication::Refuse(code),
        PublicationPreparation::Commit(prepared) => complete_commit_materialization(
            projection.materialize_commit(basis, &prepared.request, &prepared.fold, closure),
            tx_id,
        )?,
    })
}

/// Validate a commit materialization and seal it into a publication.
///
/// The validation is the part that must not drift: it is what stops a
/// projection from materializing an RCR for a different repository, a
/// different transaction, or a different request than the one that was sealed.
fn prepare_commit_publication(
    context: &AdmissionContext,
    basis: &PublicationBasis,
    tx_id: TxId,
    semantic: &fgit_authority::SemanticRequest,
    closure: &ValidatedClosure,
    materialization: CommitMaterialization,
    cumulative_outcomes: &CumulativeOutcomes,
    expected_head_token: fgit_authority::AuthorityVersionToken,
) -> Result<fgit_chronicle::VerifiedPublication, AdmissionError> {
    validate_commit_materialization(context, basis, tx_id, semantic, closure, &materialization)?;
    let mut plan = PublicationPlan::open(basis.clone())?;
    plan.commit(materialization.record);
    Ok(plan.seal(
        &CryptoBodyIdentity,
        materialization.roots,
        cumulative_outcomes,
        expected_head_token,
    )?)
}

/// Build the refusal record this attempt will publish.
///
/// Two projections can answer the same refusal code differently: the code
/// and a materialized evidence body. The two failure shapes below
/// are distinguished here: a projection that echoes the code back has failed
/// to materialize, while one that answers with a different code has replaced
/// the policy decision. Neither is allowed to silently become the published
/// refusal.
fn prepare_refusal_record<Projection>(
    projection: &Projection,
    basis: &PublicationBasis,
    seal_id: TransactionSealId,
    tx_id: TxId,
    code: RefusalCode,
) -> Result<RefusalRecordBody, AdmissionError>
where
    Projection: AdmissionProjection + ?Sized,
{
    refusal_record_from_materialization(
        basis,
        seal_id,
        tx_id,
        code,
        projection.materialize_refusal(basis, tx_id, code),
    )
}

/// Bind one materialized refusal into its immutable record.
///
/// The synchronous and asynchronous projection boundaries both pass through
/// this exact policy-replacement check.  An async materializer cannot replace
/// the selected refusal code merely because it awaited durable evidence.
fn refusal_record_from_materialization(
    basis: &PublicationBasis,
    seal_id: TransactionSealId,
    tx_id: TxId,
    code: RefusalCode,
    materialization: Result<RefusalMaterialization, RefusalCode>,
) -> Result<RefusalRecordBody, AdmissionError> {
    let materialization = materialization.map_err(|fallback| {
        if fallback == code {
            AdmissionError::MaterializationMismatch("refusal materialization")
        } else {
            AdmissionError::MaterializationMismatch("refusal policy replacement")
        }
    })?;
    let sequence = basis.open_decision_sequence()?;
    Ok(RefusalRecordBody {
        tx_id,
        seal_id,
        decision_sequence: sequence,
        code,
        policy_epoch: materialization.policy_epoch,
        detail: materialization.detail,
        evidence_root: materialization.evidence_root,
    })
}

/// Asynchronously materialize and bind a terminal refusal record.
///
/// Only acquiring the refusal evidence is asynchronous.  The policy
/// replacement check and canonical record construction remain in
/// [`refusal_record_from_materialization`], shared with the blocking path.
async fn prepare_refusal_record_async<S, Projection>(
    projection: &Projection,
    authority: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    seal_id: TransactionSealId,
    tx_id: TxId,
    code: RefusalCode,
) -> Result<RefusalRecordBody, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    let materialization = projection
        .materialize_refusal_async(authority, cx, basis, tx_id, code)
        .await;
    match materialization {
        Ok(materialization) => {
            refusal_record_from_materialization(basis, seal_id, tx_id, code, Ok(materialization))
        }
        Err(AsyncProjectionFailure::Refuse(fallback)) => {
            refusal_record_from_materialization(basis, seal_id, tx_id, code, Err(fallback))
        }
        Err(AsyncProjectionFailure::Unavailable(unavailable)) => {
            Err(AdmissionError::AsyncProjectionUnavailable(unavailable))
        }
    }
}

/// The immutable key and canonical bytes of a refusal record.
fn refusal_body_bytes(
    refusal: &RefusalRecordBody,
) -> Result<(fgit_authority::ImmutableKey, Vec<u8>), AdmissionError> {
    let key = fgit_authority::body_key(IdentityDomain::RefusalRecord, refusal)?;
    let bytes = encode_body(refusal).map_err(AdmissionError::HeadCodec)?;
    Ok((key, bytes))
}

/// Seal a staged refusal record into the publication that carries it.
///
/// The successor roots are carried forward from the basis: a refusal publishes
/// a decision, never new repository content.
fn seal_refusal_publication(
    basis: &PublicationBasis,
    refusal: &RefusalRecordBody,
    cumulative_outcomes: &CumulativeOutcomes,
    expected_head_token: fgit_authority::AuthorityVersionToken,
) -> Result<fgit_chronicle::VerifiedPublication, AdmissionError> {
    let refusal_id = refusal_record_id(refusal)?;
    let mut plan = PublicationPlan::open(basis.clone())?;
    plan.refuse(refusal.tx_id, refusal.code, refusal_id);
    let roots = ResultingRoots::carried_forward(basis);
    Ok(plan.seal(
        &CryptoBodyIdentity,
        roots,
        cumulative_outcomes,
        expected_head_token,
    )?)
}

/// The `TxId` whose terminal decision this publication settles.
fn publication_tx_id(
    publication: &fgit_chronicle::VerifiedPublication,
) -> Result<TxId, AdmissionError> {
    publication
        .batch()
        .decisions
        .first()
        .map(|decision| decision.tx_id)
        .ok_or(AdmissionError::PublishedOutcomeMissing)
}

/// One receive session, lowered and sealed, ready to be admitted.
struct SessionPlan {
    atomic: bool,
    lowered: Vec<LoweredRequest>,
    tx_ids: Vec<TxId>,
    command_count: usize,
}

/// Validate and lower a receive session into the requests that will be
/// admitted, deriving each transaction identity.
///
/// Every input check happens here, before any store contact, so both surfaces
/// refuse a malformed session identically and without having touched the
/// authority.
fn plan_session(
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    limits: AdmissionLimits,
) -> Result<SessionPlan, AdmissionError> {
    limits.validate()?;
    validate_admission_input(context, input, limits)?;
    let lowered = lower_input(context, input)?;
    let tx_ids = lowered
        .iter()
        .map(|request| derive_tx_id(context, request))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SessionPlan {
        atomic: input.atomic,
        lowered,
        tx_ids,
        command_count: input.updates.len(),
    })
}

/// The terminal outcomes a session produced.
///
/// The two shapes are distinct types rather than a `Vec` plus a length rule,
/// so an atomic session cannot be assembled from per-command outcomes or the
/// reverse — the invalid pairing is unrepresentable instead of checked.
enum SessionTerminals {
    /// One decision governs every command in the session.
    Atomic(fgit_authority::TerminalOutcome),
    /// One decision per lowered command, in wire order.
    PerCommand(Vec<fgit_authority::TerminalOutcome>),
}

/// Attach terminal decisions to the session's commands in wire order.
fn assemble_result(plan: SessionPlan, terminals: SessionTerminals) -> AdmissionResult {
    let SessionPlan {
        atomic,
        tx_ids,
        command_count,
        ..
    } = plan;
    let mut commands = Vec::with_capacity(command_count);
    match terminals {
        SessionTerminals::Atomic(terminal) => {
            commands.resize(
                command_count,
                CommandOutcome {
                    tx_id: tx_ids[0],
                    terminal,
                },
            );
        }
        SessionTerminals::PerCommand(outcomes) => {
            for (terminal, tx_id) in outcomes.into_iter().zip(&tx_ids) {
                commands.push(CommandOutcome {
                    tx_id: *tx_id,
                    terminal,
                });
            }
        }
    }
    AdmissionResult {
        session: SessionMapping { atomic, tx_ids },
        commands,
    }
}

fn validate_admission_input(
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    limits: AdmissionLimits,
) -> Result<(), AdmissionError> {
    if input.object_format != context.object_format {
        return Err(AdmissionError::ObjectFormatMismatch);
    }
    if input.updates.len() > limits.max_commands {
        return Err(AdmissionError::CommandLimitExceeded {
            limit: limits.max_commands,
        });
    }
    if input.updates.is_empty() {
        return Err(AdmissionError::CommandLimitExceeded { limit: 0 });
    }
    // The provenance declared a shape; the commands must actually have it. This
    // catches a caller whose receipt and command list disagree, on either path.
    if input.deletes_only != input.declared_delete_only {
        return Err(AdmissionError::MaterializationMismatch(
            input.delete_only_label,
        ));
    }
    Ok(())
}

/// Build the sealed semantic requests for one admission session.
///
/// Both admission paths reach the authority through this function, over
/// already-lowered ref commands. `RECEIVE_ADMISSION_SCHEMA` is deliberately the
/// schema for both: the schema names the *shape of the decision* — ref commands
/// admitted against an authority head — not the transport that carried it. A
/// separate schema per provenance would give the same refs two transaction
/// identities and split one canonical history in half, which is precisely what
/// §5.2's single stable identity derivation forbids.
fn lower_input(
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
) -> Result<Vec<LoweredRequest>, AdmissionError> {
    let push_options = input
        .push_options
        .iter()
        .cloned()
        .map(fgit_authority::PushOption::new)
        .collect::<Result<Vec<_>, _>>()?;
    if input.atomic {
        let commands = input
            .updates
            .iter()
            .map(|update| lower_ref_update(update.old, update.new, update.ref_name))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(vec![LoweredRequest {
            semantic: fgit_authority::SemanticRequest::build(
                RECEIVE_ADMISSION_SCHEMA,
                context.object_format,
                true,
                commands,
                push_options,
                Vec::new(),
            )?,
            idempotency_key: context.idempotency_key.clone(),
        }]);
    }

    input
        .updates
        .iter()
        .enumerate()
        .map(|(index, update)| {
            Ok(LoweredRequest {
                semantic: fgit_authority::SemanticRequest::build(
                    RECEIVE_ADMISSION_SCHEMA,
                    context.object_format,
                    false,
                    vec![lower_ref_update(update.old, update.new, update.ref_name)?],
                    push_options.clone(),
                    Vec::new(),
                )?,
                idempotency_key: non_atomic_key(&context.idempotency_key, index)?,
            })
        })
        .collect()
}

/// Lower one ref update into the authority's typed command.
///
/// Shared by receive-pack and source-import admission. Both paths reach the
/// authority through this one function, so a given `(old, new, name)` triple
/// lowers to the same `RefCommand` regardless of how it arrived — which is what
/// makes the two paths produce identical semantic requests, and therefore
/// identical decision records, for the same refs. A second lowering would let
/// the two drift silently in exactly the way a shared identity must not.
fn lower_ref_update(
    old: AnyGitOid,
    new: AnyGitOid,
    ref_name: &[u8],
) -> Result<fgit_authority::RefCommand, AdmissionError> {
    let name = RefName::try_new(ref_name).map_err(AdmissionError::RefName)?;
    let expected_old = if old.is_zero() {
        fgit_authority::ExpectedOld::Absent
    } else {
        fgit_authority::ExpectedOld::Exactly(old)
    };
    // The classification is the receive-pack zero-sentinel rule, applied to any
    // source: two zero IDs name nothing and are refused, a zero new deletes,
    // and anything else proposes that object.
    let proposed_new = match (old.is_zero(), new.is_zero()) {
        (true, true) => return Err(AdmissionError::InvalidZeroPair),
        (_, true) => fgit_authority::ProposedNew::Delete,
        (_, false) => fgit_authority::ProposedNew::Update(new),
    };
    Ok(fgit_authority::RefCommand {
        name,
        expected_old,
        proposed_new,
        // Receive-pack carries an expected old OID rather than a separate
        // force bit. Ref protection/fast-forward policy is evaluated by the
        // projection; it never treats the transport as evidence of a force.
        // A source import is held to the same rule: being local is not a force.
        force: false,
    })
}

fn derive_tx_id(
    context: &AdmissionContext,
    request: &LoweredRequest,
) -> Result<TxId, AdmissionError> {
    seal_attempt(context, request)
        .derive()
        .map(|(tx_id, _)| tx_id)
        .map_err(Into::into)
}

fn seal_attempt(context: &AdmissionContext, request: &LoweredRequest) -> SealAttempt {
    SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: request.idempotency_key.clone(),
        request: request.semantic.clone(),
    }
}

fn non_atomic_key(base: &IdempotencyKey, index: usize) -> Result<IdempotencyKey, AdmissionError> {
    let index = u64::try_from(index).map_err(|_| AdmissionError::InvalidLimit)?;
    let digest = base.digest();
    let mut bytes = Vec::with_capacity(31 + digest.bytes().len() + size_of::<u64>());
    bytes.extend_from_slice(b"fgit/receive/non-atomic/v1/");
    bytes.extend_from_slice(digest.bytes().as_bytes());
    bytes.extend_from_slice(&index.to_be_bytes());
    IdempotencyKey::new(bytes).map_err(AdmissionError::from)
}

fn admit_one<S, Projection>(
    store: &S,
    context: &AdmissionContext,
    closure: &ValidatedClosure,
    lowered: &LoweredRequest,
    projection: &Projection,
    limits: AdmissionLimits,
) -> Result<fgit_authority::TerminalOutcome, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    let attempt = seal_attempt(context, lowered);
    let admission = seal_request(store, &attempt)?;
    let tx_id = admission.tx_id();
    if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome(
        store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )? {
        return Ok(terminal);
    }

    for replan in 0..limits.max_cas_replans {
        // The pre-loop probe already covered the first attempt. Every later
        // replan must resolve a terminal decision that won the preceding CAS.
        if replan != 0
            && let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome(
                store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )?
        {
            return Ok(terminal);
        }
        let (basis, receipt, authenticated) = read_basis(store, &context.head_key)?;
        let cumulative_outcomes = collect_cumulative_outcomes(store, &context.head_key)?;
        if cumulative_outcomes.observed() != receipt.token() {
            continue;
        }
        let terminal = match plan_publication(
            projection,
            context,
            &basis,
            &authenticated,
            lowered,
            closure,
            tx_id,
        )? {
            PlannedPublication::Refuse(code) => publish_refusal(
                store,
                context,
                &basis,
                receipt.token(),
                admission.seal_id(),
                tx_id,
                code,
                projection,
                &cumulative_outcomes,
            )?,
            PlannedPublication::Commit(materialization) => publish_commit(
                store,
                context,
                &basis,
                receipt.token(),
                tx_id,
                &lowered.semantic,
                closure,
                *materialization,
                &cumulative_outcomes,
            )?,
        };
        if let Some(terminal) = terminal {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

fn read_basis<S>(
    store: &S,
    head_key: &HeadKey,
) -> Result<
    (
        PublicationBasis,
        fgit_authority::HeadReadReceipt,
        AuthenticatedHead,
    ),
    AdmissionError,
>
where
    S: AuthorityStore + ?Sized,
{
    let receipt = match store.read_head(head_key)? {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => return Err(AdmissionError::HeadAbsent),
    };
    let authenticated = store.authenticate_head_receipt(&receipt)?;
    let basis = basis_from_authenticated(&authenticated)?;
    Ok((basis, receipt, authenticated))
}

fn model_request(
    context: &AdmissionContext,
    semantic: &fgit_authority::SemanticRequest,
    tx_id: TxId,
    closure: &ValidatedClosure,
) -> Result<TransactionRequest, AdmissionError> {
    let intents = semantic
        .ref_commands()
        .iter()
        .map(|command| {
            let expected = match command.expected_old {
                fgit_authority::ExpectedOld::Absent => ExpectedRefState::Absent,
                fgit_authority::ExpectedOld::Exactly(oid) => ExpectedRefState::Exact(oid),
                fgit_authority::ExpectedOld::Unspecified => ExpectedRefState::Any,
            };
            let intent = match command.proposed_new {
                fgit_authority::ProposedNew::Delete => RefIntent::Delete {
                    name: command.name.clone(),
                    expected,
                },
                fgit_authority::ProposedNew::Update(new) => RefIntent::Update {
                    name: command.name.clone(),
                    expected,
                    new,
                    force: command.force,
                },
            };
            Intent::Ref(intent)
        })
        .collect();
    Ok(TransactionRequest {
        tx_id,
        tenant: context.tenant_id,
        repository: context.repository_id,
        principal: context.principal_id,
        schema: semantic.request_schema(),
        // This model key is deliberately fixed: `fgit-txn` evaluates typed
        // intents only.  The raw client key is bound once, exclusively, by the
        // authority `SealAttempt` above and never reinterpreted here.
        idempotency_key: ModelIdempotencyKey::new(AsciiSlug::from_static("receive")),
        canonical_request_digest: fgit_authority::canonical_request_digest(semantic)
            .map_err(|failure| AdmissionError::Seal(Box::new(failure.into())))?,
        statements: vec![Statement {
            intents,
            mismatch_policy: fgit_types::MismatchPolicy::TxnAbort,
        }],
        promised_closure: closure.objects.clone(),
        atomic: semantic.atomic(),
        durability: DurabilityProfile::CanonicalSource,
    })
}

fn publish_commit<S>(
    store: &S,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    expected: fgit_authority::AuthorityVersionToken,
    tx_id: TxId,
    semantic: &fgit_authority::SemanticRequest,
    closure: &ValidatedClosure,
    materialization: CommitMaterialization,
    cumulative_outcomes: &CumulativeOutcomes,
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AuthorityStore + ?Sized,
{
    let publication = prepare_commit_publication(
        context,
        basis,
        tx_id,
        semantic,
        closure,
        materialization,
        cumulative_outcomes,
        expected,
    )?;
    outcome_after_publish(store, context, expected, &publication)
}

fn validate_commit_materialization(
    context: &AdmissionContext,
    basis: &PublicationBasis,
    tx_id: TxId,
    semantic: &fgit_authority::SemanticRequest,
    closure: &ValidatedClosure,
    materialization: &CommitMaterialization,
) -> Result<(), AdmissionError> {
    let record = &materialization.record;
    if record.repository_id != context.repository_id {
        return Err(AdmissionError::MaterializationMismatch("RCR repository"));
    }
    if record.tx_id != tx_id {
        return Err(AdmissionError::MaterializationMismatch(
            "RCR transaction identity",
        ));
    }
    if record.canonical_request_digest
        != fgit_authority::canonical_request_digest(semantic)
            .map_err(|failure| AdmissionError::Seal(Box::new(failure.into())))?
    {
        return Err(AdmissionError::MaterializationMismatch(
            "RCR request digest",
        ));
    }
    if record.object_closure_root != closure.object_closure_root {
        return Err(AdmissionError::MaterializationMismatch(
            "RCR object closure root",
        ));
    }
    if record.resulting_ref_root != materialization.roots.ref_root {
        return Err(AdmissionError::MaterializationMismatch(
            "resulting ref root",
        ));
    }
    if record.policy_epoch != materialization.roots.policy_epoch {
        return Err(AdmissionError::MaterializationMismatch("policy epoch"));
    }
    // CONTINUATION AGAINST THE AUTHENTICATED BASIS. Lowered admission
    // requests are ref-only: the fold refuses any forge, retention, or
    // outbox effect before a materialization can exist, so the only correct
    // carried-forward values are EXACTLY the authenticated basis's. A
    // projection that fabricates a stream position, retention state, outbox
    // state, policy epoch, or compaction link would otherwise publish those
    // into the canonical head unchallenged — record-vs-roots agreement
    // cannot catch it because the fabrication matches itself.
    if materialization.roots.forge_position_root != basis.body().forge_position_root {
        return Err(AdmissionError::MaterializationMismatch(
            "carried forge position root",
        ));
    }
    if materialization.roots.retention_root != basis.body().retention_root {
        return Err(AdmissionError::MaterializationMismatch(
            "carried retention root",
        ));
    }
    if materialization.roots.outbox_root != basis.body().outbox_root {
        return Err(AdmissionError::MaterializationMismatch(
            "carried outbox root",
        ));
    }
    if materialization.roots.policy_epoch != basis.body().policy_epoch {
        return Err(AdmissionError::MaterializationMismatch(
            "carried policy epoch",
        ));
    }
    if materialization.roots.compaction_generation_link.is_some() {
        return Err(AdmissionError::MaterializationMismatch(
            "compaction generation link",
        ));
    }
    if record.resulting_forge_position_root != basis.body().forge_position_root {
        return Err(AdmissionError::MaterializationMismatch(
            "RCR resulting forge position root",
        ));
    }
    if record.resulting_forge_position_root != materialization.roots.forge_position_root {
        return Err(AdmissionError::MaterializationMismatch(
            "resulting forge root",
        ));
    }
    Ok(())
}

fn publish_refusal<S, Projection>(
    store: &S,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    expected: fgit_authority::AuthorityVersionToken,
    seal_id: TransactionSealId,
    tx_id: TxId,
    code: RefusalCode,
    projection: &Projection,
    cumulative_outcomes: &CumulativeOutcomes,
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    let refusal = prepare_refusal_record(projection, basis, seal_id, tx_id, code)?;
    let (key, bytes) = refusal_body_bytes(&refusal)?;
    store.put_if_absent(&key, &bytes)?;

    let publication = seal_refusal_publication(basis, &refusal, cumulative_outcomes, expected)?;
    outcome_after_publish(store, context, expected, &publication)
}

fn refusal_record_id(record: &RefusalRecordBody) -> Result<RefusalRecordId, AdmissionError> {
    body_id(&CryptoBodyIdentity, record)
        .map_err(AdmissionError::HeadIdentity)
        .and_then(|id| {
            RefusalRecordId::from_internal_object_id(id)
                .map_err(|refusal| AdmissionError::HeadIdentity(refusal.into()))
        })
}

/// Selects the already-canonical terminal outcome for this publication's `TxId`.
///
/// A pre-CAS duplicate is a successful idempotent retry: returning a fresh
/// lookup result or replanning it could conceal the existing terminal decision.
fn already_decided_terminal(
    tx_id: TxId,
    decided: Vec<(TxId, fgit_authority::TerminalOutcome)>,
) -> Result<fgit_authority::TerminalOutcome, AdmissionError> {
    decided
        .into_iter()
        .find_map(|(decided_tx_id, terminal)| (decided_tx_id == tx_id).then_some(terminal))
        .ok_or(AdmissionError::AlreadyDecidedOutcomeMissing)
}

fn outcome_after_publish<S>(
    store: &S,
    context: &AdmissionContext,
    expected: fgit_authority::AuthorityVersionToken,
    publication: &fgit_chronicle::VerifiedPublication,
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AuthorityStore + ?Sized,
{
    let tx_id = publication_tx_id(publication)?;
    match publish(
        store,
        &context.head_key,
        expected,
        publication,
        context.tenant_id,
    )? {
        PublicationVerdict::Published(_) | PublicationVerdict::Lost(_) => {
            match fgit_authority::resolve_outcome(
                store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )? {
                OutcomeLookup::Decided(terminal) => Ok(Some(terminal)),
                OutcomeLookup::Undecided => Ok(None),
            }
        }
        PublicationVerdict::AlreadyDecided { decided } => {
            Ok(Some(already_decided_terminal(tx_id, decided)?))
        }
    }
}

fn status_from_terminal(outcome: DecisionOutcome) -> ReceiveCommandStatus {
    match outcome {
        DecisionOutcome::Committed { .. } => ReceiveCommandStatus::Ok,
        DecisionOutcome::Refused { code, .. } => ReceiveCommandStatus::Rejected {
            message: refusal_message(code).to_vec(),
        },
    }
}

const fn refusal_message(code: RefusalCode) -> &'static [u8] {
    match code {
        RefusalCode::ExpectedOldRefMismatch => b"stale info",
        RefusalCode::AtomicTransactionAborted => b"atomic transaction aborted",
        RefusalCode::ObjectClosureIncomplete => b"object closure incomplete",
        RefusalCode::PackFramingInvalid => b"pack validation failed",
        RefusalCode::ProtectedRefTransitionDenied => b"protected ref denied",
        RefusalCode::ForceNotPermitted => b"force not permitted",
        RefusalCode::NonFastForwardRefused => b"non-fast-forward",
        RefusalCode::RefNameInvalid => b"invalid ref name",
        _ => b"admission refused",
    }
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

// --- the asynchronous admission surface -----------------------------------
//
// The sibling of the blocking surface above, for a backend that implements
// [`AsyncAuthorityStore`] only — `fgit-authority-fsqlite` is the one that
// motivated it, reached through `fgit-node`.
//
// These are siblings rather than layers, in the sense `fgit-authority`'s own
// async contract uses: they delegate every decision to the same core, so
// neither can conclude something the other would not about the same store
// answers. What differs is only how they wait. In particular the CAS replan
// loop below selects refusal codes, orders its checks, and interprets an
// ambiguous publication through `plan_publication`, `prepare_*` and
// `outcome_after_publish_async`'s shared deciders — not through a second copy
// of §5.2.
//
// The projection stays synchronous on purpose. `fgit-node` materializes
// canonical ref state from the authority ahead of admission and the projection
// reads only that materialized record, so nothing here needs to block on I/O
// inside a projection call.

/// Lower, seal, evaluate, and publish a validated receive session,
/// asynchronously.
///
/// The asynchronous sibling of [`admit_validated_receive`]. It plans the
/// session with the same [`plan_session`] and assembles its result with the
/// same [`assemble_result`], so a session that the blocking surface refuses
/// before touching the store is refused here identically and just as early.
pub async fn admit_validated_receive_async<S, Projection>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    validated: &ValidatedReceive,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<AdmissionResult, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    admit_input_async(
        store,
        cx,
        context,
        &receive_input(validated),
        limits,
        projection,
    )
    .await
}

/// Admit one already-planned session against the authority, asynchronously.
///
/// The single asynchronous driver, and the sibling of [`admit_input`].
async fn admit_input_async<S, Projection>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<AdmissionResult, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    let plan = plan_session(context, input, limits)?;
    let terminals = if plan.atomic {
        SessionTerminals::Atomic(
            admit_one_async(
                store,
                cx,
                context,
                input.closure,
                &plan.lowered[0],
                projection,
                limits,
            )
            .await?,
        )
    } else {
        let mut outcomes = Vec::with_capacity(plan.lowered.len());
        for request in &plan.lowered {
            outcomes.push(
                admit_one_async(
                    store,
                    cx,
                    context,
                    input.closure,
                    request,
                    projection,
                    limits,
                )
                .await?,
            );
        }
        SessionTerminals::PerCommand(outcomes)
    };
    Ok(assemble_result(plan, terminals))
}

/// Admit one sealed transaction against a fresh basis, asynchronously.
///
/// The asynchronous sibling of [`admit_one`], and structurally the same loop:
/// a pre-loop terminal check makes an idempotent retry cheap, and each replan
/// re-reads the basis rather than reusing a stale one. §5.2's rule that a CAS
/// loser reuses and revalidates *without changing the sealed request* is
/// preserved by sealing once, before the loop, exactly as the blocking sibling
/// does.
async fn admit_one_async<S, Projection>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    closure: &ValidatedClosure,
    lowered: &LoweredRequest,
    projection: &Projection,
    limits: AdmissionLimits,
) -> Result<fgit_authority::TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    let attempt = seal_attempt(context, lowered);
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
    if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
        store,
        cx,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .await?
    {
        return Ok(terminal);
    }

    for replan in 0..limits.max_cas_replans {
        // Keep the asynchronous retry surface equivalent to the blocking
        // sibling: the pre-loop probe owns attempt zero, later replans probe
        // only after a predecessor CAS could have won.
        if replan != 0
            && let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
                store,
                cx,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )
            .await?
        {
            return Ok(terminal);
        }
        let (basis, receipt, authenticated) =
            read_basis_async(store, cx, &context.head_key).await?;
        let cumulative_outcomes =
            collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative_outcomes.observed() != receipt.token() {
            continue;
        }
        let preparation = prepare_publication_async(
            projection,
            store,
            cx,
            context,
            &basis,
            &authenticated,
            lowered,
            closure,
            tx_id,
        )
        .await?;
        let planned = match preparation {
            PublicationPreparation::Commit(prepared) => complete_async_commit_materialization(
                projection
                    .materialize_commit_async(
                        store,
                        cx,
                        &basis,
                        &prepared.request,
                        &prepared.fold,
                        closure,
                    )
                    .await,
            )?,
            PublicationPreparation::Refuse(code) => PlannedPublication::Refuse(code),
        };
        let terminal = match planned {
            PlannedPublication::Refuse(code) => {
                publish_refusal_async(
                    store,
                    cx,
                    context,
                    &basis,
                    receipt.token(),
                    admission.seal_id(),
                    tx_id,
                    code,
                    projection,
                    &cumulative_outcomes,
                )
                .await?
            }
            PlannedPublication::Commit(materialization) => {
                publish_commit_async(
                    store,
                    cx,
                    context,
                    &basis,
                    receipt.token(),
                    tx_id,
                    &lowered.semantic,
                    closure,
                    *materialization,
                    &cumulative_outcomes,
                )
                .await?
            }
        };
        if let Some(terminal) = terminal {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

/// Read and authenticate the current head, asynchronously.
///
/// The asynchronous sibling of [`read_basis`]. The basis is derived by the
/// shared [`basis_from_authenticated`], so both surfaces bind the same identity
/// to the same authenticated bytes.
async fn read_basis_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
) -> Result<
    (
        PublicationBasis,
        fgit_authority::HeadReadReceipt,
        AuthenticatedHead,
    ),
    AdmissionError,
>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let receipt = match store.read_head(cx, head_key).await? {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => return Err(AdmissionError::HeadAbsent),
    };
    let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
    let basis = basis_from_authenticated(&authenticated)?;
    Ok((basis, receipt, authenticated))
}

/// Publish a committed fold through the exact-head CAS, asynchronously.
///
/// The asynchronous sibling of [`publish_commit`]. The materialization is
/// validated and sealed by the shared [`prepare_commit_publication`], so a
/// materialization the blocking surface rejects is rejected here for the same
/// reason.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the blocking sibling's parameters exactly, plus the \
              runtime context; diverging the two signatures would make the \
              pair harder to compare than the extra parameter costs"
)]
async fn publish_commit_async<S>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    expected: fgit_authority::AuthorityVersionToken,
    tx_id: TxId,
    semantic: &fgit_authority::SemanticRequest,
    closure: &ValidatedClosure,
    materialization: CommitMaterialization,
    cumulative_outcomes: &CumulativeOutcomes,
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let publication = prepare_commit_publication(
        context,
        basis,
        tx_id,
        semantic,
        closure,
        materialization,
        cumulative_outcomes,
        expected,
    )?;
    outcome_after_publish_async(store, cx, context, expected, &publication).await
}

/// Stage a refusal record and publish its terminal decision, asynchronously.
///
/// The asynchronous sibling of [`publish_refusal`], with the same ordering: the
/// refusal record is staged before the head moves, so a reader that observes
/// the decision can always resolve the record it names.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the blocking sibling's parameters exactly, plus the \
              runtime context; diverging the two signatures would make the \
              pair harder to compare than the extra parameter costs"
)]
async fn publish_refusal_async<S, Projection>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    expected: fgit_authority::AuthorityVersionToken,
    seal_id: TransactionSealId,
    tx_id: TxId,
    code: RefusalCode,
    projection: &Projection,
    cumulative_outcomes: &CumulativeOutcomes,
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    Projection: AsyncAdmissionProjection<S> + ?Sized,
{
    let refusal =
        prepare_refusal_record_async(projection, store, cx, basis, seal_id, tx_id, code).await?;
    let (key, bytes) = refusal_body_bytes(&refusal)?;
    store.put_if_absent(cx, &key, &bytes).await?;

    let publication = seal_refusal_publication(basis, &refusal, cumulative_outcomes, expected)?;
    outcome_after_publish_async(store, cx, context, expected, &publication).await
}

/// Interpret the result of a publication attempt, asynchronously.
///
/// The asynchronous sibling of [`outcome_after_publish`], and it makes the same
/// three-way reading of a conditional replacement:
///
/// - a win **or** a lost race resolves the transaction authoritatively, because
///   a loser may still have been decided by the candidate that beat it;
/// - a transaction that was already terminal before anything was attempted
///   yields that standing decision, never a fresh one.
///
/// `Ok(None)` means the transaction is still undecided and the caller may
/// replan. It never means "not committed": §5.2 forbids concluding
/// non-commitment from an ambiguous response.
async fn outcome_after_publish_async<S>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    expected: fgit_authority::AuthorityVersionToken,
    publication: &fgit_chronicle::VerifiedPublication,
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let tx_id = publication_tx_id(publication)?;
    match fgit_chronicle::publish_async(
        store,
        cx,
        &context.head_key,
        expected,
        publication,
        context.tenant_id,
    )
    .await?
    {
        PublicationVerdict::Published(_) | PublicationVerdict::Lost(_) => {
            match fgit_authority::resolve_outcome_async(
                store,
                cx,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )
            .await?
            {
                OutcomeLookup::Decided(terminal) => Ok(Some(terminal)),
                OutcomeLookup::Undecided => Ok(None),
            }
        }
        PublicationVerdict::AlreadyDecided { decided } => {
            Ok(Some(already_decided_terminal(tx_id, decided)?))
        }
    }
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet};
    use std::rc::Rc;

    use fgit_authority::{
        AuthorityOpKind, AuthorityVersionToken, DuplicateDelivery, FaultDirective, FaultKind,
        FaultPlan, FaultableAuthorityStore, HeadKey, HeadReadReceipt, MemoryAuthorityStore,
        OpIndex, StoreInstanceId, initialize_repository, resolve_outcome,
    };
    use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryCommitRecord, decode_body};
    use fgit_reference::effect::FoldOutcome;
    use fgit_types::{
        DigestAlgorithmId, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalSnapshotId,
        RegistryEpoch, RepositorySequence,
    };
    use fgit_wire::Capability;
    use fgit_wire::receive::ReceiveCommand;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum FixtureMaterializationMutation {
        ForgePositionRoot,
        RetentionRoot,
        OutboxRoot,
        PolicyEpoch,
        CompactionGenerationLink,
        RecordForgePositionRoot,
    }

    #[derive(Default)]
    struct FixtureProjection {
        reject_commit: bool,
        materialization_mutation: Option<FixtureMaterializationMutation>,
        refs: BTreeMap<RefName, fgit_types::GitOid>,
        forge_positions: BTreeMap<
            fgit_reference::intent::ForgeStreamId,
            fgit_reference::intent::ForgeStreamPosition,
        >,
        retention: BTreeSet<fgit_reference::intent::RetentionRoot>,
        outbox: BTreeMap<fgit_reference::intent::OutboxDeliveryKey, Digest>,
    }

    impl AdmissionSnapshotProjection for FixtureProjection {
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
    }

    impl AdmissionProjection for FixtureProjection {
        fn materialize_commit(
            &self,
            basis: &PublicationBasis,
            request: &TransactionRequest,
            fold: &TransactionFoldReport,
            closure: &ValidatedClosure,
        ) -> Result<CommitMaterialization, ProjectionFailure> {
            if self.reject_commit {
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied,
                ));
            }
            if !matches!(fold.outcome, FoldOutcome::Folded(_)) {
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::ConflictingSemanticEffects,
                ));
            }
            let roots = ResultingRoots {
                ref_root: digest(2),
                // Continuation is checked against the basis now, so even the
                // fixture must carry the real carried-forward values; only
                // ref_root is this projection's own decision.
                forge_position_root: basis.body().forge_position_root,
                retention_root: basis.body().retention_root,
                outbox_root: basis.body().outbox_root,
                policy_epoch: basis.body().policy_epoch,
                compaction_generation_link: None,
            };
            let mut materialization = CommitMaterialization {
                record: RepositoryCommitRecord {
                    repository_id: request.repository,
                    repository_sequence: RepositorySequence::FIRST,
                    parent_rcr_id: None,
                    tx_id: request.tx_id,
                    principal_snapshot_id: principal_snapshot(),
                    canonical_request_digest: request.canonical_request_digest,
                    ref_delta_root: digest(7),
                    resulting_ref_root: roots.ref_root,
                    object_closure_root: closure.object_closure_root,
                    forge_event_batch_root: digest(8),
                    resulting_forge_position_root: roots.forge_position_root,
                    policy_epoch: roots.policy_epoch,
                    policy_decision_root: digest(9),
                    invariant_evidence_root: digest(10),
                    outbox_effect_root: digest(11),
                    retention_delta_root: digest(12),
                },
                roots,
            };
            match self.materialization_mutation {
                Some(FixtureMaterializationMutation::ForgePositionRoot) => {
                    materialization.roots.forge_position_root = digest(3);
                    materialization.record.resulting_forge_position_root =
                        materialization.roots.forge_position_root;
                }
                Some(FixtureMaterializationMutation::RetentionRoot) => {
                    materialization.roots.retention_root = digest(4);
                }
                Some(FixtureMaterializationMutation::OutboxRoot) => {
                    materialization.roots.outbox_root = digest(5);
                }
                Some(FixtureMaterializationMutation::PolicyEpoch) => {
                    materialization.roots.policy_epoch =
                        PolicyEpoch::try_new(2).expect("fixture policy epoch is valid");
                    materialization.record.policy_epoch = materialization.roots.policy_epoch;
                }
                Some(FixtureMaterializationMutation::CompactionGenerationLink) => {
                    materialization.roots.compaction_generation_link = Some(digest(6));
                }
                Some(FixtureMaterializationMutation::RecordForgePositionRoot) => {
                    materialization.record.resulting_forge_position_root = digest(7);
                }
                None => {}
            }
            Ok(materialization)
        }

        fn materialize_refusal(
            &self,
            basis: &PublicationBasis,
            _tx_id: TxId,
            _code: RefusalCode,
        ) -> Result<RefusalMaterialization, RefusalCode> {
            Ok(RefusalMaterialization {
                policy_epoch: basis.body().policy_epoch,
                detail: "fixture policy refusal".to_owned(),
                evidence_root: digest(13),
            })
        }
    }

    struct FixtureValidator;

    impl QuarantineValidator for FixtureValidator {
        fn validate(
            &self,
            request: &ReceiveRequest,
            _pack: Option<&QuarantinedPack>,
            receipt: &QuarantineReceipt,
        ) -> Result<ValidatedClosure, RefusalCode> {
            if request.requires_pack() && receipt.object_count == 0 {
                return Err(RefusalCode::ObjectClosureIncomplete);
            }
            let objects = request
                .commands
                .iter()
                .filter(|command| !command.new.is_zero())
                .map(|command| command.new)
                .collect();
            Ok(ValidatedClosure {
                object_closure_root: digest(14),
                objects,
            })
        }
    }

    /// A canonical backing that injects exactly one pre-CAS ref-state staging
    /// failure. The second call stages normally, which makes the retry twin
    /// distinguish an undecided seal from a terminal refusal.
    #[derive(Clone, Default)]
    struct FailOnceCanonicalStore {
        refs: Rc<RefCell<BTreeMap<Digest, CanonicalRefState>>>,
        closures: Rc<RefCell<BTreeMap<Digest, PermittedObjectClosure>>>,
        fail_next_ref_stage: Rc<Cell<bool>>,
    }

    impl FailOnceCanonicalStore {
        fn fail_next_ref_stage(&self) {
            self.fail_next_ref_stage.set(true);
        }
    }

    impl CanonicalAdmissionStore for FailOnceCanonicalStore {
        fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
            self.refs
                .borrow()
                .get(&root)
                .cloned()
                .ok_or(RefusalCode::EvidenceMissing)
        }

        fn stage_ref_state(
            &self,
            root: Digest,
            state: CanonicalRefState,
        ) -> Result<(), RefusalCode> {
            if self.fail_next_ref_stage.replace(false) {
                return Err(RefusalCode::EvidenceMissing);
            }
            self.refs.borrow_mut().insert(root, state);
            Ok(())
        }

        fn resolve_permitted_object_closure(
            &self,
            root: Digest,
        ) -> Result<PermittedObjectClosure, RefusalCode> {
            self.closures
                .borrow()
                .get(&root)
                .cloned()
                .ok_or(RefusalCode::EvidenceMissing)
        }

        fn stage_permitted_object_closure(
            &self,
            root: Digest,
            closure: PermittedObjectClosure,
        ) -> Result<(), RefusalCode> {
            self.closures.borrow_mut().insert(root, closure);
            Ok(())
        }
    }

    struct CanonicalFixtureEvidence;

    impl AdmissionEvidence for CanonicalFixtureEvidence {
        fn commit_evidence(
            &self,
            _basis: &PublicationBasis,
            _request: &TransactionRequest,
            _fold: &TransactionFoldReport,
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
                detail: "canonical fixture policy refusal".to_owned(),
                evidence_root: digest(13),
            })
        }
    }

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

    fn oid(seed: u8) -> fgit_types::GitOid {
        fgit_types::GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([seed; 20]))
    }

    fn context() -> AdmissionContext {
        AdmissionContext {
            head_key: HeadKey::new(b"fg/head/test-repository".to_vec()).expect("valid head key"),
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]),
            idempotency_key: IdempotencyKey::new(b"session-idempotency-key".to_vec())
                .expect("bounded key"),
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
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(77));
        initialize_repository(&store, &context.head_key, &genesis(context))
            .expect("genesis head initializes");
        store
    }

    fn completion(commands: Vec<ReceiveCommand>, atomic: bool) -> ValidatedReceive {
        let mut capabilities = vec![Capability {
            name: b"report-status".to_vec(),
            value: None,
        }];
        if atomic {
            capabilities.push(Capability {
                name: b"atomic".to_vec(),
                value: None,
            });
        }
        let request = ReceiveRequest {
            commands,
            capabilities,
            push_options: vec![b"ci.skip=false".to_vec()],
            certificate: None,
        };
        let receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 1,
            pack_bytes: 64,
            delete_only: false,
        };
        let closure = FixtureValidator
            .validate(&request, None, &receipt)
            .expect("fixture closure validates");
        ValidatedReceive {
            request,
            receipt,
            closure,
        }
    }

    fn canonical_store_with_genesis(
        context: &AdmissionContext,
    ) -> (
        MemoryAuthorityStore,
        FailOnceCanonicalStore,
        CanonicalAdmissionProjection<FailOnceCanonicalStore, CanonicalFixtureEvidence>,
    ) {
        let state = CanonicalRefState::default();
        let ref_root =
            canonical_ref_state_root(&state).expect("empty canonical ref state has a root");
        let staging = FailOnceCanonicalStore::default();
        staging
            .stage_ref_state(ref_root, state)
            .expect("genesis ref state stages before the injected fault");

        let mut head = genesis(context);
        head.ref_root = ref_root;
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(78));
        initialize_repository(&store, &context.head_key, &head)
            .expect("canonical genesis head initializes");
        let projection =
            CanonicalAdmissionProjection::new(staging.clone(), CanonicalFixtureEvidence);
        (store, staging, projection)
    }

    fn create(ref_name: &[u8], new: u8) -> ReceiveCommand {
        ReceiveCommand {
            old: oid(0),
            new: oid(new),
            ref_name: ref_name.to_vec(),
        }
    }

    fn update(ref_name: &[u8], old: u8, new: u8) -> ReceiveCommand {
        ReceiveCommand {
            old: oid(old),
            new: oid(new),
            ref_name: ref_name.to_vec(),
        }
    }

    #[test]
    fn fabricated_carried_roots_are_refused_before_publication() {
        let permitted_context = context();
        let permitted_store = store_with_genesis(&permitted_context);
        let permitted = completion(vec![create(b"refs/heads/permitted", 20)], true);
        assert!(
            admit_validated_receive(
                &permitted_store,
                &permitted_context,
                &permitted,
                AdmissionLimits::default(),
                &FixtureProjection::default(),
            )
            .is_ok(),
            "the unmodified carried-forward basis is the permitted twin"
        );

        for (mutation, expected_field) in [
            (
                FixtureMaterializationMutation::ForgePositionRoot,
                "carried forge position root",
            ),
            (
                FixtureMaterializationMutation::RetentionRoot,
                "carried retention root",
            ),
            (
                FixtureMaterializationMutation::OutboxRoot,
                "carried outbox root",
            ),
            (
                FixtureMaterializationMutation::PolicyEpoch,
                "carried policy epoch",
            ),
            (
                FixtureMaterializationMutation::CompactionGenerationLink,
                "compaction generation link",
            ),
            (
                FixtureMaterializationMutation::RecordForgePositionRoot,
                "RCR resulting forge position root",
            ),
        ] {
            let context = context();
            let store = store_with_genesis(&context);
            let projection = FixtureProjection {
                materialization_mutation: Some(mutation),
                ..FixtureProjection::default()
            };
            let completion = completion(vec![create(b"refs/heads/main", 21)], true);

            let refusal = match admit_validated_receive(
                &store,
                &context,
                &completion,
                AdmissionLimits::default(),
                &projection,
            ) {
                Err(refusal) => refusal,
                Ok(_) => panic!("{mutation:?} must not reach publication"),
            };
            assert!(
                matches!(
                    refusal,
                    AdmissionError::MaterializationMismatch(field) if field == expected_field
                ),
                "{mutation:?} must identify its violated continuation, got {refusal:?}"
            );

            let receipt = match store.read_head(&context.head_key).expect("head reads") {
                HeadRead::Present(receipt) => receipt,
                HeadRead::Absent => panic!("materialization refusal must not remove the head"),
            };
            let body: RepositoryAuthorityHeadBody =
                decode_body(receipt.body(), fgit_codec::DecodeLimits::DEFAULT)
                    .expect("head remains canonical");
            assert_eq!(
                body.latest_repository_sequence, None,
                "{mutation:?} must fail before publishing a commit"
            );
        }
    }

    #[test]
    fn head_generation_skew_is_authority_integrity_not_materializer_blame() {
        let context = context();
        let receipt_generation = HeadGeneration::try_new(2).expect("fixture generation is valid");
        let body_generation = HeadGeneration::try_new(3).expect("fixture generation is valid");
        let mut body = genesis(&context);
        body.generation = body_generation;
        let authenticated = AuthenticatedHead::new(
            HeadReadReceipt::new(
                context.head_key,
                AuthorityVersionToken::from_opaque_bytes(
                    [0xA5; fgit_authority::VERSION_TOKEN_BYTES],
                ),
                receipt_generation,
                fgit_codec::encode_body(&body).expect("fixture head encodes"),
            ),
            StoreInstanceId::from_raw(77),
        );

        match basis_from_authenticated(&authenticated) {
            Err(AdmissionError::HeadGenerationMismatch { receipt, body }) => {
                assert_eq!(receipt, receipt_generation);
                assert_eq!(body, body_generation);
            }
            Err(other) => panic!("generation skew must retain its authority cause, got {other:?}"),
            Ok(_) => panic!("generation-skewed authenticated head must not form a basis"),
        }
    }

    #[test]
    fn one_atomic_push_commits_once_and_same_seal_retries() {
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let completion = completion(vec![create(b"refs/heads/main", 21)], true);

        let first = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("first admission commits");
        let retry = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("identical retry resolves its seal");

        assert_eq!(first.session, retry.session);
        assert_eq!(first.commands, retry.commands);
        assert!(matches!(
            first.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let head = match store.read_head(&context.head_key).expect("head reads") {
            HeadRead::Present(receipt) => receipt,
            HeadRead::Absent => panic!("committed push must leave a head"),
        };
        let body: RepositoryAuthorityHeadBody =
            decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT).expect("head decodes");
        assert_eq!(
            body.latest_decision_sequence,
            Some(fgit_types::DecisionSequence::FIRST)
        );
        assert_eq!(
            body.latest_repository_sequence,
            Some(RepositorySequence::FIRST)
        );
    }

    #[test]
    fn already_decided_returns_the_existing_terminal_outcome_for_its_txid() {
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let completion = completion(vec![create(b"refs/heads/main", 61)], true);
        let admitted = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("fixture admission commits once");

        let tx_id = admitted.session.tx_ids[0];
        let terminal = admitted.commands[0].terminal;
        assert_eq!(
            already_decided_terminal(tx_id, vec![(tx_id, terminal)])
                .expect("a duplicate must surface its existing terminal outcome"),
            terminal
        );
        assert!(matches!(
            already_decided_terminal(tx_id, Vec::new()),
            Err(AdmissionError::AlreadyDecidedOutcomeMissing)
        ));
    }

    #[test]
    fn post_cas_disconnect_is_answered_only_by_txid_lookup() {
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let completion = completion(vec![create(b"refs/heads/main", 22)], true);

        let admitted = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("CAS can commit before response delivery");
        let recovered = resolve_outcome(
            &store,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            admitted.session.tx_ids[0],
        )
        .expect("TxId outcome lookup succeeds after disconnect");
        assert_eq!(
            recovered,
            OutcomeLookup::Decided(admitted.commands[0].terminal)
        );
    }

    #[test]
    fn cas_loser_resolves_and_retries_the_same_sealed_request() {
        // Transcript since f09d bound carried-forward roots to the
        // authenticated basis: [1] seal-body put_if_absent, [2] head read,
        // [3] outcome-index read, [4] basis head read, [5] receipt
        // authentication, [6] projection head read, [7..8] staged batch and
        // ref frames, [9] post-staging basis re-read -- so the publication
        // CAS is operation 10, with the post-stamp outcome fold reading the
        // exact carried stream afterwards.  Keeping that transcript explicit
        // makes a changed authority call graph fail this planted-race test
        // instead of silently skipping it.
        const PUBLISH_CAS_OPERATION: OpIndex = OpIndex::from_raw(10);
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let completion = completion(vec![create(b"refs/heads/main", 31)], true);
        store.install_fault_plan(FaultPlan::explicit(vec![
            FaultDirective::new(
                PUBLISH_CAS_OPERATION,
                FaultKind::DuplicateRequest {
                    deliver: DuplicateDelivery::Second,
                },
            )
            .only_for(AuthorityOpKind::CompareExchangeHead),
        ]));

        let observed_loser = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("duplicate CAS response resolves through TxId replay");
        let retry = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("same sealed request retries without a second decision");

        let faults = store.fault_log();
        assert_eq!(faults.len(), 1);
        assert_eq!(
            faults.records()[0].at,
            PUBLISH_CAS_OPERATION,
            "the planted duplication must reach the publication CAS"
        );
        assert_eq!(
            faults.records()[0].op_kind,
            AuthorityOpKind::CompareExchangeHead
        );
        assert!(faults.records()[0].effect_reached);
        assert_eq!(observed_loser.session, retry.session);
        assert_eq!(observed_loser.commands, retry.commands);
    }

    #[test]
    fn atomic_stale_ref_refuses_every_command_without_a_commit() {
        let context = context();
        let store = store_with_genesis(&context);
        let mut projection = FixtureProjection::default();
        projection.refs.insert(
            RefName::try_new(b"refs/heads/main").expect("valid ref"),
            oid(9),
        );
        let completion = completion(
            vec![
                create(b"refs/heads/topic", 23),
                update(b"refs/heads/main", 8, 24),
            ],
            true,
        );

        let result = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("stale atomic request records one refusal");

        assert_eq!(result.session.tx_ids.len(), 1);
        assert!(result.commands.iter().all(|command| {
            matches!(
                command.terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    ..
                }
            )
        }));
        assert!(
            result
                .command_statuses()
                .iter()
                .all(|status| matches!(status, ReceiveCommandStatus::Rejected { .. }))
        );
        let head = match store.read_head(&context.head_key).expect("head reads") {
            HeadRead::Present(receipt) => receipt,
            HeadRead::Absent => panic!("refusal advances the decision head"),
        };
        let body: RepositoryAuthorityHeadBody =
            decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT).expect("head decodes");
        assert_eq!(body.latest_repository_sequence, None);
    }

    #[test]
    fn atomic_materializer_refusal_leaves_no_partial_commit() {
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection {
            reject_commit: true,
            ..FixtureProjection::default()
        };
        let completion = completion(
            vec![create(b"refs/heads/one", 32), create(b"refs/heads/two", 33)],
            true,
        );

        let result = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("terminal policy refusal is published atomically");

        assert!(result.commands.iter().all(|command| {
            matches!(
                command.terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ProtectedRefTransitionDenied,
                    ..
                }
            )
        }));
        let head = match store.read_head(&context.head_key).expect("head reads") {
            HeadRead::Present(receipt) => receipt,
            HeadRead::Absent => panic!("refusal advances the decision head"),
        };
        let body: RepositoryAuthorityHeadBody =
            decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT).expect("head decodes");
        assert_eq!(body.latest_repository_sequence, None);
    }

    #[test]
    fn atomic_staging_fault_leaves_every_command_undecided_then_retries() {
        // Transcript since f09d bound carried-forward roots to the
        // authenticated basis: [1] seal-body put_if_absent, [2] head read,
        // [3] outcome-index read, [4] basis head read, [5] receipt
        // authentication, [6] projection head read.  The first `put_if_absent`
        // in `publish_decisions` therefore stages the decision batch at
        // operation seven, with the second staged frame at eight, the
        // post-staging basis re-read at nine, and the publication CAS at ten.
        // A lost request at seven is deliberately before the publication CAS:
        // the body may not be a decision merely because it was prepared for
        // publication.
        const STAGE_BATCH_OPERATION: OpIndex = OpIndex::from_raw(7);

        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let completion = completion(
            vec![create(b"refs/heads/one", 35), create(b"refs/heads/two", 36)],
            true,
        );
        let lowered = lower_input(&context, &receive_input(&completion))
            .expect("atomic request lowers before the injected store failure");
        let tx_id = derive_tx_id(&context, &lowered[0]).expect("transaction id derives");
        store.install_fault_plan(FaultPlan::explicit(vec![
            FaultDirective::new(STAGE_BATCH_OPERATION, FaultKind::LoseRequest)
                .only_for(AuthorityOpKind::PutIfAbsent),
        ]));

        assert!(
            admit_validated_receive(
                &store,
                &context,
                &completion,
                AdmissionLimits::default(),
                &projection,
            )
            .is_err(),
            "a before-effect staging loss cannot report a terminal receive result"
        );
        let faults = store.fault_log();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults.records()[0].at, STAGE_BATCH_OPERATION);
        assert_eq!(faults.records()[0].op_kind, AuthorityOpKind::PutIfAbsent);
        assert!(!faults.records()[0].effect_reached);
        assert_eq!(
            resolve_outcome(
                &store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )
            .expect("undecided outcome lookup succeeds"),
            OutcomeLookup::Undecided,
            "an unstaged atomic candidate must not decide either wire command"
        );
        let head = match store.read_head(&context.head_key).expect("head reads") {
            HeadRead::Present(receipt) => receipt,
            HeadRead::Absent => panic!("the genesis head remains visible"),
        };
        let body: RepositoryAuthorityHeadBody =
            decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT).expect("head decodes");
        assert_eq!(body.latest_decision_sequence, None);
        assert_eq!(body.latest_repository_sequence, None);

        let retry = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("the same atomic seal remains retryable after the staging loss");
        assert_eq!(retry.session.tx_ids, vec![tx_id]);
        assert!(retry.commands.iter().all(|command| {
            command.tx_id == tx_id
                && matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })
        }));
    }

    #[test]
    fn canonical_pre_cas_stage_failure_leaves_its_seal_undecided_then_retries() {
        let context = context();
        let mut completion = completion(vec![create(b"refs/heads/main", 37)], true);
        completion.closure.object_closure_root = permitted_object_closure_root(
            &PermittedObjectClosure::new(completion.closure.objects.clone()),
        )
        .expect("the canonical closure commitment derives");
        let lowered = lower_input(&context, &receive_input(&completion))
            .expect("the canonical retry request lowers");
        let tx_id = derive_tx_id(&context, &lowered[0])
            .expect("the canonical retry transaction identity derives");
        let (store, staging, projection) = canonical_store_with_genesis(&context);
        let before = match store
            .read_head(&context.head_key)
            .expect("genesis head reads")
        {
            HeadRead::Present(receipt) => receipt.token(),
            HeadRead::Absent => panic!("canonical setup initialized the genesis head"),
        };

        staging.fail_next_ref_stage();
        let failure = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect_err("a pre-CAS canonical staging failure cannot publish a terminal refusal");
        assert!(
            matches!(
                failure,
                AdmissionError::ProjectionUnavailable {
                    tx_id: ref failed_tx_id,
                    code: RefusalCode::EvidenceMissing,
                } if failed_tx_id.as_ref() == &tx_id
            ),
            "the unavailable result must name the sealed retryable transaction, got {failure:?}"
        );
        assert_eq!(
            resolve_outcome(
                &store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )
            .expect("undecided canonical outcome lookup succeeds"),
            OutcomeLookup::Undecided,
            "a stage failure before head CAS must leave the sealed transaction undecided"
        );
        let after = match store
            .read_head(&context.head_key)
            .expect("head reads after the failed stage")
        {
            HeadRead::Present(receipt) => receipt.token(),
            HeadRead::Absent => panic!("a pre-CAS failure cannot remove the genesis head"),
        };
        assert_eq!(
            after, before,
            "a pre-CAS canonical stage failure must not advance the authority head"
        );

        let retry = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("the identical sealed request retries after staging becomes available");
        assert_eq!(retry.session.tx_ids, vec![tx_id]);
        assert!(matches!(
            retry.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            resolve_outcome(
                &store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                tx_id,
            )
            .expect("retry outcome lookup succeeds"),
            OutcomeLookup::Decided(retry.commands[0].terminal),
            "the retry must publish the only terminal decision for the original seal"
        );
    }

    #[test]
    fn non_atomic_session_has_replayable_per_ref_outcomes() {
        let context = context();
        let store = store_with_genesis(&context);
        let mut projection = FixtureProjection::default();
        projection.refs.insert(
            RefName::try_new(b"refs/heads/main").expect("valid ref"),
            oid(9),
        );
        let completion = completion(
            vec![
                create(b"refs/heads/topic", 25),
                update(b"refs/heads/main", 8, 26),
            ],
            false,
        );

        let result = admit_validated_receive(
            &store,
            &context,
            &completion,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("non-atomic session decides each command");

        assert_eq!(result.session.tx_ids.len(), 2);
        assert_ne!(result.session.tx_ids[0], result.session.tx_ids[1]);
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(matches!(
            result.commands[1].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        ));
        assert_eq!(
            result.command_statuses(),
            vec![
                ReceiveCommandStatus::Ok,
                ReceiveCommandStatus::Rejected {
                    message: b"stale info".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn zero_pair_is_refused_and_nearby_create_proceeds() {
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let malformed = completion(
            vec![ReceiveCommand {
                old: oid(0),
                new: oid(0),
                ref_name: b"refs/heads/main".to_vec(),
            }],
            true,
        );
        assert!(matches!(
            admit_validated_receive(
                &store,
                &context,
                &malformed,
                AdmissionLimits::default(),
                &projection,
            ),
            Err(AdmissionError::InvalidZeroPair)
        ));

        let permitted = completion(vec![create(b"refs/heads/main", 27)], true);
        assert!(
            admit_validated_receive(
                &store,
                &context,
                &permitted,
                AdmissionLimits::default(),
                &projection,
            )
            .is_ok()
        );
    }

    #[test]
    fn validation_requires_quarantined_pack_and_delete_only_twin_is_permitted() {
        let creation = completion(vec![create(b"refs/heads/main", 34)], true);
        assert_eq!(
            validate_receive(
                creation.request(),
                None,
                creation.receipt(),
                &FixtureValidator,
            ),
            Err(RefusalCode::ObjectClosureIncomplete)
        );

        let delete = ReceiveRequest {
            commands: vec![ReceiveCommand {
                old: oid(9),
                new: oid(0),
                ref_name: b"refs/heads/main".to_vec(),
            }],
            capabilities: Vec::new(),
            push_options: Vec::new(),
            certificate: None,
        };
        let delete_receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 0,
            pack_bytes: 0,
            delete_only: true,
        };
        assert!(validate_receive(&delete, None, &delete_receipt, &FixtureValidator).is_ok());
    }

    #[test]
    fn command_ceiling_refuses_before_lowering_and_permitted_twin_proceeds() {
        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let over = completion(
            vec![create(b"refs/heads/one", 28), create(b"refs/heads/two", 29)],
            true,
        );
        let one = AdmissionLimits {
            max_commands: 1,
            max_cas_replans: 1,
        };
        assert!(matches!(
            admit_validated_receive(&store, &context, &over, one, &projection,),
            Err(AdmissionError::CommandLimitExceeded { limit: 1 })
        ));

        let permitted = completion(vec![create(b"refs/heads/one", 28)], true);
        assert!(admit_validated_receive(&store, &context, &permitted, one, &projection,).is_ok());
    }
}
