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

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityStore, HeadKey, HeadRead, IdempotencyKey,
    OutcomeFailure, OutcomeLookup, SealAttempt, SealFailure, initialize_repository, seal_request,
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
    QuarantineReceipt, ReceiveCommand, ReceiveCommandKind, ReceiveCommandStatus, ReceiveError,
    ReceiveRequest, UnpackStatus, report_status,
};
use fgit_wire::{GitObjectFormat, Packet};

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

/// The single integration seam the absent ref-tree materializer must satisfy.
///
/// Every method receives a [`PublicationBasis`] derived from an authenticated
/// authority receipt.  Implementors therefore must not use an advertisement,
/// a connection-local cache, or a mutable local ref table as the basis for an
/// admission decision.  The trait returns `RefusalCode` rather than inventing
/// a second decision vocabulary; its errors are terminal only after the
/// request has been sealed by this crate.
pub trait AdmissionProjection {
    /// Opens a read-only projection rooted in exactly this authenticated head.
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode>;

    /// Materializes a committed fold into an RCR and its successor roots.
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, RefusalCode>;

    /// Supplies the policy evidence for a terminal refusal.
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode>;
}

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
    /// Resulting authenticated outcome-index root.
    pub outcome_index_root: Digest,
    /// Root over policy evaluation evidence.
    pub policy_decision_root: Digest,
    /// Root over invariant checks for the candidate.
    pub invariant_evidence_root: Digest,
    /// Root over external-effect obligations created by this candidate.
    pub outbox_effect_root: Digest,
    /// Root over retention changes created by this candidate.
    pub retention_delta_root: Digest,
    /// Root over the decision batch evidence.
    pub batch_evidence_root: Digest,
}

/// Policy and evidence owner used by the production projection.
pub trait AdmissionEvidence {
    /// Produces evidence for a committing ref-only fold at this exact basis.
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

impl<Store, Evidence> AdmissionProjection for CanonicalAdmissionProjection<Store, Evidence>
where
    Store: CanonicalAdmissionStore,
    Evidence: AdmissionEvidence,
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

    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, RefusalCode> {
        let effects = fold
            .effects()
            .ok_or(RefusalCode::ConflictingSemanticEffects)?;
        if !effects.forge.is_empty() || !effects.retention.is_empty() || !effects.outbox.is_empty()
        {
            return Err(RefusalCode::ConflictingSemanticEffects);
        }

        let current = self.resolve_ref_state(basis.body().ref_root)?;
        let next = current.apply(&effects.refs);
        let ref_root = canonical_ref_state_root(&next)?;
        self.store.stage_ref_state(ref_root, next)?;

        let closure_body = PermittedObjectClosure::new(closure.objects.clone());
        let object_closure_root = permitted_object_closure_root(&closure_body)?;
        if object_closure_root != closure.object_closure_root {
            return Err(RefusalCode::ObjectClosureIncomplete);
        }
        self.store
            .stage_permitted_object_closure(object_closure_root, closure_body)?;

        let evidence = self.evidence.commit_evidence(basis, request, fold)?;
        let ref_delta_root =
            canonical_ref_delta_root(&CanonicalRefDelta::from_effects(&effects.refs))?;
        let roots = ResultingRoots {
            ref_root,
            forge_position_root: basis.body().forge_position_root,
            outcome_index_root: evidence.outcome_index_root,
            retention_root: basis.body().retention_root,
            outbox_root: basis.body().outbox_root,
            policy_epoch: basis.body().policy_epoch,
            batch_evidence_root: evidence.batch_evidence_root,
        };
        Ok(CommitMaterialization {
            record: RepositoryCommitRecord {
                repository_id: request.repository,
                // `PublicationPlan` owns final sequence and predecessor
                // stamping. These values only satisfy the complete RCR shape
                // before it is handed to that plan; they are never identified.
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
        })
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
    /// The head identity could not be computed or did not have its pinned type.
    HeadIdentity(fgit_codec::CodecRefusal),
    /// Chronicle refused a batch/head pair before it reached the CAS.
    Chronicle(fgit_chronicle::ChronicleRefusal),
    /// Publication or replay refused to answer.
    Outcome(Box<OutcomeFailure>),
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
            Self::HeadIdentity(refusal) => {
                write!(formatter, "authority head identity refused: {refusal}")
            }
            Self::Chronicle(refusal) => {
                write!(formatter, "chronicle publication refused: {refusal}")
            }
            Self::Outcome(failure) => {
                write!(formatter, "terminal outcome resolution failed: {failure}")
            }
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
    limits.validate()?;
    validate_admission_input(context, validated, limits)?;
    let atomic = validated.request.has_capability(b"atomic");
    let lowered_requests = lower_session(context, &validated.request, atomic)?;
    let tx_ids = lowered_requests
        .iter()
        .map(|request| derive_tx_id(context, request))
        .collect::<Result<Vec<_>, _>>()?;

    let mut commands = Vec::with_capacity(validated.request.commands.len());
    if atomic {
        let terminal = admit_one(
            store,
            context,
            validated,
            &lowered_requests[0],
            projection,
            limits,
        )?;
        commands.resize(
            validated.request.commands.len(),
            CommandOutcome {
                tx_id: tx_ids[0],
                terminal,
            },
        );
    } else {
        for (request, tx_id) in lowered_requests.iter().zip(&tx_ids) {
            let terminal = admit_one(store, context, validated, request, projection, limits)?;
            commands.push(CommandOutcome {
                tx_id: *tx_id,
                terminal,
            });
        }
    }
    Ok(AdmissionResult {
        session: SessionMapping { atomic, tx_ids },
        commands,
    })
}

fn validate_admission_input(
    context: &AdmissionContext,
    validated: &ValidatedReceive,
    limits: AdmissionLimits,
) -> Result<(), AdmissionError> {
    if validated.receipt.object_format != context.object_format {
        return Err(AdmissionError::ObjectFormatMismatch);
    }
    if validated.request.commands.len() > limits.max_commands {
        return Err(AdmissionError::CommandLimitExceeded {
            limit: limits.max_commands,
        });
    }
    if validated.request.commands.is_empty() {
        return Err(AdmissionError::CommandLimitExceeded { limit: 0 });
    }
    if validated.request.deletes_only() != validated.receipt.delete_only {
        return Err(AdmissionError::MaterializationMismatch(
            "quarantine delete-only receipt",
        ));
    }
    Ok(())
}

fn lower_session(
    context: &AdmissionContext,
    receive: &ReceiveRequest,
    atomic: bool,
) -> Result<Vec<LoweredRequest>, AdmissionError> {
    let push_options = receive
        .push_options
        .iter()
        .cloned()
        .map(fgit_authority::PushOption::new)
        .collect::<Result<Vec<_>, _>>()?;
    if atomic {
        let commands = receive
            .commands
            .iter()
            .map(lower_command)
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

    receive
        .commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            Ok(LoweredRequest {
                semantic: fgit_authority::SemanticRequest::build(
                    RECEIVE_ADMISSION_SCHEMA,
                    context.object_format,
                    false,
                    vec![lower_command(command)?],
                    push_options.clone(),
                    Vec::new(),
                )?,
                idempotency_key: non_atomic_key(&context.idempotency_key, index)?,
            })
        })
        .collect()
}

fn lower_command(command: &ReceiveCommand) -> Result<fgit_authority::RefCommand, AdmissionError> {
    let name = RefName::try_new(&command.ref_name).map_err(AdmissionError::RefName)?;
    let expected_old = command.expected_old().map_or(
        fgit_authority::ExpectedOld::Absent,
        fgit_authority::ExpectedOld::Exactly,
    );
    let proposed_new = match command.kind() {
        ReceiveCommandKind::Create | ReceiveCommandKind::Update => {
            fgit_authority::ProposedNew::Update(command.new)
        }
        ReceiveCommandKind::Delete => fgit_authority::ProposedNew::Delete,
        ReceiveCommandKind::InvalidZeroPair => return Err(AdmissionError::InvalidZeroPair),
    };
    Ok(fgit_authority::RefCommand {
        name,
        expected_old,
        proposed_new,
        // Receive-pack carries an expected old OID rather than a separate
        // force bit. Ref protection/fast-forward policy is evaluated by the
        // projection; it never treats the transport as evidence of a force.
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
    validated: &ValidatedReceive,
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

    for _ in 0..limits.max_cas_replans {
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome(
            store,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            tx_id,
        )? {
            return Ok(terminal);
        }
        let (basis, receipt, authenticated) = read_basis(store, &context.head_key)?;
        let closure = &validated.closure;
        let snapshot = match projection.snapshot(&basis, &authenticated) {
            Ok(snapshot) => snapshot,
            Err(code) => match publish_refusal(
                store,
                context,
                &basis,
                receipt.token(),
                admission.seal_id(),
                tx_id,
                code,
                projection,
            )? {
                Some(terminal) => return Ok(terminal),
                None => continue,
            },
        };
        let model_request = model_request(context, &lowered.semantic, tx_id, closure)?;
        let fold = IntentEvaluator::new().evaluate(snapshot.as_fold_basis(), &model_request);
        let terminal = match &fold.outcome {
            FoldOutcome::Aborted { code, .. } => publish_refusal(
                store,
                context,
                &basis,
                receipt.token(),
                admission.seal_id(),
                tx_id,
                *code,
                projection,
            )?,
            FoldOutcome::Folded(_) => {
                match projection.materialize_commit(&basis, &model_request, &fold, closure) {
                    Ok(materialization) => publish_commit(
                        store,
                        context,
                        &basis,
                        receipt.token(),
                        tx_id,
                        &lowered.semantic,
                        closure,
                        materialization,
                    )?,
                    Err(code) => publish_refusal(
                        store,
                        context,
                        &basis,
                        receipt.token(),
                        admission.seal_id(),
                        tx_id,
                        code,
                        projection,
                    )?,
                }
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
    let body = authenticated.body().map_err(|failure| match failure {
        fgit_authority::HeadBodyRefusal::Codec(refusal) => AdmissionError::HeadCodec(refusal),
        fgit_authority::HeadBodyRefusal::GenerationMismatch { .. } => {
            AdmissionError::MaterializationMismatch("head receipt generation")
        }
    })?;
    let id = body_id(&CryptoBodyIdentity, &body)
        .map_err(AdmissionError::HeadIdentity)
        .and_then(|id| {
            fgit_types::RepositoryAuthorityHeadId::from_internal_object_id(id)
                .map_err(|refusal| AdmissionError::HeadIdentity(refusal.into()))
        })?;
    Ok((PublicationBasis::new(id, body), receipt, authenticated))
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
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AuthorityStore + ?Sized,
{
    validate_commit_materialization(context, tx_id, semantic, closure, &materialization)?;
    let mut plan = PublicationPlan::open(basis.clone())?;
    plan.commit(materialization.record);
    let publication = plan.seal(&CryptoBodyIdentity, materialization.roots)?;
    outcome_after_publish(store, context, expected, &publication)
}

fn validate_commit_materialization(
    context: &AdmissionContext,
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
    if record.resulting_forge_position_root != materialization.roots.forge_position_root {
        return Err(AdmissionError::MaterializationMismatch(
            "resulting forge root",
        ));
    }
    if record.policy_epoch != materialization.roots.policy_epoch {
        return Err(AdmissionError::MaterializationMismatch("policy epoch"));
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
) -> Result<Option<fgit_authority::TerminalOutcome>, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    let materialization =
        projection
            .materialize_refusal(basis, tx_id, code)
            .map_err(|fallback| {
                if fallback == code {
                    AdmissionError::MaterializationMismatch("refusal materialization")
                } else {
                    AdmissionError::MaterializationMismatch("refusal policy replacement")
                }
            })?;
    let sequence = basis.open_decision_sequence()?;
    let refusal = RefusalRecordBody {
        tx_id,
        seal_id,
        decision_sequence: sequence,
        code,
        policy_epoch: materialization.policy_epoch,
        detail: materialization.detail,
        evidence_root: materialization.evidence_root,
    };
    let refusal_id = refusal_record_id(&refusal)?;
    let key = fgit_authority::body_key(IdentityDomain::RefusalRecord, &refusal)?;
    let bytes = encode_body(&refusal).map_err(AdmissionError::HeadCodec)?;
    store.put_if_absent(&key, &bytes)?;

    let mut plan = PublicationPlan::open(basis.clone())?;
    plan.refuse(tx_id, code, refusal_id);
    let roots = ResultingRoots::carried_forward(basis, materialization.evidence_root);
    let publication = plan.seal(&CryptoBodyIdentity, roots)?;
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
    let tx_id = publication
        .batch()
        .decisions
        .first()
        .map(|decision| decision.tx_id)
        .ok_or(AdmissionError::PublishedOutcomeMissing)?;
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

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use std::collections::{BTreeMap, BTreeSet};

    use fgit_authority::{
        AuthorityOpKind, DuplicateDelivery, FaultDirective, FaultKind, FaultPlan,
        FaultableAuthorityStore, HeadKey, MemoryAuthorityStore, OpIndex, StoreInstanceId,
        initialize_repository, resolve_outcome,
    };
    use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryCommitRecord, decode_body};
    use fgit_reference::effect::FoldOutcome;
    use fgit_types::{
        DigestAlgorithmId, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalSnapshotId,
        RegistryEpoch, RepositorySequence,
    };
    use fgit_wire::Capability;

    use super::*;

    #[derive(Default)]
    struct FixtureProjection {
        reject_commit: bool,
        refs: BTreeMap<RefName, fgit_types::GitOid>,
        forge_positions: BTreeMap<
            fgit_reference::intent::ForgeStreamId,
            fgit_reference::intent::ForgeStreamPosition,
        >,
        retention: BTreeSet<fgit_reference::intent::RetentionRoot>,
        outbox: BTreeMap<fgit_reference::intent::OutboxDeliveryKey, Digest>,
    }

    impl AdmissionProjection for FixtureProjection {
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
            if self.reject_commit {
                return Err(RefusalCode::ProtectedRefTransitionDenied);
            }
            if !matches!(fold.outcome, FoldOutcome::Folded(_)) {
                return Err(RefusalCode::ConflictingSemanticEffects);
            }
            let roots = ResultingRoots {
                ref_root: digest(2),
                forge_position_root: digest(3),
                outcome_index_root: digest(4),
                retention_root: basis.body().retention_root,
                outbox_root: digest(5),
                policy_epoch: basis.body().policy_epoch,
                batch_evidence_root: digest(6),
            };
            Ok(CommitMaterialization {
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
        // After installing the plan, this admission path performs two seal
        // puts; two exact-outcome probes; then a head read plus one receipt
        // authentication shared by the publication basis and projection.
        // The atomic publisher now also reads the authenticated decision
        // stream to mint its duplicate-absence witness before it reaches the
        // CAS, so the CAS is operation 11. Keeping that transcript explicit
        // makes a changed
        // authority call graph fail this planted-race test instead of silently
        // skipping it.
        const PUBLISH_CAS_OPERATION: OpIndex = OpIndex::from_raw(11);
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
        // The first seven operations bind the seal and probe its outcome; the
        // next two authenticate the authoritative basis and projection.  The
        // first `put_if_absent` in `publish_decisions` therefore stages the
        // decision batch at operation nine.  A lost request there is
        // deliberately before the publication CAS: the body may not be a
        // decision merely because it was prepared for publication.
        const STAGE_BATCH_OPERATION: OpIndex = OpIndex::from_raw(9);

        let context = context();
        let store = store_with_genesis(&context);
        let projection = FixtureProjection::default();
        let completion = completion(
            vec![create(b"refs/heads/one", 35), create(b"refs/heads/two", 36)],
            true,
        );
        let lowered = lower_session(&context, completion.request(), true)
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
