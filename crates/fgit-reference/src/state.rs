//! Repository state: roots, the authority head, and everything staged behind
//! it.
//!
//! ## One authority, and only one
//!
//! `docs/ADR-0001-CANONICAL-STATE.md` decision 2 puts the canonical roots
//! *inside* the authority head body rather than beside it. This module follows
//! that literally: there is no `refs` field on [`RepositoryState`]. Canonical
//! refs are [`AuthorityHeadBody::roots`], reachable only through
//! [`RepositoryState::head`]. A second copy of the ref table would be a second
//! truth, and keeping one would make "the head establishes canonical order" a
//! convention instead of a fact about the type.
//!
//! Where §8.2 names a `Digest` root, this model carries the root's *content*.
//! Deciding what the resulting roots are is the model's job; binding content to
//! a digest is the canonical codec's, and FG-003b does it over exactly these
//! values. The consequence is stated as a non-claim in the crate
//! documentation.
//!
//! ## Publication epochs are represented, not assumed
//!
//! §9 distinguishes staged, visible, and durable. [`RepositoryState`] holds
//! staged batches and quarantined objects in fields the head does not
//! reference, so "staged but not canonical" is a state the model can actually
//! be in — which is what makes release-blocking invariant 10 ("no staged or
//! quarantined object becomes a retention root before commit") testable rather
//! than asserted.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::hash::Digest;
use fgit_types::identity::{
    PreparedTxnCapsuleId, PrincipalId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, RepositoryId, TenantId, TransactionSealId, TxId,
};
use fgit_types::label::SchemaId;
use fgit_types::native::{GitHashAlgorithm, GitOid};
use fgit_types::numeric::{
    DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositorySequence,
};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::DecisionOutcome;

use crate::capsule::PreparedTxnCapsule;
use crate::decision::{DecisionBatch, PublishedDecision, RepositoryCommitRecord};
use crate::intent::{
    DurabilityProfile, ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey, RetentionRoot,
    SealFields, TxIdDerivationInputs,
};

/// A breach of one of the model's own invariants.
///
/// This is deliberately **not** a [`fgit_types::vocabulary::RefusalCode`]. A
/// refusal is a terminal decision that enters the authenticated decision
/// stream and is replayable as history; an invariant breach means the model
/// was asked to do something its own rules say cannot happen, and writing that
/// into history would be recording a bug as a decision. §8.4 requires a
/// conflicting accelerator to *fail closed*, and §15.8 calls a second terminal
/// outcome "an invariant failure" rather than a refusal — so the model refuses
/// to make the transition at all and reports this typed value instead.
///
/// Every variant is `Copy` and small, so returning one by value in a `Result`
/// stays cheap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InvariantBreach {
    /// A batch was asked to hold two decisions for one sealed transaction.
    SecondDecisionInBatch {
        /// The transaction that already had a decision in the batch.
        tx_id: TxId,
    },
    /// A sealed transaction already terminal in the authenticated outcome
    /// index was given a second terminal decision.
    SecondTerminalDecision {
        /// The transaction that is already terminal.
        tx_id: TxId,
        /// The outcome already recorded.
        existing: DecisionOutcome,
    },
    /// A committed outcome was pushed through the refusal path, or the
    /// reverse.
    RefusalOutcomeExpected {
        /// The transaction whose outcome had the wrong shape.
        tx_id: TxId,
    },
    /// A monotone counter reached its maximum.
    SequenceExhausted {
        /// Which counter: `"decision"`, `"repository"`, or `"generation"`.
        kind: &'static str,
    },
    /// A batch that publishes nothing would consume a head generation.
    EmptyDecisionBatch {
        /// The empty batch.
        batch: RepositoryDecisionBatchId,
    },
    /// A candidate head did not name the exact current head as predecessor.
    HeadPredecessorMismatch {
        /// The head that is actually current.
        current: RepositoryAuthorityHeadId,
        /// The predecessor the candidate declared.
        declared: Option<RepositoryAuthorityHeadId>,
    },
    /// A candidate head's generation was not the immediate successor of the
    /// current head's generation.
    HeadGenerationNotSuccessor {
        /// The current generation.
        current: HeadGeneration,
        /// The generation the candidate declared.
        candidate: HeadGeneration,
    },
    /// A batch's first decision sequence did not continue the head's.
    DecisionSequenceDiscontinuity {
        /// The sequence the head requires next.
        expected: DecisionSequence,
        /// The sequence the batch declared.
        observed: DecisionSequence,
    },
    /// A batch's first repository sequence did not continue the head's.
    RepositorySequenceDiscontinuity {
        /// The sequence the head requires next.
        expected: RepositorySequence,
        /// The sequence the batch declared.
        observed: RepositorySequence,
    },
    /// An identity was introduced twice for different content.
    IdentityReused {
        /// Which identity family: `"head"`, `"batch"`, `"commit"`, `"capsule"`,
        /// or `"seal"`.
        kind: &'static str,
    },
    /// Two requests with identical §3.3 derivation inputs carried different
    /// transaction identities. The derivation is not deterministic.
    TxIdDerivationInconsistent {
        /// The transaction identity the model already bound to these inputs.
        bound: TxId,
        /// The identity the new request carried.
        observed: TxId,
    },
    /// One transaction identity was presented with two different §3.3
    /// derivation input tuples. The derivation is not injective.
    TxIdInputsInconsistent {
        /// The transaction identity that was presented twice.
        tx_id: TxId,
    },
    /// A step named a sealed transaction the model has never sealed.
    UnknownSeal {
        /// The unknown transaction.
        tx_id: TxId,
    },
    /// A step named a prepared capsule the model does not hold.
    UnknownCapsule {
        /// The unknown capsule.
        capsule: PreparedTxnCapsuleId,
    },
    /// A head compare-and-swap named a batch that was never staged.
    UnstagedBatch {
        /// The unknown batch.
        batch: RepositoryDecisionBatchId,
    },
    /// A body named a repository other than this one.
    RepositoryMismatch {
        /// The repository this state owns.
        expected: RepositoryId,
        /// The repository the body named.
        observed: RepositoryId,
    },
    /// A candidate head's roots disagreed with the batch it names.
    ResultingRootMismatch {
        /// Which root disagreed.
        root: &'static str,
    },
    /// An object that never left quarantine appeared in a canonical root.
    QuarantineEscape {
        /// The object that escaped.
        object: GitOid,
    },
}

/// What a principal may do.
///
/// Capabilities are part of the pinned policy snapshot, so a decision is
/// always evaluated against the capability set the head names — never against
/// live external state (§15.9).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrincipalCapabilities {
    /// Ref scopes this principal may write, as the component after `refs/`.
    pub writable_scopes: BTreeSet<Vec<u8>>,
    /// Whether this principal may request a forced non-fast-forward update.
    pub may_force: bool,
    /// Whether this principal may publish forge transitions.
    pub may_publish_forge: bool,
    /// Whether this principal may add a legal-hold retention root.
    pub may_add_legal_hold: bool,
}

impl PrincipalCapabilities {
    /// True when this principal may write refs in `scope`.
    #[must_use]
    pub fn may_write_scope(&self, scope: &[u8]) -> bool {
        self.writable_scopes.contains(scope)
    }
}

/// One pinned policy and configuration snapshot.
///
/// §15.9: canonical policy evaluation is deterministic over one named input
/// root and does not read a clock, an unversioned service, a mutable
/// projection, or model output. Everything a decision needs is in this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySnapshot {
    /// The epoch this snapshot occupies.
    pub epoch: PolicyEpoch,
    /// Ref scopes on which deletion is denied and updates must fast-forward.
    pub protected_scopes: BTreeSet<Vec<u8>>,
    /// Capabilities, by principal.
    pub principals: BTreeMap<PrincipalId, PrincipalCapabilities>,
    /// Largest number of intents admitted in one transaction.
    pub max_intents_per_transaction: usize,
    /// Request schemas this service implements.
    pub supported_schemas: BTreeSet<SchemaId>,
}

impl PolicySnapshot {
    /// The capabilities of one principal, or the empty set.
    ///
    /// An unknown principal has no capability rather than a default one:
    /// absence must not widen authority.
    #[must_use]
    pub fn capabilities_of(&self, principal: PrincipalId) -> PrincipalCapabilities {
        self.principals
            .get(&principal)
            .cloned()
            .unwrap_or_default()
    }

    /// True when `scope` is protected.
    #[must_use]
    pub fn is_protected(&self, scope: &[u8]) -> bool {
        self.protected_scopes.contains(scope)
    }
}

/// The canonical roots one authority head publishes.
///
/// Every collection is ordered by its key, so two states with equal content
/// iterate identically. Plan §16.3 forbids map iteration order from being
/// publication semantics; here there is no unordered map to iterate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryRoots {
    /// Canonical ref values.
    pub refs: BTreeMap<RefName, GitOid>,
    /// Authenticated logical position of every forge stream.
    pub forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    /// Terminal outcome of every sealed transaction that has one.
    pub outcome_index: BTreeMap<TxId, DecisionOutcome>,
    /// Authenticated retention roots.
    pub retention: BTreeSet<RetentionRoot>,
    /// Outbox deliveries owed, by delivery key.
    pub outbox: BTreeMap<OutboxDeliveryKey, Digest>,
}

impl RepositoryRoots {
    /// Every object any canonical root protects.
    ///
    /// Used to check that nothing still in quarantine has become a retention
    /// root.
    pub fn protected_objects(&self) -> impl Iterator<Item = GitOid> {
        self.refs
            .values()
            .copied()
            .chain(self.retention.iter().map(|root| root.object))
    }
}

/// The authenticated body of one repository authority head.
///
/// Mirrors §8.2. The digest roots of the normative body are content here; see
/// the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityHeadBody {
    /// The repository this head governs.
    pub repository: RepositoryId,
    /// Monotone generation.
    pub generation: HeadGeneration,
    /// The exact predecessor, absent only at genesis.
    pub predecessor: Option<RepositoryAuthorityHeadId>,
    /// The decision batch this head publishes, absent only at genesis.
    pub decision_tail: Option<RepositoryDecisionBatchId>,
    /// Highest consumed decision sequence, absent when nothing has been
    /// decided.
    pub latest_decision_sequence: Option<DecisionSequence>,
    /// The most recently committed record, absent when nothing has committed.
    pub latest_committed_rcr: Option<RepositoryCommitId>,
    /// Highest consumed repository sequence, absent when nothing has
    /// committed.
    pub latest_repository_sequence: Option<RepositorySequence>,
    /// The canonical roots.
    pub roots: RepositoryRoots,
    /// The pinned policy and configuration snapshot.
    pub configuration: PolicySnapshot,
    /// The format and algorithm registry epoch needed to interpret bodies.
    pub format_registry_epoch: RegistryEpoch,
}

impl AuthorityHeadBody {
    /// The decision sequence the next terminal decision must consume.
    pub fn next_decision_sequence(&self) -> Result<DecisionSequence, InvariantBreach> {
        self.latest_decision_sequence.map_or_else(
            || Ok(DecisionSequence::FIRST),
            |latest| {
                latest
                    .next()
                    .map_err(|_| InvariantBreach::SequenceExhausted { kind: "decision" })
            },
        )
    }

    /// The repository sequence the next commit must consume.
    pub fn next_repository_sequence(&self) -> Result<RepositorySequence, InvariantBreach> {
        self.latest_repository_sequence.map_or_else(
            || Ok(RepositorySequence::FIRST),
            |latest| {
                latest
                    .next()
                    .map_err(|_| InvariantBreach::SequenceExhausted { kind: "repository" })
            },
        )
    }

    /// The generation a candidate successor head must declare.
    pub fn next_generation(&self) -> Result<HeadGeneration, InvariantBreach> {
        self.generation
            .next()
            .map_err(|_| InvariantBreach::SequenceExhausted { kind: "generation" })
    }
}

/// One authority head: its identity and its authenticated body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityHead {
    /// Identity of the head body.
    pub id: RepositoryAuthorityHeadId,
    /// The authenticated body.
    pub body: AuthorityHeadBody,
}

/// One transaction seal.
///
/// §5.2: the seal is durable identity, not a commit and not an ordering
/// event. It exists so a retry of the same logical mutation cannot become a
/// second logical mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SealRecord {
    /// Identity of the seal body.
    pub seal_id: TransactionSealId,
    /// The stable fields a retry must reproduce exactly.
    pub fields: SealFields,
}

/// An object whose identity has been verified and which canonical roots may
/// reference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectRecord {
    /// Parent objects, for commits. Empty for every other object type.
    ///
    /// The model needs exactly enough of the object graph to decide whether a
    /// ref update fast-forwards. Full object semantics belong to the Git
    /// object engine.
    pub parents: Vec<GitOid>,
}

/// An object staged inside one transaction's quarantine.
///
/// §16.2: incoming bytes stay transaction-scoped and non-retained until
/// bounded validation completes, and promotion is by verified identity — never
/// by a rename treated as truth. The model carries both the identity the
/// sender declared and the identity validation recomputed, so
/// "promotion by verified identity" is a comparison the model performs rather
/// than an assumption it makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedObject {
    /// The identity the sender declared.
    pub declared: GitOid,
    /// The identity bounded validation recomputed from the bytes.
    pub recomputed: GitOid,
    /// Parent objects, for commits.
    pub parents: Vec<GitOid>,
}

impl QuarantinedObject {
    /// True when the recomputed identity matches the declared one.
    #[must_use]
    pub fn is_identity_verified(&self) -> bool {
        self.declared == self.recomputed
    }
}

/// A decision batch that exists but that no authority root references.
///
/// This is §9's *staged* epoch. A staged batch is invisible: no query answers
/// from it, and nothing it names is a retention root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedBatch {
    /// The immutable batch body.
    pub batch: DecisionBatch,
    /// The candidate head that would publish it.
    pub candidate_head: AuthorityHead,
    /// Whether the declared placement predicate has been satisfied.
    pub durability_satisfied: bool,
}

impl StagedBatch {
    /// True when this batch may become visible under its declared profile.
    ///
    /// §9: the canonical source profile is
    /// `Absent -> Staged -> DurabilitySatisfied -> Visible`, so visibility
    /// before durability is not merely discouraged, it is a different profile.
    #[must_use]
    pub fn may_become_visible(&self) -> bool {
        !self
            .batch
            .durability()
            .requires_durability_before_visibility()
            || self.durability_satisfied
    }
}

/// The record of every identity the model has seen, and what it was bound to.
///
/// The model does not compute digests — identity derivation is the canonical
/// codec's and the crypto registry's job. What it *can* do, and does here, is
/// enforce the two laws any correct derivation must satisfy:
///
/// 1. **Determinism.** Two requests whose §3.3 derivation inputs are equal must
///    carry the same [`TxId`].
/// 2. **Injectivity.** One [`TxId`] must never be presented with two different
///    input tuples.
///
/// A derivation that is broken in either direction is caught here even though
/// the digest itself is computed elsewhere. The identity families beyond
/// transactions are tracked for freshness only: an identity may be introduced
/// once, so a publisher cannot reuse a batch or head identity for new content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityLedger {
    tx_by_inputs: BTreeMap<TxIdDerivationInputs, TxId>,
    inputs_by_tx: BTreeMap<TxId, TxIdDerivationInputs>,
    heads: BTreeSet<RepositoryAuthorityHeadId>,
    batches: BTreeSet<RepositoryDecisionBatchId>,
    commits: BTreeSet<RepositoryCommitId>,
    capsules: BTreeSet<PreparedTxnCapsuleId>,
    seals: BTreeSet<TransactionSealId>,
}

impl IdentityLedger {
    /// Binds one transaction identity to its derivation inputs.
    ///
    /// Returns `Ok(())` for a first binding and for an exact rebinding, which
    /// is what an ordinary retry produces.
    pub fn bind_transaction(
        &mut self,
        tx_id: TxId,
        inputs: TxIdDerivationInputs,
    ) -> Result<(), InvariantBreach> {
        if let Some(bound) = self.tx_by_inputs.get(&inputs)
            && *bound != tx_id
        {
            return Err(InvariantBreach::TxIdDerivationInconsistent {
                bound: *bound,
                observed: tx_id,
            });
        }
        if let Some(bound_inputs) = self.inputs_by_tx.get(&tx_id)
            && *bound_inputs != inputs
        {
            return Err(InvariantBreach::TxIdDerivationInconsistent {
                bound: tx_id,
                observed: tx_id,
            });
        }
        self.tx_by_inputs.insert(inputs, tx_id);
        self.inputs_by_tx.insert(tx_id, inputs);
        Ok(())
    }

    /// The derivation inputs bound to one transaction identity.
    #[must_use]
    pub fn inputs_of(&self, tx_id: TxId) -> Option<&TxIdDerivationInputs> {
        self.inputs_by_tx.get(&tx_id)
    }

    /// Records a head identity, refusing reuse.
    pub fn introduce_head(
        &mut self,
        id: RepositoryAuthorityHeadId,
    ) -> Result<(), InvariantBreach> {
        introduce(&mut self.heads, id, "head")
    }

    /// Records a batch identity, refusing reuse.
    pub fn introduce_batch(
        &mut self,
        id: RepositoryDecisionBatchId,
    ) -> Result<(), InvariantBreach> {
        introduce(&mut self.batches, id, "batch")
    }

    /// Records a commit-record identity, refusing reuse.
    pub fn introduce_commit(&mut self, id: RepositoryCommitId) -> Result<(), InvariantBreach> {
        introduce(&mut self.commits, id, "commit")
    }

    /// Records a prepared-capsule identity, refusing reuse.
    pub fn introduce_capsule(&mut self, id: PreparedTxnCapsuleId) -> Result<(), InvariantBreach> {
        introduce(&mut self.capsules, id, "capsule")
    }

    /// Records a seal identity, refusing reuse.
    pub fn introduce_seal(&mut self, id: TransactionSealId) -> Result<(), InvariantBreach> {
        introduce(&mut self.seals, id, "seal")
    }
}

fn introduce<T: Ord>(
    set: &mut BTreeSet<T>,
    id: T,
    kind: &'static str,
) -> Result<(), InvariantBreach> {
    if set.insert(id) {
        Ok(())
    } else {
        Err(InvariantBreach::IdentityReused { kind })
    }
}

/// How a repository begins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisConfiguration {
    /// Owning tenant.
    pub tenant: TenantId,
    /// The repository.
    pub repository: RepositoryId,
    /// The one object format this repository declares (§3.1).
    pub object_format: GitHashAlgorithm,
    /// Identity of the genesis head body.
    pub genesis_head_id: RepositoryAuthorityHeadId,
    /// The initial policy and configuration snapshot.
    pub policy: PolicySnapshot,
    /// The initial format and algorithm registry epoch.
    pub format_registry_epoch: RegistryEpoch,
}

/// The complete deterministic state of one modelled repository.
///
/// Two states built from the same inputs in the same order are equal, and
/// equal states answer every query identically. Nothing here reads a clock, a
/// random source, the filesystem, or the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryState {
    pub(crate) tenant: TenantId,
    pub(crate) repository: RepositoryId,
    pub(crate) object_format: GitHashAlgorithm,
    pub(crate) head: AuthorityHead,
    pub(crate) head_chain: BTreeMap<RepositoryAuthorityHeadId, AuthorityHeadBody>,
    pub(crate) batches: BTreeMap<RepositoryDecisionBatchId, DecisionBatch>,
    pub(crate) staged: BTreeMap<RepositoryDecisionBatchId, StagedBatch>,
    pub(crate) decisions: Vec<PublishedDecision>,
    pub(crate) commits: Vec<RepositoryCommitRecord>,
    pub(crate) seals: BTreeMap<TxId, SealRecord>,
    pub(crate) capsules: BTreeMap<PreparedTxnCapsuleId, PreparedTxnCapsule>,
    pub(crate) quarantine: BTreeMap<TxId, BTreeMap<GitOid, QuarantinedObject>>,
    pub(crate) objects: BTreeMap<GitOid, ObjectRecord>,
    pub(crate) identities: IdentityLedger,
}

impl RepositoryState {
    /// Builds the genesis state: one head, no decisions, no objects.
    #[must_use]
    pub fn genesis(configuration: GenesisConfiguration) -> Self {
        let body = AuthorityHeadBody {
            repository: configuration.repository,
            generation: HeadGeneration::FIRST,
            predecessor: None,
            decision_tail: None,
            latest_decision_sequence: None,
            latest_committed_rcr: None,
            latest_repository_sequence: None,
            roots: RepositoryRoots::default(),
            configuration: configuration.policy,
            format_registry_epoch: configuration.format_registry_epoch,
        };
        let mut identities = IdentityLedger::default();
        // The genesis head is the first identity the ledger ever sees, so this
        // introduction cannot collide. The result is still consumed rather
        // than unwrapped: the model does not panic on its own construction.
        let genesis_introduced = identities.introduce_head(configuration.genesis_head_id);
        debug_assert!(genesis_introduced.is_ok(), "genesis head identity collided in a fresh ledger");
        let mut head_chain = BTreeMap::new();
        head_chain.insert(configuration.genesis_head_id, body.clone());
        Self {
            tenant: configuration.tenant,
            repository: configuration.repository,
            object_format: configuration.object_format,
            head: AuthorityHead {
                id: configuration.genesis_head_id,
                body,
            },
            head_chain,
            batches: BTreeMap::new(),
            staged: BTreeMap::new(),
            decisions: Vec::new(),
            commits: Vec::new(),
            seals: BTreeMap::new(),
            capsules: BTreeMap::new(),
            quarantine: BTreeMap::new(),
            objects: BTreeMap::new(),
            identities,
        }
    }

    /// Owning tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The repository this state models.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// The one object format this repository declares.
    #[must_use]
    pub const fn object_format(&self) -> GitHashAlgorithm {
        self.object_format
    }

    /// The current authority head.
    #[must_use]
    pub const fn head(&self) -> &AuthorityHead {
        &self.head
    }

    /// The canonical roots the current head publishes.
    #[must_use]
    pub const fn roots(&self) -> &RepositoryRoots {
        &self.head.body.roots
    }

    /// The pinned policy snapshot the current head names.
    #[must_use]
    pub const fn policy(&self) -> &PolicySnapshot {
        &self.head.body.configuration
    }

    /// Every terminal decision, in decision-sequence order.
    #[must_use]
    pub fn decisions(&self) -> &[PublishedDecision] {
        &self.decisions
    }

    /// Every committed record, in repository-sequence order.
    #[must_use]
    pub fn commits(&self) -> &[RepositoryCommitRecord] {
        &self.commits
    }

    /// The terminal outcome of one sealed transaction, if it has one.
    ///
    /// This reads the authenticated outcome index inside the head. §8.4's
    /// direct pointer is an accelerator over exactly this value and can never
    /// contradict it, because the model has no second place to look.
    #[must_use]
    pub fn outcome_of(&self, tx_id: TxId) -> Option<DecisionOutcome> {
        self.head.body.roots.outcome_index.get(&tx_id).copied()
    }

    /// True when this transaction already has a terminal decision.
    #[must_use]
    pub fn is_terminal(&self, tx_id: TxId) -> bool {
        self.outcome_of(tx_id).is_some()
    }

    /// The seal for one transaction, if it has been sealed.
    #[must_use]
    pub fn seal_of(&self, tx_id: TxId) -> Option<&SealRecord> {
        self.seals.get(&tx_id)
    }

    /// A prepared capsule the model holds.
    #[must_use]
    pub fn capsule(&self, id: PreparedTxnCapsuleId) -> Option<&PreparedTxnCapsule> {
        self.capsules.get(&id)
    }

    /// A staged, not yet visible, batch.
    #[must_use]
    pub fn staged(&self, id: RepositoryDecisionBatchId) -> Option<&StagedBatch> {
        self.staged.get(&id)
    }

    /// Every staged batch identity, in identity order.
    pub fn staged_batches(&self) -> impl Iterator<Item = &RepositoryDecisionBatchId> {
        self.staged.keys()
    }

    /// A published batch.
    #[must_use]
    pub fn batch(&self, id: RepositoryDecisionBatchId) -> Option<&DecisionBatch> {
        self.batches.get(&id)
    }

    /// The head body of any head this repository has ever had.
    #[must_use]
    pub fn head_body(&self, id: RepositoryAuthorityHeadId) -> Option<&AuthorityHeadBody> {
        self.head_chain.get(&id)
    }

    /// The transaction-scoped quarantine of one sealed transaction.
    #[must_use]
    pub fn quarantine_of(&self, tx_id: TxId) -> Option<&BTreeMap<GitOid, QuarantinedObject>> {
        self.quarantine.get(&tx_id)
    }

    /// An object canonical roots may reference.
    #[must_use]
    pub fn object(&self, oid: GitOid) -> Option<&ObjectRecord> {
        self.objects.get(&oid)
    }

    /// True when this object has been promoted out of quarantine.
    #[must_use]
    pub fn is_admitted(&self, oid: GitOid) -> bool {
        self.objects.contains_key(&oid)
    }

    /// The identity ledger.
    #[must_use]
    pub const fn identities(&self) -> &IdentityLedger {
        &self.identities
    }

    /// True when `candidate` is reachable from `tip` by following parents.
    ///
    /// This is the fast-forward predicate. It walks only objects the model has
    /// admitted, so an ancestry claim about an object that never passed
    /// validation is never believed. The walk is breadth-first over a
    /// `BTreeSet` frontier, so it is deterministic and terminates on cycles.
    #[must_use]
    pub fn is_reachable(&self, tip: GitOid, candidate: GitOid) -> bool {
        if tip == candidate {
            return true;
        }
        let mut visited = BTreeSet::new();
        let mut frontier = vec![tip];
        while let Some(current) = frontier.pop() {
            if !visited.insert(current) {
                continue;
            }
            let Some(record) = self.objects.get(&current) else {
                continue;
            };
            for parent in &record.parents {
                if *parent == candidate {
                    return true;
                }
                frontier.push(*parent);
            }
        }
        false
    }

    /// Checks that no object still in quarantine is protected by a canonical
    /// root.
    ///
    /// This is release-blocking invariant 10. It is a query rather than an
    /// assertion so a campaign can evaluate it after every step.
    pub fn assert_no_quarantine_escape(&self) -> Result<(), InvariantBreach> {
        for object in self.head.body.roots.protected_objects() {
            if !self.objects.contains_key(&object) {
                return Err(InvariantBreach::QuarantineEscape { object });
            }
        }
        Ok(())
    }

    /// Checks that the head chain is continuous back to genesis.
    ///
    /// Every head names its exact predecessor and its generation is that
    /// predecessor's successor, so following the chain must reach a head with
    /// no predecessor in exactly `generation` steps. This is ADR-0001
    /// invariant 3 and release-blocking invariant 4.
    pub fn assert_head_chain_continuous(&self) -> Result<(), InvariantBreach> {
        let mut cursor = &self.head.body;
        let mut steps = 0_u64;
        while let Some(predecessor) = cursor.predecessor {
            let Some(body) = self.head_chain.get(&predecessor) else {
                return Err(InvariantBreach::HeadPredecessorMismatch {
                    current: predecessor,
                    declared: Some(predecessor),
                });
            };
            let expected = body.generation.next().map_err(|_| {
                InvariantBreach::SequenceExhausted {
                    kind: "generation",
                }
            })?;
            if expected != cursor.generation {
                return Err(InvariantBreach::HeadGenerationNotSuccessor {
                    current: body.generation,
                    candidate: cursor.generation,
                });
            }
            cursor = body;
            steps += 1;
        }
        if cursor.generation.get() != HeadGeneration::FIRST.get() {
            return Err(InvariantBreach::HeadGenerationNotSuccessor {
                current: cursor.generation,
                candidate: HeadGeneration::FIRST,
            });
        }
        if steps + 1 != self.head.body.generation.get() {
            return Err(InvariantBreach::HeadGenerationNotSuccessor {
                current: cursor.generation,
                candidate: self.head.body.generation,
            });
        }
        Ok(())
    }

    /// Checks that decision sequence is gap-free across every terminal
    /// decision and that repository sequence is gap-free across commits only.
    ///
    /// The second half is the structural claim of this bead: a refusal
    /// consumes a decision sequence and leaves repository sequence alone.
    pub fn assert_sequences_gap_free(&self) -> Result<(), InvariantBreach> {
        let mut expected_decision = DecisionSequence::FIRST;
        for decision in &self.decisions {
            if decision.decision_sequence != expected_decision {
                return Err(InvariantBreach::DecisionSequenceDiscontinuity {
                    expected: expected_decision,
                    observed: decision.decision_sequence,
                });
            }
            expected_decision = expected_decision
                .next()
                .map_err(|_| InvariantBreach::SequenceExhausted { kind: "decision" })?;
        }
        let mut expected_repository = RepositorySequence::FIRST;
        for record in &self.commits {
            if record.repository_sequence != expected_repository {
                return Err(InvariantBreach::RepositorySequenceDiscontinuity {
                    expected: expected_repository,
                    observed: record.repository_sequence,
                });
            }
            expected_repository = expected_repository
                .next()
                .map_err(|_| InvariantBreach::SequenceExhausted { kind: "repository" })?;
        }
        Ok(())
    }

    /// The durability profile a batch staged from this head would carry by
    /// default.
    #[must_use]
    pub const fn default_durability(&self) -> DurabilityProfile {
        DurabilityProfile::CanonicalSource
    }
}
