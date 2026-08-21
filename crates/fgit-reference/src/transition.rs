//! The five transitions: seal, prepare, decide, stage, and head
//! compare-and-swap.
//!
//! Every function here has the shape `(&RepositoryState, input) -> (RepositoryState, output)`.
//! None of them mutates the state they are given, none reads a clock, a random
//! source, or an unordered map, and none of them is a method that could be
//! called on a shared mutable handle. That is the whole purity discipline: the
//! model is a value, and a transition is a function between values.
//!
//! The transitions follow §10's canonical algorithm. Steps that belong to
//! transport, storage, or lane scheduling are deliberately absent — this is the
//! semantic residue, not a service.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::hash::Digest;
use fgit_types::identity::{
    PreparationProfileId, PreparedTxnCapsuleId, PrincipalId, PrincipalSnapshotId, RefusalRecordId,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId, RepositoryId,
    TenantId, TransactionSealId, TxId,
};
use fgit_types::native::GitOid;
use fgit_types::numeric::{HeadGeneration, PolicyEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::{DecisionOutcome, RefusalCode, RequestRejectionCode};

use crate::capsule::{ConflictWitness, PreparedTxnCapsule, PreparedVerdict, WitnessGranularity};
use crate::decision::{CommitCandidate, DecisionBatch, DecisionBatchDraft};
use crate::effect::{
    FoldBasis, FoldOutcome, IntentMapping, NetEffectFolder, NetEffects, RefEffect, ReferenceFolder,
    RetentionEffect,
};
use crate::intent::{
    DurabilityProfile, ForgeEventKind, ForgeStreamId, ForgeStreamPosition, IdempotencyKey, Intent,
    OutboxDeliveryKey, RefIntent, RetentionClass, RetentionIntent, RetentionRoot,
    TransactionRequest,
};
use crate::refs::{is_canonical, scope_of};
use crate::state::{
    AuthorityHead, AuthorityHeadBody, InvariantBreach, ModelResult, ObjectRecord, PolicySnapshot,
    QuarantinedObject, RepositoryRoots, RepositoryState, SealRecord, StagedBatch,
};

/// The scope an idempotency key is unique within.
///
/// §3.3 binds tenant, repository, principal, and the key into the transaction
/// identity. The gateway additionally has to notice a key reused with a
/// *different* canonical request digest, which requires an index on exactly
/// this tuple — the transaction identity alone cannot reveal it, because a
/// different digest derives a different identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdempotencyScope {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Target repository.
    pub repository: RepositoryId,
    /// The authenticated principal.
    pub principal: PrincipalId,
    /// The client-chosen key.
    pub key: IdempotencyKey,
}

/// What sealing one request produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SealOutcome {
    /// A new seal was created; this is the first attempt at this logical
    /// mutation.
    Created(TransactionSealId),
    /// A seal with matching stable fields already existed; the retry continues
    /// under it. §5.2: the request is the *same* logical mutation, not a
    /// second one.
    ExistingRetry(TransactionSealId),
    /// The request was rejected before any seal existed.
    ///
    /// A rejection is not repository history and proves nothing about commit
    /// (§5.1). It carries no decision sequence and never appears in the
    /// decision stream.
    Rejected(RequestRejectionCode),
}

impl SealOutcome {
    /// The seal, when one exists.
    #[must_use]
    pub const fn seal_id(self) -> Option<TransactionSealId> {
        match self {
            Self::Created(id) | Self::ExistingRetry(id) => Some(id),
            Self::Rejected(_) => None,
        }
    }

    /// True when this outcome is a pre-seal rejection.
    #[must_use]
    pub const fn is_rejection(self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

/// One request presented for sealing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRequest {
    /// Identity the publisher assigned to the seal body.
    pub seal_id: TransactionSealId,
    /// The canonicalized semantic request.
    pub request: TransactionRequest,
}

/// Seals one request, or rejects it before any seal exists.
///
/// §5.2's three cases, in order: absent, present-and-matching, and
/// present-with-a-conflicting-stable-field. The idempotency-key index adds
/// §3.3's fourth: a key already bound to a different canonical request digest.
pub fn seal(
    state: &RepositoryState,
    input: &SealRequest,
) -> ModelResult<(RepositoryState, SealOutcome)> {
    let request = &input.request;
    if request.repository != state.repository {
        return Err(Box::new(InvariantBreach::RepositoryMismatch {
            expected: state.repository,
            observed: request.repository,
        }));
    }
    let fields = request.seal_fields();
    let scope = IdempotencyScope {
        tenant: request.tenant,
        repository: request.repository,
        principal: request.principal,
        key: request.idempotency_key,
    };

    // §3.3: reusing a key with a different canonical request digest is a
    // pre-decision rejection and must not alias the first request.
    if let Some(bound) = state.idempotency_index.get(&scope)
        && *bound != request.canonical_request_digest
    {
        return Ok((
            state.clone(),
            SealOutcome::Rejected(RequestRejectionCode::IdempotencyKeyReuse),
        ));
    }

    if !state
        .head
        .body
        .configuration
        .supported_schemas
        .contains(&request.schema)
    {
        return Ok((
            state.clone(),
            SealOutcome::Rejected(RequestRejectionCode::SchemaUnsupported),
        ));
    }

    if let Some(existing) = state.seals.get(&request.tx_id) {
        // §5.2: any conflicting stable field is a rejection, never an alias.
        if existing.fields == fields {
            return Ok((state.clone(), SealOutcome::ExistingRetry(existing.seal_id)));
        }
        return Ok((
            state.clone(),
            SealOutcome::Rejected(RequestRejectionCode::IdempotencyKeyReuse),
        ));
    }

    let mut next = state.clone();
    next.identities
        .bind_transaction(request.tx_id, fields.derivation_inputs())?;
    next.identities.introduce_seal(input.seal_id)?;
    next.seals.insert(
        request.tx_id,
        SealRecord {
            seal_id: input.seal_id,
            fields,
        },
    );
    next.idempotency_index
        .insert(scope, request.canonical_request_digest);
    Ok((next, SealOutcome::Created(input.seal_id)))
}

/// Objects a transaction stages into its own quarantine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineRequest {
    /// The sealed transaction the quarantine belongs to.
    pub tx_id: TxId,
    /// The staged objects.
    pub objects: Vec<QuarantinedObject>,
}

/// Stages objects into one sealed transaction's quarantine.
///
/// §16.2: incoming bytes are transaction-scoped and non-retained until bounded
/// validation completes. Nothing here promotes an object; promotion happens
/// only when the transaction's head compare-and-swap wins.
pub fn stage_objects(
    state: &RepositoryState,
    input: &QuarantineRequest,
) -> ModelResult<RepositoryState> {
    if !state.seals.contains_key(&input.tx_id) {
        return Err(Box::new(InvariantBreach::UnknownSeal {
            tx_id: input.tx_id,
        }));
    }
    let mut next = state.clone();
    let slot = next.quarantine.entry(input.tx_id).or_default();
    for object in &input.objects {
        slot.insert(object.declared, object.clone());
    }
    Ok(next)
}

/// Everything preparation needs beyond the request itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareRequest {
    /// Identity the publisher assigned to the capsule body.
    pub capsule_id: PreparedTxnCapsuleId,
    /// The canonicalized semantic request, which must be the sealed one.
    pub request: TransactionRequest,
    /// The immutable principal and capability snapshot to evaluate against.
    pub principal_snapshot: PrincipalSnapshotId,
    /// Which preparation implementation is running.
    pub profile: PreparationProfileId,
    /// How precisely to record what was read.
    pub granularity: WitnessGranularity,
}

/// Validates one sealed transaction against the current head.
///
/// This is §10 steps 7 through 11 and plan §15.3. It produces a capsule whose
/// verdict is either a commit with target-disjoint effects or a terminal
/// refusal — and, either way, the witness that decides whether the capsule
/// survives a lost compare-and-exchange.
pub fn prepare(
    state: &RepositoryState,
    input: &PrepareRequest,
) -> ModelResult<(RepositoryState, PreparedTxnCapsuleId)> {
    let request = &input.request;
    let Some(seal) = state.seals.get(&request.tx_id) else {
        return Err(Box::new(InvariantBreach::UnknownSeal {
            tx_id: request.tx_id,
        }));
    };
    if seal.fields != request.seal_fields() {
        // A prepared request must be the sealed request. Anything else would
        // let preparation quietly change the sealed semantics.
        return Err(Box::new(InvariantBreach::TxIdInputsInconsistent {
            tx_id: request.tx_id,
        }));
    }

    let verdict = evaluate(state, request);
    let witness = build_witness(state, request, input.granularity);
    let capsule = PreparedTxnCapsule {
        id: input.capsule_id,
        tx_id: request.tx_id,
        seal_id: seal.seal_id,
        basis_head: state.head.id,
        basis_generation: state.head.body.generation,
        basis_rcr: state.head.body.latest_committed_rcr,
        principal_snapshot: input.principal_snapshot,
        canonical_request_digest: request.canonical_request_digest,
        intent_map: verdict.intent_map,
        object_closure: verdict.object_closure,
        witness,
        verdict: verdict.verdict,
        durability: request.durability,
        profile: input.profile,
    };

    let mut next = state.clone();
    next.identities.introduce_capsule(input.capsule_id)?;
    next.capsules.insert(input.capsule_id, capsule);
    Ok((next, input.capsule_id))
}

/// What one preparation concluded, before the capsule wraps it.
struct Evaluation {
    verdict: PreparedVerdict,
    intent_map: Vec<IntentMapping>,
    object_closure: BTreeSet<GitOid>,
}

impl Evaluation {
    /// A refusal reached before the fold ran, so there is no intent map yet.
    ///
    /// An empty map is honest here: plan §15.4's totality requirement is about
    /// intents that were *evaluated*, and an admission refusal happens before
    /// evaluation begins.
    const fn refused_before_fold(code: RefusalCode) -> Self {
        Self {
            verdict: PreparedVerdict::Refuse(code),
            intent_map: Vec::new(),
            object_closure: BTreeSet::new(),
        }
    }
}

fn evaluate(state: &RepositoryState, request: &TransactionRequest) -> Evaluation {
    let refuse = Evaluation::refused_before_fold;

    let policy = &state.head.body.configuration;
    if !policy.supported_schemas.contains(&request.schema) {
        return refuse(RefusalCode::SchemaUnsupported);
    }
    if request.intent_count() > policy.max_intents_per_transaction {
        return refuse(RefusalCode::ResourceBudgetExceeded);
    }
    // §9: the profile a request demands must be one this repository can
    // actually offer. This is "cannot be met", which is terminal — distinct
    // from "not met yet", which leaves the batch staged and retryable and is
    // reported by `CasOutcome::DurabilityUnsatisfied`.
    if !policy.offers_durability(request.durability) {
        return refuse(RefusalCode::DurabilityProfileUnavailable);
    }

    // Every ref an intent or a forge event names must be inside the canonical
    // namespace this slice admits.
    for (_, intent) in request.addressed_intents() {
        if let Some(name) = named_ref(intent)
            && !is_canonical(name)
        {
            return refuse(RefusalCode::RefNameInvalid);
        }
    }

    // §3.1: a repository has one declared object format, and equal digest
    // bytes under different algorithms are not equal identities.
    for oid in request
        .promised_closure
        .iter()
        .copied()
        .chain(intent_objects(request))
    {
        if oid.algorithm() != state.object_format {
            return refuse(RefusalCode::HashAlgorithmDomainMismatch);
        }
    }

    // §16.2: promotion is by verified identity. An object whose recomputed
    // identity disagrees with the declared one never becomes admissible.
    let quarantine = state.quarantine.get(&request.tx_id);
    if let Some(staged) = quarantine {
        for object in staged.values() {
            if !object.is_identity_verified() {
                return refuse(RefusalCode::NativeObjectIdMismatch);
            }
        }
    }

    // Every promised object, and every object a ref update names, must be
    // either already admitted or verified in this transaction's quarantine.
    let available = available_objects(state, request.tx_id);
    for oid in request
        .promised_closure
        .iter()
        .copied()
        .chain(intent_objects(request))
    {
        if !available.contains_key(&oid) {
            return refuse(RefusalCode::ObjectClosureIncomplete);
        }
    }

    let roots = &state.head.body.roots;
    let basis = FoldBasis {
        refs: &roots.refs,
        forge_positions: &roots.forge_positions,
        retention: &roots.retention,
        outbox: &roots.outbox,
    };
    let report = ReferenceFolder.fold(basis, request);
    let effects = match &report.outcome {
        FoldOutcome::Aborted { code, .. } => {
            return Evaluation {
                verdict: PreparedVerdict::Refuse(*code),
                intent_map: report.mappings,
                object_closure: BTreeSet::new(),
            };
        }
        FoldOutcome::Folded(effects) => effects.clone(),
    };

    if let Some(code) = evaluate_policy(state, request, &effects, &available) {
        return Evaluation {
            verdict: PreparedVerdict::Refuse(code),
            intent_map: report.mappings,
            object_closure: BTreeSet::new(),
        };
    }

    // The committed closure is everything the request promised plus every
    // object its surviving effects name. Both must be protected the moment the
    // batch becomes canonical, or a canonical root would point at an object
    // still sitting in quarantine.
    let mut object_closure = request.promised_closure.clone();
    object_closure.extend(intent_objects(request));

    Evaluation {
        verdict: PreparedVerdict::Commit(effects),
        intent_map: report.mappings,
        object_closure,
    }
}

/// Deterministic policy over the **net effects**, not over the raw intents.
///
/// Plan §15.4 makes the normal form the thing that publishes, so it is also the
/// thing policy judges. One consequence is deliberate and worth stating: a
/// transaction that moves a protected ref and moves it back has no surviving
/// effect on that ref and therefore does not trip protection, because nothing
/// is published. FG-006 may refine this to judge intents as well; the reference
/// answer is that policy governs what becomes canonical.
fn evaluate_policy(
    state: &RepositoryState,
    request: &TransactionRequest,
    effects: &NetEffects,
    available: &BTreeMap<GitOid, Vec<GitOid>>,
) -> Option<RefusalCode> {
    let policy = &state.head.body.configuration;
    let capabilities = policy.capabilities_of(request.principal);
    let forced = forced_refs(request);
    let roots = &state.head.body.roots;

    for (name, effect) in &effects.refs {
        let Some(scope) = scope_of(name) else {
            return Some(RefusalCode::RefNameInvalid);
        };
        if !capabilities.may_write_scope(scope) {
            return Some(RefusalCode::CapabilityScopeViolation);
        }
        // A protected scope forbids deletion outright and forbids any update
        // that is not a fast-forward. A fast-forward, and the creation of a
        // ref that did not exist, leave the loop before the protection check,
        // which is what keeps protection from blocking ordinary progress.
        match effect {
            RefEffect::Delete => {}
            RefEffect::Set(new) => {
                let Some(old) = roots.refs.get(name).copied() else {
                    // Creating a ref is always a fast-forward from nothing.
                    continue;
                };
                if reachable_in(available, *new, old) {
                    continue;
                }
                if !forced.contains(name) {
                    return Some(RefusalCode::NonFastForwardRefused);
                }
                if !capabilities.may_force {
                    return Some(RefusalCode::ForceNotPermitted);
                }
            }
        }
        if policy.is_protected(scope) {
            return Some(RefusalCode::ProtectedRefTransitionDenied);
        }
    }

    if !effects.forge.is_empty() && !capabilities.may_publish_forge {
        return Some(RefusalCode::CapabilityScopeViolation);
    }

    // §7: a record classified as a pull-request merge cannot move the ref
    // without the corresponding forge event batch, and cannot carry the event
    // without moving the ref. The second direction is what this checks; the
    // first is structural, because both live in one `NetEffects`.
    for events in effects.forge.values() {
        for event in events {
            let Some(required) = event.required_ref_effect() else {
                continue;
            };
            match effects.refs.get(required) {
                // The merge moved the ref: one record, both effects (§7).
                Some(RefEffect::Set(_)) => {}
                // The record says "merged into this ref" and "this ref is
                // gone" at once. Plan §15.4 refuses contradictory values
                // rather than normalizing them into an invented policy.
                Some(RefEffect::Delete) => {
                    return Some(RefusalCode::ConflictingSemanticEffects);
                }
                // A merge event with no ref effect at all: §7's rule that a
                // record classified as a pull-request merge cannot carry the
                // event without moving the ref.
                None => return Some(RefusalCode::ForgeTransitionInvalid),
            }
        }
    }

    for (root, effect) in &effects.retention {
        match effect {
            RetentionEffect::Add => {
                if root.class == RetentionClass::LegalHold && !capabilities.may_add_legal_hold {
                    return Some(RefusalCode::CapabilityScopeViolation);
                }
            }
            RetentionEffect::Remove => {
                // §25: an ordinary sealed transaction may not remove a legal
                // hold. Retiring a grace tombstone is permitted, which is the
                // near-identical case that proceeds.
                if !root.class.is_ordinarily_removable() {
                    return Some(RefusalCode::RetentionHoldViolation);
                }
            }
        }
    }

    None
}

/// The refs for which some intent requested a forced update.
fn forced_refs(request: &TransactionRequest) -> BTreeSet<RefName> {
    request
        .addressed_intents()
        .filter_map(|(_, intent)| match intent {
            Intent::Ref(RefIntent::Update {
                name, force: true, ..
            }) => Some(name.clone()),
            Intent::Ref(_) | Intent::Forge(_) | Intent::Retention(_) | Intent::Outbox(_) => None,
        })
        .collect()
}

/// The ref an intent names, when it names one.
const fn named_ref(intent: &Intent) -> Option<&RefName> {
    match intent {
        Intent::Ref(ref_intent) => Some(ref_intent.target()),
        Intent::Forge(forge) => match &forge.event {
            ForgeEventKind::PullRequestOpened { target, .. }
            | ForgeEventKind::PullRequestMerged { target, .. } => Some(target),
            ForgeEventKind::PullRequestClosed { .. } => None,
        },
        Intent::Retention(_) | Intent::Outbox(_) => None,
    }
}

/// Every native object identity an intent names.
fn intent_objects(request: &TransactionRequest) -> impl Iterator<Item = GitOid> {
    request
        .addressed_intents()
        .filter_map(|(_, intent)| match intent {
            Intent::Ref(RefIntent::Update { new, .. }) => Some(*new),
            Intent::Retention(RetentionIntent::AddRoot(root)) => Some(root.object),
            Intent::Ref(RefIntent::Delete { .. })
            | Intent::Retention(RetentionIntent::RemoveRoot(_))
            | Intent::Forge(_)
            | Intent::Outbox(_) => None,
        })
}

/// The objects preparation may reason about: everything already admitted, plus
/// everything verified in this transaction's own quarantine.
fn available_objects(state: &RepositoryState, tx_id: TxId) -> BTreeMap<GitOid, Vec<GitOid>> {
    let mut view: BTreeMap<GitOid, Vec<GitOid>> = state
        .objects
        .iter()
        .map(|(oid, record)| (*oid, record.parents.clone()))
        .collect();
    if let Some(staged) = state.quarantine.get(&tx_id) {
        for object in staged.values() {
            if object.is_identity_verified() {
                view.insert(object.declared, object.parents.clone());
            }
        }
    }
    view
}

/// Breadth-first ancestry over a parent view.
///
/// The frontier is a `Vec` used as a stack and every node is visited once, so
/// the walk terminates even on a cyclic parent claim and never depends on hash
/// ordering.
fn reachable_in(view: &BTreeMap<GitOid, Vec<GitOid>>, tip: GitOid, candidate: GitOid) -> bool {
    if tip == candidate {
        return true;
    }
    let mut visited = BTreeSet::new();
    let mut frontier = vec![tip];
    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        let Some(parents) = view.get(&current) else {
            continue;
        };
        for parent in parents {
            if *parent == candidate {
                return true;
            }
            frontier.push(*parent);
        }
    }
    false
}

/// Records every value the preparation read.
fn build_witness(
    state: &RepositoryState,
    request: &TransactionRequest,
    granularity: WitnessGranularity,
) -> ConflictWitness {
    let roots = &state.head.body.roots;
    let mut refs: BTreeMap<RefName, Option<GitOid>> = BTreeMap::new();
    let mut forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition> = BTreeMap::new();
    let mut retention_present: BTreeSet<RetentionRoot> = BTreeSet::new();
    let mut retention_absent: BTreeSet<RetentionRoot> = BTreeSet::new();
    let mut outbox: BTreeMap<OutboxDeliveryKey, Option<Digest>> = BTreeMap::new();

    for (_, intent) in request.addressed_intents() {
        match intent {
            Intent::Ref(ref_intent) => {
                let name = ref_intent.target().clone();
                let observed = roots.refs.get(&name).copied();
                refs.insert(name, observed);
            }
            Intent::Forge(forge) => {
                let observed = roots
                    .forge_positions
                    .get(&forge.stream)
                    .copied()
                    .unwrap_or(ForgeStreamPosition::GENESIS);
                forge_positions.insert(forge.stream, observed);
                if let Some(target) = forge.event.required_ref_effect() {
                    let observed_ref = roots.refs.get(target).copied();
                    refs.insert(target.clone(), observed_ref);
                }
            }
            Intent::Retention(
                RetentionIntent::AddRoot(root) | RetentionIntent::RemoveRoot(root),
            ) => {
                if roots.retention.contains(root) {
                    retention_present.insert(*root);
                } else {
                    retention_absent.insert(*root);
                }
            }
            Intent::Outbox(delivery) => {
                let observed = roots.outbox.get(&delivery.delivery_key).copied();
                outbox.insert(delivery.delivery_key, observed);
            }
        }
    }

    ConflictWitness {
        granularity,
        basis_generation: state.head.body.generation,
        refs,
        forge_positions,
        retention_present,
        retention_absent,
        outbox,
        policy_epoch: state.head.body.configuration.epoch,
    }
}

/// What deciding one prepared capsule against the current head concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionVerdict {
    /// The transaction is already terminal; §10 step 18 returns the existing
    /// outcome rather than deciding again.
    AlreadyTerminal(DecisionOutcome),
    /// The capsule is still usable and would commit these effects.
    Commit(NetEffects),
    /// The capsule would be refused with this terminal code.
    Refuse(RefusalCode),
}

/// Revalidates a capsule against a set of roots and concludes.
///
/// This is a pure query: no state changes, because a decision only becomes
/// canonical when a batch containing it wins the head compare-and-swap.
#[must_use]
pub fn decide_against(
    state: &RepositoryState,
    capsule: &PreparedTxnCapsule,
    roots: &RepositoryRoots,
    generation: HeadGeneration,
) -> DecisionVerdict {
    if let Some(existing) = state.outcome_of(capsule.tx_id) {
        return DecisionVerdict::AlreadyTerminal(existing);
    }
    match &capsule.verdict {
        PreparedVerdict::Refuse(code) => DecisionVerdict::Refuse(*code),
        PreparedVerdict::Commit(effects) => {
            let policy_epoch = state.head.body.configuration.epoch;
            // §15.9 pins one policy epoch per attempt. A superseded epoch is
            // reported as its own dimension rather than folded into a stale
            // basis, because the remedy differs: re-prepare under the new
            // policy, not merely rebase onto the new roots.
            if capsule.witness.policy_epoch != policy_epoch {
                return DecisionVerdict::Refuse(RefusalCode::PolicyEpochSuperseded);
            }
            if capsule
                .witness
                .is_reusable_against(roots, generation, policy_epoch)
            {
                DecisionVerdict::Commit(effects.clone())
            } else {
                DecisionVerdict::Refuse(RefusalCode::BasisCapsuleNotReusable)
            }
        }
    }
}

/// Decides one capsule against the current head.
#[must_use]
pub fn decide(state: &RepositoryState, capsule: &PreparedTxnCapsule) -> DecisionVerdict {
    decide_against(
        state,
        capsule,
        &state.head.body.roots,
        state.head.body.generation,
    )
}

/// Identities the publisher assigned to the bodies one decision may create.
///
/// Exactly one is consumed: a commit uses `commit`, a refusal uses
/// `refusal_record`. The unused identity is never introduced into the ledger,
/// so it stays free for another attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecisionBodyIdentity {
    /// Identity for the Repository Commit Record, if this decision commits.
    pub commit: RepositoryCommitId,
    /// Identity for the immutable refusal record, if this decision refuses.
    pub refusal_record: RefusalRecordId,
}

/// Everything staging one batch needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageRequest {
    /// Identity the publisher assigned to the batch body.
    pub batch_id: RepositoryDecisionBatchId,
    /// Identity the publisher assigned to the candidate head body.
    pub candidate_head_id: RepositoryAuthorityHeadId,
    /// The prepared capsules to include.
    pub capsules: Vec<PreparedTxnCapsuleId>,
    /// Body identities, by transaction.
    pub bodies: BTreeMap<TxId, DecisionBodyIdentity>,
    /// Whether the declared placement predicate has been satisfied.
    pub durability_satisfied: bool,
}

/// Stages one decision batch and its candidate head.
///
/// §10 steps 13 through 15. Nothing here is canonical: the batch and the
/// candidate head are staged bodies that no authority root references, which is
/// §9's *staged* epoch.
///
/// ## Declared admission order
///
/// §16.3 requires the combiner's selection and tie-break policy to be
/// versioned and replayable, and forbids map iteration order from being
/// publication semantics. The declared policy here is: **capsules are admitted
/// in ascending `TxId` order**, regardless of the order the caller listed them.
/// The model therefore produces the same batch for any permutation of the same
/// capsule set, which is a property a test can check.
pub fn stage(
    state: &RepositoryState,
    input: &StageRequest,
) -> ModelResult<(RepositoryState, RepositoryDecisionBatchId)> {
    let mut selected = Vec::with_capacity(input.capsules.len());
    for id in &input.capsules {
        let Some(capsule) = state.capsules.get(id) else {
            return Err(Box::new(InvariantBreach::UnknownCapsule { capsule: *id }));
        };
        selected.push(capsule);
    }
    selected.sort_by_key(|capsule| capsule.tx_id);

    let head = &state.head;
    let mut draft = DecisionBatchDraft::open(
        input.batch_id,
        state.repository,
        head.id,
        head.body.generation,
        head.body.next_decision_sequence()?,
        head.body.next_repository_sequence()?,
        head.body.latest_committed_rcr,
        strictest_durability(&selected),
    );
    let mut scratch = head.body.roots.clone();
    let mut committed_transactions = Vec::new();

    for capsule in selected {
        if let Some(existing) = state.outcome_of(capsule.tx_id) {
            // §15.8: a different second terminal outcome is an invariant
            // failure, not a refusal to be written into history.
            return Err(Box::new(InvariantBreach::SecondTerminalDecision {
                tx_id: capsule.tx_id,
                existing,
            }));
        }
        let Some(bodies) = input.bodies.get(&capsule.tx_id) else {
            return Err(Box::new(InvariantBreach::UnknownSeal {
                tx_id: capsule.tx_id,
            }));
        };

        // §8.1: each decision is evaluated with read-your-own-prior-decisions
        // within the batch, so revalidation runs against `scratch`, not
        // against the head roots.
        match decide_against(state, capsule, &scratch, head.body.generation) {
            DecisionVerdict::AlreadyTerminal(existing) => {
                return Err(Box::new(InvariantBreach::SecondTerminalDecision {
                    tx_id: capsule.tx_id,
                    existing,
                }));
            }
            DecisionVerdict::Refuse(code) => {
                let outcome = DecisionOutcome::Refused {
                    code,
                    refusal_record_id: bodies.refusal_record,
                };
                draft.push_refusal(capsule.tx_id, outcome)?;
                scratch.outcome_index.insert(capsule.tx_id, outcome);
            }
            DecisionVerdict::Commit(effects) => {
                apply_effects(&mut scratch, &effects);
                let candidate = CommitCandidate {
                    id: bodies.commit,
                    repository: state.repository,
                    tx_id: capsule.tx_id,
                    principal_snapshot: capsule.principal_snapshot,
                    canonical_request_digest: capsule.canonical_request_digest,
                    resulting_refs: scratch.refs.clone(),
                    resulting_forge_positions: scratch.forge_positions.clone(),
                    object_closure: capsule.object_closure.clone(),
                    policy_epoch: capsule.witness.policy_epoch,
                    retention_delta: effects.retention.clone(),
                    outbox_delta: effects.outbox.clone(),
                    effects,
                };
                draft.push_commit(candidate)?;
                scratch.outcome_index.insert(
                    capsule.tx_id,
                    DecisionOutcome::Committed {
                        repository_commit_id: bodies.commit,
                    },
                );
                committed_transactions.push(capsule.tx_id);
            }
        }
    }

    let policy_epoch = head.body.configuration.epoch;
    let batch = draft.finish(scratch, policy_epoch)?;
    let candidate_head = build_candidate_head(head, &batch, input.candidate_head_id)?;

    let mut next = state.clone();
    next.identities.introduce_batch(input.batch_id)?;
    next.identities.introduce_head(input.candidate_head_id)?;
    for tx_id in committed_transactions {
        if let Some(bodies) = input.bodies.get(&tx_id) {
            next.identities.introduce_commit(bodies.commit)?;
        }
    }
    next.staged.insert(
        input.batch_id,
        StagedBatch {
            batch,
            candidate_head,
            durability_satisfied: input.durability_satisfied,
        },
    );
    Ok((next, input.batch_id))
}

/// The strictest durability profile among the capsules sharing a batch.
///
/// A batch publishes under one profile, so mixing a canonical-source
/// transaction with a derived-generation one publishes under the stronger
/// predicate. Weakening to the more permissive profile would let a canonical
/// transaction become visible before its placement predicate held.
fn strictest_durability(capsules: &[&PreparedTxnCapsule]) -> DurabilityProfile {
    if capsules
        .iter()
        .any(|capsule| capsule.durability.requires_durability_before_visibility())
    {
        DurabilityProfile::CanonicalSource
    } else {
        DurabilityProfile::DerivedGeneration
    }
}

fn build_candidate_head(
    head: &AuthorityHead,
    batch: &DecisionBatch,
    id: RepositoryAuthorityHeadId,
) -> ModelResult<AuthorityHead> {
    let (latest_committed_rcr, latest_repository_sequence) = batch.last_commit().map_or(
        (
            head.body.latest_committed_rcr,
            head.body.latest_repository_sequence,
        ),
        |(commit, sequence)| (Some(commit), Some(sequence)),
    );
    Ok(AuthorityHead {
        id,
        body: AuthorityHeadBody {
            repository: head.body.repository,
            generation: head.body.next_generation()?,
            predecessor: Some(head.id),
            decision_tail: Some(batch.id()),
            latest_decision_sequence: batch
                .last_decision_sequence()
                .or(head.body.latest_decision_sequence),
            latest_committed_rcr,
            latest_repository_sequence,
            roots: batch.resulting().clone(),
            configuration: head.body.configuration.clone(),
            format_registry_epoch: head.body.format_registry_epoch,
        },
    })
}

/// Applies target-disjoint effects to scratch roots.
fn apply_effects(roots: &mut RepositoryRoots, effects: &NetEffects) {
    for (name, effect) in &effects.refs {
        match effect {
            RefEffect::Set(oid) => {
                roots.refs.insert(name.clone(), *oid);
            }
            RefEffect::Delete => {
                roots.refs.remove(name);
            }
        }
    }
    for (stream, events) in &effects.forge {
        let position = roots
            .forge_positions
            .entry(*stream)
            .or_insert(ForgeStreamPosition::GENESIS);
        for _ in events {
            *position = position.successor();
        }
    }
    for (root, effect) in &effects.retention {
        match effect {
            RetentionEffect::Add => {
                roots.retention.insert(*root);
            }
            RetentionEffect::Remove => {
                roots.retention.remove(root);
            }
        }
    }
    for (key, parameters) in &effects.outbox {
        roots.outbox.insert(*key, *parameters);
    }
}

/// One configuration head transition.
///
/// §15.9 pins one policy and configuration snapshot per attempt, and §8.2 puts
/// the policy epoch inside the head body, so changing policy is a head
/// transition like any other: exact predecessor, monotone generation.
///
/// It publishes no decision. A configuration transition consumes a head
/// generation and leaves both sequences alone, which is why the decision tail
/// and every root carry forward unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationRequest {
    /// Identity the publisher assigned to the candidate head body.
    pub candidate_head_id: RepositoryAuthorityHeadId,
    /// The head the attempt believes is current.
    pub expected_head: RepositoryAuthorityHeadId,
    /// That head's generation.
    pub expected_generation: HeadGeneration,
    /// The snapshot to pin.
    pub policy: PolicySnapshot,
}

/// Publishes a new pinned policy snapshot through the same head authority.
///
/// The new epoch must be the immediate successor of the current one. §22
/// requires generation activation to be exact-predecessor and anti-rollback,
/// and a policy epoch that could move backwards, or skip forward, would let a
/// superseded policy be reinstated without an audited restore.
pub fn publish_configuration(
    state: &RepositoryState,
    input: &ConfigurationRequest,
) -> ModelResult<(RepositoryState, ConfigurationOutcome)> {
    if input.expected_head != state.head.id
        || input.expected_generation != state.head.body.generation
    {
        return Ok((
            state.clone(),
            ConfigurationOutcome::Lost {
                current_head: state.head.id,
                current_generation: state.head.body.generation,
            },
        ));
    }
    let required = state
        .head
        .body
        .configuration
        .epoch
        .next()
        .map_err(|_| Box::new(InvariantBreach::SequenceExhausted { kind: "policy" }))?;
    if input.policy.epoch != required {
        return Err(Box::new(InvariantBreach::PolicyEpochNotSuccessor {
            current: state.head.body.configuration.epoch,
            candidate: input.policy.epoch,
        }));
    }

    let generation = state.head.body.next_generation()?;
    let candidate = AuthorityHead {
        id: input.candidate_head_id,
        body: AuthorityHeadBody {
            repository: state.head.body.repository,
            generation,
            predecessor: Some(state.head.id),
            decision_tail: state.head.body.decision_tail,
            latest_decision_sequence: state.head.body.latest_decision_sequence,
            latest_committed_rcr: state.head.body.latest_committed_rcr,
            latest_repository_sequence: state.head.body.latest_repository_sequence,
            roots: state.head.body.roots.clone(),
            configuration: input.policy.clone(),
            format_registry_epoch: state.head.body.format_registry_epoch,
        },
    };

    let mut next = state.clone();
    next.identities.introduce_head(input.candidate_head_id)?;
    next.head_chain
        .insert(input.candidate_head_id, candidate.body.clone());
    next.head = candidate;
    Ok((
        next,
        ConfigurationOutcome::Won {
            head: input.candidate_head_id,
            epoch: input.policy.epoch,
        },
    ))
}

/// What a configuration head transition produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfigurationOutcome {
    /// The conditional replacement succeeded and the new epoch is pinned.
    Won {
        /// The head that is now current.
        head: RepositoryAuthorityHeadId,
        /// The policy epoch now in force.
        epoch: PolicyEpoch,
    },
    /// The conditional replacement failed because the head had moved.
    Lost {
        /// The head that is actually current.
        current_head: RepositoryAuthorityHeadId,
        /// That head's generation.
        current_generation: HeadGeneration,
    },
}

/// What a head compare-and-swap attempt produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CasOutcome {
    /// The conditional replacement succeeded. Every decision in the referenced
    /// batch became canonical at this instant (§8.3).
    Won {
        /// The head that is now current.
        head: RepositoryAuthorityHeadId,
        /// The batch that became canonical.
        batch: RepositoryDecisionBatchId,
    },
    /// The conditional replacement failed because the head had moved.
    ///
    /// Nothing candidate became visible. The same sealed request may reuse,
    /// refine, rebase, or re-prepare (§10 steps 18 and 19).
    Lost {
        /// The head that is actually current.
        current_head: RepositoryAuthorityHeadId,
        /// That head's generation.
        current_generation: HeadGeneration,
    },
    /// The batch may not become visible yet under its declared durability
    /// profile.
    ///
    /// This is **not** a terminal decision. §9's canonical source profile is
    /// `Absent -> Staged -> DurabilitySatisfied -> Visible`, so an unsatisfied
    /// placement predicate means the publication is not ready, not that the
    /// transactions were refused. The batch stays staged and the attempt may
    /// be repeated once durability is satisfied.
    DurabilityUnsatisfied {
        /// The batch that stayed staged.
        batch: RepositoryDecisionBatchId,
    },
}

/// One conditional head replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CasRequest {
    /// The head the attempt believes is current.
    pub expected_head: RepositoryAuthorityHeadId,
    /// That head's generation, checked as well so a recycled identity cannot
    /// pass as the same state (§4's ABA requirement).
    pub expected_generation: HeadGeneration,
    /// The staged batch to publish.
    pub batch: RepositoryDecisionBatchId,
}

/// Attempts the one linearizable conditional replacement of the repository
/// head.
///
/// §8.3: this is the linearization point. Winning makes every terminal
/// decision in the referenced batch, every committed record in order, and
/// every resulting root canonical simultaneously. Losing exposes nothing.
pub fn compare_and_swap(
    state: &RepositoryState,
    input: CasRequest,
) -> ModelResult<(RepositoryState, CasOutcome)> {
    let Some(staged) = state.staged.get(&input.batch) else {
        return Err(Box::new(InvariantBreach::UnstagedBatch {
            batch: input.batch,
        }));
    };

    // A lost compare-and-exchange is ordinary, not an invariant breach: two
    // combiners racing is the designed behaviour (§11).
    if input.expected_head != state.head.id
        || input.expected_generation != state.head.body.generation
    {
        return Ok((
            state.clone(),
            CasOutcome::Lost {
                current_head: state.head.id,
                current_generation: state.head.body.generation,
            },
        ));
    }

    if staged.candidate_head.body.predecessor != Some(state.head.id) {
        return Err(Box::new(InvariantBreach::HeadPredecessorMismatch {
            current: state.head.id,
            declared: staged.candidate_head.body.predecessor,
        }));
    }
    let expected_generation = state.head.body.next_generation()?;
    if staged.candidate_head.body.generation != expected_generation {
        return Err(Box::new(InvariantBreach::HeadGenerationNotSuccessor {
            current: state.head.body.generation,
            candidate: staged.candidate_head.body.generation,
        }));
    }
    let expected_decision = state.head.body.next_decision_sequence()?;
    if staged.batch.first_decision_sequence() != expected_decision {
        return Err(Box::new(InvariantBreach::DecisionSequenceDiscontinuity {
            expected: expected_decision,
            observed: staged.batch.first_decision_sequence(),
        }));
    }
    if let Some(first) = staged.batch.committed().first() {
        let expected_repository = state.head.body.next_repository_sequence()?;
        if first.repository_sequence != expected_repository {
            return Err(Box::new(InvariantBreach::RepositorySequenceDiscontinuity {
                expected: expected_repository,
                observed: first.repository_sequence,
            }));
        }
    }
    if !staged.may_become_visible() {
        return Ok((
            state.clone(),
            CasOutcome::DurabilityUnsatisfied { batch: input.batch },
        ));
    }

    let staged = staged.clone();
    let new_head_id = staged.candidate_head.id;
    let mut next = state.clone();
    next.staged.remove(&input.batch);
    next.head_chain
        .insert(new_head_id, staged.candidate_head.body.clone());
    next.head = staged.candidate_head;
    next.decisions
        .extend(staged.batch.decisions().iter().copied());
    next.commits
        .extend(staged.batch.committed().iter().cloned());

    // §16.2: promotion out of quarantine follows the committed closure. A
    // refused transaction's staged bytes are dropped, never retained.
    for record in staged.batch.committed() {
        promote_closure(&mut next, record.tx_id, &record.object_closure);
    }
    for tx_id in staged.batch.terminated_transactions() {
        next.quarantine.remove(&tx_id);
        next.capsules.retain(|_, capsule| capsule.tx_id != tx_id);
    }

    let batch_id = staged.batch.id();
    next.batches.insert(batch_id, staged.batch);
    Ok((
        next,
        CasOutcome::Won {
            head: new_head_id,
            batch: batch_id,
        },
    ))
}

fn promote_closure(state: &mut RepositoryState, tx_id: TxId, closure: &BTreeSet<GitOid>) {
    let Some(staged) = state.quarantine.get(&tx_id).cloned() else {
        return;
    };
    for oid in closure {
        if let Some(object) = staged.get(oid)
            && object.is_identity_verified()
        {
            state.objects.insert(
                *oid,
                ObjectRecord {
                    parents: object.parents.clone(),
                },
            );
        }
    }
}
