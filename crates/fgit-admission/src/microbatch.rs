//! Bounded, wire-ordered publication of independent receive transactions.
//!
//! A session keeps one seal and terminal decision per command. Only the
//! physical publication is combined: every chunk is evaluated from one real
//! authenticated head, with earlier accepted ref effects visible to later
//! commands, and published by one chronicle plan and exact-predecessor CAS.
//! The working ref state is private derived preparation, never an authority
//! head and never visible to readers before that CAS succeeds.

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityStore, AuthorityVersionToken,
    CumulativeOutcomes, HeadRead, HeadReadReceipt, OutcomeLookup, PutOutcome, TerminalOutcome,
    indexed_outcome, indexed_outcome_async, read_authority_head_body,
    read_authority_head_body_async, read_decision_batch_body, read_decision_batch_body_async,
    reconcile_outcome, seal_requests,
};
use fgit_chronicle::{
    LostCandidate, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
    VerifiedPublication, collect_cumulative_outcomes_from_authenticated_capsule_checkpoint,
    collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_async,
    publish_with_cumulative, verify_pair,
};
use fgit_codec::{CryptoBodyIdentity, RefusalRecordBody, RepositoryDecisionBatchBody, encode_body};
use fgit_txn::combiner::BatchBounds;
use fgit_types::{DecisionOutcome, Digest, RefusalCode, TxId};

use super::{
    AdmissionContext, AdmissionError, AdmissionEvidence, AdmissionInput, AdmissionLimits,
    AdmissionProjection, AdmissionSnapshot, AsyncAdmissionProjection, CanonicalAdmissionProjection,
    CanonicalAdmissionStore, CanonicalRefState, CommitMaterialization, LoweredRequest,
    PlannedPublication, PreparedCommit, ProjectionFailure, PublicationPreparation, SessionPlan,
    TransactionFoldReport, TransactionRequest, ValidatedClosure, ValidationBasis,
    basis_from_authenticated, canonical_ref_state_root, complete_async_commit_materialization,
    complete_commit_materialization, permitted_object_closure_root, prepare_canonical_commit,
    prepare_publication_from_snapshot, prepare_refusal_record, prepare_refusal_record_async,
    read_basis, read_basis_async, refusal_body_bytes, refusal_record_id, seal_attempt,
    validate_commit_materialization,
};

/// Maximum logical transactions sharing one receive publication.
pub const MAX_BATCH_DECISIONS: usize = 64;
/// Maximum canonical decision-batch bytes staged for one receive publication.
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;

/// Ref state derived from an authenticated basis and accepted earlier folds.
///
/// Construction and advancement are private to the admission driver. A
/// materializer can inspect the original basis and current ref state but
/// cannot mint a successor authenticated head or promote staging to authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRefState {
    basis: PublicationBasis,
    refs: CanonicalRefState,
}

impl BatchRefState {
    /// The one authenticated head against which the whole chunk is prepared.
    #[must_use]
    pub const fn basis(&self) -> &PublicationBasis {
        &self.basis
    }

    /// That basis's refs plus accepted earlier ref effects in this chunk.
    #[must_use]
    pub const fn refs(&self) -> &CanonicalRefState {
        &self.refs
    }
}

/// Shared synchronous canonical staging for an ordinary transaction or a
/// derived in-batch ref state. The public projection remains the capability
/// boundary; neither path accepts caller-computed successor roots.
pub(super) fn materialize_canonical<Store, Evidence>(
    projection: &CanonicalAdmissionProjection<Store, Evidence>,
    basis: &PublicationBasis,
    current: CanonicalRefState,
    request: &TransactionRequest,
    fold: &TransactionFoldReport,
    closure: &ValidatedClosure,
) -> Result<CommitMaterialization, ProjectionFailure>
where
    Store: CanonicalAdmissionStore,
    Evidence: AdmissionEvidence,
{
    let evidence = projection
        .evidence
        .commit_evidence(basis, request, fold)
        .map_err(ProjectionFailure::Refuse)?;
    let prepared = prepare_canonical_commit(
        basis,
        request,
        fold,
        closure,
        current,
        fgit_types::layout::RootLayoutVersion::LegacyWholeBody,
        evidence,
    )
    .map_err(ProjectionFailure::Refuse)?;
    let ref_root =
        canonical_ref_state_root(prepared.next_ref_state()).map_err(ProjectionFailure::Refuse)?;
    projection
        .store
        .stage_ref_state(ref_root, prepared.next_ref_state().clone())
        .map_err(ProjectionFailure::Unavailable)?;
    let closure_root = permitted_object_closure_root(prepared.object_closure())
        .map_err(ProjectionFailure::Refuse)?;
    projection
        .store
        .stage_permitted_object_closure(closure_root, prepared.object_closure().clone())
        .map_err(ProjectionFailure::Unavailable)?;
    Ok(prepared.into_materialization())
}

/// The pure state machine shared by the blocking and asynchronous drivers.
struct BatchAttempt {
    basis: PublicationBasis,
    state: Option<BatchRefState>,
    snapshot: Option<AdmissionSnapshot>,
    snapshot_refusal: Option<RefusalCode>,
    publication: PublicationPlan,
    roots: ResultingRoots,
}

impl BatchAttempt {
    fn new(
        basis: PublicationBasis,
        snapshot: Result<AdmissionSnapshot, RefusalCode>,
    ) -> Result<Self, AdmissionError> {
        let (snapshot, state, snapshot_refusal) = match snapshot {
            Ok(snapshot) => {
                let refs = match &snapshot.head_target {
                    Some(target) => CanonicalRefState::new_with_head_target(
                        snapshot.refs.clone(),
                        target.clone(),
                    ),
                    None => Ok(CanonicalRefState::new(snapshot.refs.clone())),
                }
                .map_err(AdmissionError::AsyncProjectionUnavailable)?;
                let state = BatchRefState {
                    basis: basis.clone(),
                    refs,
                };
                (Some(snapshot), Some(state), None)
            }
            Err(code) => (None, None, Some(code)),
        };
        Ok(Self {
            roots: ResultingRoots::carried_forward(&basis),
            publication: PublicationPlan::open(basis.clone())?,
            basis,
            state,
            snapshot,
            snapshot_refusal,
        })
    }

    fn prepare(
        &self,
        context: &AdmissionContext,
        request: &LoweredRequest,
        closure: &ValidatedClosure,
        tx_id: TxId,
    ) -> Result<PublicationPreparation, AdmissionError> {
        if let Some(code) = self.snapshot_refusal {
            return Ok(PublicationPreparation::Refuse(code));
        }
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or(AdmissionError::MaterializationMismatch(
                "microbatch snapshot",
            ))?;
        prepare_publication_from_snapshot(context, request, closure, tx_id, snapshot)
    }

    fn state(&self) -> Result<&BatchRefState, AdmissionError> {
        self.state
            .as_ref()
            .ok_or(AdmissionError::MaterializationMismatch(
                "microbatch ref state",
            ))
    }

    fn commit(
        &mut self,
        context: &AdmissionContext,
        lowered: &LoweredRequest,
        closure: &ValidatedClosure,
        prepared: &PreparedCommit,
        materialization: CommitMaterialization,
    ) -> Result<(), AdmissionError> {
        validate_commit_materialization(
            context,
            &self.basis,
            prepared.request.tx_id,
            &lowered.semantic,
            closure,
            &materialization,
        )?;
        let effects = prepared
            .fold
            .effects()
            .ok_or(AdmissionError::MaterializationMismatch(
                "microbatch committed fold",
            ))?;
        if !effects.forge.is_empty() || !effects.retention.is_empty() || !effects.outbox.is_empty()
        {
            return Err(AdmissionError::MaterializationMismatch(
                "microbatch non-ref effects",
            ));
        }
        let next = self.state()?.refs.apply(&effects.refs).map_err(|_| {
            AdmissionError::MaterializationMismatch("microbatch successor ref state")
        })?;
        let next_refs = next.refs().clone();
        self.state
            .as_mut()
            .ok_or(AdmissionError::MaterializationMismatch(
                "microbatch ref state",
            ))?
            .refs = next;
        self.snapshot
            .as_mut()
            .ok_or(AdmissionError::MaterializationMismatch(
                "microbatch snapshot",
            ))?
            .refs = next_refs;
        self.roots = materialization.roots;
        self.publication.commit(materialization.record);
        Ok(())
    }

    /// Refusal records carry their final ordinal before hashing or staging.
    fn stamp_refusal(
        &self,
        mut refusal: RefusalRecordBody,
    ) -> Result<RefusalRecordBody, AdmissionError> {
        let mut sequence = self.basis.open_decision_sequence()?;
        for _ in 0..self.publication.len() {
            sequence = sequence.next().map_err(|_| {
                AdmissionError::Chronicle(fgit_chronicle::ChronicleRefusal::SequenceExhausted {
                    counter: "decision sequence",
                })
            })?;
        }
        refusal.decision_sequence = sequence;
        Ok(refusal)
    }

    fn refuse(&mut self, refusal: &RefusalRecordBody) -> Result<(), AdmissionError> {
        self.publication
            .refuse(refusal.tx_id, refusal.code, refusal_record_id(refusal)?);
        Ok(())
    }

    fn seal(
        self,
        cumulative: &CumulativeOutcomes,
        expected: AuthorityVersionToken,
    ) -> Result<VerifiedPublication, AdmissionError> {
        let publication =
            self.publication
                .seal(&CryptoBodyIdentity, self.roots, cumulative, expected)?;
        let observed = encode_body(publication.batch())
            .map_err(AdmissionError::HeadCodec)?
            .len();
        if observed > MAX_BATCH_BYTES {
            return Err(AdmissionError::MicrobatchBytesExceeded {
                limit: MAX_BATCH_BYTES,
                observed,
            });
        }
        Ok(publication)
    }
}

fn bounds() -> Result<BatchBounds, AdmissionError> {
    BatchBounds::try_new(MAX_BATCH_DECISIONS as u32, MAX_BATCH_BYTES as u64, 0)
        .map_err(|_| AdmissionError::InvalidLimit)
}

/// Reconcile the derived accelerator with one authenticated cumulative read.
/// This avoids a full historical replay for every new command while retaining
/// the same conflict check as the single-transaction outcome resolver.
fn known_outcome(
    cumulative: &CumulativeOutcomes,
    tx_id: TxId,
    indexed: OutcomeLookup,
) -> Result<Option<TerminalOutcome>, AdmissionError> {
    let replayed = cumulative
        .decision_for(tx_id)
        .map_or(OutcomeLookup::Undecided, OutcomeLookup::Decided);
    Ok(match reconcile_outcome(indexed, replayed)? {
        OutcomeLookup::Decided(terminal) => Some(terminal),
        OutcomeLookup::Undecided => None,
    })
}

fn remember(
    known: &mut [Option<TerminalOutcome>],
    completed: &mut Vec<TerminalOutcome>,
    index: usize,
    terminal: TerminalOutcome,
) {
    known[index] = Some(terminal);
    while let Some(Some(next)) = known.get(completed.len()) {
        completed.push(*next);
    }
}

/// A validation witness may advance only over an exact publication consisting
/// entirely of this session's already authenticated outcomes. In particular,
/// one matching command inside somebody else's batch is not enough.
fn owns_batch(
    batch: &RepositoryDecisionBatchBody,
    plan: &SessionPlan,
    known: &[Option<TerminalOutcome>],
    closure_root: Digest,
) -> bool {
    !batch.decisions.is_empty()
        && batch.compaction_generation_link.is_none()
        && batch.decisions.iter().all(|decision| {
            plan.tx_ids.iter().zip(known).any(|(tx_id, terminal)| {
                *tx_id == decision.tx_id
                    && *terminal
                        == Some(TerminalOutcome {
                            decision_sequence: decision.decision_sequence,
                            outcome: decision.outcome,
                        })
            })
        })
        && batch.committed_rcrs.iter().all(|record| {
            record.object_closure_root == closure_root
                && batch.decisions.iter().any(|decision| {
                    decision.tx_id == record.tx_id
                        && matches!(decision.outcome, DecisionOutcome::Committed { .. })
                })
        })
}

fn continuation_preserves_authority(
    previous: &PublicationBasis,
    observed: &PublicationBasis,
) -> bool {
    let previous = previous.body();
    let observed = observed.body();
    observed.configuration_root == previous.configuration_root
        && observed.policy_epoch == previous.policy_epoch
        && observed.format_registry_epoch == previous.format_registry_epoch
        && observed.last_checkpoint_id == previous.last_checkpoint_id
        && observed.retention_root == previous.retention_root
        && observed.forge_position_root == previous.forge_position_root
        && observed.outbox_root == previous.outbox_root
}

fn advance_validation<S: AuthorityStore + ?Sized>(
    store: &S,
    validation: &mut Option<ValidationBasis>,
    observed: &PublicationBasis,
    plan: &SessionPlan,
    known: &[Option<TerminalOutcome>],
    closure_root: Digest,
) -> Result<(), AdmissionError> {
    let Some(permitted) = validation.as_mut() else {
        return Ok(());
    };
    if observed.id() == permitted.head {
        return Ok(());
    }
    let mut cursor = observed.clone();
    // At least one previously resolved command must own every traversed head.
    // This is a session-sized verification bound, never an arbitrary history walk.
    for _ in 0..plan.lowered.len() {
        let Some(predecessor) = cursor.body().predecessor_head_id else {
            return Ok(());
        };
        let previous =
            PublicationBasis::new(predecessor, read_authority_head_body(store, predecessor)?);
        if !continuation_preserves_authority(&previous, &cursor) {
            return Ok(());
        }
        let tail =
            cursor
                .body()
                .decision_tail_id
                .ok_or(AdmissionError::MaterializationMismatch(
                    "receive continuation decision tail",
                ))?;
        let batch = read_decision_batch_body(store, tail)?;
        verify_pair(&CryptoBodyIdentity, &previous, &batch, cursor.body())?;
        if !owns_batch(&batch, plan, known, closure_root) {
            return Ok(());
        }
        if previous.id() == permitted.head {
            permitted.head = observed.id();
            return Ok(());
        }
        cursor = previous;
    }
    Ok(())
}

async fn advance_validation_async<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    validation: &mut Option<ValidationBasis>,
    observed: &PublicationBasis,
    plan: &SessionPlan,
    known: &[Option<TerminalOutcome>],
    closure_root: Digest,
) -> Result<(), AdmissionError> {
    let Some(permitted) = validation.as_mut() else {
        return Ok(());
    };
    if observed.id() == permitted.head {
        return Ok(());
    }
    let mut cursor = observed.clone();
    for _ in 0..plan.lowered.len() {
        let Some(predecessor) = cursor.body().predecessor_head_id else {
            return Ok(());
        };
        let previous = PublicationBasis::new(
            predecessor,
            read_authority_head_body_async(store, cx, predecessor).await?,
        );
        if !continuation_preserves_authority(&previous, &cursor) {
            return Ok(());
        }
        let tail =
            cursor
                .body()
                .decision_tail_id
                .ok_or(AdmissionError::MaterializationMismatch(
                    "receive continuation decision tail",
                ))?;
        let batch = read_decision_batch_body_async(store, cx, tail).await?;
        verify_pair(&CryptoBodyIdentity, &previous, &batch, cursor.body())?;
        if !owns_batch(&batch, plan, known, closure_root) {
            return Ok(());
        }
        if previous.id() == permitted.head {
            permitted.head = observed.id();
            return Ok(());
        }
        cursor = previous;
    }
    Ok(())
}

fn same_head(read: HeadRead, expected: AuthorityVersionToken) -> Result<bool, AdmissionError> {
    match read {
        HeadRead::Present(receipt) => Ok(receipt.token() == expected),
        HeadRead::Absent => Err(AdmissionError::HeadAbsent),
    }
}

enum PublicationResolution {
    /// The CAS selected this exact batch; authenticate its returned receipt.
    Published(HeadReadReceipt),
    /// These outcomes were resolved from the canonical stream by chronicle.
    Recovered(Vec<(TxId, TerminalOutcome)>),
}

fn publication_resolution(verdict: PublicationVerdict) -> PublicationResolution {
    match verdict {
        PublicationVerdict::Published(receipt) => PublicationResolution::Published(receipt.head),
        PublicationVerdict::AlreadyDecided { decided }
        | PublicationVerdict::Lost(LostCandidate::Superseded { decided }) => {
            PublicationResolution::Recovered(decided)
        }
        PublicationVerdict::Lost(LostCandidate::Replannable) => {
            PublicationResolution::Recovered(Vec::new())
        }
    }
}

/// Resolve all of a successful chunk's terminals from its authenticated CAS
/// receipt and the exact batch that receipt selects. Later head movement
/// cannot invalidate these terminal outcomes. Staged bodies alone never enter
/// this path, and every result is still reconciled with the derived index.
fn published_decisions(
    publication: &VerifiedPublication,
    authenticated: &AuthenticatedHead,
) -> Result<Vec<(TxId, TerminalOutcome)>, AdmissionError> {
    let selected = basis_from_authenticated(authenticated)?;
    if selected.body() != publication.head() {
        return Err(AdmissionError::MaterializationMismatch(
            "published microbatch receipt",
        ));
    }
    verify_pair(
        &CryptoBodyIdentity,
        publication.basis(),
        publication.batch(),
        selected.body(),
    )?;
    Ok(publication
        .batch()
        .decisions
        .iter()
        .map(|decision| {
            (
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            )
        })
        .collect())
}

fn reconcile_terminal(
    indexed: OutcomeLookup,
    terminal: TerminalOutcome,
) -> Result<TerminalOutcome, AdmissionError> {
    match reconcile_outcome(indexed, OutcomeLookup::Decided(terminal))? {
        OutcomeLookup::Decided(outcome) => Ok(outcome),
        OutcomeLookup::Undecided => Err(AdmissionError::PublishedOutcomeMissing),
    }
}

fn terminal_index(
    plan: &SessionPlan,
    start: usize,
    end: usize,
    tx_id: TxId,
) -> Result<usize, AdmissionError> {
    plan.tx_ids[start..end]
        .iter()
        .position(|candidate| *candidate == tx_id)
        .map(|offset| start + offset)
        .ok_or(AdmissionError::MaterializationMismatch(
            "microbatch terminal identity",
        ))
}

const fn require_staged_refusal(outcome: PutOutcome) -> Result<(), AdmissionError> {
    match outcome {
        PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()),
        PutOutcome::Conflict => Err(AdmissionError::MaterializationMismatch(
            "immutable microbatch refusal",
        )),
    }
}

pub(super) fn admit_non_atomic<S, P>(
    store: &S,
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    plan: &SessionPlan,
    limits: AdmissionLimits,
    projection: &P,
    completed: &mut Vec<TerminalOutcome>,
) -> Result<(), AdmissionError>
where
    S: AuthorityStore + ?Sized,
    P: AdmissionProjection + ?Sized,
{
    let chunk_size = bounds()?.max_decisions() as usize;
    let mut known = vec![None; plan.lowered.len()];
    let mut validation = input.validation_basis;
    // One invocation may publish many chunks. Retain its authenticated history
    // only while the exact store token matches, or after authority verifies our
    // own winning successor. A foreign head always requires a fresh collection.
    let mut cumulative_cache: Option<CumulativeOutcomes> = None;
    let mut seals = Vec::with_capacity(plan.lowered.len());
    for lowered in plan
        .lowered
        .chunks(fgit_authority::MAX_IMMUTABLE_BATCH_ITEMS)
    {
        let attempts = lowered
            .iter()
            .map(|lowered| seal_attempt(context, lowered))
            .collect::<Vec<_>>();
        seals.extend(
            seal_requests(store, &attempts)?
                .iter()
                .map(fgit_authority::SealAdmission::seal_id),
        );
    }

    for start in (0..plan.lowered.len()).step_by(chunk_size) {
        let end = (start + chunk_size).min(plan.lowered.len());
        for _ in 0..limits.max_cas_replans {
            let (basis, receipt, authenticated) = read_basis(store, &context.head_key)?;
            let cumulative = match cumulative_cache
                .take()
                .filter(|outcomes| outcomes.observed() == receipt.token())
            {
                Some(outcomes) => outcomes,
                None => collect_cumulative_outcomes_from_authenticated_capsule_checkpoint(
                    store,
                    &CryptoBodyIdentity,
                    &context.head_key,
                    &authenticated,
                )?,
            };
            if cumulative.observed() != receipt.token() {
                continue;
            }
            let mut probes = Vec::with_capacity(end - start);
            for index in start..end {
                if known[index].is_none() {
                    probes.push((
                        index,
                        indexed_outcome(
                            store,
                            context.tenant_id,
                            context.repository_id,
                            plan.tx_ids[index],
                        )?,
                    ));
                }
            }
            // An accelerator can legitimately get ahead while this snapshot
            // is read. Replan before interpreting that race as corruption.
            if !same_head(store.read_head(&context.head_key)?, receipt.token())? {
                continue;
            }
            for (index, indexed) in probes {
                if let Some(terminal) = known_outcome(&cumulative, plan.tx_ids[index], indexed)? {
                    remember(&mut known, completed, index, terminal);
                }
            }
            if known[start..end].iter().all(Option::is_some) {
                cumulative_cache = Some(cumulative);
                break;
            }
            advance_validation(
                store,
                &mut validation,
                &basis,
                plan,
                &known,
                input.closure.object_closure_root,
            )?;
            let snapshot = if validation.is_some_and(|validation| validation.head != basis.id()) {
                Err(RefusalCode::AuthorityReceiptStale)
            } else {
                projection.snapshot(&basis, &authenticated)
            };
            let mut attempt = BatchAttempt::new(basis.clone(), snapshot)?;
            for index in start..end {
                if known[index].is_some() {
                    continue;
                }
                let lowered = &plan.lowered[index];
                let tx_id = plan.tx_ids[index];
                let code = match attempt.prepare(context, lowered, input.closure, tx_id)? {
                    PublicationPreparation::Refuse(code) => code,
                    PublicationPreparation::Commit(prepared) => {
                        match complete_commit_materialization(
                            projection.materialize_batch_commit(
                                attempt.state()?,
                                &prepared.request,
                                &prepared.fold,
                                input.closure,
                            ),
                            tx_id,
                        )? {
                            PlannedPublication::Commit(materialization) => {
                                attempt.commit(
                                    context,
                                    lowered,
                                    input.closure,
                                    &prepared,
                                    *materialization,
                                )?;
                                continue;
                            }
                            PlannedPublication::Refuse(code) => code,
                        }
                    }
                };
                let refusal = attempt.stamp_refusal(prepare_refusal_record(
                    projection,
                    &basis,
                    seals[index],
                    tx_id,
                    code,
                )?)?;
                let (key, bytes) = refusal_body_bytes(&refusal)?;
                require_staged_refusal(store.put_if_absent(&key, &bytes)?)?;
                attempt.refuse(&refusal)?;
            }
            let publication = attempt.seal(&cumulative, receipt.token())?;
            let (resolved, published) = match publication_resolution(publish_with_cumulative(
                store,
                &context.head_key,
                receipt.token(),
                &publication,
                context.tenant_id,
                &cumulative,
            )?) {
                PublicationResolution::Published(published) => {
                    let resolved = published_decisions(
                        &publication,
                        &store.authenticate_head_receipt(&published)?,
                    )?;
                    (resolved, Some(published))
                }
                // The cached prefix cannot be rebound to a competing writer's
                // head from terminal hints, even when every child is decided.
                PublicationResolution::Recovered(decided) => (decided, None),
            };
            for (tx_id, terminal) in resolved {
                let index = terminal_index(plan, start, end, tx_id)?;
                let terminal = reconcile_terminal(
                    indexed_outcome(store, context.tenant_id, context.repository_id, tx_id)?,
                    terminal,
                )?;
                remember(&mut known, completed, index, terminal);
            }
            // Carrying a prefix is optional work for the next chunk. Preserve
            // every authenticated terminal first, including if reauthentication
            // is cancelled or detects an integrity failure. No final chunk
            // needs an extension, so completion cannot fail on unused caching.
            if end < plan.lowered.len()
                && let Some(published) = published
            {
                cumulative_cache = Some(cumulative.extend_after_publication(
                    store,
                    &receipt,
                    &published,
                    publication.batch(),
                )?);
            }
            if known[start..end].iter().all(Option::is_some) {
                break;
            }
        }
        if known[start..end].iter().any(Option::is_none) {
            return Err(AdmissionError::CasReplanLimitExceeded {
                limit: limits.max_cas_replans,
            });
        }
    }
    Ok(())
}

/// The coordinator retains `completed` if an operation is interrupted. Only
/// the contiguous, authoritatively resolved prefix is exposed to its caller.
pub(super) async fn admit_non_atomic_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    plan: &SessionPlan,
    limits: AdmissionLimits,
    projection: &P,
    completed: &mut Vec<TerminalOutcome>,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
{
    let chunk_size = bounds()?.max_decisions() as usize;
    let mut known = vec![None; plan.lowered.len()];
    let mut validation = input.validation_basis;
    let mut cumulative_cache: Option<CumulativeOutcomes> = None;
    let mut seals = Vec::with_capacity(plan.lowered.len());
    for lowered in plan
        .lowered
        .chunks(fgit_authority::MAX_IMMUTABLE_BATCH_ITEMS)
    {
        let attempts = lowered
            .iter()
            .map(|lowered| seal_attempt(context, lowered))
            .collect::<Vec<_>>();
        seals.extend(
            fgit_authority::seal_requests_async(store, cx, &attempts)
                .await?
                .iter()
                .map(fgit_authority::SealAdmission::seal_id),
        );
    }

    for start in (0..plan.lowered.len()).step_by(chunk_size) {
        let end = (start + chunk_size).min(plan.lowered.len());
        for _ in 0..limits.max_cas_replans {
            let (basis, receipt, authenticated) =
                read_basis_async(store, cx, &context.head_key).await?;
            let cumulative = match cumulative_cache
                .take()
                .filter(|outcomes| outcomes.observed() == receipt.token())
            {
                Some(outcomes) => outcomes,
                None => {
                    collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_async(
                        store,
                        cx,
                        &CryptoBodyIdentity,
                        &context.head_key,
                        &authenticated,
                    )
                    .await?
                }
            };
            if cumulative.observed() != receipt.token() {
                continue;
            }
            let mut probes = Vec::with_capacity(end - start);
            for index in start..end {
                if known[index].is_none() {
                    probes.push((
                        index,
                        indexed_outcome_async(
                            store,
                            cx,
                            context.tenant_id,
                            context.repository_id,
                            plan.tx_ids[index],
                        )
                        .await?,
                    ));
                }
            }
            if !same_head(
                store.read_head(cx, &context.head_key).await?,
                receipt.token(),
            )? {
                continue;
            }
            for (index, indexed) in probes {
                if let Some(terminal) = known_outcome(&cumulative, plan.tx_ids[index], indexed)? {
                    remember(&mut known, completed, index, terminal);
                }
            }
            if known[start..end].iter().all(Option::is_some) {
                cumulative_cache = Some(cumulative);
                break;
            }
            advance_validation_async(
                store,
                cx,
                &mut validation,
                &basis,
                plan,
                &known,
                input.closure.object_closure_root,
            )
            .await?;
            let stale = validation.filter(|validation| validation.head != basis.id());
            let snapshot = if stale.is_some_and(|validation| validation.authority.is_none()) {
                Err(RefusalCode::AuthorityReceiptStale)
            } else {
                match projection
                    .snapshot_async(store, cx, &basis, &authenticated)
                    .await
                {
                    Ok(snapshot) => {
                        if stale.is_some_and(|validation| {
                            validation.authority != projection.validation_authority(&basis)
                        }) {
                            Err(RefusalCode::AuthorityReceiptStale)
                        } else {
                            Ok(snapshot)
                        }
                    }
                    Err(ProjectionFailure::Refuse(code)) => Err(code),
                    Err(ProjectionFailure::Unavailable(code)) => {
                        return Err(AdmissionError::AsyncProjectionUnavailable(code));
                    }
                }
            };
            // A successfully checked equivalent basis is itself a permitted
            // witness. Retain it before our own chunk changes visible refs or
            // closure; the next chunk must not need to cross the earlier
            // foreign edge again. A snapshot refusal never grants this step.
            if snapshot.is_ok()
                && let Some(validation) = &mut validation
            {
                validation.head = basis.id();
            }
            let mut attempt = BatchAttempt::new(basis.clone(), snapshot)?;
            for index in start..end {
                if known[index].is_some() {
                    continue;
                }
                let lowered = &plan.lowered[index];
                let tx_id = plan.tx_ids[index];
                let code = match attempt.prepare(context, lowered, input.closure, tx_id)? {
                    PublicationPreparation::Refuse(code) => code,
                    PublicationPreparation::Commit(prepared) => {
                        match complete_async_commit_materialization(
                            projection
                                .materialize_batch_commit_async(
                                    store,
                                    cx,
                                    attempt.state()?,
                                    &prepared.request,
                                    &prepared.fold,
                                    input.closure,
                                )
                                .await,
                        )? {
                            PlannedPublication::Commit(materialization) => {
                                attempt.commit(
                                    context,
                                    lowered,
                                    input.closure,
                                    &prepared,
                                    *materialization,
                                )?;
                                continue;
                            }
                            PlannedPublication::Refuse(code) => code,
                        }
                    }
                };
                let refusal = attempt.stamp_refusal(
                    prepare_refusal_record_async(
                        projection,
                        store,
                        cx,
                        &basis,
                        seals[index],
                        tx_id,
                        code,
                    )
                    .await?,
                )?;
                let (key, bytes) = refusal_body_bytes(&refusal)?;
                require_staged_refusal(store.put_if_absent(cx, &key, &bytes).await?)?;
                attempt.refuse(&refusal)?;
            }
            let publication = attempt.seal(&cumulative, receipt.token())?;
            let (resolved, published) = match publication_resolution(
                fgit_chronicle::publish_with_cumulative_async(
                    store,
                    cx,
                    &context.head_key,
                    receipt.token(),
                    &publication,
                    context.tenant_id,
                    &cumulative,
                )
                .await?,
            ) {
                PublicationResolution::Published(published) => {
                    let resolved = published_decisions(
                        &publication,
                        &store.authenticate_head_receipt(cx, &published).await?,
                    )?;
                    (resolved, Some(published))
                }
                PublicationResolution::Recovered(decided) => (decided, None),
            };
            for (tx_id, terminal) in resolved {
                let index = terminal_index(plan, start, end, tx_id)?;
                let terminal = reconcile_terminal(
                    indexed_outcome_async(
                        store,
                        cx,
                        context.tenant_id,
                        context.repository_id,
                        tx_id,
                    )
                    .await?,
                    terminal,
                )?;
                remember(&mut known, completed, index, terminal);
            }
            if end < plan.lowered.len()
                && let Some(published) = published
            {
                cumulative_cache = Some(
                    cumulative
                        .extend_after_publication_async(
                            store,
                            cx,
                            &receipt,
                            &published,
                            publication.batch(),
                        )
                        .await?,
                );
            }
            if known[start..end].iter().all(Option::is_some) {
                break;
            }
        }
        if known[start..end].iter().any(Option::is_none) {
            return Err(AdmissionError::CasReplanLimitExceeded {
                limit: limits.max_cas_replans,
            });
        }
    }
    Ok(())
}
