//! Admitting a sealed merge through the real publication path.
//!
//! # The gap this fills
//!
//! `fgit-forge` can compute a merge and seal an effect package, and
//! [`fgit_forge::MergeEffectPackage::seal_into_record`] reduces it to one commit
//! record carrying both the ref delta and the `MergeCommitted` event. Nothing
//! admitted one. The canonical commit preparer in this crate refuses forge
//! effects outright — correctly, because receive-pack only moves refs — so a
//! merge had no route to authority and concurrent merges could not be raced for
//! real. A test-local state machine would only have simulated the production
//! path, which `AGENTS.md` forbids as evidence.
//!
//! # Exactly one winner is inherited, not invented
//!
//! This module mirrors [`crate::admit_one`]'s control flow rather than growing a
//! second one: seal, probe for an already-decided outcome, then a bounded CAS
//! replan loop that re-reads the basis every attempt. That loop already provides
//! exactly-one-winner. A merge only has to re-check the right things inside it.
//!
//! The loser's refusal falls out of that structure instead of being bolted on.
//! Two attempts race; one wins the head CAS. The other gets `None`, replans,
//! re-reads the basis — and now the target ref holds the winner's merge commit,
//! so the staleness re-check fails and the loser publishes a typed
//! [`RefusalCode::TargetRefMoved`] as its own terminal decision. It does not
//! spin, and it never retries against a state its merge was not computed for.
//!
//! # What is re-checked here, and what cannot be
//!
//! Ref tips are re-read from the authenticated snapshot, so admission verifies
//! them itself rather than trusting the caller. The workspace epoch is supplied
//! by the caller: admission has no workspace and cannot derive it, and a value
//! it invented would be a second source of truth for someone else's state.

use fgit_authority::{
    AuthenticatedHead, CumulativeOutcomes, SealAttempt, collect_cumulative_outcomes,
};
use fgit_forge::{MergeAttempt, MergeEffectPackage, ObservedTips};
use fgit_types::{GitOid, RefName, RefusalCode, TxId};

use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionProjection, AdmissionSnapshot,
    AuthorityStore, CommitEvidence, ValidatedClosure,
};

/// One merge, sealed by its author and ready for authority.
///
/// Borrowed rather than owned because every field is already held by the caller
/// that computed the merge, and copying a package into admission would create a
/// second thing that could drift from the one the author sealed.
pub struct SealedMerge<'a> {
    /// The three effects that publish together.
    pub package: &'a MergeEffectPackage,
    /// The state the merge was computed against.
    pub attempt: &'a MergeAttempt,
    /// Objects the merge produced, already validated into the closure.
    pub closure: &'a ValidatedClosure,
    /// Evidence the policy and invariant owners supply for this decision.
    pub evidence: CommitEvidence,
    /// The workspace epoch observed at admission time.
    ///
    /// Supplied rather than derived: this crate has no workspace. See the module
    /// note on what admission can and cannot re-check for itself.
    pub workspace_epoch_now: fgit_forge::WorkspaceEpoch,
}

/// Why a merge was not admitted at one particular basis.
///
/// Separate from [`AdmissionError`] because none of these are faults: they are
/// evaluated terminal decisions about a specific head, and the caller's correct
/// response is to recompute the merge, not to retry the same one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeStaleness {
    /// A ref moved away from the tip the merge was computed against.
    RefMoved {
        /// Which side moved.
        side: fgit_forge::MergeSide,
    },
    /// The workspace advanced after the merge was computed in it.
    WorkspaceAdvanced,
}

impl MergeStaleness {
    /// The canonical refusal code this staleness publishes as.
    ///
    /// A moved ref is exactly `TargetRefMoved`. A moved workspace is
    /// `EvidenceStale` — "supplied evidence names a superseded basis" — which is
    /// what a tree computed in a workspace that has since advanced is. The
    /// alternative, `WorkspaceBaseUnavailable`, says the base could not be
    /// obtained, which is a different and untrue thing here.
    #[must_use]
    pub const fn refusal_code(self) -> RefusalCode {
        match self {
            Self::RefMoved { .. } => RefusalCode::TargetRefMoved,
            Self::WorkspaceAdvanced => RefusalCode::EvidenceStale,
        }
    }
}

/// Re-checks a merge against one authenticated snapshot.
///
/// This is the whole staleness decision, factored out so the blocking and
/// asynchronous drivers share it verbatim. A second copy would be a second
/// definition of when a merge is stale.
///
/// # Errors
///
/// Returns the staleness that disqualifies this merge at this basis.
pub fn check_against_snapshot(
    sealed: &SealedMerge<'_>,
    snapshot: &AdmissionSnapshot,
) -> Result<(), MergeStaleness> {
    let observed = ObservedTips {
        source_tip: tip_of(snapshot, &sealed.attempt.source_ref),
        target_tip: tip_of(snapshot, &sealed.attempt.target_ref),
        workspace_epoch: sealed.workspace_epoch_now,
    };
    sealed
        .attempt
        .check_fresh(&observed)
        .map_err(|refusal| match refusal {
            fgit_forge::ForgeRefusal::MergeStale { reference, .. } => {
                MergeStaleness::RefMoved { side: reference }
            }
            _ => MergeStaleness::WorkspaceAdvanced,
        })
}

/// The tip a ref holds at this snapshot.
///
/// An absent ref yields the zero identity in the repository's own hash domain,
/// which is Git's "no object" and is never a real object identity. Returning the
/// merge's own expected tip instead would make an absent ref look fresh, which
/// is the one answer that must never be reachable here.
fn tip_of(snapshot: &AdmissionSnapshot, name: &[u8]) -> GitOid {
    RefName::try_new(name)
        .ok()
        .and_then(|reference| snapshot.refs.get(&reference).copied())
        .unwrap_or(GitOid::Sha256(fgit_types::GitOidSha256::ZERO))
}

/// Builds the sealing attempt for a merge.
///
/// A merge's target-ref movement is an ordinary [`fgit_authority::RefCommand`]
/// whose expected old value is the tip the merge was computed against, so a
/// merge seals through the same path as any other transaction and derives its
/// `TxId` the same way. Nothing about the seal vocabulary is merge-specific,
/// which is deliberate: a second way to seal would be a second way to be
/// idempotent.
///
/// # Errors
///
/// [`AdmissionError`] when the ref name or the request cannot be canonicalized.
pub fn seal_attempt_for(
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
) -> Result<SealAttempt, AdmissionError> {
    let name = RefName::try_new(&sealed.package.ref_intent.name)
        .map_err(|_| AdmissionError::MaterializationMismatch("merge ref name"))?;
    let command = fgit_authority::RefCommand {
        name,
        expected_old: fgit_authority::ExpectedOld::Exactly(sealed.package.ref_intent.expected_tip),
        proposed_new: fgit_authority::ProposedNew::Update(sealed.package.ref_intent.new_tip),
        // A merge never bypasses fast-forward checking. If the merge commit does
        // not descend from the target tip, the merge itself was wrong, and
        // forcing would publish that wrongness rather than refusing it.
        force: false,
    };
    // RECEIVE_ADMISSION_SCHEMA, deliberately, and for the reason lower_input
    // states: the schema names the SHAPE of the decision -- ref commands
    // admitted against an authority head -- not the transport that carried it.
    // A merge is exactly that shape. Minting a merge-specific schema would give
    // one ref movement two transaction identities and split a single canonical
    // history in half, which is what section 5.2's one stable identity
    // derivation forbids.
    let semantic = fgit_authority::SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        vec![command],
        Vec::new(),
        Vec::new(),
    )?;
    Ok(SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request: semantic,
    })
}

/// One replan's decision: publish the merge, or publish why it cannot be.
pub(crate) enum MergePlan {
    /// The merge is fresh at this basis, and this is the ref state it results
    /// in.
    ///
    /// The resulting state travels with the decision rather than being re-derived:
    /// it must come from the very basis the staleness check passed against, and a
    /// second read could straddle another publication.
    Commit(Box<crate::CanonicalRefState>),
    /// The merge is stale at this basis and this is its terminal decision.
    Refuse(RefusalCode),
}

/// Decides one attempt against one basis.
///
/// Shared by both drivers so the blocking and asynchronous surfaces cannot
/// diverge about when a merge is admissible.
pub(crate) fn plan_attempt<Projection>(
    sealed: &SealedMerge<'_>,
    basis: &fgit_chronicle::PublicationBasis,
    authenticated: &AuthenticatedHead,
    projection: &Projection,
) -> MergePlan
where
    Projection: AdmissionProjection + ?Sized,
{
    // A projection that refuses is not a fault: it is an evaluated terminal
    // decision for this exact basis, so it becomes a refusal to publish rather
    // than an error to propagate.
    let snapshot = match projection.snapshot(basis, authenticated) {
        Ok(snapshot) => snapshot,
        Err(code) => return MergePlan::Refuse(code),
    };
    if let Err(staleness) = check_against_snapshot(sealed, &snapshot) {
        return MergePlan::Refuse(staleness.refusal_code());
    }
    let Ok(name) = RefName::try_new(&sealed.package.ref_intent.name) else {
        return MergePlan::Refuse(RefusalCode::PublicationPolicyRefused);
    };
    let mut refs = snapshot.refs;
    refs.insert(name, sealed.package.ref_intent.new_tip);
    MergePlan::Commit(Box::new(crate::CanonicalRefState::new(refs)))
}

/// Guards the cumulative outcome set against the head it was collected from.
///
/// Reused rather than re-derived: folding entries collected at one head against
/// a different head produces a well-formed root that commits to the wrong
/// history, and the token comparison is what makes that unrepresentable.
pub(crate) fn outcomes_match_basis(
    outcomes: &CumulativeOutcomes,
    receipt: &fgit_authority::HeadReadReceipt,
) -> bool {
    outcomes.observed() == receipt.token()
}

/// Admit one sealed merge against the authority.
///
/// # Errors
///
/// [`AdmissionError`] for faults. A stale merge is not a fault: it returns a
/// terminal decision carrying [`RefusalCode::TargetRefMoved`] or
/// [`RefusalCode::EvidenceStale`].
pub fn admit_merge<S, Projection>(
    store: &S,
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    limits: AdmissionLimits,
    projection: &Projection,
) -> Result<fgit_authority::TerminalOutcome, AdmissionError>
where
    S: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
{
    let attempt = seal_attempt_for(context, sealed)?;
    let admission = fgit_authority::seal_request(store, &attempt)?;
    let tx_id = admission.tx_id();
    if let fgit_authority::OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome(
        store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )? {
        return Ok(terminal);
    }

    for replan in 0..limits.max_cas_replans {
        if replan != 0
            && let fgit_authority::OutcomeLookup::Decided(terminal) =
                fgit_authority::resolve_outcome(
                    store,
                    &context.head_key,
                    context.tenant_id,
                    context.repository_id,
                    tx_id,
                )?
        {
            return Ok(terminal);
        }
        let (basis, receipt, authenticated) = crate::read_basis(store, &context.head_key)?;
        let cumulative = collect_cumulative_outcomes(store, &context.head_key)?;
        if !outcomes_match_basis(&cumulative, &receipt) {
            continue;
        }
        let terminal = match plan_attempt(sealed, &basis, &authenticated, projection) {
            MergePlan::Refuse(code) => crate::publish_refusal(
                store,
                context,
                &basis,
                receipt.token(),
                admission.seal_id(),
                tx_id,
                code,
                projection,
                &cumulative,
            )?,
            MergePlan::Commit(next_state) => {
                let materialization =
                    materialize(context, sealed, tx_id, &attempt, &basis, &next_state)?;
                crate::publish_commit(
                    store,
                    context,
                    &basis,
                    receipt.token(),
                    tx_id,
                    &attempt.request,
                    sealed.closure,
                    materialization,
                    &cumulative,
                )?
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

/// Turns the sealed package into the one record authority will publish.
///
/// The record is built by `fgit-forge` itself, from the package's own bytes, so
/// admission never restates what the merge author sealed. What admission
/// supplies is the frame: the sequence, the epoch, the principal snapshot and
/// the evidence roots, which are its to decide and not the author's.
///
/// # Errors
///
/// [`AdmissionError`] when the ref name, the resulting ref state or the
/// package's own identity cannot be produced.
fn materialize(
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &fgit_chronicle::PublicationBasis,
    next_state: &crate::CanonicalRefState,
) -> Result<crate::CommitMaterialization, AdmissionError> {
    let ref_root = crate::canonical_ref_state_root(next_state)
        .map_err(|_| AdmissionError::MaterializationMismatch("merge resulting ref root"))?;

    let roots = fgit_chronicle::ResultingRoots {
        ref_root,
        // NON-CLAIM, and the bead's own instruction: route forge events through
        // the existing mechanism if one exists, otherwise record a typed
        // non-claim and do NOT build one here.
        //
        // The forge INTENT vocabulary exists (fgit_reference::intent::ForgeIntent,
        // with an expected_position), but nothing in the workspace produces a
        // forge_position_root: every production assignment is a carry-forward or
        // a fixture. So this merge does NOT advance the forge stream position,
        // and a head it publishes records the merge event in
        // forge_event_batch_root WITHOUT moving the position that would order it.
        //
        // That is a real gap and it is stated rather than papered over. Inventing
        // a root formula here would be d6nl in a different field: a value that
        // looks well formed, publishes cleanly, and is wrong in a way nothing
        // notices until replay.
        forge_position_root: basis.body().forge_position_root,
        retention_root: basis.body().retention_root,
        outbox_root: basis.body().outbox_root,
        policy_epoch: basis.body().policy_epoch,
        compaction_generation_link: None,
    };

    let frame = fgit_forge::merge::RecordFrame {
        repository_id: context.repository_id,
        // The plan owns the real sequence and predecessor. These only satisfy
        // the complete record shape before it is handed over, exactly as the
        // receive-pack preparer does, and are never identified.
        repository_sequence: fgit_types::RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id,
        principal_snapshot_id: sealed.evidence.principal_snapshot_id,
        canonical_request_digest: fgit_authority::canonical_request_digest(&attempt.request)
            .map_err(|failure| AdmissionError::Seal(Box::new(failure.into())))?,
        resulting_ref_root: roots.ref_root,
        object_closure_root: sealed.closure.object_closure_root,
        resulting_forge_position_root: roots.forge_position_root,
        policy_epoch: roots.policy_epoch,
        policy_decision_root: sealed.evidence.policy_decision_root,
        invariant_evidence_root: sealed.evidence.invariant_evidence_root,
        outbox_effect_root: sealed.evidence.outbox_effect_root,
        retention_delta_root: sealed.evidence.retention_delta_root,
    };

    let record = sealed
        .package
        .seal_into_record(&fgit_codec::CryptoBodyIdentity, frame)
        .map_err(|_| AdmissionError::MaterializationMismatch("merge package identity"))?;
    Ok(crate::CommitMaterialization { record, roots })
}
