//! Canonical repository-administrator changes to symbolic HEAD.
//!
//! HEAD and its exact target tip are semantic preconditions, sealed by the same
//! transaction identity as every other mutation. Each losing CAS rechecks the
//! current administrator policy, authenticated ref state and native Commit.
//! There is no direct-ref edit, forge-only event, configuration shortcut or new
//! publication primitive. Historical V1 ref layouts cannot enter this path.

mod command;
mod staging;
mod transition;

pub use command::{DEFAULT_BRANCH_ADMISSION_SCHEMA, DefaultBranchCommand, proposal};
pub use transition::CanonicalHeadChange;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, OutcomeLookup, SealAttempt, TerminalOutcome,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots};
use fgit_codec::{CryptoBodyIdentity, RepositoryCommitRecord};
use fgit_forge::ForgeEventBatch;
use fgit_types::{RefusalCode, RepositorySequence, TxId};

use crate::evidence::{AdmissionAuthentication, evidence_root, head_change::HeadChangeEvidence};
use crate::merge::native::{NativeMergeProjection, protection};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, CanonicalRefState, CommitMaterialization,
    PermittedObjectClosure, ProjectionFailure, permitted_object_closure_root, ref_state_root,
};

/// Publish an existing branch as the canonical default through one ordinary
/// sealed outcome and authority-head CAS. Trusted-local OperatorAssertion is
/// required. With no installed protection policy it permits bootstrap; once a
/// policy exists only its current administrators may select HEAD. Canonically
/// declared agents remain excluded even if presented with operator provenance.
/// Historical terminal retries retain their decision after policy/head changes.
pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &DefaultBranchCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    let attempt = proposal(context, command)?;
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
    for _ in 0..limits.max_cas_replans {
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        let (basis, receipt, authenticated) =
            crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = match projection
            .collect_cumulative_outcomes_async(store, cx, &context.head_key, &authenticated)
            .await
        {
            Ok(cumulative) => cumulative,
            Err(error) => {
                if crate::collect_terminal_retryable(&error)
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
                return Err(error.into());
            }
        };
        if cumulative.observed() != receipt.token() {
            continue;
        }
        match fgit_authority::resolve_outcome_with_cumulative_async(
            store,
            cx,
            &context.head_key,
            receipt.token(),
            context.tenant_id,
            context.repository_id,
            tx_id,
            &cumulative,
        )
        .await?
        {
            Some(OutcomeLookup::Decided(outcome)) => return Ok(outcome),
            Some(OutcomeLookup::Undecided) => {}
            None => continue,
        }
        let prepared = prepare(
            store,
            cx,
            context,
            command,
            &attempt,
            tx_id,
            &basis,
            &authenticated,
            projection,
        )
        .await;
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => {
                return Err(unavailable(code));
            }
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                projection
                    .merge_publication_checkpoint(cx)
                    .map_err(unavailable)?;
                if let Some(outcome) = crate::publish_refusal_async(
                    store,
                    cx,
                    context,
                    &basis,
                    receipt.token(),
                    admission.seal_id(),
                    tx_id,
                    code,
                    projection,
                    &cumulative,
                )
                .await?
                {
                    return Ok(outcome);
                }
                continue;
            }
        };
        projection
            .merge_publication_checkpoint(cx)
            .map_err(unavailable)?;
        staging::stage_prepared(store, cx, &prepared, projection).await?;
        projection
            .merge_publication_checkpoint(cx)
            .map_err(unavailable)?;
        let mut plan = PublicationPlan::open(basis)?;
        plan.commit(prepared.materialization.record);
        let publication = plan.seal(
            &CryptoBodyIdentity,
            prepared.materialization.roots,
            &cumulative,
            receipt.token(),
        )?;
        projection
            .merge_publication_checkpoint(cx)
            .map_err(unavailable)?;
        if let Some(outcome) = crate::outcome_after_publish_async(
            store,
            cx,
            context,
            receipt.token(),
            &publication,
            &cumulative,
        )
        .await?
        {
            return Ok(outcome);
        }
    }
    projection.merge_checkpoint(cx).map_err(unavailable)?;
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
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

struct PreparedHeadChange {
    refs: CanonicalRefState,
    closure: PermittedObjectClosure,
    delta: CanonicalHeadChange,
    evidence: HeadChangeEvidence,
    protection_witness: Option<ForgeEventBatch>,
    materialization: CommitMaterialization,
}

async fn prepare<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &DefaultBranchCommand,
    attempt: &SealAttempt,
    tx_id: TxId,
    basis: &PublicationBasis,
    authenticated: &AuthenticatedHead,
    projection: &P,
) -> Result<PreparedHeadChange, PreparationFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    if basis.body().repository_id != context.repository_id {
        return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptInvalid).into());
    }
    let authentication = projection.admission_authentication();
    if authentication != Some(AdmissionAuthentication::OperatorAssertion) {
        return Err(ProjectionFailure::Refuse(RefusalCode::CapabilityScopeViolation).into());
    }
    // This precedes the snapshot/native object read. A credential or projection
    // claiming OperatorAssertion cannot turn a declared agent into an admin.
    let non_agent = protection::require_non_agent_publication_at(
        store,
        cx,
        basis,
        Some(context.principal_id),
        authentication,
        &|| projection.merge_checkpoint(cx).is_err(),
    )
    .await;
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    non_agent?;
    let protection = protection::read_at(store, cx, basis, &|| {
        projection.merge_checkpoint(cx).is_err()
    })
    .await;
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    let protection = protection?;
    if protection
        .protection()
        .is_some_and(|policy| !policy.administrators.contains(&context.principal_id))
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::PublicationPolicyRefused).into());
    }
    let layout = fgit_authority::root_layout_for_verification_async(
        store,
        cx,
        &basis.body().configuration_root,
    )
    .await
    .map_err(AdmissionError::from)?;
    if !layout.commits_head_target() {
        return Err(ProjectionFailure::Refuse(RefusalCode::SchemaUnsupported).into());
    }
    let snapshot = projection
        .snapshot_async(store, cx, basis, authenticated)
        .await?;
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    if snapshot.hidden_refs.hides(b"HEAD")
        || snapshot.hidden_refs.hides(command.target.as_bytes())
        || snapshot
            .head_target
            .as_ref()
            .is_some_and(|name| snapshot.hidden_refs.hides(name.as_bytes()))
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
    }
    let before = match snapshot.head_target {
        Some(target) => CanonicalRefState::new_with_head_target(snapshot.refs, target)
            .map_err(ProjectionFailure::Unavailable)?,
        None => CanonicalRefState::new(snapshot.refs),
    };
    if ref_state_root(layout, &before).map_err(ProjectionFailure::Unavailable)?
        != basis.body().ref_root
        || before
            .refs()
            .values()
            .any(|oid| oid.algorithm() != context.object_format)
    {
        return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into());
    }
    if before.head_target() != command.expected_head.as_ref()
        || before.refs().get(&command.target) != Some(&command.expected_target_tip)
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::ExpectedOldRefMismatch).into());
    }
    projection
        .validate_default_branch_target_async(
            store,
            cx,
            basis,
            authenticated,
            &command.target,
            command.expected_target_tip,
        )
        .await?;
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    let refs =
        CanonicalRefState::new_with_head_target(before.refs().clone(), command.target.clone())
            .map_err(ProjectionFailure::Unavailable)?;
    let resulting_ref_root =
        ref_state_root(layout, &refs).map_err(ProjectionFailure::Unavailable)?;
    let (derived_tx, seal) = attempt.derive().map_err(AdmissionError::from)?;
    if derived_tx != tx_id {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid).into());
    }
    let protection_witness = protection.event.map(ForgeEventBatch::of_one);
    let protection_witness_root = protection_witness
        .as_ref()
        .map(evidence_root)
        .transpose()
        .map_err(ProjectionFailure::Unavailable)?;
    let delta = CanonicalHeadChange {
        tenant: context.tenant_id,
        repository: context.repository_id,
        principal: context.principal_id,
        tx_id,
        request_digest: seal.canonical_request_digest,
        basis_head: basis.id(),
        layout,
        previous_ref_root: basis.body().ref_root,
        resulting_ref_root,
        command: command.clone(),
        protection_witness_root,
    };
    delta
        .verify_transition(
            context,
            basis,
            &before,
            &refs,
            command,
            protection_witness_root,
        )
        .map_err(ProjectionFailure::Unavailable)?;
    let delta_root = evidence_root(&delta).map_err(ProjectionFailure::Unavailable)?;
    let evidence = HeadChangeEvidence::derive(context, basis, tx_id, seal.canonical_request_digest)
        .map_err(ProjectionFailure::Unavailable)?;
    let closure = PermittedObjectClosure::default();
    let roots = ResultingRoots {
        ref_root: resulting_ref_root,
        forge_position_root: basis.body().forge_position_root,
        retention_root: basis.body().retention_root,
        outbox_root: basis.body().outbox_root,
        policy_epoch: basis.body().policy_epoch,
        compaction_generation_link: None,
    };
    let record = RepositoryCommitRecord {
        repository_id: context.repository_id,
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id,
        principal_snapshot_id: evidence
            .principal
            .id()
            .map_err(ProjectionFailure::Unavailable)?,
        canonical_request_digest: seal.canonical_request_digest,
        ref_delta_root: delta_root,
        resulting_ref_root,
        object_closure_root: permitted_object_closure_root(&closure)
            .map_err(ProjectionFailure::Unavailable)?,
        forge_event_batch_root: evidence_root(&evidence.forge)
            .map_err(ProjectionFailure::Unavailable)?,
        resulting_forge_position_root: roots.forge_position_root,
        policy_epoch: roots.policy_epoch,
        policy_decision_root: evidence_root(&evidence.policy)
            .map_err(ProjectionFailure::Unavailable)?,
        invariant_evidence_root: delta_root,
        outbox_effect_root: evidence_root(&evidence.outbox)
            .map_err(ProjectionFailure::Unavailable)?,
        retention_delta_root: evidence_root(&evidence.retention)
            .map_err(ProjectionFailure::Unavailable)?,
    };
    Ok(PreparedHeadChange {
        refs,
        closure,
        delta,
        evidence,
        protection_witness,
        materialization: CommitMaterialization { record, roots },
    })
}

enum PreparationFailure {
    Projection(ProjectionFailure),
    Admission(Box<AdmissionError>),
}
impl From<ProjectionFailure> for PreparationFailure {
    fn from(value: ProjectionFailure) -> Self {
        Self::Projection(value)
    }
}
impl From<AdmissionError> for PreparationFailure {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(Box::new(value))
    }
}
const fn unavailable(code: RefusalCode) -> AdmissionError {
    AdmissionError::AsyncProjectionUnavailable(code)
}

#[cfg(test)]
mod tests;
