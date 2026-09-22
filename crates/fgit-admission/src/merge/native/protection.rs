//! Authority-selected required-review protection. The forge frontier commits
//! the complete policy and ownership, while the head epoch invalidates old votes.
//! Immutable placement alone never activates a policy.
use super::pull_request::reviews::gate::{ReviewRequirements, verify_at};
use super::{
    NativeMergeIntent, NativeMergeProjection, PreparationFailure, metadata, storage, unavailable,
};
use crate::merge::NativeMergeBasis;
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure,
    ProjectionFailure, ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, validate_transition};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, PolicyEpoch, PrincipalId, RefusalCode, RepositoryAuthorityHeadId};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionState {
    pub source_head: RepositoryAuthorityHeadId,
    pub policy_epoch: PolicyEpoch,
    /// None means no policy has ever been installed, not a missing body.
    pub event: Option<ForgeEvent>,
}
impl ProtectionState {
    pub fn version(&self) -> Option<AggregateVersion> {
        self.event.as_ref().map(|event| event.version)
    }
    pub fn protection(&self) -> Option<&ReviewProtection> {
        self.event.as_ref().and_then(|event| match &event.payload {
            ForgeEventPayload::ReviewProtectionChanged(change) => Some(&change.protection),
            _ => None,
        })
    }
}
fn live(cancelled: &(impl Fn() -> bool + Sync)) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}
fn infrastructure(error: AdmissionError) -> ProjectionFailure {
    match error {
        AdmissionError::AsyncProjectionUnavailable(code) => ProjectionFailure::Unavailable(code),
        _ => ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptInvalid),
    }
}
/// Read from the exact authenticated forge root, never a local policy file or
/// an optional caller projection. Missing/corrupt selected bodies fail closed.
pub async fn read_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    cancelled: &C,
) -> Result<ProtectionState, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    live(cancelled)?;
    let positions = storage::load_forge_positions(store, cx, basis).await?;
    live(cancelled)?;
    let entry = positions.entry(storage::aggregate_label(AggregateId::ReviewProtection)?);
    let event = if let Some(entry) = entry {
        let batch = storage::read_events(
            store,
            cx,
            basis.body().repository_id,
            entry.event_batch_root(),
        )
        .await?;
        live(cancelled)?;
        let event = batch
            .events
            .into_iter()
            .rev()
            .find(|event| event.aggregate == AggregateId::ReviewProtection)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let ForgeEventPayload::ReviewProtectionChanged(change) = &event.payload else {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        };
        change
            .validate()
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        if event.version.get() != entry.successor_position()
            || change.resulting_epoch().map_err(unavailable)? != basis.body().policy_epoch
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        Some(event)
    } else {
        None
    };
    live(cancelled)?;
    Ok(ProtectionState {
        source_head: basis.id(),
        policy_epoch: basis.body().policy_epoch,
        event,
    })
}

pub fn proposal(
    context: &AdmissionContext,
    command: &ProtectionCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command
        .proposed_event(context.principal_id)
        .map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("review-protection.event-batch-root.v1"),
            root.bytes().as_bytes(),
        )?],
    )?;
    Ok((
        event,
        SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request,
        },
    ))
}
pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &ProtectionCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = proposal(context, command)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &Validation,
    )
    .await
}
struct Validation;
impl<S, P> metadata::MetadataValidation<S, P> for Validation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }
    async fn validate(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        _: &AuthenticatedHead,
        _: &AdmissionSnapshot,
        _: &NativeMergeBasis,
        event: &ForgeEvent,
        projection: &P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let current = read_at(store, cx, basis, &|| {
            projection.merge_checkpoint(cx).is_err()
        })
        .await?;
        validate_transition(current.event.as_ref(), event, basis.body().policy_epoch)
            .map_err(ProjectionFailure::Refuse)?;
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let objects = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: crate::permitted_object_closure_root(&objects)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: BTreeSet::new(),
        })
    }
}

/// Required on the embedded node's ordinary ref-only commit materializer.
/// Receive, source import, workspace publication, branch changes and rebase all
/// use that materializer; a client cannot opt out by choosing another CLI verb.
/// Identity/no-op effects do not change a protected branch and remain permitted.
pub async fn enforce_direct_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    fold: &fgit_txn::TransactionFoldReport,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let fgit_reference::effect::FoldOutcome::Folded(effects) = &fold.outcome else {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
    };
    if effects.refs.is_empty() {
        return Ok(());
    }
    let selected = read_at(store, cx, basis, cancelled)
        .await
        .map_err(infrastructure)?;
    if let Some(policy) = selected.protection() {
        let has_protected = effects
            .refs
            .keys()
            .any(|name| policy.branch(name).is_some());
        if has_protected {
            // Evaluated through fg043 PolicySnapshot via evaluate_protection
            let mut source = crate::policy_bridge::InMemoryPolicySnapshots::new();
            let branch_strings: Vec<String> = policy
                .branches
                .iter()
                .filter_map(|b| {
                    std::str::from_utf8(b.name.as_bytes())
                        .ok()
                        .map(ToOwned::to_owned)
                })
                .collect();
            let branch_refs: Vec<&str> = branch_strings.iter().map(String::as_str).collect();
            let compiled = crate::policy_bridge::compile_protected_branch_rules(branch_refs)
                .map_err(|_| {
                    ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied)
                })?;
            let id = source.pin(compiled);
            let verdict = crate::policy_bridge::evaluate_effects_protection(
                &source,
                &id,
                &crate::policy_bridge::SubjectCodeMap::default(),
                PrincipalId::from_bytes([0; 16]),
                crate::policy_bridge::default_principal_snapshot_id(),
                &std::collections::BTreeMap::new(),
                &effects.refs,
                fgit_policy::PolicyInstant::from_seconds(0),
            )
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
            if let Some(code) = verdict.refusal {
                return Err(ProjectionFailure::Refuse(code));
            }
        }
    }
    live(cancelled).map_err(infrastructure)
}
/// Required on every production native merge validation attempt. Reuse the
/// exact-candidate gate, including opener/submitter independence and withdrawals.
/// The request seal remains unchanged: this is current repository policy, not a
/// caller-selected additional requirement or a new retry identity.
pub async fn enforce_merge_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    intent: &NativeMergeIntent,
    submitter: PrincipalId,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let selected = read_at(store, cx, basis, cancelled)
        .await
        .map_err(infrastructure)?;
    let merge = intent.merge().map_err(infrastructure)?;
    if let Some(rule) = selected
        .protection()
        .and_then(|p| p.branch(&merge.target_ref))
    {
        let required = ReviewRequirements::new(selected.policy_epoch, rule.reviewers.clone())
            .map_err(infrastructure)?;
        verify_at(store, cx, basis, intent, submitter, &required, cancelled).await?;
    }
    live(cancelled).map_err(infrastructure)
}

/// Verify the one policy-epoch transition this embedded profile can publish.
/// The RCR records the policy used to authorize it (the predecessor epoch),
/// while its successor head records the newly installed policy epoch. This
/// exception is accepted only for the exact authenticated singleton event and
/// an independently checked administrator/version transition; arbitrary epoch
/// mismatches remain corruption, not an instruction to reset policy.
pub async fn verify_epoch_advance_at<S, C>(
    store: &S,
    cx: &S::Context,
    predecessor: &PublicationBasis,
    successor: &fgit_codec::schema::RepositoryAuthorityHeadBody,
    batch: &fgit_codec::schema::RepositoryDecisionBatchBody,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    live(cancelled)?;
    let [record] = batch.committed_rcrs.as_slice() else {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    };
    if batch.decisions.len() != 1
        || record.policy_epoch != predecessor.body().policy_epoch
        || successor.policy_epoch
            != predecessor
                .body()
                .policy_epoch
                .next()
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        || record.resulting_ref_root != predecessor.body().ref_root
        || successor.retention_root != predecessor.body().retention_root
        || successor.configuration_root != predecessor.body().configuration_root
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let selected = storage::read_events(
        store,
        cx,
        successor.repository_id,
        record.forge_event_batch_root,
    )
    .await?;
    let [event] = selected.events.as_slice() else {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    };
    let previous = read_at(store, cx, predecessor, cancelled).await?;
    validate_transition(
        previous.event.as_ref(),
        event,
        predecessor.body().policy_epoch,
    )
    .map_err(unavailable)?;
    let successor_id = fgit_codec::body_id(&fgit_codec::CryptoBodyIdentity, successor)
        .and_then(|id| RepositoryAuthorityHeadId::from_internal_object_id(id).map_err(Into::into))
        .map_err(|_| unavailable(RefusalCode::AuthorityReceiptInvalid))?;
    let current = read_at(
        store,
        cx,
        &PublicationBasis::new(successor_id, successor.clone()),
        cancelled,
    )
    .await?;
    if current.event.as_ref() != Some(event) {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    live(cancelled)
}
