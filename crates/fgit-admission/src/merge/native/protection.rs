//! Canonical named-review protection selected at each publication attempt.
//! Administrative state is a singleton forge stream on the SAME authority head
//! as refs, PRs and review decisions. An immutable staged policy is not active.
use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::PublicationBasis;
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_forge::event::protection::{ProtectionCommand, NativeProtectionEvent};
use fgit_types::{AsciiSlug, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure, ValidatedClosure};
use super::{NativeMergeIntent, NativeMergeProjection, PreparationFailure, metadata, storage, unavailable};
use super::super::NativeMergeBasis;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedProtection {
    pub source_head: RepositoryAuthorityHeadId,
    pub version: AggregateVersion,
    pub event: NativeProtectionEvent,
}
fn failure(error: AdmissionError) -> ProjectionFailure {
    match error {
        AdmissionError::AsyncProjectionUnavailable(code) => ProjectionFailure::Unavailable(code),
        _ => ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid),
    }
}
fn checkpoint<C: Fn() -> bool + ?Sized>(cancelled: &C) -> Result<(), AdmissionError> {
    if cancelled() { Err(unavailable(RefusalCode::CancellationInProgress)) } else { Ok(()) }
}

/// Resolve only the exact authenticated forge frontier. Missing selected bytes
/// or a substituted event never become an unprotected repository.
pub async fn read_at<S, C>(store: &S, cx: &S::Context, basis: &PublicationBasis, cancelled: &C)
    -> Result<Option<SelectedProtection>, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync + ?Sized,
{
    checkpoint(cancelled)?;
    let positions = storage::load_forge_positions(store, cx, basis).await?;
    checkpoint(cancelled)?;
    let label = AsciiSlug::from_static("repository-protection");
    let Some(entry) = positions.entry(label) else { return Ok(None); };
    let batch = storage::read_events(store, cx, basis.body().repository_id, entry.event_batch_root()).await?;
    checkpoint(cancelled)?;
    let event = batch.events.iter().rev().find(|event| event.aggregate == AggregateId::RepositoryProtection)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    if event.version.get() != entry.successor_position() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let ForgeEventPayload::RepositoryProtectionChangedNative(change) = &event.payload else {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    };
    change.validate().map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if change.activated_epoch().map_err(unavailable)? > basis.body().policy_epoch {
        return Err(unavailable(RefusalCode::EvidenceStale));
    }
    Ok(Some(SelectedProtection { source_head: basis.id(), version: event.version, event: change.clone() }))
}

pub fn proposal(context: &AdmissionContext, command: &ProtectionCommand)
    -> Result<(ForgeEvent, SealAttempt), AdmissionError>
{
    let event = command.proposed_event(context.principal_id).map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format, true, Vec::new(), Vec::new(), vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"), AsciiSlug::from_static("repository-protection.event-batch-root"), root.bytes().as_bytes(),
        )?])?;
    Ok((event, SealAttempt { tenant_id: context.tenant_id, repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id, idempotency_key: context.idempotency_key.clone(), request }))
}

pub async fn admit_protection_async<S, P>(store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &ProtectionCommand, limits: AdmissionLimits, projection: &P)
    -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = proposal(context, command)?;
    metadata::admit_metadata_async(store, cx, context, event, attempt, limits, projection, &ProtectionValidation).await
}
struct ProtectionValidation;
impl<S, P> metadata::MetadataValidation<S, P> for ProtectionValidation
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> { Ok(()) }
    async fn validate(&self, store: &S, cx: &S::Context, basis: &PublicationBasis,
        _: &AuthenticatedHead, _: &AdmissionSnapshot, _: &NativeMergeBasis,
        event: &ForgeEvent, projection: &P) -> Result<ValidatedClosure, PreparationFailure>
    {
        let ForgeEventPayload::RepositoryProtectionChangedNative(change) = &event.payload else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        if change.expected_policy_epoch != basis.body().policy_epoch {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        let current = read_at(store, cx, basis, &|| projection.merge_checkpoint(cx).is_err()).await?;
        let authorized = match &current {
            // Bootstrap is an explicitly authenticated local administrative
            // operation, not a network receive capability or a ref update.
            None => event.version == AggregateVersion::FIRST && change.policy.administrators.contains(&change.actor),
            Some(current) => current.event.policy.administrators.contains(&change.actor),
        };
        if !authorized { return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into()); }
        let expected = current.map_or(0, |current| current.version.get());
        if expected.checked_add(1) != Some(event.version.get()) {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        projection.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
        let closure = crate::PermittedObjectClosure::default();
        Ok(ValidatedClosure { object_closure_root: crate::permitted_object_closure_root(&closure)
            .map_err(ProjectionFailure::Unavailable)?, objects: Default::default() })
    }
}

/// A direct ref mutation carries no canonical PR candidate-review authority.
/// Administrators do not get an implicit bypass. Even force/delete/import must
/// use an ordinary authorized policy change before touching a protected branch.
pub async fn guard_direct_refs<S, C>(store: &S, cx: &S::Context, basis: &PublicationBasis,
    targets: &[RefName], cancelled: &C) -> Result<(), ProjectionFailure>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync + ?Sized,
{
    if targets.is_empty() { return Ok(()); }
    let Some(selected) = read_at(store, cx, basis, cancelled).await.map_err(failure)? else { return Ok(()); };
    if targets.iter().any(|target| selected.event.policy.reviewers(target).is_some()) {
        return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied));
    }
    Ok(())
}

/// Ordinary, explicitly reviewed and original sealed native merges all reach
/// this same gate inside their per-basis publication loop. Caller requirements
/// can add constraints, never remove the current repository requirements.
pub async fn guard_native_merge<S, C>(store: &S, cx: &S::Context, basis: &PublicationBasis,
    intent: &NativeMergeIntent, submitter: PrincipalId, cancelled: &C) -> Result<(), ProjectionFailure>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync,
{
    let Some(selected) = read_at(store, cx, basis, cancelled).await.map_err(failure)? else { return Ok(()); };
    let target = &intent.merge().map_err(failure)?.target_ref;
    let Some(reviewers) = selected.event.policy.reviewers(target) else { return Ok(()); };
    let required = super::pull_request::reviews::gate::ReviewRequirements::new(basis.body().policy_epoch, reviewers.to_vec())
        .map_err(failure)?;
    super::pull_request::reviews::gate::verify_at(store, cx, basis, intent, submitter, &required, cancelled).await
}
