//! Authority-selected required-review protection. The forge frontier commits
//! the complete policy and ownership, while the head epoch invalidates old votes.
//! Immutable placement alone never activates a policy.
use super::{
    NativeMergeIntent, NativeMergeProjection, PreparationFailure, metadata, storage, unavailable,
};
use crate::evidence::AdmissionAuthentication;
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
use fgit_types::{
    AsciiSlug, GitOid, PolicyEpoch, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId,
};
use std::collections::{BTreeMap, BTreeSet};

mod checks;
mod queue_gate;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionState {
    pub source_head: RepositoryAuthorityHeadId,
    pub policy_epoch: PolicyEpoch,
    /// None means no policy has ever been installed, not a missing body.
    pub event: Option<ForgeEvent>,
}
impl ProtectionState {
    #[must_use]
    pub fn version(&self) -> Option<AggregateVersion> {
        self.event.as_ref().map(|event| event.version)
    }
    #[must_use]
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
    error.into_projection_unavailable(RefusalCode::AuthorityReceiptInvalid)
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
/// `refs` must be materialized from this authenticated publication basis, plus
/// only the successful prior decisions in the same bounded decision batch.
pub async fn enforce_direct_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    fold: &fgit_txn::TransactionFoldReport,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    enforce_direct_selected_at(store, cx, basis, refs, fold, None, None, cancelled)
        .await
        .map(|_| ())
}

async fn enforce_direct_selected_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    fold: &fgit_txn::TransactionFoldReport,
    principal: Option<PrincipalId>,
    authentication: Option<AdmissionAuthentication>,
    cancelled: &C,
) -> Result<Option<ProtectionState>, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let fgit_reference::effect::FoldOutcome::Folded(effects) = &fold.outcome else {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
    };
    if effects.refs.is_empty() {
        return Ok(None);
    }
    let selected = read_at(store, cx, basis, cancelled)
        .await
        .map_err(infrastructure)?;
    if let Some(policy) = selected.protection() {
        enforce_installed_snapshot_with_authentication(
            policy,
            refs,
            &effects.refs,
            principal,
            authentication,
        )?;
        queue_gate::enforce(policy, basis, refs, &effects.refs, principal, None)?;
        let has_protected = effects.refs.keys().any(|name| {
            policy
                .branch(name)
                .is_some_and(|rule| !rule.reviewers.is_empty())
        });
        if has_protected {
            // Evaluated through fg043 PolicySnapshot via evaluate_protection
            let mut source = crate::policy_bridge::InMemoryPolicySnapshots::new();
            let compiled = compile_direct_branches(
                policy
                    .branches
                    .iter()
                    .filter(|branch| !branch.reviewers.is_empty())
                    .map(|branch| &branch.name),
            )?;
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
        for (name, effect) in &effects.refs {
            if let Some(rule) = policy.branch(name) {
                let fgit_reference::effect::RefEffect::Set(candidate) = effect else {
                    return Err(ProjectionFailure::Refuse(
                        RefusalCode::ProtectedRefTransitionDenied,
                    ));
                };
                // A fanout cannot use a checked source and simultaneously
                // delete it or repoint it to an unchecked commit.
                for check in &rule.required_checks {
                    if effects.refs.get(&check.source_ref).is_some_and(|effect| {
                        !matches!(effect, fgit_reference::effect::RefEffect::Set(oid) if oid == candidate)
                    }) {
                        return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied));
                    }
                }
                checks::verify_at(
                    store,
                    cx,
                    basis,
                    refs,
                    *candidate,
                    &rule.required_checks,
                    cancelled,
                )
                .await?;
            }
        }
    }
    live(cancelled).map_err(infrastructure)?;
    Ok(Some(selected))
}

/// The production ref materializer's final gate. It retains the snapshots that
/// actually decided this attempt, after resolving protection at the exact
/// authenticated basis and checking every required status check. The caller's
/// current refs include only driver-accepted earlier microbatch decisions.
pub async fn direct_decision_evidence_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    current: &crate::CanonicalRefState,
    layout: fgit_types::RootLayoutVersion,
    request: &fgit_reference::intent::TransactionRequest,
    fold: &fgit_txn::TransactionFoldReport,
    cancelled: &C,
) -> Result<crate::evidence::DecisionEvidenceBodies, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    direct_decision_evidence_selected_at(
        store, cx, context, basis, current, layout, request, fold, None, cancelled,
    )
    .await
}

/// The same authority-selected decision gate with host-verified authentication.
/// The fact is retained in the principal receipt and supplied to policy before
/// evaluation; it never changes the sealed request or transaction identity.
pub async fn direct_decision_evidence_with_authentication_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    current: &crate::CanonicalRefState,
    layout: fgit_types::RootLayoutVersion,
    request: &fgit_reference::intent::TransactionRequest,
    fold: &fgit_txn::TransactionFoldReport,
    authentication: AdmissionAuthentication,
    cancelled: &C,
) -> Result<crate::evidence::DecisionEvidenceBodies, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    direct_decision_evidence_selected_at(
        store,
        cx,
        context,
        basis,
        current,
        layout,
        request,
        fold,
        Some(authentication),
        cancelled,
    )
    .await
}

async fn direct_decision_evidence_selected_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    current: &crate::CanonicalRefState,
    layout: fgit_types::RootLayoutVersion,
    request: &fgit_reference::intent::TransactionRequest,
    fold: &fgit_txn::TransactionFoldReport,
    authentication: Option<AdmissionAuthentication>,
    cancelled: &C,
) -> Result<crate::evidence::DecisionEvidenceBodies, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    if context.repository_id != basis.body().repository_id
        || request.repository != context.repository_id
        || request.tenant != context.tenant_id
        || request.principal != context.principal_id
    {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
    }
    let selected = enforce_direct_selected_at(
        store,
        cx,
        basis,
        current.refs(),
        fold,
        Some(context.principal_id),
        authentication,
        cancelled,
    )
    .await?;
    let mut evidence = match authentication {
        Some(authentication) => {
            crate::evidence::DecisionEvidenceBodies::derive_with_authentication(
                context,
                basis,
                request,
                fold,
                authentication,
            )
        }
        None => crate::evidence::DecisionEvidenceBodies::derive(context, basis, request, fold),
    }
    .map_err(ProjectionFailure::Unavailable)?;
    if let Some(selected) = selected {
        let branches = review_branches(&selected);
        match selected.protection().and_then(|p| p.ref_policy.as_ref()) {
            Some(snapshot) => evidence.record_activated_policy(
                context,
                basis,
                current,
                layout,
                fold,
                branches,
                snapshot.clone(),
                crate::evidence::RefPolicyPublication::Direct,
            ),
            None => evidence.record_ref_policies(context, basis, current, layout, fold, branches),
        }
        .map_err(ProjectionFailure::Refuse)?;
    }
    live(cancelled).map_err(infrastructure)?;
    Ok(evidence)
}

/// Verify a historical record against its selected policy, without running
/// today's required-check acceptance or recompiling historical source text.
pub async fn verify_direct_decision_evidence_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    current: &crate::CanonicalRefState,
    layout: fgit_types::RootLayoutVersion,
    record: &crate::evidence::EvaluatedPolicyDecisionEvidence,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let selected = read_at(store, cx, basis, cancelled)
        .await
        .map_err(infrastructure)?;
    // A historical 1.1 record may not substitute for a receipt from an epoch
    // with an activated DSL snapshot.
    if selected
        .protection()
        .is_some_and(|p| p.ref_policy.is_some())
    {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
    }
    record
        .verify_provenance(basis, current, layout, &review_branches(&selected))
        .map_err(ProjectionFailure::Unavailable)?;
    live(cancelled).map_err(infrastructure)
}

/// Validate the evidence version and exact policy selected by its original
/// authenticated publication basis. No current policy reinterprets history.
pub async fn verify_policy_decision_record_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    current: &crate::CanonicalRefState,
    layout: fgit_types::RootLayoutVersion,
    record: &crate::evidence::PolicyDecisionRecord,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    match record {
        crate::evidence::PolicyDecisionRecord::Legacy(_) => {
            return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
        }
        crate::evidence::PolicyDecisionRecord::Evaluated(record) => {
            return verify_direct_decision_evidence_at(
                store, cx, basis, current, layout, record, cancelled,
            )
            .await;
        }
        crate::evidence::PolicyDecisionRecord::Activated(record) => {
            let selected = read_at(store, cx, basis, cancelled)
                .await
                .map_err(infrastructure)?;
            let snapshot = selected
                .protection()
                .and_then(|p| p.ref_policy.as_ref())
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
            record
                .verify_provenance(
                    basis,
                    current,
                    layout,
                    &review_branches(&selected),
                    snapshot,
                )
                .map_err(ProjectionFailure::Unavailable)?;
        }
        crate::evidence::PolicyDecisionRecord::ActorActivated(record) => {
            let selected = read_at(store, cx, basis, cancelled)
                .await
                .map_err(infrastructure)?;
            let snapshot = selected
                .protection()
                .and_then(|p| p.ref_policy.as_ref())
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
            record
                .verify_provenance(
                    basis,
                    current,
                    layout,
                    &review_branches(&selected),
                    snapshot,
                )
                .map_err(ProjectionFailure::Unavailable)?;
        }
        crate::evidence::PolicyDecisionRecord::AuthenticationActivated(record) => {
            let selected = read_at(store, cx, basis, cancelled)
                .await
                .map_err(infrastructure)?;
            let snapshot = selected
                .protection()
                .and_then(|p| p.ref_policy.as_ref())
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
            record
                .verify_provenance(
                    basis,
                    current,
                    layout,
                    &review_branches(&selected),
                    snapshot,
                )
                .map_err(ProjectionFailure::Unavailable)?;
        }
    }
    live(cancelled).map_err(infrastructure)
}

/// Historical 1.0 evidence remains valid only where no activated DSL selected
/// an additional ref decision. Metadata-only records do not call this gate.
pub async fn verify_legacy_ref_policy_absence_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let selected = read_at(store, cx, basis, cancelled)
        .await
        .map_err(infrastructure)?;
    if selected
        .protection()
        .is_some_and(|p| p.ref_policy.is_some())
    {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
    }
    live(cancelled).map_err(infrastructure)
}

/// Bind the installed DSL decision into a completely folded native/legacy
/// merge before any immutable evidence or RCR is staged. Metadata operations
/// have no ref effects and are deliberately outside the DSL ref-policy scope.
pub async fn attach_prepared_policy_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
    prepared: &mut crate::merge::PreparedNativeMerge,
    publication: crate::evidence::RefPolicyPublication,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    attach_prepared_policy_selected_at(
        store,
        cx,
        context,
        basis,
        resolved,
        prepared,
        publication,
        None,
        None,
        cancelled,
    )
    .await
}

/// Attach a current policy decision and an authenticated principal receipt to a
/// completely folded merge before staging any body or attempting publication.
pub async fn attach_prepared_policy_with_authentication_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
    prepared: &mut crate::merge::PreparedNativeMerge,
    publication: crate::evidence::RefPolicyPublication,
    authentication: AdmissionAuthentication,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    attach_prepared_policy_selected_at(
        store,
        cx,
        context,
        basis,
        resolved,
        prepared,
        publication,
        Some(authentication),
        None,
        cancelled,
    )
    .await
}

pub(super) async fn attach_prepared_policy_selected_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
    prepared: &mut crate::merge::PreparedNativeMerge,
    publication: crate::evidence::RefPolicyPublication,
    authentication: Option<AdmissionAuthentication>,
    landing: Option<&super::queue::ValidatedQueueLanding>,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    if let Some(landing) = landing {
        if publication != crate::evidence::RefPolicyPublication::NativeMerge {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
        }
        landing
            .verify_prepared(context, basis, prepared)
            .map_err(ProjectionFailure::Refuse)?;
    }
    let selected = if publication == crate::evidence::RefPolicyPublication::Direct {
        enforce_direct_selected_at(
            store,
            cx,
            basis,
            resolved.refs.refs(),
            &prepared.fold,
            Some(context.principal_id),
            authentication,
            cancelled,
        )
        .await?
        .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?
    } else {
        if !matches!(
            prepared.event.events.as_slice(),
            [ForgeEvent {
                payload: ForgeEventPayload::MergeCommittedNative(_),
                ..
            }]
        ) {
            super::queue::validate_publication_shape(&prepared.event)
                .map_err(ProjectionFailure::Unavailable)?;
        }
        read_at(store, cx, basis, cancelled)
            .await
            .map_err(infrastructure)?
    };
    if let Some(policy) = selected.protection() {
        let effects = prepared
            .fold
            .effects()
            .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
        queue_gate::enforce(
            policy,
            basis,
            resolved.refs.refs(),
            &effects.refs,
            Some(context.principal_id),
            landing,
        )?;
    }
    if let Some(authentication) = authentication {
        prepared.evidence = crate::evidence::DecisionEvidenceBodies::derive_with_authentication(
            context,
            basis,
            &prepared.request,
            &prepared.fold,
            authentication,
        )
        .map_err(ProjectionFailure::Unavailable)?;
        prepared.materialization.record.principal_snapshot_id = prepared
            .evidence
            .principal_snapshot()
            .id()
            .map_err(ProjectionFailure::Unavailable)?;
        prepared.materialization.record.policy_decision_root = prepared
            .evidence
            .policy_decision()
            .root()
            .map_err(ProjectionFailure::Unavailable)?;
    }
    if let Some(snapshot) = selected.protection().and_then(|p| p.ref_policy.as_ref()) {
        prepared
            .evidence
            .record_activated_policy(
                context,
                basis,
                &resolved.refs,
                resolved.root_layout,
                &prepared.fold,
                review_branches(&selected),
                snapshot.clone(),
                publication,
            )
            .map_err(ProjectionFailure::Refuse)?;
        prepared.materialization.record.policy_decision_root = prepared
            .evidence
            .policy_decision()
            .root()
            .map_err(ProjectionFailure::Unavailable)?;
    }
    live(cancelled).map_err(infrastructure)
}

#[cfg(test)]
fn enforce_installed_snapshot(
    policy: &ReviewProtection,
    refs: &BTreeMap<RefName, GitOid>,
    effects: &BTreeMap<RefName, fgit_reference::effect::RefEffect>,
    principal: Option<PrincipalId>,
) -> Result<(), ProjectionFailure> {
    enforce_installed_snapshot_with_authentication(policy, refs, effects, principal, None)
}

fn enforce_installed_snapshot_with_authentication(
    policy: &ReviewProtection,
    refs: &BTreeMap<RefName, GitOid>,
    effects: &BTreeMap<RefName, fgit_reference::effect::RefEffect>,
    principal: Option<PrincipalId>,
    authentication: Option<AdmissionAuthentication>,
) -> Result<(), ProjectionFailure> {
    let Some(snapshot) = &policy.ref_policy else {
        return Ok(());
    };
    let profile = fgit_policy::reference_profile::classify(snapshot)
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
    let principal = match profile {
        fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceFactsV1 => {
            // Frozen ref-only predicates cannot inspect this compatibility fact.
            principal.unwrap_or_else(|| PrincipalId::from_bytes([0; 16]))
        }
        fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceActorIdV1
        | fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceAuthenticationV1 => {
            principal.ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?
        }
    };
    fgit_policy::reference_profile::validate_evaluation_for(profile, snapshot, effects.keys())
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ResourceBudgetExceeded))?;
    let updates = crate::policy_bridge::ref_updates_from_effects(refs, effects)
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
    if profile == fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceAuthenticationV1
    {
        let authentication =
            authentication.ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?;
        let input = fgit_policy::reference_profile::AuthenticatedReferenceInput::try_new(
            principal,
            authentication.authentication_strength(),
            updates,
        )
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
        let verdict = fgit_policy::reference_profile::evaluate_authenticated(snapshot, &input)
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
        return if verdict.decision() == fgit_policy::Decision::Allow {
            Ok(())
        } else {
            Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied,
            ))
        };
    }
    let input = crate::policy_bridge::build_input_root(
        principal,
        crate::policy_bridge::default_principal_snapshot_id(),
        updates,
        fgit_policy::PolicyInstant::from_seconds(0),
    )
    .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
    // This profile can observe only the supplied principal identifier. It
    // cannot inspect compatibility kind/strength/memberships/snapshot/instant.
    let verdict = fgit_policy::evaluate(snapshot, &input)
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
    if verdict.decision() != fgit_policy::Decision::Allow {
        return Err(ProjectionFailure::Refuse(
            RefusalCode::ProtectedRefTransitionDenied,
        ));
    }
    Ok(())
}

fn review_branches(selected: &ProtectionState) -> Vec<RefName> {
    selected.protection().map_or_else(Vec::new, |policy| {
        policy
            .branches
            .iter()
            .filter(|rule| !rule.reviewers.is_empty())
            .map(|rule| rule.name.clone())
            .collect()
    })
}
/// Preserve every authority-selected branch when lowering into the text policy
/// profile. RefName is byte-oriented: filtering or replacing invalid UTF-8 can
/// turn an installed deny rule into the compiler's default allow. A profile
/// that cannot represent a protected name must refuse, never erase that name.
fn compile_direct_branches<'a>(
    branches: impl IntoIterator<Item = &'a fgit_types::RefName>,
) -> Result<fgit_policy::PolicySnapshot, ProjectionFailure> {
    let names = branches
        .into_iter()
        .map(|name| {
            std::str::from_utf8(name.as_bytes())
                .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))
        })
        .collect::<Result<Vec<_>, _>>()?;
    crate::policy_bridge::compile_protected_branch_rules(names)
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))
}

/// Required on every production native merge validation attempt. Reuse the
/// exact-candidate gate, including opener/submitter independence and withdrawals.
/// The request seal remains unchanged: this is current repository policy, not a
/// caller-selected additional requirement or a new retry identity. `refs` must
/// be materialized from this same authenticated publication basis.
pub async fn enforce_merge_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    intent: &NativeMergeIntent,
    submitter: PrincipalId,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    enforce_merge_selected_at(
        store, cx, basis, refs, intent, submitter, None, None, cancelled,
    )
    .await
}

/// Enforce the native merge gate with authentication established by its host.
/// Reviews and required checks remain independent requirements.
pub async fn enforce_merge_with_authentication_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    intent: &NativeMergeIntent,
    submitter: PrincipalId,
    authentication: AdmissionAuthentication,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    enforce_merge_selected_at(
        store,
        cx,
        basis,
        refs,
        intent,
        submitter,
        Some(authentication),
        None,
        cancelled,
    )
    .await
}

/// Enforce every native merge requirement for the exact queue attempt already
/// authenticated by admission. The opaque context cannot be created from a
/// caller-selected policy profile or a well-formed event batch alone.
pub async fn enforce_queued_merge_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    intent: &NativeMergeIntent,
    submitter: PrincipalId,
    authentication: Option<AdmissionAuthentication>,
    landing: &super::queue::ValidatedQueueLanding,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    enforce_merge_selected_at(
        store,
        cx,
        basis,
        refs,
        intent,
        submitter,
        authentication,
        Some(landing),
        cancelled,
    )
    .await
}

async fn enforce_merge_selected_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    intent: &NativeMergeIntent,
    submitter: PrincipalId,
    authentication: Option<AdmissionAuthentication>,
    landing: Option<&super::queue::ValidatedQueueLanding>,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    if let Some(landing) = landing {
        landing
            .verify_intent(basis, intent, submitter)
            .map_err(ProjectionFailure::Refuse)?;
    }
    let selected = read_at(store, cx, basis, cancelled)
        .await
        .map_err(infrastructure)?;
    let merge = intent.merge().map_err(infrastructure)?;
    if let Some(policy) = selected.protection() {
        enforce_installed_snapshot_with_authentication(
            policy,
            refs,
            &BTreeMap::from([(
                merge.target_ref.clone(),
                fgit_reference::effect::RefEffect::Set(merge.merge_commit),
            )]),
            Some(submitter),
            authentication,
        )?;
        queue_gate::enforce(
            policy,
            basis,
            refs,
            &BTreeMap::from([(
                merge.target_ref.clone(),
                fgit_reference::effect::RefEffect::Set(merge.merge_commit),
            )]),
            Some(submitter),
            landing,
        )?;
    }
    if let Some(rule) = selected
        .protection()
        .and_then(|p| p.branch(&merge.target_ref))
    {
        if !rule.reviewers.is_empty() {
            super::pull_request::reviews::gate::verify_quorum_at(
                store,
                cx,
                basis,
                intent,
                submitter,
                selected.policy_epoch,
                &rule.reviewers,
                rule.required_approvals,
                cancelled,
            )
            .await?;
        }
        checks::verify_at(
            store,
            cx,
            basis,
            refs,
            merge.merge_commit,
            &rule.required_checks,
            cancelled,
        )
        .await?;
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

#[cfg(test)]
mod direct_policy_tests {
    use super::*;
    use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
    use fgit_types::{GitOid, GitOidSha1, RefName};
    use std::collections::BTreeMap;

    #[test]
    fn installed_authentication_policy_requires_verified_facts_with_permitted_twins() {
        let principal = PrincipalId::from_bytes([0x33; 16]);
        let mut policy = ReviewProtection {
            administrators: vec![principal],
            branches: Vec::new(),
            ref_policy: Some(fgit_forge::event::protection::compile_ref_policy(
                "policy credential { rule writers { when actor.id == \"33333333333333333333333333333333\" and actor.authentication >= single_factor then allow } default deny \"credential required\" }"
            ).unwrap()),
        };
        let effects = BTreeMap::from([(
            RefName::try_new(b"refs/heads/main").unwrap(),
            fgit_reference::effect::RefEffect::Set(GitOid::Sha1(GitOidSha1::from_bytes([1; 20]))),
        )]);
        let refs = BTreeMap::new();
        assert!(matches!(
            enforce_installed_snapshot(&policy, &refs, &effects, Some(principal)),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing)),
        ));
        assert!(matches!(
            enforce_installed_snapshot_with_authentication(
                &policy,
                &refs,
                &effects,
                Some(principal),
                Some(AdmissionAuthentication::OperatorAssertion),
            ),
            Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied
            )),
        ));
        for authentication in [
            AdmissionAuthentication::HttpToken,
            AdmissionAuthentication::SshDeployKey,
        ] {
            enforce_installed_snapshot_with_authentication(
                &policy,
                &refs,
                &effects,
                Some(principal),
                Some(authentication),
            )
            .unwrap();
            assert!(matches!(
                enforce_installed_snapshot_with_authentication(
                    &policy,
                    &refs,
                    &effects,
                    None,
                    Some(authentication)
                ),
                Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing)),
            ));
            assert!(matches!(
                enforce_installed_snapshot_with_authentication(
                    &policy,
                    &refs,
                    &effects,
                    Some(PrincipalId::from_bytes([0x99; 16])),
                    Some(authentication)
                ),
                Err(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied
                )),
            ));
        }
        for strength in ["multi_factor", "hardware_backed"] {
            policy.ref_policy = Some(fgit_forge::event::protection::compile_ref_policy(&format!(
                "policy stronger {{ rule credential {{ when actor.authentication >= {strength} then allow }} default deny \"stronger credential required\" }}"
            )).unwrap());
            for authentication in [
                AdmissionAuthentication::HttpToken,
                AdmissionAuthentication::SshDeployKey,
            ] {
                assert!(matches!(
                    enforce_installed_snapshot_with_authentication(
                        &policy,
                        &refs,
                        &effects,
                        Some(principal),
                        Some(authentication)
                    ),
                    Err(ProjectionFailure::Refuse(
                        RefusalCode::ProtectedRefTransitionDenied
                    )),
                ));
            }
        }
    }

    #[test]
    fn absent_authentication_cannot_satisfy_a_negated_predicate() {
        let principal = PrincipalId::from_bytes([0x33; 16]);
        let policy = ReviewProtection {
            administrators: vec![principal],
            branches: Vec::new(),
            ref_policy: Some(fgit_forge::event::protection::compile_ref_policy(
                "policy explicit { rule weak { when not actor.authentication >= single_factor then allow } default deny \"explicit weak identity required\" }"
            ).unwrap()),
        };
        let effects = BTreeMap::from([(
            RefName::try_new(b"refs/heads/main").unwrap(),
            fgit_reference::effect::RefEffect::Set(GitOid::Sha1(GitOidSha1::from_bytes([1; 20]))),
        )]);
        assert!(matches!(
            enforce_installed_snapshot(&policy, &BTreeMap::new(), &effects, Some(principal)),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing)),
        ));
        enforce_installed_snapshot_with_authentication(
            &policy,
            &BTreeMap::new(),
            &effects,
            Some(principal),
            Some(AdmissionAuthentication::OperatorAssertion),
        )
        .unwrap();
    }

    #[test]
    fn installed_actor_policy_requires_actual_principal_and_has_permit_twin() {
        let principal = PrincipalId::from_bytes([0x33; 16]);
        let policy = ReviewProtection {
            administrators: vec![principal],
            branches: Vec::new(),
            ref_policy: Some(fgit_forge::event::protection::compile_ref_policy(
                "policy releases { rule publishers { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"publisher required\" }"
            ).unwrap()),
        };
        let target = RefName::try_new(b"refs/tags/release").unwrap();
        let effects = BTreeMap::from([(
            target,
            fgit_reference::effect::RefEffect::Set(GitOid::Sha1(GitOidSha1::from_bytes([1; 20]))),
        )]);
        let refs = BTreeMap::new();
        enforce_installed_snapshot(&policy, &refs, &effects, Some(principal)).unwrap();
        assert!(matches!(
            enforce_installed_snapshot(
                &policy,
                &refs,
                &effects,
                Some(PrincipalId::from_bytes([0x99; 16]))
            ),
            Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied
            ))
        ));
        assert!(matches!(
            enforce_installed_snapshot(&policy, &refs, &effects, None),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))
        ));

        // In particular, a compatibility path without identity cannot satisfy
        // an administrator's rule allowing the all-zero principal identifier.
        let mut zero = policy;
        zero.ref_policy = Some(fgit_forge::event::protection::compile_ref_policy(
            "policy zero { rule selected { when actor.id == \"00000000000000000000000000000000\" then allow } default deny \"selected principal\" }"
        ).unwrap());
        assert!(matches!(
            enforce_installed_snapshot(&zero, &refs, &effects, None),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))
        ));
        enforce_installed_snapshot(
            &zero,
            &refs,
            &effects,
            Some(PrincipalId::from_bytes([0; 16])),
        )
        .unwrap();
    }

    #[test]
    fn non_utf8_protection_cannot_disappear_into_default_allow() {
        let raw = RefName::try_new(b"refs/heads/non-utf8-\xff").unwrap();
        let ordinary = RefName::try_new(b"refs/heads/main").unwrap();
        for names in [vec![&raw], vec![&ordinary, &raw], vec![&raw, &ordinary]] {
            assert!(matches!(
                compile_direct_branches(names),
                Err(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied
                ))
            ));
        }
    }

    #[test]
    fn representable_protection_retains_identity_and_exact_denials() {
        let names = [
            RefName::try_new(b"refs/heads/main").unwrap(),
            RefName::try_new(b"refs/heads/release\"or\"true").unwrap(),
        ];
        let compiled = compile_direct_branches(&names).unwrap();
        let expected = crate::policy_bridge::compile_protected_branch_rules([
            "refs/heads/main",
            "refs/heads/release\"or\"true",
        ])
        .unwrap();
        assert_eq!(compiled.id(), expected.id());
        let mut source = crate::policy_bridge::InMemoryPolicySnapshots::new();
        let id = source.pin(compiled);
        let old = GitOid::Sha1(GitOidSha1::from_bytes([1; 20]));
        let new = GitOid::Sha1(GitOidSha1::from_bytes([2; 20]));
        for (name, protected) in [
            (names[0].clone(), true),
            (names[1].clone(), true),
            (RefName::try_new(b"refs/heads/topic").unwrap(), false),
        ] {
            for proposed_new in [ProposedNew::Update(new), ProposedNew::Delete] {
                let commands = [RefCommand {
                    name: name.clone(),
                    expected_old: ExpectedOld::Exactly(old),
                    proposed_new,
                    force: false,
                }];
                let verdict = crate::policy_bridge::evaluate_receive_pack_protection(
                    &source,
                    &id,
                    &crate::policy_bridge::SubjectCodeMap::default(),
                    PrincipalId::from_bytes([7; 16]),
                    crate::policy_bridge::default_principal_snapshot_id(),
                    &BTreeMap::from([(name.clone(), old)]),
                    &commands,
                    fgit_policy::PolicyInstant::from_seconds(0),
                )
                .unwrap();
                assert_eq!(
                    verdict.refusal,
                    protected.then_some(RefusalCode::ProtectedRefTransitionDenied)
                );
            }
        }
    }
}
