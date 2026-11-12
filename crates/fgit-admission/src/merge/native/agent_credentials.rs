//! Canonical sponsored-credential registry. Credential state is selected only
//! by the authenticated forge frontier; an immutable grant body is not active
//! merely because it exists. Revocation retains the complete original grant.

use super::{
    NativeMergeProjection, PreparationFailure, metadata, protection, storage, unavailable,
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
use fgit_forge::event::agent_credential::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, AgentCredentialId,
};
use fgit_forge::{
    AggregateId, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload,
};
use fgit_types::{AsciiSlug, Digest, RefusalCode, RepositoryAuthorityHeadId};
use std::collections::BTreeSet;

pub const MAX_CREDENTIALS: usize = 256;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentCredentialState {
    pub source_head: RepositoryAuthorityHeadId,
    pub id: AgentCredentialId,
    pub version: AggregateVersion,
    pub grant: AgentCredentialGrant,
    pub grant_root: Digest,
    pub revoked: bool,
}

fn live(cancelled: &(impl Fn() -> bool + Sync)) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}

/// Identity of the original issuance, independent of revocation or the current
/// authority head. The issuer must be the named sponsor.
pub fn grant_root(
    id: AgentCredentialId,
    grant: &AgentCredentialGrant,
) -> Result<Digest, AdmissionError> {
    let command = AgentCredentialCommand {
        id,
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::Issue(*grant),
    };
    let event = command.proposed_event(grant.sponsor).map_err(unavailable)?;
    storage::root(&ForgeEventBatch::of_one(event))
}

/// Read all retained identity declarations, including revoked agents. A revoked
/// agent can never become a human sponsor by disappearing from an active map.
pub async fn read_all_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    cancelled: &C,
) -> Result<Vec<AgentCredentialState>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    live(cancelled)?;
    let positions = storage::load_forge_positions(store, cx, basis).await?;
    let mut states = Vec::new();
    let mut bytes = 0usize;
    for entry in positions.entries() {
        live(cancelled)?;
        if !entry.stream().as_str().starts_with("agent/") {
            continue;
        }
        if states.len() == MAX_CREDENTIALS {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        let id = AgentCredentialId::from_aggregate_label(entry.stream().as_str())
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let aggregate = AggregateId::AgentCredential(id);
        if storage::aggregate_label(aggregate)? != entry.stream() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        let (batch, size) = storage::read_events_with_size(
            store,
            cx,
            basis.body().repository_id,
            entry.event_batch_root(),
        )
        .await?;
        bytes = bytes
            .checked_add(size)
            .filter(|n| *n <= MAX_REGISTRY_BYTES)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        let event = batch
            .events
            .iter()
            .rev()
            .find(|event| event.aggregate == aggregate)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if event.version.get() != entry.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        let ForgeEventPayload::AgentCredentialChangedNative(change) = &event.payload else {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        };
        let (grant, revoked) = match &change.action {
            AgentCredentialAction::Issue(grant) if event.version == AggregateVersion::FIRST => {
                (grant, false)
            }
            AgentCredentialAction::Revoke(grant) if event.version.get() == 2 => (grant, true),
            _ => return Err(unavailable(RefusalCode::EvidenceInvalid)),
        };
        if (!revoked && change.actor != grant.sponsor)
            || grant.repository != basis.body().repository_id
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        grant
            .validate()
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        states.push(AgentCredentialState {
            source_head: basis.id(),
            id,
            version: event.version,
            grant: *grant,
            grant_root: grant_root(id, grant)?,
            revoked,
        });
    }
    live(cancelled)?;
    Ok(states)
}

pub async fn read_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    id: AgentCredentialId,
    cancelled: &C,
) -> Result<Option<AgentCredentialState>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    Ok(read_all_at(store, cx, basis, cancelled)
        .await?
        .into_iter()
        .find(|state| state.id == id))
}

pub fn proposal(
    context: &AdmissionContext,
    command: &AgentCredentialCommand,
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
            AsciiSlug::from_static("agent-credential.event-batch-root.v1"),
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

pub(in crate::merge) fn verify_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    let (AggregateId::AgentCredential(id), ForgeEventPayload::AgentCredentialChangedNative(change)) =
        (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let expected_version = match event.version.get() {
        1 => ExpectedVersion::NewStream,
        2 => ExpectedVersion::Exactly(AggregateVersion::FIRST),
        _ => return Err(RefusalCode::EvidenceInvalid),
    };
    let command = AgentCredentialCommand {
        id,
        expected_version,
        action: change.action.clone(),
    };
    let (expected, seal) = proposal(context, &command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected != *event || seal != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &AgentCredentialCommand,
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
        &Validation {
            tenant: context.tenant_id,
        },
    )
    .await
}

struct Validation {
    tenant: fgit_types::TenantId,
}

/// Recheck the immutable credential against the exact candidate publication
/// basis. A concurrent revocation forces a CAS replan and a refusal here; an
/// already decided retry is recovered before this check by the shared driver.
pub(super) async fn validate_metadata_at<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    event: &ForgeEvent,
    projection: &P,
) -> Result<(), PreparationFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    use fgit_forge::event::agent_credential::{
        DISCUSSIONS_WRITE, ISSUES_WRITE, MILESTONES_WRITE, PULLS_WRITE,
    };
    let denied = || ProjectionFailure::Refuse(RefusalCode::CapabilityScopeViolation);
    let authentication = projection.admission_authentication();
    let Some(agent) = authentication
        .as_ref()
        .and_then(|value| value.agent_provenance())
    else {
        if read_all_at(store, cx, basis, &|| {
            projection.merge_checkpoint(cx).is_err()
        })
        .await?
        .iter()
        .any(|state| state.grant.agent == context.principal_id)
        {
            return Err(denied().into());
        }
        return Ok(());
    };
    let operation = match &event.payload {
        ForgeEventPayload::IssueChangedNative(_) => ISSUES_WRITE,
        ForgeEventPayload::MilestoneChangedNative(_) => MILESTONES_WRITE,
        ForgeEventPayload::PullRequestChangedNative(_)
        | ForgeEventPayload::PullRequestCommentedNative(_) => PULLS_WRITE,
        ForgeEventPayload::DiscussionChangedNative(_) => DISCUSSIONS_WRITE,
        _ => return Err(denied().into()),
    };
    let now = projection.agent_credential_now().ok_or_else(denied)?;
    if now < agent.authenticated_at() || now >= agent.expires_at() {
        return Err(ProjectionFailure::Refuse(RefusalCode::CapabilityExpired).into());
    }
    let state = read_at(store, cx, basis, agent.credential_id(), &|| {
        projection.merge_checkpoint(cx).is_err()
    })
    .await?
    .ok_or_else(denied)?;
    let config = fgit_authority::read_repository_incarnation_configuration_async(
        store,
        cx,
        &basis.body().configuration_root,
    )
    .await
    .map_err(AdmissionError::from)?;
    if state.revoked
        || state.grant_root != agent.grant_root()
        || state.grant.agent != context.principal_id
        || state.grant.agent != agent.agent()
        || state.grant.sponsor != agent.sponsor()
        || state.grant.sponsor_kind != agent.sponsor_kind()
        || state.grant.tenant != context.tenant_id
        || state.grant.repository != context.repository_id
        || state.grant.incarnation != config.repository_incarnation_id
        || agent.authenticated_at() < state.grant.issued_at
        || agent.expires_at() > state.grant.expires_at
        || !state.grant.permits(operation)
    {
        return Err(denied().into());
    }
    Ok(())
}

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
        let refuse = |code| ProjectionFailure::Refuse(code);
        let (
            AggregateId::AgentCredential(id),
            ForgeEventPayload::AgentCredentialChangedNative(change),
        ) = (event.aggregate, &event.payload)
        else {
            return Err(refuse(RefusalCode::EvidenceInvalid).into());
        };
        // Only an explicit trusted-local operator command may administer this
        // bounded registry. An agent cannot grant authority to itself or peers.
        if !matches!(
            projection.admission_authentication(),
            Some(crate::evidence::AdmissionAuthentication::OperatorAssertion)
        ) {
            return Err(refuse(RefusalCode::ProtectedRefTransitionDenied).into());
        }
        let grant = match &change.action {
            AgentCredentialAction::Issue(grant) | AgentCredentialAction::Revoke(grant) => grant,
        };
        let config = fgit_authority::read_repository_incarnation_configuration_async(
            store,
            cx,
            &basis.body().configuration_root,
        )
        .await
        .map_err(AdmissionError::from)?;
        if grant.tenant != self.tenant
            || grant.repository != basis.body().repository_id
            || grant.incarnation != config.repository_incarnation_id
            || (matches!(change.action, AgentCredentialAction::Issue(_))
                && change.actor != grant.sponsor)
        {
            return Err(refuse(RefusalCode::ProtectedRefTransitionDenied).into());
        }
        let cancelled = || projection.merge_checkpoint(cx).is_err();
        let protection = protection::read_at(store, cx, basis, &cancelled).await?;
        if protection
            .protection()
            .is_some_and(|policy| !policy.administrators.contains(&change.actor))
        {
            return Err(refuse(RefusalCode::ProtectedRefTransitionDenied).into());
        }
        let states = read_all_at(store, cx, basis, &cancelled).await?;
        let current = states.iter().find(|state| state.id == id);
        match &change.action {
            AgentCredentialAction::Issue(_) => {
                if current.is_some() {
                    return Err(refuse(RefusalCode::EvidenceStale).into());
                }
                if states.len() == MAX_CREDENTIALS {
                    return Err(refuse(RefusalCode::ResourceBudgetExceeded).into());
                }
                if states.iter().any(|state| {
                    state.grant.agent == grant.sponsor
                        || state.grant.sponsor == grant.agent
                        || (state.grant.agent == grant.agent
                            && (state.grant.sponsor != grant.sponsor
                                || state.grant.sponsor_kind != grant.sponsor_kind))
                        || (state.grant.sponsor == grant.sponsor
                            && state.grant.sponsor_kind != grant.sponsor_kind)
                }) {
                    return Err(refuse(RefusalCode::ProtectedRefTransitionDenied).into());
                }
            }
            AgentCredentialAction::Revoke(_) => {
                if current.is_none_or(|state| {
                    state.revoked
                        || state.grant != *grant
                        || state.version != AggregateVersion::FIRST
                }) {
                    return Err(refuse(RefusalCode::EvidenceStale).into());
                }
            }
        }
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let closure = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: crate::permitted_object_closure_root(&closure)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: BTreeSet::new(),
        })
    }
}
