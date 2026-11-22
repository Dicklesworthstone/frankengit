//! Independently scoped creation of one task branch, with ordinary protection.

use super::*;
use crate::evidence::AgentAuthentication;
use fgit_reference::effect::{FoldOutcome, RefEffect};
use fgit_reference::intent::{ExpectedRefState, Intent, RefIntent, TransactionRequest};
use fgit_txn::TransactionFoldReport;

/// Authorize exactly one absent branch at an already verified native commit.
/// The host must establish current visible-branch-tip membership at this exact
/// basis and obtain `agent` from a live request-owned authentication boundary.
/// No public receipt or source-publication grant selects this exception.
pub async fn direct_branch_creation_decision_evidence_at<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    current: &crate::CanonicalRefState,
    layout: fgit_types::RootLayoutVersion,
    request: &TransactionRequest,
    fold: &TransactionFoldReport,
    agent: AgentAuthentication,
    reference: &RefName,
    target: GitOid,
    now: u64,
    cancelled: &C,
) -> Result<crate::evidence::DecisionEvidenceBodies, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let denied = || ProjectionFailure::Refuse(RefusalCode::CapabilityScopeViolation);
    live(cancelled).map_err(infrastructure)?;
    if !reference.as_bytes().starts_with(b"refs/heads/")
        || !request.atomic
        || request.intent_count() != 1
        || context.principal_id != agent.agent()
    {
        return Err(denied());
    }
    let Some((
        _,
        Intent::Ref(RefIntent::Update {
            name,
            expected: ExpectedRefState::Absent,
            new,
            force: false,
        }),
    )) = request.addressed_intents().next()
    else {
        return Err(denied());
    };
    let FoldOutcome::Folded(effects) = &fold.outcome else {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
    };
    if name != reference
        || *new != target
        || current.refs().contains_key(reference)
        || !current.refs().iter().any(|(name, oid)| {
            name.as_bytes().starts_with(b"refs/heads/") && *oid == target
        })
        || effects.refs.len() != 1
        || !effects.forge.is_empty()
        || !effects.retention.is_empty()
        || !effects.outbox.is_empty()
        || effects.refs.get(reference) != Some(&RefEffect::Set(target))
    {
        return Err(denied());
    }
    super::super::agent_credentials::validate_branch_creation_at(
        store, cx, context, basis, &agent, now, reference, cancelled,
    )
    .await?;
    direct_decision_evidence_selected_at(
        store,
        cx,
        context,
        basis,
        current,
        layout,
        request,
        fold,
        Some(AdmissionAuthentication::AgentCredential(agent)),
        true,
        cancelled,
    )
    .await
}
