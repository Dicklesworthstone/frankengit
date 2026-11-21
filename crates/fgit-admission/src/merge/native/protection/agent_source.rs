//! The sole sponsored-agent exception to the direct publication gate.
//! It authorizes one exact native single-parent update at the deciding basis;
//! ordinary receive, branch, review and merge entrypoints retain their gates.

use super::*;
use crate::evidence::AgentAuthentication;
use fgit_reference::effect::{FoldOutcome, RefEffect};
use fgit_reference::intent::{ExpectedRefState, Intent, RefIntent, TransactionRequest};
use fgit_txn::TransactionFoldReport;

/// Check a source publication's current scoped credential, immutable native
/// tree delta and exact sealed ref operation before evaluating ordinary policy.
/// The host must obtain `agent` from a request-owned authentication boundary;
/// provenance supplied by a client is never authentication.
pub async fn direct_source_decision_evidence_at<S, C>(
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
    paths: &path_reviews::VerifiedSourcePaths,
    now: u64,
    cancelled: &C,
) -> Result<crate::evidence::DecisionEvidenceBodies, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let denied = || ProjectionFailure::Refuse(RefusalCode::CapabilityScopeViolation);
    live(cancelled).map_err(infrastructure)?;
    // This capability publishes one existing source branch. A wider grant
    // selector cannot turn it into a tag, branch-creation or deletion API.
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
            expected: ExpectedRefState::Exact(before),
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
        || *before != paths.before()
        || *new != paths.after()
        || current.refs().get(reference) != Some(before)
        || effects.refs.len() != 1
        || !effects.forge.is_empty()
        || !effects.retention.is_empty()
        || !effects.outbox.is_empty()
        || effects.refs.get(reference) != Some(&RefEffect::Set(*new))
    {
        return Err(denied());
    }
    let scope = super::super::agent_credentials::validate_source_at(
        store, cx, context, basis, &agent, now, reference, cancelled,
    )
    .await?;
    for path in paths.changed_paths() {
        live(cancelled).map_err(infrastructure)?;
        if !scope.permits_path(path) {
            return Err(denied());
        }
    }
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
