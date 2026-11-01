//! Independently mandatory exact-candidate and ordinary branch checks. One
//! reverse canonical scan applies latest-result semantics to both profiles.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::protection::{RequiredCandidateWorkflowCheck, RequiredWorkflowCheck};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::{AggregateId, ExpectedVersion};
use fgit_types::{GitOid, RefName, RefusalCode};

use super::{NativeMergeIntent, checks, infrastructure, live};
use crate::ProjectionFailure;

mod matching;

fn denied() -> ProjectionFailure {
    ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied)
}

pub(super) async fn verify_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    intent: &NativeMergeIntent,
    ordinary: &[RequiredWorkflowCheck],
    required: &[RequiredCandidateWorkflowCheck],
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    live(cancelled).map_err(infrastructure)?;
    let merge = intent.merge().map_err(infrastructure)?;
    if required.is_empty() {
        return checks::verify_at(
            store,
            cx,
            basis,
            refs,
            merge.merge_commit,
            ordinary,
            cancelled,
        )
        .await;
    }
    // A new PR stream or an arbitrary ref write cannot supply an existing,
    // independently validated PR subject for candidate-bound protection.
    let AggregateId::PullRequest(number) = intent.event().aggregate else {
        return Err(denied());
    };
    let ExpectedVersion::Exactly(version) = intent.expected_version() else {
        return Err(denied());
    };
    let subject = ReviewSubject {
        pull_request: number,
        pull_request_version: version,
        source_ref: merge.source_ref.clone(),
        target_ref: merge.target_ref.clone(),
        source_tip: merge.source_tip,
        target_tip: merge.target_tip_before,
        policy_epoch: basis.body().policy_epoch,
    };
    let candidate = CandidateBinding {
        merge_base: merge.base_tip,
        commit: merge.merge_commit,
    };
    candidate.validate(&subject).map_err(|_| denied())?;
    if ordinary
        .iter()
        .any(|check| refs.get(&check.source_ref) != Some(&candidate.commit))
    {
        return Err(denied());
    }
    let mut matching = matching::ExactChecks::new(subject, candidate, ordinary, required);
    checks::verify_observations_at(
        store,
        cx,
        basis,
        |payload| matching.observe(payload).map_err(ProjectionFailure::Refuse),
        cancelled,
    )
    .await
}
