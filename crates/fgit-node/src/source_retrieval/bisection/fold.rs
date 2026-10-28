//! Fold one queried native state; never create a mutable product database.
use super::{
    BisectionRange, DecisionSequence, Error, GitOid, IssueState, MAX_EVENTS, PolicyEpoch,
    Predicate, PullState, Query, RepositoryAuthorityHeadBody, RepositoryAuthorityHeadId,
};
use fgit_forge::aggregate::{AggregateId, AggregateVersion};
use fgit_forge::bisection::PredicateOutcome;
use fgit_forge::event::{ForgeEvent, ForgeEventPayload};
use fgit_forge::event::{issue, pull_request};
use fgit_forge::snapshot::HistoricalBatch;

pub(super) struct Point {
    pub sequence: DecisionSequence,
    pub head: RepositoryAuthorityHeadId,
    pub epoch: PolicyEpoch,
    pub replayed: usize,
    reference: Option<GitOid>,
    issue: Option<IssueState>,
    pull: Option<PullState>,
}
impl Point {
    pub fn evaluate(&self, predicate: &Predicate) -> PredicateOutcome {
        let yes = match predicate {
            Predicate::RefEquals { target, .. } => self.reference == Some(*target),
            Predicate::RefAbsent { .. } => self.reference.is_none(),
            Predicate::PolicyAtLeast(epoch) => self.epoch >= *epoch,
            Predicate::IssueState { state, .. } => self.issue == Some(*state),
            Predicate::PullRequestState { state, .. } => self.pull == Some(*state),
        };
        if yes {
            PredicateOutcome::Satisfied
        } else {
            PredicateOutcome::Unsatisfied
        }
    }
}

pub(super) fn points(
    history: &[HistoricalBatch],
    head: &RepositoryAuthorityHeadBody,
    query: &Query,
    range: BisectionRange,
    mut reference: Option<GitOid>,
    check: &mut impl FnMut() -> Result<(), Error>,
) -> Result<(Vec<Point>, usize), Error> {
    let mut result = Vec::new();
    let mut previous_end: Option<DecisionSequence> = None;
    let mut previous_epoch: Option<PolicyEpoch> = None;
    let mut events = 0usize;
    let mut issue: Option<issue::IssueSnapshot> = None;
    let mut pull: Option<ForgeEvent> = None;
    let mut pull_state = None;
    for (index, historical) in history.iter().enumerate() {
        check()?;
        let batch = &historical.batch;
        let last = batch
            .decisions
            .last()
            .ok_or_else(|| Error::new("corrupt_history", "empty decision batch"))?
            .decision_sequence;
        let expected = previous_end.map_or(Some(1), |end| end.get().checked_add(1));
        if batch.repository_id != head.repository_id
            || expected != Some(batch.first_decision_sequence.get())
            || last < batch.first_decision_sequence
        {
            return Err(Error::new(
                "corrupt_history",
                "history has a gap, overlap or foreign repository",
            ));
        }
        if previous_epoch.is_some_and(|epoch| epoch > batch.resulting_policy_epoch) {
            return Err(Error::new(
                "corrupt_history",
                "historical policy epoch regresses",
            ));
        }
        previous_epoch = Some(batch.resulting_policy_epoch);
        previous_end = Some(last);
        events = events
            .checked_add(historical.forge_events.len())
            .filter(|count| *count <= MAX_EVENTS)
            .ok_or_else(|| Error::new("history_limit", "more than 65536 historical events"))?;
        if let Predicate::RefEquals { name, .. } | Predicate::RefAbsent { name } = &query.predicate
        {
            for (changed, next) in &historical.ref_updates {
                check()?;
                if changed.as_slice() == name.as_bytes() {
                    reference = *next;
                }
            }
        }
        for event in &historical.forge_events {
            check()?;
            match &query.predicate {
                Predicate::IssueState { number, .. }
                    if event.aggregate == AggregateId::Issue(*number) =>
                {
                    issue = Some(issue::apply_event(issue.as_ref(), event).map_err(|error| {
                        Error::new("unsupported_or_corrupt_issue_history", format!("{error:?}"))
                    })?);
                }
                Predicate::PullRequestState { number, .. }
                    if event.aggregate == AggregateId::PullRequest(*number) =>
                {
                    pull_state = Some(match &event.payload {
                        ForgeEventPayload::PullRequestChangedNative(change) => {
                            pull_request::validate_transition(pull.as_ref(), event).map_err(
                                |error| {
                                    Error::new(
                                        "unsupported_or_corrupt_pull_history",
                                        format!("{error:?}"),
                                    )
                                },
                            )?;
                            if change.action == pull_request::PullRequestAction::Close {
                                PullState::Closed
                            } else {
                                PullState::Open
                            }
                        }
                        ForgeEventPayload::MergeCommittedNative(merge) => {
                            merge
                                .validate()
                                .map_err(|error| Error::new("corrupt_pull_history", error))?;
                            match pull.as_ref() {
                                None if event.version == AggregateVersion::FIRST => {}
                                Some(previous)
                                    if previous
                                        .version
                                        .is_immediate_predecessor_of(event.version) =>
                                {
                                    if !matches!(&previous.payload, ForgeEventPayload::PullRequestChangedNative(change) if change.action != pull_request::PullRequestAction::Close && change.data.matches_merge(merge))
                                    {
                                        return Err(Error::new(
                                            "corrupt_pull_history",
                                            "merge does not match its native predecessor",
                                        ));
                                    }
                                }
                                _ => {
                                    return Err(Error::new(
                                        "corrupt_pull_history",
                                        "merge version has no exact predecessor",
                                    ));
                                }
                            }
                            PullState::Merged
                        }
                        _ => {
                            return Err(Error::new(
                                "unsupported_pull_history",
                                "legacy or unsupported PR state is not a native false result",
                            ));
                        }
                    });
                    pull = Some(event.clone());
                }
                _ => {}
            }
        }
        if last >= range.start() && last <= range.end() {
            result.push(Point {
                sequence: last,
                head: historical.resulting_head_id,
                epoch: batch.resulting_policy_epoch,
                replayed: index + 1,
                reference,
                issue: issue.as_ref().map(|state| state.state),
                pull: pull_state,
            });
        }
    }
    if previous_end != head.latest_decision_sequence || previous_epoch != Some(head.policy_epoch) {
        return Err(Error::new(
            "snapshot_changed",
            "loaded history does not reach the exact observed decision and policy epoch",
        ));
    }
    check()?;
    Ok((result, events))
}
