//! Canonical single-head queue selection for actual candidate CI. A fixed
//! queue scope owns every selected PR's custody; neither workflow success nor
//! this selector grants target publication or autonomous merge authority.

use super::{
    NodeRequestContext, NodeWorkspaceRefusal, OneNode, Path, RefName, RepositoryAuthorityHeadId,
    Selected, Selection, TrustedRefWorkflowPoll, TrustedWorkflowArtifactConfig,
    TrustedWorkflowFailure, WorkflowLimits, cancellation, commitment, hex, invalid, invalid_owned,
    pull_request_merge, reporting, workspace_request_live,
};
use fgit_admission::merge::native::queue;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::merge_queue::MergeQueueSnapshot;
use fgit_forge::preparation::MergeCommitStyle;
use fgit_forge::{AggregateVersion, QueueNumber};
use fgit_wire::visibility::RefVisibility;

#[derive(Clone, Debug)]
pub(super) struct QueueSelection {
    pub(super) number: QueueNumber,
    pub(super) version: AggregateVersion,
    pub(super) source: RefName,
}

impl QueueSelection {
    pub(super) fn event_id(
        &self,
        scope: &[u8; 32],
        selected: &Selected,
    ) -> Result<[u8; 32], TrustedWorkflowFailure> {
        let pull = selected
            .pull
            .as_ref()
            .ok_or_else(|| invalid("queue candidate lacks its exact PR"))?;
        // The historical PR event includes its version, source decision and
        // current target. Queue order/membership and policy epoch are additional
        // invalidation coordinates. Unrelated check/comment publications must
        // not create a new execution by changing the repository authority head.
        Ok(commitment(&[
            b"frankengit/merge-queue-head-workflow-event/v1",
            scope,
            &self.number.get().to_be_bytes(),
            &self.version.get().to_be_bytes(),
            self.source.as_bytes(),
            &pull.event_id(scope, selected),
            &pull.policy_epoch.get().to_be_bytes(),
            &selected.commit.algorithm().code_point().to_be_bytes(),
            selected.commit.as_bytes(),
            pull.recorded_source.as_bytes(),
            pull.recorded_target.as_bytes(),
        ]))
    }

    pub(super) fn to_json(&self, selected: &Selected) -> Result<String, TrustedWorkflowFailure> {
        let pull = selected
            .pull
            .as_ref()
            .ok_or_else(|| invalid("queue candidate lacks its exact PR"))?;
        Ok(format!(
            concat!(
                "{{\"number\":\"{}\",\"version\":\"{}\",\"target_ref_hex\":\"{}\",",
                "\"pull_request\":\"{}\",\"pull_request_version\":\"{}\",\"policy_epoch\":\"{}\"}}"
            ),
            self.number.get(),
            self.version.get(),
            hex(pull.target.as_bytes()),
            pull.number,
            pull.version,
            pull.policy_epoch.get(),
        ))
    }

    fn matches(&self, queue: &MergeQueueSnapshot, subject: &ReviewSubject) -> bool {
        queue.queue_number == self.number
            && queue.version == self.version
            && queue.target_ref == subject.target_ref
            && queue.active_batch.is_none()
            && self.source == subject.source_ref
            && queue.entries.first().is_some_and(|entry| {
                entry.pull_request == subject.pull_request
                    && entry.source_ref == subject.source_ref
                    && entry.head_tip == subject.source_tip
            })
    }
}

pub(super) fn validate_selection(
    reference: &RefName,
    pull_number: Option<u64>,
    queue_number: Option<u64>,
    merge: Option<&pull_request_merge::PullRequestMergeWatchConfig>,
) -> Result<(), TrustedWorkflowFailure> {
    if let Some(number) = queue_number {
        if number == 0 || pull_number.is_some() {
            return Err(invalid(
                "queue selection requires a positive number and excludes a PR selector",
            ));
        }
        let merge = merge.ok_or_else(|| {
            invalid("queue watch requires explicit merge candidate configuration")
        })?;
        if merge.style() != MergeCommitStyle::TwoParent || merge.reference() == reference {
            return Err(invalid(
                "queue watch requires a two-parent candidate on a distinct CI branch",
            ));
        }
    }
    Ok(())
}

pub(super) fn scope(node: &OneNode, target: &RefName, directory: &[u8], number: u64) -> [u8; 32] {
    // Never include current queue version, selected PR or configuration here:
    // a changed head must not escape the previous head's unresolved custody.
    commitment(&[
        b"frankengit/merge-queue-workflow-watch/v1",
        &reporting::scope(node, target, directory),
        &number.to_be_bytes(),
    ])
}

impl OneNode {
    /// Select the exact first entry of one canonical idle queue, prepare its
    /// real two-parent commit, publish that candidate to an explicitly owned CI
    /// branch and execute its actual files. The fixed target is a scope ceiling;
    /// reordering the queue changes the selected PR, never the permitted target.
    ///
    /// All scripts retain this explicit trusted-local host privilege profile.
    /// This method neither lands a PR nor grants any queue/protection exemption.
    /// An unresolved earlier head blocks later queue heads until reconciled.
    pub async fn poll_trusted_queue_head_merge_workflows_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
        merge: &pull_request_merge::PullRequestMergeWatchConfig,
    ) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
        self.poll_selected_workflows_in(
            request,
            target,
            directory,
            parent,
            read_prefixes,
            limits,
            artifacts,
            None,
            Some(number),
            Some(merge),
        )
        .await
    }

    pub(super) async fn select_queue_workflow_event(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        number: u64,
    ) -> Result<Selection, TrustedWorkflowFailure> {
        let number =
            QueueNumber::try_new(number).ok_or_else(|| invalid("queue number must be positive"))?;
        let state = match self.materialize_admission_in(request).await {
            Ok(state) => state,
            Err(error) if cancellation::materialization(&error) => {
                return Ok(Selection::StoppedBeforeReservation);
            }
            Err(error) => {
                return Err(TrustedWorkflowFailure::Source(
                    NodeWorkspaceRefusal::Authority(Box::new(error)),
                ));
            }
        };
        let visible = |name: &RefName| !state.snapshot().hidden_refs.hides(name.as_bytes());
        let queue = match queue::read_queue_at(
            &self.authority,
            request.authority(),
            state.basis(),
            number,
            &visible,
            &|| !workspace_request_live(request),
        )
        .await
        {
            Ok(queue) => queue,
            Err(error) if cancellation::admission(&error) => {
                return Ok(Selection::StoppedBeforeReservation);
            }
            Err(error) => return Err(invalid_owned(error.to_string())),
        };
        let Some(queue) = queue.filter(|queue| queue.target_ref == *target) else {
            return Ok(Selection::Absent);
        };
        if queue.active_batch.is_some() {
            return Ok(Selection::Idle("queue_busy"));
        }
        let Some(entry) = queue.entries.first() else {
            return Ok(Selection::Idle("queue_empty"));
        };
        let selected = self
            .select_pull_request_workflow_event(
                request,
                &entry.source_ref,
                entry.pull_request.get(),
            )
            .await?;
        let mut selected = match selected {
            Selection::Ready(selected) => selected,
            Selection::Absent => return Ok(Selection::Idle("queue_head_unavailable")),
            other => return Ok(other),
        };
        if selected.head != state.basis().id() {
            return Ok(Selection::ChangedBeforeReservation);
        }
        let pull = selected
            .pull
            .as_ref()
            .ok_or_else(|| invalid("queue head selection lacks its PR"))?;
        if pull.target != *target
            || selected.commit != entry.head_tip
            || pull.recorded_source != selected.commit
            || pull.recorded_target != pull.target_commit
        {
            return Ok(Selection::Idle("queue_head_stale"));
        }
        selected.queue = Some(QueueSelection {
            number,
            version: queue.version,
            source: entry.source_ref.clone(),
        });
        Ok(Selection::Ready(selected))
    }

    /// Revalidate a prepared queue selection and its full PR subject at one
    /// authority head. Before publication that head must be the original lease;
    /// afterwards the returned head pins dispatch, so intervening queue, PR,
    /// ref or policy publications cannot select a different execution.
    pub(super) async fn validate_queue_workflow_candidate_in(
        &self,
        request: &NodeRequestContext,
        selected: &QueueSelection,
        subject: &ReviewSubject,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<RepositoryAuthorityHeadId, TrustedWorkflowFailure> {
        let current = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| {
                TrustedWorkflowFailure::Source(NodeWorkspaceRefusal::Authority(Box::new(error)))
            })?;
        if expected_head.is_some_and(|head| head != current.basis().id()) {
            return Err(TrustedWorkflowFailure::Source(
                NodeWorkspaceRefusal::StaleWorkspaceBase,
            ));
        }
        let visible = |name: &RefName| !current.snapshot().hidden_refs.hides(name.as_bytes());
        let queue = queue::read_queue_at(
            &self.authority,
            request.authority(),
            current.basis(),
            selected.number,
            &visible,
            &|| !workspace_request_live(request),
        )
        .await
        .map_err(|error| invalid_owned(error.to_string()))?;
        if queue
            .as_ref()
            .is_none_or(|queue| !selected.matches(queue, subject))
        {
            return Err(TrustedWorkflowFailure::Source(
                NodeWorkspaceRefusal::StaleWorkspaceBase,
            ));
        }
        let head = self
            .validate_pull_request_preparation_in(request, subject, &RefVisibility::new())
            .await
            .map_err(TrustedWorkflowFailure::Source)?;
        if head != current.basis().id() {
            return Err(TrustedWorkflowFailure::Source(
                NodeWorkspaceRefusal::StaleWorkspaceBase,
            ));
        }
        Ok(head)
    }
}

#[cfg(test)]
mod tests;
