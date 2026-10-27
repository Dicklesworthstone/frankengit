//! Canonical same-repository PR-head selection. This is not a synthetic merge.
use super::*;
use fgit_forge::event::{ForgeEventPayload, pull_request::PullRequestAction};
use fgit_wire::visibility::RefVisibility;

#[derive(Debug)]
pub(super) struct PullSelection {
    number: u64,
    version: u64,
    target: RefName,
    target_commit: GitOid,
    recorded_source: GitOid,
    recorded_target: GitOid,
}
impl PullSelection {
    pub(super) fn path_comparison_base(&self) -> GitOid {
        self.target_commit
    }

    pub(super) fn target_reference(&self) -> &RefName {
        &self.target
    }

    pub(super) fn event_id(&self, scope: &[u8; 32], source: &Selected) -> [u8; 32] {
        let batch = source.batch.as_internal_object_id();
        commitment(&[
            b"frankengit/pull-request-workflow-event/v1",
            scope,
            &self.number.to_be_bytes(),
            &self.version.to_be_bytes(),
            &batch.algorithm().code_point().to_be_bytes(),
            batch.digest().as_bytes(),
            self.target.as_bytes(),
            self.target_commit.as_bytes(),
        ])
    }
    pub(super) fn to_json(&self) -> String {
        format!(
            "{{\"number\":\"{}\",\"version\":\"{}\",\"target_ref_hex\":\"{}\",\"observed_target_commit\":\"{}\",\"recorded_source_commit\":\"{}\",\"recorded_target_commit\":\"{}\",\"execution_profile\":\"source-head-only\",\"synthetic_merge\":false}}",
            self.number,
            self.version,
            hex(self.target.as_bytes()),
            self.target_commit,
            self.recorded_source,
            self.recorded_target
        )
    }
}

pub(super) fn scope(
    node: &OneNode,
    reference: &RefName,
    directory: &[u8],
    number: u64,
) -> [u8; 32] {
    commitment(&[
        b"frankengit/pull-request-workflow-watch/v1",
        &reporting::scope(node, reference, directory),
        &number.to_be_bytes(),
    ])
}

impl OneNode {
    /// Observe an actual open native PR and execute its CURRENT source-head
    /// definitions declaring `pull_request`. The explicit source branch must
    /// match its canonical metadata; neither an arbitrary event string nor a
    /// stale recorded tip can select execution. Source and target visibility,
    /// PR version and live branch tips are selected at one authenticated head.
    ///
    /// This is trusted local, same-repository, latest-state execution: not
    /// GitHub's synthetic-merge profile, a fork sandbox, an all-events queue or
    /// merge approval. Every selected script keeps host-user privileges.
    /// Close/merge/absence suppress new execution, not original result recovery.
    /// Metadata updates/reopen, new source decisions and observed target tips
    /// create distinct events; unrelated comments/checks do not. The existing
    /// custody owner, interruption fence, artifacts and publisher are reused.
    pub async fn poll_trusted_pull_request_workflows_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
        self.poll_selected_workflows_in(
            request,
            reference,
            directory,
            parent,
            read_prefixes,
            limits,
            artifacts,
            Some(number),
        )
        .await
    }

    pub(super) async fn select_pull_request_workflow_event(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        number: u64,
    ) -> Result<Selection, TrustedWorkflowFailure> {
        let after = number
            .checked_sub(1)
            .ok_or_else(|| invalid("pull-request number must be positive"))?;
        let page = match self
            .read_pull_requests_in(request, &RefVisibility::new(), after, 1, None)
            .await
        {
            Ok(page) => page,
            Err(error) if cancellation::pull_request_read(&error) => {
                return Ok(Selection::StoppedBeforeReservation);
            }
            Err(error) => return Err(invalid_owned(error.to_string())),
        };
        let Some(view) = page
            .pull_requests
            .into_iter()
            .find(|p| p.number.get() == number)
        else {
            return Ok(Selection::Absent);
        };
        let version = view.event.version.get();
        let ForgeEventPayload::PullRequestChangedNative(event) = view.event.payload else {
            return Ok(Selection::Absent);
        };
        if event.action == PullRequestAction::Close || event.data.source_ref != *reference {
            return Ok(Selection::Absent);
        }
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
        if state.basis().id() != page.source_head {
            return Ok(Selection::ChangedBeforeReservation);
        }
        if [reference, &event.data.target_ref]
            .iter()
            .any(|r| state.snapshot().hidden_refs.hides(r.as_bytes()))
        {
            return Ok(Selection::Absent);
        }
        let Some(target_commit) = state.snapshot().refs.get(&event.data.target_ref).copied() else {
            return Ok(Selection::Absent);
        };
        let selected = self.select_ref_workflow_event(request, reference).await?;
        let Selection::Ready(mut selected) = selected else {
            return Ok(selected);
        };
        if selected.head != page.source_head {
            return Ok(Selection::ChangedBeforeReservation);
        }
        selected.pull = Some(PullSelection {
            number,
            version,
            target: event.data.target_ref,
            target_commit,
            recorded_source: event.data.source_tip,
            recorded_target: event.data.target_tip,
        });
        Ok(Selection::Ready(selected))
    }
}
