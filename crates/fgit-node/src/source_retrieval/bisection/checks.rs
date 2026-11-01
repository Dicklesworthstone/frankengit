//! Fold immutable workflow observations in canonical publication order. The
//! aggregate identity is per publisher/run/attempt/job, while the query selects
//! a ref/commit/publisher/graph/job across those executions.
use super::{Error, Predicate};
use fgit_forge::aggregate::{AggregateId, AggregateVersion};
use fgit_forge::event::workflow_check::{
    NativeWorkflowCheck, WorkflowCheckConclusion, WorkflowCheckId,
};
use fgit_forge::event::{ForgeEvent, ForgeEventPayload};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct WorkflowChecks<'history> {
    // Keep references into the already bounded history; evidence is not cloned.
    observed: BTreeMap<WorkflowCheckId, &'history NativeWorkflowCheck>,
    latest: Option<WorkflowCheckConclusion>,
}

impl<'history> WorkflowChecks<'history> {
    pub(super) fn observe(
        &mut self,
        predicate: &Predicate,
        event: &'history ForgeEvent,
    ) -> Result<(), Error> {
        let Predicate::WorkflowCheck {
            source_ref,
            source_commit,
            publisher,
            graph_root,
            job,
            ..
        } = predicate
        else {
            return Ok(());
        };
        let observation = match (&event.aggregate, &event.payload) {
            (
                AggregateId::WorkflowCheck(_),
                ForgeEventPayload::WorkflowCheckObservedNative(observation),
            ) => observation,
            (AggregateId::WorkflowCheck(_), _)
            | (_, ForgeEventPayload::WorkflowCheckObservedNative(_)) => {
                return Err(corrupt("workflow-check aggregate and payload disagree"));
            }
            _ => return Ok(()),
        };
        observation.record.validate().map_err(corrupt)?;
        let id = observation.id();
        if event.version != AggregateVersion::FIRST
            || event.aggregate != AggregateId::WorkflowCheck(id)
            || observation.record.source_commit.algorithm() != source_commit.algorithm()
        {
            return Err(corrupt(
                "workflow check has an invalid immutable identity, version or native hash domain",
            ));
        }
        // Validate before selector filtering: reusing an immutable identity for
        // another subject or evidence must not disappear as an unrelated check.
        if self
            .observed
            .get(&id)
            .is_some_and(|previous| *previous != observation)
        {
            return Err(corrupt(
                "one immutable workflow-check identity has conflicting observations",
            ));
        }
        self.observed.entry(id).or_insert(observation);
        let record = &observation.record;
        if record.source_ref == *source_ref
            && record.source_commit == *source_commit
            && observation.actor == *publisher
            && record.graph_root == *graph_root
            && record.job == *job
        {
            // Even an identical repeated observation occupies its literal place
            // in publication order, matching the required-check protection gate.
            self.latest = Some(record.conclusion);
        }
        Ok(())
    }

    pub(super) const fn latest(&self) -> Option<WorkflowCheckConclusion> {
        self.latest
    }
}

fn corrupt(detail: impl std::fmt::Display) -> Error {
    Error::new("corrupt_workflow_check_history", detail)
}
