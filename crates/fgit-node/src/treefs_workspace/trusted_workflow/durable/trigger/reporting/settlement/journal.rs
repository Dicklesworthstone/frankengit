//! Reconcile each full, closed execution receipt with every terminal job in
//! the exact handoff journal. A useful partial proposal stream never suffices.
use super::{
    Budget, GitOid, OneNode, Path, Run, TrustedWorkflowFailure, checkpoint, hex, invalid, metadata,
    root,
};
use fgit_runner::coordinator::delivery::journal::attempt::FileWorkflowAttempt;
use fgit_runner::coordinator::delivery::journal::history::decode_trusted_observation;
use fgit_runner::coordinator::delivery::journal::{CheckJournalPin, CheckJournalScope};
use fgit_runner::coordinator::{
    AttemptId, CheckRunStatus, CoordinatorExecutionProfile, WorkflowRunId,
};
use fgit_runner::workflow::JobOutcome;
use fgit_schema::json::Value;
use fgit_types::{CANONICAL_CODEC_VERSION, RepositoryAuthorityHeadId};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn verify(
    node: &OneNode,
    directory: &Path,
    marker: &Value,
    definition: &metadata::Definition,
    source: &Run,
    commit: GitOid,
    budget: &mut Budget,
    live: &dyn Fn() -> bool,
) -> Result<(), TrustedWorkflowFailure> {
    checkpoint(live)?;
    if source.bytes < 72 || budget.receipts == 0 {
        return Err(invalid("watch settlement journal or receipt bound invalid"));
    }
    budget.journal_bytes = budget
        .journal_bytes
        .checked_sub(source.bytes)
        .ok_or_else(|| invalid("watch settlement aggregate journal bound exceeded"))?;
    let scope = CheckJournalScope {
        tenant: node.tenant_id(),
        repository: node.repository_id(),
        journal_id: root(source.journal)?,
    };
    let pin = CheckJournalPin::new(source.bytes, root(source.tail)?);
    let recorded = FileWorkflowAttempt::read_completed_scoped(
        &directory.join("execution.owner"),
        scope,
        None,
        budget.receipts,
        live,
    )
    .map_err(|error| failure(directory, error))?;
    if recorded.requires_containment() || recorded.journal_pin() != pin {
        return Err(invalid(
            "watch execution is unclosed or has another final journal pin",
        ));
    }
    let completed = decode_trusted_observation(
        recorded.frame(),
        recorded.commitment(),
        budget.receipts,
        live,
    )
    .map_err(|error| failure(directory, error))?;
    budget.receipts = budget
        .receipts
        .checked_sub(recorded.frame().len())
        .ok_or_else(|| invalid("watch settlement receipt bound exceeded"))?;
    let report = completed.report();
    // Use the original native coordinator's identity derivation, including all
    // 128 bits of the dispatch child nonce. Self-consistent copied owner/job
    // receipts cannot stand in for this selected child execution.
    let expected_run = WorkflowRunId::derive(
        &node.tenant_id(),
        &node.repository_id(),
        completed.authority_head(),
        &commit,
        root(definition.graph)?,
        &format!("trusted-local-{}", hex(&source.run)),
        0,
    );
    if completed.tenant() != node.tenant_id()
        || completed.repository() != node.repository_id()
        || completed.source_commit() != commit
        || completed.run_id() != expected_run
        || completed.attempt_id() != AttemptId::derive(expected_run, 1)
        || completed.run_id() != recorded.binding().run_id()
        || completed.attempt_id() != recorded.binding().attempt_id()
        || completed.requires_containment()
        || report
            .jobs
            .iter()
            .any(|job| job.outcome == JobOutcome::Cancelled)
        || hex(report.graph.digest().bytes().as_bytes()) != hex(&definition.graph)
    {
        return Err(invalid(
            "watch completed receipt differs from original closed execution",
        ));
    }
    budget.jobs = budget
        .jobs
        .checked_sub(report.jobs.len())
        .ok_or_else(|| invalid("watch settlement aggregate job bound exceeded"))?;
    let marker = metadata::object(marker)?;
    let head = completed.authority_head().digest();
    let head = RepositoryAuthorityHeadId::from_digest(
        head.algorithm(),
        CANONICAL_CODEC_VERSION,
        *head.bytes(),
    );
    metadata::equal_text(marker, "source_head", &head.to_string())?;
    let plan = metadata::object(
        marker
            .get("execution_plan")
            .ok_or_else(|| invalid("watch original execution plan missing"))?,
    )?;
    metadata::equal_text(plan, "workflow_source", &report.source.to_string())?;
    metadata::equal_text(plan, "workflow_graph", &report.graph.to_string())?;
    for (name, expected) in [
        (
            "step_timeout_millis",
            report.limits.step_timeout.as_millis() as u64,
        ),
        (
            "run_timeout_millis",
            report.limits.run_timeout.as_millis() as u64,
        ),
        ("stream_bytes", report.limits.stream_bytes as u64),
        (
            "total_output_bytes",
            report.limits.total_output_bytes as u64,
        ),
    ] {
        if plan.get(name).and_then(Value::unsigned) != Some(expected) {
            return Err(invalid(
                "watch completed execution limits differ from original marker",
            ));
        }
    }
    let mut journal = OneNode::open_trusted_workflow_journal(directory, scope, Some(pin), live)?;
    if journal.pin() != pin {
        return Err(invalid("watch handoff journal has changed"));
    }
    let jobs = report
        .jobs
        .iter()
        .map(|job| (job.id.as_str(), job))
        .collect::<BTreeMap<_, _>>();
    let mut last = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut after = None;
    loop {
        checkpoint(live)?;
        if budget.metadata == 0 || budget.batches == 0 {
            return Err(invalid("watch settlement history bound exceeded"));
        }
        let page = journal
            .read_history(
                Some(pin),
                after,
                budget.batches.min(64),
                budget.metadata,
                live,
            )
            .map_err(|error| failure(directory, error))?;
        for entry in page.entries() {
            checkpoint(live)?;
            budget.batches = budget
                .batches
                .checked_sub(1)
                .ok_or_else(|| invalid("watch settlement batch bound exceeded"))?;
            let batch = entry.batch();
            budget.metadata = budget
                .metadata
                .checked_sub(
                    batch.body().len() + usize::from(entry.delivery_receipt().is_some()) * 32,
                )
                .ok_or_else(|| invalid("watch settlement history byte bound exceeded"))?;
            if batch.tenant() != completed.tenant()
                || batch.repository() != completed.repository()
                || batch.run_id() != completed.run_id()
                || batch.attempt_id() != completed.attempt_id()
                || batch.authority_head() != completed.authority_head()
                || batch.source_commit() != commit
                || batch.graph_commitment() != report.graph
                || !matches!(batch.execution_profile(), CoordinatorExecutionProfile::TrustedWorkflow { source, limits } if source == report.source && limits == report.limits)
            {
                return Err(invalid("watch journal spans another execution"));
            }
            for (index, fact) in batch.facts().iter().enumerate() {
                checkpoint(live)?;
                let original = jobs
                    .get(fact.job_id.as_str())
                    .ok_or_else(|| invalid("watch journal names an unrecorded job"))?;
                last.insert(fact.job_id.clone(), fact.status);
                if fact.status != CheckRunStatus::Completed {
                    continue;
                }
                if !seen.insert(fact.job_id.clone()) || budget.evidence == 0 {
                    return Err(invalid(
                        "watch job completion duplicated or evidence bound exhausted",
                    ));
                }
                let observed = journal
                    .read_trusted_job(pin, batch.id(), index, budget.evidence, live)
                    .map_err(|error| failure(directory, error))?;
                let job = observed.report();
                if job.jobs.len() != 1
                    || &job.jobs[0] != *original
                    || job.source != report.source
                    || job.graph != report.graph
                    || job.limits != report.limits
                    || observed.requires_containment()
                    || observed.job_attempt(&fact.job_id) != completed.job_attempt(&fact.job_id)
                {
                    return Err(invalid(
                        "watch job evidence differs from the completed execution",
                    ));
                }
                // read_trusted_job checked this body's length before allocation
                // while this exact journal remains locked. Charge its real frame.
                let evidence = journal
                    .read_evidence(
                        fact.receipt_commitment
                            .ok_or_else(|| invalid("watch completed job lacks evidence"))?,
                    )
                    .map_err(|error| failure(directory, error))?;
                budget.evidence = budget
                    .evidence
                    .checked_sub(evidence.len())
                    .ok_or_else(|| invalid("watch aggregate evidence bound exceeded"))?;
            }
        }
        after = page.next_after();
        if after.is_none() {
            break;
        }
    }
    if seen.len() != jobs.len()
        || last.len() != jobs.len()
        || last
            .values()
            .any(|status| *status != CheckRunStatus::Completed)
    {
        return Err(invalid(
            "watch journal does not complete every original job",
        ));
    }
    journal
        .verify_checkpoint(pin)
        .map_err(|error| failure(directory, error))?;
    checkpoint(live)
}

fn failure(path: &Path, error: impl std::fmt::Display) -> TrustedWorkflowFailure {
    TrustedWorkflowFailure::Journal {
        directory: path.to_path_buf(),
        detail: error.to_string(),
    }
}
