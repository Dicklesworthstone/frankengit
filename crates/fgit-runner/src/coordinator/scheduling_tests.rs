//! State-machine regression tests. These do not claim live process containment.
use super::*;
use fgit_schema::workflow::{Limits, compile};
use fgit_types::GitOidSha1;

const DAG: &str = "name: scheduling\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n  test:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: true\n  ship:\n    runs-on: fgit-trusted-local\n    needs: test\n    steps:\n      - run: true\n  diagnostics:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: failure()\n    steps:\n      - run: true\n";

fn coordinator() -> WorkflowCoordinator {
    WorkflowCoordinator::new(
        CoordinatorLimits::default(),
        ResourceCeilings::new(
            100_000,
            512 * 1024 * 1024,
            1024 * 1024 * 1024,
            0,
            16,
            60_000,
        )
        .unwrap(),
        8,
    )
    .unwrap()
}
fn enqueue(c: &mut WorkflowCoordinator, graph: WorkflowGraph) -> WorkflowRunId {
    c.enqueue_run(
        TenantId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
        Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
        graph,
        TriggerContext::trusted_push("alice"),
        1,
        100,
    )
    .unwrap()
}
fn graph() -> WorkflowGraph {
    compile(DAG, &Limits::default()).unwrap()
}
fn finish(c: &mut WorkflowCoordinator, run: WorkflowRunId, job: &str, outcome: JobOutcome) {
    c.record_terminal_job(run, job, outcome, None, 200);
}
fn job(c: &WorkflowCoordinator, run: WorkflowRunId, name: &str) -> JobStatus {
    c.active_runs[&run].job_statuses[name].clone()
}

#[test]
fn execution_guard_refuses_unready_jobs_without_any_responsibility() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph());
    let before = c.obligations().clone();
    assert!(c.require_ready_job(run, "build").is_ok());
    assert!(matches!(
        c.require_ready_job(run, "test"),
        Err(CoordinatorRefusal::InvalidStateTransition { .. })
    ));
    assert!(matches!(
        c.require_ready_job(run, "missing"),
        Err(CoordinatorRefusal::JobNotFound(_))
    ));
    assert_eq!(before, *c.obligations());
    assert_eq!(c.active_runs[&run].job_attempts["test"], 0);
    assert_eq!(job(&c, run, "test"), JobStatus::Queued);
}

#[test]
fn failed_dependency_closes_skip_chain_but_runs_failure_diagnostics() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph());
    finish(&mut c, run, "build", JobOutcome::Failed);
    assert_eq!(
        job(&c, run, "test"),
        JobStatus::Terminal(JobOutcome::Skipped)
    );
    assert_eq!(
        job(&c, run, "ship"),
        JobStatus::Terminal(JobOutcome::Skipped)
    );
    assert_eq!(c.eligible_jobs(run).unwrap(), vec!["diagnostics"]);
    finish(&mut c, run, "diagnostics", JobOutcome::Succeeded);
    assert_eq!(
        c.active_runs[&run].status,
        RunStatus::Terminal(RunOutcome::Failed {
            failed_jobs: vec!["build".to_owned()]
        })
    );
    let facts = c.drain_check_facts();
    assert_eq!(
        facts
            .iter()
            .filter(|fact| fact.status == CheckRunStatus::Completed)
            .count(),
        4
    );
    assert!(
        facts
            .iter()
            .filter(|fact| fact.conclusion == Some(CheckRunConclusion::Neutral))
            .all(|fact| fact.receipt_commitment.is_none())
    );
    assert!(c.verify_quiescence().is_ok());
}

#[test]
fn successful_dependency_skips_failure_only_job_and_allows_the_chain() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph());
    finish(&mut c, run, "build", JobOutcome::Succeeded);
    assert_eq!(
        job(&c, run, "diagnostics"),
        JobStatus::Terminal(JobOutcome::Skipped)
    );
    assert_eq!(c.eligible_jobs(run).unwrap(), vec!["test"]);
    finish(&mut c, run, "test", JobOutcome::Succeeded);
    assert_eq!(c.eligible_jobs(run).unwrap(), vec!["ship"]);
    finish(&mut c, run, "ship", JobOutcome::Succeeded);
    assert_eq!(
        c.active_runs[&run].status,
        RunStatus::Terminal(RunOutcome::Succeeded)
    );
}

#[test]
fn terminal_job_cannot_run_again_while_another_job_remains_ready() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph());
    finish(&mut c, run, "build", JobOutcome::Succeeded);
    let before = c.outbox_facts.clone();
    assert!(matches!(
        c.require_ready_job(run, "build"),
        Err(CoordinatorRefusal::InvalidStateTransition { .. })
    ));
    finish(&mut c, run, "build", JobOutcome::Failed);
    c.settle_skipped_jobs(run, 300);
    assert_eq!(before, c.outbox_facts);
    assert_eq!(
        job(&c, run, "build"),
        JobStatus::Terminal(JobOutcome::Succeeded)
    );
}

#[test]
fn always_can_follow_ordinary_failure_but_not_lost_containment() {
    for outcome in [
        JobOutcome::Failed,
        JobOutcome::Refused,
        JobOutcome::Cancelled,
    ] {
        let mut c = coordinator();
        let mut g = graph();
        g.jobs
            .iter_mut()
            .find(|j| j.id == "diagnostics")
            .unwrap()
            .condition = Condition::Always;
        let run = enqueue(&mut c, g);
        finish(&mut c, run, "build", outcome);
        if outcome == JobOutcome::Failed {
            assert_eq!(c.eligible_jobs(run).unwrap(), vec!["diagnostics"]);
        } else {
            assert_eq!(
                job(&c, run, "diagnostics"),
                JobStatus::Terminal(JobOutcome::Skipped)
            );
            assert!(c.eligible_jobs(run).unwrap().is_empty());
            assert!(matches!(c.active_runs[&run].status, RunStatus::Terminal(_)));
        }
    }
}

#[test]
fn root_false_condition_settles_at_enqueue_without_a_runner() {
    let mut c = coordinator();
    let mut g = graph();
    g.jobs.truncate(1);
    g.jobs[0].condition = Condition::Failure;
    let run = enqueue(&mut c, g);
    assert!(c.eligible_jobs(run).unwrap().is_empty());
    assert_eq!(
        c.active_runs[&run].status,
        RunStatus::Terminal(RunOutcome::Succeeded)
    );
    assert_eq!(c.obligations.runner_slots_reserved, 0);
    assert_eq!(c.outbox_facts.len(), 2);
    assert_eq!(
        c.outbox_facts[1].conclusion,
        Some(CheckRunConclusion::Neutral)
    );
}

#[test]
fn mutated_graphs_refuse_before_outbox_or_idempotency_state() {
    let original = graph();
    let mut duplicate = original.clone();
    duplicate.jobs.push(duplicate.jobs[0].clone());
    let mut cycle = original.clone();
    cycle.jobs[0].needs.push("ship".to_owned());
    let mut empty = original.clone();
    empty.jobs.clear();
    let mut missing_steps = original.clone();
    missing_steps.jobs[0].steps.clear();
    let mut huge = original.clone();
    huge.jobs[0].steps = vec![huge.jobs[0].steps[0].clone(); MAX_STEPS + 1];
    for g in [duplicate, cycle, empty, missing_steps, huge] {
        let mut c = coordinator();
        let result = c.enqueue_run(
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            Commitment::of_bytes(b"head"),
            GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
            g,
            TriggerContext::trusted_push("alice"),
            1,
            100,
        );
        assert!(matches!(
            result,
            Err(CoordinatorRefusal::WorkflowRefusal(_))
        ));
        assert!(c.active_runs.is_empty());
        assert!(c.idempotency_map.is_empty());
        assert!(c.outbox_facts.is_empty());
        assert_eq!(c.obligations, ObligationSummary::default());
    }
    let mut c = coordinator();
    let run = enqueue(&mut c, graph());
    assert!(c.require_ready_job(run, "build").is_ok());
}

#[test]
fn concurrency_capacity_includes_draining_jobs() {
    let mut c = coordinator();
    c.limits.max_concurrent_jobs = 1;
    let mut g = graph();
    g.jobs
        .iter_mut()
        .find(|j| j.id == "diagnostics")
        .unwrap()
        .needs
        .clear();
    g.jobs
        .iter_mut()
        .find(|j| j.id == "diagnostics")
        .unwrap()
        .condition = Condition::Always;
    let run = enqueue(&mut c, g);
    assert_eq!(c.eligible_jobs(run).unwrap(), vec!["build"]);
    c.active_runs.get_mut(&run).unwrap().job_statuses.insert(
        "build".to_owned(),
        JobStatus::Draining {
            reason: DrainReason::Cancelled(CancellationReason::UserRequested),
        },
    );
    assert!(c.eligible_jobs(run).unwrap().is_empty());
    finish(&mut c, run, "build", JobOutcome::Cancelled);
    assert_eq!(c.eligible_jobs(run).unwrap(), vec!["diagnostics"]);
}

#[test]
fn terminal_outcomes_survive_recovery_and_late_finalization() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph());
    c.cancel_run(run, CancellationReason::UserRequested)
        .unwrap();
    let before = c.active_runs[&run].status.clone();
    c.check_and_finalize_run(run);
    assert!(
        c.recover_from_crash(Commitment::of_bytes(b"new-head"))
            .is_empty()
    );
    assert_eq!(before, c.active_runs[&run].status);
}
