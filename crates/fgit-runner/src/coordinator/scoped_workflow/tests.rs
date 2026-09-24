//! Coordinator/worker fixtures. Only the separately named Linux test launches
//! real trusted shells; none of these fixtures claims hostile-code isolation.
use super::*;
use crate::workflow::StepOutcome;
use crate::{ConcurrencyGroup, CoordinatorLimits, ResourceCeilings, RunOutcome, RunnerText};
use fgit_types::GitOidSha1;
use std::cell::Cell;
use std::collections::VecDeque;

const MULTI: &str = "name: multi\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first > marker\n      - run: cat marker\n  test:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: echo test\n      - run: echo done\n";
const CONDITIONS: &str = "name: conditions\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: fail\n      - run: skipped-success\n      - if: failure()\n        run: diagnose\n      - if: always()\n        run: cleanup\n  dependent:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: should-not-run\n  independent:\n    runs-on: fgit-trusted-local\n    if: always()\n    steps:\n      - run: independent\n";

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
        4,
    )
    .unwrap()
}
fn enqueue(
    c: &mut WorkflowCoordinator,
    source: &str,
    sequence: u64,
    limits: WorkflowLimits,
    trigger: TriggerContext,
) -> PreparedTrustedWorkflow {
    c.enqueue_trusted_workflow(
        TenantId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
        Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
        WorkflowPlan::compile(source).unwrap(),
        limits,
        trigger,
        sequence,
        100,
    )
    .unwrap()
}
fn observed(outcome: StepOutcome) -> StepObservation {
    StepObservation {
        outcome,
        exit_code: Some(if outcome == StepOutcome::Succeeded {
            0
        } else {
            1
        }),
        stdout: b"data".to_vec(),
        stderr: b"x".to_vec(),
        elapsed_millis: 1,
        output_complete: true,
        retain_workspace: false,
    }
}
struct Worker<'a> {
    events: Vec<String>,
    budgets: Vec<StepLimits>,
    outcomes: VecDeque<StepOutcome>,
    live: Option<&'a Cell<bool>>,
    panic_step: bool,
    refuse_begin_once: bool,
    retain_scope: bool,
}
impl Worker<'_> {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            budgets: Vec::new(),
            outcomes: VecDeque::new(),
            live: None,
            panic_step: false,
            refuse_begin_once: false,
            retain_scope: false,
        }
    }
}
impl WorkflowExecutor for Worker<'_> {
    fn begin_job(
        &mut self,
        _: usize,
        job: &fgit_schema::workflow::Job,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.events.push(format!("begin:{}", job.id));
        if std::mem::take(&mut self.refuse_begin_once) {
            Err(WorkerFailure::new("clean pre-launch refusal", false))
        } else {
            Ok(())
        }
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        limits: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.events.push(format!("step:{script}"));
        self.budgets.push(limits);
        assert!(!self.panic_step, "injected executor panic");
        let mut observation = observed(self.outcomes.pop_front().unwrap_or(StepOutcome::Succeeded));
        if self.retain_scope {
            observation.retain_workspace = true;
            observation.stdout = vec![b'x'; 32];
        }
        Ok(observation)
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.events.push(format!("close:{retain}"));
        if let Some(live) = self.live {
            live.set(false);
        }
        Ok(())
    }
    fn observe_job(&mut self, report: &JobReport) {
        self.events.push(format!("observe:{}", report.id));
    }
}

#[test]
fn multiple_steps_share_one_scope_and_dependencies_start_only_after_close() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let id = prepared.run_id();
    let mut worker = Worker::new();
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    assert!(receipt.report().succeeded());
    assert_eq!(
        worker.events,
        [
            "begin:build",
            "step:echo first > marker",
            "step:cat marker",
            "close:false",
            "observe:build",
            "begin:test",
            "step:echo test",
            "step:echo done",
            "close:false",
            "observe:test",
        ]
    );
    assert_eq!(
        c.active_runs[&id]
            .job_attempts
            .values()
            .copied()
            .collect::<Vec<_>>(),
        vec![1, 1]
    );
    assert_eq!(c.active_runs[&id].job_outputs["build"].len(), 2);
    assert_eq!(
        c.active_runs[&id].status,
        RunStatus::Terminal(RunOutcome::Succeeded)
    );
    let roots = [
        receipt.job_commitment("build").unwrap(),
        receipt.job_commitment("test").unwrap(),
    ];
    let facts = c.drain_check_facts();
    let terminal = facts
        .iter()
        .filter(|f| f.status == CheckRunStatus::Completed)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 2);
    for (fact, root) in terminal.iter().zip(roots) {
        assert_eq!(fact.conclusion, Some(CheckRunConclusion::ActionRequired));
        assert_eq!(fact.receipt_commitment, Some(root));
    }
    assert!(c.active_runs[&id].job_receipts.is_empty()); // Never manufacture CheckReceipt.
    assert_eq!(c.obligations.workflow_scopes_opened, 2);
    assert_eq!(c.obligations.workflow_scopes_closed, 2);
    assert_eq!(c.obligations.secret_leases_issued, 0);
    c.verify_quiescence().unwrap();
}

#[test]
fn failure_predicates_run_in_the_same_job_and_failure_stays_sticky() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        CONDITIONS,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let id = prepared.run_id();
    let mut worker = Worker::new();
    worker.outcomes.push_back(StepOutcome::Failed);
    let report = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap()
        .report();
    assert_eq!(report.jobs[0].outcome, JobOutcome::Failed);
    assert_eq!(
        report.jobs[0]
            .steps
            .iter()
            .map(|s| s.index)
            .collect::<Vec<_>>(),
        vec![0, 2, 3]
    );
    assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
    assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
    assert!(
        !worker
            .events
            .iter()
            .any(|s| s == "step:skipped-success" || s == "begin:dependent")
    );
    assert_eq!(c.active_runs[&id].job_attempts["dependent"], 0);
    assert_eq!(
        c.active_runs[&id].status,
        RunStatus::Terminal(RunOutcome::Failed {
            failed_jobs: vec!["build".to_owned()]
        })
    );
    c.drain_check_facts();
    c.verify_quiescence().unwrap();
}

#[test]
fn shared_output_budget_does_not_reset_at_job_boundaries() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits {
            stream_bytes: 4,
            total_output_bytes: 16,
            ..WorkflowLimits::default()
        },
        TriggerContext::trusted_push("alice"),
    );
    let mut worker = Worker::new();
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    // Build retains 5+5 bytes. Test gets only 3 bytes per stream, not a fresh budget.
    assert_eq!(
        worker
            .budgets
            .iter()
            .map(|b| b.stream_bytes)
            .collect::<Vec<_>>(),
        vec![4, 4, 3]
    );
    let retained: usize = receipt
        .report()
        .jobs
        .iter()
        .flat_map(|j| &j.steps)
        .map(|s| s.observation.stdout.len() + s.observation.stderr.len())
        .sum();
    assert!(retained <= 16);
    assert_eq!(receipt.report().jobs[0].outcome, JobOutcome::Succeeded);
    assert_eq!(receipt.report().jobs[1].outcome, JobOutcome::OutputLimit);
}

#[test]
fn cancellation_during_close_cannot_be_published_as_success() {
    let live = Cell::new(true);
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let mut worker = Worker::new();
    worker.live = Some(&live);
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| live.get())
        .unwrap();
    assert!(
        receipt
            .report()
            .jobs
            .iter()
            .all(|j| j.outcome == JobOutcome::Cancelled)
    );
    assert!(!worker.events.iter().any(|s| s == "begin:test"));
    let facts = c.drain_check_facts();
    assert!(
        facts
            .iter()
            .all(|f| f.conclusion != Some(CheckRunConclusion::Success))
    );
    assert_eq!(
        c.obligations.workflow_scopes_opened,
        c.obligations.workflow_scopes_closed
    );
    c.verify_quiescence().unwrap();
}

#[test]
fn containment_hold_survives_finalization_and_blocks_coordinator_reuse() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        CONDITIONS,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let id = prepared.run_id();
    let mut worker = Worker::new();
    worker.outcomes.push_back(StepOutcome::ContainmentFailure);
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    assert!(receipt.report().jobs[0].requires_containment());
    assert!(!worker.events.iter().any(|s| s == "begin:independent"));
    assert!(matches!(
        c.active_runs[&id].status,
        RunStatus::Draining { .. }
    ));
    assert!(matches!(
        c.drain_and_finalize(id).unwrap(),
        RunOutcome::ContainmentFailure { .. }
    ));
    c.drain_check_facts();
    assert!(c.verify_quiescence().is_err());
    let mut next = enqueue(
        &mut c,
        MULTI,
        2,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    assert!(c.eligible_jobs(next.run_id()).unwrap().is_empty());
    assert!(matches!(
        c.execute_trusted_workflow(&mut next, &mut worker, 300, &|| true),
        Err(CoordinatorRefusal::ObligationLeak(_))
    ));
    assert!(!next.attempted);
}

#[test]
fn unwound_executor_attempts_reaping_but_never_claims_settlement_or_reexecutes() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let id = prepared.run_id();
    let mut worker = Worker::new();
    worker.panic_step = true;
    assert!(matches!(
        c.execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true),
        Err(CoordinatorRefusal::ContainmentFailure(_))
    ));
    assert_eq!(worker.events.last().unwrap(), "close:true");
    assert!(prepared.receipt().is_none());
    assert!(matches!(
        c.active_runs[&id].status,
        RunStatus::Draining { .. }
    ));
    let count = worker.events.len();
    assert!(
        c.execute_trusted_workflow(&mut prepared, &mut worker, 201, &|| true)
            .is_err()
    );
    assert_eq!(worker.events.len(), count);
    c.drain_check_facts();
    assert!(c.verify_quiescence().is_err());
}

#[test]
fn clean_begin_refusal_settles_without_suppressing_independent_jobs() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        CONDITIONS,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let mut worker = Worker::new();
    worker.refuse_begin_once = true;
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    assert_eq!(receipt.report().jobs[0].outcome, JobOutcome::Refused);
    assert_eq!(receipt.report().jobs[2].outcome, JobOutcome::Succeeded);
    assert_eq!(c.obligations.workflow_scopes_opened, 2);
    assert_eq!(c.obligations.workflow_scopes_closed, 2);
    c.drain_check_facts();
    c.verify_quiescence().unwrap();
}

#[test]
fn forks_and_execution_profile_switches_are_refused_before_work() {
    let mut c = coordinator();
    assert!(
        c.enqueue_trusted_workflow(
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            Commitment::of_bytes(b"head"),
            GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
            WorkflowPlan::compile(MULTI).unwrap(),
            WorkflowLimits::default(),
            TriggerContext::fork_pull_request(7, "fork"),
            1,
            100
        )
        .is_err()
    );
    assert!(c.active_runs.is_empty());
    assert!(c.outbox_facts.is_empty());
    let prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let before = c.obligations.clone();
    assert!(matches!(
        c.require_ready_job(prepared.run_id(), "build"),
        Err(CoordinatorRefusal::UnsupportedExecution { .. })
    ));
    assert_eq!(c.obligations, before);
}

#[test]
fn completed_retry_returns_same_receipt_without_work_or_duplicate_facts() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let mut worker = Worker::new();
    let root = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap()
        .commitment();
    let count = worker.events.len();
    c.drain_check_facts();
    assert_eq!(
        c.execute_trusted_workflow(&mut prepared, &mut worker, 999, &|| false)
            .unwrap()
            .commitment(),
        root
    );
    assert_eq!(worker.events.len(), count);
    assert!(c.drain_check_facts().is_empty());
}

#[test]
fn fifo_preflight_does_not_consume_a_blocked_prepared_plan() {
    let mut c = coordinator();
    let mut trigger = TriggerContext::trusted_push("alice");
    trigger.concurrency_group = Some(ConcurrencyGroup::new("serial", false));
    let mut first = enqueue(&mut c, MULTI, 1, WorkflowLimits::default(), trigger.clone());
    let mut second = enqueue(&mut c, MULTI, 2, WorkflowLimits::default(), trigger);
    let mut worker = Worker::new();
    assert!(
        c.execute_trusted_workflow(&mut second, &mut worker, 200, &|| true)
            .is_err()
    );
    assert!(!second.attempted);
    assert!(worker.events.is_empty());
    c.execute_trusted_workflow(&mut first, &mut worker, 201, &|| true)
        .unwrap();
    c.execute_trusted_workflow(&mut second, &mut worker, 202, &|| true)
        .unwrap();
    assert!(matches!(
        c.active_runs[&second.run_id()].status,
        RunStatus::Terminal(RunOutcome::Succeeded)
    ));
}

#[test]
fn prepared_plan_cannot_cross_trust_bindings_or_fabricate_execution_on_another_coordinator() {
    let mut first = coordinator();
    let mut prepared = enqueue(
        &mut first,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let mut second = coordinator();
    let mut trigger = TriggerContext::trusted_push("alice");
    trigger.trust_domain = TrustDomain::new(RunnerText::parse("trust", "another-domain").unwrap());
    let other = enqueue(&mut second, MULTI, 1, WorkflowLimits::default(), trigger);
    assert_eq!(other.run_id(), prepared.run_id()); // Legacy run identity is unchanged.
    let mut worker = Worker::new();
    assert!(
        second
            .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
            .is_err()
    );
    assert!(worker.events.is_empty());
    first
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    let mut same_binding = coordinator();
    enqueue(
        &mut same_binding,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    assert!(
        same_binding
            .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
            .is_err()
    );
}

#[test]
fn admitted_timeouts_are_intersections_and_skipped_jobs_cannot_issue_green_checks() {
    let mut c = WorkflowCoordinator::new(
        CoordinatorLimits {
            step_timeout: Duration::from_millis(40),
            run_timeout: Duration::from_secs(1),
            ..CoordinatorLimits::default()
        },
        ResourceCeilings::new(1, 1, 1, 0, 1, 10).unwrap(),
        1,
    )
    .unwrap();
    let source = "name: no-work\non: push\njobs:\n  skip:\n    runs-on: fgit-trusted-local\n    if: failure()\n    steps:\n      - run: echo skip\n";
    let mut prepared = enqueue(
        &mut c,
        source,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    assert_eq!(prepared.limits().step_timeout, Duration::from_millis(10));
    assert_eq!(prepared.limits().run_timeout, Duration::from_secs(1));
    let mut worker = Worker::new();
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    assert_eq!(receipt.report().jobs[0].outcome, JobOutcome::Skipped);
    assert_eq!(worker.events, ["observe:skip"]);
    assert_eq!(c.obligations.workflow_scopes_opened, 0);
    let facts = c.drain_check_facts();
    assert_eq!(
        facts.last().unwrap().conclusion,
        Some(CheckRunConclusion::ActionRequired)
    );
    c.verify_quiescence().unwrap();
}

#[cfg(target_os = "linux")]
mod live;

#[test]
fn local_receipts_bind_exact_yaml_bytes_even_when_semantic_run_identity_is_unchanged() {
    let mut first = coordinator();
    let mut a = enqueue(
        &mut first,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let mut second = coordinator();
    let mut b = enqueue(
        &mut second,
        &format!("{MULTI}\n"),
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    assert_eq!(a.run_id(), b.run_id());
    let mut worker = Worker::new();
    let ra = first
        .execute_trusted_workflow(&mut a, &mut worker, 200, &|| true)
        .unwrap();
    let mut worker = Worker::new();
    let rb = second
        .execute_trusted_workflow(&mut b, &mut worker, 200, &|| true)
        .unwrap();
    assert_eq!(ra.report().graph, rb.report().graph);
    assert_ne!(ra.report().source, rb.report().source);
    assert_ne!(ra.commitment(), rb.commitment());
    assert_ne!(ra.job_commitment("build"), rb.job_commitment("build"));
}

#[test]
fn local_receipt_identity_retains_submillisecond_limits_and_output_bytes() {
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        MULTI,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"),
    );
    let mut worker = Worker::new();
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
        .unwrap();
    let mut changed = receipt.clone();
    changed.report.limits.step_timeout += Duration::from_nanos(1);
    assert_eq!(receipt.report().to_json(), changed.report().to_json());
    assert_ne!(receipt.commitment(), changed.commitment());
    let mut changed = receipt.clone();
    changed.report.jobs[0].steps[0].observation.stdout[0] ^= 1;
    assert_ne!(receipt.commitment(), changed.commitment());
    assert_ne!(
        receipt.job_commitment("build"),
        changed.job_commitment("build")
    );
}

#[test]
fn forced_stops_keep_their_primary_reason_while_retaining_unresolved_scopes() {
    for (outcome, expected) in [
        (StepOutcome::Cancelled, JobOutcome::Cancelled),
        (StepOutcome::TimedOut, JobOutcome::TimedOut),
        (StepOutcome::OutputLimit, JobOutcome::OutputLimit),
    ] {
        let mut c = coordinator();
        let mut prepared = enqueue(
            &mut c,
            CONDITIONS,
            1,
            WorkflowLimits {
                stream_bytes: 8,
                ..WorkflowLimits::default()
            },
            TriggerContext::trusted_push("alice"),
        );
        let mut worker = Worker::new();
        worker.retain_scope = true;
        worker.outcomes.push_back(outcome);
        let receipt = c
            .execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true)
            .unwrap();
        let first = &receipt.report().jobs[0];
        assert_eq!(first.outcome, expected);
        assert_eq!(first.steps[0].observation.outcome, outcome);
        assert_eq!(first.steps[0].observation.stdout.len(), 8);
        assert!(first.requires_containment());
        assert!(
            receipt.report().jobs[1..]
                .iter()
                .all(|job| job.outcome == JobOutcome::Cancelled)
        );
        assert!(worker.events.iter().any(|event| event == "close:true"));
        assert!(
            !worker
                .events
                .iter()
                .any(|event| event == "begin:independent")
        );
        c.drain_check_facts();
        assert!(c.verify_quiescence().is_err());
    }
}
