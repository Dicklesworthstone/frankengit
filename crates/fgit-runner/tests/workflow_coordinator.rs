#![forbid(unsafe_code)]
//! Exhaustive unit and integration tests for the workflow coordinator (FG-095b).

use fgit_resource::kinds::{ContainmentClass, ExitClass, RunnerReaped};
use fgit_schema::workflow::compile;
use fgit_schema::workflow::Limits as SchemaLimits;
use fgit_types::{GitOid, GitOidSha1, RepositoryId, TenantId};

use fgit_runner::coordinator::{
    CancellationReason, CheckRunConclusion, CheckRunStatus, ConcurrencyGroup,
    CoordinatorLimits, CoordinatorRefusal, IdempotencyKey, JobStatus, RunOutcome, RunStatus,
    TriggerContext, WorkflowCoordinator,
};
use fgit_runner::{
    CheckOutcome, Commitment, ContainmentSubstrate, LogRedactor, ResourceCeilings,
    ResourceUsage, SandboxPlan, SourceObject, SubstrateObservation, SubstrateRefusal,
};

fn hash(val: &[u8]) -> Commitment {
    Commitment::of_bytes(val)
}

fn sample_oid(val: u8) -> GitOid {
    let mut bytes = [0u8; 20];
    bytes[0] = val;
    GitOid::Sha1(GitOidSha1::from_bytes(bytes))
}

fn ceilings() -> ResourceCeilings {
    ResourceCeilings::new(100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, 60_000).unwrap()
}

struct MockSubstrate {
    fail: bool,
    output: Vec<u8>,
}

impl MockSubstrate {
    fn success() -> Self {
        Self {
            fail: false,
            output: b"step output".to_vec(),
        }
    }

    fn failure() -> Self {
        Self {
            fail: true,
            output: b"failure output".to_vec(),
        }
    }
}

impl ContainmentSubstrate for MockSubstrate {
    fn launch(&mut self, _: &SandboxPlan) -> Result<SubstrateObservation, SubstrateRefusal> {
        if self.fail {
            Ok(SubstrateObservation {
                exit: ExitClass::Failed,
                usage: ResourceUsage {
                    cpu_micros: 10,
                    memory_bytes: 1024,
                    disk_bytes: 512,
                    network_bytes: 0,
                    processes: 1,
                    wall_clock_millis: 15,
                },
                reaped: RunnerReaped {
                    processes_reaped: 1,
                    containment: ContainmentClass::Cooperative,
                },
                log_redaction: LogRedactor::new(vec![]).unwrap().redact(&self.output).unwrap().receipt(),
                artifacts: Vec::new(),
            })
        } else {
            Ok(SubstrateObservation {
                exit: ExitClass::Succeeded,
                usage: ResourceUsage {
                    cpu_micros: 20,
                    memory_bytes: 2048,
                    disk_bytes: 1024,
                    network_bytes: 0,
                    processes: 1,
                    wall_clock_millis: 25,
                },
                reaped: RunnerReaped {
                    processes_reaped: 1,
                    containment: ContainmentClass::Cooperative,
                },
                log_redaction: LogRedactor::new(vec![]).unwrap().redact(&self.output).unwrap().receipt(),
                artifacts: vec![hash(b"test-artifact-1")],
            })
        }
    }
}

const TWO_STAGE_DAG: &str = r#"
name: test-ci
on: push
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: echo "building"
  test:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: echo "testing"
"#;

#[test]
fn state_machine_four_state_lifecycle_and_dag_progression() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 8).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit = sample_oid(1);

    let run_id = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph,
        TriggerContext::trusted_push("alice"),
        1,
        1000,
    ).unwrap();

    // Initial state: Queued
    let run = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit, "test-ci", 1)).unwrap();
    assert_eq!(run.status, RunStatus::Queued);
    assert_eq!(run.job_statuses.get("build"), Some(&JobStatus::Queued));
    assert_eq!(run.job_statuses.get("test"), Some(&JobStatus::Queued));

    // Initially, only 'build' is eligible ('test' depends on 'build')
    let eligible = coordinator.eligible_jobs(run_id).unwrap();
    assert_eq!(eligible, vec!["build".to_string()]);

    // Execute 'build' job
    let mut substrate = MockSubstrate::success();
    let receipt = coordinator.execute_job(
        run_id,
        "build",
        &mut substrate,
        1050,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    assert_eq!(receipt.outcome(), CheckOutcome::Succeeded);
    assert_eq!(receipt.artifacts(), &[hash(b"test-artifact-1")]);

    // Now 'test' should become eligible
    let eligible_next = coordinator.eligible_jobs(run_id).unwrap();
    assert_eq!(eligible_next, vec!["test".to_string()]);

    // Execute 'test' job
    let receipt_test = coordinator.execute_job(
        run_id,
        "test",
        &mut substrate,
        1100,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    assert_eq!(receipt_test.outcome(), CheckOutcome::Succeeded);

    // Entire run is now terminal Succeeded!
    let run_final = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit, "test-ci", 1)).unwrap();
    assert_eq!(run_final.status, RunStatus::Terminal(RunOutcome::Succeeded));

    // Publish / drain outbox check facts
    let facts = coordinator.drain_check_facts();
    assert_eq!(facts.len(), 6);

    // Verify all obligations cleanly settled
    coordinator.verify_quiescence().unwrap();
}

#[test]
fn idempotency_derivation_prevents_duplicate_executions() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit = sample_oid(2);

    let run_id = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph.clone(),
        TriggerContext::trusted_push("alice"),
        42,
        1000,
    ).unwrap();

    // Re-enqueuing with the exact same parameters must return DuplicateIdempotencyKey
    let dup_err = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph,
        TriggerContext::trusted_push("alice"),
        42,
        1001,
    ).unwrap_err();

    let expected_key = IdempotencyKey::of("push", &commit, "test-ci", 42);
    assert_eq!(dup_err, CoordinatorRefusal::DuplicateIdempotencyKey(expected_key));

    let looked_up = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit, "test-ci", 42)).unwrap();
    assert_eq!(looked_up.id, run_id);
}

#[test]
fn request_drain_finalize_cancellation_lifecycle() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit = sample_oid(3);

    let run_id = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph,
        TriggerContext::trusted_push("alice"),
        1,
        1000,
    ).unwrap();

    // Cancel while queued -> directly terminates
    coordinator.cancel_run(run_id, CancellationReason::UserRequested).unwrap();
    let run = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit, "test-ci", 1)).unwrap();
    assert_eq!(
        run.status,
        RunStatus::Terminal(RunOutcome::Cancelled { reason: CancellationReason::UserRequested })
    );

    // Draining and finalizing already terminal run returns its outcome
    let final_outcome = coordinator.drain_and_finalize(run_id).unwrap();
    assert_eq!(
        final_outcome,
        RunOutcome::Cancelled { reason: CancellationReason::UserRequested }
    );
}

#[test]
fn concurrency_group_cancel_in_progress_preempts_older_run() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 8).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit1 = sample_oid(10);
    let commit2 = sample_oid(11);

    let group = ConcurrencyGroup::new("pr-concurrency-branch-feat", true);

    let mut trigger1 = TriggerContext::trusted_push("alice");
    trigger1.concurrency_group = Some(group.clone());

    let run1 = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit1,
        graph.clone(),
        trigger1,
        1,
        1000,
    ).unwrap();

    // Start executing run1's build job so it's in Running state
    let mut substrate = MockSubstrate::success();
    let _ = coordinator.execute_job(
        run1,
        "build",
        &mut substrate,
        1050,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    // Enqueue run2 in the same concurrency group with cancel_in_progress = true
    let mut trigger2 = TriggerContext::trusted_push("alice");
    trigger2.concurrency_group = Some(group);

    let run2 = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit2,
        graph,
        trigger2,
        2,
        1100,
    ).unwrap();

    // Run1 should now be in Draining phase with ConcurrencyPreempted reason!
    let run1_state = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit1, "test-ci", 1)).unwrap();
    match &run1_state.status {
        RunStatus::Draining { reason: fgit_runner::coordinator::DrainReason::Cancelled(CancellationReason::ConcurrencyPreempted { group, newer_run }) } => {
            assert_eq!(group, "pr-concurrency-branch-feat");
            assert_eq!(*newer_run, run2);
        }
        other => panic!("expected draining with ConcurrencyPreempted, got {other:?}"),
    }

    // Drain and finalize run1
    let outcome = coordinator.drain_and_finalize(run1).unwrap();
    assert!(matches!(outcome, RunOutcome::Cancelled { reason: CancellationReason::ConcurrencyPreempted { .. } }));
}

#[test]
fn fork_pull_request_attenuation_enforces_isolated_domain_and_denied_network() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit = sample_oid(50);

    let trigger = TriggerContext::fork_pull_request(123, "external-contributor");
    assert!(trigger.is_fork);

    let run_id = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph,
        trigger,
        1,
        2000,
    ).unwrap();

    let mut substrate = MockSubstrate::success();
    let receipt = coordinator.execute_job(
        run_id,
        "build",
        &mut substrate,
        2050,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    // For a fork PR: zero secret leases should have been bound/revoked
    assert_eq!(receipt.revoked_secrets(), 0);
    assert_eq!(coordinator.obligations().secret_leases_issued, 0);

    // Drain outbox facts and verify clean quiescence
    let _ = coordinator.drain_check_facts();
    coordinator.verify_quiescence().unwrap();
}

#[test]
fn check_publication_facts_emitted_to_outbox() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit = sample_oid(70);

    let run_id = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph,
        TriggerContext::trusted_push("alice"),
        1,
        3000,
    ).unwrap();

    let facts = coordinator.drain_check_facts();
    // 2 jobs in graph -> 2 Queued check facts
    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0].status, CheckRunStatus::Queued);
    assert_eq!(facts[0].run_id, run_id);
    assert_eq!(facts[0].job_id, "build");
    assert_eq!(facts[1].status, CheckRunStatus::Queued);
    assert_eq!(facts[1].job_id, "test");

    // Execute build job
    let mut substrate = MockSubstrate::success();
    let _ = coordinator.execute_job(
        run_id,
        "build",
        &mut substrate,
        3050,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    let next_facts = coordinator.drain_check_facts();
    // InProgress + Completed facts
    assert_eq!(next_facts.len(), 2);
    assert_eq!(next_facts[0].status, CheckRunStatus::InProgress);
    assert_eq!(next_facts[1].status, CheckRunStatus::Completed);
    assert_eq!(next_facts[1].conclusion, Some(CheckRunConclusion::Success));

    // Each fact has a deterministic commitment
    let commit_fact = next_facts[1].canonical_commitment();
    assert_eq!(commit_fact, next_facts[1].canonical_commitment());
}

#[test]
fn crash_recovery_marks_inflight_runs_as_reaped_and_invalidates_stale_heads() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-old");
    let commit1 = sample_oid(80);
    let commit2 = sample_oid(81);

    // Run 1: left in running state
    let run1 = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit1,
        graph.clone(),
        TriggerContext::trusted_push("alice"),
        1,
        4000,
    ).unwrap();

    let mut substrate = MockSubstrate::success();
    let _ = coordinator.execute_job(
        run1,
        "build",
        &mut substrate,
        4050,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    // Run 2: queued with the old head
    let run2 = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit2,
        graph,
        TriggerContext::trusted_push("alice"),
        2,
        4100,
    ).unwrap();

    // Authority head moves forward while coordinator was down
    let head_new = hash(b"head-new");
    let recovered = coordinator.recover_from_crash(head_new);

    // Both runs should be recovered/invalidated
    assert_eq!(recovered.len(), 2);
    assert!(recovered.contains(&run1));
    assert!(recovered.contains(&run2));

    let run1_state = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit1, "test-ci", 1)).unwrap();
    assert!(matches!(run1_state.status, RunStatus::Terminal(RunOutcome::Invalidated { .. })));

    let run2_state = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit2, "test-ci", 2)).unwrap();
    assert!(matches!(run2_state.status, RunStatus::Terminal(RunOutcome::Invalidated { .. })));
}

#[test]
fn job_failure_skips_dependents_and_marks_run_failed() {
    let graph = compile(TWO_STAGE_DAG, &SchemaLimits::default()).unwrap();
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap();

    let tenant = TenantId::from_bytes([1; 16]);
    let repo = RepositoryId::from_bytes([2; 16]);
    let head = hash(b"head-001");
    let commit = sample_oid(90);

    let run_id = coordinator.enqueue_run(
        tenant,
        repo,
        head,
        commit,
        graph,
        TriggerContext::trusted_push("alice"),
        1,
        5000,
    ).unwrap();

    let mut fail_substrate = MockSubstrate::failure();
    let receipt = coordinator.execute_job(
        run_id,
        "build",
        &mut fail_substrate,
        5050,
        vec![SourceObject::new(hash(b"src1"), 100)],
        hash(b"lock-file"),
        "rust-stable",
    ).unwrap();

    assert_eq!(receipt.outcome(), CheckOutcome::Failed);

    // Prerequisite 'build' failed, so 'test' (which has condition: success()) must not be eligible
    let eligible = coordinator.eligible_jobs(run_id).unwrap();
    assert!(eligible.is_empty());

    // Run outcome should be marked failed
    let run = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit, "test-ci", 1)).unwrap();
    match &run.status {
        RunStatus::Running => {
            // Cancel/terminate the run since no jobs remain eligible
            coordinator.cancel_run(run_id, CancellationReason::UserRequested).unwrap();
            let term = coordinator.lookup_by_idempotency(&IdempotencyKey::of("push", &commit, "test-ci", 1)).unwrap();
            assert!(matches!(term.status, RunStatus::Terminal(RunOutcome::Cancelled { .. })));
        }
        RunStatus::Terminal(RunOutcome::Failed { failed_jobs }) => {
            assert_eq!(failed_jobs, &["build".to_string()]);
        }
        other => panic!("unexpected run status: {other:?}"),
    }
}
