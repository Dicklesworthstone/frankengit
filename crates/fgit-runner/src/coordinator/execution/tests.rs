//! Coordinator regressions. Fixtures test metadata/control flow; the separately
//! named Linux test uses real trusted direct children, not a hostile sandbox.
use super::*;
use crate::{LogRedactor, ResourceUsage, SandboxPlan, SubstrateObservation, SubstrateRefusal};
use fgit_resource::kinds::{ContainmentClass, ExitClass, RunnerReaped};
use fgit_schema::workflow::{Job, Limits, compile};
use fgit_types::GitOidSha1;

fn graph(command: &str) -> WorkflowGraph {
    let mut graph = compile("name: commands\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n", &Limits::default()).unwrap();
    graph.jobs[0].steps[0].run = command.to_owned();
    graph
}
fn lowered(command: &str) -> Result<BuildCommand, CoordinatorRefusal> {
    lower_command(&graph(command).jobs[0])
}
fn argv(command: &BuildCommand) -> Vec<&str> {
    std::iter::once(command.program().as_str())
        .chain(command.arguments().iter().map(RunnerText::as_str))
        .collect()
}
fn ceilings() -> ResourceCeilings {
    ResourceCeilings::new(100_000, 4096, 4096, 0, 16, 60_000).unwrap()
}
fn coordinator() -> WorkflowCoordinator {
    WorkflowCoordinator::new(CoordinatorLimits::default(), ceilings(), 4).unwrap()
}
fn enqueue(
    c: &mut WorkflowCoordinator,
    graph: WorkflowGraph,
) -> Result<WorkflowRunId, CoordinatorRefusal> {
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
}
fn source() -> Vec<SourceObject> {
    vec![SourceObject::new(Commitment::of_bytes(b"source"), 6)]
}

struct Fixture {
    calls: usize,
    exit: ExitClass,
    memory: u64,
    observed_wall_limit: u64,
}
impl Fixture {
    fn success() -> Self {
        Self {
            calls: 0,
            exit: ExitClass::Succeeded,
            memory: 16,
            observed_wall_limit: 0,
        }
    }
}
impl ContainmentSubstrate for Fixture {
    fn launch(&mut self, plan: &SandboxPlan) -> Result<SubstrateObservation, SubstrateRefusal> {
        self.calls += 1;
        self.observed_wall_limit = plan.policy().ceilings().wall_clock_millis();
        assert!(
            plan.secret_leases().is_empty(),
            "no unrequested credential may reach the runner"
        );
        assert!(
            plan.capsule()
                .environment()
                .iter()
                .any(|binding| binding.name().as_str() == "FGIT_JOB_ATTEMPT")
        );
        Ok(SubstrateObservation {
            exit: self.exit,
            usage: ResourceUsage {
                cpu_micros: 2,
                memory_bytes: self.memory,
                disk_bytes: 3,
                network_bytes: 0,
                processes: 1,
                wall_clock_millis: 4,
            },
            reaped: RunnerReaped {
                processes_reaped: 1,
                containment: ContainmentClass::Cooperative,
            },
            log_redaction: LogRedactor::new(Vec::new())
                .unwrap()
                .redact(b"observed output")
                .unwrap()
                .receipt(),
            artifacts: Vec::new(),
        })
    }
}

#[test]
fn command_lowering_preserves_literals_and_never_substitutes_true() {
    let cases: &[(&str, &[&str])] = &[
        ("cargo test --locked", &["cargo", "test", "--locked"]),
        ("echo \"building\"", &["echo", "building"]),
        ("printf '%s' '*.rs'", &["printf", "%s", "*.rs"]),
        ("echo '$HOME'", &["echo", "$HOME"]),
        (r#"echo "\$HOME""#, &["echo", "$HOME"]),
        (r#"echo a\;b"#, &["echo", "a;b"]),
        (r#"echo "a\qb""#, &["echo", r"a\qb"]),
        (" ca\"rg\"o\tcheck \n", &["cargo", "check"]),
    ];
    for (source, expected) in cases {
        let command = lowered(source).unwrap();
        assert_eq!(argv(&command).as_slice(), *expected, "{source:?}");
        assert_eq!(command.commitment(), lowered(source).unwrap().commitment());
    }
    assert_ne!(
        lowered("cargo check").unwrap().commitment(),
        lowered("cargo test").unwrap().commitment()
    );
}

#[test]
fn shell_syntax_and_unrepresentable_arguments_refuse_instead_of_approximating() {
    for script in [
        "",
        " ",
        "echo $HOME",
        "echo `id`",
        "echo $(id)",
        "echo *.rs",
        "echo ~",
        "echo x | cat",
        "echo x > result",
        "true && false",
        "true; false",
        "true\nfalse",
        "FOO=value cargo test",
        "cd src",
        "echo 'unterminated",
        "echo \"unterminated",
        "echo \\",
        "echo \"hello world\"",
        "echo ''",
        "echo \0",
        "echo café",
        "echo # comment",
        "echo ${{x}}",
    ] {
        assert!(lowered(script).is_err(), "must refuse {script:?}");
    }
    assert_eq!(
        argv(&lowered("echo '$HOME'").unwrap()),
        vec!["echo", "$HOME"]
    );
}

#[test]
fn argument_count_and_byte_bounds_have_permitted_boundary_twins() {
    let at_limit = format!("echo {}", "x".repeat(MAX_RUNNER_TEXT_BYTES));
    assert!(lowered(&at_limit).is_ok());
    assert!(lowered(&format!("{at_limit}x")).is_err());
    let at_count = format!("echo {}", vec!["x"; MAX_COMMAND_ARGUMENTS].join(" "));
    assert_eq!(
        lowered(&at_count).unwrap().arguments().len(),
        MAX_COMMAND_ARGUMENTS
    );
    assert!(lowered(&format!("{at_count} x")).is_err());
    assert!(lowered(&" ".repeat(MAX_COMMAND_SOURCE_BYTES + 1)).is_err());
}

#[test]
fn entire_graph_is_preflighted_before_any_run_or_proposal() {
    let mut invalid = graph("echo build");
    let mut second: Job = invalid.jobs[0].clone();
    second.id = "test".to_owned();
    second.needs = vec!["build".to_owned()];
    second.steps[0].run = "cargo test && echo done".to_owned();
    invalid.jobs.push(second);
    let mut c = coordinator();
    assert!(matches!(
        enqueue(&mut c, invalid),
        Err(CoordinatorRefusal::UnsupportedExecution { .. })
    ));
    assert!(c.active_runs.is_empty());
    assert!(c.idempotency_map.is_empty());
    assert!(c.outbox_facts.is_empty());
    assert_eq!(c.obligations, ObligationSummary::default());
    assert!(enqueue(&mut c, graph("cargo test --locked")).is_ok());
}

#[test]
fn multistep_and_unavailable_runner_profiles_fail_explicitly() {
    let mut multi = graph("true");
    let repeated = multi.jobs[0].steps[0].clone();
    multi.jobs[0].steps.push(repeated);
    assert!(matches!(
        enqueue(&mut coordinator(), multi),
        Err(CoordinatorRefusal::UnsupportedExecution { .. })
    ));
    let mut conditional = graph("true");
    conditional.jobs[0].steps[0].condition = Condition::Failure;
    assert!(enqueue(&mut coordinator(), conditional).is_err());
    let mut unavailable = graph("true");
    unavailable.jobs[0].runs_on = "not-a-registered-runner".to_owned();
    assert!(matches!(
        enqueue(&mut coordinator(), unavailable),
        Err(CoordinatorRefusal::WorkflowRefusal(
            WorkflowError::UnsupportedRunner(_)
        ))
    ));
}

#[test]
fn invalid_inputs_do_not_start_jobs_issue_secrets_or_leak_slots() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph("echo building")).unwrap();
    let before = c.obligations.clone();
    let mut fixture = Fixture::success();
    assert!(
        c.execute_job(
            run,
            "build",
            &mut fixture,
            100,
            source(),
            Commitment::of_bytes(b"lock"),
            "bad toolchain"
        )
        .is_err()
    );
    assert!(
        c.execute_job(
            run,
            "build",
            &mut fixture,
            100,
            Vec::new(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly"
        )
        .is_err()
    );
    assert_eq!(fixture.calls, 0);
    assert_eq!(c.obligations, before);
    assert_eq!(c.active_runs[&run].job_attempts["build"], 0);
    assert_eq!(c.active_runs[&run].status, RunStatus::Queued);
    let receipt = c
        .execute_job(
            run,
            "build",
            &mut fixture,
            100,
            source(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly",
        )
        .unwrap();
    assert_eq!(argv(receipt.command()), vec!["echo", "building"]);
    assert_eq!(receipt.revoked_secrets(), 0);
    assert_eq!(c.obligations.secret_leases_issued, 0);
    assert_eq!(fixture.calls, 1);
    assert!(
        c.execute_job(
            run,
            "build",
            &mut fixture,
            101,
            source(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly"
        )
        .is_err()
    );
    assert_eq!(fixture.calls, 1);
    c.drain_check_facts();
    c.verify_quiescence().unwrap();
}

#[test]
fn configured_resource_ceilings_and_step_deadline_reach_the_substrate() {
    let limited = ResourceCeilings::new(100_000, 8, 4096, 0, 16, 60_000).unwrap();
    let limits = CoordinatorLimits {
        step_timeout: Duration::from_secs(2),
        ..CoordinatorLimits::default()
    };
    let mut c = WorkflowCoordinator::new(limits, limited, 4).unwrap();
    let run = enqueue(&mut c, graph("echo test")).unwrap();
    let mut fixture = Fixture {
        exit: ExitClass::ResourceCeiling,
        ..Fixture::success()
    };
    let receipt = c
        .execute_job(
            run,
            "build",
            &mut fixture,
            100,
            source(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly",
        )
        .unwrap();
    assert_eq!(fixture.observed_wall_limit, 2000);
    assert_eq!(
        receipt.outcome(),
        CheckOutcome::ResourceCeiling {
            dimension: ResourceDimension::MemoryBytes
        }
    );
    assert!(!matches!(
        c.active_runs[&run].status,
        RunStatus::Terminal(RunOutcome::Succeeded)
    ));
}

#[test]
fn check_fact_binds_actual_terminal_evidence_not_just_input_capsule() {
    let mut observations = Vec::new();
    for exit in [ExitClass::Succeeded, ExitClass::Failed] {
        let mut c = coordinator();
        let run = enqueue(&mut c, graph("echo same-input")).unwrap();
        let mut fixture = Fixture {
            exit,
            ..Fixture::success()
        };
        let receipt = c
            .execute_job(
                run,
                "build",
                &mut fixture,
                100,
                source(),
                Commitment::of_bytes(b"lock"),
                "rust-nightly",
            )
            .unwrap();
        receipt.verify_evidence().unwrap();
        let facts = c.drain_check_facts();
        let terminal = facts
            .iter()
            .find(|fact| fact.status == CheckRunStatus::Completed)
            .unwrap();
        let evidence = Commitment::of_bytes(receipt.evidence().frame());
        assert_eq!(terminal.receipt_commitment, Some(evidence));
        assert_ne!(evidence, receipt.capsule_id().commitment());
        observations.push((receipt.capsule_id(), evidence));
    }
    assert_eq!(observations[0].0, observations[1].0);
    assert_ne!(observations[0].1, observations[1].1);
}

#[cfg(target_os = "linux")]
#[test]
fn real_trusted_process_runs_declared_command_and_preserves_nonzero_exit() {
    // This is a trusted direct-child test, not namespace/cgroup containment.
    for (command, outcome) in [
        ("/bin/true", CheckOutcome::Succeeded),
        ("/bin/false", CheckOutcome::Failed),
        ("/bin/echo building", CheckOutcome::Succeeded),
    ] {
        let mut c = coordinator();
        let run = enqueue(&mut c, graph(command)).unwrap();
        let receipt = c
            .execute_job(
                run,
                "build",
                &mut crate::ProcessSubstrate::new(),
                100,
                source(),
                Commitment::of_bytes(b"lock"),
                "host-tools",
            )
            .unwrap();
        assert_eq!(receipt.outcome(), outcome);
        assert_eq!(receipt.command(), &lowered(command).unwrap());
        assert_eq!(receipt.reaped().processes_reaped, 1);
        receipt.verify_evidence().unwrap();
        c.drain_check_facts();
        c.verify_quiescence().unwrap();
    }
}

#[test]
fn lost_containment_blocks_independent_jobs_and_transitive_always_paths() {
    let mut c = coordinator();
    let mut g = graph("echo build");
    for (name, needs) in [
        ("middle", vec!["build".to_owned()]),
        ("last", vec!["middle".to_owned()]),
        ("independent", Vec::new()),
    ] {
        let mut job = g.jobs[0].clone();
        job.id = name.to_owned();
        job.needs = needs;
        if name != "middle" {
            job.condition = Condition::Always;
        }
        g.jobs.push(job);
    }
    let run = enqueue(&mut c, g).unwrap();
    // Exceeding memory without a resource-termination report is an actual
    // control-plane containment verdict, not a normal nonzero program exit.
    let mut fixture = Fixture {
        memory: 4097,
        ..Fixture::success()
    };
    let receipt = c
        .execute_job(
            run,
            "build",
            &mut fixture,
            100,
            source(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly",
        )
        .unwrap();
    assert!(matches!(
        receipt.outcome(),
        CheckOutcome::ContainmentFailure { .. }
    ));
    assert!(matches!(
        c.active_runs[&run].status,
        RunStatus::Draining {
            reason: DrainReason::WorkerFailure(_)
        }
    ));
    assert!(c.eligible_jobs(run).unwrap().is_empty());
    assert!(
        c.execute_job(
            run,
            "independent",
            &mut fixture,
            101,
            source(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly"
        )
        .is_err()
    );
    assert_eq!(fixture.calls, 1);
}

#[test]
fn exhausted_run_deadline_never_reserves_or_launches_another_command() {
    let mut c = coordinator();
    let run = enqueue(&mut c, graph("echo late")).unwrap();
    c.active_runs.get_mut(&run).unwrap().started_at =
        Instant::now().checked_sub(Duration::from_secs(3601));
    assert!(c.active_runs[&run].started_at.is_some());
    let mut fixture = Fixture::success();
    assert!(
        c.execute_job(
            run,
            "build",
            &mut fixture,
            100,
            source(),
            Commitment::of_bytes(b"lock"),
            "rust-nightly"
        )
        .is_err()
    );
    assert_eq!(fixture.calls, 0);
    assert_eq!(c.obligations.runner_slots_reserved, 0);
    assert_eq!(
        c.active_runs[&run].job_statuses["build"],
        JobStatus::Terminal(JobOutcome::TimedOut)
    );
    assert!(
        c.drain_check_facts()
            .iter()
            .any(|fact| fact.conclusion == Some(CheckRunConclusion::TimedOut))
    );
}
