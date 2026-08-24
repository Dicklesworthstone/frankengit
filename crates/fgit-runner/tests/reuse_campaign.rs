#![forbid(unsafe_code)]
//! Bounded adversarial and economics campaign for runner output reuse.
//!
//! This target exercises the public runner control plane with fixed substrate
//! observations. It measures the current typed control-plane workload only; it
//! does not claim an operating-system sandbox or deployment-level CI economics.

use std::time::Instant;

use fgit_codec::DecodeLimits;
use fgit_resource::kinds::{
    ContainmentClass, ExitClass, NetworkPolicy, RunnerReaped, SandboxProfile,
};
use fgit_runner::{
    BuildCommand, BuildInputCapsule, CheckOutcome, Commitment, ContainmentSubstrate,
    DeterminismDeclaration, EnvironmentBinding, ExecutionRunId, JobRequest, LogRedactionReceipt,
    LoweredWorkflowStep, OutputStore, ReuseDecision, ReuseMiss, ReusePolicy, RunnerControlPlane,
    RunnerPolicy, RunnerText, SourceObject, SpotCheckResult, SpotCheckSchedule,
    SubstrateObservation, SubstrateRefusal, TrustDomain, VerificationLane, WorkflowStepDeclaration,
};

const SAMPLE_COUNT: u32 = 24;

fn text(value: &str) -> RunnerText {
    RunnerText::parse("reuse-campaign", value).expect("fixture text is canonical")
}

fn commitment(label: &str) -> Commitment {
    Commitment::of_bytes(label.as_bytes())
}

fn capsule(mode: &str) -> BuildInputCapsule {
    BuildInputCapsule::new(
        commitment("authority"),
        vec![SourceObject::new(commitment("source"), 19)],
        commitment("dependency-lock"),
        text("nightly-2026-08-20"),
        BuildCommand::new(text("cargo"), vec![text("check"), text("--locked")])
            .expect("fixture command is canonical"),
        vec![
            EnvironmentBinding::new(text("MODE"), text(mode))
                .expect("fixture environment is canonical"),
        ],
    )
    .expect("fixture capsule is admitted")
}

fn ceilings() -> fgit_runner::ResourceCeilings {
    fgit_runner::ResourceCeilings::new(100, 100, 100, 0, 1, 100)
        .expect("fixture ceilings are valid")
}

fn domain(name: &str) -> TrustDomain {
    TrustDomain::new(text(name))
}

fn deterministic_step() -> LoweredWorkflowStep {
    WorkflowStepDeclaration::new(
        text("compile"),
        DeterminismDeclaration::DeclaredDeterministic,
    )
    .lower()
}

fn nondeterministic_step() -> LoweredWorkflowStep {
    WorkflowStepDeclaration::new(
        text("compile"),
        DeterminismDeclaration::DeclaredNondeterministic,
    )
    .lower()
}

fn incremental_policy(step: &LoweredWorkflowStep, numerator: u16, denominator: u16) -> ReusePolicy {
    ReusePolicy::new(
        vec![step.step_id().clone()],
        SpotCheckSchedule::new(
            numerator,
            denominator,
            commitment("campaign-selection-seed"),
        )
        .expect("fixture sample schedule is valid"),
    )
    .expect("fixture incremental reuse policy is valid")
}

struct FixedSubstrate(SubstrateObservation);

impl ContainmentSubstrate for FixedSubstrate {
    fn launch(
        &mut self,
        _plan: &fgit_runner::SandboxPlan,
    ) -> Result<SubstrateObservation, SubstrateRefusal> {
        Ok(self.0.clone())
    }
}

fn successful_receipt(
    input: BuildInputCapsule,
    trust_domain: TrustDomain,
    artifact: Commitment,
    logical_order: u64,
) -> fgit_runner::CheckReceipt {
    let mut broker = fgit_runner::SecretBroker::default();
    let mut control = RunnerControlPlane::new(ceilings(), 1).expect("fixture capacity");
    let policy = RunnerPolicy::new(
        trust_domain,
        SandboxProfile::ProcessIsolated,
        NetworkPolicy::Denied,
        ceilings(),
    )
    .expect("fixture policy is supported");
    let admitted = control
        .admit(
            input,
            policy,
            JobRequest::new(false, Vec::new(), Vec::new(), logical_order).expect("fixture request"),
            &mut broker,
            logical_order,
        )
        .expect("fixture run is admitted");
    let mut substrate = FixedSubstrate(SubstrateObservation {
        exit: ExitClass::Succeeded,
        usage: fgit_runner::ResourceUsage {
            cpu_micros: 1,
            memory_bytes: 1,
            disk_bytes: 1,
            network_bytes: 0,
            processes: 1,
            wall_clock_millis: 1,
        },
        reaped: RunnerReaped {
            processes_reaped: 1,
            containment: ContainmentClass::Cooperative,
        },
        log_redaction: LogRedactionReceipt::new(commitment("campaign-log"), 0, 0),
        artifacts: vec![artifact],
    });
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("terminal receipt");
    assert_eq!(receipt.outcome(), CheckOutcome::Succeeded);
    receipt
}

#[test]
fn trusted_output_cannot_poison_an_untrusted_reuse_namespace() {
    let input = capsule("TRUSTED");
    let trusted = domain("trusted");
    let untrusted = domain("untrusted");
    let step = deterministic_step();
    let policy = incremental_policy(&step, 0, 1);
    let receipt = successful_receipt(input.clone(), trusted.clone(), commitment("artifact"), 1);
    let mut store = OutputStore::new();
    store
        .record_execution(
            trusted,
            &input,
            &step,
            &policy,
            ExecutionRunId::parse("trusted-run").expect("run id"),
            &receipt,
        )
        .expect("trusted output records under its own domain");

    let ReuseDecision::Execute(miss) = store.decide(untrusted, &input, &step, &policy) else {
        panic!("untrusted lookup must not accept trusted output");
    };
    assert!(matches!(*miss, ReuseMiss::ExactOutputAbsent { .. }));
}

#[test]
fn nondeterministic_and_release_verification_reuse_attempts_are_refused() {
    let input = capsule("INCREMENTAL");
    let trusted = domain("trusted");
    let step = deterministic_step();
    let incremental = incremental_policy(&step, 0, 1);
    let receipt = successful_receipt(input.clone(), trusted.clone(), commitment("artifact"), 1);
    let mut store = OutputStore::new();
    store
        .record_execution(
            trusted.clone(),
            &input,
            &step,
            &incremental,
            ExecutionRunId::parse("incremental-run").expect("run id"),
            &receipt,
        )
        .expect("incremental output records");

    let ReuseDecision::Execute(miss) = store.decide(
        trusted.clone(),
        &input,
        &nondeterministic_step(),
        &incremental,
    ) else {
        panic!("declared-nondeterministic step must not reuse output");
    };
    assert!(matches!(*miss, ReuseMiss::NondeterministicDeclaration));

    let release = ReusePolicy::release_verification(
        SpotCheckSchedule::new(1, 1, commitment("release-selection-seed"))
            .expect("release schedule"),
    );
    assert_eq!(
        release.verification_lane(),
        VerificationLane::ReleaseVerification
    );
    let ReuseDecision::Execute(miss) = store.decide(trusted, &input, &step, &release) else {
        panic!("release verification must not accept derived output");
    };
    assert!(matches!(*miss, ReuseMiss::PolicyDenied));
}

#[test]
fn spot_check_mismatch_quarantines_and_emits_negative_evidence() {
    let input = capsule("SPOTCHECK");
    let trusted = domain("trusted");
    let step = deterministic_step();
    let policy = incremental_policy(&step, 1, 1);
    let original = successful_receipt(
        input.clone(),
        trusted.clone(),
        commitment("artifact-before"),
        1,
    );
    let mut store = OutputStore::new();
    store
        .record_execution(
            trusted.clone(),
            &input,
            &step,
            &policy,
            ExecutionRunId::parse("original-run").expect("run id"),
            &original,
        )
        .expect("recorded original output");
    let ReuseDecision::Reuse(reuse) = store.decide(trusted.clone(), &input, &step, &policy) else {
        panic!("exact output should be offered for the scheduled drill");
    };
    assert!(reuse.spot_check_scheduled());

    let reexecution = successful_receipt(
        input.clone(),
        trusted.clone(),
        commitment("artifact-after"),
        2,
    );
    let SpotCheckResult::Mismatch(negative) = store
        .complete_spot_check(
            &reuse,
            ExecutionRunId::parse("reverification-run").expect("run id"),
            &input,
            &reexecution,
        )
        .expect("scheduled spot check is comparable")
    else {
        panic!("changed output must trigger detection and quarantine");
    };
    assert!(negative.evidence().verify(DecodeLimits::default()).is_ok());
    assert_eq!(negative.class().trust_domain().name().as_str(), "trusted");
    assert_eq!(
        negative.reexecution_run_id().as_text().as_str(),
        "reverification-run"
    );

    let ReuseDecision::Execute(miss) = store.decide(trusted, &input, &step, &policy) else {
        panic!("quarantined class must no longer reuse output");
    };
    assert!(matches!(*miss, ReuseMiss::ClassQuarantined { .. }));
}

#[test]
fn representative_warm_workload_reports_hit_rate_latency_and_cost_overhead() {
    let trusted = domain("trusted");
    let step = deterministic_step();
    let policy = incremental_policy(&step, 1, 2);
    let mut store = OutputStore::new();
    let mut inputs = Vec::new();
    let mut artifacts = Vec::new();

    for index in 0..SAMPLE_COUNT {
        let mode = format!("WARM{index:02}");
        let input = capsule(&mode);
        let artifact = commitment(&format!("artifact-{index}"));
        let receipt = successful_receipt(
            input.clone(),
            trusted.clone(),
            artifact,
            u64::from(index) + 1,
        );
        store
            .record_execution(
                trusted.clone(),
                &input,
                &step,
                &policy,
                ExecutionRunId::parse(&format!("warmup-run-{index}")).expect("run id is canonical"),
                &receipt,
            )
            .expect("warmup output records");
        inputs.push(input);
        artifacts.push(artifact);
    }

    let baseline_start = Instant::now();
    for (index, input) in inputs.iter().enumerate() {
        let receipt = successful_receipt(
            input.clone(),
            trusted.clone(),
            artifacts[index],
            u64::try_from(index).expect("sample index fits") + 100,
        );
        assert_eq!(receipt.outcome(), CheckOutcome::Succeeded);
    }
    let baseline_ns = baseline_start.elapsed().as_nanos();

    let reuse_start = Instant::now();
    let mut hits = 0_u32;
    let mut spot_check_reexecutions = 0_u32;
    for (index, input) in inputs.iter().enumerate() {
        let ReuseDecision::Reuse(reuse) = store.decide(trusted.clone(), input, &step, &policy)
        else {
            panic!("warmed exact input must be a reuse hit");
        };
        hits += 1;
        if reuse.spot_check_scheduled() {
            spot_check_reexecutions += 1;
            let reexecution = successful_receipt(
                input.clone(),
                trusted.clone(),
                artifacts[index],
                u64::try_from(index).expect("sample index fits") + 200,
            );
            assert_eq!(
                store
                    .complete_spot_check(
                        &reuse,
                        ExecutionRunId::parse(&format!("sample-run-{index}"))
                            .expect("run id is canonical"),
                        input,
                        &reexecution,
                    )
                    .expect("matched spot check"),
                SpotCheckResult::Matched
            );
        }
    }
    let reuse_ns = reuse_start.elapsed().as_nanos();
    assert!(spot_check_reexecutions > 0);
    assert!(spot_check_reexecutions < SAMPLE_COUNT);

    let hit_rate_ppm = hits * 1_000_000 / SAMPLE_COUNT;
    let avoided_runner_executions = SAMPLE_COUNT - spot_check_reexecutions;
    println!(
        "reuse-campaign-economics schema=frankengit.reuse.economics.v1 workload=runner-control-plane-warm-cache-{SAMPLE_COUNT}-capsules hit_rate_ppm={hit_rate_ppm} baseline_ns={baseline_ns} reuse_ns={reuse_ns} baseline_runner_executions={SAMPLE_COUNT} cache_fill_runner_executions={SAMPLE_COUNT} spot_check_runner_executions={spot_check_reexecutions} avoided_warm_runner_executions={avoided_runner_executions} claim=bounded-control-plane-only"
    );
}
