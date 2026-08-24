#![forbid(unsafe_code)]
//! Public-surface tests for derived runner-output reuse.
//!
//! These tests use a fixed containment substrate only to supply a terminal
//! observation.  Each receipt is still produced by `RunnerControlPlane`, so
//! reuse cannot bypass the runner's capsule, namespace, reaping, or evidence
//! construction boundaries.

use fgit_resource::kinds::{
    ContainmentClass, ExitClass, NetworkPolicy, RunnerReaped, SandboxProfile,
};
use fgit_runner::{
    BuildCommand, BuildInputCapsule, CheckOutcome, Commitment, ContainmentSubstrate,
    DeterminismDeclaration, EnvironmentBinding, ExecutionRunId, JobRequest, LogRedactionReceipt,
    LoweredWorkflowStep, OutputStore, ReuseDecision, ReuseMiss, ReusePolicy, RunnerControlPlane,
    RunnerPolicy, RunnerText, SourceObject, SpotCheckResult, SpotCheckSchedule,
    SubstrateObservation, SubstrateRefusal, TrustDomain, WorkflowStepDeclaration,
};

fn text(value: &str) -> RunnerText {
    RunnerText::parse("reuse-test", value).expect("fixture text is canonical")
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

fn trust_domain(name: &str) -> TrustDomain {
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

fn reuse_policy(step: &LoweredWorkflowStep, numerator: u16, denominator: u16) -> ReusePolicy {
    ReusePolicy::new(
        vec![step.step_id().clone()],
        SpotCheckSchedule::new(numerator, denominator, commitment("selection-seed"))
            .expect("fixture sample schedule is valid"),
    )
    .expect("fixture reuse policy is valid")
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
    domain: TrustDomain,
    artifact: Commitment,
) -> fgit_runner::CheckReceipt {
    let mut broker = fgit_runner::SecretBroker::default();
    let mut control = RunnerControlPlane::new(ceilings(), 1).expect("fixture capacity");
    let policy = RunnerPolicy::new(
        domain,
        SandboxProfile::ProcessIsolated,
        NetworkPolicy::Denied,
        ceilings(),
    )
    .expect("fixture policy is supported");
    let admitted = control
        .admit(
            input,
            policy,
            JobRequest::new(false, Vec::new(), Vec::new(), 1).expect("fixture request"),
            &mut broker,
            1,
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
        log_redaction: LogRedactionReceipt::new(commitment("runner-log"), 0, 0),
        artifacts: vec![artifact],
    });
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("terminal receipt");
    assert_eq!(receipt.outcome(), CheckOutcome::Succeeded);
    receipt
}

#[test]
fn exact_reuse_returns_a_distinct_receipt_naming_the_original_execution() {
    let input = capsule("FAST");
    let domain = trust_domain("trusted");
    let step = deterministic_step();
    let policy = reuse_policy(&step, 0, 1);
    let original = successful_receipt(input.clone(), domain.clone(), commitment("artifact-a"));
    let original_run = ExecutionRunId::parse("run-original").expect("run id");
    let mut store = OutputStore::new();

    store
        .record_execution(
            domain.clone(),
            &input,
            &step,
            &policy,
            original_run.clone(),
            &original,
        )
        .expect("successful exact output is reusable");

    let ReuseDecision::Reuse(reuse) = store.decide(domain, &input, &step, &policy) else {
        panic!("exact identity should reuse the original output");
    };
    assert_eq!(reuse.artifacts(), original.artifacts());
    assert_eq!(reuse.original_execution().run_id(), &original_run);
    assert_eq!(reuse.original_execution().capsule_id(), input.id());
    assert!(!reuse.spot_check_scheduled());
}

#[test]
fn a_single_environment_near_miss_never_hits_the_cache() {
    let recorded_input = capsule("FAST");
    let near_miss = capsule("SAFE");
    let domain = trust_domain("trusted");
    let step = deterministic_step();
    let policy = reuse_policy(&step, 0, 1);
    let original = successful_receipt(
        recorded_input.clone(),
        domain.clone(),
        commitment("artifact-a"),
    );
    let mut store = OutputStore::new();
    store
        .record_execution(
            domain.clone(),
            &recorded_input,
            &step,
            &policy,
            ExecutionRunId::parse("run-original").expect("run id"),
            &original,
        )
        .expect("recorded output");

    let ReuseDecision::Execute(miss) = store.decide(domain, &near_miss, &step, &policy) else {
        panic!("changing one admitted environment binding must miss");
    };
    let ReuseMiss::ExactOutputAbsent { key } = *miss else {
        panic!("near-miss must have no exact output");
    };
    assert_eq!(key.capsule_id(), near_miss.id());
    assert_ne!(recorded_input.id(), near_miss.id());
}

#[test]
fn trust_domains_and_nondeterministic_declarations_never_reuse_outputs() {
    let input = capsule("FAST");
    let trusted = trust_domain("trusted");
    let untrusted = trust_domain("untrusted");
    let deterministic = deterministic_step();
    let policy = reuse_policy(&deterministic, 0, 1);
    let original = successful_receipt(input.clone(), trusted.clone(), commitment("artifact-a"));
    let mut store = OutputStore::new();
    store
        .record_execution(
            trusted.clone(),
            &input,
            &deterministic,
            &policy,
            ExecutionRunId::parse("run-original").expect("run id"),
            &original,
        )
        .expect("recorded trusted output");

    assert!(matches!(
        store.decide(untrusted, &input, &deterministic, &policy),
        ReuseDecision::Execute(miss) if matches!(*miss, ReuseMiss::ExactOutputAbsent { .. })
    ));
    assert!(matches!(
        store.decide(trusted, &input, &nondeterministic_step(), &policy),
        ReuseDecision::Execute(miss)
            if matches!(*miss, ReuseMiss::NondeterministicDeclaration)
    ));
}

#[test]
fn sampled_byte_mismatch_emits_evidence_and_quarantines_the_reuse_class() {
    let input = capsule("FAST");
    let domain = trust_domain("trusted");
    let step = deterministic_step();
    let policy = reuse_policy(&step, 1, 1);
    let original = successful_receipt(input.clone(), domain.clone(), commitment("artifact-old"));
    let mut store = OutputStore::new();
    store
        .record_execution(
            domain.clone(),
            &input,
            &step,
            &policy,
            ExecutionRunId::parse("run-original").expect("run id"),
            &original,
        )
        .expect("recorded output");
    let ReuseDecision::Reuse(reuse) = store.decide(domain.clone(), &input, &step, &policy) else {
        panic!("one-over-one schedule must still return the selected reuse receipt");
    };
    assert!(reuse.spot_check_scheduled());

    let reexecution = successful_receipt(input.clone(), domain.clone(), commitment("artifact-new"));
    let SpotCheckResult::Mismatch(negative) = store
        .complete_spot_check(
            &reuse,
            ExecutionRunId::parse("run-reexecution").expect("run id"),
            &input,
            &reexecution,
        )
        .expect("scheduled reexecution is comparable")
    else {
        panic!("different artifact bytes must be a mismatch");
    };
    assert_eq!(
        negative.original_execution().run_id().as_text().as_str(),
        "run-original"
    );
    assert_eq!(
        negative.reexecution_run_id().as_text().as_str(),
        "run-reexecution"
    );
    assert_ne!(negative.expected_artifacts(), negative.observed_artifacts());
    assert!(
        negative
            .evidence()
            .verify(fgit_codec::DecodeLimits::default())
            .is_ok()
    );

    assert!(matches!(
        store.decide(domain, &input, &step, &policy),
        ReuseDecision::Execute(miss) if matches!(*miss, ReuseMiss::ClassQuarantined { .. })
    ));
}
