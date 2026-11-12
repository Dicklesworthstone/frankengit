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
    BuildCommand, BuildInputCapsule, CheckOutcome, CheckReceipt, Commitment, ContainmentSubstrate,
    DeterminismDeclaration, EnvironmentBinding, ExecutionRunId, JobRequest, LogRedactionReceipt,
    LoweredWorkflowStep, OutputStore, ReuseDecision, ReuseMiss, ReuseNegativeEvidence, ReusePolicy,
    ReuseReceipt, ReuseRefusal, ReuseReverification, RunnerControlPlane, RunnerPolicy, RunnerText,
    SourceObject, SpotCheckResult, SpotCheckSchedule, SubstrateObservation, SubstrateRefusal,
    TrustDomain, WorkflowStepDeclaration,
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
    execution_receipt(input, domain, vec![artifact], 1, ExitClass::Succeeded)
}

fn execution_receipt(
    input: BuildInputCapsule,
    domain: TrustDomain,
    artifacts: Vec<Commitment>,
    logical_order: u64,
    exit: ExitClass,
) -> CheckReceipt {
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
            JobRequest::new(false, Vec::new(), Vec::new(), logical_order).expect("fixture request"),
            &mut broker,
            logical_order,
        )
        .expect("fixture run is admitted");
    let mut substrate = FixedSubstrate(SubstrateObservation {
        exit,
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
        artifacts,
    });
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("terminal receipt");
    assert_eq!(receipt.logical_order(), logical_order);
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

    let reexecution = execution_receipt(
        input.clone(),
        domain.clone(),
        vec![commitment("artifact-new")],
        2,
        ExitClass::Succeeded,
    );
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

fn run_id(label: &str) -> ExecutionRunId {
    ExecutionRunId::parse(label).expect("fixture run identity")
}

struct QuarantinedClass {
    store: OutputStore,
    domain: TrustDomain,
    step: LoweredWorkflowStep,
    policy: ReusePolicy,
    inputs: [BuildInputCapsule; 2],
    originals: [CheckReceipt; 2],
    selected: [Box<ReuseReceipt>; 2],
    negative: Box<ReuseNegativeEvidence>,
}

impl QuarantinedClass {
    fn new() -> Self {
        let domain = trust_domain("trusted");
        let step = deterministic_step();
        let policy = reuse_policy(&step, 1, 1);
        let inputs = [capsule("FIRST"), capsule("SECOND")];
        let originals = std::array::from_fn(|index| {
            execution_receipt(
                inputs[index].clone(),
                domain.clone(),
                vec![
                    commitment(&format!("artifact-{index}-first")),
                    commitment(&format!("artifact-{index}-second")),
                ],
                u64::try_from(index).expect("fixture index") + 1,
                ExitClass::Succeeded,
            )
        });
        let mut store = OutputStore::new();
        for index in 0..2 {
            store
                .record_execution(
                    domain.clone(),
                    &inputs[index],
                    &step,
                    &policy,
                    run_id(&format!("producer-{index}")),
                    &originals[index],
                )
                .expect("record original output");
        }
        let selected = std::array::from_fn(|index| {
            let ReuseDecision::Reuse(reuse) =
                store.decide(domain.clone(), &inputs[index], &step, &policy)
            else {
                panic!("original output must be reusable before quarantine");
            };
            reuse
        });
        let mismatch = execution_receipt(
            inputs[0].clone(),
            domain.clone(),
            vec![commitment("unexpected-output")],
            10,
            ExitClass::Succeeded,
        );
        let SpotCheckResult::Mismatch(negative) = store
            .complete_spot_check(
                &selected[0],
                run_id("quarantining-run"),
                &inputs[0],
                &mismatch,
            )
            .expect("scheduled mismatch produces negative evidence")
        else {
            panic!("changed output must quarantine the class");
        };
        Self {
            store,
            domain,
            step,
            policy,
            inputs,
            originals,
            selected,
            negative,
        }
    }

    fn quarantine(&self) -> Box<ReuseNegativeEvidence> {
        let mut observed = None;
        for input in &self.inputs {
            let ReuseDecision::Execute(miss) =
                self.store
                    .decide(self.domain.clone(), input, &self.step, &self.policy)
            else {
                panic!("every member of the class must remain quarantined");
            };
            let ReuseMiss::ClassQuarantined { evidence, .. } = *miss else {
                panic!("lookup must name the class quarantine");
            };
            if let Some(previous) = &observed {
                assert_eq!(previous, &evidence);
            }
            observed = Some(evidence);
        }
        observed.expect("fixture has two class members")
    }

    fn matching(&self, orders: [u64; 2]) -> [CheckReceipt; 2] {
        std::array::from_fn(|index| {
            execution_receipt(
                self.inputs[index].clone(),
                self.domain.clone(),
                self.originals[index].artifacts().to_vec(),
                orders[index],
                ExitClass::Succeeded,
            )
        })
    }

    fn reverify(
        &mut self,
        witness: &ReuseNegativeEvidence,
        receipts: &[CheckReceipt; 2],
    ) -> Result<(), ReuseRefusal> {
        self.store.reverify_class(
            witness,
            &self.step,
            &self.policy,
            &observations(&self.inputs, receipts),
        )
    }

    fn assert_original_provenance(&self) {
        for index in 0..2 {
            let ReuseDecision::Reuse(reuse) = self.store.decide(
                self.domain.clone(),
                &self.inputs[index],
                &self.step,
                &self.policy,
            ) else {
                panic!("complete reverification must restore exact reuse");
            };
            assert_eq!(reuse, self.selected[index]);
            assert_eq!(
                reuse.original_execution().evidence(),
                self.originals[index].evidence()
            );
        }
    }
}

fn observations<'a>(
    inputs: &'a [BuildInputCapsule; 2],
    receipts: &'a [CheckReceipt; 2],
) -> [ReuseReverification<'a>; 2] {
    std::array::from_fn(|index| {
        // Fresh fixture executions advance both their evidence-bound order
        // and their identity; replaying a receipt retains the same identity.
        ReuseReverification::new(
            &inputs[index],
            run_id(&format!(
                "recovery-{index}-{}",
                receipts[index].logical_order()
            )),
            &receipts[index],
        )
    })
}

#[test]
fn replaying_the_original_receipt_never_clears_class_quarantine() {
    let mut fixture = QuarantinedClass::new();
    fixture
        .store
        .record_execution(
            fixture.domain.clone(),
            &fixture.inputs[0],
            &fixture.step,
            &fixture.policy,
            run_id("producer-0"),
            &fixture.originals[0],
        )
        .expect("recording the identical producer is idempotent");
    assert_eq!(fixture.quarantine(), fixture.negative);
}

#[test]
fn new_capsules_stay_quarantined_and_must_join_complete_class_reverification() {
    let mut fixture = QuarantinedClass::new();
    let input = capsule("ADDED-DURING-QUARANTINE");
    let original = execution_receipt(
        input.clone(),
        fixture.domain.clone(),
        vec![commitment("new-artifact")],
        40,
        ExitClass::Succeeded,
    );
    fixture
        .store
        .record_execution(
            fixture.domain.clone(),
            &input,
            &fixture.step,
            &fixture.policy,
            run_id("new-producer"),
            &original,
        )
        .expect("new exact output may be recorded while its class is quarantined");
    assert_eq!(fixture.quarantine(), fixture.negative);
    assert!(matches!(
        fixture.store.decide(fixture.domain.clone(), &input, &fixture.step, &fixture.policy),
        ReuseDecision::Execute(miss) if matches!(*miss, ReuseMiss::ClassQuarantined { .. })
    ));
    let witness = fixture.quarantine();
    let matching = fixture.matching([50, 50]);
    assert_eq!(
        fixture.reverify(&witness, &matching),
        Err(ReuseRefusal::ReverificationCoverageMismatch)
    );

    // The added producer's own order is also a fence, even though it was
    // recorded after the original failed spot check at order 10.
    let before_producer = execution_receipt(
        input.clone(),
        fixture.domain.clone(),
        original.artifacts().to_vec(),
        30,
        ExitClass::Succeeded,
    );
    let mut complete = observations(&fixture.inputs, &matching).to_vec();
    complete.push(ReuseReverification::new(
        &input,
        run_id("new-recovery"),
        &before_producer,
    ));
    assert_eq!(
        fixture
            .store
            .reverify_class(&witness, &fixture.step, &fixture.policy, &complete),
        Err(ReuseRefusal::ReexecutionNotFresh)
    );
    assert_eq!(fixture.quarantine(), witness);

    let fresh = execution_receipt(
        input.clone(),
        fixture.domain.clone(),
        original.artifacts().to_vec(),
        50,
        ExitClass::Succeeded,
    );
    complete[2] = ReuseReverification::new(&input, run_id("new-recovery"), &fresh);
    fixture
        .store
        .reverify_class(&witness, &fixture.step, &fixture.policy, &complete)
        .expect("all three exact keys were freshly reverified");
    fixture.assert_original_provenance();
    let ReuseDecision::Reuse(reuse) = fixture.store.decide(
        fixture.domain.clone(),
        &input,
        &fixture.step,
        &fixture.policy,
    ) else {
        panic!("new class member must become reusable only with the whole class");
    };
    assert_eq!(reuse.original_execution().run_id(), &run_id("new-producer"));
    assert_eq!(reuse.original_execution().evidence(), original.evidence());
}

#[test]
fn complete_reverification_rejects_missing_duplicate_and_foreign_keys_without_replacing_producers()
{
    let mut fixture = QuarantinedClass::new();
    let witness = fixture.quarantine();
    let matching = fixture.matching([20, 20]);
    let complete = observations(&fixture.inputs, &matching);
    let foreign = capsule("NOT-IN-THIS-CLASS");
    let foreign_receipt = successful_receipt(
        foreign.clone(),
        fixture.domain.clone(),
        commitment("foreign"),
    );
    let cases = [
        Vec::new(),
        vec![complete[0].clone()],
        vec![complete[0].clone(), complete[0].clone()],
        vec![
            complete[0].clone(),
            ReuseReverification::new(&foreign, run_id("foreign-run"), &foreign_receipt),
        ],
    ];
    for candidate in cases {
        assert_eq!(
            fixture
                .store
                .reverify_class(&witness, &fixture.step, &fixture.policy, &candidate),
            Err(ReuseRefusal::ReverificationCoverageMismatch)
        );
        assert_eq!(fixture.quarantine(), witness);
    }
    // A fresh producer cannot replace the old provenance through insertion.
    assert_eq!(
        fixture.store.record_execution(
            fixture.domain.clone(),
            &fixture.inputs[0],
            &fixture.step,
            &fixture.policy,
            run_id("replacement-producer"),
            &matching[0],
        ),
        Err(ReuseRefusal::ConflictingExactOutput)
    );
    let reversed = [complete[1].clone(), complete[0].clone()];
    fixture
        .store
        .reverify_class(&witness, &fixture.step, &fixture.policy, &reversed)
        .expect("complete recovery is independent of candidate order");
    fixture.assert_original_provenance();
    assert_eq!(
        fixture.reverify(&witness, &matching),
        Err(ReuseRefusal::ClassNotQuarantined)
    );
}

#[test]
fn renamed_original_receipts_and_nonadvancing_orders_are_never_fresh_reexecutions() {
    let mut fixture = QuarantinedClass::new();
    let witness = fixture.quarantine();
    assert_eq!(
        fixture.store.complete_spot_check(
            &fixture.selected[0],
            run_id("renamed-original"),
            &fixture.inputs[0],
            &fixture.originals[0],
        ),
        Err(ReuseRefusal::ReexecutionNotFresh)
    );
    let renamed_originals = fixture.originals.clone();
    assert_eq!(
        fixture.reverify(&witness, &renamed_originals),
        Err(ReuseRefusal::ReexecutionNotFresh)
    );
    let not_after_quarantine = fixture.matching([10, 20]);
    assert_eq!(
        fixture.reverify(&witness, &not_after_quarantine),
        Err(ReuseRefusal::ReexecutionNotFresh)
    );
    let matching = fixture.matching([20, 20]);
    for (identity, refusal) in [
        ("producer-0", ReuseRefusal::ReexecutionUsesOriginalRun),
        ("producer-1", ReuseRefusal::ReexecutionUsesOriginalRun),
        (
            "quarantining-run",
            ReuseRefusal::ReexecutionUsesQuarantiningRun,
        ),
    ] {
        let mut candidate = observations(&fixture.inputs, &matching);
        candidate[0] = ReuseReverification::new(&fixture.inputs[0], run_id(identity), &matching[0]);
        assert_eq!(
            fixture
                .store
                .reverify_class(&witness, &fixture.step, &fixture.policy, &candidate),
            Err(refusal)
        );
        assert_eq!(fixture.quarantine(), witness);
    }
    let mut duplicate_runs = observations(&fixture.inputs, &matching);
    duplicate_runs[1] = ReuseReverification::new(
        &fixture.inputs[1],
        run_id(&format!("recovery-0-{}", matching[0].logical_order())),
        &matching[1],
    );
    assert_eq!(
        fixture
            .store
            .reverify_class(&witness, &fixture.step, &fixture.policy, &duplicate_runs,),
        Err(ReuseRefusal::DuplicateReexecutionRun)
    );
    assert_eq!(fixture.quarantine(), witness);
}

#[test]
fn policy_and_binding_refusals_do_not_partially_change_quarantine_or_other_trust_domains() {
    let mut fixture = QuarantinedClass::new();
    let witness = fixture.quarantine();
    let matching = fixture.matching([20, 20]);
    let complete = observations(&fixture.inputs, &matching);
    let denied = ReusePolicy::new(Vec::new(), fixture.policy.spot_checks()).expect("empty policy");
    let release = ReusePolicy::release_verification(fixture.policy.spot_checks());
    for policy in [&denied, &release] {
        assert_eq!(
            fixture
                .store
                .reverify_class(&witness, &fixture.step, policy, &complete),
            Err(ReuseRefusal::StepNotPermitted)
        );
    }
    assert_eq!(
        fixture.store.reverify_class(
            &witness,
            &nondeterministic_step(),
            &fixture.policy,
            &complete
        ),
        Err(ReuseRefusal::NondeterministicStep)
    );

    let untrusted = trust_domain("untrusted");
    let other = execution_receipt(
        fixture.inputs[1].clone(),
        untrusted.clone(),
        matching[1].artifacts().to_vec(),
        50,
        ExitClass::Succeeded,
    );
    fixture
        .store
        .record_execution(
            untrusted.clone(),
            &fixture.inputs[1],
            &fixture.step,
            &fixture.policy,
            run_id("untrusted-producer"),
            &other,
        )
        .expect("separate trust namespace records normally");
    let mismatch = execution_receipt(
        fixture.inputs[0].clone(),
        fixture.domain.clone(),
        vec![commitment("wrong")],
        50,
        ExitClass::Succeeded,
    );
    let candidate = [
        ReuseReverification::new(&fixture.inputs[0], run_id("mismatching-run"), &mismatch),
        ReuseReverification::new(&fixture.inputs[1], run_id("wrong-domain-run"), &other),
    ];
    for observations in [
        candidate.clone(),
        [candidate[1].clone(), candidate[0].clone()],
    ] {
        assert_eq!(
            fixture
                .store
                .reverify_class(&witness, &fixture.step, &fixture.policy, &observations),
            Err(ReuseRefusal::ReceiptBindingMismatch)
        );
        assert_eq!(fixture.quarantine(), witness);
    }
    assert!(matches!(
        fixture.store.decide(
            untrusted,
            &fixture.inputs[1],
            &fixture.step,
            &fixture.policy
        ),
        ReuseDecision::Reuse(_)
    ));
}

#[test]
fn failed_recovery_advances_negative_evidence_before_any_later_retry_can_clear_the_class() {
    for exit in [
        ExitClass::Succeeded,
        ExitClass::Failed,
        ExitClass::Cancelled,
    ] {
        let mut fixture = QuarantinedClass::new();
        let old_witness = fixture.quarantine();
        let mut candidate = fixture.matching([30, 40]);
        let mut artifacts = candidate[1].artifacts().to_vec();
        artifacts.reverse();
        candidate[1] = execution_receipt(
            fixture.inputs[1].clone(),
            fixture.domain.clone(),
            artifacts,
            40,
            exit,
        );
        let refusal = if exit == ExitClass::Succeeded {
            ReuseRefusal::ReexecutionOutputMismatch
        } else {
            assert_ne!(candidate[1].outcome(), CheckOutcome::Succeeded);
            ReuseRefusal::ExecutionDidNotSucceed
        };
        assert_eq!(fixture.reverify(&old_witness, &candidate), Err(refusal));
        let current = fixture.quarantine();
        assert_ne!(current, old_witness);
        assert_eq!(current.reexecution_logical_order(), 40);
        assert_eq!(current.observed_artifacts(), candidate[1].artifacts());
        assert!(
            current
                .evidence()
                .verify(fgit_codec::DecodeLimits::default())
                .is_ok()
        );
        let older_matching = fixture.matching([35, 35]);
        assert_eq!(
            fixture.reverify(&old_witness, &older_matching),
            Err(ReuseRefusal::QuarantineEvidenceMismatch)
        );
        assert_eq!(
            fixture.reverify(&current, &older_matching),
            Err(ReuseRefusal::ReexecutionNotFresh)
        );
        assert_eq!(fixture.quarantine(), current);
        let fresh_matching = fixture.matching([50, 50]);
        fixture
            .reverify(&current, &fresh_matching)
            .expect("fresh whole-class match recovers");
        fixture.assert_original_provenance();
    }
}

#[test]
fn adverse_reverification_evidence_and_result_do_not_depend_on_candidate_order() {
    let mut forward = QuarantinedClass::new();
    let mut reverse = QuarantinedClass::new();
    let witness = forward.quarantine();
    let mut receipts = forward.matching([30, 30]);
    receipts[0] = execution_receipt(
        forward.inputs[0].clone(),
        forward.domain.clone(),
        vec![commitment("mismatch")],
        30,
        ExitClass::Succeeded,
    );
    receipts[1] = execution_receipt(
        forward.inputs[1].clone(),
        forward.domain.clone(),
        Vec::new(),
        30,
        ExitClass::Failed,
    );
    assert_eq!(
        forward.reverify(&witness, &receipts),
        Err(ReuseRefusal::ExecutionDidNotSucceed)
    );
    let candidates = observations(&reverse.inputs, &receipts);
    let reversed = [candidates[1].clone(), candidates[0].clone()];
    assert_eq!(
        reverse
            .store
            .reverify_class(&witness, &reverse.step, &reverse.policy, &reversed),
        Err(ReuseRefusal::ExecutionDidNotSucceed)
    );
    assert_eq!(forward.quarantine(), reverse.quarantine());
    assert_eq!(forward.quarantine().reexecution_logical_order(), 30);
}

#[test]
fn out_of_order_failed_spot_checks_never_lower_the_reverification_fence() {
    let mut fixture = QuarantinedClass::new();
    let mut latest = None;
    for order in [100, 90] {
        let mismatch = execution_receipt(
            fixture.inputs[0].clone(),
            fixture.domain.clone(),
            vec![commitment("wrong")],
            order,
            ExitClass::Succeeded,
        );
        let SpotCheckResult::Mismatch(negative) = fixture
            .store
            .complete_spot_check(
                &fixture.selected[0],
                run_id(&format!("spot-check-{order}")),
                &fixture.inputs[0],
                &mismatch,
            )
            .expect("fresh scheduled mismatch produces evidence")
        else {
            panic!("different output must remain an adverse observation");
        };
        if order == 100 {
            latest = Some(negative);
        }
    }
    let witness = fixture.quarantine();
    assert_eq!(Some(witness.clone()), latest);
    let stale_matching = fixture.matching([95, 95]);
    assert_eq!(
        fixture.reverify(&witness, &stale_matching),
        Err(ReuseRefusal::ReexecutionNotFresh)
    );
    let fresh_matching = fixture.matching([101, 101]);
    fixture
        .reverify(&witness, &fresh_matching)
        .expect("recovery advances past newest failure");
    fixture.assert_original_provenance();
}
