//! Producer/consumer round trips use the real coordinator and report encoder.
//! The executor is a control-flow fixture, not a hostile-code isolation test.
use super::*;
use crate::{CoordinatorLimits, ResourceCeilings, TriggerContext, WorkflowCoordinator};
use crate::workflow::{StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowExecutor, WorkflowLimits, WorkflowPlan};
use std::cell::Cell;

const SOURCE: &str = "name: observed\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - name: first\n        run: echo first\n      - if: always()\n        run: echo diagnostic\n  test:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: echo test\n";

struct Worker { outcome: StepOutcome, begins: usize, closes: usize }
impl WorkflowExecutor for Worker {
    fn begin_job(&mut self, _: usize, _: &fgit_schema::workflow::Job, _: &dyn Fn() -> bool) -> Result<(), WorkerFailure> {
        self.begins += 1; Ok(())
    }
    fn execute_step(&mut self, _: usize, _: &str, _: StepLimits, _: &dyn Fn() -> bool) -> Result<StepObservation, WorkerFailure> {
        Ok(StepObservation { outcome: self.outcome,
            exit_code: Some(if self.outcome == StepOutcome::Succeeded { 0 } else { 1 }),
            stdout: vec![0, 255, 27, b'[', b'm'], stderr: "π diagnostic\n".as_bytes().to_vec(),
            elapsed_millis: 1, output_complete: true,
            retain_workspace: self.outcome == StepOutcome::ContainmentFailure })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> { self.closes += 1; Ok(()) }
}
pub(super) fn produce(format: bool, outcome: StepOutcome) -> (CheckDeliveryBatch, TrustedWorkflowReceipt) {
    let mut c = WorkflowCoordinator::new(CoordinatorLimits::default(),
        ResourceCeilings::new(100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, 60_000).unwrap(), 4).unwrap();
    let source = if format { GitOid::Sha256(GitOidSha256::from_bytes([3; 32])) }
        else { GitOid::Sha1(GitOidSha1::from_bytes([3; 20])) };
    let limits = WorkflowLimits { step_timeout: Duration::new(1, 37),
        run_timeout: Duration::new(2, 53), ..WorkflowLimits::default() };
    let mut prepared = c.enqueue_trusted_workflow(TenantId::from_bytes([1;16]), RepositoryId::from_bytes([2;16]),
        Commitment::of_bytes(b"head"), source, WorkflowPlan::compile(SOURCE).unwrap(), limits,
        TriggerContext::trusted_push("fixture"), 1, 100).unwrap();
    let mut worker = Worker { outcome, begins: 0, closes: 0 };
    let receipt = c.execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true).unwrap().clone();
    assert!(worker.begins > 0);
    assert_eq!(worker.begins, worker.closes);
    let batch = c.prepare_check_delivery(128, 1024 * 1024).unwrap().unwrap();
    (batch, receipt)
}
fn decode(bytes: &[u8]) -> Result<VerifiedLocalObservation, ObservationRefusal> {
    decode_trusted_observation(bytes, Commitment::of_bytes(bytes), MAX_OBSERVATION_BYTES, &|| true)
}
pub(super) fn selected(batch: &CheckDeliveryBatch) -> usize {
    batch.facts().iter().position(|fact| fact.status == CheckRunStatus::Completed).unwrap()
}
pub(super) fn rebind_hash(batch: &CheckDeliveryBatch, index: usize, bytes: &[u8]) -> CheckDeliveryBatch {
    let old = batch.facts()[index].receipt_commitment.unwrap();
    let old_digest = old.digest();
    let raw = old_digest.bytes();
    let positions = batch.body().windows(32).enumerate().filter_map(|(i, part)|
        (part == raw.as_bytes()).then_some(i)).collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let mut body = batch.body().to_vec();
    body[positions[0]..positions[0]+32].copy_from_slice(Commitment::of_bytes(bytes).digest().bytes().as_bytes());
    CheckDeliveryBatch::decode(&body).unwrap()
}
fn change_json(receipt: &TrustedWorkflowReceipt, change: impl FnOnce(String) -> String) -> Vec<u8> {
    let mut frame = receipt.frame();
    let old = receipt.report().to_json();
    let start = frame.len() - old.len() - 8;
    frame.truncate(start);
    let new = change(old);
    frame.extend_from_slice(&(new.len() as u64).to_be_bytes());
    frame.extend_from_slice(new.as_bytes());
    frame
}

#[test]
fn production_reports_and_each_job_round_trip_in_both_hash_domains() {
    for sha256 in [false, true] {
        for outcome in [StepOutcome::Succeeded, StepOutcome::Failed, StepOutcome::Cancelled,
            StepOutcome::TimedOut, StepOutcome::OutputLimit, StepOutcome::ContainmentFailure] {
            let (batch, receipt) = produce(sha256, outcome);
            let decoded = decode(&receipt.frame()).unwrap();
            assert_eq!(decoded.report(), receipt.report());
            assert_eq!(decoded.receipt.frame(), receipt.frame());
            assert_eq!(decoded.report().limits.step_timeout.subsec_nanos(), 37);
            assert_eq!(decoded.report().limits.run_timeout.subsec_nanos(), 53);
            assert_eq!(decoded.requires_containment(), receipt.report.jobs.iter().any(|job| job.requires_containment()));
            for (index, fact) in batch.facts().iter().enumerate() {
                if fact.status != CheckRunStatus::Completed { continue; }
                let bytes = receipt.job_frame(&fact.job_id).unwrap();
                let one = verify_trusted_job(&batch, index, &bytes, MAX_OBSERVATION_BYTES, &|| true).unwrap();
                assert_eq!(one.report().jobs.len(), 1);
                assert_eq!(one.report().jobs[0], *receipt.report.jobs.iter().find(|job| job.id == fact.job_id).unwrap());
                assert_eq!(one.evidence(), fact.receipt_commitment.unwrap());
                assert!(!one.report_json().contains("\"authoritative_check\":true"));
            }
        }
    }
}

#[test]
fn valid_hash_never_substitutes_for_any_proposal_subject_coordinate() {
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let index = selected(&batch);
    let id = &batch.facts()[index].job_id;
    for coordinate in 0..11 {
        let mut other = receipt.clone();
        match coordinate {
            0 => other.binding.run = WorkflowRunId(Commitment::of_bytes(b"other run")),
            1 => other.binding.attempt = AttemptId(Commitment::of_bytes(b"other attempt")),
            2 => other.binding.tenant = TenantId::from_bytes([8;16]),
            3 => other.binding.repository = RepositoryId::from_bytes([8;16]),
            4 => other.binding.head = Commitment::of_bytes(b"other head"),
            5 => other.binding.source = GitOid::Sha1(GitOidSha1::from_bytes([8;20])),
            6 => other.binding.trust = TrustDomain::new(RunnerText::parse("trust", "other").unwrap()),
            7 => other.report.source = Commitment::of_bytes(b"other workflow"),
            8 => other.report.graph = Commitment::of_bytes(b"other graph"),
            9 => other.report.limits.step_timeout += Duration::from_nanos(1),
            10 => other.logical_now += 1,
            _ => unreachable!(),
        }
        let bytes = other.job_frame(id).unwrap();
        assert!(decode(&bytes).is_ok(), "coordinate {coordinate} must be a valid independent record");
        let changed = rebind_hash(&batch, index, &bytes);
        assert_eq!(verify_trusted_job(&changed, index, &bytes, MAX_OBSERVATION_BYTES, &|| true),
            Err(ObservationRefusal::BindingMismatch), "coordinate {coordinate}");
    }
}

#[test]
fn full_workflow_wrong_job_and_changed_conclusion_are_not_single_job_proofs() {
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let index = selected(&batch);
    for bytes in [receipt.frame(), receipt.job_frame("test").unwrap()] {
        let changed = rebind_hash(&batch, index, &bytes);
        assert_eq!(verify_trusted_job(&changed, index, &bytes, MAX_OBSERVATION_BYTES, &|| true), Err(ObservationRefusal::BindingMismatch));
    }
    let mut failed = receipt.clone();
    failed.report.jobs[0].outcome = JobOutcome::Failed;
    failed.report.jobs[0].steps[0].observation.outcome = StepOutcome::Failed;
    failed.report.jobs[0].steps[0].observation.exit_code = Some(1);
    let bytes = failed.job_frame("build").unwrap();
    assert!(decode(&bytes).is_ok());
    let changed = rebind_hash(&batch, index, &bytes);
    assert_eq!(verify_trusted_job(&changed, index, &bytes, MAX_OBSERVATION_BYTES, &|| true), Err(ObservationRefusal::BindingMismatch));
    assert_eq!(verify_trusted_job(&batch, 0, &[], MAX_OBSERVATION_BYTES, &|| true), Err(ObservationRefusal::FactNotCompleted));
    assert_eq!(verify_trusted_job(&batch, usize::MAX, &[], MAX_OBSERVATION_BYTES, &|| true), Err(ObservationRefusal::FactNotCompleted));
}

#[test]
fn every_truncation_and_suffix_refuses_even_with_its_own_valid_hash() {
    let (_, receipt) = produce(false, StepOutcome::Succeeded);
    let bytes = receipt.job_frame("build").unwrap();
    for end in 0..bytes.len() { assert!(decode(&bytes[..end]).is_err(), "prefix {end}"); }
    for suffix in [b"\0".as_slice(), b"{}", bytes.as_slice()] {
        let mut bad = bytes.clone(); bad.extend_from_slice(suffix); assert!(decode(&bad).is_err());
    }
    let mut bad = bytes.clone(); bad[0] ^= 1;
    assert_eq!(decode_trusted_observation(&bad, Commitment::of_bytes(&bytes), MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::CommitmentMismatch));
}

#[test]
fn json_summary_authority_environment_limits_and_unknown_fields_cannot_drift() {
    let (_, receipt) = produce(false, StepOutcome::Succeeded);
    for (old, new) in [
        ("\"authoritative_check\":false", "\"authoritative_check\":true"),
        ("\"schema_version\":1", "\"schema_version\":2"),
        ("\"succeeded\":true", "\"succeeded\":false"),
        ("\"step_timeout_millis\":1000", "\"step_timeout_millis\":1001"),
        ("/usr/bin:/bin", "/tmp/bin"),
        ("\"LANG\":\"C\"", "\"LANG\":\"C\",\"secret\":true"),
        ("\"index\":0", "\"index\":00"),
        ("\"index\":0", "\"index\":18446744073709551616"),
        ("\"exit_code\":0", "\"exit_code\":2147483648"),
        ("\"output_complete\":true", "\"output_complete\":false"),
        ("\"workspace_retained\":false", "\"workspace_retained\":true"),
        ("\"stream_bytes\":262144", "\"stream_bytes\":1"),
    ] {
        let bytes = change_json(&receipt, |text| { assert!(text.contains(old), "{old}"); text.replacen(old, new, 1) });
        assert!(decode(&bytes).is_err(), "accepted {old} -> {new}");
    }
}

#[test]
fn binary_logs_unicode_control_names_and_signed_exits_are_byte_exact() {
    let (_, mut receipt) = produce(false, StepOutcome::Failed);
    let job = &mut receipt.report.jobs[0];
    job.failure = Some(WorkerFailure::new("why\0\t\n\r\u{1f} π\\\"", false));
    job.steps[0].name = Some("name\0\t\n\r\u{1f} π\\\"".to_owned());
    job.steps[0].observation.stdout = (0..=255).collect();
    for code in [i32::MIN, -1, 0, i32::MAX] {
        receipt.report.jobs[0].steps[0].observation.exit_code = Some(code);
        assert_eq!(decode(&receipt.frame()).unwrap().report(), receipt.report());
    }
}

#[test]
fn identity_collections_and_output_bounds_refuse_before_unbounded_growth() {
    let (_, receipt) = produce(false, StepOutcome::Succeeded);
    let mut duplicate = receipt.clone();
    duplicate.report.jobs[1].id = duplicate.report.jobs[0].id.clone();
    assert!(decode(&duplicate.frame()).is_err());
    let mut zero = receipt.clone(); zero.attempts.insert("build".to_owned(), 0);
    assert!(decode(&zero.frame()).is_err());
    let mut backwards = receipt.clone(); backwards.report.jobs[0].steps[1].index = 0;
    assert!(decode(&backwards.frame()).is_err());
    let mut aggregate = receipt.clone(); aggregate.report.limits.total_output_bytes = 16;
    assert!(decode(&aggregate.frame()).is_err());
    let bytes = receipt.frame();
    assert_eq!(decode_trusted_observation(&bytes, Commitment::of_bytes(&bytes), bytes.len()-1, &|| true), Err(ObservationRefusal::RecordTooLarge));
    assert!(decode_trusted_observation(&bytes, Commitment::of_bytes(&bytes), bytes.len(), &|| true).is_ok());
    for maximum in [0, MAX_OBSERVATION_BYTES + 1] {
        assert_eq!(decode_trusted_observation(&bytes, Commitment::of_bytes(&bytes), maximum, &|| true), Err(ObservationRefusal::InvalidLimits));
    }
}

#[test]
fn cancellation_never_returns_partially_decoded_evidence() {
    let (_, receipt) = produce(false, StepOutcome::Succeeded);
    let bytes = receipt.frame();
    for allowed in [0, 1, 2, 3, 4] {
        let polls = Cell::new(0);
        let live = || { let count = polls.get(); polls.set(count + 1); count < allowed };
        assert_eq!(decode_trusted_observation(&bytes, Commitment::of_bytes(&bytes), MAX_OBSERVATION_BYTES, &live), Err(ObservationRefusal::Cancelled));
    }
}

#[test]
fn one_job_workflow_full_receipt_is_the_same_exact_job_body() {
    let mut c = WorkflowCoordinator::new(CoordinatorLimits::default(),
        ResourceCeilings::new(100_000, 512*1024*1024, 1024*1024*1024, 0, 16, 60_000).unwrap(), 4).unwrap();
    let source = "name: one\non: push\njobs:\n  only:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: fixture\n";
    let mut prepared = c.enqueue_trusted_workflow(TenantId::from_bytes([1;16]), RepositoryId::from_bytes([2;16]),
        Commitment::of_bytes(b"head"), GitOid::Sha1(GitOidSha1::from_bytes([3;20])), WorkflowPlan::compile(source).unwrap(),
        WorkflowLimits::default(), TriggerContext::trusted_push("fixture"), 1, 100).unwrap();
    let mut worker = Worker { outcome: StepOutcome::Succeeded, begins: 0, closes: 0 };
    let receipt = c.execute_trusted_workflow(&mut prepared, &mut worker, 200, &|| true).unwrap().clone();
    let batch = c.prepare_check_delivery(128, 1024*1024).unwrap().unwrap();
    assert_eq!(receipt.frame(), receipt.job_frame("only").unwrap());
    let verified = verify_trusted_job(&batch, selected(&batch), &receipt.frame(), MAX_OBSERVATION_BYTES, &|| true).unwrap();
    assert_eq!(verified.report(), receipt.report());
}
