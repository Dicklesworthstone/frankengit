#![forbid(unsafe_code)]
use fgit_runner::workflow::{
    JobOutcome, StepLimits, StepObservation, StepOutcome, WorkerFailure,
    WorkflowExecutor, WorkflowLimits, WorkflowPlan,
};
use fgit_schema::workflow::Job;

#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    fail: &'static str,
    retain_on: &'static str,
}
impl WorkflowExecutor for Fake {
    fn begin_job(&mut self, _: usize, job: &Job, _: &dyn Fn() -> bool) -> Result<(), WorkerFailure> {
        self.calls.push(format!("begin:{}", job.id));
        Ok(())
    }
    fn execute_step(&mut self, index: usize, script: &str, _: StepLimits, _: &dyn Fn() -> bool)
        -> Result<StepObservation, WorkerFailure>
    {
        self.calls.push(format!("step:{index}:{script}"));
        let failed = script == self.fail;
        Ok(StepObservation {
            outcome: if failed { StepOutcome::Failed } else { StepOutcome::Succeeded },
            exit_code: Some(if failed { 7 } else { 0 }),
            stdout: Vec::new(), stderr: Vec::new(), elapsed_millis: 1,
            output_complete: true, retain_workspace: script == self.retain_on,
        })
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.calls.push(format!("finish:{retain}"));
        Ok(())
    }
}

const FLOW: &str = "name: diagnostics\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: build\n      - run: forbidden-success\n      - if: failure()\n        run: same-job-failure-diagnostic\n      - if: always()\n        run: same-job-always-diagnostic\n  cleanup:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: always()\n    steps:\n      - run: dependent-always\n  failure-report:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: failure()\n    steps:\n      - run: dependent-failure\n  success-only:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: forbidden-dependent-success\n";

#[test]
fn ordinary_failure_runs_failure_and_always_diagnostics_without_turning_green() {
    let plan = WorkflowPlan::compile(FLOW).unwrap();
    let mut worker = Fake { fail: "build", ..Default::default() };
    let report = plan.execute(WorkflowLimits::default(), &mut worker, &|| true).unwrap();
    assert!(!report.succeeded());
    assert_eq!(report.jobs.iter().map(|j| j.outcome).collect::<Vec<_>>(),
        [JobOutcome::Failed, JobOutcome::Succeeded, JobOutcome::Succeeded, JobOutcome::Skipped]);
    assert_eq!(worker.calls, [
        "begin:build", "step:0:build", "step:2:same-job-failure-diagnostic",
        "step:3:same-job-always-diagnostic", "finish:false",
        "begin:cleanup", "step:0:dependent-always", "finish:false",
        "begin:failure-report", "step:0:dependent-failure", "finish:false",
    ]);
    assert_eq!(report.jobs[0].steps.len(), 3, "default success step after failure is skipped, not fabricated");
}

#[test]
fn success_skips_failure_predicates_but_runs_always() {
    let plan = WorkflowPlan::compile(FLOW).unwrap();
    let mut worker = Fake::default();
    let report = plan.execute(WorkflowLimits::default(), &mut worker, &|| true).unwrap();
    assert_eq!(report.jobs.iter().map(|j| j.outcome).collect::<Vec<_>>(),
        [JobOutcome::Succeeded, JobOutcome::Succeeded, JobOutcome::Skipped, JobOutcome::Succeeded]);
    assert!(worker.calls.contains(&"step:1:forbidden-success".to_owned()));
    assert!(!worker.calls.iter().any(|s| s.contains("same-job-failure-diagnostic")));
    assert!(worker.calls.iter().any(|s| s.contains("same-job-always-diagnostic")));
    assert!(!worker.calls.iter().any(|s| s.contains("dependent-failure")));
}

#[test]
fn always_never_overrides_lost_containment() {
    let plan = WorkflowPlan::compile(FLOW).unwrap();
    let mut worker = Fake { fail: "build", retain_on: "build", ..Default::default() };
    let report = plan.execute(WorkflowLimits::default(), &mut worker, &|| true).unwrap();
    assert_eq!(report.jobs[0].outcome, JobOutcome::Failed);
    assert!(report.jobs[1..].iter().all(|job| job.outcome == JobOutcome::Cancelled));
    assert!(!worker.calls.iter().any(|s| s.contains("diagnostic") || s.contains("dependent")));
    assert_eq!(worker.calls.last().unwrap(), "finish:true");
}
