//! Whole-run completion is distinct from the legacy per-job evidence summary.
//! A skipped diagnostic is not a failed workflow or a successful check.
use fgit_runner::workflow::{JobOutcome, StepOutcome, WorkflowReport};

pub(super) fn succeeded(report: &WorkflowReport) -> bool {
    report
        .jobs
        .iter()
        .any(|job| job.outcome == JobOutcome::Succeeded)
        && report.jobs.iter().all(|job| {
            if job.failure.is_some() || job.requires_containment() {
                return false;
            }
            match job.outcome {
                JobOutcome::Succeeded => job.steps.iter().all(|step| {
                    let result = &step.observation;
                    result.outcome == StepOutcome::Succeeded
                        && result.exit_code == Some(0)
                        && result.output_complete
                        && !result.retain_workspace
                }),
                JobOutcome::Skipped => job.steps.is_empty(),
                JobOutcome::Failed
                | JobOutcome::Cancelled
                | JobOutcome::TimedOut
                | JobOutcome::OutputLimit
                | JobOutcome::Refused => false,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_runner::Commitment;
    use fgit_runner::workflow::{JobReport, StepObservation, StepReport, WorkerFailure};

    fn report(states: &[JobOutcome]) -> WorkflowReport {
        WorkflowReport {
            source: Commitment::of_bytes(b"completion-source"),
            graph: Commitment::of_bytes(b"completion-graph"),
            limits: Default::default(),
            jobs: states
                .iter()
                .enumerate()
                .map(|(index, outcome)| JobReport {
                    id: format!("job-{index}"),
                    outcome: *outcome,
                    failure: None,
                    steps: if *outcome == JobOutcome::Skipped {
                        Vec::new()
                    } else {
                        vec![StepReport {
                            index: 0,
                            name: None,
                            script: Commitment::of_bytes(b"true"),
                            observation: StepObservation {
                                outcome: if *outcome == JobOutcome::Succeeded {
                                    StepOutcome::Succeeded
                                } else {
                                    StepOutcome::Failed
                                },
                                exit_code: Some(i32::from(*outcome != JobOutcome::Succeeded)),
                                stdout: Vec::new(),
                                stderr: Vec::new(),
                                elapsed_millis: 0,
                                output_complete: true,
                                retain_workspace: false,
                            },
                        }]
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn successful_jobs_and_skipped_diagnostics_complete_without_rewriting_evidence() {
        let report = report(&[JobOutcome::Succeeded, JobOutcome::Skipped]);
        assert!(succeeded(&report));
        // Existing v1 observation bytes and their strict per-job success bit
        // remain untouched. Recovery still verifies their original commitments.
        assert!(!report.succeeded());
        let encoded = report.to_json();
        assert!(encoded.contains("\"succeeded\":false"));
        assert!(encoded.contains("\"authoritative_check\":false"));
        assert!(encoded.contains("\"outcome\":\"skipped\""));
        assert!(encoded.starts_with("{\"schema_version\":1,"));
    }

    #[test]
    fn every_terminal_pair_preserves_failure_and_nonvacuous_completion() {
        use JobOutcome::*;
        let states = [
            Succeeded,
            Skipped,
            Failed,
            Cancelled,
            TimedOut,
            OutputLimit,
            Refused,
        ];
        for first in states {
            for second in states {
                let expected = matches!(
                    (first, second),
                    (Succeeded, Succeeded | Skipped) | (Skipped, Succeeded)
                );
                assert_eq!(
                    succeeded(&report(&[first, second])),
                    expected,
                    "{first:?} {second:?}"
                );
            }
        }
        assert!(!succeeded(&report(&[])));
        assert!(!succeeded(&report(&[Skipped])));
        assert!(succeeded(&report(&[Succeeded])));
    }

    #[test]
    fn skipped_jobs_cannot_hide_execution_failure_or_unclosed_workspaces() {
        let original = report(&[JobOutcome::Succeeded, JobOutcome::Skipped]);
        let mut executed_skip = original.clone();
        executed_skip.jobs[1].steps = executed_skip.jobs[0].steps.clone();
        assert!(!succeeded(&executed_skip));
        let mut failed_cleanup = original.clone();
        failed_cleanup.jobs[1].failure = Some(WorkerFailure::new("unresolved cleanup", true));
        assert!(!succeeded(&failed_cleanup));
        let mut retained = original.clone();
        retained.jobs[0].steps[0].observation.retain_workspace = true;
        assert!(!succeeded(&retained));
        assert!(succeeded(&original));
    }

    #[test]
    fn fabricated_success_metadata_never_counts_as_completed_success() {
        let original = report(&[JobOutcome::Succeeded, JobOutcome::Skipped]);
        for outcome in [
            StepOutcome::Failed,
            StepOutcome::Cancelled,
            StepOutcome::TimedOut,
            StepOutcome::OutputLimit,
            StepOutcome::ContainmentFailure,
        ] {
            let mut changed = original.clone();
            changed.jobs[0].steps[0].observation.outcome = outcome;
            assert!(!succeeded(&changed));
        }
        for code in [None, Some(1)] {
            let mut changed = original.clone();
            changed.jobs[0].steps[0].observation.exit_code = code;
            assert!(!succeeded(&changed));
        }
        let mut incomplete = original.clone();
        incomplete.jobs[0].steps[0].observation.output_complete = false;
        assert!(!succeeded(&incomplete));
        let mut failure = original.clone();
        failure.jobs[0].failure = Some(WorkerFailure::new("failed cleanup", false));
        assert!(!succeeded(&failure));
        assert!(succeeded(&original));
    }
}
