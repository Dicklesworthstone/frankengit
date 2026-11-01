//! Exact operator inputs for the first dispatch of a retained merge candidate.
//! This identity is local custody, never a canonical check or execution receipt.

use super::super::{TrustedWorkflowArtifactConfig, WorkflowLimits};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use std::os::unix::ffi::OsStrExt;

pub(super) fn identity(
    directory: &[u8],
    read_prefixes: &[Vec<u8>],
    limits: WorkflowLimits,
    artifacts: Option<&TrustedWorkflowArtifactConfig>,
) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    part(&mut hash, b"frankengit/watch-prestart-execution/v1");
    part(&mut hash, directory);
    number(&mut hash, read_prefixes.len());
    for prefix in read_prefixes {
        part(&mut hash, prefix);
    }
    // Milliseconds would alias distinct finite operator deadlines.
    hash.update(&limits.step_timeout.as_secs().to_be_bytes());
    hash.update(&limits.step_timeout.subsec_nanos().to_be_bytes());
    hash.update(&limits.run_timeout.as_secs().to_be_bytes());
    hash.update(&limits.run_timeout.subsec_nanos().to_be_bytes());
    number(&mut hash, limits.stream_bytes);
    number(&mut hash, limits.total_output_bytes);
    let Some(artifacts) = artifacts else {
        hash.update(&[0]);
        return hash.finish();
    };
    hash.update(&[1]);
    part(&mut hash, artifacts.root().as_os_str().as_bytes());
    number(&mut hash, artifacts.maximum_bytes());
    number(&mut hash, artifacts.total_bytes());
    hash.update(&[u8::from(artifacts.capture_logs())]);
    number(&mut hash, artifacts.selections().len());
    for selection in artifacts.selections() {
        part(&mut hash, selection.workflow_path());
        part(&mut hash, selection.job_id().as_bytes());
        part(&mut hash, selection.output_path());
    }
    // Bind input delivery even when the JSON report omits an empty selection.
    number(&mut hash, artifacts.input_total_bytes());
    number(&mut hash, artifacts.inputs().len());
    for input in artifacts.inputs() {
        part(&mut hash, input.workflow_path());
        part(&mut hash, input.consumer_job_id().as_bytes());
        part(&mut hash, input.producer_job_id().as_bytes());
        part(&mut hash, input.output_path());
        part(&mut hash, input.destination());
    }
    hash.finish()
}

fn number(hash: &mut Sha256Hasher, value: usize) {
    hash.update(&(value as u64).to_be_bytes());
}

fn part(hash: &mut Sha256Hasher, bytes: &[u8]) {
    number(hash, bytes.len());
    hash.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::treefs_workspace::{TrustedWorkflowArtifactInput, TrustedWorkflowArtifactSelection};
    use std::path::PathBuf;
    use std::time::Duration;

    fn artifact(
        root: &str,
        logs: bool,
        input: Option<(&str, usize)>,
    ) -> TrustedWorkflowArtifactConfig {
        let selections =
            vec![TrustedWorkflowArtifactSelection::new(b"ci/build.yml", "build", b"out").unwrap()];
        let config = if logs {
            TrustedWorkflowArtifactConfig::new_with_logs(PathBuf::from(root), selections, 128, 256)
        } else {
            TrustedWorkflowArtifactConfig::new(PathBuf::from(root), selections, 128, 256)
        }
        .unwrap();
        match input {
            None => config,
            Some((destination, bytes)) => config
                .with_inputs(
                    vec![
                        TrustedWorkflowArtifactInput::new(
                            b"ci/build.yml",
                            "test",
                            "build",
                            b"out",
                            destination.as_bytes(),
                        )
                        .unwrap(),
                    ],
                    bytes,
                )
                .unwrap(),
        }
    }

    #[test]
    fn every_execution_budget_and_selection_is_bound_without_duration_rounding() {
        let prefixes = vec![b"ci".to_vec(), b"src".to_vec()];
        let limits = WorkflowLimits::default();
        let original = identity(b"ci", &prefixes, limits, None);
        assert_eq!(original, identity(b"ci", &prefixes, limits, None));
        assert_ne!(original, identity(b"src", &prefixes, limits, None));
        assert_ne!(original, identity(b"ci", &[b"ci".to_vec()], limits, None));
        assert_ne!(
            original,
            identity(b"ci", &[b"src".to_vec(), b"ci".to_vec()], limits, None)
        );
        for changed in [
            WorkflowLimits {
                step_timeout: limits.step_timeout + Duration::from_nanos(1),
                ..limits
            },
            WorkflowLimits {
                run_timeout: limits.run_timeout + Duration::from_nanos(1),
                ..limits
            },
            WorkflowLimits {
                stream_bytes: limits.stream_bytes - 1,
                ..limits
            },
            WorkflowLimits {
                total_output_bytes: limits.total_output_bytes - 1,
                ..limits
            },
        ] {
            assert_ne!(original, identity(b"ci", &prefixes, changed, None));
        }
        // Length framing prevents concatenation aliases between input paths.
        assert_ne!(
            identity(b"ci", &[b"ab".to_vec(), b"c".to_vec()], limits, None),
            identity(b"ci", &[b"a".to_vec(), b"bc".to_vec()], limits, None),
        );
    }

    #[test]
    fn artifact_capture_and_delivery_contracts_cannot_be_substituted() {
        let prefixes = vec![b"ci".to_vec()];
        let limits = WorkflowLimits::default();
        let original = artifact("/private/artifacts", false, Some(("input", 256)));
        let expected = identity(b"ci", &prefixes, limits, Some(&original));
        assert_eq!(
            expected,
            identity(b"ci", &prefixes, limits, Some(&original.clone()))
        );
        assert_ne!(expected, identity(b"ci", &prefixes, limits, None));
        for changed in [
            artifact("/private/other", false, Some(("input", 256))),
            artifact("/private/artifacts", true, Some(("input", 256))),
            artifact("/private/artifacts", false, None),
            artifact("/private/artifacts", false, Some(("changed", 256))),
            artifact("/private/artifacts", false, Some(("input", 255))),
        ] {
            assert_ne!(expected, identity(b"ci", &prefixes, limits, Some(&changed)));
        }
    }
}
