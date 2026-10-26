//! Bounded operator-owned output and log capture. Parsing performs no filesystem I/O.
use super::{unhex, validate_path};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Selection {
    workflow: Vec<u8>,
    job: String,
    output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct InputSelection {
    workflow: Vec<u8>,
    consumer: String,
    producer: String,
    output: Vec<u8>,
    destination: Vec<u8>,
}

pub(super) fn input_selection(value: &str, encoded: bool) -> Result<InputSelection, String> {
    let fields = value.splitn(5, ':').collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err("artifact input must be workflow:consumer:producer:output:destination".into());
    }
    let producer = selection(
        &format!("{}:{}:{}", fields[0], fields[2], fields[3]),
        encoded,
    )?;
    let target = selection(
        &format!("{}:{}:{}", fields[0], fields[1], fields[4]),
        encoded,
    )?;
    if producer.job == target.job || target.output.len() > 4000 {
        return Err("artifact input needs different jobs and a bounded destination".into());
    }
    Ok(InputSelection {
        workflow: producer.workflow,
        consumer: target.job,
        producer: producer.job,
        output: producer.output,
        destination: target.output,
    })
}

#[derive(Debug)]
pub(super) struct Options {
    root: PathBuf,
    selections: Vec<Selection>,
    capture_logs: bool,
    maximum_bytes: usize,
    total_bytes: usize,
    inputs: Vec<InputSelection>,
    input_total_bytes: usize,
}

pub(super) fn selection(value: &str, encoded: bool) -> Result<Selection, String> {
    let mut fields = value.splitn(3, ':');
    let workflow = fields.next().ok_or("missing artifact workflow")?;
    let job = fields
        .next()
        .ok_or("artifact selector must be workflow:job:output")?;
    let output = fields
        .next()
        .ok_or("artifact selector must be workflow:job:output")?;
    let decode = |value: &str| {
        if encoded {
            unhex(value, 4096)
        } else {
            Ok(value.as_bytes().to_vec())
        }
    };
    let workflow = decode(workflow)?;
    let output = decode(output)?;
    validate_path(&workflow)?;
    validate_path(&output)?;
    if output == b".fgit-host-receipt"
        || job.is_empty()
        || job.len() > 256
        || !job
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(
            "artifact requires a bounded ASCII job identifier and a regular output path".into(),
        );
    }
    Ok(Selection {
        workflow,
        job: job.to_owned(),
        output,
    })
}

pub(super) fn options_with_inputs(
    flags: &BTreeMap<&str, &str>,
    mut selections: Vec<Selection>,
    mut inputs: Vec<InputSelection>,
) -> Result<Option<Options>, String> {
    let root = flags.get("--artifact-root");
    let capture_logs = flags.contains_key("--artifact-logs");
    let has_limit = flags.contains_key("--max-artifact-mib")
        || flags.contains_key("--max-artifact-total-mib")
        || flags.contains_key("--max-artifact-input-total-mib");
    if root.is_none() && selections.is_empty() && inputs.is_empty() && !has_limit && !capture_logs {
        return Ok(None);
    }
    let root = PathBuf::from(*root.ok_or("--artifact-root is required for output or log capture")?);
    if !root.is_absolute() || root.as_os_str().len() > 4096 {
        return Err("artifact root must be an absolute bounded private directory".into());
    }
    if (selections.is_empty() && !capture_logs) || selections.len() > 64 {
        return Err(
            "artifact capture requires --artifact-logs or 1..64 explicit selections".into(),
        );
    }
    if selections
        .iter()
        .map(|s| s.workflow.len() + s.output.len())
        .sum::<usize>()
        > 64 * 1024
    {
        return Err("artifact selection paths exceed 64 KiB".into());
    }
    selections.sort();
    if selections.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("artifact selections must be distinct".into());
    }
    if inputs.len() > 64
        || (inputs.is_empty() && flags.contains_key("--max-artifact-input-total-mib"))
    {
        return Err("artifact input limits require 1..64 explicit input selections".into());
    }
    if selections
        .iter()
        .map(|s| s.workflow.len() + s.output.len())
        .sum::<usize>()
        + inputs
            .iter()
            .map(|s| s.workflow.len() + s.output.len() + s.destination.len())
            .sum::<usize>()
        > 64 * 1024
    {
        return Err("combined artifact input/output paths exceed 64 KiB".into());
    }
    inputs.sort();
    for (index, input) in inputs.iter().enumerate() {
        if !selections.iter().any(|output| {
            output.workflow == input.workflow
                && output.job == input.producer
                && output.output == input.output
        }) {
            return Err("artifact input producer output must be explicitly captured".into());
        }
        if inputs[..index].iter().any(|previous| {
            previous.workflow == input.workflow
                && previous.consumer == input.consumer
                && (previous.destination == input.destination
                    || previous
                        .destination
                        .strip_prefix(input.destination.as_slice())
                        .is_some_and(|r| r.starts_with(b"/"))
                    || input
                        .destination
                        .strip_prefix(previous.destination.as_slice())
                        .is_some_and(|r| r.starts_with(b"/")))
        }) {
            return Err("artifact input destinations overlap within a consumer".into());
        }
    }
    let mib = |flag: &str, default: usize, maximum: usize| -> Result<usize, String> {
        let count = match flags.get(flag) {
            None => default,
            Some(value)
                if !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit())
                    && (value.len() == 1 || !value.starts_with('0')) =>
            {
                value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid {flag}"))?
            }
            Some(_) => return Err(format!("invalid {flag}")),
        };
        if count == 0 || count > maximum {
            return Err(format!("{flag} must be in 1..={maximum}"));
        }
        Ok(count * 1024 * 1024)
    };
    Ok(Some(Options {
        root,
        selections,
        capture_logs,
        maximum_bytes: mib("--max-artifact-mib", 16, 64)?,
        total_bytes: mib("--max-artifact-total-mib", 64, 512)?,
        inputs,
        input_total_bytes: mib("--max-artifact-input-total-mib", 64, 512)?,
    }))
}

#[cfg(test)]
fn options(
    flags: &BTreeMap<&str, &str>,
    selections: Vec<Selection>,
) -> Result<Option<Options>, String> {
    options_with_inputs(flags, selections, Vec::new())
}

#[cfg(target_os = "linux")]
impl Options {
    pub(super) fn node_config(&self) -> Result<fgit_node::TrustedWorkflowArtifactConfig, String> {
        let selections = self
            .selections
            .iter()
            .map(|s| {
                fgit_node::TrustedWorkflowArtifactSelection::new(&s.workflow, &s.job, &s.output)
                    .map_err(str::to_owned)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let config = if self.capture_logs {
            fgit_node::TrustedWorkflowArtifactConfig::new_with_logs(
                self.root.clone(),
                selections,
                self.maximum_bytes,
                self.total_bytes,
            )
        } else {
            fgit_node::TrustedWorkflowArtifactConfig::new(
                self.root.clone(),
                selections,
                self.maximum_bytes,
                self.total_bytes,
            )
        }
        .map_err(str::to_owned)?;
        if self.inputs.is_empty() {
            return Ok(config);
        }
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                fgit_node::TrustedWorkflowArtifactInput::new(
                    &input.workflow,
                    &input.consumer,
                    &input.producer,
                    &input.output,
                    &input.destination,
                )
                .map_err(str::to_owned)
            })
            .collect::<Result<Vec<_>, _>>()?;
        config
            .with_inputs(inputs, self.input_total_bytes)
            .map_err(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_paths_and_expanded_job_ids_are_exact_without_globs() {
        let selected = selection("63692fff2e796d6c:build__matrix_007:6f75742fff", true).unwrap();
        assert_eq!(selected.workflow, b"ci/\xff.yml");
        assert_eq!(selected.job, "build__matrix_007");
        assert_eq!(selected.output, b"out/\xff");
        for value in [
            "ci/a.yml:build:../outside",
            "ci/a.yml:build:/outside",
            "ci/a.yml:build:.fgit-host-receipt",
            "ci/a.yml::out",
            "ci/a.yml:bad job:out",
            "ci/a.yml:build",
        ] {
            assert!(selection(value, false).is_err(), "{value}");
        }
    }

    #[test]
    fn root_contract_and_budget_refusals_are_preflight_only() {
        let selected = selection("ci/a.yml:build:out/result", false).unwrap();
        let base = BTreeMap::from([("--artifact-root", "/explicit-not-opened-root")]);
        let config = options(&base, vec![selected.clone()]).unwrap().unwrap();
        assert!(!config.capture_logs);
        assert_eq!(config.maximum_bytes, 16 * 1024 * 1024);
        assert_eq!(config.total_bytes, 64 * 1024 * 1024);
        assert!(options(&base, vec![]).is_err());
        assert!(options(&BTreeMap::new(), vec![selected.clone()]).is_err());
        assert!(options(&base, vec![selected.clone(), selected.clone()]).is_err());
        for (flag, value) in [
            ("--max-artifact-mib", "0"),
            ("--max-artifact-mib", "65"),
            ("--max-artifact-mib", "01"),
            ("--max-artifact-mib", "+1"),
            ("--max-artifact-total-mib", "513"),
        ] {
            let mut flags = base.clone();
            flags.insert(flag, value);
            assert!(options(&flags, vec![selected.clone()]).is_err());
        }
        assert!(options(&BTreeMap::from([("--max-artifact-mib", "4")]), vec![],).is_err());
        assert!(options(&BTreeMap::new(), vec![]).unwrap().is_none());
    }

    #[test]
    fn input_selectors_preserve_byte_paths_and_require_explicit_direct_job_names() {
        let selected = input_selection(
            "63692fff2e796d6c:test__matrix_003:build__matrix_007:6f75742ffe:62696e2fff",
            true,
        )
        .unwrap();
        assert_eq!(selected.workflow, b"ci/\xff.yml");
        assert_eq!(selected.consumer, "test__matrix_003");
        assert_eq!(selected.producer, "build__matrix_007");
        assert_eq!(selected.output, b"out/\xfe");
        assert_eq!(selected.destination, b"bin/\xff");
        for value in [
            "ci/a.yml:test:build:out",
            "ci/a.yml:build:build:out:bin/tool",
            "ci/a.yml:test:build:out:../outside",
            "ci/a.yml:test:build:out:/outside",
            "ci/a.yml:test:build:out:.fgit-host-receipt",
            "ci/a.yml::build:out:tool",
            "ci/a.yml:bad job:build:out:tool",
        ] {
            assert!(input_selection(value, false).is_err(), "{value}");
        }
    }

    #[test]
    fn input_options_bound_delivery_and_refuse_uncaptured_or_overlapping_destinations() {
        let base = BTreeMap::from([("--artifact-root", "/explicit-not-opened-root")]);
        let capture = selection("ci/a.yml:build:out", false).unwrap();
        let selected = input_selection("ci/a.yml:test:build:out:bin/tool", false).unwrap();
        let config = options_with_inputs(&base, vec![capture.clone()], vec![selected.clone()])
            .unwrap()
            .unwrap();
        assert_eq!(config.input_total_bytes, 64 * 1024 * 1024);
        assert!(options_with_inputs(&base, Vec::new(), vec![selected.clone()]).is_err());
        assert!(
            options_with_inputs(
                &base,
                vec![capture.clone()],
                vec![input_selection("ci/a.yml:test:build:other:bin/tool", false).unwrap(),]
            )
            .is_err()
        );
        for path in ["bin", "bin/tool", "bin/tool/child"] {
            let other = input_selection(&format!("ci/a.yml:test:build:out:{path}"), false).unwrap();
            assert!(
                options_with_inputs(&base, vec![capture.clone()], vec![selected.clone(), other])
                    .is_err()
            );
        }
        assert!(
            options_with_inputs(
                &base,
                vec![capture.clone()],
                vec![
                    selected.clone(),
                    input_selection("ci/a.yml:package:build:out:bin/tool", false).unwrap(),
                ]
            )
            .is_ok()
        );
        for total in ["0", "513", "01", "+1"] {
            let mut flags = base.clone();
            flags.insert("--max-artifact-input-total-mib", total);
            assert!(
                options_with_inputs(&flags, vec![capture.clone()], vec![selected.clone()]).is_err()
            );
        }
        let mut flags = base;
        flags.insert("--max-artifact-input-total-mib", "1");
        assert!(options_with_inputs(&flags, vec![capture.clone()], Vec::new()).is_err());
        assert_eq!(
            options_with_inputs(&flags, vec![capture], vec![selected])
                .unwrap()
                .unwrap()
                .input_total_bytes,
            1024 * 1024
        );
    }

    #[test]
    fn log_only_capture_requires_opt_in_root_and_preserves_payload_and_input_bounds() {
        let flags = BTreeMap::from([
            ("--artifact-root", "/explicit-not-opened-root"),
            ("--artifact-logs", ""),
        ]);
        let config = options(&flags, Vec::new()).unwrap().unwrap();
        assert!(config.capture_logs);
        assert!(config.selections.is_empty());
        assert_eq!(config.maximum_bytes, 16 * 1024 * 1024);
        assert_eq!(config.total_bytes, 64 * 1024 * 1024);
        assert!(options(&BTreeMap::from([("--artifact-logs", "")]), Vec::new()).is_err());
        let mut relative = flags.clone();
        relative.insert("--artifact-root", "relative");
        assert!(options(&relative, Vec::new()).is_err());
        for (flag, value) in [
            ("--max-artifact-mib", "0"),
            ("--max-artifact-mib", "65"),
            ("--max-artifact-total-mib", "513"),
            ("--max-artifact-input-total-mib", "1"),
        ] {
            let mut invalid = flags.clone();
            invalid.insert(flag, value);
            assert!(options(&invalid, Vec::new()).is_err(), "{flag} {value}");
        }
        let input = input_selection("ci/a.yml:test:build:out:bin/tool", false).unwrap();
        assert!(options_with_inputs(&flags, Vec::new(), vec![input.clone()]).is_err());
        let output = selection("ci/a.yml:build:out", false).unwrap();
        let config = options_with_inputs(&flags, vec![output], vec![input])
            .unwrap()
            .unwrap();
        assert!(config.capture_logs);
        assert_eq!(config.selections.len(), 1);
        assert_eq!(config.inputs.len(), 1);
    }
}
