//! Bounded operator-owned output selectors. Parsing performs no filesystem I/O.
use super::{unhex, validate_path};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Selection {
    workflow: Vec<u8>,
    job: String,
    output: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct Options {
    root: PathBuf,
    selections: Vec<Selection>,
    maximum_bytes: usize,
    total_bytes: usize,
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

pub(super) fn options(
    flags: &BTreeMap<&str, &str>,
    mut selections: Vec<Selection>,
    candidate: bool,
) -> Result<Option<Options>, String> {
    let root = flags.get("--artifact-root");
    let has_limit =
        flags.contains_key("--max-artifact-mib") || flags.contains_key("--max-artifact-total-mib");
    if root.is_none() && selections.is_empty() && !has_limit {
        return Ok(None);
    }
    if candidate {
        return Err(
            "artifact output capture currently requires canonical workflow run or dispatch".into(),
        );
    }
    let root = PathBuf::from(*root.ok_or("--artifact-root is required for output capture")?);
    if !root.is_absolute() || root.as_os_str().len() > 4096 {
        return Err("artifact root must be an absolute bounded private directory".into());
    }
    if selections.is_empty() || selections.len() > 64 {
        return Err("artifact capture requires 1..64 explicit selections".into());
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
        maximum_bytes: mib("--max-artifact-mib", 16, 64)?,
        total_bytes: mib("--max-artifact-total-mib", 64, 512)?,
    }))
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
        fgit_node::TrustedWorkflowArtifactConfig::new(
            self.root.clone(),
            selections,
            self.maximum_bytes,
            self.total_bytes,
        )
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
    fn root_contract_budget_and_candidate_refusals_are_preflight_only() {
        let selected = selection("ci/a.yml:build:out/result", false).unwrap();
        let base = BTreeMap::from([("--artifact-root", "/explicit-not-opened-root")]);
        let config = options(&base, vec![selected.clone()], false)
            .unwrap()
            .unwrap();
        assert_eq!(config.maximum_bytes, 16 * 1024 * 1024);
        assert_eq!(config.total_bytes, 64 * 1024 * 1024);
        assert!(options(&base, vec![selected.clone()], true).is_err());
        assert!(options(&base, vec![], false).is_err());
        assert!(options(&BTreeMap::new(), vec![selected.clone()], false).is_err());
        assert!(options(&base, vec![selected.clone(), selected.clone()], false).is_err());
        for (flag, value) in [
            ("--max-artifact-mib", "0"),
            ("--max-artifact-mib", "65"),
            ("--max-artifact-mib", "01"),
            ("--max-artifact-mib", "+1"),
            ("--max-artifact-total-mib", "513"),
        ] {
            let mut flags = base.clone();
            flags.insert(flag, value);
            assert!(options(&flags, vec![selected.clone()], false).is_err());
        }
        assert!(
            options(
                &BTreeMap::from([("--max-artifact-mib", "4")]),
                vec![],
                false
            )
            .is_err()
        );
        assert!(options(&BTreeMap::new(), vec![], false).unwrap().is_none());
    }
}
