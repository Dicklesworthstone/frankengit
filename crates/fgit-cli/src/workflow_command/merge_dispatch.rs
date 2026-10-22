//! Explicit batch selection reuses merge intake and the shared signal/node owner.
use super::*;
use fgit_forge::{event::NativeMerge, preparation::MergeCommitStyle};
const USAGE: &str = "usage: fg workflow dispatch-merge-candidate <storage-root> <tenant-id> <repository-id> <target-ref>
  --trusted-local --event pull_request|workflow_dispatch
  --bundle <reviewed-file> --candidate-commit <reviewed-oid> --expected-commit <target-tip>
  --source-ref <incoming-branch> --expected-source <incoming-tip> --merge-base <common-base>
  --workflow <candidate-directory> --input <top-level-path> [--input ...]
  --run-parent <absolute-private-0700-directory> --run-id <32-lowercase-hex>
  [--method merge-commit|squash] [--object-format sha1|sha256]
  [--expected-head <snapshot-token>] [--expected-incarnation <id>]
  [--ref-hex] [--source-ref-hex <hex> instead of --source-ref]
  [--workflow-hex <hex> instead of --workflow] [--input-hex <hex>]
  [--artifact-root <private-directory> --artifact <workflow:job:output> ...]
  [--artifact-input <workflow:consumer:producer:output:destination> ...]
  [artifact hex selectors and byte ceilings from fg workflow run --help]

Execute ALL selected direct .yml/.yaml children from one verified unpublished
merge or squash candidate. Both branch tips, merge base, native parents and
bundle prerequisites are checked before any batch reservation or host script.
Definitions and inputs come from the actual candidate, not either parent.
pull_request branch filters match the target; path filters compare canonical
incoming source changes from its unique merge base. This is an explicit local
selection key, not an automatic PR trigger or a PR-version attestation.

Scripts run with trusted host-user privileges. Review candidate code before
execution. There is no hostile isolation, temporary ref, automatic check grant,
merge publication or automatic retry. Source-head watchers are unchanged.
All definitions and artifact selectors are checked before the first child.
Workflows share the native 600-second deadline, 16 MiB captured-output allowance,
aggregate jobs/steps/materialization limits and artifact budgets. Ordinary job
failure preserves independent results; timeout, cancellation or unproved
containment stops later work. A zero-match report does not produce checks.

The create-only dispatch-ID directory contains dispatch.json before execution
and original child journals for workflow recover/publish-run. An occupied batch
always refuses. Missing output never authorizes script replay; retain custody.
SIGTERM/SIGINT drain through the same request owner as single-workflow execution.
Exit 0: selected runs succeeded (possibly zero); 1: non-green/stopped;
2: invalid input, infrastructure, cleanup or report-output failure.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["dispatch-merge-candidate", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let (options, merge, style, event) = parse(args)?;
    #[cfg(target_os = "linux")]
    {
        super::execute_selected(options, Some((merge, style)), Some(&event))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, merge, style, event);
        Err("trusted merge dispatch requires Linux; no alternative runner is selected".into())
    }
}
fn parse(args: &[String]) -> Result<(Options, NativeMerge, MergeCommitStyle, String), String> {
    if args.first().map(String::as_str) != Some("dispatch-merge-candidate") || args.len() < 5 {
        return Err(USAGE.into());
    }
    if args.len() > 2112
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("merge dispatch arguments exceed bounded profile".into());
    }
    let mut common = args[..5].to_vec();
    common[0] = "run-merge-candidate".into();
    let mut event = None;
    let mut at = 5;
    while at < args.len() {
        let flag = &args[at];
        at += 1;
        if matches!(flag.as_str(), "--trusted-local" | "--ref-hex") {
            common.push(flag.clone());
            continue;
        }
        let value = args
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        if flag == "--event" {
            if event.is_some() || !matches!(value.as_str(), "pull_request" | "workflow_dispatch") {
                return Err("supply exactly one --event: pull_request or workflow_dispatch".into());
            }
            event = Some(value.clone());
        } else {
            common.extend([flag.clone(), value.clone()]);
        }
    }
    let event = event.ok_or("--event is mandatory")?;
    let (options, merge, style) = super::merge::parse(&common)?;
    Ok((options, merge, style, event))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(width: usize) -> Vec<String> {
        [
            "dispatch-merge-candidate",
            "not-opened",
            &"11".repeat(16),
            &"22".repeat(16),
            "refs/heads/main",
            "--trusted-local",
            "--event",
            "pull_request",
            "--workflow",
            "ci",
            "--input",
            "ci",
            "--run-id",
            &"33".repeat(16),
            "--run-parent",
            "/private",
            "--bundle",
            "not-opened.bundle",
            "--expected-commit",
            &"a".repeat(width),
            "--candidate-commit",
            &"b".repeat(width),
            "--source-ref",
            "refs/heads/topic",
            "--expected-source",
            &"c".repeat(width),
            "--merge-base",
            &"d".repeat(width),
            "--object-format",
            if width == 40 { "sha1" } else { "sha256" },
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn explicit_merge_and_squash_batches_parse_both_hash_domains_without_io() {
        for width in [40, 64] {
            for event in ["pull_request", "workflow_dispatch"] {
                for method in ["merge-commit", "squash"] {
                    let mut a = args(width);
                    a[7] = event.into();
                    a.extend(["--method".into(), method.into()]);
                    let (o, m, s, e) = parse(&a).unwrap();
                    assert_eq!(o.workflow, b"ci");
                    assert_eq!(e, event);
                    assert_eq!(m.merge_commit, o.candidate.unwrap().commit);
                    assert_eq!(
                        s,
                        if method == "squash" {
                            MergeCommitStyle::Squash
                        } else {
                            MergeCommitStyle::TwoParent
                        }
                    );
                }
            }
        }
    }
    #[test]
    fn events_cannot_forge_pushes_or_escape_option_value_positions() {
        for value in ["push", "pull_request_target", "", "auto", "Pull_Request"] {
            let mut a = args(40);
            a[7] = value.into();
            assert!(parse(&a).is_err());
        }
        let mut a = args(40);
        a.extend(["--event".into(), "pull_request".into()]);
        assert!(parse(&a).is_err());
        let mut a = args(40);
        a.drain(6..8);
        assert!(parse(&a).is_err());
        let mut a = args(40);
        let at = a.iter().position(|s| s == "--bundle").unwrap();
        a[at + 1] = "--event".into();
        assert_eq!(
            parse(&a).unwrap().0.candidate.unwrap().bundle,
            PathBuf::from("--event")
        );
    }
    #[test]
    fn no_authority_or_parent_pin_is_inferred_and_other_modes_reject_batch_flags() {
        for flag in [
            "--trusted-local",
            "--expected-commit",
            "--expected-source",
            "--source-ref",
            "--merge-base",
            "--candidate-commit",
            "--bundle",
        ] {
            let mut a = args(64);
            let at = a.iter().position(|s| s == flag).unwrap();
            a.drain(at..at + if flag == "--trusted-local" { 1 } else { 2 });
            assert!(parse(&a).is_err(), "{flag}");
        }
        for mode in ["run", "run-candidate", "run-merge-candidate", "watch"] {
            let mut a = args(40);
            a[0] = mode.into();
            assert!(parse(&a).is_err());
            if mode == "run-merge-candidate" {
                assert!(super::super::merge::parse(&a).is_err());
            } else {
                assert!(super::super::parse(&a).is_err());
            }
        }
        let mut a = args(40);
        a.extend(["--force".into(), "true".into()]);
        assert!(parse(&a).is_err());
    }
}
