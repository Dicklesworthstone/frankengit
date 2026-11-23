//! Explicit complete-series execution without widening the merge/squash parser.
use super::*;
use fgit_forge::event::NativeMerge;

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../fgit-node/tests/trusted_rebase_workflow/support.rs"]
mod native;

const USAGE: &str = "usage: fg workflow run-rebase-candidate <storage-root> <tenant-id> <repository-id> <target-ref>
  --trusted-local --bundle <stable-local-file> --candidate-commit <reviewed-final-oid>
  --expected-commit <target-before-oid> --source-ref <incoming-branch>
  --expected-source <incoming-tip-oid> --merge-base <original-common-ancestor-oid>
  --workflow <candidate-path> --input <repository-path> [--input <repository-path> ...]
  --run-id <32-lowercase-hex> --run-parent <absolute-private-0700-directory>
  [--object-format sha1|sha256] [--expected-head <snapshot-token>]
  [--expected-incarnation <id>] [--ref-hex]
  [--source-ref-hex <hex> instead of --source-ref]
  [--workflow-hex <hex> instead of --workflow] [--input-hex <hex> instead of --input]
  [artifact capture/input options from fg workflow run --help]

Execute the final tree and scripts of an already prepared linear rebase series.
The bundle names the target and has its tip as the sole prerequisite. Both
current branch tips, original common-base ancestry, every original and rewritten
single-parent commit (1..256), intermediate object closure and pack coverage
must validate before an execution slot or process is created. The source branch
stays unchanged. This command never prepares, substitutes or publishes a candidate.

Linux trusted-local execution only: review and trust the ACTUAL candidate scripts.
They run with host-user privileges, not hostile-code isolation. The usual finite
budgets, fresh job copies, no-replay journals, artifacts and cleanup apply.
Occupied run IDs refuse; a missing report is not evidence that no script ran.
The report records the canonical target base separately from the executed final
commit and its verified immediate parent, which may be an intermediate commit.

To publish a saved completed job for the exact current PR, use
fg workflow publish-candidate --method rebase (see publish-candidate --help
for required subject, publisher, original journal, bundle digest and retry key).
Execution grants no PR approval, canonical green check or permission to merge.
Automatic workflow watchers retain their existing merge/squash profiles.
Stdout and exit codes are the same as fg workflow run.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["run-rebase-candidate", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let (options, merge) = parse(args)?;
    #[cfg(target_os = "linux")]
    {
        super::execute_selected(options, None, None, Some(merge))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, merge);
        Err("trusted rebase workflow execution requires Linux; no fallback is selected".into())
    }
}

fn parse(args: &[String]) -> Result<(Options, NativeMerge), String> {
    if args.len() < 5 || args[0] != "run-rebase-candidate" {
        return Err(USAGE.into());
    }
    if args.len() > 2110
        || args.iter().any(|value| value.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("rebase workflow arguments exceed the bounded profile".into());
    }
    // Consume each value with its flag. A path or value spelling --method must
    // not become a command option; an actual method option has no meaning here.
    let mut cursor = 5;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        if flag == "--method" {
            return Err(
                "run-rebase-candidate selects rebase explicitly and accepts no --method".into(),
            );
        }
        cursor += if matches!(flag, "--trusted-local" | "--ref-hex" | "--artifact-logs") {
            1
        } else {
            2
        };
    }
    let mut ordinary = args.to_vec();
    ordinary[0] = "run-merge-candidate".into();
    let (options, merge, _) = super::merge::parse(&ordinary)?;
    if merge.base_tip == merge.source_tip || merge.merge_commit == merge.target_tip_before {
        return Err("rebase requires nonempty original and rewritten series".into());
    }
    Ok((options, merge))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(format: &str) -> Vec<String> {
        let width = if format == "sha1" { 40 } else { 64 };
        let mut args = vec![
            "run-rebase-candidate".into(),
            "/private/node".into(),
            "01".repeat(16),
            "02".repeat(16),
            "refs/heads/main".into(),
            "--trusted-local".into(),
        ];
        for (flag, value) in [
            ("--bundle", "/private/candidate.bundle".into()),
            ("--candidate-commit", "4".repeat(width)),
            ("--expected-commit", "1".repeat(width)),
            ("--source-ref", "refs/heads/topic".into()),
            ("--expected-source", "2".repeat(width)),
            ("--merge-base", "3".repeat(width)),
            ("--workflow", "workflow.yml".into()),
            ("--input", "workflow.yml".into()),
            ("--run-id", "05".repeat(16)),
            ("--run-parent", "/private/runs".into()),
            ("--object-format", format.into()),
        ] {
            args.extend([flag.into(), value]);
        }
        args
    }

    #[test]
    fn explicit_rebase_coordinates_preserve_both_hash_domains_and_old_profiles() {
        for format in ["sha1", "sha256"] {
            let values = args(format);
            let (options, merge) = parse(&values).unwrap();
            assert_eq!(merge.target_ref.as_bytes(), b"refs/heads/main");
            assert_eq!(merge.source_ref.as_bytes(), b"refs/heads/topic");
            assert_eq!(options.candidate.unwrap().commit, merge.merge_commit);
            let mut wrong = values.clone();
            wrong.extend(["--method".into(), "rebase".into()]);
            assert!(parse(&wrong).is_err());
            wrong[0] = "run-merge-candidate".into();
            assert!(super::super::merge::parse(&wrong).is_err());
            let mut empty = values.clone();
            let base = empty.iter().position(|arg| arg == "--merge-base").unwrap() + 1;
            let source = empty
                .iter()
                .position(|arg| arg == "--expected-source")
                .unwrap()
                + 1;
            empty[base] = empty[source].clone();
            assert!(parse(&empty).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_cli_runs_and_publishes_rebase_checks_then_recovers_without_bundle_in_both_formats() {
        use fgit_node::OneNode;
        use fgit_runner::coordinator::CheckRunStatus;
        use fgit_runner::coordinator::delivery::journal::CheckJournalScope;
        use native::{Case, OWNER, REPOSITORY, TENANT};
        use std::fs;
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut case = Case::new(format);
            let incarnation = case.node().repository_incarnation_id();
            let bundle_path = case.f.root.join("candidate.bundle");
            fs::write(&bundle_path, &case.bundle).unwrap();
            let mut input = args(format.as_str());
            input[1] = case.f.root.join("node").to_string_lossy().into_owned();
            input[2] = TENANT.to_string();
            input[3] = REPOSITORY.to_string();
            for (flag, value) in [
                ("--bundle", bundle_path.to_string_lossy().into_owned()),
                ("--candidate-commit", case.binding.commit.to_string()),
                ("--expected-commit", case.f.target.to_string()),
                ("--expected-source", case.f.source.to_string()),
                ("--merge-base", case.f.base.to_string()),
                (
                    "--run-parent",
                    case.f.parent().to_string_lossy().into_owned(),
                ),
            ] {
                let index = input.iter().position(|value| value == flag).unwrap();
                input[index + 1] = value;
            }
            input.extend([
                "--input".into(),
                "left".into(),
                "--input".into(),
                "right".into(),
            ]);
            case.f.node.take().unwrap().shutdown().unwrap();
            assert_eq!(run(&input).unwrap(), 0);
            let directory = case
                .f
                .parent()
                .join(format!("workflow-{}", "05".repeat(16)));
            let report = fs::read_to_string(directory.join("report.json")).unwrap();
            assert!(report.contains("\"rebase\":{\"method\":\"rebase\""));
            assert!(report.contains(&format!("\"executed_commit\":\"{}\"", case.binding.commit)));
            let marker = fs::read(directory.join("attempt.json")).unwrap();
            let scope = CheckJournalScope {
                tenant: TENANT,
                repository: REPOSITORY,
                journal_id: fgit_runner::Commitment::of_bytes(&marker),
            };
            let mut journal =
                OneNode::open_trusted_workflow_journal(&directory, scope, None, &|| true).unwrap();
            let page = journal
                .read_history(None, None, 128, 1024 * 1024, &|| true)
                .unwrap();
            let (batch, index) = page
                .entries()
                .iter()
                .find_map(|entry| {
                    entry
                        .batch()
                        .facts()
                        .iter()
                        .enumerate()
                        .find_map(|(index, fact)| {
                            (fact.status == CheckRunStatus::Completed && fact.job_id == "a")
                                .then(|| (entry.batch().id(), index))
                        })
                })
                .unwrap();
            drop(journal);
            let mut publication = vec![
                "publish-candidate".into(),
                input[1].clone(),
                TENANT.to_string(),
                REPOSITORY.to_string(),
                "refs/heads/main".into(),
                "--trusted-local".into(),
            ];
            for (flag, value) in [
                ("--run-directory", directory.to_string_lossy().into_owned()),
                (
                    "--journal-id",
                    hex(scope.journal_id.digest().bytes().as_bytes()),
                ),
                ("--batch", hex(batch.digest().bytes().as_bytes())),
                ("--fact-index", index.to_string()),
                ("--principal-id", OWNER.to_string()),
                ("--idempotency-key", "cli-exact-rebase-check".into()),
                ("--expected-incarnation", incarnation.to_string()),
                (
                    "--pull-request",
                    case.subject.pull_request.get().to_string(),
                ),
                (
                    "--expected-pull-request-version",
                    case.subject.pull_request_version.get().to_string(),
                ),
                (
                    "--expected-policy-epoch",
                    case.subject.policy_epoch.get().to_string(),
                ),
                ("--source-ref", "refs/heads/topic".into()),
                ("--expected-source-tip", case.f.source.to_string()),
                ("--expected-target-tip", case.f.target.to_string()),
                ("--merge-base", case.f.base.to_string()),
                ("--candidate-commit", case.binding.commit.to_string()),
                ("--bundle", bundle_path.to_string_lossy().into_owned()),
                (
                    "--bundle-sha256",
                    hex(&fgit_crypto::sha256_digest(&case.bundle)),
                ),
                ("--object-format", format.as_str().into()),
                ("--method", "rebase".into()),
            ] {
                publication.extend([flag.into(), value]);
            }
            let mut wrong_profile = publication.clone();
            let method = wrong_profile
                .iter()
                .position(|value| value == "--method")
                .unwrap();
            wrong_profile.drain(method..method + 2);
            let key = wrong_profile
                .iter()
                .position(|value| value == "--idempotency-key")
                .unwrap()
                + 1;
            wrong_profile[key] = "cli-original-profile-refusal".into();
            let mut refusal = Vec::new();
            assert_eq!(
                super::super::publish_candidate::run(&wrong_profile, &mut refusal).unwrap(),
                3
            );
            wrong_profile.extend(["--method".into(), "rebase".into()]);
            let mut refusal_recovery = Vec::new();
            assert_eq!(
                super::super::publish_candidate::run(&wrong_profile, &mut refusal_recovery)
                    .unwrap(),
                3
            );
            let refusal_recovery = String::from_utf8(refusal_recovery).unwrap();
            assert!(refusal_recovery.contains("\"outcome_recovered\":true"));
            assert!(
                refusal_recovery.contains("\"requested_validation_profile\":\"rebase-series-v1\"")
            );
            let mut first = Vec::new();
            assert_eq!(
                super::super::publish_candidate::run(&publication, &mut first).unwrap(),
                0
            );
            assert!(
                String::from_utf8(first)
                    .unwrap()
                    .contains("\"requested_validation_profile\":\"rebase-series-v1\"")
            );
            fs::remove_file(bundle_path).unwrap();
            let mut recovered = Vec::new();
            assert_eq!(
                super::super::publish_candidate::run(&publication, &mut recovered).unwrap(),
                0
            );
            assert!(
                String::from_utf8(recovered)
                    .unwrap()
                    .contains("\"outcome_recovered\":true")
            );
            assert_eq!(fs::read_dir(case.f.parent()).unwrap().count(), 1);
            assert_eq!(
                fs::read_to_string(directory.join("report.json")).unwrap(),
                report
            );
            case.f.reopen();
            let selected = case
                .node()
                .runtime()
                .block_on(case.node().materialize_admission())
                .unwrap();
            assert_eq!(
                selected.snapshot().refs[&native::target_ref()],
                case.f.target
            );
            assert_eq!(
                selected.snapshot().refs[&native::source_ref()],
                case.f.source
            );
            assert!(case.node().read_git_object(case.binding.commit).is_err());
        }
    }
}
