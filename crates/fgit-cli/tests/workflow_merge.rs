#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual fg subprocesses: merge preparation -> execution -> restart/no replay.
#[path = "../../fgit-node/tests/trusted_merge_workflow/support.rs"]
mod support;
use fgit_forge::event::NativeMerge;
use fgit_types::GitHashAlgorithm;
use std::fs;
use std::process::{Command, Output};
use support::*;

fn command(f: &Fixture, merge: &NativeMerge, run: &str, trusted: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fg"));
    command
        .args(["workflow", "run-merge-candidate"])
        .arg(f.root.join("node"))
        .arg(TENANT.to_string())
        .arg(REPOSITORY.to_string())
        .arg("refs/heads/main")
        .arg("--bundle")
        .arg(f.root.join("merge.bundle"))
        .arg("--candidate-commit")
        .arg(merge.merge_commit.to_string())
        .arg("--expected-commit")
        .arg(merge.target_tip_before.to_string())
        .arg("--source-ref-hex")
        .arg(
            merge
                .source_ref
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .arg("--expected-source")
        .arg(merge.source_tip.to_string())
        .arg("--merge-base")
        .arg(merge.base_tip.to_string())
        .args(["--workflow", "workflow.yml", "--run-id"])
        .arg(run.repeat(16))
        .arg("--run-parent")
        .arg(f.parent())
        .args(["--object-format", f.target.algorithm().as_str()]);
    for path in inputs() {
        command.arg("--input").arg(String::from_utf8(path).unwrap());
    }
    if trusted {
        command.arg("--trusted-local");
    }
    command
}
fn exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn unchanged(f: &mut Fixture, before: u64, merge: &NativeMerge) {
    f.reopen();
    assert_eq!(generation(f.node()), before);
    let state = f
        .node()
        .runtime()
        .block_on(f.node().materialize_admission())
        .unwrap();
    assert_eq!(state.snapshot().refs[&target_ref()], f.target);
    assert_eq!(state.snapshot().refs[&source_ref()], f.source);
    drop(state);
    assert!(f.node().read_git_object(merge.merge_commit).is_err());
    f.node.take().unwrap().shutdown().unwrap();
}

#[test]
fn cli_executes_merged_bytes_records_all_coordinates_and_refuses_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let (merge, bundle) = f.prepared();
        fs::write(f.root.join("merge.bundle"), &bundle).unwrap();
        f.node.take().unwrap().shutdown().unwrap();
        let output = command(&f, &merge, "31", true).output().unwrap();
        exit(&output, 0);
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"node_closed\":true"));
        assert!(text.contains("\"stdout_hex\":\"6d6572676564\""));
        assert!(text.contains(&format!("\"executed_commit\":\"{}\"", merge.merge_commit)));
        assert!(text.contains(&format!("\"parents\":[\"{}\",\"{}\"]", f.target, f.source)));
        let directory = f.parent().join(format!("workflow-{}", "31".repeat(16)));
        let saved = fs::read_to_string(directory.join("report.json")).unwrap();
        assert!(text.contains(&format!("\"run\":{saved}")));
        assert!(
            saved.contains("\"succeeded\":true") && saved.contains("\"authoritative_check\":false")
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        unchanged(&mut f, before, &merge);
        let again = command(&f, &merge, "31", true).output().unwrap();
        exit(&again, 2);
        assert!(again.stdout.is_empty());
        assert_eq!(
            fs::read_to_string(directory.join("report.json")).unwrap(),
            saved
        );
        unchanged(&mut f, before, &merge);
    }
}

#[test]
fn cli_trust_corruption_and_stale_incoming_refuse_before_creating_an_attempt() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let (merge, bundle) = f.prepared();
        fs::write(f.root.join("merge.bundle"), &bundle).unwrap();
        f.node.take().unwrap().shutdown().unwrap();
        let output = command(&f, &merge, "32", false).output().unwrap();
        exit(&output, 2);
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        let mut stale = merge.clone();
        stale.source_tip = f.base;
        let output = command(&f, &stale, "32", true).output().unwrap();
        exit(&output, 2);
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        let mut corrupt = bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(f.root.join("merge.bundle"), corrupt).unwrap();
        let output = command(&f, &merge, "32", true).output().unwrap();
        exit(&output, 2);
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        unchanged(&mut f, before, &merge);
        fs::write(f.root.join("merge.bundle"), bundle).unwrap();
        let output = command(&f, &merge, "32", true).output().unwrap();
        exit(&output, 0);
        unchanged(&mut f, before, &merge);
    }
}

#[test]
fn cli_failed_execution_is_a_persisted_non_green_report_not_a_publication() {
    let fail = "name: failed\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf failed; exit 11\n";
    let mut f = Fixture::new(GitHashAlgorithm::Sha1, fail);
    let before = generation(f.node());
    let (merge, bundle) = f.prepared();
    fs::write(f.root.join("merge.bundle"), bundle).unwrap();
    f.node.take().unwrap().shutdown().unwrap();
    let output = command(&f, &merge, "33", true).output().unwrap();
    exit(&output, 1);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\"succeeded\":false") && text.contains("\"exit_code\":11"));
    assert!(text.contains("\"node_closed\":true") && text.contains("\"published\":false"));
    assert!(
        f.parent()
            .join(format!("workflow-{}", "33".repeat(16)))
            .join("report.json")
            .is_file()
    );
    unchanged(&mut f, before, &merge);
}
