#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual CLI subprocesses over real imported nodes and native candidate bundles.
#[path = "../../fgit-node/tests/trusted_candidate_workflow/support.rs"]
mod support;
use fgit_crypto::sha256_digest;
use fgit_types::{GitHashAlgorithm, GitOid};
use std::fs;
use std::process::{Command, Output};
use support::*;

const WORKFLOW: &str = "name: proposed-check\non: push\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat input.txt)\" = candidate || exit 7; printf checked\n";
fn command(f: &Fixture, candidate: GitOid, run: &str, trusted: bool) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fg"));
    c.args(["workflow", "run-candidate"])
        .arg(f.root.join("node"))
        .arg(TENANT.to_string())
        .arg(REPOSITORY.to_string())
        .arg("refs/heads/main")
        .args(["--workflow", "workflow.yml", "--run-id"])
        .arg(run.repeat(16))
        .arg("--run-parent")
        .arg(f.parent())
        .args(["--object-format", f.tip.algorithm().as_str()])
        .arg("--expected-commit")
        .arg(f.tip.to_string())
        .arg("--candidate-commit")
        .arg(candidate.to_string())
        .arg("--bundle")
        .arg(f.root.join("candidate.bundle"));
    for path in inputs() {
        c.arg("--input").arg(String::from_utf8(path).unwrap());
    }
    if trusted {
        c.arg("--trusted-local");
    }
    c
}
fn exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn assert_unchanged(f: &mut Fixture, candidate: GitOid, before: u64) {
    f.reopen();
    assert_eq!(generation(f.node()), before);
    let state = f
        .node()
        .runtime()
        .block_on(f.node().materialize_admission())
        .unwrap();
    assert_eq!(state.snapshot().refs[&reference()], f.tip);
    assert!(f.node().read_git_object(candidate).is_err());
    drop(state);
    f.node.take().unwrap().shutdown().unwrap();
}

#[test]
fn cli_executes_candidate_persists_exact_binding_and_refuses_replay_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let candidate = f.replace_file("input.txt", "original\n", "candidate\n");
        fs::write(f.root.join("candidate.bundle"), candidate.bundle_bytes()).unwrap();
        let digest: String = sha256_digest(candidate.bundle_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        f.node.take().unwrap().shutdown().unwrap();
        let out = command(&f, candidate.candidate_commit, "51", true)
            .output()
            .unwrap();
        exit(&out, 0);
        let text = String::from_utf8(out.stdout).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"node_closed\":true"));
        assert!(text.contains("\"input_kind\":\"unpublished_candidate\""));
        assert!(text.contains("\"stdout_hex\":\"636865636b6564\""));
        assert!(text.contains(&format!("\"source_commit\":\"{}\"", f.tip)));
        assert!(text.contains(&format!(
            "\"executed_commit\":\"{}\"",
            candidate.candidate_commit
        )));
        assert!(text.contains(&format!("\"workflow_blob\":\"{}\"", f.workflow)));
        assert!(text.contains(&format!("\"bundle_sha256\":\"{digest}\"")));
        assert!(
            text.contains("\"admitted\":false") && text.contains("\"authoritative_check\":false")
        );
        let report_path = f
            .parent()
            .join(format!("workflow-{}", "51".repeat(16)))
            .join("report.json");
        let saved = fs::read_to_string(&report_path).unwrap();
        assert!(text.contains(&format!("\"run\":{saved}")));
        assert_unchanged(&mut f, candidate.candidate_commit, before);
        let retry = command(&f, candidate.candidate_commit, "51", true)
            .output()
            .unwrap();
        exit(&retry, 2);
        assert!(retry.stdout.is_empty());
        assert_eq!(fs::read_to_string(&report_path).unwrap(), saved);
        assert_unchanged(&mut f, candidate.candidate_commit, before);
    }
}

#[test]
fn cli_trust_and_corrupt_inputs_refuse_before_execution_and_non_green_is_not_an_io_error() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        // Valid native candidate, deliberately wrong input for the workflow.
        let candidate = f.replace_file("input.txt", "original\n", "not-candidate\n");
        fs::write(f.root.join("candidate.bundle"), candidate.bundle_bytes()).unwrap();
        f.node.take().unwrap().shutdown().unwrap();
        let denied = command(&f, candidate.candidate_commit, "52", false)
            .output()
            .unwrap();
        exit(&denied, 2);
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        let mut bad = candidate.bundle_bytes().to_vec();
        let end = bad.len() - 1;
        bad[end] ^= 1;
        fs::write(f.root.join("candidate.bundle"), &bad).unwrap();
        let refused = command(&f, candidate.candidate_commit, "52", true)
            .output()
            .unwrap();
        exit(&refused, 2);
        assert!(refused.stdout.is_empty());
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        fs::write(f.root.join("candidate.bundle"), candidate.bundle_bytes()).unwrap();
        let failed = command(&f, candidate.candidate_commit, "52", true)
            .output()
            .unwrap();
        exit(&failed, 1);
        let text = String::from_utf8(failed.stdout).unwrap();
        assert!(text.contains("\"node_closed\":true") && text.contains("\"succeeded\":false"));
        assert!(text.contains("\"exit_code\":7") && text.contains("\"published\":false"));
        let report = f
            .parent()
            .join(format!("workflow-{}", "52".repeat(16)))
            .join("report.json");
        assert!(report.is_file());
        assert_unchanged(&mut f, candidate.candidate_commit, before);
    }
}
