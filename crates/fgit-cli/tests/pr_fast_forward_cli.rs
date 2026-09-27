#![forbid(unsafe_code)]
//! Execute the real fg binary against a persisted native repository.
//! The fixture is the node API's ordinary loose-import/PR setup, not a mock.
#[path = "../../fgit-node/tests/fast_forward_command/fixture.rs"]
mod fixture;
use fixture::*;

use std::path::Path;
use std::process::{Command, Output};

use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::{ExpectedVersion, ForgeEventPayload};
use fgit_node::OneNode;
use fgit_types::{GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch};

fn arguments(root: &Path, format: GitHashAlgorithm, source: GitOid, target: GitOid, key: &str) -> Vec<String> {
    vec![
        "pr".into(), "fast-forward".into(), root.join("node").to_str().unwrap().into(),
        "e1".repeat(16), "e2".repeat(16), "1".into(),
        "--trusted-local".into(), "--principal".into(), actor(2).to_string(),
        "--idempotency-key".into(), key.into(),
        "--expected-version".into(), "1".into(),
        "--source-ref".into(), "refs/heads/topic".into(), "--expected-source".into(), source.to_string(),
        "--target-ref".into(), "refs/heads/main".into(), "--expected-target".into(), target.to_string(),
        "--object-format".into(), format.as_str().into(),
    ]
}
fn command(args: &[String]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fg"));
    command.args(args);
    command
}
fn result(output: &Output, code: i32) -> &str {
    assert_eq!(output.status.code(), Some(code), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    std::str::from_utf8(&output.stdout).unwrap()
}
fn observed(root: &Path, format: GitHashAlgorithm) -> (GitOid, bool, HeadGeneration) {
    let mut node = OneNode::open_existing(config(root, format)).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    let generation = head.receipt().generation();
    node.bring_into_service(generation).unwrap();
    let request = node.request_context();
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let tip = selected.snapshot().refs[&main_ref()];
    let page = node.runtime().block_on(node.read_pull_requests_in(&request, &Default::default(), 0, 1, None)).unwrap();
    let merged = matches!(page.pull_requests[0].event.payload, ForgeEventPayload::MergeCommittedNative(_));
    node.shutdown().unwrap();
    (tip, merged, generation)
}

#[test]
fn real_cli_publishes_without_new_commit_and_recovers_identical_json_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch.0, format, false);
        let args = arguments(&scratch.0, format, f.source, f.target, "cli-fast-forward");
        f.node.shutdown().unwrap();
        let first = command(&args).output().unwrap();
        let receipt = result(&first, 0);
        for field in [
            "\"method\":\"fast-forward-only/v1\"", "\"outcome\":\"committed\"",
            "\"number\":\"1\"", "\"expected_version\":\"1\"", "\"git_objects_created\":false",
            "\"coupled_pr_and_ref\":true", "\"current_refs_asserted\":false", "\"delivery_acknowledged\":null",
        ] { assert!(receipt.contains(field), "{receipt}"); }
        let after = observed(&scratch.0, format);
        assert_eq!((after.0, after.1), (f.source, true));
        let retry = command(&args).output().unwrap();
        assert_eq!(result(&retry, 0), receipt);
        assert_eq!(observed(&scratch.0, format), after, "no duplicate decision after reopening");
        let mut changed = args;
        let at = changed.iter().position(|arg| arg == "--expected-version").unwrap();
        changed[at + 1] = "2".into();
        assert!(result(&command(&changed).output().unwrap(), 2).is_empty());
        assert_eq!(observed(&scratch.0, format), after);
    }
}

#[test]
fn real_cli_divergence_is_terminal_exit_three_and_never_falls_back() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch.0, format, true);
        let args = arguments(&scratch.0, format, f.source, f.target, "cli-divergent");
        f.node.shutdown().unwrap();
        let first = command(&args).output().unwrap();
        let receipt = result(&first, 3);
        assert!(receipt.contains("\"refusal_code\":\"NonFastForwardRefused\""));
        assert!(receipt.contains("\"outcome\":\"refused\""));
        let after = observed(&scratch.0, format);
        assert_eq!((after.0, after.1), (f.target, false));
        assert_eq!(result(&command(&args).output().unwrap(), 3), receipt);
        assert_eq!(observed(&scratch.0, format), after);
    }
}

#[test]
fn real_cli_does_not_turn_trusted_local_into_a_review_bypass() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let mut f = fixture(&scratch.0, format, false);
    let protection = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![actor(2)],
            branches: vec![ProtectedBranch { name: main_ref(), reviewers: vec![actor(3)] }],
        },
    };
    let request = f.node.request_context();
    committed(f.node.runtime().block_on(f.node.admit_review_protection_durable_in(
        &request, &session(b"cli-protection"), &protection, Default::default()
    )).unwrap().1);
    let args = arguments(&scratch.0, format, f.source, f.target, "cli-protected");
    f.node.shutdown().unwrap();
    let output = command(&args).output().unwrap();
    assert!(result(&output, 3).contains("\"outcome\":\"refused\""));
    let state = observed(&scratch.0, format);
    assert_eq!((state.0, state.1), (f.target, false));
}

#[test]
#[cfg(target_os = "linux")]
fn stdout_failure_preserves_the_commit_and_the_original_retry_resolves_it() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let mut f = fixture(&scratch.0, format, false);
    let args = arguments(&scratch.0, format, f.source, f.target, "cli-output-lost");
    f.node.shutdown().unwrap();
    let full = std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap();
    let lost = command(&args).stdout(full).output().unwrap();
    result(&lost, 2);
    let diagnostic = String::from_utf8(lost.stderr).unwrap();
    assert!(diagnostic.contains("is committed as"), "{diagnostic}");
    assert!(diagnostic.contains("receipt output failed"), "{diagnostic}");
    let before_retry = observed(&scratch.0, format);
    assert_eq!((before_retry.0, before_retry.1), (f.source, true));
    assert!(result(&command(&args).output().unwrap(), 0).contains("\"outcome\":\"committed\""));
    assert_eq!(observed(&scratch.0, format), before_retry);
}
