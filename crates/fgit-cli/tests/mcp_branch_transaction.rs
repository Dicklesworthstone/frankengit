#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real native seed and fresh stdio MCP clients; no substitute branch store.
#[path = "../../fgit-node/tests/trusted_candidate_workflow/support.rs"]
mod support;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, RefName};
use std::process::Command;
use support::*;

#[test]
fn stdio_atomic_branches_preserve_scope_recovery_and_all_or_nothing_state() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(
            format,
            "name: unused\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n",
        );
        let child = fixture.replace_file("input.txt", "original\n", "changed\n");
        let result = fixture
            .node()
            .runtime()
            .block_on(fixture.node().apply_workspace_bundle_durable_in(
                &fixture.node().request_context(),
                PRINCIPAL,
                b"mcp-seed-child",
                &reference(),
                fixture.tip,
                child.candidate_commit,
                child.bundle_bytes(),
            ))
            .unwrap();
        assert!(
            result
                .commands
                .iter()
                .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let incarnation = fixture.node().repository_incarnation_id();
        fixture.node.take().unwrap().shutdown().unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/e2e/mcp_branch_transaction_smoke.py");
        let output = Command::new("python3")
            .arg(script)
            .arg("--binary")
            .arg(env!("CARGO_BIN_EXE_fg-mcp"))
            .arg("--storage")
            .arg(fixture.root.join("node"))
            .args([
                "--tenant",
                &TENANT.to_string(),
                "--repository",
                &REPOSITORY.to_string(),
                "--principal",
                &PRINCIPAL.to_string(),
                "--incarnation",
                &incarnation.to_string(),
                "--format",
                format.as_str(),
                "--base",
                &fixture.tip.to_string(),
                "--tip",
                &child.candidate_commit.to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = String::from_utf8(output.stdout).unwrap();
        assert!(report.contains(&format!(
            "MCP_BRANCH_TRANSACTION format={} passed",
            format.as_str()
        )));
        print!("{report}");
        fixture.reopen();
        let state = fixture
            .node()
            .runtime()
            .block_on(fixture.node().materialize_admission())
            .unwrap();
        assert_eq!(state.snapshot().refs.len(), 3);
        for name in [
            b"refs/heads/main".as_slice(),
            b"refs/heads/a",
            b"refs/heads/raw-\xff",
        ] {
            assert_eq!(
                state.snapshot().refs.get(&RefName::try_new(name).unwrap()),
                Some(&child.candidate_commit)
            );
        }
        for absent in [
            b"refs/heads/b".as_slice(),
            b"refs/heads/no-prefix",
            b"refs/heads/forbidden",
            b"refs/heads/key-reuse",
        ] {
            assert!(
                !state
                    .snapshot()
                    .refs
                    .contains_key(&RefName::try_new(absent).unwrap())
            );
        }
    }
}
