//! History-only credentials cross the real MCP dispatch and canonical ledger.
//! Fixture publication is setup; every exposed tool remains a bounded read.
use super::super::super::{head_token, hex, json};
use super::*;
use fgit_forge::preparation::MergeMetadata;
use fgit_identity::agent::{AgentCredentialId, SOURCE_HISTORY_READ, SOURCE_READ};
use fgit_types::{DecisionOutcome, GitOid, RefName, RepositoryAuthorityHeadId};

const TOPIC: &str = "refs/heads/agent/topic";
const OLD: &[u8] = b"agent MCP fixture\n";
const NEW: &[u8] = b"reviewed history fixture\n";
const TOOLS: [&str; 5] = [
    "frankengit_source_log",
    "frankengit_source_blame",
    "frankengit_source_historical_tree",
    "frankengit_source_historical_blob",
    "frankengit_source_compare",
];

struct HistoryFixture {
    fixture: Fixture,
    options: Options,
    credential: AgentCredentialId,
    tip: GitOid,
}

impl HistoryFixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let fixture = Fixture::new(format);
        let administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let node = &administrator.node;
        let credential = issue(
            node,
            &token(0x51),
            grant(node, SOURCE_HISTORY_READ),
            "issue-history-only",
        );
        for (byte, operations) in [(0x52, SOURCE_READ), (0x53, 0x00ff)] {
            issue(
                node,
                &token(byte),
                grant(node, operations),
                &format!("issue-existing-scopes-{byte}"),
            );
        }
        let reference = RefName::try_new(TOPIC.as_bytes()).unwrap();
        let request = node.command_request_context(None);
        let metadata = MergeMetadata {
            author: "A <a@example.invalid>".into(),
            committer: "C <c@example.invalid>".into(),
            timestamp: 2,
            message: b"history scope fixture change\n".to_vec(),
        };
        let patch = b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-agent MCP fixture\n+reviewed history fixture\n";
        let candidate = node
            .runtime()
            .block_on(node.prepare_trusted_patch_in(
                &request,
                &reference,
                fixture.tip,
                [0x51; 16],
                patch,
                &metadata,
                Default::default(),
            ))
            .unwrap();
        let result = node
            .runtime()
            .block_on(node.apply_workspace_bundle_durable_in(
                &request,
                SPONSOR,
                b"seed-agent-history-change",
                &reference,
                fixture.tip,
                candidate.candidate_commit,
                candidate.bundle_bytes(),
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        administrator.close().unwrap();
        let mut options = fixture.replacement(0x51);
        options.source = true;
        options.issues = false;
        options.discussions = false;
        options.pulls = false;
        options.outcomes = false;
        options.writes = Default::default();
        Self {
            fixture,
            options,
            credential,
            tip: candidate.candidate_commit,
        }
    }

    fn query(&self, name: &str, head: RepositoryAuthorityHeadId) -> Object {
        let mut args = object([
            ("reference", text(TOPIC)),
            ("expected_head", text(head_token(head))),
        ])
        .object()
        .unwrap()
        .clone();
        match name {
            "frankengit_source_log" => {
                args.insert("expected_commit".into(), text(self.tip.to_string()));
            }
            "frankengit_source_blame" => {
                args.insert("path_hex".into(), text(hex(b"file")));
                args.insert("expected_commit".into(), text(self.tip.to_string()));
            }
            "frankengit_source_historical_tree" | "frankengit_source_historical_blob" => {
                args.insert("expected_ref_tip".into(), text(self.tip.to_string()));
                args.insert("at_commit".into(), text(self.fixture.tip.to_string()));
                if name == "frankengit_source_historical_blob" {
                    args.insert("path_hex".into(), text(hex(b"file")));
                }
            }
            "frankengit_source_compare" => {
                args.remove("reference");
                args.insert("before_ref".into(), text("refs/heads/main"));
                args.insert("after_ref".into(), text(TOPIC));
                args.insert("expected_before".into(), text(self.fixture.tip.to_string()));
                args.insert("expected_after".into(), text(self.tip.to_string()));
            }
            _ => panic!("unknown history test tool"),
        }
        args
    }
}

fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .basis()
        .id()
}

fn rows(value: &Value) -> &[Value] {
    let Value::Array(rows) = value else {
        panic!("array required: {value:?}");
    };
    rows
}

#[test]
fn sponsored_history_tools_read_real_ancestry_and_diffs_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = HistoryFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend.node);
        for name in TOOLS {
            assert!(backend.tools().iter().any(|tool| tool.name == name));
            assert_eq!(operation(&backend.options, name), Some(SOURCE_HISTORY_READ));
            assert!(!backend.is_mutation(name));
            let value = backend.call(name, &fixture.query(name, before)).unwrap();
            let result = value.object().unwrap();
            assert_eq!(result["snapshot_token"], text(head_token(before)));
            assert_eq!(result["read_only"], Value::Bool(true));
            match name {
                "frankengit_source_log" => {
                    let commits = rows(&result["commits"]);
                    assert_eq!(commits.len(), 2);
                    assert_eq!(
                        commits[0].object().unwrap()["id"],
                        text(fixture.tip.to_string())
                    );
                    assert_eq!(
                        commits[1].object().unwrap()["id"],
                        text(fixture.fixture.tip.to_string())
                    );
                }
                "frankengit_source_blame" => {
                    assert_eq!(result["bytes_hex"], text(hex(NEW)));
                    assert_eq!(rows(&result["lines"]).len(), 1);
                }
                "frankengit_source_historical_tree" => {
                    assert_eq!(result["at_commit"], text(fixture.fixture.tip.to_string()));
                    assert_eq!(
                        rows(&result["entries"])[0].object().unwrap()["name_hex"],
                        text(hex(b"file"))
                    );
                }
                "frankengit_source_historical_blob" => {
                    assert_eq!(result["bytes_hex"], text(hex(OLD)));
                    assert_eq!(result["source_commit"], text(fixture.fixture.tip.to_string()));
                    assert_eq!(result["source_ref_tip"], text(fixture.tip.to_string()));
                }
                "frankengit_source_compare" => {
                    assert_eq!(
                        result["requested_before"],
                        text(fixture.fixture.tip.to_string())
                    );
                    assert_eq!(result["requested_after"], text(fixture.tip.to_string()));
                    assert_eq!(rows(&result["entries"]).len(), 1);
                    let encoded = value.encode(MAX_RESPONSE).unwrap();
                    assert!(encoded.contains(&hex(OLD)) && encoded.contains(&hex(NEW)));
                }
                _ => unreachable!(),
            }
            let request = backend.agent.as_ref().unwrap().response.as_ref().unwrap();
            assert!(request.mcp_source_read_context(&backend.node).is_err());
            let session = request.authenticated_session();
            let fgit_admission::evidence::AdmissionAuthentication::AgentCredential(witness) =
                session.authenticated_session().unwrap().authentication()
            else {
                panic!("history read lost canonical agent authentication");
            };
            assert_eq!(witness.agent(), AGENT);
            assert_eq!(witness.sponsor(), SPONSOR);
            assert_eq!(witness.credential_id(), fixture.credential);
            assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
            assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
        }

        let mut recent = fixture.query(TOOLS[0], before);
        recent.insert("first_parent".into(), Value::Bool(true));
        recent.insert("limit".into(), json::number(1));
        let first = backend.call(TOOLS[0], &recent).unwrap();
        assert_eq!(rows(&first.object().unwrap()["commits"]).len(), 1);
        recent.insert(
            "cursor".into(),
            first.object().unwrap()["next_cursor"].clone(),
        );
        let next = backend.call(TOOLS[0], &recent).unwrap();
        assert_eq!(
            rows(&next.object().unwrap()["commits"])[0].object().unwrap()["id"],
            text(fixture.fixture.tip.to_string())
        );

        // The new commit exists in the repository, but is not an ancestor of
        // main. Historical browsing must prove reachability from its own ref.
        let mut unrelated = fixture.query(TOOLS[3], before);
        unrelated.insert("reference".into(), text("refs/heads/main"));
        unrelated.insert(
            "expected_ref_tip".into(),
            text(fixture.fixture.tip.to_string()),
        );
        unrelated.insert("at_commit".into(), text(fixture.tip.to_string()));
        assert_eq!(
            backend.call(TOOLS[3], &unrelated).unwrap_err().code,
            "reference_unavailable"
        );
        assert_eq!(authority(&backend.node), before);
        backend.close().unwrap();
    }
}

#[test]
fn sponsored_history_scope_is_independent_of_prior_scopes_and_launch_flags() {
    let fixture = HistoryFixture::new(GitHashAlgorithm::Sha256);
    for byte in [0x52, 0x53] {
        let mut options = fixture.options.clone();
        options.agent_token_file = fixture.fixture.replacement(byte).agent_token_file;
        let mut backend = NodeTools::open(options).unwrap();
        let current = object([
            ("reference", text(TOPIC)),
            ("path_hex", text(hex(b"file"))),
        ])
        .object()
        .unwrap()
        .clone();
        assert!(
            backend
                .call("frankengit_source_blob", &current)
                .is_ok()
        );
        for name in TOOLS {
            // Refusal precedes parsing, even with every legacy bit enabled.
            assert_eq!(
                backend.call(name, &Object::new()).unwrap_err().code,
                "agent_operation_not_granted"
            );
        }
        backend.close().unwrap();
    }
    let mut options = fixture.options.clone();
    options.agent_context = true;
    options.issues = true;
    options.pulls = true;
    let mut backend = NodeTools::open(options).unwrap();
    for name in [
        "frankengit_source_blob",
        "frankengit_source_tree",
        "frankengit_agent_context",
        "frankengit_issue_list",
        "frankengit_pull_list",
    ] {
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "agent_operation_not_granted"
        );
    }
    for name in [
        "frankengit_pull_diff",
        "frankengit_source_candidate",
        "frankengit_source_publish",
        "frankengit_source_verified_blob",
    ] {
        assert!(!backend.tools().iter().any(|tool| tool.name == name));
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
    }
    backend.options.source = false;
    for name in TOOLS {
        assert!(!backend.tools().iter().any(|tool| tool.name == name));
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
    }
    backend.close().unwrap();
}

#[test]
fn sponsored_history_preserves_deadlines_and_reauthenticates_revoke_and_snapshot_changes() {
    let fixture = HistoryFixture::new(GitHashAlgorithm::Sha1);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = authority(&backend.node);
    backend
        .call(TOOLS[0], &fixture.query(TOOLS[0], before))
        .unwrap();
    let mut reservation = backend.agent.as_mut().unwrap().response.take().unwrap();
    reservation.constrain_deadline(Instant::now() - Duration::from_secs(1));
    backend.agent.as_mut().unwrap().request = Some(reservation);
    assert!(!backend.command_context().is_live());
    for name in TOOLS {
        assert!(
            backend
                .call_granted(name, &fixture.query(name, before))
                .is_err(),
            "{name}"
        );
    }
    backend.agent.as_mut().unwrap().request = None;
    assert_eq!(authority(&backend.node), before);

    issue(
        &backend.node,
        &token(0x54),
        grant(&backend.node, ISSUES_READ),
        "history-snapshot-change",
    );
    for name in TOOLS {
        assert!(
            backend.call(name, &fixture.query(name, before)).is_err(),
            "{name}"
        );
    }
    let current = authority(&backend.node);
    for name in TOOLS {
        assert!(
            backend.call(name, &fixture.query(name, current)).is_ok(),
            "{name}"
        );
    }
    revoke(&backend.node, fixture.credential, "revoke-history-reader");
    let revoked = authority(&backend.node);
    for name in TOOLS {
        assert_eq!(
            backend
                .call(name, &fixture.query(name, revoked))
                .unwrap_err()
                .code,
            "agent_credential_unavailable"
        );
    }
    assert_eq!(authority(&backend.node), revoked);
    backend.close().unwrap();
}
