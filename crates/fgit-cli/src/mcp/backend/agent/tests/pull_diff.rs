//! Explicit sponsored PR-diff authority crosses the real ledger and native
//! comparison. Fixture publication is setup, never a capability of the reader.
use super::super::super::{head_token, hex, review};
use super::*;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_identity::agent::{AgentCredentialId, PULLS_DIFF_READ, SOURCE_HISTORY_READ};
use fgit_types::{DecisionOutcome, GitOid, RefName, RepositoryAuthorityHeadId};

const TOPIC: &str = "refs/heads/agent/topic";
const OLD: &str = "agent MCP fixture";
const NEW: &str = "review this exact candidate";

fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.command_request_context(None)))
        .unwrap()
        .basis()
        .id()
}

fn edit(node: &OneNode, before: GitOid, old: &str, new: &str, retry: &str) -> GitOid {
    let reference = RefName::try_new(TOPIC.as_bytes()).unwrap();
    let request = node.command_request_context(None);
    let patch =
        format!("diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-{old}\n+{new}\n");
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 2,
        message: b"sponsored diff fixture\n".to_vec(),
    };
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &reference,
            before,
            [0x65; 16],
            patch.as_bytes(),
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            SPONSOR,
            retry.as_bytes(),
            &reference,
            before,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    candidate.candidate_commit
}

struct DiffFixture {
    fixture: Fixture,
    options: Options,
    credential: AgentCredentialId,
    tip: GitOid,
}

impl DiffFixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let fixture = Fixture::new(format);
        let administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let node = &administrator.node;
        let tip = edit(node, fixture.tip, OLD, NEW, "seed-diff-change");
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.command_request_context(None),
                &operator(SPONSOR, "seed-diff-pr"),
                &PullRequestCommand {
                    number: PullRequestNumber::FIRST,
                    expected_version: ExpectedVersion::NewStream,
                    action: PullRequestAction::Open,
                    data: PullRequestData {
                        source_ref: RefName::try_new(TOPIC.as_bytes()).unwrap(),
                        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                        source_tip: tip,
                        target_tip: fixture.tip,
                        title: "Exact recorded source".into(),
                        body: "A diff grants no review or publication.".into(),
                    },
                },
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let credential = issue(
            node,
            &token(0x65),
            grant(node, PULLS_DIFF_READ),
            "issue-diff-only",
        );
        for (byte, operations) in [
            (0x66, PULLS_READ),
            (0x67, SOURCE_HISTORY_READ),
            (0x68, 0x0fff),
        ] {
            issue(
                node,
                &token(byte),
                grant(node, operations),
                &format!("old-diff-scope-{byte}"),
            );
        }
        administrator.close().unwrap();
        let mut options = fixture.replacement(0x65);
        options.source = true;
        options.pulls = true;
        options.writes = Default::default();
        Self {
            fixture,
            options,
            credential,
            tip,
        }
    }

    fn query(&self, head: RepositoryAuthorityHeadId) -> Object {
        object([
            ("number", text("1")),
            ("expected_version", text("1")),
            ("expected_head", text(head_token(head))),
            ("expected_before", text(self.fixture.tip.to_string())),
            ("expected_after", text(self.tip.to_string())),
        ])
        .object()
        .unwrap()
        .clone()
    }
}

#[test]
fn sponsored_pull_diff_reads_recorded_tips_after_branch_movement_without_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = DiffFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend.node);
        let result = backend
            .call(review::PULL_DIFF, &fixture.query(before))
            .unwrap();
        let fields = result.object().unwrap();
        assert_eq!(
            fields["requested_before"],
            text(fixture.fixture.tip.to_string())
        );
        assert_eq!(fields["requested_after"], text(fixture.tip.to_string()));
        assert_eq!(fields["entry_count"], text("1"));
        assert_eq!(fields["repository_changed"], Value::Bool(false));
        assert_eq!(fields["merge_permission"], Value::Null);
        let encoded = result.encode(MAX_RESPONSE).unwrap();
        assert!(encoded.contains(&hex(format!("{OLD}\n").as_bytes())));
        assert!(encoded.contains(&hex(format!("{NEW}\n").as_bytes())));
        let reservation = backend.agent.as_ref().unwrap().response.as_ref().unwrap();
        assert!(reservation.mcp_source_read_context(&backend.node).is_err());
        let session = reservation.authenticated_session();
        let authentication = session.authenticated_session().unwrap().authentication();
        let witness = authentication.agent_provenance().unwrap();
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.credential);
        assert_eq!(authority(&backend.node), before);

        let moved = edit(
            &backend.node,
            fixture.tip,
            NEW,
            "later unreviewed source",
            "move-diff-topic",
        );
        assert_ne!(moved, fixture.tip);
        let after = authority(&backend.node);
        assert!(
            backend
                .call(review::PULL_DIFF, &fixture.query(before))
                .is_err()
        );
        let current = backend
            .call(review::PULL_DIFF, &fixture.query(after))
            .unwrap();
        assert_eq!(
            current.object().unwrap()["requested_after"],
            text(fixture.tip.to_string())
        );
        assert!(
            !current
                .encode(MAX_RESPONSE)
                .unwrap()
                .contains(&hex(b"later unreviewed source"))
        );
        let mut stale_version = fixture.query(after);
        stale_version.insert("expected_version".into(), text("2"));
        assert!(backend.call(review::PULL_DIFF, &stale_version).is_err());
        assert_eq!(authority(&backend.node), after);
        backend.close().unwrap();
    }
}

#[test]
fn sponsored_pull_diff_requires_its_new_grant_and_both_launch_ceilings() {
    let fixture = DiffFixture::new(GitHashAlgorithm::Sha256);
    for byte in [0x66, 0x67, 0x68] {
        let mut options = fixture.fixture.replacement(byte);
        options.source = true;
        let mut backend = NodeTools::open(options).unwrap();
        assert!(
            backend
                .tools()
                .iter()
                .any(|tool| tool.name == review::PULL_DIFF)
        );
        assert_eq!(
            backend
                .call(review::PULL_DIFF, &Object::new())
                .unwrap_err()
                .code,
            "agent_operation_not_granted"
        );
        backend.close().unwrap();
    }
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    for name in [
        "frankengit_pull_show",
        "frankengit_source_blob",
        review::COMPARE,
    ] {
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "agent_operation_not_granted"
        );
    }
    for name in [
        "frankengit_pull_reviews",
        "frankengit_pull_merge",
        "frankengit_source_publish",
    ] {
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
    }
    assert_eq!(
        review::call(&backend, review::PULL_DIFF, &Object::new())
            .unwrap_err()
            .code,
        "agent_request_required"
    );
    let head = authority(&backend.node);
    assert!(
        backend
            .call(review::PULL_DIFF, &fixture.query(head))
            .is_ok()
    );
    for (source, pulls) in [(false, true), (true, false)] {
        backend.options.source = source;
        backend.options.pulls = pulls;
        assert!(
            !backend
                .tools()
                .iter()
                .any(|tool| tool.name == review::PULL_DIFF)
        );
        assert_eq!(
            backend
                .call(review::PULL_DIFF, &fixture.query(head))
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
    }
    assert_eq!(authority(&backend.node), head);
    backend.close().unwrap();
}

#[test]
fn sponsored_pull_diff_retains_request_deadline_output_budget_and_current_revocation() {
    let fixture = DiffFixture::new(GitHashAlgorithm::Sha1);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let head = authority(&backend.node);
    backend
        .call(review::PULL_DIFF, &fixture.query(head))
        .unwrap();
    assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
    assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
    let mut reservation = backend.agent.as_mut().unwrap().response.take().unwrap();
    reservation.constrain_deadline(Instant::now() - Duration::from_secs(1));
    backend.agent.as_mut().unwrap().request = Some(reservation);
    assert!(review::call(&backend, review::PULL_DIFF, &fixture.query(head)).is_err());
    assert_eq!(authority(&backend.node), head);
    backend.agent.as_mut().unwrap().request = None;
    revoke(&backend.node, fixture.credential, "revoke-diff-reader");
    let after = authority(&backend.node);
    assert_eq!(
        backend
            .call(review::PULL_DIFF, &fixture.query(after))
            .unwrap_err()
            .code,
        "agent_credential_unavailable"
    );
    assert_eq!(authority(&backend.node), after);
    backend.close().unwrap();
}
