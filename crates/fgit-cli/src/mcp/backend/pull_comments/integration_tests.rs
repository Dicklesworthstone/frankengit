//! Real persisted authority; the protocol never substitutes an in-memory PR.
use super::super::super::protocol::ReadTools;
use super::super::super::{Options, WriteGrants};
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ACTOR: PrincipalId = PrincipalId::from_bytes([0xc3; 16]);

struct Fixture {
    root: PathBuf,
    options: Options,
    base: GitOid,
    source: GitOid,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        Self::with_changed_source(format, false)
    }

    fn with_changed_source(format: GitHashAlgorithm, changed: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-comments-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut options = Options {
            storage: root.join("node"),
            tenant: TenantId::from_bytes([0xc1; 16]),
            repository: RepositoryId::from_bytes([0xc2; 16]),
            format,
            incarnation: None,
            issues: false,
            pulls: true,
            source: false,
            writes: WriteGrants {
                pulls: true,
                ..Default::default()
            },
            outcomes: true,
            principal: Some(ACTOR),
            artifacts: false,
            artifact_root: None,
            max_messages: 64,
        };
        let (mut node, _) = OneNode::init(config(&options)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = fgit_cli::command_request_context(&node);
        let main = RefName::try_new(b"refs/heads/main").unwrap();
        let topic = RefName::try_new(b"refs/heads/topic").unwrap();
        let metadata = MergeMetadata {
            author: "A <a@example.invalid>".into(),
            committer: "C <c@example.invalid>".into(),
            timestamp: 1,
            message: b"root\n".to_vec(),
        };
        let patch = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+base\n";
        let (_, plan, bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &main,
                patch,
                &metadata,
                Default::default(),
                None,
            ))
            .unwrap();
        let initial = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session("seed"),
                &main,
                plan.commit,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            initial.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let branch = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session("topic"),
                &[RefCommand {
                    name: topic.clone(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(plan.commit),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            branch.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let source = if changed {
            let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
                &request, &topic, plan.commit, [0xc4; 16],
                b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-base\n+reviewed\n",
                &metadata, Default::default(),
            )).unwrap();
            let result = node
                .runtime()
                .block_on(node.apply_workspace_bundle_durable_in(
                    &request,
                    ACTOR,
                    b"changed-topic",
                    &topic,
                    plan.commit,
                    candidate.candidate_commit,
                    candidate.bundle_bytes(),
                ))
                .unwrap();
            assert!(matches!(
                result.commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            candidate.candidate_commit
        } else {
            plan.commit
        };
        let command = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: topic,
                target_ref: main,
                source_tip: source,
                target_tip: plan.commit,
                title: "Discuss".into(),
                body: "Original PR body".into(),
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &request,
                &session("open"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        options.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        Self {
            root,
            options,
            base: plan.commit,
            source,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn config(options: &Options) -> NodeConfig {
    NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)
        .with_worker_threads(2)
}
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        ACTOR,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn args(version: &str, key: &str, body: &str) -> Object {
    object([
        ("number", text("1")),
        ("expected_version", text(version)),
        ("idempotency_key", text(key)),
        ("body", text(body)),
    ])
    .object()
    .unwrap()
    .clone()
}
fn read_args() -> Object {
    object([("number", text("1"))]).object().unwrap().clone()
}

#[test]
fn comments_are_durable_independent_and_identical_retries_survive_stopped_intake() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let initial = backend.call(READ, &read_args()).unwrap();
        assert_eq!(
            initial.object().unwrap()["discussion_version"].text(),
            Some("0")
        );
        let first_args = args(
            "0",
            "first-comment",
            " é\r\n<script>literal comment</script> ",
        );
        let first = backend.call(WRITE, &first_args).unwrap();
        assert_eq!(first.object().unwrap()["outcome"].text(), Some("committed"));
        assert!(backend.is_mutation(WRITE));
        assert!(!backend.is_mutation(READ));
        let second = backend
            .call(WRITE, &args("1", "second-comment", "Second"))
            .unwrap();
        assert_eq!(
            second.object().unwrap()["outcome"].text(),
            Some("committed")
        );
        let stale = backend
            .call(WRITE, &args("0", "stale-comment", "Stale"))
            .unwrap();
        assert_eq!(stale.object().unwrap()["outcome"].text(), Some("refused"));
        assert!(backend.result_is_error(WRITE, &stale));
        let page = backend.call(READ, &read_args()).unwrap();
        let held = page.object().unwrap()["snapshot_token"].clone();
        assert_eq!(
            page.object().unwrap()["discussion_version"].text(),
            Some("2")
        );
        let Value::Array(comments) = &page.object().unwrap()["comments"] else {
            panic!("comments")
        };
        assert_eq!(comments.len(), 2);
        assert_eq!(
            comments[0].object().unwrap()["body"].text(),
            Some(" é\r\n<script>literal comment</script> ")
        );
        let pr = backend.call("frankengit_pull_show", &read_args()).unwrap();
        assert_eq!(
            pr.object().unwrap()["pull_request"].object().unwrap()["version"].text(),
            Some("1")
        );
        assert_eq!(backend.call(WRITE, &first_args).unwrap(), first);
        assert_eq!(
            backend.call(READ, &read_args()).unwrap().object().unwrap()["snapshot_token"],
            held
        );
        let NodeTools { node, options } = backend;
        node.shutdown().unwrap();
        let mut stopped = NodeTools {
            node: OneNode::open_existing(config(&options)).unwrap(),
            options,
        };
        assert_eq!(stopped.call(WRITE, &first_args).unwrap(), first);
        assert_eq!(
            stopped
                .call(WRITE, &args("0", "stale-comment", "Stale"))
                .unwrap(),
            stale
        );
        assert!(
            stopped
                .call(WRITE, &args("0", "first-comment", "Changed bytes"))
                .is_err()
        );
        stopped.close().unwrap();
        let mut reader = fixture.options.clone();
        reader.writes = WriteGrants::default();
        reader.outcomes = false;
        reader.principal = None;
        let mut reader = NodeTools::open(reader).unwrap();
        assert!(!reader.tools().iter().any(|tool| tool.name == WRITE));
        assert!(reader.call(WRITE, &first_args).is_err());
        let after_restart = reader.call(READ, &read_args()).unwrap();
        assert_eq!(
            after_restart.object().unwrap()["discussion_version"].text(),
            Some("2")
        );
        reader.close().unwrap();
    }
}

#[test]
fn write_only_launch_does_not_grant_comment_reads_or_original_key_lookup() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut options = fixture.options.clone();
    options.pulls = false;
    options.outcomes = false;
    let mut backend = NodeTools::open(options).unwrap();
    assert!(backend.tools().iter().any(|tool| tool.name == WRITE));
    assert!(!backend.tools().iter().any(|tool| tool.name == READ));
    assert!(backend.call(READ, &read_args()).is_err());
    assert!(read(&backend, &read_args()).is_err());
    assert!(
        backend
            .call(
                "frankengit_transaction_outcome",
                &object([("idempotency_key", text("comment"))])
                    .object()
                    .unwrap()
                    .clone()
            )
            .is_err()
    );
    assert_eq!(
        backend
            .call(WRITE, &args("0", "comment", "Allowed append"))
            .unwrap()
            .object()
            .unwrap()["outcome"]
            .text(),
        Some("committed")
    );
    backend.close().unwrap();
}

#[test]
fn source_comments_verify_real_blob_coordinates_and_retain_anchor_identity_across_mcp_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::with_changed_source(format, true);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let anchor = object([
            ("pull_request_version", text("1")),
            (
                "source_ref_hex",
                text(fgit_crypto::lowercase_hex(b"refs/heads/topic")),
            ),
            (
                "target_ref_hex",
                text(fgit_crypto::lowercase_hex(b"refs/heads/main")),
            ),
            ("source_tip", text(fixture.source.to_string())),
            ("target_tip", text(fixture.base.to_string())),
            ("compared_base", text(fixture.base.to_string())),
            ("comparison", text("direct")),
            ("path_hex", text("66696c65")),
            ("side", text("after")),
            (
                "blob",
                text(
                    fgit_crypto::git_object_id(
                        format,
                        fgit_crypto::GitObjectKind::Blob,
                        b"reviewed\n",
                    )
                    .to_string(),
                ),
            ),
            ("mode", text("100644")),
            ("byte_start", text("0")),
            ("byte_end", text("9")),
            ("line_start", text("0")),
            ("line_count", text("1")),
        ]);
        let mut original = args("0", "source-comment", "Please explain this source change.");
        original.insert("anchor".into(), anchor.clone());
        let mut wrong_span = original.clone();
        wrong_span.insert("idempotency_key".into(), text("wrong-source-span"));
        let mut invalid_anchor = anchor.object().unwrap().clone();
        invalid_anchor.insert("byte_end".into(), text("8"));
        wrong_span.insert("anchor".into(), Value::Object(invalid_anchor));
        let refused = backend.call(WRITE, &wrong_span).unwrap();
        assert_eq!(refused.object().unwrap()["outcome"].text(), Some("refused"));
        assert_eq!(
            backend.call(READ, &read_args()).unwrap().object().unwrap()["discussion_version"]
                .text(),
            Some("0")
        );
        let accepted = backend.call(WRITE, &original).unwrap();
        assert_eq!(
            accepted.object().unwrap()["outcome"].text(),
            Some("committed")
        );
        let receipt_anchor = &accepted.object().unwrap()["anchor"];
        assert_eq!(
            receipt_anchor.object().unwrap()["byte_end"].text(),
            Some("9")
        );
        assert!(!accepted.object().unwrap().contains_key("anchor_status"));
        let first_page = backend.call(READ, &read_args()).unwrap();
        let Value::Array(rows) = &first_page.object().unwrap()["comments"] else {
            panic!("comments")
        };
        assert_eq!(rows[0].object().unwrap()["anchor"], *receipt_anchor);
        assert_eq!(
            rows[0].object().unwrap()["anchor_status"].text(),
            Some("exact")
        );
        let pinned = first_page.object().unwrap()["snapshot_token"].clone();
        let update = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: PullRequestAction::Update,
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: fixture.source,
                target_tip: fixture.base,
                title: "Updated discussion basis".into(),
                body: "Original PR body".into(),
            },
        };
        let context = fgit_cli::command_request_context(&backend.node);
        let (_, terminal) = backend
            .node
            .runtime()
            .block_on(backend.node.admit_pull_request_durable_in(
                &context,
                &session("change-pr-metadata"),
                &update,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let current = backend.call(READ, &read_args()).unwrap();
        let Value::Array(rows) = &current.object().unwrap()["comments"] else {
            panic!("comments")
        };
        assert_eq!(rows[0].object().unwrap()["anchor"], *receipt_anchor);
        assert_eq!(
            rows[0].object().unwrap()["anchor_status"].text(),
            Some("outdated")
        );
        let mut historical = read_args();
        historical.insert("expected_head".into(), pinned);
        assert_eq!(backend.call(READ, &historical).unwrap(), first_page);
        assert_eq!(backend.call(WRITE, &original).unwrap(), accepted);
        let mut stale = original.clone();
        stale.insert("idempotency_key".into(), text("new-stale-anchor"));
        stale.insert("expected_version".into(), text("1"));
        assert_eq!(
            backend.call(WRITE, &stale).unwrap().object().unwrap()["outcome"].text(),
            Some("refused")
        );
        backend.close().unwrap();
        let mut reopened = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(reopened.call(WRITE, &original).unwrap(), accepted);
        let mut changed_key = original;
        let mut changed_anchor = anchor.object().unwrap().clone();
        changed_anchor.insert("side".into(), text("before"));
        changed_key.insert("anchor".into(), Value::Object(changed_anchor));
        assert!(
            reopened.call(WRITE, &changed_key).is_err(),
            "same key cannot change source anchor"
        );
        reopened.close().unwrap();
    }
}
