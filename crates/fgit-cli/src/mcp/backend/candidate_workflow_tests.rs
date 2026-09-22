//! Persisted, native source -> candidate -> review -> coupled merge scenarios.
//! No Git subprocess, mocked authority, or precomputed approval is used.
use super::super::{
    WriteGrants,
    protocol::{self, Server},
};
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::{MergeMetadata, MergePreparation};
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Cursor, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"candidate-workflow","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const OPENER: u8 = 0x60;
const REVIEWER: u8 = 0x61;
const MERGER: u8 = 0x62;
fn actor(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}
fn reference(name: &str) -> RefName {
    RefName::try_new(name.as_bytes()).unwrap()
}
fn session(principal: u8, key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        actor(principal),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn metadata(timestamp: u64) -> MergeMetadata {
    MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp,
        message: b"native candidate workflow\n".to_vec(),
    }
}
fn config(options: &Options) -> NodeConfig {
    NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)
        .with_worker_threads(2)
}
fn state(node: &OneNode) -> (RepositoryAuthorityHeadId, BTreeMap<RefName, GitOid>) {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    (selected.basis().id(), selected.snapshot().refs.clone())
}
struct Fixture {
    root: PathBuf,
    options: Options,
    coordinates: Object,
    candidate: GitOid,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-candidates-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut options = Options {
            storage: root.join("node"),
            tenant: TenantId::from_bytes([0x71; 16]),
            repository: RepositoryId::from_bytes([0x72; 16]),
            format,
            incarnation: None,
            issues: false,
            pulls: false,
            source: false,
            writes: WriteGrants::default(),
            outcomes: true,
            principal: Some(actor(OPENER)),
            max_messages: 128,
        };
        let (mut node, _) = OneNode::init(config(&options)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let main = reference("refs/heads/main");
        let topic = reference("refs/heads/topic");
        let patch = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+before\n";
        let (_, root_plan, root_bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &main,
                patch,
                &metadata(1),
                Default::default(),
                None,
            ))
            .unwrap();
        let published = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session(OPENER, "root"),
                &main,
                root_plan.commit,
                root_bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let branch = RefCommand {
            name: topic.clone(),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(root_plan.commit),
            force: false,
        };
        let published = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session(OPENER, "topic"),
                &[branch],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        // Divergent branches touch distinct paths, requiring a real two-parent
        // candidate rather than a fast-forward/no-op preparation result.
        for (branch, patch, timestamp, key) in [
            (&topic, b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-before\n+topic\n".as_slice(), 2, "source"),
            (&main, b"diff --git a/target b/target\nnew file mode 100644\n--- /dev/null\n+++ b/target\n@@ -0,0 +1 @@\n+target\n".as_slice(), 3, "target"),
        ] {
            let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
                &request, branch, root_plan.commit, [timestamp as u8; 16], patch, &metadata(timestamp), Default::default(),
            )).unwrap();
            let published = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
                &request, actor(OPENER), key.as_bytes(), branch, root_plan.commit,
                candidate.candidate_commit, candidate.bundle_bytes(),
            )).unwrap();
            assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        }
        let refs = state(&node).1;
        let command = PullRequestCommand {
            number: PullRequestNumber::try_new(7).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: topic.clone(),
                target_ref: main.clone(),
                source_tip: refs[&topic],
                target_tip: refs[&main],
                title: "Native candidate".into(),
                body: "Exact review".into(),
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &request,
                &session(OPENER, "open-pr"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let before = state(&node);
        let prepared = node
            .runtime()
            .block_on(node.prepare_merge_bundle_in(
                &request,
                &main,
                &topic,
                &Default::default(),
                &metadata(4),
                Default::default(),
            ))
            .unwrap();
        assert_eq!(
            state(&node),
            before,
            "preparing a candidate must not publish objects or refs"
        );
        let MergePreparation::Clean(plan) = prepared.outcome else {
            panic!("clean divergent candidate required")
        };
        let bundle = prepared.bundle.unwrap();
        assert!(bundle.len() <= review_writes::MAX_BUNDLE_BYTES);
        let Value::Object(coordinates) = object([
            ("number", text("7")),
            ("expected_version", text("1")),
            ("source_reference", text("refs/heads/topic")),
            ("target_reference", text("refs/heads/main")),
            ("expected_source", text(plan.source.to_string())),
            ("expected_target", text(plan.target.to_string())),
            ("merge_base", text(plan.base.to_string())),
            ("candidate_commit", text(plan.commit.to_string())),
            ("policy_epoch", text("1")),
            (
                "bundle_hex_chunks",
                Value::Array(bundle.chunks(8192).map(|chunk| text(hex(chunk))).collect()),
            ),
        ]) else {
            unreachable!()
        };
        options.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        Self {
            root,
            options,
            coordinates,
            candidate: plan.commit,
        }
    }
    fn options(&self, principal: u8, reviews: bool, merges: bool) -> Options {
        let mut options = self.options.clone();
        options.principal = Some(actor(principal));
        options.writes = WriteGrants {
            reviews,
            merges,
            ..Default::default()
        };
        options
    }
    fn review(&self, key: &str, version: &str, decision: &str) -> Object {
        let mut args = self.coordinates.clone();
        args.insert("idempotency_key".into(), text(key));
        args.insert("review_version".into(), text(version));
        args.insert("decision".into(), text(decision));
        // Request-changes and withdrawal require an explicit nonblank reason.
        args.insert(
            "reason".into(),
            text("Operator decision on this exact candidate"),
        );
        if decision == "withdraw" {
            args.remove("bundle_hex_chunks");
        }
        args
    }
    fn merge(&self, key: &str, reviewers: &[u8]) -> Object {
        let mut args = self.coordinates.clone();
        args.insert("idempotency_key".into(), text(key));
        args.insert(
            "required_reviewers".into(),
            Value::Array(
                reviewers
                    .iter()
                    .map(|byte| text(actor(*byte).to_string()))
                    .collect(),
            ),
        );
        args
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn start(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, INIT.as_bytes()).unwrap();
    assert!(server.receive(backend, READY.as_bytes()).is_none());
    server
}
fn message(id: u64, name: &str, args: Object) -> String {
    object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(name)), ("arguments", Value::Object(args))]),
        ),
    ])
    .encode(json::MAX_INPUT)
    .unwrap()
}
fn invoke(
    server: &mut Server,
    backend: &mut NodeTools,
    id: u64,
    name: &str,
    args: Object,
) -> Value {
    server
        .receive(backend, message(id, name, args).as_bytes())
        .unwrap()
}
fn result(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"]
        .object()
        .unwrap()
}
fn assert_outcome(value: &Value, expected: &str) {
    assert_eq!(result(value)["outcome"].text(), Some(expected), "{value:?}");
    assert_eq!(result(value)["terminal"], Value::Bool(true));
    assert_eq!(result(value)["outcome_unknown"], Value::Bool(false));
    assert_eq!(
        value.object().unwrap()["result"].object().unwrap()["isError"],
        Value::Bool(expected == "refused")
    );
}

#[test]
fn missing_review_refusal_exact_approval_coupled_merge_and_stopped_recovery_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut merger = NodeTools::open(fixture.options(MERGER, false, true)).unwrap();
        let mut server = start(&mut merger);
        let original_refs = state(&merger.node).1;
        let refused = invoke(
            &mut server,
            &mut merger,
            2,
            merge_writes::NAME,
            fixture.merge("before-review", &[REVIEWER]),
        );
        assert_outcome(&refused, "refused");
        assert_eq!(state(&merger.node).1, original_refs);
        assert!(
            review_writes::call(&merger, &fixture.review("no-review-grant", "0", "approve"))
                .unwrap_err()
                .invalid
        );
        merger.close().unwrap();

        let mut reviewer = NodeTools::open(fixture.options(REVIEWER, true, false)).unwrap();
        let mut server = start(&mut reviewer);
        assert_eq!(reviewer.tools().len(), 2); // review + separately granted recovery, no reads or merge
        assert!(reviewer.is_mutation(review_writes::NAME));
        assert!(!reviewer.is_mutation(merge_writes::NAME));
        assert!(
            merge_writes::call(&reviewer, &fixture.merge("no-merge-grant", &[OPENER]))
                .unwrap_err()
                .invalid
        );
        let approved = invoke(
            &mut server,
            &mut reviewer,
            2,
            review_writes::NAME,
            fixture.review("approve", "0", "approve"),
        );
        assert_outcome(&approved, "committed");
        assert_eq!(state(&reviewer.node).1, original_refs);
        let head = state(&reviewer.node).0;
        let retry = invoke(
            &mut server,
            &mut reviewer,
            3,
            review_writes::NAME,
            fixture.review("approve", "0", "approve"),
        );
        assert_eq!(result(&retry), result(&approved));
        assert_eq!(state(&reviewer.node).0, head);
        let stale = invoke(
            &mut server,
            &mut reviewer,
            4,
            review_writes::NAME,
            fixture.review("stale-review", "0", "approve"),
        );
        assert_outcome(&stale, "refused");
        assert_eq!(state(&reviewer.node).1, original_refs);
        reviewer.close().unwrap();

        let mut merger = NodeTools::open(fixture.options(MERGER, false, true)).unwrap();
        let mut server = start(&mut merger);
        let held = state(&merger.node).0;
        // A newly acquired approval must not rewrite an earlier terminal refusal.
        let retry = invoke(
            &mut server,
            &mut merger,
            2,
            merge_writes::NAME,
            fixture.merge("before-review", &[REVIEWER]),
        );
        assert_eq!(result(&retry), result(&refused));
        assert_eq!(state(&merger.node).0, held);
        let merged = invoke(
            &mut server,
            &mut merger,
            3,
            merge_writes::NAME,
            fixture.merge("publish", &[REVIEWER]),
        );
        assert_outcome(&merged, "committed");
        assert_eq!(result(&merged)["coupled_pr_and_ref"], Value::Bool(true));
        let (head, refs) = state(&merger.node);
        assert_eq!(refs[&reference("refs/heads/main")], fixture.candidate);
        assert_eq!(
            refs[&reference("refs/heads/topic")],
            original_refs[&reference("refs/heads/topic")]
        );
        let request = merger.node.request_context();
        let reviews = merger
            .node
            .runtime()
            .block_on(merger.node.read_reviews_in(
                &request,
                &Default::default(),
                PullRequestNumber::try_new(7).unwrap(),
                None,
                20,
                None,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(
            reviews.pull_request_version.get(),
            2,
            "PR advances in the same merge transaction"
        );
        let options = merger.options.clone();
        merger.close().unwrap();
        let mut stopped = NodeTools {
            node: OneNode::open_existing(config(&options)).unwrap(),
            options,
        };
        let mut server = start(&mut stopped);
        let retry = invoke(
            &mut server,
            &mut stopped,
            2,
            merge_writes::NAME,
            fixture.merge("publish", &[REVIEWER]),
        );
        assert_eq!(result(&retry), result(&merged));
        let recovered = invoke(
            &mut server,
            &mut stopped,
            3,
            outcomes::NAME,
            object([("idempotency_key", text("publish"))])
                .object()
                .unwrap()
                .clone(),
        );
        assert_eq!(result(&recovered)["tx_id"], result(&merged)["tx_id"]);
        let fresh = invoke(
            &mut server,
            &mut stopped,
            4,
            merge_writes::NAME,
            fixture.merge("new-stopped", &[REVIEWER]),
        );
        assert_eq!(result(&fresh)["outcome_unknown"], Value::Bool(true));
        stopped
            .node
            .bring_into_service(HeadGeneration::FIRST)
            .unwrap();
        assert_eq!(state(&stopped.node), (head, refs));
        stopped.close().unwrap();
    }
}

#[test]
fn withdrawal_removes_gate_satisfaction_and_review_stream_predecessors_are_not_refreshed() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut reviewer = NodeTools::open(fixture.options(REVIEWER, true, false)).unwrap();
    let mut server = start(&mut reviewer);
    for (id, key, version, decision) in [
        (2, "approve", "0", "approve"),
        (3, "changes", "1", "request-changes"),
        (4, "withdraw", "2", "withdraw"),
    ] {
        let answer = invoke(
            &mut server,
            &mut reviewer,
            id,
            review_writes::NAME,
            fixture.review(key, version, decision),
        );
        assert_outcome(&answer, "committed");
    }
    let before = state(&reviewer.node).1;
    reviewer.close().unwrap();
    let mut merger = NodeTools::open(fixture.options(MERGER, false, true)).unwrap();
    let mut server = start(&mut merger);
    let refused = invoke(
        &mut server,
        &mut merger,
        2,
        merge_writes::NAME,
        fixture.merge("withdrawn", &[REVIEWER]),
    );
    assert_outcome(&refused, "refused");
    assert_eq!(state(&merger.node).1, before);
    merger.close().unwrap();
    let mut reviewer = NodeTools::open(fixture.options(REVIEWER, true, false)).unwrap();
    let mut server = start(&mut reviewer);
    let approved = invoke(
        &mut server,
        &mut reviewer,
        2,
        review_writes::NAME,
        fixture.review("approve-again", "3", "approve"),
    );
    assert_outcome(&approved, "committed");
    reviewer.close().unwrap();
    let mut merger = NodeTools::open(fixture.options(MERGER, false, true)).unwrap();
    let mut server = start(&mut merger);
    let merged = invoke(
        &mut server,
        &mut merger,
        2,
        merge_writes::NAME,
        fixture.merge("after-withdrawal", &[REVIEWER]),
    );
    assert_outcome(&merged, "committed");
    merger.close().unwrap();
}

struct LoseToolReply {
    frames: usize,
}
impl Write for LoseToolReply {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.frames != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "lost committed reply",
            ));
        }
        self.frames += bytes.iter().filter(|byte| **byte == b'\n').count();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn lost_merge_stdout_is_recovered_by_original_key_with_no_write_grant() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let reviewer = NodeTools::open(fixture.options(REVIEWER, true, false)).unwrap();
    let approval =
        review_writes::call(&reviewer, &fixture.review("approve", "0", "approve")).unwrap();
    assert_eq!(
        approval.object().unwrap()["outcome"].text(),
        Some("committed")
    );
    reviewer.close().unwrap();
    let mut merger = NodeTools::open(fixture.options(MERGER, false, true)).unwrap();
    let input = format!(
        "{INIT}\n{READY}\n{}\n",
        message(
            2,
            merge_writes::NAME,
            fixture.merge("lost-merge", &[REVIEWER])
        )
    );
    assert!(
        protocol::serve(
            &mut Cursor::new(input.into_bytes()),
            &mut LoseToolReply { frames: 0 },
            &mut merger,
            8
        )
        .is_err()
    );
    assert_eq!(
        state(&merger.node).1[&reference("refs/heads/main")],
        fixture.candidate
    );
    merger.close().unwrap();
    let mut recovery = NodeTools::open(fixture.options(MERGER, false, false)).unwrap();
    assert_eq!(recovery.tools().len(), 1);
    let mut server = start(&mut recovery);
    let recovered = invoke(
        &mut server,
        &mut recovery,
        2,
        outcomes::NAME,
        object([("idempotency_key", text("lost-merge"))])
            .object()
            .unwrap()
            .clone(),
    );
    assert_eq!(result(&recovered)["outcome"].text(), Some("committed"));
    assert!(
        merge_writes::call(&recovery, &fixture.merge("no-grant", &[REVIEWER]))
            .unwrap_err()
            .invalid
    );
    recovery.close().unwrap();
}
