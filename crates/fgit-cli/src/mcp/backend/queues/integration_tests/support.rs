//! Native patch publication supplies real commit ancestry to MCP queue tests.
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    GitOid, HeadGeneration, PrincipalId, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"queue-tests","version":"1"}}}"#;
pub(super) const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
pub(super) fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0x83; 16])
}
pub(super) fn reference(name: &str) -> RefName {
    RefName::try_new(name.as_bytes()).unwrap()
}
pub(super) fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        actor(),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
pub(super) fn fields<const N: usize>(rows: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(rows) else {
        unreachable!()
    };
    fields
}
pub(super) fn value<'a>(value: &'a Value, key: &str) -> &'a str {
    value.object().unwrap()[key].text().unwrap()
}
pub(super) fn message(id: u64, name: &str, args: Object) -> String {
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
pub(super) fn invoke(backend: &mut NodeTools, name: &str, args: Object) -> Value {
    let mut server = protocol::Server::new(backend).unwrap();
    server.receive(backend, INIT.as_bytes()).unwrap();
    assert!(server.receive(backend, READY.as_bytes()).is_none());
    let reply = server
        .receive(backend, message(2, name, args).as_bytes())
        .unwrap();
    let result = reply.object().unwrap()["result"].object().unwrap();
    let value = result["structuredContent"].clone();
    if is_mutation(backend.options.queues, name) {
        assert_eq!(
            result["isError"],
            Value::Bool(value.object().unwrap()["outcome"].text() == Some("refused"))
        );
    }
    value
}
pub(super) fn selected_head(backend: &NodeTools) -> RepositoryAuthorityHeadId {
    backend
        .node
        .runtime()
        .block_on(backend.node.materialize_admission())
        .unwrap()
        .basis()
        .id()
}
pub(super) fn refs(backend: &NodeTools) -> BTreeMap<RefName, GitOid> {
    backend
        .node
        .runtime()
        .block_on(backend.node.materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}
pub(super) fn show(backend: &mut NodeTools, number: u64) -> Value {
    invoke(
        backend,
        SHOW,
        fields([("number", text(number.to_string()))]),
    )
}
pub(super) fn assert_queue(value: &Value, version: u64, order: &[u64]) {
    let fields = value.object().unwrap();
    assert_eq!(fields["found"], Value::Bool(true));
    assert_eq!(fields["version"], text(version.to_string()));
    let queue = fields["queue"].object().unwrap();
    assert_eq!(queue["version"], text(version.to_string()));
    assert_eq!(
        queue["order"],
        Value::Array(order.iter().map(|n| text(n.to_string())).collect())
    );
    assert_eq!(queue["active_batch"], Value::Null);
    let Value::Array(entries) = &queue["entries"] else {
        panic!()
    };
    assert_eq!(entries.len(), order.len());
    assert!(
        entries
            .iter()
            .all(|entry| entry.object().unwrap()["enqueued_by"] == text(actor().to_string()))
    );
}

pub(super) struct Fixture {
    root: PathBuf,
    pub options: Options,
    pub source: GitOid,
    pub target: GitOid,
}
impl Fixture {
    pub fn config(&self) -> NodeConfig {
        configuration(&self.options)
    }
    pub fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-queues-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut options = Options {
            storage: root.join("node"),
            tenant: TenantId::from_bytes([0x81; 16]),
            repository: RepositoryId::from_bytes([0x82; 16]),
            format,
            incarnation: None,
            issues: false,
            pulls: false,
            source: false,
            queues: QueueGrants {
                read: true,
                write: true,
                land: true,
            },
            agent_context: false,
            artifacts: false,
            artifact_root: None,
            writes: Default::default(),
            outcomes: true,
            principal: Some(actor()),
            max_messages: 64,
        };
        let (mut node, _) = OneNode::init(configuration(&options)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let target_ref = reference("refs/heads/main");
        let source_ref = reference("refs/heads/topic");
        let metadata = MergeMetadata {
            author: "A <a@example.invalid>".into(),
            committer: "C <c@example.invalid>".into(),
            timestamp: 1,
            message: b"native queue fixture\n".to_vec(),
        };
        let patch = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+base\n";
        let (_, plan, bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &target_ref,
                patch,
                &metadata,
                Default::default(),
                None,
            ))
            .unwrap();
        let target = plan.commit;
        let published = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session("seed-target"),
                &target_ref,
                target,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let created = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session("seed-topic"),
                &[RefCommand {
                    name: source_ref.clone(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(target),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let patch = b"diff --git a/feature b/feature\nnew file mode 100644\n--- /dev/null\n+++ b/feature\n@@ -0,0 +1 @@\n+candidate\n";
        let prepared = node
            .runtime()
            .block_on(node.prepare_trusted_patch_in(
                &request,
                &source_ref,
                target,
                [0x85; 16],
                patch,
                &metadata,
                Default::default(),
            ))
            .unwrap();
        let source = prepared.candidate_commit;
        let published = node
            .runtime()
            .block_on(node.apply_workspace_bundle_durable_in(
                &request,
                actor(),
                b"publish-topic",
                &source_ref,
                target,
                source,
                prepared.bundle_bytes(),
            ))
            .unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        for number in [7, 9] {
            let command = PullRequestCommand {
                number: PullRequestNumber::try_new(number).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: PullRequestAction::Open,
                data: PullRequestData {
                    source_ref: source_ref.clone(),
                    target_ref: target_ref.clone(),
                    source_tip: source,
                    target_tip: target,
                    title: format!("Native queue PR {number}"),
                    body: "Literal repository text, not authority".into(),
                },
            };
            let (_, outcome) = node
                .runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &request,
                    &session(&format!("open-{number}")),
                    &command,
                    Default::default(),
                ))
                .unwrap();
            assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        }
        options.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        Self {
            root,
            options,
            source,
            target,
        }
    }
    pub fn command(&self, name: &str, number: u64, version: u64, pull: u64, key: &str) -> Object {
        let mut fields = fields([
            ("number", text(number.to_string())),
            ("expected_version", text(version.to_string())),
            (
                "expected_incarnation",
                text(self.options.incarnation.unwrap().to_string()),
            ),
            ("object_format", text(self.options.format.as_str())),
            ("idempotency_key", text(key)),
            ("target_reference", text("refs/heads/main")),
        ]);
        if matches!(name, ENQUEUE | LAND) {
            fields.extend([
                ("pull_request".into(), text(pull.to_string())),
                ("expected_pull_request_version".into(), text("1")),
                ("source_reference".into(), text("refs/heads/topic")),
                ("expected_source".into(), text(self.source.to_string())),
                ("expected_target".into(), text(self.target.to_string())),
            ]);
            if name == LAND {
                fields.insert("expected_policy_epoch".into(), text("1"));
            }
        } else if name == DEQUEUE {
            fields.insert("pull_request".into(), text(pull.to_string()));
            fields.insert("reason".into(), text("withdrawn"));
        }
        fields
    }
}
fn configuration(options: &Options) -> NodeConfig {
    NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)
        .with_worker_threads(2)
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
