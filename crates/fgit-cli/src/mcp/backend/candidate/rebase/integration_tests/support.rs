//! Persisted native source/onto histories. Setup and requests use the same
//! authority, bundle and Git object owners as production, without foreign Git.
use super::super::super::super::super::protocol::{ReadTools, Server};
use super::super::super::super::Options;
use super::super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, TenantId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy)]
pub(super) enum History {
    Clean,
    Conflicted,
    BecomesEmpty,
}
pub(super) fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(pairs) else {
        unreachable!()
    };
    fields
}
fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0xe3; 16])
}
fn metadata(message: &[u8]) -> MergeMetadata {
    MergeMetadata {
        author: "Original <original@example.invalid>".into(),
        committer: "Original <original@example.invalid>".into(),
        timestamp: 1,
        message: message.to_vec(),
    }
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn apply(node: &OneNode, reference: &RefName, base: GitOid, patch: &[u8], key: &[u8]) -> GitOid {
    let request = node.request_context();
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            reference,
            base,
            [0xe4; 16],
            patch,
            &metadata(key),
            Default::default(),
        ))
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            actor(),
            key,
            reference,
            base,
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
pub(super) struct Fixture {
    root: PathBuf,
    backend: Option<NodeTools>,
    pub source: RefName,
    pub onto: RefName,
    pub base: GitOid,
    pub first: GitOid,
    pub source_tip: GitOid,
    pub onto_tip: GitOid,
    pub genesis: RepositoryAuthorityHeadId,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm, history: History) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-rebase-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0xe1; 16]);
        let repository = fgit_types::RepositoryId::from_bytes([0xe2; 16]);
        let (mut node, _) = OneNode::init(
            NodeConfig::new(root.join("node"), tenant, repository)
                .with_object_format(format)
                .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let genesis = fgit_authority::authority_head_identity(&head.body().unwrap()).unwrap();
        let onto = RefName::try_new(b"refs/heads/main").unwrap();
        let source = RefName::try_new(b"refs/heads/topic-\xff").unwrap();
        let request = node.request_context();
        let initial = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+base\ndiff --git a/sibling b/sibling\nnew file mode 100644\n--- /dev/null\n+++ b/sibling\n@@ -0,0 +1 @@\n+untouched\n";
        let (_, plan, bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &onto,
                initial,
                &metadata(b"initial\n"),
                Default::default(),
                None,
            ))
            .unwrap();
        let base = plan.commit;
        let result = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session(b"initial"),
                &onto,
                base,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session(b"source-branch"),
                &[RefCommand {
                    name: source.clone(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(base),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let onto_patch = match history {
            History::Clean => b"diff --git a/onto-only b/onto-only\nnew file mode 100644\n--- /dev/null\n+++ b/onto-only\n@@ -0,0 +1 @@\n+onto\n".as_slice(),
            History::Conflicted | History::BecomesEmpty => b"diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+onto\n".as_slice(),
        };
        let onto_tip = apply(&node, &onto, base, onto_patch, b"onto\n");
        let first_patch = match history {
            History::Clean => b"diff --git a/first-file b/first-file\nnew file mode 100644\n--- /dev/null\n+++ b/first-file\n@@ -0,0 +1 @@\n+first\n".as_slice(),
            History::Conflicted => b"diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+first\n".as_slice(),
            History::BecomesEmpty => onto_patch,
        };
        let first = apply(&node, &source, base, first_patch, b"first original\r\n");
        let source_tip = if matches!(history, History::BecomesEmpty) {
            first
        } else {
            let patch = if matches!(history, History::Conflicted) {
                b"diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-first\n+second\n".as_slice()
            } else {
                b"diff --git a/second-file b/second-file\nnew file mode 100644\n--- /dev/null\n+++ b/second-file\n@@ -0,0 +1 @@\n+second\n".as_slice()
            };
            apply(&node, &source, first, patch, b"second original\n")
        };
        let incarnation = node.repository_incarnation_id();
        node.shutdown().unwrap();
        let backend = NodeTools::open(Options {
            storage: root.join("node"),
            tenant,
            repository,
            format,
            incarnation: Some(incarnation),
            issues: false,
            discussions: false,
            pulls: false,
            source: true,
            writes: Default::default(),
            outcomes: false,
            principal: None,
            queues: Default::default(),
            agent_context: false,
            artifacts: false,
            artifact_root: None,
            agent_token_file: None,
            max_messages: 64,
            index_maintenance: None,
        })
        .unwrap();
        Self {
            root,
            backend: Some(backend),
            source,
            onto,
            base,
            first,
            source_tip,
            onto_tip,
            genesis,
        }
    }
    pub fn backend(&self) -> &NodeTools {
        self.backend.as_ref().unwrap()
    }
    pub fn backend_mut(&mut self) -> &mut NodeTools {
        self.backend.as_mut().unwrap()
    }
    pub fn reopen(&mut self, options: Options) {
        self.backend.take().unwrap().close().unwrap();
        self.backend = Some(NodeTools::open(options).unwrap());
    }
    pub fn allow_publication(&mut self) {
        let mut options = self.backend().options.clone();
        options.writes.source = true;
        options.principal = Some(actor());
        self.reopen(options);
    }
    pub fn refs(&self) -> std::collections::BTreeMap<RefName, GitOid> {
        let node = &self.backend().node;
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        selected.snapshot().refs.clone()
    }
    pub fn head(&self) -> (RepositoryAuthorityHeadId, Vec<u8>) {
        let backend = self.backend();
        let head = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        (
            fgit_authority::authority_head_identity(&head.body().unwrap()).unwrap(),
            head.receipt().body().to_vec(),
        )
    }
    pub fn args(&self) -> Object {
        fields([
            ("operation", text(PREPARE)),
            ("profile", text("linear-v1")),
            ("reference_hex", text(hex(self.source.as_bytes()))),
            ("onto_reference_hex", text(hex(self.onto.as_bytes()))),
            ("expected_source", text(raw_oid(self.source_tip))),
            ("expected_onto", text(raw_oid(self.onto_tip))),
            ("upstream", text(raw_oid(self.base))),
            ("expected_head", text(head_token(self.head().0))),
            ("empty", text("stop")),
            ("committer", text("Rebaser <rebaser@example.invalid>")),
            ("timestamp", text("2")),
        ])
    }
    pub fn resolve(&self, prepared: &Object, rows: Vec<Value>) -> Object {
        let mut args = self.args();
        args.insert("operation".into(), text(RESOLVE));
        args.insert("expected_head".into(), prepared["snapshot_token"].clone());
        args.insert("empty".into(), prepared["empty"].clone());
        args.insert("resolutions".into(), Value::Array(rows));
        args
    }
    pub fn call(&mut self, args: &Object) -> Result<Value, ToolError> {
        self.call_tool(NAME, args)
    }
    pub fn call_tool(&mut self, tool: &str, args: &Object) -> Result<Value, ToolError> {
        self.backend_mut().call(tool, args)
    }
    pub fn protocol_call(&mut self, args: Object) -> Value {
        self.protocol_tool_call(NAME, args)
    }
    pub fn protocol_tool_call(&mut self, tool: &str, args: Object) -> Value {
        let backend = self.backend_mut();
        let mut server = Server::new(backend).unwrap();
        server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rebase-test","version":"1"}}}"#).unwrap();
        server.receive(
            backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let wire = object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(2)),
            ("method", text("tools/call")),
            (
                "params",
                object([("name", text(tool)), ("arguments", Value::Object(args))]),
            ),
        ])
        .encode(json::MAX_INPUT)
        .unwrap();
        server.receive(backend, wire.as_bytes()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            backend.close().unwrap();
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
pub(super) fn content(response: &Value) -> &Object {
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false));
    result["structuredContent"].object().unwrap()
}
pub(super) fn recipe(original: GitOid, choice: &str) -> Value {
    object([
        ("original", text(raw_oid(original))),
        (
            "paths",
            Value::Array(vec![object([
                ("path_hex", text(hex(b"README"))),
                ("choice", text(choice)),
            ])]),
        ),
    ])
}
