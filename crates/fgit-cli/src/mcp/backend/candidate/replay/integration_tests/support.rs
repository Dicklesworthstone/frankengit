//! Persisted native histories and protocol calls. All graph/pack work goes
//! through OneNode; there is no foreign Git or replacement authority engine.
use super::super::super::super::super::protocol::{ReadTools, Server};
use super::super::super::super::Options;
use super::super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(pairs) else {
        unreachable!()
    };
    fields
}
pub(super) fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0xd3; 16])
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Seed <seed@example.invalid>".into(),
        committer: "Seed <seed@example.invalid>".into(),
        timestamp: 1,
        message: b"seed native replay history\n".to_vec(),
    }
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn apply_patch(
    node: &OneNode,
    reference: &RefName,
    base: GitOid,
    patch: &[u8],
    key: &[u8],
) -> GitOid {
    let request = node.request_context();
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            reference,
            base,
            [0xd4; 16],
            patch,
            &metadata(),
            Default::default(),
        ))
        .unwrap();
    let committed = node
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
        committed.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    candidate.candidate_commit
}

pub(super) struct Fixture {
    root: PathBuf,
    backend: Option<NodeTools>,
    pub reference: RefName,
    pub source: RefName,
    pub base: GitOid,
    pub target: GitOid,
    pub selected: GitOid,
    pub source_tip: GitOid,
    pub genesis: RepositoryAuthorityHeadId,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm, conflict: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-replay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0xd1; 16]);
        let repository = RepositoryId::from_bytes([0xd2; 16]);
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
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let source = RefName::try_new(b"refs/heads/topic-\xff").unwrap();
        let initial = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+base\ndiff --git a/sibling b/sibling\nnew file mode 100644\n--- /dev/null\n+++ b/sibling\n@@ -0,0 +1 @@\n+untouched\n";
        let request = node.request_context();
        let (_, plan, bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &reference,
                initial,
                &metadata(),
                Default::default(),
                None,
            ))
            .unwrap();
        let base = plan.commit;
        let admitted = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session(b"initial"),
                &reference,
                base,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let request = node.request_context();
        let created = node
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
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let target_patch = if conflict {
            b"diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+target\n".as_slice()
        } else {
            b"diff --git a/target-only b/target-only\nnew file mode 100644\n--- /dev/null\n+++ b/target-only\n@@ -0,0 +1 @@\n+target\n".as_slice()
        };
        let target = apply_patch(&node, &reference, base, target_patch, b"target");
        let selected_patch = if conflict {
            b"diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+selected\n".as_slice()
        } else {
            b"diff --git a/selected-file b/selected-file\nnew file mode 100644\n--- /dev/null\n+++ b/selected-file\n@@ -0,0 +1 @@\n+selected\n".as_slice()
        };
        let selected = apply_patch(&node, &source, base, selected_patch, b"selected");
        let later = b"diff --git a/later-file b/later-file\nnew file mode 100644\n--- /dev/null\n+++ b/later-file\n@@ -0,0 +1 @@\n+later source must not appear\n";
        let source_tip = apply_patch(&node, &source, selected, later, b"later-source");
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
            reference,
            source,
            base,
            target,
            selected,
            source_tip,
            genesis,
        }
    }
    pub fn backend(&self) -> &NodeTools {
        self.backend.as_ref().unwrap()
    }
    pub fn backend_mut(&mut self) -> &mut NodeTools {
        self.backend.as_mut().unwrap()
    }
    pub fn options(&self) -> Options {
        self.backend().options.clone()
    }
    pub fn reopen(&mut self, options: Options) {
        self.backend.take().unwrap().close().unwrap();
        self.backend = Some(NodeTools::open(options).unwrap());
    }
    pub fn allow_publication(&mut self) {
        let mut options = self.options();
        options.writes.source = true;
        options.principal = Some(actor());
        self.reopen(options);
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
    pub fn prepare_args(&self) -> Object {
        fields([
            ("operation", text(PREPARE)),
            ("profile", text("path-v1")),
            ("direction", text("cherry-pick")),
            ("reference_hex", text(hex(self.reference.as_bytes()))),
            ("source_reference_hex", text(hex(self.source.as_bytes()))),
            ("expected_base", text(raw_oid(self.target))),
            ("expected_source", text(raw_oid(self.source_tip))),
            ("selected_commit", text(raw_oid(self.selected))),
            ("expected_head", text(head_token(self.head().0))),
            ("author", text("Author <author@example.invalid>")),
            ("committer", text("Committer <committer@example.invalid>")),
            ("timestamp", text("2")),
            (
                "message_hex",
                text(hex(b"one selected historical change\r\n")),
            ),
        ])
    }
    pub fn resolve_args(&self, prepared: &Object, rows: Vec<Value>) -> Object {
        let mut args = self.prepare_args();
        args.insert("operation".into(), text(RESOLVE));
        // Retain the actual preparation snapshot, never the fixture's latest head.
        args.insert("expected_head".into(), prepared["snapshot_token"].clone());
        args.insert("resolutions".into(), Value::Array(rows));
        args
    }
    pub fn call(&mut self, tool: &str, args: &Object) -> Result<Value, ToolError> {
        self.backend_mut().call(tool, args)
    }
    pub fn blob(&mut self, path: &[u8]) -> Result<Value, ToolError> {
        let reference = std::str::from_utf8(self.reference.as_bytes())
            .unwrap()
            .to_owned();
        self.call(
            "frankengit_source_blob",
            &fields([
                ("reference", text(reference)),
                ("path_hex", text(hex(path))),
            ]),
        )
    }
    pub fn protocol_call(&mut self, tool: &str, args: Object) -> Value {
        let backend = self.backend_mut();
        let mut server = Server::new(backend).unwrap();
        server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"replay-test","version":"1"}}}"#).unwrap();
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
pub(super) fn side(path: &[u8], name: &str) -> Value {
    object([("path_hex", text(hex(path))), ("choice", text(name))])
}
