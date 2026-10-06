//! Real persisted native histories. No foreign Git, mock node, or fake approval.
use super::super::*;
use super::super::super::super::Options;
use super::super::super::super::super::protocol::{ReadTools, Server};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) fn actor(byte: u8) -> PrincipalId { PrincipalId::from_bytes([byte; 16]) }
pub(super) fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(pairs) else { unreachable!() };
    fields
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Author <author@example.invalid>".into(),
        committer: "Committer <committer@example.invalid>".into(),
        timestamp: 1, message: b"seed\n".to_vec(),
    }
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(1), IdempotencyKey::new(key.to_vec()).unwrap())
}

pub(super) struct Fixture {
    root: PathBuf,
    backend: Option<NodeTools>,
    pub subject: ReviewSubject,
    pub base: GitOid,
    pub genesis: RepositoryAuthorityHeadId,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm, conflict: bool) -> Self {
        let root = std::env::temp_dir().join(format!("fg-mcp-pr-candidate-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0xc1; 16]);
        let repository = RepositoryId::from_bytes([0xc2; 16]);
        let (mut node, _) = OneNode::init(NodeConfig::new(root.join("node"), tenant, repository)
            .with_object_format(format).with_worker_threads(2)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
        let genesis = fgit_authority::authority_head_identity(&head.body().unwrap()).unwrap();
        let target_ref = RefName::try_new(b"refs/heads/main").unwrap();
        let source_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        let patch = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+base\ndiff --git a/sibling b/sibling\nnew file mode 100644\n--- /dev/null\n+++ b/sibling\n@@ -0,0 +1 @@\n+unchanged\n";
        let request = node.request_context();
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &target_ref, patch, &metadata(), Default::default(), None,
        )).unwrap();
        let base = plan.commit;
        let initial = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session(b"initial"), &target_ref, base, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(initial.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let request = node.request_context();
        let created = node.runtime().block_on(node.admit_branch_updates_durable_in(
            &request, &session(b"topic"), &[RefCommand {
                name: source_ref.clone(), expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(base), force: false,
            }], Default::default(),
        )).unwrap();
        assert!(matches!(created.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let mut tips = Vec::new();
        for (reference, name) in [(&target_ref, "main"), (&source_ref, "topic")] {
            let patch = if conflict {
                format!("diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+{name}\n")
            } else {
                format!("diff --git a/{name}-only b/{name}-only\nnew file mode 100644\n--- /dev/null\n+++ b/{name}-only\n@@ -0,0 +1 @@\n+{name}\n")
            };
            let request = node.request_context();
            let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
                &request, reference, base, [0xc3; 16], patch.as_bytes(), &metadata(), Default::default(),
            )).unwrap();
            let published = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
                &request, actor(1), name.as_bytes(), reference, base,
                candidate.candidate_commit, candidate.bundle_bytes(),
            )).unwrap();
            assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
            tips.push(candidate.candidate_commit);
        }
        let incarnation = node.repository_incarnation_id();
        node.shutdown().unwrap();
        let mut options = Options {
            storage: root.join("node"), tenant, repository, format, incarnation: Some(incarnation),
            issues: false, pulls: true, source: true, writes: Default::default(), outcomes: false,
            principal: Some(actor(1)), max_messages: 64,
        };
        options.writes.pulls = true;
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let subject = ReviewSubject {
            pull_request: PullRequestNumber::try_new(1).unwrap(),
            pull_request_version: AggregateVersion::try_new(1).unwrap(),
            source_ref, target_ref, source_tip: tips[1], target_tip: tips[0],
            policy_epoch: PolicyEpoch::FIRST,
        };
        let mut open = subject_fields(&subject);
        open.remove("policy_epoch");
        open.insert("expected_version".into(), text("0"));
        open.insert("idempotency_key".into(), text("open-pr"));
        open.insert("title".into(), text("Native candidate"));
        open.insert("body".into(), text("Read, inspect and separately approve."));
        let opened = backend.call("frankengit_pull_open", &open).unwrap();
        assert_eq!(opened.object().unwrap()["outcome"].text(), Some("committed"));
        backend.close().unwrap();
        options.writes = Default::default();
        options.principal = None;
        let backend = NodeTools::open(options).unwrap();
        Self { root, backend: Some(backend), subject, base, genesis }
    }
    pub fn backend(&self) -> &NodeTools { self.backend.as_ref().unwrap() }
    pub fn backend_mut(&mut self) -> &mut NodeTools { self.backend.as_mut().unwrap() }
    pub fn options(&self) -> Options { self.backend().options.clone() }
    pub fn reopen(&mut self, options: Options) {
        self.backend.take().unwrap().close().unwrap();
        self.backend = Some(NodeTools::open(options).unwrap());
    }
    pub fn head(&self) -> (RepositoryAuthorityHeadId, Vec<u8>) {
        let backend = self.backend();
        let head = backend.node.runtime().block_on(backend.node.authenticate_authority_head()).unwrap();
        (fgit_authority::authority_head_identity(&head.body().unwrap()).unwrap(), head.receipt().body().to_vec())
    }
    pub fn prepare_args(&self) -> Object {
        let mut args = subject_fields(&self.subject);
        args.insert("operation".into(), text(PREPARE));
        args.insert("expected_head".into(), text(head_token(self.head().0)));
        args.insert("author".into(), text("Merger <merger@example.invalid>"));
        args.insert("committer".into(), text("Committer <committer@example.invalid>"));
        args.insert("timestamp".into(), text("2"));
        args.insert("message_hex".into(), text(hex(b"review this actual merge\n")));
        args
    }
    pub fn call(&mut self, tool: &str, args: &Object) -> Result<Value, ToolError> {
        self.backend_mut().call(tool, args)
    }
    pub fn protocol_call(&mut self, tool: &str, args: Object) -> Value {
        let backend = self.backend_mut();
        let mut server = Server::new(backend).unwrap();
        server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"pr-candidate-test","version":"1"}}}"#).unwrap();
        server.receive(backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let request = object([
            ("jsonrpc", text("2.0")), ("id", json::number(2)), ("method", text("tools/call")),
            ("params", object([("name", text(tool)), ("arguments", Value::Object(args))])),
        ]).encode(json::MAX_INPUT).unwrap();
        server.receive(backend, request.as_bytes()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() { backend.close().unwrap(); }
        fs::remove_dir_all(&self.root).unwrap();
    }
}

pub(super) fn content(response: &Value) -> &Object {
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false));
    result["structuredContent"].object().unwrap()
}
