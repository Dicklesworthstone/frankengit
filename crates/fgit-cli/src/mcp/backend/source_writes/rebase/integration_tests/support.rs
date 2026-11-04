//! Native setup and exact protocol frames for persisted rebase-publication tests.
use super::super::super::super::super::{WriteGrants, protocol::Server};
use super::super::super::super::Options;
use super::super::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::{
    MergeMetadata,
    rebase::{EmptyCommitPolicy, RebaseCommitter, RebasePreparation, RebaseRequest},
};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{HeadGeneration, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0xf3; 16])
}
fn metadata(time: u64) -> MergeMetadata {
    MergeMetadata {
        author: "Author <author@example.invalid>".into(),
        committer: "Committer <committer@example.invalid>".into(),
        timestamp: time,
        message: format!("native source commit {time}\n").into_bytes(),
    }
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn patch(name: &str) -> Vec<u8> {
    format!(
        "diff --git a/{name} b/{name}\nnew file mode 100644\n--- /dev/null\n+++ b/{name}\n@@ -0,0 +1 @@\n+{name}\n"
    ).into_bytes()
}
fn append(
    node: &OneNode,
    reference: &RefName,
    base: GitOid,
    name: &str,
    key: &[u8],
    time: u64,
) -> GitOid {
    let request = node.request_context();
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            reference,
            base,
            [0xf4; 16],
            &patch(name),
            &metadata(time),
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

#[derive(Debug, Eq, PartialEq)]
pub(super) struct State {
    pub head: RepositoryAuthorityHeadId,
    pub refs: BTreeMap<RefName, GitOid>,
}
pub(super) struct Prepared {
    pub candidate: GitOid,
    pub bundle: Vec<u8>,
    pub rewritten: Vec<GitOid>,
}
pub(super) struct Fixture {
    root: PathBuf,
    backend: Option<NodeTools>,
    pub source_ref: RefName,
    pub onto_ref: RefName,
    pub base: GitOid,
    pub source: GitOid,
    pub onto: GitOid,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-publish-rebase-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0xf1; 16]);
        let repository = RepositoryId::from_bytes([0xf2; 16]);
        let (mut node, _) = OneNode::init(
            NodeConfig::new(root.join("node"), tenant, repository)
                .with_object_format(format)
                .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let onto_ref = RefName::try_new(b"refs/heads/main").unwrap();
        let source_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        let request = node.request_context();
        let (_, plan, bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &onto_ref,
                &patch("base.txt"),
                &metadata(1),
                Default::default(),
                None,
            ))
            .unwrap();
        let base = plan.commit;
        let initial = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session(b"seed"),
                &onto_ref,
                base,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            initial.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let request = node.request_context();
        let created = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session(b"create-topic"),
                &[RefCommand {
                    name: source_ref.clone(),
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
        let first = append(&node, &source_ref, base, "first.txt", b"topic-first", 2);
        let source = append(&node, &source_ref, first, "second.txt", b"topic-second", 3);
        let onto = append(&node, &onto_ref, base, "onto.txt", b"main-onto", 4);
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
            source: false,
            writes: WriteGrants {
                source: true,
                ..Default::default()
            },
            outcomes: false,
            principal: Some(actor()),
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
            source_ref,
            onto_ref,
            base,
            source,
            onto,
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
    pub fn state(&self) -> State {
        let node = &self.backend().node;
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        State {
            head: selected.basis().id(),
            refs: selected.snapshot().refs.clone(),
        }
    }
    pub fn prepare(&self, empty: bool) -> Prepared {
        let node = &self.backend().node;
        let before = self.state();
        let artifact = node
            .runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &node.request_context(),
                &self.source_ref,
                &self.onto_ref,
                RebaseRequest {
                    source_tip: self.source,
                    upstream: if empty { self.source } else { self.base },
                    onto: self.onto,
                    empty: EmptyCommitPolicy::Stop,
                },
                &Default::default(),
                Some(before.head),
                &RebaseCommitter {
                    identity: "Rebaser <rebaser@example.invalid>".into(),
                    timestamp: 100,
                },
                Default::default(),
            ))
            .unwrap();
        let RebasePreparation::Clean(plan) = artifact.outcome else {
            panic!("clean rebase fixture required")
        };
        let bundle = artifact.bundle.unwrap();
        assert!(bundle.len() <= MAX_BUNDLE_BYTES);
        assert_eq!(self.state(), before, "native preparation must not publish");
        Prepared {
            candidate: plan.commit,
            bundle,
            rewritten: plan.steps.iter().map(|step| step.rewritten).collect(),
        }
    }
    pub fn args(&self, candidate: GitOid, bundle: &[u8], key: &str) -> Object {
        let Value::Object(mut args) = object([
            ("expected_source", text(self.source.to_string())),
            ("onto", text(self.onto.to_string())),
            ("expected_candidate", text(candidate.to_string())),
            ("idempotency_key", text(key)),
            (
                "bundle_hex_chunks",
                Value::Array(
                    bundle
                        .chunks(CHUNK_BYTES)
                        .map(|chunk| text(hex(chunk)))
                        .collect(),
                ),
            ),
        ]) else {
            unreachable!()
        };
        match self.backend().options.format {
            GitHashAlgorithm::Sha1 => {
                args.insert("reference".into(), text("refs/heads/topic"));
            }
            GitHashAlgorithm::Sha256 => {
                args.insert(
                    "reference_hex".into(),
                    text(hex(self.source_ref.as_bytes())),
                );
            }
        }
        args
    }
    pub fn advance(&self, base: GitOid, name: &str, key: &[u8]) -> GitOid {
        append(&self.backend().node, &self.source_ref, base, name, key, 101)
    }
    pub fn assert_private(&self, id: GitOid) {
        assert!(
            matches!(self.backend().node.read_git_object(id),
                Err(fgit_node::NodeRefusal::Fabric(error))
                    if matches!(*error, fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent)
            ),
            "unpublished candidate {id} must not enter durable custody"
        );
    }
    pub fn assert_staging_empty(&self) {
        assert_eq!(
            fs::read_dir(self.backend().options.storage.join("staging"))
                .unwrap()
                .count(),
            0
        );
    }
    pub fn protocol_call(&mut self, args: Object) -> Value {
        let backend = self.backend_mut();
        let mut server = Server::new(backend).unwrap();
        server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"publish-rebase-test","version":"1"}}}"#).unwrap();
        assert!(
            server
                .receive(
                    backend,
                    br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
                )
                .is_none()
        );
        let wire = object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(2)),
            ("method", text("tools/call")),
            (
                "params",
                object([("name", text(NAME)), ("arguments", Value::Object(args))]),
            ),
        ])
        .encode(json::MAX_INPUT)
        .unwrap();
        server.receive(backend, wire.as_bytes()).unwrap()
    }
    pub fn non_linear_bundle(&self) -> (GitOid, Vec<u8>) {
        // A real native pack containing a deliberately invalid two-parent
        // rebase commit. The tree and both parent objects already exist.
        let node = &self.backend().node;
        let target = node.read_git_object(self.onto).unwrap();
        let tree = target
            .payload()
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap();
        assert!(tree.starts_with(b"tree "));
        let mut body = tree.to_vec();
        body.extend(format!(
            "\nparent {}\nparent {}\nauthor Author <author@example.invalid> 1 +0000\ncommitter Committer <committer@example.invalid> 1 +0000\n\nnonlinear candidate\n",
            self.onto, self.source,
        ).as_bytes());
        let format = self.backend().options.format;
        let id = git_object_id(format, GitObjectKind::Commit, &body);
        struct Source(CanonicalPackObject);
        impl CanonicalObjectSource for Source {
            fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
                if *id == self.0.id() {
                    Ok(self.0.clone())
                } else {
                    Err(PackWriteError::MissingCanonicalObject(*id))
                }
            }
        }
        let source = Source(CanonicalPackObject::new(
            id,
            GitObjectKind::Commit,
            body,
            Vec::new(),
            0,
            0,
        ));
        let limits = PackLimits::default();
        let plan = PackPlanner::new(
            format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            limits.clone(),
        )
        .plan_selected(&source, &[id], &mut || true)
        .unwrap();
        let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
        let mut bundle = format!(
            "# v3 git bundle\n@object-format={}\n-{} onto\n{id} ",
            format.as_str(),
            self.onto
        )
        .into_bytes();
        bundle.extend_from_slice(self.source_ref.as_bytes());
        bundle.extend_from_slice(b"\n\n");
        bundle.extend(pack);
        (id, bundle)
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
pub(super) fn content(reply: &Value, is_error: bool) -> &Object {
    let result = reply.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(is_error), "{reply:?}");
    result["structuredContent"].object().unwrap()
}
