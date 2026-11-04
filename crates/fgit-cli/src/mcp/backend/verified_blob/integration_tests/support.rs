//! Real persisted native objects, authenticated Merkle ref layouts and MCP.
//! Test-only loose-object encoding feeds the production importer; no Git
//! subprocess, alternate proof producer or fake native source owner is used.
use super::super::super::super::protocol::Server;
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{LoopbackReceiveSession, NodeConfig};
use fgit_types::{DecisionOutcome, GitOid, PrincipalId, RepositoryId, TenantId};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub(super) const TEXT: &[u8] = b"Exact source bytes\r\nnot normalized\n";
pub(super) const BINARY: &[u8] = b"\0\xffbinary\r\n";
pub(super) const RAW_PATH: &[u8] = b"bin\xff.dat";
pub(super) const LINK: &[u8] = b"../../outside-secret";
const ACTOR: PrincipalId = PrincipalId::from_bytes([0x74; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Eq, PartialEq)]
pub(super) struct State {
    pub head: RepositoryAuthorityHeadId,
    pub refs: BTreeMap<RefName, GitOid>,
}

pub(super) struct Fixture {
    root: PathBuf,
    backend: Option<NodeTools>,
    pub reference: RefName,
    pub commit: GitOid,
}

impl Fixture {
    pub fn new(format: GitHashAlgorithm, layout: RootLayoutVersion) -> Self {
        Self::with_text(format, layout, TEXT, 0)
    }

    pub fn with_text(
        format: GitHashAlgorithm,
        layout: RootLayoutVersion,
        text_bytes: &[u8],
        extra_commit_bytes: usize,
    ) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-verified-blob-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0x71; 16]);
        let repository = RepositoryId::from_bytes([0x72; 16]);
        let (mut node, _) = OneNode::init(
            NodeConfig::new(root.join("node"), tenant, repository)
                .with_object_format(format)
                .with_root_layout(layout)
                .with_worker_threads(2),
        )
        .unwrap();
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
        let git = root.join("source");
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(git.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let blob = |bytes: &[u8]| loose(&git, format, GitObjectKind::Blob, "blob", bytes);
        let tree = |bytes: &[u8]| loose(&git, format, GitObjectKind::Tree, "tree", bytes);
        let commit = |tree: GitOid, parent: Option<GitOid>, padding: usize| {
            let mut bytes = format!("tree {tree}\n").into_bytes();
            if let Some(parent) = parent {
                bytes.extend(format!("parent {parent}\n").as_bytes());
            }
            bytes.extend_from_slice(b"author Native <native@example.invalid> 1 +0000\ncommitter Native <native@example.invalid> 1 +0000\n\nOriginal message\r\n");
            bytes.extend(std::iter::repeat_n(b'x', padding));
            loose(&git, format, GitObjectKind::Commit, "commit", &bytes)
        };
        let base = commit(tree(&[]), None, 0);
        let nested = tree(
            &[
                b"100644 nested.txt\0".as_slice(),
                blob(b"nested\n").as_bytes(),
            ]
            .concat(),
        );
        let mut entries = Vec::new();
        for (mode, name, id) in [
            ("100644", b"alpha.txt".as_slice(), blob(text_bytes)),
            ("100644", RAW_PATH, blob(BINARY)),
            ("40000", b"dir".as_slice(), nested),
            ("100644", b"empty".as_slice(), blob(&[])),
            ("120000", b"link".as_slice(), blob(LINK)),
            ("160000", b"module".as_slice(), base),
            ("100755", b"run".as_slice(), blob(b"#!/bin/sh\nexit 0\n")),
        ] {
            entries.extend_from_slice(mode.as_bytes());
            entries.push(b' ');
            entries.extend_from_slice(name);
            entries.push(0);
            entries.extend_from_slice(id.as_bytes());
        }
        let tip = commit(tree(&entries), Some(base), extra_commit_bytes);
        fs::write(git.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        fs::write(
            root.join("outside-secret"),
            b"host bytes must never be disclosed",
        )
        .unwrap();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &git,
                ACTOR,
                b"verified-blob-fixture",
            ))
            .unwrap();
        assert!(
            imported.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let reference = RefName::try_new(b"refs/heads/raw-\xff").unwrap();
        add_ref(&node, reference.clone(), tip, b"raw-proof-reference");
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
            queues: Default::default(),
            agent_context: false,
            artifacts: false,
            artifact_root: None,
            writes: Default::default(),
            outcomes: false,
            principal: None,
            agent_token_file: None,
            max_messages: 64,
            index_maintenance: None,
        })
        .unwrap();
        Self {
            root,
            backend: Some(backend),
            reference,
            commit: tip,
        }
    }

    pub fn backend(&self) -> &NodeTools {
        self.backend.as_ref().unwrap()
    }
    pub fn backend_mut(&mut self) -> &mut NodeTools {
        self.backend.as_mut().unwrap()
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
    pub fn args(&self, path: &[u8]) -> Object {
        object([
            ("reference_hex", text(hex(self.reference.as_bytes()))),
            ("path_hex", text(hex(path))),
            ("expected_head", text(head_token(self.state().head))),
        ])
        .object()
        .unwrap()
        .clone()
    }
    pub fn call(&mut self, args: &Object) -> Result<Value, ToolError> {
        self.backend_mut().call(NAME, args)
    }
    pub fn envelope(&self, args: &Object) -> VerifiedBlobEnvelope {
        let query = input::parse(args).unwrap();
        let node = &self.backend().node;
        node.runtime()
            .block_on(node.verified_blob_in(
                &node.request_context(),
                &RefVisibility::new(),
                &query.reference,
                &query.path,
                query.expected_head,
            ))
            .unwrap()
    }
    pub fn advance_head(&self) {
        add_ref(
            &self.backend().node,
            RefName::try_new(b"refs/heads/later").unwrap(),
            self.commit,
            b"advance-proof-head",
        );
    }
    pub fn reopen(&mut self) {
        let options = self.backend().options.clone();
        self.backend.take().unwrap().close().unwrap();
        self.backend = Some(NodeTools::open(options).unwrap());
    }
    pub fn protocol_call(&mut self, args: Object) -> Value {
        let backend = self.backend_mut();
        let mut server = Server::new(backend).unwrap();
        server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verified-blob-test","version":"1"}}}"#).unwrap();
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            backend.close().unwrap();
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn add_ref(node: &OneNode, reference: RefName, commit: GitOid, key: &[u8]) {
    let session =
        LoopbackReceiveSession::authenticated(ACTOR, IdempotencyKey::new(key.to_vec()).unwrap());
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session,
            &[RefCommand {
                name: reference,
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(commit),
                force: false,
            }],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    name: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let mut encoded = vec![0x78, 0x01];
    let count = raw.chunks(usize::from(u16::MAX)).len();
    for (ordinal, chunk) in raw.chunks(usize::from(u16::MAX)).enumerate() {
        let length = u16::try_from(chunk.len()).unwrap();
        encoded.push(u8::from(ordinal + 1 == count));
        encoded.extend(length.to_le_bytes());
        encoded.extend((!length).to_le_bytes());
        encoded.extend(chunk);
    }
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let name = id.to_string();
    fs::create_dir_all(root.join("objects").join(&name[..2])).unwrap();
    fs::write(
        root.join("objects").join(&name[..2]).join(&name[2..]),
        encoded,
    )
    .unwrap();
    id
}

pub(super) fn content(reply: &Value) -> &Object {
    let result = reply.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{reply:?}");
    result["structuredContent"].object().unwrap()
}

pub(super) fn decode_chunks(value: &Object, name: &str) -> Vec<u8> {
    let Value::Array(rows) = &value[name] else {
        panic!("chunks required")
    };
    rows.iter()
        .flat_map(|row| unhex(row.text().unwrap(), CHUNK_BYTES).unwrap())
        .collect()
}
