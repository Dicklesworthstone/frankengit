//! Persisted node and real immutable artifact containers; no mock read owner.
use super::*;
use crate::mcp::protocol::Server;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_node::TRUSTED_WORKFLOW_ARTIFACT_TRUST;
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use fgit_object_fabric::{ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    Digest, GitHashAlgorithm, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    options: Options,
    scope: ArtifactScope,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-artifacts-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let artifact_root = root.join("artifacts");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&artifact_root)
            .unwrap();
        let tenant = TenantId::from_bytes([0xa1; 16]);
        let repository = RepositoryId::from_bytes([0xa2; 16]);
        let config = NodeConfig::new(root.join("node"), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        node.shutdown().unwrap();
        Self {
            scope: ArtifactScope::new(
                tenant,
                repository,
                incarnation,
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
            options: Options {
                storage: root.join("node"),
                tenant,
                repository,
                format,
                incarnation: Some(incarnation),
                issues: false,
                pulls: false,
                source: false,
                agent_context: true,
                artifacts: true,
                artifact_root: Some(artifact_root),
                writes: Default::default(),
                outcomes: false,
                principal: None,
                max_messages: 32,
            },
            root,
        }
    }
    fn publish(&self, bytes: &[u8], scope: &ArtifactScope) -> ArtifactIdentity {
        let identity = ArtifactIdentity::new(
            digest(bytes),
            bytes.len() as u64,
            MediaType::parse("application/octet-stream").unwrap(),
            ArtifactPayloadKind::BuildLog,
            Some(digest(b"asserted build capsule")),
            Some(digest(b"asserted check receipt")),
            Some(digest(b"asserted source RCR")),
            RetentionProfile::StandardLog { retain_days: 7 },
        );
        let store =
            LocalArtifactStore::open(self.options.artifact_root.as_ref().unwrap(), scope.clone())
                .unwrap();
        let op =
            ArtifactOperation::new(64 * 1024 * 1024, Duration::from_secs(30), &|| true).unwrap();
        store
            .put_reader(&identity, &mut Cursor::new(bytes), &op)
            .unwrap();
        identity
    }
    fn container(&self, identity: &ArtifactIdentity) -> PathBuf {
        self.options
            .artifact_root
            .as_ref()
            .unwrap()
            .join(format!(
                "scope-{}",
                hex(self.scope.commitment().bytes().as_bytes())
            ))
            .join(hex(identity.artifact_id().bytes().as_bytes()))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn digest(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256Hasher::new();
    DigestHasher::update(&mut hasher, bytes);
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&DigestHasher::finish(hasher)).unwrap(),
    )
}
fn selection(identity: &ArtifactIdentity) -> Object {
    args([(
        "artifact_id",
        text(hex(identity.artifact_id().bytes().as_bytes())),
    )])
}
fn head(backend: &NodeTools) -> RepositoryAuthorityHeadId {
    let request = backend.node.request_context();
    backend
        .node
        .runtime()
        .block_on(backend.node.read_issues_in(&request, 0, 1, None))
        .unwrap()
        .source_head
}
fn invoke(
    server: &mut Server,
    backend: &mut NodeTools,
    id: u64,
    name: &str,
    arguments: Object,
) -> Value {
    let message = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text(name)),
                ("arguments", Value::Object(arguments)),
            ]),
        ),
    ])
    .encode(4096)
    .unwrap();
    server.receive(backend, message.as_bytes()).unwrap()
}
fn result(reply: &Value) -> &Object {
    reply.object().unwrap()["result"].object().unwrap()["structuredContent"]
        .object()
        .unwrap()
}

#[test]
fn real_mcp_reads_exact_binary_chunks_and_metadata_without_publishing_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let bytes: Vec<u8> = (0..65545).map(|index| (index % 251) as u8).collect();
        let identity = fixture.publish(&bytes, &fixture.scope);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(
            backend
                .tools()
                .iter()
                .map(|tool| tool.name)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([INSPECT, READ])
        );
        assert!(!backend.is_mutation(INSPECT) && !backend.is_mutation(READ));
        let before = head(&backend);
        let request = backend.node.request_context();
        let expected = backend
            .node
            .runtime()
            .block_on(
                backend
                    .node
                    .inspect_workflow_artifact_in(&request, identity.artifact_id()),
            )
            .unwrap()
            .json_value();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"artifact-test","version":"1"}}}"#).unwrap();
        server.receive(
            &mut backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let inspected = invoke(&mut server, &mut backend, 2, INSPECT, selection(&identity));
        assert_eq!(Value::Object(result(&inspected).clone()), expected);
        let metadata = result(&inspected);
        assert_eq!(
            metadata["trust_domain"].text(),
            Some(TRUSTED_WORKFLOW_ARTIFACT_TRUST)
        );
        assert_eq!(metadata["payload_verified"], Value::Bool(true));
        assert_eq!(metadata["provenance_authenticated"], Value::Bool(false));
        assert_eq!(
            metadata["canonical_repository_published"],
            Value::Bool(false)
        );
        assert_eq!(metadata["retention_enforced"], Value::Bool(false));
        let first = invoke(&mut server, &mut backend, 3, READ, selection(&identity));
        assert_eq!(result(&first)["metadata"], expected);
        assert_eq!(
            result(&first)["content_hex"].text(),
            Some(hex(&bytes[..65536]).as_str())
        );
        assert_eq!(result(&first)["byte_count"].text(), Some("65536"));
        assert_eq!(result(&first)["next_offset"].text(), Some("65536"));
        assert_eq!(result(&first)["read_only"], Value::Bool(true));
        assert_eq!(result(&first)["transaction_created"], Value::Bool(false));
        let mut next = selection(&identity);
        next.insert("offset".into(), text("65536"));
        let second = invoke(&mut server, &mut backend, 4, READ, next);
        assert_eq!(
            result(&second)["content_hex"].text(),
            Some(hex(&bytes[65536..]).as_str())
        );
        assert_eq!(result(&second)["byte_count"].text(), Some("9"));
        assert_eq!(result(&second)["next_offset"], Value::Null);
        let mut eof = selection(&identity);
        eof.insert("offset".into(), text(bytes.len().to_string()));
        let empty = backend.call(READ, &eof).unwrap();
        assert_eq!(empty.object().unwrap()["content_hex"].text(), Some(""));
        assert_eq!(empty.object().unwrap()["next_offset"], Value::Null);
        eof.insert("offset".into(), text((bytes.len() + 1).to_string()));
        assert_eq!(
            backend.call(READ, &eof).unwrap_err().code,
            "artifact_offset_out_of_bounds"
        );
        for name in [
            "frankengit_issue_list",
            "frankengit_source_tree",
            "frankengit_outcome",
            "frankengit_artifact_upload",
            "frankengit_artifact_list",
        ] {
            assert_eq!(
                backend.call(name, &Object::new()).unwrap_err().code,
                "tool_not_granted"
            );
        }
        assert_eq!(head(&backend), before);
        backend.close().unwrap();
        let mut reopened = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(
            reopened.call(INSPECT, &selection(&identity)).unwrap(),
            expected
        );
        reopened.close().unwrap();
    }
}

#[test]
fn corruption_after_the_requested_prefix_refuses_metadata_and_all_snippet_bytes() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let identity = fixture.publish(
        b"valid prefix then corrupt the last payload byte",
        &fixture.scope,
    );
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = head(&backend);
    let path = fixture.container(&identity);
    let original = fs::read(&path).unwrap();
    let mut damaged = original.clone();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&path, damaged).unwrap();
    let mut first_byte = selection(&identity);
    first_byte.insert("limit".into(), json::number(1));
    let error = backend.call(READ, &first_byte).unwrap_err();
    assert_eq!(error.code, "artifact_storage_unavailable");
    assert!(!error.invalid);
    assert_eq!(
        backend
            .call(INSPECT, &selection(&identity))
            .unwrap_err()
            .code,
        "artifact_storage_unavailable"
    );
    fs::write(path, original).unwrap();
    let permitted = backend.call(READ, &first_byte).unwrap();
    assert_eq!(
        permitted.object().unwrap()["content_hex"].text(),
        Some("76")
    );
    assert_eq!(head(&backend), before);
    backend.close().unwrap();
}

#[test]
fn foreign_incarnation_and_trust_artifacts_are_absent_until_published_in_the_selected_scope() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let scopes = [
        ArtifactScope::new(
            fixture.options.tenant,
            fixture.options.repository,
            RepositoryIncarnationId::from_bytes([0xb1; 16]),
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
        )
        .unwrap(),
        ArtifactScope::new(
            fixture.options.tenant,
            fixture.options.repository,
            fixture.options.incarnation.unwrap(),
            "another-trust-domain",
        )
        .unwrap(),
    ];
    for (index, scope) in scopes.iter().enumerate() {
        let bytes = format!("only selected namespace may disclose payload {index}").into_bytes();
        let identity = fixture.publish(&bytes, scope);
        let error = backend.call(READ, &selection(&identity)).unwrap_err();
        assert_eq!(error.code, "artifact_not_found");
        assert!(!error.invalid);
        assert_eq!(fixture.publish(&bytes, &fixture.scope), identity);
        let permitted = backend.call(READ, &selection(&identity)).unwrap();
        assert_eq!(
            permitted.object().unwrap()["content_hex"].text(),
            Some(hex(&bytes).as_str())
        );
    }
    backend.close().unwrap();
}

#[test]
fn startup_checks_exact_incarnation_existing_private_root_and_independent_grant() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let mut wrong = fixture.options.clone();
    wrong.incarnation = Some(RepositoryIncarnationId::from_bytes([0xc1; 16]));
    assert!(NodeTools::open(wrong).is_err());
    let absent = fixture.root.join("not-created-by-a-read-service");
    let mut missing = fixture.options.clone();
    missing.artifact_root = Some(absent.clone());
    assert!(NodeTools::open(missing).is_err());
    assert!(!absent.exists());
    let root = fixture.options.artifact_root.as_ref().unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(NodeTools::open(fixture.options.clone()).is_err());
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    assert_eq!(
        backend
            .call(INSPECT, &args([("artifact_id", text("00".repeat(32)))]))
            .unwrap_err()
            .code,
        "artifact_not_found"
    );
    backend.close().unwrap();
    let mut source_only = fixture.options.clone();
    source_only.artifacts = false;
    source_only.artifact_root = None;
    source_only.source = true;
    let mut source_only = NodeTools::open(source_only).unwrap();
    assert!(!source_only.tools().iter().any(|tool| is_tool(tool.name)));
    for name in [INSPECT, READ] {
        assert_eq!(
            source_only.call(name, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
    }
    source_only.close().unwrap();
}

fn workflow_object(
    root: &std::path::Path,
    format: GitHashAlgorithm,
    kind: fgit_crypto::GitObjectKind,
    name: &str,
    body: &[u8],
) -> fgit_types::GitOid {
    let oid = fgit_crypto::git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = oid.to_string();
    fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(
        root.join("objects").join(&text[..2]).join(&text[2..]),
        encoded,
    )
    .unwrap();
    oid
}

#[test]
fn actual_failed_workflow_binary_logs_are_readable_by_exact_ids_after_mcp_reopen() {
    use fgit_crypto::GitObjectKind;
    use fgit_node::TrustedWorkflowArtifactConfig;
    use fgit_types::{DecisionOutcome, PrincipalId, RefName};

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let source = fixture.root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let workflow = b"name: MCP binary logs\non: push\njobs:\n  failure:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf 'mcp\\000\\377'; printf 'error\\000\\376' >&2; exit 9\n";
        let blob = workflow_object(&source, format, GitObjectKind::Blob, "blob", workflow);
        let mut tree = b"100644 workflow.yml\0".to_vec();
        tree.extend(blob.as_bytes());
        let tree = workflow_object(&source, format, GitObjectKind::Tree, "tree", &tree);
        let commit = format!(
            "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nworkflow log fixture\n"
        );
        let tip = workflow_object(
            &source,
            format,
            GitObjectKind::Commit,
            "commit",
            commit.as_bytes(),
        );
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let parent = fixture.root.join("runs");
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let backend = NodeTools::open(fixture.options.clone()).unwrap();
        let imported = backend
            .node
            .runtime()
            .block_on(backend.node.import_loose_git_directory_durable_in(
                &backend.node.command_request_context(None),
                &source,
                PrincipalId::from_bytes([0xa3; 16]),
                b"mcp-native-workflow-log-fixture",
            ))
            .unwrap();
        assert!(
            imported.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let before = head(&backend);
        let contract = TrustedWorkflowArtifactConfig::new_with_logs(
            fixture.options.artifact_root.clone().unwrap(),
            vec![],
            1024,
            2048,
        )
        .unwrap();
        let run = backend
            .node
            .runtime()
            .block_on(backend.node.run_trusted_workflow_with_artifacts_in(
                &backend.node.command_request_context(None),
                &RefName::try_new(b"refs/heads/main").unwrap(),
                b"workflow.yml",
                [0xa4; 16],
                &parent,
                &[b"workflow.yml".to_vec()],
                (None, Some(tip)),
                Default::default(),
                Some(&contract),
            ))
            .unwrap();
        assert!(!run.succeeded());
        assert!(run.workspaces_closed);
        assert_eq!(run.execution.jobs[0].outcome.token(), "failed");
        assert_eq!(run.artifact_logs.len(), 1);
        let captured = &run.artifact_logs[0];
        assert_eq!(captured.logs.len(), 2);
        let expected = [b"mcp\0\xff".as_slice(), b"error\0\xfe".as_slice()];
        for (log, bytes) in captured.logs.iter().zip(expected) {
            assert_eq!(log.payload_bytes, bytes.len());
            assert_eq!(log.payload_sha256, digest(bytes));
            assert!(log.output_complete);
        }
        assert_eq!(head(&backend), before);
        backend.close().unwrap();
        // Reopening proves the protocol adapter reads the settled immutable
        // containers, not an in-memory process report or fixture publication.
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"workflow-log-test","version":"1"}}}"#).unwrap();
        server.receive(
            &mut backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        for (index, (log, bytes)) in captured.logs.iter().zip(expected).enumerate() {
            let arguments = args([("artifact_id", text(hex(log.artifact_id.bytes().as_bytes())))]);
            let inspected = invoke(
                &mut server,
                &mut backend,
                (index * 2 + 2) as u64,
                INSPECT,
                arguments.clone(),
            );
            let metadata = result(&inspected);
            assert_eq!(metadata["kind"].text(), Some("build_log"));
            assert_eq!(
                metadata["payload_sha256"].text(),
                Some(hex(log.payload_sha256.bytes().as_bytes()).as_str())
            );
            assert_eq!(metadata["payload_verified"], Value::Bool(true));
            assert_eq!(metadata["provenance_authenticated"], Value::Bool(false));
            assert_eq!(
                metadata["canonical_repository_published"],
                Value::Bool(false)
            );
            assert_eq!(metadata["build_capsule_sha256"], Value::Null);
            assert_eq!(metadata["check_receipt_sha256"], Value::Null);
            let downloaded = invoke(
                &mut server,
                &mut backend,
                (index * 2 + 3) as u64,
                READ,
                arguments,
            );
            let content = result(&downloaded);
            assert_eq!(content["content_hex"].text(), Some(hex(bytes).as_str()));
            assert_eq!(
                content["byte_count"].text(),
                Some(bytes.len().to_string().as_str())
            );
            assert_eq!(content["next_offset"], Value::Null);
            assert_eq!(content["metadata"], Value::Object(metadata.clone()));
            assert_eq!(content["transaction_created"], Value::Bool(false));
        }
        let manifest_args = args([(
            "artifact_id",
            text(hex(captured.manifest_id.bytes().as_bytes())),
        )]);
        let manifest = backend.call(READ, &manifest_args).unwrap();
        let manifest = manifest.object().unwrap();
        assert_eq!(
            manifest["metadata"].object().unwrap()["kind"].text(),
            Some("provenance")
        );
        let receipt = fs::read_to_string(run.run_directory.join("job-000-logs.json")).unwrap();
        let prefix = format!(
            "{{\"type\":\"trusted_workflow_log_receipt\",\"manifest_id_sha256\":\"{}\",\"manifest\":",
            hex(captured.manifest_id.bytes().as_bytes())
        );
        let original_manifest = receipt
            .strip_prefix(&prefix)
            .unwrap()
            .strip_suffix('}')
            .unwrap();
        assert_eq!(
            manifest["content_hex"].text(),
            Some(hex(original_manifest.as_bytes()).as_str())
        );
        assert_eq!(head(&backend), before);
        backend.close().unwrap();
    }
}
