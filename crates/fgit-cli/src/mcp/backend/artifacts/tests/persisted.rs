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
