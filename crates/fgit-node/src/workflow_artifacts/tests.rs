use super::*;
use crate::NodeConfig;
use fgit_crypto::sha256_digest;
use fgit_object_fabric::{ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    GitHashAlgorithm, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fs;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-workflow-artifact-read-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let artifacts = path.join("artifacts");
        fs::create_dir(&artifacts).unwrap();
        fs::set_permissions(artifacts, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf {
        self.0.join("artifacts")
    }
    fn config(&self, name: &str, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join(name),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
        .with_workflow_artifact_root(self.root())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn open(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Digest::new(
            DigestAlgorithmId::try_new(2).unwrap(),
            DigestBytes::try_new(&sha256_digest(bytes)).unwrap(),
        ),
        bytes.len() as u64,
        MediaType::parse("application/octet-stream").unwrap(),
        ArtifactPayloadKind::CiArtifact,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    )
}
fn store(node: &OneNode, root: &Path, identity: &ArtifactIdentity, bytes: &[u8], trust: &str) {
    let scope = ArtifactScope::new(
        node.tenant_id(),
        node.repository_id(),
        node.repository_incarnation_id(),
        trust,
    )
    .unwrap();
    let storage = LocalArtifactStore::open(root, scope).unwrap();
    storage
        .put_reader(
            identity,
            &mut Cursor::new(bytes),
            &ArtifactOperation::new(
                MAX_WORKFLOW_ARTIFACT_READ_BYTES,
                Duration::from_secs(10),
                &|| true,
            )
            .unwrap(),
        )
        .unwrap();
}
fn read(
    node: &OneNode,
    id: &Digest,
) -> Result<WorkflowArtifactPayload, WorkflowArtifactReadRefusal> {
    node.runtime()
        .block_on(node.read_workflow_artifact_in(&node.request_context(), id))
}
fn inspect(
    node: &OneNode,
    id: &Digest,
) -> Result<WorkflowArtifactMetadata, WorkflowArtifactReadRefusal> {
    node.runtime()
        .block_on(node.inspect_workflow_artifact_in(&node.request_context(), id))
}
fn head(node: &OneNode) -> Vec<u8> {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .body()
        .to_vec()
}

#[test]
fn exact_artifact_identifiers_refuse_paths_alternate_encodings_and_wrong_domains() {
    let id = parse_artifact_id(&"01".repeat(32)).unwrap();
    assert_eq!(id.bytes().as_bytes(), &[1; 32]);
    for value in [
        "../outside".to_owned(),
        "a".repeat(63),
        "a".repeat(65),
        "AB".repeat(32),
        "gg".repeat(32),
        format!("sha256:{}", "ab".repeat(32)),
    ] {
        assert!(matches!(
            parse_artifact_id(&value),
            Err(WorkflowArtifactReadRefusal::InvalidId)
        ));
    }
    assert!(
        valid_id(&Digest::new(
            DigestAlgorithmId::try_new(1).unwrap(),
            DigestBytes::try_new(&[1; 32]).unwrap()
        ))
        .is_err()
    );
}

#[test]
fn verified_metadata_and_binary_payload_survive_reopen_without_any_canonical_write() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = open(scratch.config("node", format));
        node.validate_workflow_artifact_storage().unwrap();
        let bytes = b"\0\xff<script>inert artifact</script>\r\nexact bytes";
        let identity = identity(bytes);
        let before = head(&node);
        store(
            &node,
            &scratch.root(),
            &identity,
            bytes,
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
        );
        let metadata = inspect(&node, identity.artifact_id()).unwrap();
        assert_eq!(metadata.identity(), &identity);
        let parsed = json::parse(metadata.to_json().unwrap().as_bytes()).unwrap();
        let fields = parsed.object().unwrap();
        assert_eq!(fields["payload_bytes"].unsigned(), Some(bytes.len() as u64));
        assert_eq!(
            fields["artifact_id"].text(),
            Some(hex(identity.artifact_id()).as_str())
        );
        assert_eq!(fields["payload_verified"], Value::Bool(true));
        assert_eq!(fields["provenance_authenticated"], Value::Bool(false));
        assert_eq!(fields["canonical_repository_published"], Value::Bool(false));
        assert!(!fields.contains_key("root") && !fields.contains_key("run_directory_hex"));
        let payload = read(&node, identity.artifact_id()).unwrap();
        assert_eq!(payload.metadata(), &metadata);
        assert_eq!(payload.bytes(), bytes);
        assert_eq!(head(&node), before);
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(scratch.config("node", format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(
            read(&node, identity.artifact_id()).unwrap().into_parts(),
            (metadata, bytes.to_vec())
        );
        assert_eq!(head(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn namespace_incarnation_and_current_configuration_are_not_caller_assertions() {
    let scratch = Scratch::new();
    let mut node = open(scratch.config("first", GitHashAlgorithm::Sha1));
    let bytes = b"private workflow output";
    let identity = identity(bytes);
    store(
        &node,
        &scratch.root(),
        &identity,
        bytes,
        "other-trust-domain",
    );
    assert_eq!(
        read(&node, identity.artifact_id()).unwrap_err().code(),
        "artifact_not_found"
    );
    store(
        &node,
        &scratch.root(),
        &identity,
        bytes,
        TRUSTED_WORKFLOW_ARTIFACT_TRUST,
    );
    assert_eq!(read(&node, identity.artifact_id()).unwrap().bytes(), bytes);
    let other = open(scratch.config("second", GitHashAlgorithm::Sha1));
    assert_ne!(
        node.repository_incarnation_id(),
        other.repository_incarnation_id()
    );
    assert_eq!(
        read(&other, identity.artifact_id()).unwrap_err().code(),
        "artifact_not_found"
    );
    other.shutdown().unwrap();

    // Even a stale/mismatched opened-node binding cannot select an old scope:
    // every read compares it to current authenticated configuration first.
    node.repository_incarnation_id = RepositoryIncarnationId::from_bytes([0xe3; 16]);
    assert_eq!(
        read(&node, identity.artifact_id()).unwrap_err().code(),
        "artifact_storage_unavailable"
    );
    node.shutdown().unwrap();
}

#[test]
fn corruption_and_unavailable_roots_never_become_metadata_or_payload_absence() {
    let scratch = Scratch::new();
    let node = open(scratch.config("node", GitHashAlgorithm::Sha1));
    let bytes = b"verified complete output";
    let identity = identity(bytes);
    store(
        &node,
        &scratch.root(),
        &identity,
        bytes,
        TRUSTED_WORKFLOW_ARTIFACT_TRUST,
    );
    let scope = ArtifactScope::new(
        node.tenant_id(),
        node.repository_id(),
        node.repository_incarnation_id(),
        TRUSTED_WORKFLOW_ARTIFACT_TRUST,
    )
    .unwrap();
    let path = scratch
        .root()
        .join(format!("scope-{}", hex(&scope.commitment())))
        .join(hex(identity.artifact_id()));
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(b"!").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(
        inspect(&node, identity.artifact_id()).unwrap_err().code(),
        "artifact_storage_unavailable"
    );
    assert_eq!(
        read(&node, identity.artifact_id()).unwrap_err().code(),
        "artifact_storage_unavailable"
    );
    assert_eq!(
        read(&node, &parse_artifact_id(&"12".repeat(32)).unwrap())
            .unwrap_err()
            .code(),
        "artifact_not_found"
    );
    fs::rename(scratch.root(), scratch.0.join("retained-root")).unwrap();
    assert_eq!(
        read(&node, identity.artifact_id()).unwrap_err().code(),
        "artifact_storage_unavailable"
    );
    node.shutdown().unwrap();
}

#[test]
fn disabled_symlink_and_cancelled_reads_fail_before_disclosing_bytes() {
    let scratch = Scratch::new();
    let mut config = scratch.config("node", GitHashAlgorithm::Sha1);
    config.workflow_artifact_root = None;
    let mut node = open(config);
    let id = identity(b"payload");
    assert_eq!(
        inspect(&node, id.artifact_id()).unwrap_err().code(),
        "artifact_storage_disabled"
    );
    let alias = scratch.0.join("alias");
    symlink(scratch.root(), &alias).unwrap();
    node.service_config.workflow_artifact_root = Some(alias);
    assert_eq!(
        node.validate_workflow_artifact_storage()
            .unwrap_err()
            .code(),
        "artifact_storage_unavailable"
    );
    node.service_config.workflow_artifact_root = Some(scratch.root());
    store(
        &node,
        &scratch.root(),
        &id,
        b"payload",
        TRUSTED_WORKFLOW_ARTIFACT_TRUST,
    );
    let before = head(&node);
    let request = node.request_context();
    request.cancel();
    assert_eq!(
        node.runtime()
            .block_on(node.read_workflow_artifact_in(&request, id.artifact_id()))
            .unwrap_err()
            .code(),
        "artifact_request_expired"
    );
    assert_eq!(read(&node, id.artifact_id()).unwrap().bytes(), b"payload");
    assert_eq!(head(&node), before);
    node.shutdown().unwrap();
}
