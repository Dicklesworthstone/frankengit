//! Native persisted backup/preflight/restore path, including a stopped restore.
//! Fixtures generate blob bytes in chunks and do not allocate an object-sized Vec.
use super::*;
use crate::NodeRequestContext;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{
    DigestHasher, GitObjectHasher, IdentityDomain, NativeObjectIdentity, Sha1, Sha256, Sha256Hasher,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

const LENGTH: usize = 32 * 1024 * 1024 + 17;
const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "fg-large-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Body(usize);
impl Read for Body {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        assert!(out.len() <= 64 * 1024);
        let count = self.0.min(out.len()).min(4093);
        out[..count].fill(b'x');
        self.0 -= count;
        Ok(count)
    }
}
fn blob_identity<A: fgit_crypto::GitHashAlgorithm>() -> (GitOid, [u8; 32]) {
    let mut native = GitObjectHasher::<A>::new(GitObjectKind::Blob, LENGTH as u64);
    let mut strong = Sha256Hasher::new();
    let header = format!("blob {LENGTH}\0");
    strong.update(&fgit_crypto::internal_id_preimage_header(
        IdentityDomain::GitPayloadCommitment,
        fgit_crypto::GIT_PAYLOAD_SCHEMA,
        LENGTH as u64 + header.len() as u64,
    ));
    strong.update(header.as_bytes());
    let block = [b'x'; 4096];
    let mut remaining = LENGTH;
    while remaining != 0 {
        let count = remaining.min(block.len());
        native.update(&block[..count]).unwrap();
        strong.update(&block[..count]);
        remaining -= count;
    }
    (native.finish().unwrap().erase(), strong.finish())
}
fn node_config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.to_path_buf(),
        TenantId::from_hex(TENANT).unwrap(),
        RepositoryId::from_hex(REPOSITORY).unwrap(),
    )
    .with_object_format(format)
    .with_selected_pack_blob_limit(LENGTH)
}
fn source(root: &Path, format: GitHashAlgorithm) -> GitOid {
    let (mut node, _) = OneNode::init(node_config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (blob, commitment) = match format {
        GitHashAlgorithm::Sha1 => blob_identity::<Sha1>(),
        GitHashAlgorithm::Sha256 => blob_identity::<Sha256>(),
    };
    node.put_git_blob_stream(
        blob,
        LENGTH as u64,
        commitment,
        LENGTH as u64,
        &mut Body(LENGTH),
        &mut || true,
    )
    .unwrap();
    let mut tree = b"100644 large.bin\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = node
        .put_git_object(GitObjectKind::Tree, tree)
        .unwrap()
        .identity();
    let commit = format!("tree {tree}\nauthor Backup <b@example.invalid> 1 +0000\ncommitter Backup <b@example.invalid> 1 +0000\n\nlarge\n")
        .into_bytes();
    let commit = node
        .put_git_object(GitObjectKind::Commit, commit)
        .unwrap()
        .identity();
    let objects = BTreeSet::from([blob, tree, commit]);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let updates = [SourceRefUpdate {
        old: GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap(),
        new: commit,
        ref_name: b"refs/heads/main".to_vec(),
    }];
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: 3,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(&updates, &receipt, closure).unwrap();
    let context = AdmissionContext {
        head_key: node.authority_head_key().clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([7; 16]),
        idempotency_key: IdempotencyKey::new(b"large-backup-source".to_vec()).unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let admitted = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    drop(request);
    node.shutdown().unwrap();
    blob
}
fn pin(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            return hash.finish();
        }
        hash.update(&buffer[..count]);
    }
}
fn readback(node: &OneNode, blob: GitOid, request: &NodeRequestContext) {
    let mut stream = BlobReader::open(
        node,
        blob,
        LENGTH as u64,
        Profile::default().start(),
        request,
    )
    .unwrap();
    assert_eq!(stream.length(), LENGTH as u64);
    let mut bytes = 0;
    let mut block = [0; 4093];
    loop {
        let count = stream.read(&mut block).unwrap();
        if count == 0 {
            break;
        }
        assert!(block[..count].iter().all(|byte| *byte == b'x'));
        bytes += count;
    }
    assert_eq!(bytes, LENGTH);
}

#[test]
fn explicit_large_blob_export_preflight_and_interrupted_restore_roundtrip_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source_root = scratch.0.join("source");
        let blob = source(&source_root, format);
        let archive_path = scratch.0.join("source.fg");
        let mut export = vec![
            "export".into(),
            source_root.to_str().unwrap().into(),
            archive_path.to_str().unwrap().into(),
            TENANT.into(),
            REPOSITORY.into(),
            "--trusted-local".into(),
            "--object-format".into(),
            format.as_str().into(),
        ];
        assert!(super::super::run(&export, &mut Vec::new()).is_err());
        assert!(!archive_path.exists());
        export.extend(["--max-blob-bytes".into(), LENGTH.to_string()]);
        super::super::run(&export, &mut Vec::new()).unwrap();
        let expected = pin(&archive_path);
        fs::remove_dir_all(&source_root).unwrap();
        let verification_root = scratch.0.join("verify");
        let mut verify = vec![
            "verify".into(),
            archive_path.to_str().unwrap().into(),
            verification_root.to_str().unwrap().into(),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            hex(&expected),
            "--verification-instance".into(),
            "991".into(),
        ];
        assert!(super::super::run(&verify, &mut Vec::new()).is_err());
        assert!(!verification_root.exists());
        verify.extend(["--max-blob-bytes".into(), LENGTH.to_string()]);
        super::super::run(&verify, &mut Vec::new()).unwrap();
        assert!(!verification_root.exists());
        let mut profile = Profile::default();
        profile.transfer.max_blob_bytes = LENGTH as u64;
        let output = scratch.0.join("restored");
        let mut options = Options {
            input: archive_path.clone(),
            output: output.clone(),
            expected,
            instance: StoreInstanceId::from_raw(992),
            profile,
            resume: false,
            approval: None,
        };
        let mut reached = false;
        let error = execute_with_checkpoints(&options, |stage| {
            if stage == Stage::Objects {
                reached = true;
                Err("interrupted after large-blob placement".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(reached, "{error}");
        assert!(!output.join("authority.fsqlite").exists());
        options.resume = true;
        let receipt = execute(&options).unwrap();
        assert!(receipt.contains("\"objects\":3,"));
        assert!(receipt.contains("\"resume_requested\":true"));
        let first = with_node(node_config(&output, format), |node| {
            let request = node.request_context();
            readback(node, blob, &request);
            let head = node
                .runtime()
                .block_on(node.authenticate_authority_head_in(&request))
                .map_err(|e| e.to_string())?;
            Ok(head.receipt().clone())
        })
        .unwrap();
        let repeated = execute(&options).unwrap();
        assert!(repeated.contains("\"already_published\":true"));
        with_node(node_config(&output, format), |node| {
            let request = node.request_context();
            readback(node, blob, &request);
            let head = node
                .runtime()
                .block_on(node.authenticate_authority_head_in(&request))
                .map_err(|e| e.to_string())?;
            assert_eq!(
                head.receipt(),
                &first,
                "identical retry preserves exact authority and token"
            );
            Ok(())
        })
        .unwrap();
    }
}
