#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{
    AdmissionLimits, PermittedObjectClosure, QuarantineValidator, ValidatedClosure,
    permitted_object_closure_root, validate_receive,
};
use fgit_authority::IdempotencyKey;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefusalCode, RepositoryId, TenantId,
};
use fgit_wire::receive::{QuarantineReceipt, ReceiveCommand, ReceiveRequest};
use fgit_wire::{AnyGitOid, GitObjectFormat};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory {
    root: PathBuf,
}

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frankengit-authenticated-receive-{}-{sequence}",
            std::process::id()
        ));
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn node(root: PathBuf) -> OneNode {
    OneNode::init(NodeConfig::new(
        root,
        TenantId::from_bytes([0x41; 16]),
        RepositoryId::from_bytes([0x42; 16]),
    ))
    .expect("node initializes")
    .0
}

fn decode_hex(text: &str) -> Vec<u8> {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("fixed fixture contains hexadecimal digits"),
        }
    }

    let compact = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let (pairs, remainder) = compact.as_chunks::<2>();
    assert!(remainder.is_empty(), "fixed fixture has whole hex bytes");
    pairs
        .iter()
        .map(|pair| (digit(pair[0]) * 16) + digit(pair[1]))
        .collect()
}

fn write_loose_blob_repository(root: &Path) -> AnyGitOid {
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").expect("fixture symbolic HEAD writes");
    let oid = AnyGitOid::from_hex(
        GitObjectFormat::Sha1,
        "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
    )
    .expect("fixed blob identity parses");
    let object_path = root.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    fs::create_dir_all(object_path.parent().expect("object parent exists"))
        .expect("object directory creates");
    fs::write(
        object_path,
        decode_hex(include_str!(
            "../../fgit-git-object/tests/corpus/blob-hello.zlib.hex"
        )),
    )
    .expect("fixture loose object writes");
    let ref_path = root.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(ref_path, format!("{oid}\n")).expect("fixture ref writes");
    oid
}

struct DeleteOnlyValidator;

impl QuarantineValidator for DeleteOnlyValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
        _deadline: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::default())
                .expect("the empty permitted closure has a canonical root"),
            objects: BTreeSet::new(),
        })
    }
}

fn validated_delete(old: AnyGitOid) -> fgit_admission::ValidatedReceive {
    let request = ReceiveRequest {
        commands: vec![ReceiveCommand {
            old,
            new: AnyGitOid::from_hex(
                GitObjectFormat::Sha1,
                "0000000000000000000000000000000000000000",
            )
            .expect("SHA-1 zero identity parses"),
            ref_name: b"refs/heads/main".to_vec(),
        }],
        capabilities: Vec::new(),
        push_options: Vec::new(),
        certificate: None,
    };
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    let mut deadline = || true;
    validate_receive(
        &request,
        None,
        &receipt,
        &DeleteOnlyValidator,
        &mut deadline,
    )
    .expect("a delete-only receive has no pack but remains quarantine-validated")
}

#[test]
fn authenticated_loopback_session_admits_a_validated_push() {
    let scratch = ScratchDirectory::new();
    let node = node(scratch.path().join("node"));
    let source = scratch.path().join("source");
    let old = write_loose_blob_repository(&source);

    let import_request = node.request_context();
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &import_request,
            &source,
            PrincipalId::from_bytes([0x01; 16]),
            b"transport-test-bootstrap-import",
        ))
        .expect("the real loose-object source establishes the ref to delete");

    let principal = PrincipalId::from_bytes([0x73; 16]);
    let retry_key = IdempotencyKey::new(b"client-push-retry-key-0001".to_vec())
        .expect("bounded client retry key constructs");
    let session = LoopbackReceiveSession::authenticated(principal, retry_key.clone());
    let request = node.request_context();
    let outcome = node
        .runtime()
        .block_on(node.admit_loopback_receive_durable_in(
            &request,
            &session,
            &validated_delete(old),
            AdmissionLimits::default(),
        ))
        .expect("an authenticated principal and its client retry key admit the validated push");

    assert_eq!(outcome.commands.len(), 1);
    assert!(matches!(
        outcome.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("the committed delete materializes from the authority-selected head");
    assert!(materialized.snapshot().refs.is_empty());
    assert_eq!(retry_key.as_bytes(), b"client-push-retry-key-0001");
    assert_eq!(principal, PrincipalId::from_bytes([0x73; 16]));
    node.shutdown().expect("node closes cleanly");
}

#[test]
fn anonymous_loopback_session_is_refused_before_admission() {
    let scratch = ScratchDirectory::new();
    let node = node(scratch.path().join("node"));
    let old = GitOid::from_hex(
        GitHashAlgorithm::Sha1,
        "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
    )
    .expect("fixed object identity parses");
    let request = node.request_context();
    let refusal = node
        .runtime()
        .block_on(node.admit_loopback_receive_durable_in(
            &request,
            &LoopbackReceiveSession::anonymous(),
            &validated_delete(old),
            AdmissionLimits::default(),
        ));

    assert!(matches!(
        refusal,
        Err(NodeReceiveTransportRefusal::Unauthenticated)
    ));
    node.shutdown().expect("node closes cleanly");
}
