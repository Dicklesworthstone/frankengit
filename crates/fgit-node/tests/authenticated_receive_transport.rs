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
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{
    LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, NodeSourceImportRefusal,
    OneNode,
};
use fgit_types::cell::{CellRefusal, CellState};
use fgit_types::numeric::HeadGeneration;
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

/// A node brought into service, which every write-side path now requires.
///
/// `frankengit-fg036b`. The cell lifecycle is operator-driven: `init` and
/// `open_existing` leave the cell in `CellState::Bootstrapping`, and both the
/// receive transport and the source import refuse there. A caller that means to
/// carry traffic performs the transition itself, and `fg import` does exactly
/// this at `fgit-cli/src/lib.rs`.
fn serving_node(root: PathBuf) -> OneNode {
    let mut node = node(root);
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("a freshly initialised cell comes into service");
    assert_eq!(node.cell_state(), CellState::Serving);
    node
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

/// Write one zlib-framed loose object as a single stored deflate block.
fn write_loose_object(root: &Path, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(GitHashAlgorithm::Sha1, kind, body);
    let framed = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(framed.len()).expect("fixture object fits one stored block");
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&framed);
    let (low, high) = framed.iter().fold((1_u32, 0_u32), |(low, high), byte| {
        let low = (low + u32::from(*byte)) % 65521;
        (low, (high + low) % 65521)
    });
    encoded.extend(((high << 16) | low).to_be_bytes());
    let hex = id.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).expect("object directory creates");
    fs::write(directory.join(&hex[2..]), encoded).expect("fixture loose object writes");
    id
}

/// A branch whose tip is a real commit: `refs/heads/*` admits commits only
/// (FG-019, ef9a090e), so the fixture commits blob `hello` in a one-entry tree.
fn write_loose_commit_repository(root: &Path) -> AnyGitOid {
    fs::create_dir_all(root).expect("fixture source directory creates");
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").expect("fixture symbolic HEAD writes");
    let blob = write_loose_object(root, GitObjectKind::Blob, "blob", b"hello");
    let mut tree = b"100644 hello.txt\0".to_vec();
    tree.extend(decode_hex(&blob.to_string()));
    let tree = write_loose_object(root, GitObjectKind::Tree, "tree", &tree);
    let commit = write_loose_object(
        root,
        GitObjectKind::Commit,
        "commit",
        format!(
            "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n"
        )
        .as_bytes(),
    );
    let ref_path = root.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(ref_path, format!("{commit}\n")).expect("fixture ref writes");
    AnyGitOid::from_hex(GitObjectFormat::Sha1, &commit.to_string())
        .expect("fixture commit identity parses")
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
    let node = serving_node(scratch.path().join("node"));
    let source = scratch.path().join("source");
    let old = write_loose_commit_repository(&source);

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
    // DELIBERATELY NOT `serving_node`: this cell violates the state gate too,
    // so naming `Unauthenticated` is a claim about which guard runs first.
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

#[test]
fn a_cell_nobody_brought_into_service_refuses_a_source_import() {
    // `frankengit-fg036b`, `GoldLotus`'s option (A). The workspace measurement
    // for this ruling found that the receive transport has ZERO production
    // callers and that `fgit-cli`'s `run_import` is the ONE production site at
    // which a `OneNode` takes external work in and publishes it. Gating only
    // the receive path would therefore have satisfied the ruling's letter with
    // nothing at stake, so the source import asks the same question — and this
    // is the case that holds it to it.
    let scratch = ScratchDirectory::new();
    let bootstrapping = node(scratch.path().join("node"));
    let source = scratch.path().join("source");
    write_loose_commit_repository(&source);
    assert_eq!(bootstrapping.cell_state(), CellState::Bootstrapping);

    let request = bootstrapping.request_context();
    let refusal = bootstrapping
        .runtime()
        .block_on(bootstrapping.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([0x01; 16]),
            b"fg036b-import-into-an-unserving-cell",
        ))
        .expect_err("a cell nobody brought into service publishes nothing");

    // BY VARIANT. `is_err()` here is satisfied by a staging failure, a
    // validation refusal, or an admission fault — none of which is the claim.
    // The claim is that the cell's STATE was consulted, and consulted before
    // the local source was read at all.
    assert!(
        matches!(
            refusal,
            NodeSourceImportRefusal::CellState(CellRefusal::StateAdmitsNoStaging {
                state: CellState::Bootstrapping
            })
        ),
        "expected a pre-intake state refusal naming Bootstrapping, got {refusal:?}"
    );
    bootstrapping.shutdown().expect("node closes cleanly");

    // THE PERMITTED TWIN: the identical source, the identical principal and
    // retry key, at a cell walked Bootstrapping -> VerifiedReadOnly -> Serving.
    let served_scratch = ScratchDirectory::new();
    let serving = serving_node(served_scratch.path().join("node"));
    let served_source = served_scratch.path().join("source");
    write_loose_commit_repository(&served_source);
    let served_request = serving.request_context();
    let admission = serving
        .runtime()
        .block_on(serving.import_loose_git_directory_durable_in(
            &served_request,
            &served_source,
            PrincipalId::from_bytes([0x01; 16]),
            b"fg036b-import-into-an-unserving-cell",
        ))
        .expect("a cell in service imports the same source");
    assert_eq!(admission.commands.len(), 1);
    assert!(
        matches!(
            admission.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ),
        "the permitted twin must actually publish, not merely avoid the state refusal"
    );
    serving.shutdown().expect("node closes cleanly");
}
