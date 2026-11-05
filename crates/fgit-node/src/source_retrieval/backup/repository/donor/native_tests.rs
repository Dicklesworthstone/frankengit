//! Native consumer regressions. These use real authority decisions, object
//! envelopes, cold reopen, archive preflight and ordinary restore; no fixture
//! constructor can manufacture a VerifiedSourceArchive or ancestry receipt.
#![cfg(unix)]

use super::super as repository;
use super::*;
use crate::{LoopbackReceiveSession, MaterializedAdmission, NodeConfig};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_authority_fsqlite::export_bundle;
use fgit_crypto::{DigestHasher, GitObjectKind, Sha256Hasher};
use fgit_forge::{
    ExpectedVersion, IssueNumber,
    event::issue::{IssueAction, IssueCommand},
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-native-donor-{}-{}",
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
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.to_path_buf(),
        TenantId::from_hex(TENANT).unwrap(),
        RepositoryId::from_hex(REPOSITORY).unwrap(),
    )
    .with_object_format(format)
    .with_worker_threads(2)
}
fn create(root: &Path, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
fn open(root: &Path, format: GitHashAlgorithm) -> OneNode {
    let mut node = OneNode::open_existing(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([7; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
struct Objects {
    blob: GitOid,
    tree: GitOid,
    commit: GitOid,
    all: BTreeSet<GitOid>,
}
fn publish(node: &OneNode, label: &str, previous: Option<&Objects>) -> Objects {
    let blob = node
        .put_git_object(
            GitObjectKind::Blob,
            format!("{label} payload\n").into_bytes(),
        )
        .unwrap()
        .identity();
    let mut tree = b"100644 file\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = node
        .put_git_object(GitObjectKind::Tree, tree)
        .unwrap()
        .identity();
    let parent = previous.map_or_else(String::new, |objects| {
        format!("parent {}\n", objects.commit)
    });
    let commit = node.put_git_object(GitObjectKind::Commit,
        format!("tree {tree}\n{parent}author Backup <b@example.invalid> 1 +0000\ncommitter Backup <b@example.invalid> 1 +0000\n\n{label}\n").into_bytes()).unwrap().identity();
    let mut all = previous.map_or_else(BTreeSet::new, |objects| objects.all.clone());
    all.extend([blob, tree, commit]);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            all.clone(),
        ))
        .unwrap(),
        objects: all.clone(),
    };
    let receipt = SourceImportReceipt {
        object_format: node.object_format,
        object_count: u32::try_from(all.len()).unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let old = previous.map_or_else(
        || {
            GitOid::from_hex(
                node.object_format,
                &"0".repeat(node.object_format.digest_len() * 2),
            )
            .unwrap()
        },
        |objects| objects.commit,
    );
    let import = validate_source_import(
        &[SourceRefUpdate {
            old,
            new: commit,
            ref_name: b"refs/heads/main".to_vec(),
        }],
        &receipt,
        closure,
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.authority_head_key().clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([7; 16]),
        idempotency_key: IdempotencyKey::new(format!("donor-{label}").into_bytes()).unwrap(),
        object_format: node.object_format,
    };
    let admitted = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &node.request_context(),
            &context,
            &import,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    Objects {
        blob,
        tree,
        commit,
        all,
    }
}
fn issue() -> IssueCommand {
    IssueCommand {
        number: IssueNumber::try_new(1).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Newer than donor".into(),
            body: "Retain the newer canonical forge state and outcome".into(),
            labels: vec![],
        },
    }
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}
fn pin(path: &Path) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(&fs::read(path).unwrap());
    hash.finish()
}
fn arguments(root: &Path, output: &Path, format: GitHashAlgorithm) -> Vec<String> {
    [
        "export",
        root.to_str().unwrap(),
        output.to_str().unwrap(),
        TENANT,
        REPOSITORY,
        "--trusted-local",
        "--object-format",
        format.as_str(),
    ]
    .map(str::to_owned)
    .to_vec()
}
fn donor_arguments(
    root: &Path,
    output: &Path,
    donor: &Path,
    scratch: &Path,
    format: GitHashAlgorithm,
) -> Vec<String> {
    let mut args = arguments(root, output, format);
    args.extend(
        [
            "--donor-backup",
            donor.to_str().unwrap(),
            "--donor-sha256",
            &hex(&pin(donor)),
            "--donor-scratch",
            scratch.to_str().unwrap(),
            "--donor-verification-instance",
            "7771",
        ]
        .map(str::to_owned),
    );
    args
}
fn run(args: &[String]) -> Result<String, String> {
    let mut output = Vec::new();
    repository::run(args, &mut output)?;
    String::from_utf8(output).map_err(|error| error.to_string())
}
// Locate a known admitted fixture object's real envelope solely to inject
// physical corruption. The production export continues to use canonical IDs.
fn body_path(root: &Path, oid: GitOid) -> PathBuf {
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file()
                && entry.file_name().to_str() == Some(oid.to_string().as_str())
                && fs::read(entry.path()).unwrap().starts_with(b"FGOB")
            {
                found.push(entry.path());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "exactly one persisted native object envelope"
    );
    found.pop().unwrap()
}

#[test]
fn cold_donor_export_recovers_missing_and_corrupt_history_while_retaining_newer_refs_forge_and_checkpoint()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = scratch.0.join("source");
        let node = create(&source, format);
        let old = publish(&node, "old", None);
        let old_head = snapshot(&node);
        node.shutdown().unwrap();
        let donor = scratch.0.join("old.fg");
        let ordinary = run(&arguments(&source, &donor, format)).unwrap();
        assert!(!ordinary.contains("donor_backup"));
        assert_eq!(&fs::read(&donor).unwrap()[..8], b"FGSRC001");

        let node = open(&source, format);
        let current = publish(&node, "new", Some(&old));
        let issued = node
            .runtime()
            .block_on(node.admit_issue_durable_in(
                &node.request_context(),
                &session("donor-new-issue"),
                &issue(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            issued.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let checkpoint = node
            .runtime()
            .block_on(node.checkpoint_outcomes_in(&node.request_context(), Default::default()))
            .unwrap();
        assert!(checkpoint.published);
        let expected = snapshot(&node);
        assert_ne!(
            expected.snapshot().forge_positions,
            old_head.snapshot().forge_positions
        );
        assert!(
            expected.authenticated().receipt().generation()
                > old_head.authenticated().receipt().generation()
        );
        node.shutdown().unwrap();
        let intact = scratch.0.join("intact-current.fg");
        run(&arguments(&source, &intact, format)).unwrap();
        assert_eq!(&fs::read(&intact).unwrap()[..8], b"FGSRC002");

        let missing = body_path(&source, old.blob);
        let corrupt = body_path(&source, old.tree);
        fs::remove_file(&missing).unwrap();
        fs::write(&corrupt, b"damaged original envelope").unwrap();
        let failed = scratch.0.join("ordinary-must-fail.fg");
        assert!(run(&arguments(&source, &failed, format)).is_err());
        assert!(!failed.exists());

        let repaired = scratch.0.join("current-recovery.fg");
        let verification = scratch.0.join("donor-verify");
        let receipt = run(&donor_arguments(
            &source,
            &repaired,
            &donor,
            &verification,
            format,
        ))
        .unwrap();
        assert_eq!(
            fs::read(&repaired).unwrap(),
            fs::read(&intact).unwrap(),
            "current authority, checkpoint and complete object bytes match intact export"
        );
        assert!(receipt.contains("\"selected_objects_supplied\":3"));
        assert!(receipt.contains("\"local_objects_supplied\":3"));
        assert!(receipt.contains("\"source_objects_repaired\":false"));
        assert!(receipt.contains(&format!("\"sha256\":\"{}\"", hex(&pin(&donor)))));
        assert!(!verification.exists());
        assert!(!missing.exists());
        assert_eq!(fs::read(&corrupt).unwrap(), b"damaged original envelope");
        let node = open(&source, format);
        assert_eq!(
            snapshot(&node).authenticated().receipt(),
            expected.authenticated().receipt()
        );
        assert!(node.read_git_object(old.blob).is_err());
        node.shutdown().unwrap();

        let restored = scratch.0.join("restored");
        run(&[
            "restore",
            repaired.to_str().unwrap(),
            restored.to_str().unwrap(),
            "--trusted-local",
            "--expected-sha256",
            &hex(&pin(&repaired)),
            "--destination-instance",
            "7772",
        ]
        .map(str::to_owned))
        .unwrap();
        let node = open(&restored, format);
        let actual = snapshot(&node);
        assert_eq!(
            actual.authenticated().receipt().body(),
            expected.authenticated().receipt().body()
        );
        assert_eq!(actual.snapshot(), expected.snapshot());
        assert_eq!(actual.selected_closure().closure().objects(), &current.all);
        assert_eq!(
            node.read_git_object(old.blob).unwrap().payload(),
            b"old payload\n"
        );
        assert_eq!(
            node.read_git_object(current.blob).unwrap().payload(),
            b"new payload\n"
        );
        let recovered = node
            .runtime()
            .block_on(node.admit_issue_durable_in(
                &node.request_context(),
                &session("donor-new-issue"),
                &issue(),
                Default::default(),
            ))
            .unwrap();
        assert_eq!(
            recovered, issued,
            "the original canonical issue outcome survives the retained checkpoint"
        );
        let same_checkpoint = node
            .runtime()
            .block_on(node.checkpoint_outcomes_in(&node.request_context(), Default::default()))
            .unwrap();
        assert!(!same_checkpoint.published);
        assert_eq!(same_checkpoint.checkpoint_root, checkpoint.checkpoint_root);
        assert_eq!(same_checkpoint.capsule_id, checkpoint.capsule_id);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_missing_current_only_object_refuses_without_reverting_to_the_donor_snapshot() {
    let scratch = Scratch::new();
    let source = scratch.0.join("source");
    let format = GitHashAlgorithm::Sha256;
    let node = create(&source, format);
    let old = publish(&node, "old", None);
    node.shutdown().unwrap();
    let donor = scratch.0.join("old.fg");
    run(&arguments(&source, &donor, format)).unwrap();
    let node = open(&source, format);
    let new = publish(&node, "new", Some(&old));
    let expected = snapshot(&node);
    node.shutdown().unwrap();
    let missing = body_path(&source, new.blob);
    fs::remove_file(&missing).unwrap();
    let output = scratch.0.join("refused.fg");
    let verification = scratch.0.join("verify");
    assert!(
        run(&donor_arguments(
            &source,
            &output,
            &donor,
            &verification,
            format
        ))
        .is_err()
    );
    assert!(!output.exists());
    assert!(!missing.exists());
    let node = open(&source, format);
    assert_eq!(
        snapshot(&node).authenticated().receipt(),
        expected.authenticated().receipt()
    );
    node.shutdown().unwrap();
}

#[test]
fn wrong_pin_and_another_incarnation_refuse_before_any_output_can_publish() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let donor_source = scratch.0.join("donor-source");
    let node = create(&donor_source, format);
    publish(&node, "same", None);
    let donor_incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let donor = scratch.0.join("old.fg");
    run(&arguments(&donor_source, &donor, format)).unwrap();
    let source = scratch.0.join("different-source");
    let node = create(&source, format);
    publish(&node, "same", None);
    assert_ne!(node.repository_incarnation_id(), donor_incarnation);
    let expected = snapshot(&node);
    node.shutdown().unwrap();
    let output = scratch.0.join("no-output.fg");
    let verification = scratch.0.join("verify");
    let mut arguments = donor_arguments(&source, &output, &donor, &verification, format);
    let pin_index = arguments
        .iter()
        .position(|value| value == "--donor-sha256")
        .unwrap()
        + 1;
    arguments[pin_index] = "00".repeat(32);
    assert!(run(&arguments).unwrap_err().contains("checksum mismatch"));
    assert!(!verification.exists());
    assert!(!output.exists());
    arguments[pin_index] = hex(&pin(&donor));
    assert!(run(&arguments).unwrap_err().contains("incarnation"));
    assert!(!output.exists());
    assert!(!verification.exists());
    let node = open(&source, format);
    assert_eq!(
        snapshot(&node).authenticated().receipt(),
        expected.authenticated().receipt()
    );
    node.shutdown().unwrap();
}

#[test]
fn an_explicitly_cancelled_native_request_never_begins_donor_or_local_payload_reads() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let source = scratch.0.join("source");
    let node = create(&source, format);
    publish(&node, "old", None);
    node.shutdown().unwrap();
    let donor = scratch.0.join("old.fg");
    run(&arguments(&source, &donor, format)).unwrap();
    let destination = scratch.0.join("absent.fg");
    let verification = scratch.0.join("verify");
    let parsed = repository::parse(&donor_arguments(
        &source,
        &destination,
        &donor,
        &verification,
        format,
    ))
    .unwrap();
    let options = parsed.donor.unwrap();
    let deadline = parsed.profile.start();
    let (mut prepared, _) = options
        .prepare(
            &source,
            &destination,
            (parsed.tenant, parsed.repository, format),
            parsed.profile,
            deadline,
        )
        .unwrap();
    let node = open(&source, format);
    let selected = snapshot(&node);
    let request = node.request_context();
    request.cancel();
    let encoded = export_bundle(&prepared.archive.header().authority).unwrap();
    let mut private = Vec::new();
    let mut output = StreamEncoder::new(
        &mut private,
        prepared.archive.header().identity,
        &encoded,
        selected.selected_closure().closure().objects().len(),
        parsed.profile.transfer,
        &mut || Ok(()),
    )
    .unwrap();
    let result = prepared.write_selected(
        SourceSnapshot {
            node: &node,
            request: &request,
            captured: selected.authenticated().receipt(),
            objects: selected.selected_closure().closure().objects(),
        },
        &mut output,
        deadline,
        |_, _| panic!("cancelled before any local object read"),
    );
    assert!(result.err().unwrap().contains("cancelled"));
    assert!(!destination.exists());
    assert_eq!(
        snapshot(&node).authenticated().receipt(),
        selected.authenticated().receipt()
    );
    node.shutdown().unwrap();
}
