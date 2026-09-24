//! Real node/store executions stopped at the production restore boundaries.
//! Returned interruption errors are not an exhaustive process-kill/power-loss lane.
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::git_object_id;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RepositoryId, TenantId};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PAYLOAD: &[u8] = b"resume fixture content\n";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fg-resume-engine-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap(); Self(root)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn node_config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.to_path_buf(), TenantId::from_hex(TENANT).unwrap(), RepositoryId::from_hex(REPOSITORY).unwrap())
        .with_object_format(format)
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body); let id = oid.to_string();
    let path = root.join("objects").join(&id[..2]).join(&id[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes(); framed.extend_from_slice(body);
    let count = u16::try_from(framed.len()).unwrap(); let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend_from_slice(&count.to_le_bytes()); bytes.extend_from_slice(&(!count).to_le_bytes()); bytes.extend_from_slice(&framed);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed { a = (a + u32::from(byte)) % 65521; b = (b + a) % 65521; }
    bytes.extend_from_slice(&((b << 16) | a).to_be_bytes()); fs::write(path, bytes).unwrap(); oid
}
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (PathBuf, [u8; 32], GitOid) {
    let root = scratch.0.join("source-node"); let git = scratch.0.join("source.git");
    let blob = loose(&git, format, GitObjectKind::Blob, PAYLOAD);
    let mut tree = b"100644 README\0".to_vec(); tree.extend_from_slice(blob.as_bytes());
    let tree = loose(&git, format, GitObjectKind::Tree, &tree);
    let body = format!("tree {tree}\nauthor Resume <r@example.invalid> 1 +0000\ncommitter Resume <r@example.invalid> 1 +0000\n\nresume\n");
    let commit = loose(&git, format, GitObjectKind::Commit, body.as_bytes());
    fs::create_dir_all(git.join("refs/heads")).unwrap();
    fs::write(git.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let git_config = match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    };
    fs::write(git.join("config"), git_config).unwrap();
    let (mut node, _) = OneNode::init(node_config(&root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(&request,
        &git, PrincipalId::from_bytes([3; 16]), b"resume-source")).unwrap();
    assert_eq!(imported.commands.len(), 1);
    assert!(matches!(imported.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    node.shutdown().unwrap();
    let backup = scratch.0.join("source.fg");
    let args = vec!["export".into(), root.to_str().unwrap().into(), backup.to_str().unwrap().into(),
        TENANT.into(), REPOSITORY.into(), "--trusted-local".into(), "--object-format".into(), format.as_str().into()];
    super::super::run(&args, &mut Vec::new()).unwrap();
    let pin = super::super::super::sha256(&fs::read(&backup).unwrap());
    // The backup is the only source for every recovery attempt below.
    fs::remove_dir_all(root).unwrap(); fs::remove_dir_all(git).unwrap();
    (backup, pin, commit)
}
fn options(input: &Path, output: PathBuf, expected: [u8; 32]) -> Options {
    Options { input: input.to_path_buf(), output, expected, instance: StoreInstanceId::from_raw(991),
        profile: Profile::default(), resume: false }
}
fn snapshot(root: &Path) -> ExportBundle {
    with_store(&root.join("authority.fsqlite"), StoreInstanceId::from_raw(991), true,
        |runtime, store, cx| runtime.block_on(store.export_portable(cx, Default::default())).map_err(|e| e.to_string())).unwrap()
}
fn stop(options: &Options, stop: Stage) {
    let mut reached = false;
    let error = execute_with_checkpoints(options, |stage| {
        if stage == stop { reached = true; Err(format!("injected stop at {stage:?}")) } else { Ok(()) }
    }).unwrap_err();
    assert!(reached, "{stop:?} was not reached: {error}");
    assert!(error.contains("injected stop"), "{error}");
}

#[test]
fn each_restore_boundary_resumes_in_both_domains_without_new_authority_tokens() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let (input, pin, _) = fixture(&scratch, format);
        for (ordinal, stage) in [Stage::Intent, Stage::Authority, Stage::Objects, Stage::QuarantineVerified,
            Stage::DataPrepared, Stage::Published, Stage::FinalVerified, Stage::Cleaned].into_iter().enumerate()
        {
            let mut options = options(&input, scratch.0.join(format!("target-{ordinal}")), pin);
            stop(&options, stage);
            assert_eq!(options.output.join("authority.fsqlite").exists(),
                matches!(stage, Stage::Published | Stage::FinalVerified | Stage::Cleaned));
            options.resume = true;
            let receipt = execute(&options).unwrap();
            assert!(receipt.contains("\"objects\":3,"));
            assert!(receipt.contains("\"resume_requested\":true"));
            assert!(!options.output.join(".restore-quarantine").exists());
            let before = snapshot(&options.output);
            let again = execute(&options).unwrap();
            assert!(again.contains("\"already_published\":true"));
            assert_eq!(snapshot(&options.output), before, "retry cannot advance the ledger");
        }
    }
}

#[test]
fn a_partial_object_set_reuses_valid_bytes_and_installs_the_missing_selected_objects() {
    let scratch = Scratch::new(); let format = GitHashAlgorithm::Sha256;
    let (input, pin, _) = fixture(&scratch, format);
    let mut options = options(&input, scratch.0.join("partial"), pin); stop(&options, Stage::Authority);
    let quarantine = options.output.join(".restore-quarantine");
    with_node(node_config(&quarantine, format), |node| {
        node.put_git_object(GitObjectKind::Blob, PAYLOAD.to_vec()).map_err(|e| e.to_string())?; Ok(())
    }).unwrap();
    options.resume = true; assert!(execute(&options).unwrap().contains("\"objects\":3,"));
    with_node(node_config(&options.output, format), |node| {
        assert_eq!(node.read_git_object(git_object_id(format, GitObjectKind::Blob, PAYLOAD)).unwrap().payload(), PAYLOAD); Ok(())
    }).unwrap();
}

#[test]
fn a_published_destination_with_new_work_is_refused_without_rewinding_or_cleanup() {
    let scratch = Scratch::new(); let format = GitHashAlgorithm::Sha1;
    let (input, pin, commit) = fixture(&scratch, format);
    let mut options = options(&input, scratch.0.join("advanced"), pin); execute(&options).unwrap();
    with_node(node_config(&options.output, format), |node| {
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([3; 16]), IdempotencyKey::new(b"new-work".to_vec()).unwrap());
        let command = RefCommand { name: RefName::try_new(b"refs/heads/new-work").unwrap(),
            expected_old: ExpectedOld::Absent, proposed_new: ProposedNew::Update(commit), force: false };
        let result = node.runtime().block_on(node.admit_branch_updates_durable_in(&request, &session, &[command], Default::default())).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. })); Ok(())
    }).unwrap();
    let before = snapshot(&options.output); options.resume = true;
    let error = execute(&options).unwrap_err(); assert!(error.contains("complete imported snapshot"), "{error}");
    assert_eq!(snapshot(&options.output), before); assert!(!options.output.join(".restore-quarantine").exists());
}

/// Test-only fault injection in the isolated object's physical backing file.
fn payload_file(root: &Path, matches: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() { payload_file(&entry.path(), matches); }
        else if fs::read(entry.path()).unwrap().ends_with(PAYLOAD) { matches.push(entry.path()); }
    }
}
#[test]
fn corrupt_preexisting_object_is_not_overwritten_and_never_publishes_authority() {
    let scratch = Scratch::new(); let format = GitHashAlgorithm::Sha1;
    let (input, pin, _) = fixture(&scratch, format);
    let mut options = options(&input, scratch.0.join("corrupt"), pin); stop(&options, Stage::Objects);
    let mut matches = Vec::new(); payload_file(&options.output.join(".restore-quarantine/objects"), &mut matches);
    assert_eq!(matches.len(), 1); let path = &matches[0]; let original = fs::read(path).unwrap();
    let mut corrupted = original.clone(); *corrupted.last_mut().unwrap() ^= 1; fs::write(path, &corrupted).unwrap();
    options.resume = true; assert!(execute(&options).is_err());
    assert!(!options.output.join("authority.fsqlite").exists()); assert_eq!(fs::read(path).unwrap(), corrupted);
    // Only the test restores its planted bytes; the resume implementation did not.
    fs::write(path, original).unwrap(); execute(&options).unwrap();
}
