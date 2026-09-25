//! Native backend preflight, with no live source and no substitute authority.
use super::*;
use super::super::{NodeConfig, OneNode};
use fgit_crypto::{DigestHasher, GitObjectKind, Sha256Hasher, git_object_id, git_payload_commitment};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration,
    PrincipalId, RepositoryId, TenantId,
};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(1);
const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-backup-preflight-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}
fn node_config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.to_path_buf(), TenantId::from_hex(TENANT).unwrap(),
        RepositoryId::from_hex(REPOSITORY).unwrap())
        .with_object_format(format).with_worker_threads(2)
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let hex = id.to_string();
    let path = root.join("objects").join(&hex[..2]).join(&hex[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let length = u16::try_from(framed.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&(!length).to_le_bytes());
    bytes.extend_from_slice(&framed);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    bytes.extend_from_slice(&((b << 16) | a).to_be_bytes());
    fs::write(path, bytes).unwrap();
    id
}
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (PathBuf, [u8; 32], [GitOid; 3]) {
    let git = scratch.0.join("source.git");
    let root = scratch.0.join("source-node");
    let blob = loose(&git, format, GitObjectKind::Blob, b"preflight before restore\n");
    let mut tree = b"100644 README\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = loose(&git, format, GitObjectKind::Tree, &tree);
    let body = format!(
        "tree {tree}\nauthor Verify <v@example.invalid> 1 +0000\ncommitter Verify <v@example.invalid> 1 +0000\n\nverify\n"
    );
    let commit = loose(&git, format, GitObjectKind::Commit, body.as_bytes());
    fs::create_dir_all(git.join("refs/heads")).unwrap();
    fs::write(git.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(git.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let (mut node, _) = OneNode::init(node_config(&root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &git, PrincipalId::from_bytes([3; 16]), b"preflight-source",
    )).unwrap();
    assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    node.shutdown().unwrap();
    let file = scratch.0.join("source.fg");
    super::super::super::run(&[
        "export".into(), root.to_str().unwrap().into(), file.to_str().unwrap().into(),
        TENANT.into(), REPOSITORY.into(), "--trusted-local".into(),
        "--object-format".into(), format.as_str().into(),
    ], &mut Vec::new()).unwrap();
    let digest = hash(&fs::read(&file).unwrap());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(git).unwrap();
    (file, digest, [blob, tree, commit])
}
fn arguments(input: &Path, output: &Path, expected: [u8; 32]) -> Vec<String> {
    vec!["verify".into(), input.to_str().unwrap().into(), output.to_str().unwrap().into(),
        "--trusted-local".into(), "--expected-sha256".into(), hex(&expected),
        "--verification-instance".into(), "991".into()]
}
fn options(input: &Path, output: &Path, expected: [u8; 32]) -> Options {
    parse(&arguments(input, output, expected)).unwrap()
}

#[test]
fn real_preflight_checks_both_domains_without_writing_payloads_or_publishing_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (input, pin, ids) = fixture(&scratch, format);
        let output = scratch.0.join("verification");
        let request_options = options(&input, &output, pin);
        let mut observed = Vec::new();
        let receipt = execute_with_checkpoints(&request_options, |stage| {
            observed.push(stage);
            assert!(!output.join("authority.fsqlite").exists());
            assert!(!output.join(".restore-intent").exists());
            if stage == Stage::GraphCheckedAndNodeClosed {
                with_node(node_config(&output.join(".verify-quarantine"), format), |node| {
                    for id in ids {
                        assert!(node.read_git_object(id).is_err(), "preflight placed a Git payload");
                    }
                    Ok(())
                })?;
            }
            Ok(())
        }).unwrap();
        assert_eq!(observed, [Stage::AuthorityClosed, Stage::GraphCheckedAndNodeClosed]);
        assert!(receipt.contains("\"objects\":3,"));
        assert!(receipt.contains("\"object_graph_verified\":true"));
        assert!(receipt.contains("\"destination_readback_verified\":false"));
        assert!(receipt.contains("\"scratch_removed\":true"));
        assert!(!output.exists());
        assert_eq!(hash(&fs::read(&input).unwrap()), pin);
        // A separate actual restore still installs and reads the payloads back.
        let restored = options(&input, &scratch.0.join("restored"), pin);
        let receipt = super::super::execute(&restored).unwrap();
        assert!(receipt.contains("\"reopened_and_verified\":true"));
    }
}

#[test]
fn pin_size_and_deadline_refusals_never_create_scratch() {
    let scratch = Scratch::new();
    let (input, pin, _) = fixture(&scratch, GitHashAlgorithm::Sha1);
    let output = scratch.0.join("verification");
    let mut wrong = options(&input, &output, pin);
    wrong.expected[0] ^= 1;
    assert!(execute(&wrong).unwrap_err().contains("checksum mismatch"));
    assert!(!output.exists());
    let mut small = options(&input, &output, pin);
    small.profile.transfer.max_archive_bytes = fs::metadata(&input).unwrap().len() - 1;
    assert!(execute(&small).unwrap_err().contains("archive-byte limit"));
    assert!(!output.exists());
    let mut expired = options(&input, &output, pin);
    expired.profile.timeout = Duration::ZERO;
    assert!(execute(&expired).unwrap_err().contains("deadline"));
    assert!(!output.exists());
    assert!(execute(&options(&input, &output, pin)).is_ok());
}

#[test]
fn an_existing_scratch_directory_is_never_reused_or_removed() {
    let scratch = Scratch::new();
    let output = scratch.0.join("existing");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("keep"), b"not owned by verification").unwrap();
    let options = options(&scratch.0.join("unread"), &output, [0; 32]);
    assert!(execute(&options).unwrap_err().contains("already exists"));
    assert_eq!(fs::read(output.join("keep")).unwrap(), b"not owned by verification");
}

#[test]
fn a_validly_framed_archive_cannot_omit_an_authority_selected_object() {
    use super::super::super::archive::{decode, Encoder};
    let scratch = Scratch::new();
    let (input, pin, _) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let bytes = fs::read(&input).unwrap();
    let decoded = decode(&bytes, || Ok(())).unwrap();
    let authority = fgit_authority_fsqlite::export_bundle(&decoded.authority).unwrap();
    let mut reduced = Encoder::new(decoded.identity, &authority, decoded.records.len() - 1).unwrap();
    for record in decoded.records.iter().skip(1) {
        let commitment = git_payload_commitment(record.kind, record.payload, CANONICAL_CODEC_VERSION);
        let mut original = [0_u8; 32];
        original.copy_from_slice(commitment.digest().as_bytes());
        reduced.object(record.oid, record.kind, record.payload, &original).unwrap();
    }
    let bytes = reduced.finish().unwrap();
    let missing = scratch.0.join("missing.fg");
    fs::write(&missing, &bytes).unwrap();
    let output = scratch.0.join("missing-verification");
    let error = execute(&options(&missing, &output, hash(&bytes))).unwrap_err();
    assert!(error.contains("inventory does not equal the authority-selected object set"), "{error}");
    assert!(output.join(".verify-quarantine").exists());
    assert!(!output.join("authority.fsqlite").exists());
    assert!(execute(&options(&input, &scratch.0.join("correct-verification"), pin)).is_ok());
}

#[test]
fn interrupted_preflight_retains_private_state_and_never_enables_resume() {
    let scratch = Scratch::new();
    let (input, pin, _) = fixture(&scratch, GitHashAlgorithm::Sha1);
    for stage in [Stage::AuthorityClosed, Stage::GraphCheckedAndNodeClosed] {
        let output = scratch.0.join(format!("interrupted-{stage:?}"));
        let mut options = options(&input, &output, pin);
        let error = execute_with_checkpoints(&options, |observed| {
            if observed == stage { Err("injected preflight interruption".into()) } else { Ok(()) }
        }).unwrap_err();
        assert!(error.contains("injected preflight interruption"));
        assert!(error.contains("no destination authority published"));
        assert!(output.join(".verify-quarantine").exists());
        assert!(!output.join("authority.fsqlite").exists());
        assert!(!output.join(".restore-intent").exists());
        assert!(execute(&options).unwrap_err().contains("already exists"));
        options.resume = true;
        assert!(execute(&options).unwrap_err().contains("cannot resume"));
    }
}

#[test]
fn verification_parser_is_bounded_and_has_no_restore_or_resume_authority() {
    let base = arguments(Path::new("archive"), Path::new("scratch"), [1; 32]);
    assert!(parse(&base).is_ok());
    for value in ["0", "01", "+1", "-1", "9223372036854775808", "18446744073709551616"] {
        let mut bad = base.clone();
        bad[7] = value.into();
        assert!(parse(&bad).is_err());
    }
    for extra in [vec!["--resume"], vec!["--trusted-local"], vec!["--destination-instance", "3"],
        vec!["--expected-sha256", "00"], vec!["--timeout-secs", "0"]] {
        let mut bad = base.clone();
        bad.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&bad).is_err());
    }
    let mut missing_trust = base.clone();
    missing_trust.remove(3);
    assert!(parse(&missing_trust).is_err());
    let mut large = base;
    large[1] = "x".repeat(8193);
    assert!(parse(&large).is_err());
}
