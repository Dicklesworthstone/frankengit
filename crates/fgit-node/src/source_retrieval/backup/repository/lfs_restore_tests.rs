//! Paired recovery through the production native export, verify and restore
//! paths, including original source loss and interrupted authority publication.
use super::super::super as repository;
use super::*;
use fgit_object_fabric::artifact::storage::ArtifactOperation;
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore};
use fgit_types::RepositoryIncarnationId;
use std::io::Cursor;
use std::time::Duration;

const OLD_PAYLOAD: &[u8] = b"historical LFS payload\0\xff\n";
const CURRENT_PAYLOAD: &[u8] = b"current LFS payload\0\xfe\n";

fn lfs_object(bytes: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(bytes),
        size: bytes.len() as u64,
    }
}

struct Source {
    root: PathBuf,
    git: PathBuf,
    custody: PathBuf,
    format: GitHashAlgorithm,
    incarnation: RepositoryIncarnationId,
}

impl Source {
    fn new(scratch: &Scratch, format: GitHashAlgorithm, include_historical: bool) -> Self {
        let root = scratch.0.join("source-node");
        let git = scratch.0.join("source.git");
        let custody = scratch.0.join("source-lfs");
        let old_blob = loose(
            &git,
            format,
            GitObjectKind::Blob,
            lfs_object(OLD_PAYLOAD).pointer().as_bytes(),
        );
        let current_blob = loose(
            &git,
            format,
            GitObjectKind::Blob,
            lfs_object(CURRENT_PAYLOAD).pointer().as_bytes(),
        );
        let mut old_tree = b"100644 historical.bin\0".to_vec();
        old_tree.extend_from_slice(old_blob.as_bytes());
        let old_tree = loose(&git, format, GitObjectKind::Tree, &old_tree);
        let old_commit = loose(
            &git,
            format,
            GitObjectKind::Commit,
            format!("tree {old_tree}\nauthor LFS <lfs@example.invalid> 1 +0000\ncommitter LFS <lfs@example.invalid> 1 +0000\n\nhistorical\n").as_bytes(),
        );
        // Two paths share one pointer. Its payload must travel only once, while
        // the pointer reachable exclusively through the parent still travels.
        let mut current_tree = b"100644 current.bin\0".to_vec();
        current_tree.extend_from_slice(current_blob.as_bytes());
        current_tree.extend_from_slice(b"100644 duplicate.bin\0");
        current_tree.extend_from_slice(current_blob.as_bytes());
        let current_tree = loose(&git, format, GitObjectKind::Tree, &current_tree);
        let tip = loose(
            &git,
            format,
            GitObjectKind::Commit,
            format!("tree {current_tree}\nparent {old_commit}\nauthor LFS <lfs@example.invalid> 2 +0000\ncommitter LFS <lfs@example.invalid> 2 +0000\n\ncurrent\n").as_bytes(),
        );
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::write(git.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(
            git.join("config"),
            match format {
                GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
                GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
            },
        ).unwrap();
        let (mut node, _) = OneNode::init(node_config(&root, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &git,
                PrincipalId::from_bytes([3; 16]),
                b"paired-lfs-source",
            ))
            .unwrap();
        assert!(matches!(
            imported.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let incarnation = node.repository_incarnation_id();
        create_private(&custody).unwrap();
        let store = LfsStore::open(
            &custody,
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
            incarnation,
        )
        .unwrap();
        let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &|| true).unwrap();
        for bytes in [CURRENT_PAYLOAD]
            .into_iter()
            .chain(include_historical.then_some(OLD_PAYLOAD))
        {
            store
                .put(lfs_object(bytes), &mut Cursor::new(bytes), &op)
                .unwrap();
        }
        node.shutdown().unwrap();
        Self {
            root,
            git,
            custody,
            format,
            incarnation,
        }
    }

    fn export(&self, input: &Path, companion: &Path) -> Result<String, String> {
        let args = vec![
            "export".into(),
            self.root.to_str().unwrap().into(),
            input.to_str().unwrap().into(),
            TENANT.into(),
            REPOSITORY.into(),
            "--trusted-local".into(),
            "--object-format".into(),
            self.format.as_str().into(),
            "--lfs-root".into(),
            self.custody.to_str().unwrap().into(),
            "--lfs-output".into(),
            companion.to_str().unwrap().into(),
        ];
        let mut output = Vec::new();
        repository::run(&args, &mut output)?;
        Ok(String::from_utf8(output).unwrap())
    }

    fn retire(self) {
        fs::remove_dir_all(self.root).unwrap();
        fs::remove_dir_all(self.git).unwrap();
        fs::remove_dir_all(self.custody).unwrap();
    }
}

struct Pair {
    input: PathBuf,
    pin: [u8; 32],
    companion: PathBuf,
    companion_pin: [u8; 32],
    incarnation: RepositoryIncarnationId,
}

impl Pair {
    fn new(scratch: &Scratch, format: GitHashAlgorithm) -> Self {
        let source = Source::new(scratch, format, true);
        let input = scratch.0.join("source.fg");
        let companion = scratch.0.join("source.fglf");
        let receipt = source.export(&input, &companion).unwrap();
        assert!(
            receipt.contains("\"lfs_payloads_included\":true"),
            "{receipt}"
        );
        assert!(
            receipt.contains("\"objects\":2,\"payload_bytes\":"),
            "{receipt}"
        );
        let pin = fgit_crypto::sha256_digest(&fs::read(&input).unwrap());
        let companion_pin = fgit_crypto::sha256_digest(&fs::read(&companion).unwrap());
        let incarnation = source.incarnation;
        source.retire();
        Self {
            input,
            pin,
            companion,
            companion_pin,
            incarnation,
        }
    }

    fn restore(&self, output: PathBuf) -> Options {
        let mut request = options(&self.input, output, self.pin);
        request.lfs = Some(repository::LfsInput {
            path: self.companion.clone(),
            expected: self.companion_pin,
        });
        request
    }

    fn assert_custody(&self, output: &Path) {
        let store = LfsStore::open(
            &output.join("lfs"),
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
            self.incarnation,
        )
        .unwrap();
        let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &|| true).unwrap();
        for bytes in [OLD_PAYLOAD, CURRENT_PAYLOAD] {
            assert_eq!(store.read(lfs_object(bytes), &op).unwrap(), bytes);
        }
    }

    fn verify_args(&self, scratch: &Path) -> Vec<String> {
        vec![
            "verify".into(),
            self.input.to_str().unwrap().into(),
            scratch.to_str().unwrap().into(),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            hex(&self.pin),
            "--verification-instance".into(),
            "992".into(),
            "--lfs-archive".into(),
            self.companion.to_str().unwrap().into(),
            "--expected-lfs-sha256".into(),
            hex(&self.companion_pin),
        ]
    }
}

#[test]
fn paired_native_recovery_survives_source_loss_and_verifies_historical_lfs_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let pair = Pair::new(&scratch, format);
        let verify_root = scratch.0.join("verify");
        let mut receipt = Vec::new();
        repository::run(&pair.verify_args(&verify_root), &mut receipt).unwrap();
        let receipt = String::from_utf8(receipt).unwrap();
        assert!(
            receipt.contains("\"lfs_payloads_verified\":true"),
            "{receipt}"
        );
        assert!(!verify_root.exists());

        let mut request = pair.restore(scratch.0.join("restored"));
        let receipt = execute(&request).unwrap();
        assert!(
            receipt.contains("\"lfs_payloads_restored\":true"),
            "{receipt}"
        );
        assert!(receipt.contains("\"already_published\":false"), "{receipt}");
        pair.assert_custody(&request.output);
        let original = snapshot(&request.output);
        assert!(!request.output.join(".restore-quarantine").exists());
        request.resume = true;
        let receipt = execute(&request).unwrap();
        assert!(receipt.contains("\"already_published\":true"), "{receipt}");
        assert_eq!(snapshot(&request.output), original);
        pair.assert_custody(&request.output);
    }
}

#[test]
fn missing_or_corrupt_companion_refuses_before_destination_or_verify_scratch() {
    let scratch = Scratch::new();
    let pair = Pair::new(&scratch, GitHashAlgorithm::Sha256);
    let mut request = pair.restore(scratch.0.join("bad-pin"));
    request.lfs.as_mut().unwrap().expected[0] ^= 1;
    assert!(execute(&request).is_err());
    assert!(!request.output.exists());

    let bytes = fs::read(&pair.companion).unwrap();
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    fs::write(&pair.companion, changed).unwrap();
    let verify_root = scratch.0.join("bad-verify");
    assert!(repository::run(&pair.verify_args(&verify_root), &mut Vec::new()).is_err());
    assert!(!verify_root.exists());
    fs::remove_file(&pair.companion).unwrap();
    let request = pair.restore(scratch.0.join("missing"));
    assert!(execute(&request).is_err());
    assert!(!request.output.exists());

    // The established explicit source-only lane remains available. Its receipt
    // must not silently claim the external payloads survived.
    let source_only = options(&pair.input, scratch.0.join("source-only"), pair.pin);
    let receipt = execute(&source_only).unwrap();
    assert!(!receipt.contains("lfs_companion"));
    assert!(!source_only.output.join("lfs").exists());
}

#[test]
fn interrupted_lfs_installation_and_publication_resume_only_with_the_original_pair() {
    let scratch = Scratch::new();
    let pair = Pair::new(&scratch, GitHashAlgorithm::Sha1);
    for (name, stage) in [
        ("lfs-staged", Stage::Lfs),
        ("data-moved", Stage::DataPrepared),
        ("published", Stage::Published),
    ] {
        let mut request = pair.restore(scratch.0.join(name));
        stop(&request, stage);
        assert_eq!(
            request.output.join("authority.fsqlite").exists(),
            stage == Stage::Published
        );
        request.resume = true;
        let mut without_companion = options(&pair.input, request.output.clone(), pair.pin);
        without_companion.resume = true;
        let error = execute(&without_companion).unwrap_err();
        assert!(error.contains("intent"), "{error}");
        assert_eq!(
            request.output.join("authority.fsqlite").exists(),
            stage == Stage::Published
        );
        let receipt = execute(&request).unwrap();
        assert!(
            receipt.contains("\"lfs_payloads_restored\":true"),
            "{receipt}"
        );
        pair.assert_custody(&request.output);
        assert!(!request.output.join(".restore-quarantine").exists());
    }
}

#[test]
fn published_retry_refuses_missing_lfs_without_repair_or_authority_rewrite() {
    let scratch = Scratch::new();
    let pair = Pair::new(&scratch, GitHashAlgorithm::Sha256);
    let mut request = pair.restore(scratch.0.join("published"));
    execute(&request).unwrap();
    let original = snapshot(&request.output);
    fs::remove_dir_all(request.output.join("lfs")).unwrap();
    request.resume = true;
    let error = execute(&request).unwrap_err();
    assert!(error.contains("authority is visible"), "{error}");
    assert!(error.contains("LFS"), "{error}");
    assert!(!request.output.join("lfs").exists());
    assert_eq!(snapshot(&request.output), original);
}

#[test]
fn export_requires_historical_payload_and_distinct_pair_destinations() {
    let scratch = Scratch::new();
    let source = Source::new(&scratch, GitHashAlgorithm::Sha1, false);
    let input = scratch.0.join("incomplete.fg");
    let companion = scratch.0.join("incomplete.fglf");
    assert!(source.export(&input, &companion).is_err());
    assert!(!input.exists());
    assert!(!companion.exists());
    assert!(source.export(&input, &input).is_err());
    assert!(!input.exists());
}

#[test]
fn optional_lfs_argument_pairs_are_explicit_and_checksum_pins_remain_independent() {
    let base: Vec<String> = [
        "restore",
        "source.fg",
        "destination",
        "--trusted-local",
        "--expected-sha256",
        &"a".repeat(64),
        "--destination-instance",
        "991",
    ]
    .iter()
    .map(|s| (*s).into())
    .collect();
    assert!(parse(&base).unwrap().lfs.is_none());
    for flag in ["--lfs-archive", "--expected-lfs-sha256"] {
        let mut args = base.clone();
        args.extend([
            flag.into(),
            if flag == "--lfs-archive" {
                "source.fglf".into()
            } else {
                "b".repeat(64)
            },
        ]);
        assert!(parse(&args).is_err());
    }
    let mut args = base.clone();
    args.extend([
        "--lfs-archive".into(),
        "source.fglf".into(),
        "--expected-lfs-sha256".into(),
        "b".repeat(64),
    ]);
    let parsed = parse(&args).unwrap();
    assert_eq!(parsed.expected, [0xaa; 32]);
    assert_eq!(parsed.lfs.unwrap().expected, [0xbb; 32]);
    args.extend(["--lfs-archive".into(), "substitute.fglf".into()]);
    assert!(parse(&args).is_err());
}
