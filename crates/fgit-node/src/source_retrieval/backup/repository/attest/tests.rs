//! Native attestation uses real authority import and graph verification. The
//! fixed private key is the public RFC8032 test vector, never a deployment key.
use super::*;
use crate::{NodeConfig, OneNode};
use fgit_crypto::{
    DigestHasher, GitObjectKind, Sha256Hasher, git_object_id, git_payload_commitment,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration,
    PrincipalId, RepositoryId, TenantId,
};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);
const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRIVATE: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n";
const PUBLIC: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";

pub(in super::super) struct Fixture {
    pub root: PathBuf,
    pub input: PathBuf,
    pub expected: [u8; 32],
    pub identity: super::super::archive::Identity,
    pub generation: u64,
    pub private_key: PathBuf,
    pub public_key: PathBuf,
}

impl Fixture {
    pub(in super::super) fn new(format: GitHashAlgorithm, payload: &[u8]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-native-attest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let source = root.join("source-node");
        let git = root.join("source.git");
        let blob = loose(&git, format, GitObjectKind::Blob, payload);
        let mut tree = b"100644 payload\0".to_vec();
        tree.extend_from_slice(blob.as_bytes());
        let tree = loose(&git, format, GitObjectKind::Tree, &tree);
        let commit = format!(
            "tree {tree}\nauthor Attest <a@example.invalid> 1 +0000\ncommitter Attest <a@example.invalid> 1 +0000\n\nnative approval fixture\n"
        );
        let commit = loose(&git, format, GitObjectKind::Commit, commit.as_bytes());
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::write(git.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(git.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let config = NodeConfig::new(
            source.clone(),
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &git,
                PrincipalId::from_bytes([3; 16]),
                b"native-attestation-source",
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        node.shutdown().unwrap();
        let input = root.join("source.fg");
        super::super::run(
            &[
                "export".into(),
                source.to_str().unwrap().into(),
                input.to_str().unwrap().into(),
                TENANT.into(),
                REPOSITORY.into(),
                "--trusted-local".into(),
                "--object-format".into(),
                format.as_str().into(),
            ],
            &mut Vec::new(),
        )
        .unwrap();
        let bytes = fs::read(&input).unwrap();
        let decoded = super::super::archive::decode(&bytes, || Ok(())).unwrap();
        let identity = decoded.identity;
        let generation = decoded.authority.head.as_ref().unwrap().generation;
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(git).unwrap();
        let private_key = root.join("operator.private.pem");
        fs::write(&private_key, PRIVATE).unwrap();
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600)).unwrap();
        let public_key = root.join("operator.public.pem");
        fs::write(&public_key, PUBLIC).unwrap();
        Self {
            root,
            input,
            expected: hash(&bytes),
            identity,
            generation,
            private_key,
            public_key,
        }
    }

    pub(in super::super) fn options(&self, name: &str) -> Options {
        Options {
            input: self.input.clone(),
            output: self.root.join(format!("{name}.approval")),
            scratch: self.root.join(format!("{name}.scratch")),
            private_key: self.private_key.clone(),
            expected: self.expected,
            instance: StoreInstanceId::from_raw(991),
            declarations: Declarations {
                identity: self.identity,
                generation: self.generation,
                expires_at: None,
                clock: None,
            },
            profile: Profile::default(),
        }
    }

    fn assert_no_stages(&self) {
        assert!(!fs::read_dir(&self.root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fg-backup-approval-")
        }));
    }

    fn signed_arguments(&self, operation: &str, output: &Path, approval: &Path) -> Vec<String> {
        vec![
            operation.into(),
            self.input.to_str().unwrap().into(),
            output.to_str().unwrap().into(),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            hex(&self.expected),
            if operation == "verify" {
                "--verification-instance"
            } else {
                "--destination-instance"
            }
            .into(),
            "992".into(),
            "--approval".into(),
            approval.to_str().unwrap().into(),
            "--trust-key".into(),
            self.public_key.to_str().unwrap().into(),
            "--tenant-id".into(),
            self.identity.tenant.to_string(),
            "--repository-id".into(),
            self.identity.repository.to_string(),
            "--incarnation-id".into(),
            self.identity.incarnation.to_string(),
            "--object-format".into(),
            self.identity.format.as_str().into(),
            "--minimum-head-generation".into(),
            self.generation.to_string(),
        ]
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let text = id.to_string();
    let path = root.join("objects").join(&text[..2]).join(&text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let mut bytes = vec![0x78, 0x01];
    let chunks = framed.chunks(u16::MAX as usize);
    let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        bytes.push(u8::from(index + 1 == count));
        let length = chunk.len() as u16;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&(!length).to_le_bytes());
        bytes.extend_from_slice(chunk);
    }
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    bytes.extend_from_slice(&((b << 16) | a).to_be_bytes());
    fs::write(path, bytes).unwrap();
    id
}

#[test]
fn source_deleted_both_domains_attest_then_native_signed_verify_and_restore() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"verified source approval\0\xff\n");
        let mut options = fixture.options("valid");
        options.profile.transfer.max_objects = 3;
        options.profile.transfer.max_archive_bytes = fs::metadata(&fixture.input).unwrap().len();
        let receipt = execute_in(&options, options.profile.start()).unwrap();
        for field in [
            "\"native_content_verified\":true",
            "\"archive_bytes_authenticated\":true",
            "\"object_graph_verified\":true",
            "\"scratch_removed\":true",
            "\"publication_state\":\"durable\"",
        ] {
            assert!(receipt.json().contains(field), "{}", receipt.json());
        }
        assert!(!options.scratch.exists());
        assert!(!fixture.root.join("source-node").exists());
        for operation in ["verify", "restore"] {
            let output = fixture.root.join(operation);
            let mut result = Vec::new();
            super::super::run(
                &fixture.signed_arguments(operation, &output, &options.output),
                &mut result,
            )
            .unwrap();
            let result = String::from_utf8(result).unwrap();
            assert!(result.contains("\"signature_verified\":true"), "{result}");
            if operation == "restore" {
                assert!(result.contains("\"reopened_and_verified\":true"));
            }
        }
        fixture.assert_no_stages();
    }
}

#[test]
fn false_declarations_and_incomplete_graph_refuse_before_any_private_key_read() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"actual selected payload");
    let mut false_declaration = fixture.options("false-declaration");
    false_declaration.declarations.generation += 1;
    false_declaration.private_key = fixture.root.join("missing-key");
    let error = execute_in(&false_declaration, false_declaration.profile.start()).unwrap_err();
    assert!(error.contains("declarations do not match"), "{error}");
    assert!(!false_declaration.output.exists());
    assert!(!false_declaration.scratch.exists());

    let bytes = fs::read(&fixture.input).unwrap();
    let decoded = super::super::archive::decode(&bytes, || Ok(())).unwrap();
    let authority = fgit_authority_fsqlite::export_bundle(&decoded.authority).unwrap();
    let mut encoder = super::super::archive::Encoder::new(
        decoded.identity,
        &authority,
        decoded.records.len() - 1,
    )
    .unwrap();
    for record in decoded.records.iter().skip(1) {
        let commitment =
            git_payload_commitment(record.kind, record.payload, CANONICAL_CODEC_VERSION);
        let mut original = [0; 32];
        original.copy_from_slice(commitment.digest().as_bytes());
        encoder
            .object(record.oid, record.kind, record.payload, &original)
            .unwrap();
    }
    let missing = encoder.finish().unwrap();
    let mut bad_graph = fixture.options("bad-graph");
    bad_graph.input = fixture.root.join("missing-object.fg");
    fs::write(&bad_graph.input, &missing).unwrap();
    bad_graph.expected = hash(&missing);
    bad_graph.private_key = fixture.root.join("missing-key");
    let error = execute_in(&bad_graph, bad_graph.profile.start()).unwrap_err();
    assert!(error.contains("inventory does not equal"), "{error}");
    assert!(!bad_graph.output.exists());
    assert!(bad_graph.scratch.exists());
    assert!(!bad_graph.scratch.join("authority.fsqlite").exists());
    fixture.assert_no_stages();
}

#[test]
fn changing_verified_archive_after_preflight_cannot_get_a_signature() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"immutable source bytes");
    let options = fixture.options("changed");
    let error = execute_with_checkpoints(&options, options.profile.start(), |stage| {
        if stage == Stage::KeyRead {
            let mut bytes = fs::read(&options.input).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            fs::write(&options.input, bytes).unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("publication_state=not_created"), "{error}");
    assert!(!options.output.exists());
    assert!(!options.scratch.exists());
    fixture.assert_no_stages();
}

#[test]
fn private_keys_reject_permissions_links_symlinks_noncanonical_bytes_and_wrong_owner() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"private key profile");
    let deadline = Profile::default().start();
    let mut stage =
        filesystem::Stage::reserve(&fixture.root.join("private-check"), deadline).unwrap();
    let owner = stage.owner();
    assert!(filesystem::read_private_key(&fixture.private_key, owner, deadline).is_ok());
    assert!(
        filesystem::read_private_key(&fixture.private_key, owner.wrapping_add(1), deadline)
            .is_err()
    );
    fs::set_permissions(&fixture.private_key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(filesystem::read_private_key(&fixture.private_key, owner, deadline).is_err());
    fs::set_permissions(&fixture.private_key, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = fixture.root.join("hard-linked-key");
    fs::hard_link(&fixture.private_key, &linked).unwrap();
    assert!(filesystem::read_private_key(&fixture.private_key, owner, deadline).is_err());
    fs::remove_file(linked).unwrap();
    let alias = fixture.root.join("symlink-key");
    symlink(&fixture.private_key, &alias).unwrap();
    assert!(filesystem::read_private_key(&alias, owner, deadline).is_err());
    for body in [
        PUBLIC.to_vec(),
        [PRIVATE, b"suffix"].concat(),
        b"not an Ed25519 PKCS8 key".to_vec(),
        vec![b'x'; 8193],
    ] {
        fs::write(&fixture.private_key, body).unwrap();
        assert!(filesystem::read_private_key(&fixture.private_key, owner, deadline).is_err());
    }
    fs::write(&fixture.private_key, PRIVATE).unwrap();
    assert!(filesystem::read_private_key(&fixture.private_key, owner, deadline).is_ok());
    assert!(stage.failure("test abort".into()).contains("not_created"));
    fixture.assert_no_stages();

    let mut replaced =
        filesystem::Stage::reserve(&fixture.root.join("replaced-stage"), deadline).unwrap();
    let temporary = fs::read_dir(&fixture.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".fg-backup-approval-")
        })
        .unwrap();
    fs::remove_file(&temporary).unwrap();
    fs::write(&temporary, b"replacement is not owned by this stage").unwrap();
    let error = replaced.failure("injected namespace replacement".into());
    assert!(error.contains("cleanup refused"), "{error}");
    assert_eq!(
        fs::read(&temporary).unwrap(),
        b"replacement is not owned by this stage"
    );
    assert!(!fixture.root.join("replaced-stage").exists());
    fs::remove_file(temporary).unwrap();
}

#[test]
fn deadline_expiry_racing_output_and_late_errors_preserve_publication_state() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"publication boundaries");
    let mut expired = fixture.options("deadline");
    expired.profile.timeout = Duration::ZERO;
    assert!(
        execute_in(&expired, expired.profile.start())
            .unwrap_err()
            .contains("deadline")
    );
    assert!(!expired.scratch.exists());
    assert!(!expired.output.exists());

    let mut expiry = fixture.options("expiry");
    let clock = Arc::new(AtomicI64::new(1_893_456_000_000)); // 2030-01-01T00:00:00Z
    expiry.declarations.clock = Some(Arc::clone(&clock));
    expiry.declarations.expires_at = Some("2030-01-01T00:00:01Z".into());
    let error = execute_with_checkpoints(&expiry, expiry.profile.start(), |stage| {
        if stage == Stage::EnvelopeStaged {
            clock.store(1_893_456_001_000, Ordering::SeqCst);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("expired"), "{error}");
    assert!(!expiry.output.exists());
    fixture.assert_no_stages();

    let race = fixture.options("race");
    let error = execute_with_checkpoints(&race, race.profile.start(), |stage| {
        if stage == Stage::BeforePublication {
            fs::write(&race.output, b"another writer owns this").unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("not_created"), "{error}");
    assert_eq!(fs::read(&race.output).unwrap(), b"another writer owns this");
    fixture.assert_no_stages();

    let late = fixture.options("late");
    let error = execute_with_checkpoints(&late, late.profile.start(), |stage| {
        if stage == Stage::Published {
            Err("injected late receipt failure".into())
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.contains("publication_state=durable"), "{error}");
    assert!(late.output.exists());
    super::super::run(
        &fixture.signed_arguments(
            "verify",
            &fixture.root.join("late-verification"),
            &late.output,
        ),
        &mut Vec::new(),
    )
    .unwrap();
}

#[test]
fn attest_parser_requires_all_independent_inputs_and_accepts_every_resource_limit() {
    let base: Vec<String> = [
        "attest",
        "archive",
        "approval",
        "scratch",
        "--trusted-local",
        "--private-key",
        "private.pem",
        "--expected-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--verification-instance",
        "9",
        "--tenant-id",
        TENANT,
        "--repository-id",
        REPOSITORY,
        "--incarnation-id",
        "33333333333333333333333333333333",
        "--object-format",
        "sha256",
        "--head-generation",
        "18446744073709551615",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(base.len(), 21);
    assert_eq!(parse(&base).unwrap().declarations.generation, u64::MAX);
    let mut full = base.clone();
    full.extend(
        [
            "--expires-at",
            "2099-12-31T23:59:59Z",
            "--max-archive-bytes",
            "2147483648",
            "--max-blob-bytes",
            "536870912",
            "--max-objects",
            "1000000",
            "--timeout-secs",
            "900",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let parsed = parse(&full).unwrap();
    assert_eq!(full.len(), 31);
    assert_eq!(parsed.profile.transfer.max_objects, 1_000_000);
    assert_eq!(parsed.profile.transfer.max_archive_bytes, 2 << 30);
    assert_eq!(parsed.profile.transfer.max_blob_bytes, 512 * 1024 * 1024);
    assert_eq!(parsed.profile.timeout.as_secs(), 900);
    for at in [5, 7, 9, 11, 13, 15, 17, 19] {
        let mut missing = base.clone();
        missing.drain(at..at + 2);
        assert!(parse(&missing).is_err());
    }
    for extra in [
        vec!["--private-key", "other"],
        vec!["--head-generation", "1"],
        vec!["--max-objects", "1000001"],
        vec!["--expires-at", "2030-02-29T00:00:00Z"],
        vec!["--unknown", "x"],
        vec!["--max-blob-bytes", "0"],
    ] {
        let mut bad = base.clone();
        bad.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&bad).is_err());
    }
}
