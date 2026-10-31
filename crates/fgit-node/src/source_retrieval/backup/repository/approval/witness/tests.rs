use super::super::{Identity, MAX_SIGNED_ARCHIVE_BYTES, PAYLOAD_TYPE, Statement, sha256, unhex};
use super::*;
use fgit_crypto::DsseEd25519SigningKey;
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const KEY_ID: &str = "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";
const NOW: i64 = 1_893_456_000_000;
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    format: GitHashAlgorithm,
    clock: Arc<AtomicI64>,
}

impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-native-witness-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("public.pem"), PUBLIC_PEM).unwrap();
        Self {
            root,
            format,
            clock: Arc::new(AtomicI64::new(NOW)),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn flags(&self, floor: u64) -> Vec<String> {
        [
            "--trusted-local".into(),
            "--trust-key".into(),
            self.path("public.pem").to_str().unwrap().into(),
            "--tenant-id".into(),
            "11111111111111111111111111111111".into(),
            "--repository-id".into(),
            "22222222222222222222222222222222".into(),
            "--incarnation-id".into(),
            "33333333333333333333333333333333".into(),
            "--object-format".into(),
            self.format.as_str().into(),
            "--minimum-head-generation".into(),
            floor.to_string(),
        ]
        .into()
    }

    fn trust(&self, floor: u64) -> LoadedApprovalTrust {
        let args = self.arguments("init", "unused", floor);
        let mut options = parse(&args).unwrap();
        options.trust.set_test_clock(Arc::clone(&self.clock));
        options.trust.load(Profile::default().start()).unwrap()
    }

    fn arguments(&self, operation: &str, name: &str, floor: u64) -> Vec<String> {
        let mut args = vec![
            "witness".into(),
            operation.into(),
            self.path(name).to_str().unwrap().into(),
        ];
        args.extend(self.flags(floor));
        args
    }

    fn envelope(&self, generation: u64, marker: u8, expires: bool) -> Vec<u8> {
        let statement = Statement {
            identity: Identity {
                tenant: TenantId::from_bytes([0x11; 16]),
                repository: RepositoryId::from_bytes([0x22; 16]),
                incarnation: RepositoryIncarnationId::from_bytes([0x33; 16]),
                format: self.format,
            },
            generation,
            issued_at: "2030-01-01T00:00:00Z".into(),
            issued_millis: NOW,
            expires_at: expires.then(|| "2030-01-01T00:00:01Z".into()),
            expires_millis: expires.then_some(NOW + 1000),
            archive_bytes: MAX_SIGNED_ARCHIVE_BYTES,
            digest: [marker; 32],
        }
        .canonical();
        let signer = DsseEd25519SigningKey::from_seed(
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
        );
        let signature = signer.sign(PAYLOAD_TYPE, statement.as_bytes()).unwrap();
        format!(
            "{{\"payloadType\":\"{PAYLOAD_TYPE}\",\"payload\":\"{}\",\"signatures\":[{{\"keyid\":\"{KEY_ID}\",\"sig\":\"{}\"}}]}}\n",
            state::encode_base64(statement.as_bytes()), state::encode_base64(&signature),
        ).into_bytes()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn deadline() -> Deadline {
    Profile::default().start()
}

fn state_bytes(path: &Path) -> Vec<u8> {
    fs::read(path.join(filesystem::STATE)).unwrap()
}

#[test]
fn native_initialization_matches_existing_javascript_state_wire_and_is_create_only() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let trust = fixture.trust(1);
        let path = fixture.path("witness");
        let receipt = initialize(&path, &trust, deadline()).unwrap();
        assert!(
            receipt
                .json()
                .contains("repository_backup_witness_initialized")
        );
        let expected = format!(
            concat!(
                "{{\"type\":\"repository_backup_witness_v1\",\"policy\":{{",
                "\"tenant_id\":\"11111111111111111111111111111111\",",
                "\"repository_id\":\"22222222222222222222222222222222\",",
                "\"incarnation_id\":\"33333333333333333333333333333333\",",
                "\"object_format\":\"{}\",\"minimum_head_generation\":\"1\"}},",
                "\"trusted_key_id\":\"{}\",\"observations\":[]}}\n"
            ),
            format.as_str(),
            KEY_ID,
        );
        assert_eq!(state_bytes(&path), expected.as_bytes());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path.join(filesystem::STATE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(initialize(&path, &trust, deadline()).is_err());
        assert_eq!(state_bytes(&path), expected.as_bytes());
        let guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
        assert!(
            guard
                .snapshot_json()
                .contains("\"highest_observed_generation\":null")
        );
        assert!(guard.check_selected().is_err());
        guard.finish().unwrap();
        assert!(!path.join(filesystem::LOCK).exists());
    }
}

#[test]
fn authenticated_expired_or_unavailable_newer_checkpoint_survives_restart_and_blocks_rollback() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let higher_bytes = fixture.envelope(20, 20, true);
    let higher = trust.inspect_bytes(&higher_bytes).unwrap();
    let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    guard.observe(&higher).unwrap();
    fixture.clock.store(NOW + 1000, Ordering::SeqCst);
    assert!(
        trust
            .inspect_bytes(&higher_bytes)
            .unwrap()
            .into_verified([20; 32], MAX_SIGNED_ARCHIVE_BYTES)
            .unwrap_err()
            .contains("expired")
    );
    // No archive is created or opened anywhere in this witness scenario.
    guard.finish().unwrap();
    drop(trust);
    let trust = fixture.trust(1);
    let mut reopened = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    assert!(
        reopened
            .snapshot_json()
            .contains("\"highest_observed_generation\":\"20\"")
    );
    let older = trust
        .inspect_bytes(&fixture.envelope(19, 19, false))
        .unwrap();
    let before = state_bytes(&path);
    reopened.observe(&older).unwrap();
    assert_eq!(state_bytes(&path), before);
    assert!(reopened.require(&older).unwrap_err().contains("below"));
    let newer = trust
        .inspect_bytes(&fixture.envelope(21, 21, false))
        .unwrap();
    reopened.observe(&newer).unwrap();
    reopened.require(&newer).unwrap();
    reopened.check_selected().unwrap();
    reopened.finish().unwrap();
    let restored = State::decode(&state_bytes(&path), &trust).unwrap();
    assert_eq!(restored.observations[0].generation(), 21);
}

#[test]
fn conflicting_highest_statements_persist_and_only_strictly_higher_evidence_clears_them() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let first_bytes = fixture.envelope(20, 1, false);
    let first = trust.inspect_bytes(&first_bytes).unwrap();
    let conflict = trust
        .inspect_bytes(&fixture.envelope(20, 2, false))
        .unwrap();
    let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    guard.observe(&first).unwrap();
    let before = state_bytes(&path);
    let inode = fs::metadata(path.join(filesystem::STATE)).unwrap().ino();
    let equivalent = trust
        .inspect_bytes(&[first_bytes.as_slice(), b"\n"].concat())
        .unwrap();
    guard.observe(&equivalent).unwrap();
    assert_eq!(state_bytes(&path), before);
    assert_eq!(
        fs::metadata(path.join(filesystem::STATE)).unwrap().ino(),
        inode
    );
    guard.observe(&conflict).unwrap();
    assert!(guard.require(&first).unwrap_err().contains("conflicting"));
    assert!(
        guard
            .require(&conflict)
            .unwrap_err()
            .contains("conflicting")
    );
    guard.finish().unwrap();
    let mut reopened = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    reopened.observe(&first).unwrap();
    assert!(
        reopened
            .require(&first)
            .unwrap_err()
            .contains("conflicting")
    );
    let newest = trust
        .inspect_bytes(&fixture.envelope(u64::MAX, 3, false))
        .unwrap();
    reopened.observe(&newest).unwrap();
    reopened.require(&newest).unwrap();
    reopened.check_selected().unwrap();
    reopened.finish().unwrap();
    let state = State::decode(&state_bytes(&path), &trust).unwrap();
    assert_eq!(state.observations.len(), 1);
    assert_eq!(state.observations[0].generation(), u64::MAX);
}

#[test]
fn stronger_floor_is_durable_and_a_later_weaker_policy_is_refused() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let mut first = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    first
        .observe(
            &trust
                .inspect_bytes(&fixture.envelope(20, 1, false))
                .unwrap(),
        )
        .unwrap();
    first.finish().unwrap();
    let stronger = fixture.trust(21);
    let mut guard = WitnessGuard::open(&path, &stronger, deadline()).unwrap();
    assert_eq!(guard.state.floor, 21);
    assert_eq!(guard.state.observations[0].generation(), 20);
    let old = stronger
        .inspect_bytes(&fixture.envelope(20, 1, false))
        .unwrap();
    assert!(guard.require(&old).unwrap_err().contains("below"));
    guard.finish().unwrap();
    assert!(
        WitnessGuard::open(&path, &trust, deadline())
            .unwrap_err()
            .contains("weaker")
    );
    assert!(!path.join(filesystem::LOCK).exists());
    let mut allowed = WitnessGuard::open(&path, &stronger, deadline()).unwrap();
    let current = stronger
        .inspect_bytes(&fixture.envelope(21, 2, false))
        .unwrap();
    allowed.observe(&current).unwrap();
    allowed.require(&current).unwrap();
    allowed.finish().unwrap();
}

#[test]
fn durable_lease_excludes_competing_owners_and_unfinished_drop_never_steals_or_releases() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let mut owner = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    owner
        .observe(
            &trust
                .inspect_bytes(&fixture.envelope(10, 1, false))
                .unwrap(),
        )
        .unwrap();
    assert!(
        WitnessGuard::open(&path, &trust, deadline())
            .unwrap_err()
            .contains("exclusive lease")
    );
    drop(owner);
    assert!(path.join(filesystem::LOCK).exists());
    assert!(
        WitnessGuard::open(&path, &trust, deadline())
            .unwrap_err()
            .contains("exclusive lease")
    );
    // Test-only operator intervention after the only owner has explicitly died.
    fs::remove_file(path.join(filesystem::LOCK)).unwrap();
    let reopened = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    assert_eq!(reopened.state.observations[0].generation(), 10);
    let error = reopened.retain("native shutdown outcome is unresolved");
    assert!(error.contains("witness_lock_retained=true"));
    assert!(path.join(filesystem::LOCK).exists());
}

#[test]
fn every_persistence_failure_preserves_obligations_and_never_rolls_back_visible_state() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let trust = fixture.trust(1);
    for (index, target) in [
        filesystem::Checkpoint::BeforeStage,
        filesystem::Checkpoint::StageSynced,
        filesystem::Checkpoint::BeforeRename,
        filesystem::Checkpoint::Renamed,
        filesystem::Checkpoint::DirectorySynced,
    ]
    .into_iter()
    .enumerate()
    {
        let path = fixture.path(&format!("witness-{index}"));
        initialize(&path, &trust, deadline()).unwrap();
        let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
        let older = trust
            .inspect_bytes(&fixture.envelope(10, 1, false))
            .unwrap();
        guard.observe(&older).unwrap();
        let original = state_bytes(&path);
        let higher = trust
            .inspect_bytes(&fixture.envelope(20, 2, false))
            .unwrap();
        let error = guard
            .observe_with_checkpoints(&higher, |checkpoint| {
                if checkpoint == target {
                    Err("injected persistence interruption".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.contains("witness_lock_retained=true"), "{error}");
        assert!(
            guard
                .finish()
                .unwrap_err()
                .contains("witness_lock_retained=true")
        );
        assert!(path.join(filesystem::LOCK).exists());
        assert!(WitnessGuard::open(&path, &trust, deadline()).is_err());
        let retained = State::decode(&state_bytes(&path), &trust).unwrap();
        let visible = matches!(
            target,
            filesystem::Checkpoint::Renamed | filesystem::Checkpoint::DirectorySynced
        );
        assert_eq!(
            retained.observations[0].generation(),
            if visible { 20 } else { 10 }
        );
        if !visible {
            assert_eq!(state_bytes(&path), original);
        }
        assert!(!fs::read_dir(&path).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }
}

#[test]
fn deadline_between_authentication_and_retention_keeps_lease_but_settled_cleanup_can_finish_late() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let observed = trust
        .inspect_bytes(&fixture.envelope(20, 1, false))
        .unwrap();
    let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    guard.deadline = Profile {
        timeout: Duration::ZERO,
        ..Profile::default()
    }
    .start();
    assert!(guard.observe(&observed).unwrap_err().contains("deadline"));
    assert!(
        guard
            .finish()
            .unwrap_err()
            .contains("witness_lock_retained=true")
    );
    assert!(path.join(filesystem::LOCK).exists());

    let settled_path = fixture.path("settled");
    initialize(&settled_path, &trust, deadline()).unwrap();
    let mut settled = WitnessGuard::open(&settled_path, &trust, deadline()).unwrap();
    settled.observe(&observed).unwrap();
    settled.require(&observed).unwrap();
    settled.deadline = Profile {
        timeout: Duration::ZERO,
        ..Profile::default()
    }
    .start();
    assert!(settled.check_selected().unwrap_err().contains("deadline"));
    settled.finish().unwrap();
    assert!(!settled_path.join(filesystem::LOCK).exists());
    assert_eq!(
        State::decode(&state_bytes(&settled_path), &trust)
            .unwrap()
            .observations[0]
            .generation(),
        20
    );
}

#[test]
fn absent_corrupt_noncanonical_or_nonprivate_state_never_becomes_an_empty_witness() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let trust = fixture.trust(1);
    assert!(WitnessGuard::open(&fixture.path("absent"), &trust, deadline()).is_err());
    for (index, kind) in [
        "missing",
        "invalid",
        "noncanonical",
        "permissions",
        "hardlink",
        "symlink",
        "oversize",
    ]
    .into_iter()
    .enumerate()
    {
        let path = fixture.path(&format!("bad-{index}"));
        initialize(&path, &trust, deadline()).unwrap();
        let state_path = path.join(filesystem::STATE);
        let bytes = state_bytes(&path);
        match kind {
            "missing" => fs::remove_file(&state_path).unwrap(),
            "invalid" => fs::write(&state_path, b"{broken").unwrap(),
            "noncanonical" => fs::write(&state_path, [b" ".as_slice(), &bytes].concat()).unwrap(),
            "permissions" => {
                fs::set_permissions(&state_path, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "hardlink" => {
                fs::hard_link(&state_path, fixture.path(&format!("alias-{index}"))).unwrap()
            }
            "symlink" => {
                let saved = fixture.path(&format!("saved-{index}"));
                fs::rename(&state_path, &saved).unwrap();
                symlink(saved, &state_path).unwrap();
            }
            _ => fs::write(&state_path, vec![b'x'; state::MAX_STATE_BYTES + 1]).unwrap(),
        }
        assert!(
            WitnessGuard::open(&path, &trust, deadline()).is_err(),
            "{kind}"
        );
        assert!(
            !path.join(filesystem::LOCK).exists(),
            "load refusal retires its own lease: {kind}"
        );
    }
}

#[test]
fn retained_signatures_and_independent_key_namespace_are_rechecked_on_every_open() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let encoded = fixture.envelope(20, 1, false);
    let observed = trust.inspect_bytes(&encoded).unwrap();
    let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    guard.observe(&observed).unwrap();
    guard.finish().unwrap();
    let original = state_bytes(&path);

    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(
        DsseEd25519SigningKey::from_seed([0xa5; 32])
            .verifying_key()
            .as_bytes(),
    );
    let other_key = fixture.path("other-public.pem");
    fs::write(
        &other_key,
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            state::encode_base64(&der),
        ),
    )
    .unwrap();
    for (index, replacement) in [
        (5, other_key.to_str().unwrap()),
        (7, "44444444444444444444444444444444"),
        (9, "44444444444444444444444444444444"),
        (11, "44444444444444444444444444444444"),
        (13, "sha256"),
    ] {
        let mut args = fixture.arguments("inspect", "witness", 1);
        args[index] = replacement.to_owned();
        let other = parse(&args).unwrap().trust.load(deadline()).unwrap();
        assert!(WitnessGuard::open(&path, &other, deadline()).is_err());
        assert_eq!(state_bytes(&path), original);
        assert!(!path.join(filesystem::LOCK).exists());
    }

    // Keep the state wire canonical while changing an original signature.
    // A stored envelope is evidence to authenticate, never a trusted assertion.
    let mut forged = String::from_utf8(encoded.clone()).unwrap();
    let at = forged.find("\"sig\":\"").unwrap() + 7;
    let replacement = if forged.as_bytes()[at] == b'A' {
        "B"
    } else {
        "A"
    };
    forged.replace_range(at..at + 1, replacement);
    let forged_state = String::from_utf8(original.clone()).unwrap().replace(
        &state::encode_base64(&encoded),
        &state::encode_base64(forged.as_bytes()),
    );
    fs::write(path.join(filesystem::STATE), forged_state.as_bytes()).unwrap();
    assert!(WitnessGuard::open(&path, &trust, deadline()).is_err());
    assert_eq!(state_bytes(&path), forged_state.as_bytes());
    assert!(!path.join(filesystem::LOCK).exists());

    fs::write(path.join(filesystem::STATE), &original).unwrap();
    let mut allowed = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    allowed.require(&observed).unwrap();
    allowed.check_selected().unwrap();
    allowed.finish().unwrap();
    assert_eq!(state_bytes(&path), original);
}

#[test]
fn authenticated_observation_from_other_namespace_cannot_change_a_live_witness() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let original = state_bytes(&path);
    let different = Fixture::new(GitHashAlgorithm::Sha256);
    let different_trust = different.trust(1);
    let foreign = different_trust
        .inspect_bytes(&different.envelope(u64::MAX, 1, false))
        .unwrap();
    let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    assert!(guard.observe(&foreign).unwrap_err().contains("trust"));
    assert_eq!(state_bytes(&path), original);
    let allowed = trust
        .inspect_bytes(&fixture.envelope(20, 2, false))
        .unwrap();
    guard.observe(&allowed).unwrap();
    guard.require(&allowed).unwrap();
    guard.finish().unwrap();
    assert_eq!(
        State::decode(&state_bytes(&path), &trust)
            .unwrap()
            .observations[0]
            .generation(),
        20,
    );
}

#[test]
fn final_checks_detect_changed_state_or_foreign_lock_and_preserve_the_replacement() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let trust = fixture.trust(1);
    let path = fixture.path("witness");
    initialize(&path, &trust, deadline()).unwrap();
    let observed = trust
        .inspect_bytes(&fixture.envelope(20, 1, false))
        .unwrap();
    let mut guard = WitnessGuard::open(&path, &trust, deadline()).unwrap();
    guard.observe(&observed).unwrap();
    guard.require(&observed).unwrap();
    let state_path = path.join(filesystem::STATE);
    fs::write(&state_path, b"foreign state").unwrap();
    assert!(guard.check_selected().is_err());
    assert!(
        guard
            .finish()
            .unwrap_err()
            .contains("witness_lock_retained=true")
    );
    assert_eq!(fs::read(&state_path).unwrap(), b"foreign state");

    let other = fixture.path("foreign-lock");
    initialize(&other, &trust, deadline()).unwrap();
    let guard = WitnessGuard::open(&other, &trust, deadline()).unwrap();
    let lock = other.join(filesystem::LOCK);
    fs::rename(&lock, other.join("old-lock")).unwrap();
    fs::write(&lock, b"different owner").unwrap();
    assert!(
        guard
            .finish()
            .unwrap_err()
            .contains("witness_lock_retained=true")
    );
    assert_eq!(fs::read(lock).unwrap(), b"different owner");
}

#[test]
fn command_grammar_and_receipt_failures_preserve_durable_state_and_released_ownership() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let args = fixture.arguments("init", "command", 1);
    assert_eq!(args.len(), 16);
    let mut all = args.clone();
    all.extend(["--timeout-secs".into(), "86400".into()]);
    assert_eq!(parse(&all).unwrap().profile.timeout.as_secs(), 86400);
    for removed in [4, 6, 8, 10, 12, 14] {
        let mut missing = all.clone();
        missing.drain(removed..removed + 2);
        assert!(parse(&missing).is_err());
    }
    let mut untrusted = all.clone();
    untrusted.remove(3);
    assert!(parse(&untrusted).is_err());
    struct RefusedWriter;
    impl Write for RefusedWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("receipt closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = run(&args, &mut RefusedWriter, None).unwrap_err();
    assert!(error.contains("operation completed"));
    let path = fixture.path("command");
    let before = state_bytes(&path);
    let inspect = fixture.arguments("inspect", "command", 1);
    assert!(
        run(&inspect, &mut RefusedWriter, None)
            .unwrap_err()
            .contains("operation completed")
    );
    assert_eq!(state_bytes(&path), before);
    assert!(!path.join(filesystem::LOCK).exists());
    let mut successful = Vec::new();
    run(&inspect, &mut successful, None).unwrap();
    assert!(
        String::from_utf8(successful)
            .unwrap()
            .contains("repository_backup_witness_inspection")
    );
    assert_eq!(sha256(&state_bytes(&path)), sha256(&before));
}
