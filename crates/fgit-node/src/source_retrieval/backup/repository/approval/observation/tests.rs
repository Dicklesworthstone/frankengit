use super::super::super::profile::Profile;
use super::*;
use fgit_crypto::DsseEd25519SigningKey;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

// Public RFC 8032 sample material, never a deployed signing secret.
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const SAMPLE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const NOW: i64 = 1_893_456_000_000;
const PIN: [u8; 32] = [0x5a; 32];
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    clock: Arc<AtomicI64>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-backup-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("public.pem"), PUBLIC_PEM).unwrap();
        Self {
            root,
            clock: Arc::new(AtomicI64::new(NOW)),
        }
    }

    fn options(&self, format: GitHashAlgorithm, floor: u64) -> SelectionTrustOptions {
        let mut flags = SelectionTrustFlags::default();
        let key_path = self.root.join("public.pem");
        let floor = floor.to_string();
        for (flag, value) in [
            ("--trust-key", key_path.to_str().unwrap()),
            ("--tenant-id", "11111111111111111111111111111111"),
            ("--repository-id", "22222222222222222222222222222222"),
            ("--incarnation-id", "33333333333333333333333333333333"),
            ("--object-format", format.as_str()),
            ("--minimum-head-generation", &floor),
        ] {
            flags.set(flag, value).unwrap();
        }
        let mut options = flags.finish().unwrap();
        options.set_test_clock(Arc::clone(&self.clock));
        options
    }

    fn loaded(&self, format: GitHashAlgorithm, floor: u64) -> LoadedApprovalTrust {
        self.options(format, floor)
            .load(Profile::default().start())
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn payload(format: GitHashAlgorithm, generation: u64, bytes: u64) -> String {
    Statement {
        identity: Identity {
            tenant: TenantId::from_bytes([0x11; 16]),
            repository: RepositoryId::from_bytes([0x22; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([0x33; 16]),
            format,
        },
        generation,
        issued_at: "2030-01-01T00:00:00Z".into(),
        issued_millis: NOW,
        expires_at: None,
        expires_millis: None,
        archive_bytes: bytes,
        digest: PIN,
    }
    .canonical()
}

fn encoded(payload: &str) -> Vec<u8> {
    signed(payload, unhex(SAMPLE_SEED).unwrap())
}

fn signed(payload: &str, seed: [u8; 32]) -> Vec<u8> {
    let key = DsseEd25519SigningKey::from_seed(seed);
    let signature = key.sign(PAYLOAD_TYPE, payload.as_bytes()).unwrap();
    let (_, der) = public_key(PUBLIC_PEM.as_bytes()).unwrap();
    format!(
        "{{\"payloadType\":\"{PAYLOAD_TYPE}\",\"payload\":\"{}\",\"signatures\":[{{\"keyid\":\"sha256:{}\",\"sig\":\"{}\"}}]}}\n",
        encode_base64(payload.as_bytes()), hex(&sha256(&der)), encode_base64(&signature),
    ).into_bytes()
}

fn encode_base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for part in bytes.chunks(3) {
        let bits = u32::from(part[0]) << 16
            | u32::from(part.get(1).copied().unwrap_or(0)) << 8
            | u32::from(part.get(2).copied().unwrap_or(0));
        text.push(char::from(DIGITS[(bits >> 18) as usize]));
        text.push(char::from(DIGITS[((bits >> 12) & 63) as usize]));
        text.push(if part.len() > 1 {
            char::from(DIGITS[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        text.push(if part.len() > 2 {
            char::from(DIGITS[(bits & 63) as usize])
        } else {
            '='
        });
    }
    text
}

#[test]
fn both_formats_keep_full_u64_observations_and_exact_existing_recovery_binding() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new();
        let options = fixture.options(format, u64::MAX);
        let loaded = options.load(Profile::default().start()).unwrap();
        let statement = payload(format, u64::MAX, 30);
        let envelope = encoded(&statement);
        let path = fixture.root.join("approval.json");
        fs::write(&path, &envelope).unwrap();
        let observed = loaded.inspect_path(&path).unwrap();
        assert_eq!(observed.generation(), u64::MAX);
        assert_eq!(
            observed.artifact_seal(),
            Seal {
                bytes: 30,
                digest: PIN
            }
        );
        assert_eq!(observed.statement_json(), statement);
        assert_eq!(observed.envelope_bytes(), envelope);
        assert_eq!(observed.approval_digest(), sha256(&envelope));
        assert_eq!(observed.statement_digest(), sha256(statement.as_bytes()));
        assert_eq!(observed.trusted_key_id(), loaded.trusted_key_id);

        let conventional = ApprovalOptions {
            approval: path,
            trust_key: options.trust_key_path().into(),
            policy: options.policy,
            clock: Some(Arc::clone(&fixture.clock)),
        }
        .authenticate(PIN, 30, Profile::default().start())
        .unwrap();
        let selected = observed.into_verified(PIN, 30).unwrap();
        assert_eq!(selected.binding_digest(), conventional.binding_digest());
        assert_eq!(selected.receipt_json(), conventional.receipt_json());
    }
}

#[test]
fn full_width_ranking_does_not_discard_below_floor_or_oversized_observations() {
    let fixture = Fixture::new();
    let format = GitHashAlgorithm::Sha256;
    let loaded = fixture.loaded(format, 9_007_199_254_740_993);
    let lower = encoded(&payload(format, 9_007_199_254_740_992, 30));
    let higher = encoded(&payload(format, 9_007_199_254_740_993, 30));
    let observed_lower = loaded.inspect_bytes(&lower).unwrap();
    let observed_higher = loaded.inspect_bytes(&higher).unwrap();
    assert!(observed_lower.generation() < observed_higher.generation());
    assert!(!observed_lower.same_statement(&observed_higher));
    assert!(
        observed_lower
            .into_verified(PIN, 30)
            .unwrap_err()
            .contains("generation floor")
    );
    observed_higher.into_verified(PIN, 30).unwrap();

    let large = encoded(&payload(format, u64::MAX, MAX_SIGNED_ARCHIVE_BYTES));
    let observed = loaded.inspect_bytes(&large).unwrap();
    assert_eq!(observed.artifact_seal().bytes, MAX_SIGNED_ARCHIVE_BYTES);
    assert!(
        observed
            .into_verified(PIN, MAX_SIGNED_ARCHIVE_BYTES - 1)
            .unwrap_err()
            .contains("permitted range")
    );
    loaded
        .inspect_bytes(&large)
        .unwrap()
        .into_verified(PIN, MAX_SIGNED_ARCHIVE_BYTES)
        .unwrap();
    let outside = encoded(&payload(format, u64::MAX, MAX_SIGNED_ARCHIVE_BYTES + 1));
    assert!(
        loaded
            .inspect_bytes(&outside)
            .unwrap_err()
            .contains("permitted range")
    );
}

#[test]
fn expired_and_future_observations_authenticate_but_cannot_become_eligible_approvals() {
    let fixture = Fixture::new();
    let format = GitHashAlgorithm::Sha1;
    let loaded = fixture.loaded(format, 1);
    let expired = encoded(&payload(format, 20, 30).replace(
        "\"expires_at\":null",
        "\"expires_at\":\"2030-01-01T00:00:01Z\"",
    ));
    let observed = loaded.inspect_bytes(&expired).unwrap();
    fixture.clock.store(NOW + 1000, Ordering::SeqCst);
    assert!(
        observed
            .into_verified(PIN, 30)
            .unwrap_err()
            .contains("expired")
    );
    let still_observed = loaded.inspect_bytes(&expired).unwrap();
    assert_eq!(still_observed.generation(), 20);
    fixture.clock.store(NOW, Ordering::SeqCst);
    still_observed.into_verified(PIN, 30).unwrap();

    let future =
        encoded(&payload(format, 21, 30).replace("2030-01-01T00:00:00Z", "2030-01-01T00:05:01Z"));
    let observed = loaded.inspect_bytes(&future).unwrap();
    assert!(
        observed
            .into_verified(PIN, 30)
            .unwrap_err()
            .contains("future")
    );
    fixture.clock.store(NOW + 1000, Ordering::SeqCst);
    loaded
        .inspect_bytes(&future)
        .unwrap()
        .into_verified(PIN, 30)
        .unwrap();
}

#[test]
fn original_envelopes_are_owned_and_trusted_key_is_loaded_once() {
    let fixture = Fixture::new();
    let format = GitHashAlgorithm::Sha256;
    let options = fixture.options(format, 1);
    let loaded = options.load(Profile::default().start()).unwrap();
    fs::remove_file(options.trust_key_path()).unwrap();
    let canonical = payload(format, 7, 30);
    let mut envelope = encoded(&canonical);
    let path = fixture.root.join("approval.json");
    fs::write(&path, &envelope).unwrap();
    let original = loaded.inspect_path(&path).unwrap();
    fs::write(&path, b"changed after inspection").unwrap();
    assert_eq!(original.envelope_bytes(), envelope);
    envelope.push(b'\n');
    let equivalent = loaded.inspect_bytes(&envelope).unwrap();
    assert!(original.same_statement(&equivalent));
    assert_eq!(original.statement_digest(), equivalent.statement_digest());
    assert_ne!(original.approval_digest(), equivalent.approval_digest());
    let left = original.into_verified(PIN, 30).unwrap();
    let right = equivalent.into_verified(PIN, 30).unwrap();
    assert_ne!(left.binding_digest(), right.binding_digest());
    assert!(options.load(Profile::default().start()).is_err());
}

#[test]
fn cryptographic_inspection_still_rejects_wrong_key_identity_and_signed_noncanonical_payloads() {
    let fixture = Fixture::new();
    let format = GitHashAlgorithm::Sha256;
    let loaded = fixture.loaded(format, 1);
    let canonical = payload(format, 7, 30);
    assert!(
        loaded
            .inspect_bytes(&signed(&canonical, [0x22; 32]))
            .unwrap_err()
            .contains("signature refused")
    );
    for changed in [
        canonical.replace(
            "11111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        canonical.replace(
            "22222222222222222222222222222222",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        canonical.replace(
            "33333333333333333333333333333333",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        canonical.replace("\"object_format\":\"sha256\"", "\"object_format\":\"sha1\""),
    ] {
        assert!(
            loaded
                .inspect_bytes(&encoded(&changed))
                .unwrap_err()
                .contains("independent policy")
        );
    }
    assert!(
        loaded
            .inspect_bytes(&encoded(&format!(" {canonical}")))
            .unwrap_err()
            .contains("canonical original JSON")
    );
    assert!(
        loaded
            .inspect_bytes(&vec![b'x'; MAX_ENVELOPE_BYTES + 1])
            .is_err()
    );
    loaded
        .inspect_bytes(&encoded(&canonical))
        .unwrap()
        .into_verified(PIN, 30)
        .unwrap();
}

#[test]
fn conversion_preserves_explicit_digest_budget_and_original_deadline_gates() {
    let fixture = Fixture::new();
    let format = GitHashAlgorithm::Sha1;
    let mut loaded = fixture.loaded(format, 1);
    let envelope = encoded(&payload(format, 7, 30));
    assert!(
        loaded
            .inspect_bytes(&envelope)
            .unwrap()
            .into_verified([0; 32], 30)
            .unwrap_err()
            .contains("--expected-sha256")
    );
    for maximum in [0, 29, MAX_SIGNED_ARCHIVE_BYTES + 1] {
        assert!(
            loaded
                .inspect_bytes(&envelope)
                .unwrap()
                .into_verified(PIN, maximum)
                .is_err()
        );
    }
    loaded
        .inspect_bytes(&envelope)
        .unwrap()
        .into_verified(PIN, 30)
        .unwrap();

    // Deterministically install an expired original operation lifetime. There
    // is no deadline argument to inspection/conversion with which to renew it.
    let expired = Profile {
        timeout: Duration::ZERO,
        ..Profile::default()
    }
    .start();
    let mut observed = loaded.inspect_bytes(&envelope).unwrap();
    observed.deadline = expired;
    assert!(
        observed
            .into_verified(PIN, 30)
            .unwrap_err()
            .contains("deadline")
    );
    loaded.deadline = expired;
    assert!(
        loaded
            .inspect_bytes(&envelope)
            .unwrap_err()
            .contains("deadline")
    );
    assert!(
        fixture
            .options(format, 1)
            .load(expired)
            .unwrap_err()
            .contains("deadline")
    );
}

#[test]
fn selection_trust_grammar_requires_each_external_field_without_an_approval_path() {
    let fixture = Fixture::new();
    let fields = [
        (
            "--trust-key",
            fixture.root.join("public.pem").to_str().unwrap().to_owned(),
        ),
        ("--tenant-id", "11111111111111111111111111111111".into()),
        ("--repository-id", "22222222222222222222222222222222".into()),
        (
            "--incarnation-id",
            "33333333333333333333333333333333".into(),
        ),
        ("--object-format", "sha256".into()),
        ("--minimum-head-generation", u64::MAX.to_string()),
    ];
    for omitted in 0..fields.len() {
        let mut flags = SelectionTrustFlags::default();
        for (index, (flag, value)) in fields.iter().enumerate() {
            assert!(SelectionTrustFlags::accepts(flag));
            if index != omitted {
                flags.set(flag, value).unwrap();
            }
        }
        assert!(flags.finish().is_err(), "missing {}", fields[omitted].0);
    }
    let mut flags = SelectionTrustFlags::default();
    for (flag, value) in &fields {
        flags.set(flag, value).unwrap();
    }
    assert!(flags.set("--trust-key", "other.pem").is_err());
    let options = flags.finish().unwrap();
    assert_eq!(options.policy.minimum_generation, u64::MAX);
    assert_eq!(options.trust_key_path(), fixture.root.join("public.pem"));
    assert!(!SelectionTrustFlags::accepts("--approval"));
    assert!(
        SelectionTrustFlags::default()
            .set("--approval", "candidate")
            .is_err()
    );
    assert!(SelectionTrustFlags::default().finish().is_err());
}
