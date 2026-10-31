//! Real source archives and native recovery; adversarial observations use real
//! independent DSSE signatures, never fabricated native verification evidence.

#[path = "witness_tests.rs"]
mod witness_tests;

use super::super::super::hex;
use super::super::attest;
use super::super::attest::tests::Fixture;
use super::engine::{Checkpoint, execute_with_checkpoints, highest};
use super::*;
use fgit_crypto::{DigestHasher, DsseEd25519SigningKey, Sha256Hasher};
use fgit_types::GitHashAlgorithm;
use std::fs;
use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

const NOW: i64 = 1_893_456_000_000; // 2030-01-01T00:00:00Z

fn approve(fixture: &Fixture) -> PathBuf {
    let options = fixture.options("native");
    attest::execute_in(&options, options.profile.start()).unwrap();
    options.output
}

fn candidate(input: &Path, approval: &Path) -> Candidate {
    Candidate {
        input: input.to_path_buf(),
        approval: approval.to_path_buf(),
    }
}

fn arguments(
    fixture: &Fixture,
    operation: &str,
    name: &str,
    candidates: &[Candidate],
) -> Vec<String> {
    let mut args = vec![
        operation.into(),
        fixture.root.join(name).to_str().unwrap().into(),
        "--trusted-local".into(),
        "--expected-sha256".into(),
        hex(&fixture.expected),
        if operation == "recover" {
            "--destination-instance"
        } else {
            "--verification-instance"
        }
        .into(),
        "992".into(),
        "--trust-key".into(),
        fixture.public_key.to_str().unwrap().into(),
        "--tenant-id".into(),
        fixture.identity.tenant.to_string(),
        "--repository-id".into(),
        fixture.identity.repository.to_string(),
        "--incarnation-id".into(),
        fixture.identity.incarnation.to_string(),
        "--object-format".into(),
        fixture.identity.format.as_str().into(),
        "--minimum-head-generation".into(),
        fixture.generation.to_string(),
    ];
    for candidate in candidates {
        args.extend([
            "--candidate".into(),
            candidate.input.to_str().unwrap().into(),
            candidate.approval.to_str().unwrap().into(),
        ]);
    }
    args
}

fn options(fixture: &Fixture, operation: &str, name: &str, candidates: &[Candidate]) -> Options {
    let mut options = parse(&arguments(fixture, operation, name, candidates)).unwrap();
    options.trust.set_test_clock(Arc::new(AtomicI64::new(NOW)));
    options
}

#[derive(Clone)]
struct Statement {
    generation: u64,
    bytes: u64,
    digest: [u8; 32],
    tenant: String,
    issued: &'static str,
    expires: Option<&'static str>,
}
impl Statement {
    fn new(fixture: &Fixture) -> Self {
        Self {
            generation: fixture.generation,
            bytes: fs::metadata(&fixture.input).unwrap().len(),
            digest: fixture.expected,
            tenant: fixture.identity.tenant.to_string(),
            issued: "2020-01-01T00:00:00Z",
            expires: None,
        }
    }
}

fn sign(fixture: &Fixture, name: &str, statement: &Statement) -> PathBuf {
    // Public RFC8032 test material, matching the fixture's independently
    // supplied PEM. This signs an external assertion, not native proof.
    let key = DsseEd25519SigningKey::from_seed(
        super::super::restore::digest(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap(),
    );
    let payload_type = "application/vnd.frankengit.repository-backup-approval.v1+json";
    let expiry = statement
        .expires
        .map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""));
    let payload = format!(
        concat!(
            "{{\"type\":\"frankengit-repository-backup-approval-v1\",",
            "\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"incarnation_id\":\"{}\",",
            "\"object_format\":\"{}\",\"head_generation\":\"{}\",\"issued_at\":\"{}\",",
            "\"expires_at\":{},\"artifact\":{{\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
            "\"scope\":\"authority_and_selected_git_objects\"}}"
        ),
        statement.tenant,
        fixture.identity.repository,
        fixture.identity.incarnation,
        fixture.identity.format.as_str(),
        statement.generation,
        statement.issued,
        expiry,
        statement.bytes,
        hex(&statement.digest),
    );
    let signature = key.sign(payload_type, payload.as_bytes()).unwrap();
    let mut der = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".to_vec();
    der.extend_from_slice(key.verifying_key().as_bytes());
    let envelope = format!(
        "{{\"payloadType\":\"{payload_type}\",\"payload\":\"{}\",\"signatures\":[{{\"keyid\":\"sha256:{}\",\"sig\":\"{}\"}}]}}\n",
        base64(payload.as_bytes()),
        hex(&digest(&der)),
        base64(&signature),
    );
    let path = fixture.root.join(format!("{name}.approval"));
    fs::write(&path, envelope).unwrap();
    path
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let bits = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(char::from(DIGITS[(bits >> 18) as usize]));
        encoded.push(char::from(DIGITS[((bits >> 12) & 63) as usize]));
        encoded.push(if chunk.len() > 1 {
            char::from(DIGITS[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(DIGITS[(bits & 63) as usize])
        } else {
            '='
        });
    }
    encoded
}

fn lower(fixture: &Fixture) -> Candidate {
    let mut statement = Statement::new(fixture);
    assert!(statement.generation > 1);
    statement.generation -= 1;
    let approval = sign(fixture, "obsolete", &statement);
    candidate(&fixture.root.join("a-missing-obsolete.fg"), &approval)
}

#[test]
fn selected_native_verify_restore_and_exact_resume_work_after_source_loss_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"native selected recovery\0\xff\n");
        let approval = approve(&fixture);
        let candidates = [candidate(&fixture.input, &approval), lower(&fixture)];
        assert!(!fixture.root.join("source-node").exists());
        assert!(!fixture.root.join("source.git").exists());
        let mut verify = options(&fixture, "verify-selected", "selected-scratch", &candidates);
        verify.profile.transfer.max_archive_bytes = fs::metadata(&fixture.input).unwrap().len();
        verify.profile.transfer.max_objects = 3;
        let receipt = execute_in(&verify, verify.profile.start()).unwrap();
        for expected in [
            "\"type\":\"repository_source_backup_selected_verify\"",
            "\"candidates_authenticated\":2",
            "\"highest_supplied_generation_selected\":true",
            "\"newest_checkpoint_verified\":false",
            "\"object_graph_verified\":true",
            "\"signature_verified\":true",
            "\"scratch_removed\":true",
        ] {
            assert!(receipt.json().contains(expected), "{}", receipt.json());
        }
        assert!(receipt.json().contains(&format!(
            "\"selected_head_generation\":\"{}\"",
            fixture.generation
        )));
        assert!(!verify.destination.exists());
        let mut recover = options(&fixture, "recover", "restored", &candidates);
        let receipt = execute_in(&recover, recover.profile.start()).unwrap();
        assert!(
            receipt
                .json()
                .contains("\"type\":\"repository_source_backup_recover\"")
        );
        assert!(receipt.json().contains("\"reopened_and_verified\":true"));
        assert!(recover.destination.join("authority.fsqlite").is_file());
        recover.resume = true;
        let receipt = execute_in(&recover, recover.profile.start()).unwrap();
        assert!(receipt.json().contains("\"already_published\":true"));
        assert!(receipt.json().contains("\"resume_requested\":true"));

        // The recovered native node can export the same canonical authority
        // body and payloads, independently of the selection report.
        let exported = fixture.root.join("reexport.fg");
        super::super::run(
            &[
                "export".into(),
                recover.destination.to_str().unwrap().into(),
                exported.to_str().unwrap().into(),
                fixture.identity.tenant.to_string(),
                fixture.identity.repository.to_string(),
                "--trusted-local".into(),
                "--object-format".into(),
                format.as_str().into(),
            ],
            &mut Vec::new(),
        )
        .unwrap();
        let original_bytes = fs::read(&fixture.input).unwrap();
        let restored_bytes = fs::read(&exported).unwrap();
        let original = super::super::archive::decode(&original_bytes, || Ok(())).unwrap();
        let restored = super::super::archive::decode(&restored_bytes, || Ok(())).unwrap();
        assert_eq!(original.identity, restored.identity);
        assert_eq!(
            original.authority.head.as_ref().unwrap().body,
            restored.authority.head.as_ref().unwrap().body
        );
        assert_eq!(original.records.len(), restored.records.len());
        for (before, after) in original.records.iter().zip(&restored.records) {
            assert_eq!(before.oid, after.oid);
            assert_eq!(before.kind, after.kind);
            assert_eq!(before.payload, after.payload);
        }
    }
}

#[test]
fn highest_missing_corrupt_or_truncated_archive_never_falls_back_or_tries_an_alias() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"highest artifact is mandatory");
    let approval = approve(&fixture);
    let old = lower(&fixture);
    let original = fs::read(&fixture.input).unwrap();
    for name in ["missing", "corrupt", "truncated"] {
        let path = fixture.root.join(format!("a-{name}-highest.fg"));
        match name {
            "corrupt" => {
                let mut bytes = original.clone();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(&path, bytes).unwrap();
            }
            "truncated" => fs::write(&path, &original[..original.len() - 1]).unwrap(),
            _ => {}
        }
        // The healthy alias has the exact same signed statement. It remains
        // unopened because this first profile has no hidden replica failover.
        let candidates = [
            old.clone(),
            candidate(&fixture.input, &approval),
            candidate(&path, &approval),
        ];
        let refused = options(&fixture, "recover", &format!("refused-{name}"), &candidates);
        let mut native = false;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            native |= stage == Checkpoint::BeforeNative;
            Ok(())
        })
        .unwrap_err();
        assert!(!native, "{error}");
        assert!(!refused.destination.exists());
        if name == "missing" {
            assert!(error.contains("inspect input"), "{error}");
        } else {
            assert!(error.contains("checksum mismatch"), "{error}");
        }
    }
    let valid = options(
        &fixture,
        "verify-selected",
        "valid-twin",
        &[candidate(&fixture.input, &approval), old],
    );
    execute_in(&valid, valid.profile.start()).unwrap();
}

#[test]
fn newer_signed_ineligible_observations_block_a_usable_older_checkpoint_before_payload_io() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        b"checkpoint eligibility follows rank",
    );
    let approval = approve(&fixture);
    let base = Statement::new(&fixture);
    for name in ["expired", "future", "over-budget", "wrong-pin"] {
        let mut statement = base.clone();
        statement.generation += 1;
        match name {
            "expired" => statement.expires = Some("2030-01-01T00:00:00Z"),
            "future" => statement.issued = "2030-01-01T00:10:00Z",
            "over-budget" => statement.bytes += 1,
            _ => statement.digest = [0x42; 32],
        }
        let newer = sign(&fixture, name, &statement);
        let candidates = [
            candidate(&fixture.input, &approval),
            candidate(&fixture.root.join(format!("missing-{name}.fg")), &newer),
        ];
        let mut refused = options(&fixture, "recover", &format!("refused-{name}"), &candidates);
        refused.profile.transfer.max_archive_bytes = base.bytes;
        let mut selected = false;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            selected |= stage == Checkpoint::WinnerSelected;
            assert_ne!(
                stage,
                Checkpoint::BeforeNative,
                "ineligible winner entered native work"
            );
            Ok(())
        })
        .unwrap_err();
        assert!(selected, "selection must precede eligibility: {error}");
        assert!(!refused.destination.exists());
        let expected = match name {
            "expired" => "expired",
            "future" => "future",
            "over-budget" => "archive",
            _ => "digest",
        };
        assert!(error.contains(expected), "{name}: {error}");
    }
    let valid = options(
        &fixture,
        "verify-selected",
        "eligible-twin",
        &[candidate(&fixture.input, &approval)],
    );
    execute_in(&valid, valid.profile.start()).unwrap();
}

#[test]
fn every_approval_authenticates_before_any_archive_open_and_foreign_lower_observations_refuse() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"authenticate entire supplied set");
    let good = approve(&fixture);
    let invalid = fixture.root.join("invalid.approval");
    fs::write(&invalid, b"not a DSSE approval").unwrap();
    let mut foreign = Statement::new(&fixture);
    foreign.generation -= 1;
    foreign.tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    let foreign = sign(&fixture, "foreign", &foreign);
    for (name, approval) in [("invalid", invalid), ("foreign", foreign)] {
        let candidates = [
            candidate(&fixture.root.join("a-missing-highest.fg"), &good),
            candidate(&fixture.root.join("z-missing-lower.fg"), &approval),
        ];
        let refused = options(&fixture, "recover", name, &candidates);
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |_| {
            panic!("invalid supplied set reached post-authentication checkpoint")
        })
        .unwrap_err();
        assert!(
            !error.contains("inspect input"),
            "payload path was examined first: {error}"
        );
        assert!(!refused.destination.exists());
    }
}

#[test]
fn full_u64_rank_conflicting_highest_statements_and_identical_alias_order_are_exact() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"exact checkpoint ranking");
    let mut a = Statement::new(&fixture);
    a.generation = u64::MAX - 1;
    let lower = sign(&fixture, "u64-lower", &a);
    a.generation = u64::MAX;
    let higher = sign(&fixture, "u64-higher", &a);
    let candidates = [
        candidate(&fixture.input, &lower),
        candidate(&fixture.root.join("z-higher"), &higher),
    ];
    let options = options(&fixture, "verify-selected", "rank", &candidates);
    let trust = options.trust.load(options.profile.start()).unwrap();
    let inspected = [
        trust.inspect_path(&lower).unwrap(),
        trust.inspect_path(&higher).unwrap(),
    ];
    assert_eq!(highest(&inspected).unwrap(), 1);
    let inspected = [
        trust.inspect_path(&higher).unwrap(),
        trust.inspect_path(&lower).unwrap(),
    ];
    assert_eq!(highest(&inspected).unwrap(), 0);
    a.issued = "2021-01-01T00:00:00Z";
    let conflict = sign(&fixture, "u64-conflict", &a);
    let inspected = [
        trust.inspect_path(&higher).unwrap(),
        trust.inspect_path(&conflict).unwrap(),
    ];
    assert!(
        highest(&inspected)
            .unwrap_err()
            .contains("conflicting canonical")
    );
    let inspected = [
        trust.inspect_path(&higher).unwrap(),
        trust.inspect_path(&higher).unwrap(),
    ];
    assert_eq!(highest(&inspected).unwrap(), 0);

    let good = approve(&fixture);
    let alias = fixture.root.join("a-valid-alias.fg");
    fs::copy(&fixture.input, &alias).unwrap();
    let candidates = [candidate(&fixture.input, &good), candidate(&alias, &good)];
    let first =
        super::native_tests::options(&fixture, "verify-selected", "alias-first", &candidates);
    let mut reverse = candidates.clone();
    reverse.reverse();
    let second =
        super::native_tests::options(&fixture, "verify-selected", "alias-second", &reverse);
    assert_eq!(first.candidates, second.candidates);
    let receipt = execute_in(&first, first.profile.start()).unwrap();
    assert!(receipt.json().contains("\"selected_index\":0"));
    assert!(receipt.json().contains("\"same_statement_replicas\":2"));
    assert!(receipt.json().contains("\"replica_failover\":false"));
}

#[test]
fn captured_controls_and_opened_archive_cannot_be_replaced_after_selection() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"captured selection inputs");
    let approval = approve(&fixture);
    let original_approval = fs::read(&approval).unwrap();
    let original_key = fs::read(&fixture.public_key).unwrap();
    let original_archive = fs::read(&fixture.input).unwrap();
    let selected = options(
        &fixture,
        "verify-selected",
        "captured",
        &[candidate(&fixture.input, &approval)],
    );
    let receipt = execute_with_checkpoints(&selected, selected.profile.start(), |stage| {
        if stage == Checkpoint::AllApprovalsAuthenticated {
            fs::write(&approval, b"changed after signature capture").unwrap();
            fs::write(&fixture.public_key, b"changed independent key path").unwrap();
        }
        if stage == Checkpoint::BeforeNative {
            // Path replacement must not replace the one already-open archive.
            fs::rename(&fixture.input, fixture.root.join("retained-open-input.fg")).unwrap();
            fs::write(&fixture.input, b"unrelated replacement").unwrap();
        }
        Ok(())
    })
    .unwrap();
    assert!(receipt.json().contains("\"object_graph_verified\":true"));
    assert!(receipt.json().contains(&hex(&digest(&original_approval))));
    assert!(!selected.destination.exists());
    fs::write(&approval, &original_approval).unwrap();
    fs::write(&fixture.public_key, &original_key).unwrap();
    fs::write(&fixture.input, &original_archive).unwrap();

    let changed = options(
        &fixture,
        "recover",
        "changed-content",
        &[candidate(&fixture.input, &approval)],
    );
    let error = execute_with_checkpoints(&changed, changed.profile.start(), |stage| {
        if stage == Checkpoint::BeforeNative {
            let mut bytes = original_archive.clone();
            *bytes.last_mut().unwrap() ^= 1;
            fs::write(&fixture.input, bytes).unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        error.contains("checksum") || error.contains("commitment") || error.contains("identity"),
        "{error}"
    );
    assert!(!changed.destination.join("authority.fsqlite").exists());
}

#[test]
fn cancellation_original_deadline_and_expiry_gate_native_handoff_without_renewal() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"one recovery lifetime");
    let approval = approve(&fixture);
    for (index, target) in [
        Checkpoint::AllApprovalsAuthenticated,
        Checkpoint::WinnerSelected,
        Checkpoint::BeforeNative,
    ]
    .into_iter()
    .enumerate()
    {
        let refused = options(
            &fixture,
            "recover",
            &format!("cancel-{index}"),
            &[candidate(&fixture.input, &approval)],
        );
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            if stage == target {
                Err("injected caller cancellation".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.contains("caller cancellation"));
        assert!(!refused.destination.exists());
    }
    let mut elapsed = options(
        &fixture,
        "recover",
        "deadline",
        &[candidate(&fixture.input, &approval)],
    );
    elapsed.profile.timeout = Duration::ZERO;
    assert!(
        execute_in(&elapsed, elapsed.profile.start())
            .unwrap_err()
            .contains("deadline")
    );
    assert!(!elapsed.destination.exists());
    let mut statement = Statement::new(&fixture);
    statement.expires = Some("2030-01-01T00:00:01Z");
    let expires = sign(&fixture, "expiring", &statement);
    let mut expired = options(
        &fixture,
        "recover",
        "expired-before-native",
        &[candidate(&fixture.input, &expires)],
    );
    let clock = Arc::new(AtomicI64::new(NOW));
    expired.trust.set_test_clock(Arc::clone(&clock));
    let error = execute_with_checkpoints(&expired, expired.profile.start(), |stage| {
        if stage == Checkpoint::BeforeNative {
            clock.store(NOW + 1000, Ordering::SeqCst);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("expired"), "{error}");
    assert!(!expired.destination.exists());
}

#[test]
fn late_output_failure_preserves_completed_native_restore_and_exact_resume_binding() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        b"selected recovery completion and retry",
    );
    let approval = approve(&fixture);
    let candidates = [candidate(&fixture.input, &approval)];
    let mut recovered = options(&fixture, "recover", "late-restore", &candidates);
    let error = execute_with_checkpoints(&recovered, recovered.profile.start(), |stage| {
        if stage == Checkpoint::NativeCompleted {
            Err("late observer failure".into())
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.contains("native_operation_complete=true"), "{error}");
    assert!(recovered.destination.join("authority.fsqlite").exists());
    recovered.resume = true;
    assert!(
        execute_in(&recovered, recovered.profile.start())
            .unwrap()
            .json()
            .contains("\"already_published\":true")
    );
    let original_approval = fs::read(&approval).unwrap();
    // Same statement/signature but different envelope serialization changes the
    // original signed resume binding, even though selection still authenticates.
    fs::write(
        &approval,
        [b" ".as_slice(), original_approval.as_slice()].concat(),
    )
    .unwrap();
    let error = execute_in(&recovered, recovered.profile.start()).unwrap_err();
    assert!(
        error.contains("intent") || error.contains("binding"),
        "{error}"
    );
    assert!(recovered.destination.join("authority.fsqlite").exists());
    fs::write(&approval, original_approval).unwrap();
    recovered.expected = [0x42; 32];
    let error = execute_in(&recovered, recovered.profile.start()).unwrap_err();
    assert!(
        error.contains("prior attempt may already have published authority"),
        "{error}"
    );
    assert!(recovered.destination.join("authority.fsqlite").exists());

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("closed receipt pipe"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let args = arguments(&fixture, "verify-selected", "late-verify", &candidates);
    let error = run(&args, &mut Broken, None).unwrap_err();
    assert!(error.contains("native_operation_complete=true"), "{error}");
    assert!(!fixture.root.join("late-verify").exists());
}
