//! Real signed native source archives and actual create-only replica publication.
//! The fixed RFC8032 key is public test material; publication never issues a key.

use super::super::super::hex;
use super::super::attest::tests::Fixture;
use super::super::{archive, attest, selection};
use super::*;
use fgit_crypto::{DigestHasher, DsseEd25519SigningKey, Sha256Hasher, git_payload_commitment};
use fgit_schema::json::{self, Value};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

const NOW: i64 = 1_893_456_000_000;

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}

fn destination(fixture: &Fixture, name: &str) -> PathBuf {
    let path = fixture.root.join(name);
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}

fn approve(fixture: &Fixture, name: &str, expires: Option<&str>) -> PathBuf {
    let mut options = fixture.options(name);
    options.declarations.clock = Some(Arc::new(AtomicI64::new(NOW)));
    options.declarations.expires_at = expires.map(str::to_owned);
    attest::execute_in(&options, options.profile.start()).unwrap();
    options.output
}

fn candidate(input: &Path, approval: &Path) -> (PathBuf, PathBuf) {
    (input.to_path_buf(), approval.to_path_buf())
}

fn arguments(
    fixture: &Fixture,
    directory: &Path,
    name: &str,
    candidates: &[(PathBuf, PathBuf)],
    expected: [u8; 32],
    maximum: Option<u64>,
    failover: bool,
) -> Vec<String> {
    let mut args = vec![
        "replicate".into(),
        directory.to_str().unwrap().into(),
        "--verification-root".into(),
        fixture
            .root
            .join(format!("{name}.scratch"))
            .to_str()
            .unwrap()
            .into(),
        "--verification-instance".into(),
        "992".into(),
        "--trusted-local".into(),
        "--expected-sha256".into(),
        hex(&expected),
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
        "--max-archive-bytes".into(),
        "16777216".into(),
        "--max-objects".into(),
        "3".into(),
    ];
    for (input, approval) in candidates {
        args.extend([
            "--candidate".into(),
            input.to_str().unwrap().into(),
            approval.to_str().unwrap().into(),
        ]);
    }
    if let Some(maximum) = maximum {
        args.extend(["--max-read-bytes".into(), maximum.to_string()]);
    }
    if failover {
        args.push("--replica-failover".into());
    }
    args
}

fn options(
    fixture: &Fixture,
    directory: &Path,
    name: &str,
    candidates: &[(PathBuf, PathBuf)],
    expected: [u8; 32],
    maximum: Option<u64>,
    failover: bool,
) -> Options {
    let mut options = parse(&arguments(
        fixture, directory, name, candidates, expected, maximum, failover,
    ))
    .unwrap();
    options
        .selection
        .trust
        .set_test_clock(Arc::new(AtomicI64::new(NOW)));
    options
}

fn paths(directory: &Path, archive: &[u8], approval: &[u8]) -> (PathBuf, PathBuf) {
    (
        directory.join(format!("archive-sha256-{}.fgbackup", hex(&digest(archive)))),
        directory.join(format!(
            "checkpoint-sha256-{}.approval.json",
            hex(&digest(approval))
        )),
    )
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn number(value: &Value, name: &str) -> u64 {
    field(value, name).unsigned().unwrap()
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).text().unwrap()
}

fn parsed(receipt: &Receipt) -> Value {
    json::parse(receipt.json().as_bytes()).unwrap()
}

fn assert_publication(
    value: &Value,
    directory: &Path,
    archive: &[u8],
    approval: &[u8],
    read_bytes: u64,
) {
    let (body, envelope) = paths(directory, archive, approval);
    assert_eq!(text(value, "type"), "repository_backup_replica_published");
    assert_eq!(text(value, "publication_state"), "durable");
    assert_eq!(text(value, "read_budget_scope"), "all_archive_passes");
    assert_eq!(number(value, "payload_bytes_read"), read_bytes);
    assert!(number(value, "payload_read_calls") > 0);
    for name in [
        "archive_readback_verified",
        "body_before_approval",
        "files_and_directory_synced",
    ] {
        assert_eq!(field(value, name), &Value::Bool(true), "{name}");
    }
    assert_eq!(
        text(field(value, "candidate"), "input"),
        body.to_str().unwrap()
    );
    assert_eq!(
        text(field(value, "candidate"), "approval"),
        envelope.to_str().unwrap()
    );
    assert_eq!(fs::read(&body).unwrap(), archive);
    assert_eq!(fs::read(&envelope).unwrap(), approval);
    assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
}

fn inode(path: &Path) -> (u64, u64) {
    let metadata = fs::metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

fn recover(
    fixture: &Fixture,
    name: &str,
    input: &Path,
    approval: &Path,
) -> (PathBuf, selection::Receipt) {
    let output = fixture.root.join(name);
    let args = vec![
        "recover".into(),
        output.to_str().unwrap().into(),
        "--candidate".into(),
        input.to_str().unwrap().into(),
        approval.to_str().unwrap().into(),
        "--destination-instance".into(),
        "993".into(),
        "--trusted-local".into(),
        "--expected-sha256".into(),
        hex(&fixture.expected),
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
    let mut options = selection::parse(&args).unwrap();
    options.trust.set_test_clock(Arc::new(AtomicI64::new(NOW)));
    let receipt = selection::execute_in(&options, options.profile.start()).unwrap();
    (output, receipt)
}

#[test]
fn published_original_approval_recovers_after_every_source_copy_is_lost_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"native replica survives source loss\0\xff");
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        let approval = approve(&fixture, "original", None);
        let original = [b" \n".as_slice(), fs::read(&approval).unwrap().as_slice()].concat();
        fs::write(&approval, &original).unwrap();
        let alias = fixture.root.join("alias.approval");
        fs::write(&alias, [b"\n".as_slice(), original.as_slice()].concat()).unwrap();
        let absent = fixture.root.join("a-unavailable.fg");
        let available = fixture.root.join("z-available.fg");
        fs::rename(&fixture.input, &available).unwrap();
        let directory = destination(&fixture, "replica");
        let options = options(
            &fixture,
            &directory,
            "publish",
            &[candidate(&available, &alias), candidate(&absent, &approval)],
            fixture.expected,
            Some(5 * size),
            true,
        );
        fs::remove_file(&fixture.private_key).unwrap();
        let value = parsed(&execute_in(&options, options.selection.profile.start()).unwrap());
        assert_publication(&value, &directory, &bytes, &original, 5 * size);
        assert_eq!(field(&value, "archive_created"), &Value::Bool(true));
        assert_eq!(field(&value, "approval_created"), &Value::Bool(true));
        let selection = field(&value, "selection");
        assert_eq!(number(selection, "selected_index"), 0);
        assert_eq!(number(selection, "same_statement_replicas"), 2);
        assert_eq!(text(selection, "approval_sha256"), hex(&digest(&original)));
        let (body, published_approval) = paths(&directory, &bytes, &original);
        fs::remove_file(available).unwrap();
        fs::remove_file(approval).unwrap();
        fs::remove_file(alias).unwrap();
        assert!(!fixture.root.join("source-node").exists());
        assert!(!fixture.root.join("source.git").exists());

        let (restored, receipt) = recover(&fixture, "recovered", &body, &published_approval);
        let value = json::parse(receipt.json().as_bytes()).unwrap();
        assert_eq!(
            field(field(&value, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
        assert_eq!(
            text(field(&value, "selection"), "approval_sha256"),
            hex(&digest(&original))
        );
        assert!(restored.join("authority.fsqlite").is_file());
        assert_eq!(fs::read(published_approval).unwrap(), original);
    }
}

#[test]
fn fresh_retry_and_failed_copy_reads_share_exact_finite_budget_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"exact source and destination read budgets");
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        let approval = approve(&fixture, "original", None);
        let envelope = fs::read(&approval).unwrap();
        let bad = fixture.root.join("a-damaged.fg");
        let healthy = fixture.root.join("z-healthy.fg");
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&bad, changed).unwrap();
        fs::write(&healthy, &bytes).unwrap();
        for failed_first in [false, true] {
            let directory = destination(&fixture, &format!("destination-{failed_first}"));
            let candidates = if failed_first {
                vec![candidate(&healthy, &approval), candidate(&bad, &approval)]
            } else {
                vec![candidate(&healthy, &approval)]
            };
            let needed = (5 + u64::from(failed_first)) * size;
            let refused = options(
                &fixture,
                &directory,
                "short",
                &candidates,
                fixture.expected,
                Some(needed - 1),
                failed_first,
            );
            let mut total = 0;
            let error =
                execute_with_checkpoints(&refused, refused.selection.profile.start(), |stage| {
                    if let Checkpoint::PayloadRead { total: bytes, .. } = stage {
                        total = bytes;
                    }
                    assert_ne!(stage, Checkpoint::ArchiveStaged);
                    assert_ne!(stage, Checkpoint::ArchiveVisible);
                    assert_ne!(stage, Checkpoint::ApprovalVisible);
                    Ok(())
                })
                .unwrap_err();
            assert!(
                error.contains("budget") || error.contains("allowance"),
                "{error}"
            );
            assert_eq!(total, (3 + u64::from(failed_first)) * size);
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
            let complete = options(
                &fixture,
                &directory,
                "exact",
                &candidates,
                fixture.expected,
                Some(needed),
                failed_first,
            );
            let value = parsed(&execute_in(&complete, complete.selection.profile.start()).unwrap());
            assert_publication(&value, &directory, &bytes, &envelope, needed);
            let (body, signature) = paths(&directory, &bytes, &envelope);
            let before = (inode(&body), inode(&signature));

            let retry_candidates = [candidate(&healthy, &approval)];
            let short_retry = options(
                &fixture,
                &directory,
                "short-retry",
                &retry_candidates,
                fixture.expected,
                Some(4 * size - 1),
                false,
            );
            let mut retry_reads = 0;
            let error = execute_with_checkpoints(
                &short_retry,
                short_retry.selection.profile.start(),
                |stage| {
                    if let Checkpoint::PayloadRead { total, .. } = stage {
                        retry_reads = total;
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(
                error.contains("budget") || error.contains("allowance"),
                "{error}"
            );
            assert_eq!(retry_reads, 3 * size);
            assert_eq!((inode(&body), inode(&signature)), before);
            let retry = options(
                &fixture,
                &directory,
                "exact-retry",
                &retry_candidates,
                fixture.expected,
                Some(4 * size),
                false,
            );
            let value = parsed(&execute_in(&retry, retry.selection.profile.start()).unwrap());
            assert_publication(&value, &directory, &bytes, &envelope, 4 * size);
            assert_eq!(field(&value, "archive_created"), &Value::Bool(false));
            assert_eq!(field(&value, "approval_created"), &Value::Bool(false));
            assert_eq!((inode(&body), inode(&signature)), before);
        }
    }
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let bits = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(DIGITS[(bits >> 18) as usize]));
        output.push(char::from(DIGITS[((bits >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(DIGITS[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(DIGITS[(bits & 63) as usize])
        } else {
            '='
        });
    }
    output
}

fn external_approval(fixture: &Fixture, name: &str, bytes: &[u8]) -> PathBuf {
    let key = DsseEd25519SigningKey::from_seed(
        super::super::restore::digest(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap(),
    );
    let payload_type = "application/vnd.frankengit.repository-backup-approval.v1+json";
    let payload = format!(
        concat!(
            "{{\"type\":\"frankengit-repository-backup-approval-v1\",",
            "\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"incarnation_id\":\"{}\",",
            "\"object_format\":\"{}\",\"head_generation\":\"{}\",",
            "\"issued_at\":\"2020-01-01T00:00:00Z\",\"expires_at\":null,",
            "\"artifact\":{{\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
            "\"scope\":\"authority_and_selected_git_objects\"}}"
        ),
        fixture.identity.tenant,
        fixture.identity.repository,
        fixture.identity.incarnation,
        fixture.identity.format.as_str(),
        fixture.generation,
        bytes.len(),
        hex(&digest(bytes)),
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

#[test]
fn damaged_sources_wrong_keys_and_invalid_signatures_refuse_before_destination_effects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"only independently approved native bytes publish");
        let bytes = fs::read(&fixture.input).unwrap();
        let approval = approve(&fixture, "original", None);
        let envelope = fs::read(&approval).unwrap();
        let public = fs::read(&fixture.public_key).unwrap();
        let directory = destination(&fixture, "never-written");
        for case in ["changed", "truncated", "wrong-key", "signature"] {
            fs::write(&fixture.input, &bytes).unwrap();
            fs::write(&approval, &envelope).unwrap();
            fs::write(&fixture.public_key, &public).unwrap();
            match case {
                "changed" => {
                    let mut changed = bytes.clone();
                    *changed.last_mut().unwrap() ^= 1;
                    fs::write(&fixture.input, changed).unwrap();
                }
                "truncated" => fs::write(&fixture.input, &bytes[..bytes.len() - 1]).unwrap(),
                "wrong-key" => {
                    let key = DsseEd25519SigningKey::from_seed([0x55; 32]);
                    let mut der = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".to_vec();
                    der.extend_from_slice(key.verifying_key().as_bytes());
                    fs::write(
                        &fixture.public_key,
                        format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                            base64(&der)
                        ),
                    )
                    .unwrap();
                }
                "signature" => {
                    let mut changed = envelope.clone();
                    let marker = b"\"sig\":\"";
                    let index = changed
                        .windows(marker.len())
                        .position(|part| part == marker)
                        .unwrap()
                        + marker.len();
                    changed[index] = if changed[index] == b'A' { b'B' } else { b'A' };
                    fs::write(&approval, changed).unwrap();
                }
                _ => unreachable!(),
            }
            let options = options(
                &fixture,
                &directory,
                case,
                &[candidate(&fixture.input, &approval)],
                fixture.expected,
                None,
                false,
            );
            let error =
                execute_with_checkpoints(&options, options.selection.profile.start(), |stage| {
                    assert_ne!(stage, Checkpoint::DestinationChecked);
                    assert_ne!(stage, Checkpoint::ArchiveStaged);
                    assert_ne!(stage, Checkpoint::ArchiveVisible);
                    assert_ne!(stage, Checkpoint::ApprovalVisible);
                    Ok(())
                })
                .unwrap_err();
            assert!(!error.is_empty());
            assert_eq!(
                fs::read_dir(&directory).unwrap().count(),
                0,
                "{case}: {error}"
            );
        }
    }
}

#[test]
fn a_valid_signature_and_whole_file_pin_do_not_admit_an_incomplete_native_inventory() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"native inventory is independently required");
        let bytes = fs::read(&fixture.input).unwrap();
        let decoded = archive::decode(&bytes, || Ok(())).unwrap();
        let authority = fgit_authority_fsqlite::export_bundle(&decoded.authority).unwrap();
        let mut encoder =
            archive::Encoder::new(decoded.identity, &authority, decoded.records.len() - 1).unwrap();
        for record in decoded.records.iter().skip(1) {
            let commitment =
                git_payload_commitment(record.kind, record.payload, CANONICAL_CODEC_VERSION);
            let mut original = [0; 32];
            original.copy_from_slice(commitment.digest().as_bytes());
            encoder
                .object(record.oid, record.kind, record.payload, &original)
                .unwrap();
        }
        let incomplete = encoder.finish().unwrap();
        // Real canonical decoding still succeeds; one selected object is absent.
        assert_eq!(
            archive::decode(&incomplete, || Ok(()))
                .unwrap()
                .records
                .len(),
            decoded.records.len() - 1
        );
        let input = fixture.root.join("incomplete.fg");
        fs::write(&input, &incomplete).unwrap();
        let approval = external_approval(&fixture, "incomplete", &incomplete);
        let directory = destination(&fixture, "never-published");
        let options = options(
            &fixture,
            &directory,
            "incomplete",
            &[candidate(&input, &approval)],
            digest(&incomplete),
            None,
            false,
        );
        let deadline = options.selection.profile.start();
        options
            .selection
            .trust
            .load(deadline)
            .unwrap()
            .inspect_path(&approval)
            .unwrap()
            .into_verified(
                digest(&incomplete),
                options.selection.profile.transfer.max_archive_bytes,
            )
            .unwrap();
        let mut native = false;
        let error = execute_with_checkpoints(&options, deadline, |stage| {
            native |= stage == Checkpoint::BeforeNative;
            assert_ne!(stage, Checkpoint::NativeCompleted);
            assert_ne!(stage, Checkpoint::DestinationChecked);
            assert_ne!(stage, Checkpoint::ArchiveStaged);
            assert_ne!(stage, Checkpoint::ApprovalVisible);
            Ok(())
        })
        .unwrap_err();
        assert!(native, "{error}");
        assert!(error.contains("inventory does not equal"), "{error}");
        assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
        assert!(
            !options
                .selection
                .destination
                .join("authority.fsqlite")
                .exists()
        );
    }
}

#[test]
fn corrupt_existing_body_or_approval_is_never_overwritten_by_an_exact_name() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"immutable names refuse conflicting bytes",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = approve(&fixture, "original", None);
    let envelope = fs::read(&approval).unwrap();
    for case in ["body", "short-body", "approval"] {
        let directory = destination(&fixture, case);
        let options = options(
            &fixture,
            &directory,
            case,
            &[candidate(&fixture.input, &approval)],
            fixture.expected,
            Some(5 * size),
            false,
        );
        execute_in(&options, options.selection.profile.start()).unwrap();
        let (body, signature) = paths(&directory, &bytes, &envelope);
        let before = (inode(&body), inode(&signature));
        match case {
            "body" => {
                let mut changed = bytes.clone();
                *changed.last_mut().unwrap() ^= 1;
                fs::write(&body, changed).unwrap();
            }
            "short-body" => fs::write(&body, &bytes[..bytes.len() - 1]).unwrap(),
            "approval" => fs::write(&signature, b"another writer's different envelope").unwrap(),
            _ => unreachable!(),
        }
        let preserved_body = fs::read(&body).unwrap();
        let preserved_approval = fs::read(&signature).unwrap();
        let error = execute_in(&options, options.selection.profile.start()).unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(fs::read(&body).unwrap(), preserved_body, "{case}: {error}");
        assert_eq!(
            fs::read(&signature).unwrap(),
            preserved_approval,
            "{case}: {error}"
        );
        assert_eq!((inode(&body), inode(&signature)), before);
        assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
    }
}

#[test]
fn body_durability_does_not_publish_approval_after_cancellation_or_expiry() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"body durable before original approval",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    for case in ["cancel", "expire"] {
        let approval = approve(
            &fixture,
            case,
            (case == "expire").then_some("2030-01-01T00:00:01Z"),
        );
        let envelope = fs::read(&approval).unwrap();
        let directory = destination(&fixture, case);
        let mut options = options(
            &fixture,
            &directory,
            case,
            &[candidate(&fixture.input, &approval)],
            fixture.expected,
            Some(5 * size),
            false,
        );
        let clock = Arc::new(AtomicI64::new(NOW));
        options.selection.trust.set_test_clock(clock.clone());
        let (body, signature) = paths(&directory, &bytes, &envelope);
        let mut boundary = false;
        let error =
            execute_with_checkpoints(&options, options.selection.profile.start(), |stage| {
                assert_ne!(stage, Checkpoint::ApprovalVisible);
                assert_ne!(stage, Checkpoint::Completed);
                if stage == Checkpoint::ArchiveDurable {
                    assert_eq!(fs::read(&body).unwrap(), bytes);
                    assert!(!signature.exists());
                    boundary = true;
                    if case == "cancel" {
                        return Err("cancelled after body durability".into());
                    }
                    clock.store(NOW + 1_001, Ordering::SeqCst);
                }
                Ok(())
            })
            .unwrap_err();
        assert!(boundary, "{case}: {error}");
        assert!(
            error.contains(if case == "cancel" {
                "cancelled"
            } else {
                "expir"
            }),
            "{error}"
        );
        assert_eq!(fs::read(&body).unwrap(), bytes);
        assert!(!signature.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        if case == "cancel" {
            let before = inode(&body);
            let retry = self::options(
                &fixture,
                &directory,
                "resume-after-cancel",
                &[candidate(&fixture.input, &approval)],
                fixture.expected,
                Some(4 * size),
                false,
            );
            let value = parsed(&execute_in(&retry, retry.selection.profile.start()).unwrap());
            assert_publication(&value, &directory, &bytes, &envelope, 4 * size);
            assert_eq!(field(&value, "archive_created"), &Value::Bool(false));
            assert_eq!(field(&value, "approval_created"), &Value::Bool(true));
            assert_eq!(inode(&body), before);
        }
    }
}

#[test]
fn interleaved_exact_publishers_preserve_the_winners_body_and_approval_inodes() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"two publishers one immutable candidate",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = approve(&fixture, "original", None);
    let envelope = fs::read(&approval).unwrap();
    let directory = destination(&fixture, "shared-replica");
    let candidates = [candidate(&fixture.input, &approval)];
    let first = options(
        &fixture,
        &directory,
        "first",
        &candidates,
        fixture.expected,
        Some(5 * size),
        false,
    );
    let second = options(
        &fixture,
        &directory,
        "second",
        &candidates,
        fixture.expected,
        Some(5 * size),
        false,
    );
    let (body, signature) = paths(&directory, &bytes, &envelope);
    let mut winner = None;
    let mut winner_inodes = None;
    let receipt = execute_with_checkpoints(&first, first.selection.profile.start(), |stage| {
        if stage == Checkpoint::ArchiveStaged {
            assert!(winner.is_none());
            assert!(!body.exists());
            assert!(!signature.exists());
            // The first real invocation is paused with its private bytes
            // staged. A complete second invocation wins both create-only
            // names before the first attempts to publish either one.
            winner = Some(parsed(
                &execute_in(&second, second.selection.profile.start()).unwrap(),
            ));
            winner_inodes = Some((inode(&body), inode(&signature)));
        }
        Ok(())
    })
    .unwrap();
    let first = parsed(&receipt);
    let second = winner.expect("exact competitor ran at the staged boundary");
    assert_publication(&first, &directory, &bytes, &envelope, 5 * size);
    assert_publication(&second, &directory, &bytes, &envelope, 5 * size);
    assert_eq!(field(&first, "archive_created"), &Value::Bool(false));
    assert_eq!(field(&first, "approval_created"), &Value::Bool(false));
    assert_eq!(field(&second, "archive_created"), &Value::Bool(true));
    assert_eq!(field(&second, "approval_created"), &Value::Bool(true));
    assert_eq!(
        (inode(&body), inode(&signature)),
        winner_inodes.unwrap(),
        "an exact loser must retain the winner's actual files"
    );
}

#[test]
fn late_callback_failure_preserves_the_complete_candidate_and_exact_receipt() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"known durability survives observer failure",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = approve(&fixture, "original", None);
    let envelope = fs::read(&approval).unwrap();
    let directory = destination(&fixture, "replica");
    let options = options(
        &fixture,
        &directory,
        "late",
        &[candidate(&fixture.input, &approval)],
        fixture.expected,
        Some(5 * size),
        false,
    );
    let mut delivered = false;
    let error = execute_with_checkpoints(&options, options.selection.profile.start(), |stage| {
        if stage == Checkpoint::Completed {
            delivered = true;
            return Err("injected observer failure after durable approval".into());
        }
        Ok(())
    })
    .unwrap_err();
    assert!(delivered, "{error}");
    assert!(error.contains("injected observer failure"), "{error}");
    assert!(error.contains("publication complete=true"), "{error}");
    assert!(error.contains("publication_state=durable"), "{error}");
    let (_, completed) = error
        .split_once("completed_result=")
        .expect("known receipt is preserved");
    let completed = json::parse(completed.as_bytes()).unwrap();
    assert_publication(&completed, &directory, &bytes, &envelope, 5 * size);
    let (body, signature) = paths(&directory, &bytes, &envelope);
    fs::remove_file(&fixture.input).unwrap();
    fs::remove_file(approval).unwrap();
    fs::remove_file(&fixture.private_key).unwrap();
    let (recovered, receipt) = recover(&fixture, "late-recovery", &body, &signature);
    assert!(recovered.join("authority.fsqlite").is_file());
    assert!(receipt.json().contains("\"reopened_and_verified\":true"));
}

#[test]
fn replacing_control_files_after_authentication_cannot_replace_the_captured_approval() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"captured original envelope and trust",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = approve(&fixture, "original", None);
    let envelope = fs::read(&approval).unwrap();
    let directory = destination(&fixture, "replica");
    let options = options(
        &fixture,
        &directory,
        "captured",
        &[candidate(&fixture.input, &approval)],
        fixture.expected,
        Some(5 * size),
        false,
    );
    let mut changed = false;
    let receipt = execute_with_checkpoints(&options, options.selection.profile.start(), |stage| {
        if stage == Checkpoint::AllApprovalsAuthenticated {
            fs::write(&approval, b"untrusted replacement after authentication").unwrap();
            fs::write(&fixture.public_key, b"changed public control file").unwrap();
            changed = true;
        }
        Ok(())
    })
    .unwrap();
    assert!(changed);
    let value = parsed(&receipt);
    assert_publication(&value, &directory, &bytes, &envelope, 5 * size);
    assert_eq!(
        text(field(&value, "selection"), "approval_sha256"),
        hex(&digest(&envelope))
    );
    assert_eq!(
        fs::read(&approval).unwrap(),
        b"untrusted replacement after authentication"
    );
    assert_eq!(
        fs::read(&fixture.public_key).unwrap(),
        b"changed public control file"
    );
}
