//! Real source archives, real DSSE approval, and actual native preflight. The
//! damaged-copy cases have no complete surviving source after fixture setup.

use super::super::super::hex;
use super::super::archive::stream::Seal;
use super::super::attest::tests::Fixture;
use super::super::{archive, attest};
use super::catalog::{CHUNK_BYTES, Catalog, digest};
use super::engine::execute_with_checkpoints;
use super::io::Checkpoint;
use super::*;
use fgit_crypto::{DsseEd25519SigningKey, git_payload_commitment};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm};
use std::fs;
use std::io::{self as stdio, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

fn approve(fixture: &Fixture, name: &str) -> PathBuf {
    let options = fixture.options(name);
    attest::execute_in(&options, options.profile.start()).unwrap();
    options.output
}

fn arguments(
    fixture: &Fixture,
    operation: &str,
    name: &str,
    input: &Path,
    approval: &Path,
    replicas: &[PathBuf],
) -> Vec<String> {
    let mut args = vec![
        operation.into(),
        input.to_str().unwrap().into(),
        fixture
            .root
            .join(format!("{name}.out"))
            .to_str()
            .unwrap()
            .into(),
        "--trusted-local".into(),
        "--verification-root".into(),
        fixture
            .root
            .join(format!("{name}.scratch"))
            .to_str()
            .unwrap()
            .into(),
        "--verification-instance".into(),
        "992".into(),
        "--expected-sha256".into(),
        hex(&fixture.expected),
        "--approval".into(),
        approval.to_str().unwrap().into(),
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
    for replica in replicas {
        args.extend(["--replica".into(), replica.to_str().unwrap().into()]);
    }
    args
}

fn options(
    fixture: &Fixture,
    operation: &str,
    name: &str,
    input: &Path,
    approval: &Path,
    replicas: &[PathBuf],
) -> Options {
    parse(&arguments(
        fixture, operation, name, input, approval, replicas,
    ))
    .unwrap()
}

fn make_catalog(fixture: &Fixture, approval: &Path, name: &str) -> PathBuf {
    let options = options(fixture, "catalog", name, &fixture.input, approval, &[]);
    execute_in(&options, options.profile.start()).unwrap();
    options.output
}

fn no_stages(fixture: &Fixture) {
    assert!(!fs::read_dir(&fixture.root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fg-backup-approval-")
    }));
}

#[test]
fn complementary_damage_recovers_native_multichunk_archives_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let payload: Vec<u8> = (0..(2 * CHUNK_BYTES as usize + 137))
            .map(|index| ((index * 73 + 19) % 251) as u8)
            .collect();
        let fixture = Fixture::new(format, &payload);
        let original = fs::read(&fixture.input).unwrap();
        let size = original.len() as u64;
        assert!(size > 2 * CHUNK_BYTES && size < 3 * CHUNK_BYTES);
        let approval = approve(&fixture, "original");
        let approval_bytes = fs::read(&approval).unwrap();
        let mut catalog_options = options(
            &fixture,
            "catalog",
            "catalog",
            &fixture.input,
            &approval,
            &[],
        );
        catalog_options.max_read_bytes = 4 * size;
        catalog_options.profile.transfer.max_archive_bytes = size;
        catalog_options.profile.transfer.max_objects = 3;
        let receipt = execute_in(&catalog_options, catalog_options.profile.start()).unwrap();
        assert!(
            receipt
                .json()
                .contains(&format!("\"payload_bytes_read\":{}", 4 * size)),
            "{}",
            receipt.json()
        );
        let catalog_path = catalog_options.output;
        let catalog_bytes = fs::read(&catalog_path).unwrap();
        assert_eq!(&catalog_bytes[..8], b"FGCHNK01");
        assert_eq!(&catalog_bytes[8..16], &size.to_be_bytes());
        assert_eq!(&catalog_bytes[16..48], &fixture.expected);
        assert_eq!(&catalog_bytes[48..56], &[0, 64, 0, 0, 0, 0, 0, 3]);
        for (index, chunk) in original.chunks(CHUNK_BYTES as usize).enumerate() {
            assert_eq!(
                &catalog_bytes[56 + index * 32..88 + index * 32],
                &digest(chunk)
            );
        }
        assert_eq!(
            &catalog_bytes[catalog_bytes.len() - 32..],
            &digest(&catalog_bytes[..catalog_bytes.len() - 32])
        );
        let first = fixture.root.join("a-damaged.fg");
        let second = fixture.root.join("b-damaged.fg");
        let mut first_bytes = original.clone();
        first_bytes[17] ^= 1;
        let mut second_bytes = original.clone();
        second_bytes[CHUNK_BYTES as usize + 29] ^= 1;
        fs::write(&first, &first_bytes).unwrap();
        fs::write(&second, &second_bytes).unwrap();
        fs::set_permissions(&first, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(digest(&first_bytes), fixture.expected);
        assert_ne!(digest(&second_bytes), fixture.expected);
        fs::remove_file(&fixture.input).unwrap();
        assert!(!fixture.root.join("source-node").exists());
        assert!(!fixture.root.join("source.git").exists());

        let mut too_small = options(
            &fixture,
            "reconstruct",
            "read-budget-refusal",
            &catalog_path,
            &approval,
            &[second.clone(), first.clone()],
        );
        too_small.max_read_bytes = 4 * size + CHUNK_BYTES - 1;
        let error = execute_in(&too_small, too_small.profile.start()).unwrap_err();
        assert!(error.contains("payload-read allowance"), "{error}");
        assert!(!too_small.output.exists());
        assert!(!too_small.scratch.exists());
        no_stages(&fixture);

        let mut repair = options(
            &fixture,
            "reconstruct",
            "recovered",
            &catalog_path,
            &approval,
            &[second.clone(), first.clone()],
        );
        repair.max_read_bytes = 4 * size + CHUNK_BYTES;
        repair.profile.transfer.max_archive_bytes = size;
        repair.profile.transfer.max_objects = 3;
        repair.profile.transfer.max_blob_bytes = payload.len() as u64;
        let receipt = execute_in(&repair, repair.profile.start()).unwrap();
        assert_eq!(fs::read(&repair.output).unwrap(), original);
        for field in [
            "\"native_content_verified\":true",
            "\"object_graph_verified\":true",
            "\"publication_state\":\"durable\"",
            "\"new_signature_created\":false",
            "\"catalog_is_authority\":false",
        ] {
            assert!(receipt.json().contains(field), "{}", receipt.json());
        }
        assert!(
            receipt.json().contains(&format!(
                "\"payload_bytes_read\":{}",
                4 * size + CHUNK_BYTES
            )),
            "{}",
            receipt.json()
        );
        assert!(
            receipt
                .json()
                .contains("\"chunks_used\":2,\"chunks_rejected\":1")
        );
        assert!(
            receipt
                .json()
                .contains("\"chunks_used\":1,\"chunks_rejected\":0")
        );
        assert_eq!(fs::read(&first).unwrap(), first_bytes);
        assert_eq!(fs::read(&second).unwrap(), second_bytes);
        assert_eq!(fs::read(&approval).unwrap(), approval_bytes);
        assert!(!repair.scratch.exists());
        no_stages(&fixture);

        // A short replica may still contribute its intact complete first
        // range. No full copy is selected, including the recovered output.
        fs::write(&second, &second_bytes[..CHUNK_BYTES as usize]).unwrap();
        let mut short = options(
            &fixture,
            "reconstruct",
            "short-copy",
            &catalog_path,
            &approval,
            &[first.clone(), second.clone()],
        );
        short.max_read_bytes = 4 * size + CHUNK_BYTES;
        let receipt = execute_in(&short, short.profile.start()).unwrap();
        assert_eq!(fs::read(&short.output).unwrap(), original);
        assert!(receipt.json().contains(&format!(
            "\"payload_bytes_read\":{}",
            4 * size + CHUNK_BYTES
        )));
        assert_eq!(fs::metadata(&second).unwrap().len(), CHUNK_BYTES);
        no_stages(&fixture);
    }
}

#[test]
fn changed_source_is_retired_and_only_an_explicit_stable_copy_can_recover() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"stable source descriptor custody",
    );
    let original = fs::read(&fixture.input).unwrap();
    let approval = approve(&fixture, "approved");
    let catalog = make_catalog(&fixture, &approval, "catalog");
    let changed = fixture.root.join("a-changing.fg");
    let stable = fixture.root.join("b-stable.fg");
    fs::write(&changed, &original).unwrap();
    fs::write(&stable, &original).unwrap();
    let repair = options(
        &fixture,
        "reconstruct",
        "changed-copy",
        &catalog,
        &approval,
        &[changed.clone(), stable.clone()],
    );
    let mut replaced = false;
    let receipt = execute_with_checkpoints(&repair, repair.profile.start(), |checkpoint| {
        if !replaced && matches!(checkpoint, Checkpoint::PayloadRead { .. }) {
            let mut corrupt = original.clone();
            corrupt[0] ^= 1;
            fs::write(&changed, corrupt).unwrap();
            replaced = true;
        }
        Ok(())
    })
    .unwrap();
    assert!(replaced);
    assert!(
        receipt
            .json()
            .contains("source identity or content metadata changed")
    );
    assert!(
        receipt
            .json()
            .contains("\"chunks_used\":0,\"chunks_rejected\":1")
    );
    assert_eq!(fs::read(&repair.output).unwrap(), original);
    assert_eq!(fs::read(&stable).unwrap(), original);
    assert_ne!(fs::read(&changed).unwrap(), original);
    no_stages(&fixture);
}

#[test]
fn external_signature_and_exact_chunk_hashes_cannot_bypass_complete_native_graph() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        b"a signed incomplete archive must still refuse",
    );
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
    let missing = encoder.finish().unwrap();
    let expected = digest(&missing);
    let input = fixture.root.join("incomplete.fg");
    fs::write(&input, &missing).unwrap();
    let approval = fixture.root.join("external-approval.dsse");
    // Independently construct an external operator's valid DSSE signature.
    // This intentionally has no native preflight evidence and never calls the
    // attestation issuer's trusted private composition interface.
    let key = DsseEd25519SigningKey::from_seed(
        super::super::restore::digest(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap(),
    );
    let payload_type = "application/vnd.frankengit.repository-backup-approval.v1+json";
    let statement = format!(
        concat!(
            "{{\"type\":\"frankengit-repository-backup-approval-v1\",",
            "\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"incarnation_id\":\"{}\",",
            "\"object_format\":\"{}\",\"head_generation\":\"{}\",\"issued_at\":\"2000-01-01T00:00:00Z\",",
            "\"expires_at\":null,\"artifact\":{{\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
            "\"scope\":\"authority_and_selected_git_objects\"}}"
        ),
        fixture.identity.tenant,
        fixture.identity.repository,
        fixture.identity.incarnation,
        fixture.identity.format.as_str(),
        fixture.generation,
        missing.len(),
        hex(&expected),
    );
    let signature = key.sign(payload_type, statement.as_bytes()).unwrap();
    let mut der = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".to_vec();
    der.extend_from_slice(key.verifying_key().as_bytes());
    let envelope = format!(
        "{{\"payloadType\":\"{payload_type}\",\"payload\":\"{}\",\"signatures\":[{{\"keyid\":\"sha256:{}\",\"sig\":\"{}\"}}]}}\n",
        base64(statement.as_bytes()),
        hex(&digest(&der)),
        base64(&signature),
    );
    fs::write(&approval, envelope).unwrap();
    let mut catalog = Catalog::new(Seal {
        digest: expected,
        bytes: missing.len() as u64,
    })
    .unwrap();
    for chunk in missing.chunks(CHUNK_BYTES as usize) {
        catalog.push(digest(chunk)).unwrap();
    }
    let catalog_path = fixture.root.join("external.catalog");
    fs::write(&catalog_path, catalog.encode().unwrap()).unwrap();
    for (operation, source) in [("catalog", &input), ("reconstruct", &catalog_path)] {
        let replicas = if operation == "reconstruct" {
            vec![input.clone()]
        } else {
            Vec::new()
        };
        let mut refused = options(&fixture, operation, operation, source, &approval, &replicas);
        refused.expected = expected;
        let error = execute_in(&refused, refused.profile.start()).unwrap_err();
        assert!(error.contains("inventory does not equal"), "{error}");
        assert!(!refused.output.exists());
        assert!(
            refused.scratch.exists(),
            "failed native verification retains diagnostic scratch"
        );
        assert!(!refused.scratch.join("authority.fsqlite").exists());
        no_stages(&fixture);
    }
    assert_eq!(fs::read(&input).unwrap(), missing);
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let bits = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        text.push(char::from(DIGITS[(bits >> 18) as usize]));
        text.push(char::from(DIGITS[((bits >> 12) & 63) as usize]));
        text.push(if chunk.len() > 1 {
            char::from(DIGITS[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        text.push(if chunk.len() > 2 {
            char::from(DIGITS[(bits & 63) as usize])
        } else {
            '='
        });
    }
    text
}

#[test]
fn exact_healthy_budget_missing_and_symlink_replicas_and_native_limits_have_permitted_twins() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"healthy original source\0bytes");
    let original = fs::read(&fixture.input).unwrap();
    let size = original.len() as u64;
    let approval = approve(&fixture, "approved");
    let catalog = make_catalog(&fixture, &approval, "catalog");
    let alias = fixture.root.join("a-symlink");
    symlink(&fixture.input, &alias).unwrap();
    let missing = fixture.root.join("b-missing");
    let mut valid = options(
        &fixture,
        "reconstruct",
        "healthy",
        &catalog,
        &approval,
        &[fixture.input.clone(), missing, alias.clone()],
    );
    valid.max_read_bytes = 4 * size;
    let receipt = execute_in(&valid, valid.profile.start()).unwrap();
    assert_eq!(fs::read(&valid.output).unwrap(), original);
    assert!(
        receipt
            .json()
            .contains(&format!("\"payload_bytes_read\":{}", 4 * size))
    );
    assert!(receipt.json().contains("source unavailable"));
    let symlink_only = options(
        &fixture,
        "reconstruct",
        "symlink-only",
        &catalog,
        &approval,
        &[alias],
    );
    assert!(
        execute_in(&symlink_only, symlink_only.profile.start())
            .unwrap_err()
            .contains("no surviving")
    );
    assert!(!symlink_only.output.exists());
    assert!(!symlink_only.scratch.exists());
    for (name, limit) in [("archive", 0), ("objects", 1), ("blob", 2), ("read", 3)] {
        let mut refused = options(
            &fixture,
            "reconstruct",
            name,
            &catalog,
            &approval,
            &[fixture.input.clone()],
        );
        match limit {
            0 => refused.profile.transfer.max_archive_bytes = size - 1,
            1 => refused.profile.transfer.max_objects = 2,
            2 => refused.profile.transfer.max_blob_bytes = 1,
            _ => refused.max_read_bytes = 4 * size - 1,
        }
        assert!(
            execute_in(&refused, refused.profile.start()).is_err(),
            "{name}"
        );
        assert!(!refused.output.exists(), "{name}");
    }
    let duplicate = fixture.root.join("hard-linked-copy");
    fs::hard_link(&fixture.input, &duplicate).unwrap();
    let duplicate_options = options(
        &fixture,
        "reconstruct",
        "duplicate",
        &catalog,
        &approval,
        &[fixture.input.clone(), duplicate.clone()],
    );
    assert!(
        execute_in(&duplicate_options, duplicate_options.profile.start())
            .unwrap_err()
            .contains("distinct underlying")
    );
    assert_eq!(fs::read(&duplicate).unwrap(), original);
    no_stages(&fixture);
}

#[test]
fn malformed_or_forged_catalogs_never_replace_original_signature_and_whole_digest() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        b"original payload for catalog distrust",
    );
    let approval = approve(&fixture, "approved");
    let catalog_path = make_catalog(&fixture, &approval, "catalog");
    let catalog_bytes = fs::read(&catalog_path).unwrap();
    for (name, changed) in [
        ("short", catalog_bytes[..55].to_vec()),
        ("trailing", [catalog_bytes.as_slice(), b"x"].concat()),
        ("count", {
            let mut bytes = catalog_bytes.clone();
            bytes[52..56].copy_from_slice(&u32::MAX.to_be_bytes());
            let end = bytes.len() - 32;
            let trailer = digest(&bytes[..end]);
            bytes[end..].copy_from_slice(&trailer);
            bytes
        }),
        ("digest", {
            let mut bytes = catalog_bytes.clone();
            bytes[16] ^= 1;
            let end = bytes.len() - 32;
            let trailer = digest(&bytes[..end]);
            bytes[end..].copy_from_slice(&trailer);
            bytes
        }),
    ] {
        let input = fixture.root.join(format!("{name}.catalog"));
        fs::write(&input, changed).unwrap();
        let refused = options(
            &fixture,
            "reconstruct",
            name,
            &input,
            &approval,
            &[fixture.input.clone()],
        );
        let error = execute_in(&refused, refused.profile.start()).unwrap_err();
        assert!(error.contains("catalog"), "{error}");
        assert!(!refused.output.exists());
        assert!(!refused.scratch.exists());
    }
    let mut corrupt = fs::read(&fixture.input).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let corrupt_path = fixture.root.join("corrupt.fg");
    fs::write(&corrupt_path, &corrupt).unwrap();
    let missing = options(
        &fixture,
        "reconstruct",
        "missing-chunk",
        &catalog_path,
        &approval,
        &[corrupt_path.clone()],
    );
    assert!(
        execute_in(&missing, missing.profile.start())
            .unwrap_err()
            .contains("no surviving")
    );
    assert!(!missing.output.exists());
    let mut forged = Catalog::new(Seal {
        digest: fixture.expected,
        bytes: corrupt.len() as u64,
    })
    .unwrap();
    for chunk in corrupt.chunks(CHUNK_BYTES as usize) {
        forged.push(digest(chunk)).unwrap();
    }
    let forged_path = fixture.root.join("forged.catalog");
    fs::write(&forged_path, forged.encode().unwrap()).unwrap();
    let refused = options(
        &fixture,
        "reconstruct",
        "forged",
        &forged_path,
        &approval,
        &[corrupt_path.clone()],
    );
    let error = execute_in(&refused, refused.profile.start()).unwrap_err();
    assert!(error.contains("checksum mismatch"), "{error}");
    assert!(!refused.output.exists());
    assert!(!refused.scratch.exists());
    assert_eq!(fs::read(&corrupt_path).unwrap(), corrupt);
    no_stages(&fixture);

    let mut foreign = arguments(
        &fixture,
        "reconstruct",
        "foreign",
        &catalog_path,
        &approval,
        &[fixture.input.clone()],
    );
    let tenant = foreign
        .iter()
        .position(|value| value == "--tenant-id")
        .unwrap()
        + 1;
    foreign[tenant] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    let refused = parse(&foreign).unwrap();
    let error = execute_with_checkpoints(&refused, refused.profile.start(), |_| {
        panic!("foreign approval reached payload I/O")
    })
    .unwrap_err();
    assert!(error.contains("independent policy"), "{error}");
    assert!(!refused.output.exists());
}

#[test]
fn cancellation_expiry_and_postverification_tamper_abort_without_fallback_or_output() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"cancellation and freshness boundaries",
    );
    let approval = approve(&fixture, "approved");
    let catalog = make_catalog(&fixture, &approval, "catalog");
    for (name, target) in [("cancel-read", 0), ("cancel-range", 1), ("late-cancel", 2)] {
        let refused = options(
            &fixture,
            "reconstruct",
            name,
            &catalog,
            &approval,
            &[fixture.input.clone()],
        );
        let mut callbacks = 0;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |checkpoint| {
            let stop = match target {
                0 => matches!(checkpoint, Checkpoint::PayloadRead { .. }),
                1 => matches!(checkpoint, Checkpoint::ChunkAccepted { .. }),
                _ => checkpoint == Checkpoint::BeforePublication,
            };
            if stop {
                callbacks += 1;
                return Err("injected caller cancellation".into());
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("caller cancellation"), "{error}");
        assert_eq!(callbacks, 1);
        assert!(!refused.output.exists());
        assert!(!refused.scratch.exists());
        no_stages(&fixture);
    }
    let mut deadline = options(
        &fixture,
        "reconstruct",
        "deadline",
        &catalog,
        &approval,
        &[fixture.input.clone()],
    );
    deadline.profile.timeout = Duration::ZERO;
    assert!(
        execute_in(&deadline, deadline.profile.start())
            .unwrap_err()
            .contains("deadline")
    );
    assert!(!deadline.output.exists());

    let clock = Arc::new(AtomicI64::new(1_893_456_000_000));
    let mut expiring = fixture.options("expiring");
    expiring.declarations.clock = Some(Arc::clone(&clock));
    expiring.declarations.expires_at = Some("2030-01-01T00:00:01Z".into());
    attest::execute_in(&expiring, expiring.profile.start()).unwrap();
    let mut expired = options(
        &fixture,
        "reconstruct",
        "expiry",
        &catalog,
        &expiring.output,
        &[fixture.input.clone()],
    );
    expired.approval.set_test_clock(Arc::clone(&clock));
    let error = execute_with_checkpoints(&expired, expired.profile.start(), |checkpoint| {
        if checkpoint == Checkpoint::BeforePublication {
            clock.store(1_893_456_001_000, Ordering::SeqCst);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("expired"), "{error}");
    assert!(!expired.output.exists());
    assert!(!expired.scratch.exists());
    no_stages(&fixture);

    let tampered = options(
        &fixture,
        "reconstruct",
        "post-verify-tamper",
        &catalog,
        &approval,
        &[fixture.input.clone()],
    );
    let error = execute_with_checkpoints(&tampered, tampered.profile.start(), |checkpoint| {
        if checkpoint == Checkpoint::AfterVerification {
            let staged = fs::read_dir(&fixture.root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".fg-backup-approval-")
                })
                .unwrap();
            let mut bytes = fs::read(&staged).unwrap();
            bytes[0] ^= 1;
            fs::write(&staged, bytes).unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("changed after readback"), "{error}");
    assert!(!tampered.output.exists());
    assert!(!tampered.scratch.exists());
    no_stages(&fixture);
}

#[test]
fn existing_and_racing_outputs_are_preserved_and_late_receipt_failure_keeps_durable_recovery() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"publication boundaries");
    let original = fs::read(&fixture.input).unwrap();
    let approval = approve(&fixture, "approved");
    let catalog = make_catalog(&fixture, &approval, "catalog");
    for kind in ["file", "directory", "symlink"] {
        let refused = options(
            &fixture,
            "reconstruct",
            kind,
            &catalog,
            &approval,
            &[fixture.input.clone()],
        );
        match kind {
            "file" => fs::write(&refused.output, b"existing output").unwrap(),
            "directory" => fs::create_dir(&refused.output).unwrap(),
            _ => symlink(&fixture.input, &refused.output).unwrap(),
        }
        assert!(execute_in(&refused, refused.profile.start()).is_err());
        assert!(fs::symlink_metadata(&refused.output).is_ok());
        if kind == "file" {
            assert_eq!(fs::read(&refused.output).unwrap(), b"existing output");
        }
        assert!(!refused.scratch.exists());
    }
    let raced = options(
        &fixture,
        "reconstruct",
        "race",
        &catalog,
        &approval,
        &[fixture.input.clone()],
    );
    let error = execute_with_checkpoints(&raced, raced.profile.start(), |checkpoint| {
        if checkpoint == Checkpoint::BeforePublication {
            fs::write(&raced.output, b"another owner won").unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("not_created"), "{error}");
    assert_eq!(fs::read(&raced.output).unwrap(), b"another owner won");
    no_stages(&fixture);
    struct FailedReceipt;
    impl Write for FailedReceipt {
        fn write(&mut self, _: &[u8]) -> stdio::Result<usize> {
            Err(stdio::Error::other("receipt pipe closed"))
        }
        fn flush(&mut self) -> stdio::Result<()> {
            Ok(())
        }
    }
    let args = arguments(
        &fixture,
        "reconstruct",
        "late",
        &catalog,
        &approval,
        &[fixture.input.clone()],
    );
    let late = parse(&args).unwrap();
    let error = run(&args, &mut FailedReceipt, None).unwrap_err();
    assert!(error.contains("publication_state=durable"), "{error}");
    assert_eq!(fs::read(&late.output).unwrap(), original);
    assert!(!late.scratch.exists());
    no_stages(&fixture);
}
