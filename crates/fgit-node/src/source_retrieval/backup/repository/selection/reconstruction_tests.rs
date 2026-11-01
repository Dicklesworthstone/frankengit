//! Direct selected reconstruction consumes genuine signed native archives. The
//! catalog is an independently encoded recovery hint, never native proof.

use super::super::super::approval::witness::{self, WitnessGuard};
use super::*;
use fgit_schema::json::{self, Value};
use std::os::unix::fs::{PermissionsExt, symlink};

const CHUNK_BYTES: usize = 4 * 1024 * 1024;
const LOCK: &str = ".witness-lock";

fn reconstruction_options(
    fixture: &Fixture,
    operation: &str,
    name: &str,
    catalog: &Path,
    candidates: &[Candidate],
    maximum: Option<u64>,
) -> Options {
    let mut args = arguments(fixture, operation, name, candidates);
    args.extend([
        "--reconstruct-catalog".into(),
        catalog.to_str().unwrap().into(),
        "--reconstruction-root".into(),
        fixture
            .root
            .join(format!("{name}.reconstruction"))
            .to_str()
            .unwrap()
            .into(),
    ]);
    if let Some(maximum) = maximum {
        args.extend(["--max-read-bytes".into(), maximum.to_string()]);
    }
    let mut options = parse(&args).unwrap();
    options.trust.set_test_clock(Arc::new(AtomicI64::new(NOW)));
    options
}

fn reconstruction_root(options: &Options) -> &Path {
    &options.reconstruction.as_ref().unwrap().root
}

fn set_maximum(options: &mut Options, maximum: u64) {
    options.reconstruction.as_mut().unwrap().max_read_bytes = maximum;
}

// This encodes the documented FGCHNK01 wire format independently of the
// production catalog encoder. Adversarial tests deliberately supply chunk
// hashes for different bytes while retaining the original signed digest.
fn catalog(fixture: &Fixture, name: &str, bytes: &[u8]) -> PathBuf {
    let mut encoded = b"FGCHNK01".to_vec();
    encoded.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&fixture.expected);
    encoded.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    encoded.extend_from_slice(&(bytes.len().div_ceil(CHUNK_BYTES) as u32).to_be_bytes());
    for chunk in bytes.chunks(CHUNK_BYTES) {
        encoded.extend_from_slice(&digest(chunk));
    }
    encoded.extend_from_slice(&digest(&encoded));
    let path = fixture.root.join(format!("{name}.chunks"));
    fs::write(&path, encoded).unwrap();
    path
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

fn number(value: &Value, name: &str) -> u64 {
    field(value, name)
        .unsigned()
        .unwrap_or_else(|| panic!("{name} is not an exact unsigned integer"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).text().unwrap()
}

fn array<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    let Value::Array(values) = field(value, name) else {
        panic!("{name} is not an array");
    };
    values
}

fn parsed(receipt: &Receipt) -> Value {
    json::parse(receipt.json().as_bytes()).unwrap()
}

fn acquisition(value: &Value, total: u64, maximum: u64, indices: &[u64]) {
    let selection = field(value, "selection");
    assert_eq!(field(selection, "range_reconstruction"), &Value::Bool(true));
    assert_eq!(field(selection, "replica_failover"), &Value::Bool(false));
    let report = field(value, "acquisition");
    assert_eq!(text(report, "method"), "reconstructed_ranges");
    assert_eq!(number(report, "chunk_bytes"), CHUNK_BYTES as u64);
    assert_eq!(number(report, "payload_bytes_read"), total);
    assert_eq!(number(report, "max_read_bytes"), maximum);
    assert!(number(report, "payload_read_calls") > 0);
    assert_eq!(text(report, "read_budget_scope"), "all_archive_passes");
    assert_eq!(field(report, "root_removed"), &Value::Bool(true));
    assert_eq!(
        field(report, "intermediate_archive_published"),
        &Value::Bool(false)
    );
    let recorded: Vec<_> = array(report, "candidate_indices")
        .iter()
        .map(|index| index.unsigned().unwrap())
        .collect();
    assert_eq!(recorded, indices);
}

fn initialize(options: &Options, directory: &Path) {
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline).unwrap();
    witness::initialize(directory, &trust, deadline).unwrap();
}

fn snapshot(options: &Options, directory: &Path) -> String {
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline).unwrap();
    let guard = WitnessGuard::open(directory, &trust, deadline).unwrap();
    let snapshot = guard.snapshot_json();
    guard.finish().unwrap();
    snapshot
}

fn private_stage(directory: &Path) -> PathBuf {
    let entries: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    let stage = entries.into_iter().next().unwrap();
    assert!(stage.is_file());
    assert!(
        stage
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".fg-backup-approval-")
    );
    stage
}

#[test]
fn complementary_ranges_recover_only_the_highest_original_approval_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let payload: Vec<_> = (0..CHUNK_BYTES + 137)
            .map(|index| ((index * 73 + 19) % 251) as u8)
            .collect();
        let fixture = Fixture::new(format, &payload);
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        assert!(bytes.len() > CHUNK_BYTES && bytes.len() < 2 * CHUNK_BYTES);
        let original = sign(&fixture, "original", &Statement::new(&fixture));
        let envelope = fs::read(&original).unwrap();
        let reformatted = fixture.root.join("reformatted.approval");
        fs::write(
            &reformatted,
            [b" \n".as_slice(), envelope.as_slice(), b"\n"].concat(),
        )
        .unwrap();
        let mut older = Statement::new(&fixture);
        older.generation -= 1;
        let older_approval = sign(&fixture, "older", &older);
        let first = fixture.root.join("a-damaged.fg");
        let lower = fixture.root.join("m-lower.fg");
        let last = fixture.root.join("z-damaged.fg");
        let mut first_bytes = bytes.clone();
        first_bytes[17] ^= 1;
        let mut last_bytes = bytes.clone();
        last_bytes[CHUNK_BYTES + 29] ^= 1;
        fs::write(&first, &first_bytes).unwrap();
        fs::write(&last, &last_bytes).unwrap();
        // Even intact ranges at a lower signed generation cannot contribute.
        fs::write(&lower, &bytes).unwrap();
        let catalog = catalog(&fixture, "original", &bytes);
        fs::remove_file(&fixture.input).unwrap();
        assert_ne!(digest(&first_bytes), fixture.expected);
        assert_ne!(digest(&last_bytes), fixture.expected);
        let candidates = [
            candidate(&last, &reformatted),
            candidate(&lower, &older_approval),
            candidate(&first, &original),
        ];
        let maximum = 7 * size + CHUNK_BYTES as u64;
        let refused = reconstruction_options(
            &fixture,
            "recover",
            "one-byte-short",
            &catalog,
            &candidates,
            Some(maximum - 1),
        );
        let mut read_bytes = 0;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            assert_ne!(stage, Checkpoint::BeforeNative);
            if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
                read_bytes = total;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(
            error.contains("allowance") || error.contains("budget"),
            "{error}"
        );
        assert_eq!(read_bytes, CHUNK_BYTES as u64);
        assert!(!refused.destination.exists());
        assert!(!reconstruction_root(&refused).exists());

        let mut recover = reconstruction_options(
            &fixture,
            "recover",
            "recovered",
            &catalog,
            &candidates,
            Some(maximum),
        );
        recover.profile.transfer.max_archive_bytes = size;
        recover.profile.transfer.max_objects = 3;
        recover.profile.transfer.max_blob_bytes = payload.len() as u64;
        let directory = fixture.root.join("witness");
        recover.witness = Some(directory.clone());
        initialize(&recover, &directory);
        let mut accepted = Vec::new();
        let mut total = 0;
        let receipt = execute_with_checkpoints(&recover, recover.profile.start(), |stage| {
            match stage {
                Checkpoint::ReconstructionChunkAccepted { chunk, replica } => {
                    accepted.push((chunk, replica));
                }
                Checkpoint::ReconstructionPayloadRead { total: bytes, .. } => total = bytes,
                Checkpoint::BeforeNative | Checkpoint::NativeCompleted => {
                    assert!(directory.join(LOCK).is_file());
                }
                _ => {}
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(accepted, [(0, 1), (1, 0)]);
        assert_eq!(total, maximum);
        let value = parsed(&receipt);
        acquisition(&value, maximum, maximum, &[0, 2]);
        let selection = field(&value, "selection");
        assert_eq!(number(selection, "selected_index"), 0);
        assert_eq!(number(selection, "same_statement_replicas"), 2);
        assert_eq!(text(selection, "approval_sha256"), hex(&digest(&envelope)));
        let report = field(&value, "acquisition");
        assert_eq!(number(report, "chunks"), 2);
        let replicas = array(report, "replicas");
        assert_eq!(replicas.len(), 2);
        assert_eq!(number(&replicas[0], "chunks_used"), 1);
        assert_eq!(number(&replicas[0], "chunks_rejected"), 1);
        assert_eq!(number(&replicas[1], "chunks_used"), 1);
        assert_eq!(number(&replicas[1], "chunks_rejected"), 0);
        assert_eq!(
            field(field(&value, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
        assert!(recover.destination.join("authority.fsqlite").is_file());
        assert!(!reconstruction_root(&recover).exists());
        assert!(!directory.join(LOCK).exists());
        assert_eq!(fs::read(&first).unwrap(), first_bytes);
        assert_eq!(fs::read(&last).unwrap(), last_bytes);
        assert_eq!(fs::read(&lower).unwrap(), bytes);
        assert_eq!(fs::read(original).unwrap(), envelope);
    }
}

#[test]
fn exact_global_limits_and_original_resume_binding_survive_changed_copy_availability() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"one proof through range reconstruction and resume");
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        let original = sign(&fixture, "original", &Statement::new(&fixture));
        let envelope = fs::read(&original).unwrap();
        let alias = fixture.root.join("reformatted.approval");
        fs::write(&alias, [b" \n".as_slice(), envelope.as_slice()].concat()).unwrap();
        let first = fixture.root.join("a-original.fg");
        let last = fixture.root.join("z-copy.fg");
        fs::write(&last, &bytes).unwrap();
        let catalog = catalog(&fixture, "original", &bytes);
        fs::remove_file(&fixture.input).unwrap();
        let candidates = [candidate(&last, &alias), candidate(&first, &original)];
        for (operation, passes) in [("verify-selected", 4_u64), ("recover", 7)] {
            let mut bounded = reconstruction_options(
                &fixture,
                operation,
                operation,
                &catalog,
                &candidates,
                Some(passes * size - 1),
            );
            let mut read_bytes = 0;
            let error = execute_with_checkpoints(&bounded, bounded.profile.start(), |stage| {
                assert_ne!(stage, Checkpoint::BeforeNative);
                if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
                    read_bytes = total;
                }
                Ok(())
            })
            .unwrap_err();
            assert!(
                error.contains("allowance") || error.contains("budget"),
                "{error}"
            );
            assert_eq!(read_bytes, 0);
            assert!(!bounded.destination.exists());
            assert!(!reconstruction_root(&bounded).exists());
            set_maximum(&mut bounded, passes * size);
            let deadline = bounded.profile.start();
            let trust = bounded.trust.load(deadline).unwrap();
            let selected_binding = trust
                .inspect_path(&original)
                .unwrap()
                .into_verified(fixture.expected, bounded.profile.transfer.max_archive_bytes)
                .unwrap()
                .binding_digest();
            let alias_binding = trust
                .inspect_path(&alias)
                .unwrap()
                .into_verified(fixture.expected, bounded.profile.transfer.max_archive_bytes)
                .unwrap()
                .binding_digest();
            assert_ne!(selected_binding, alias_binding);
            let value = parsed(&execute_in(&bounded, bounded.profile.start()).unwrap());
            acquisition(&value, passes * size, passes * size, &[0, 1]);
            assert_eq!(
                text(field(&value, "selection"), "approval_sha256"),
                hex(&digest(&envelope))
            );
            assert_eq!(
                text(field(field(&value, "native"), "approval"), "binding_sha256"),
                hex(&selected_binding)
            );
            assert!(!reconstruction_root(&bounded).exists());
            if operation == "verify-selected" {
                assert!(!bounded.destination.exists());
                continue;
            }
            let intent = fs::read(bounded.destination.join(".restore-intent")).unwrap();
            fs::write(&first, &bytes).unwrap();
            fs::remove_file(&last).unwrap();
            bounded.resume = true;

            // A published resume actually needs 4N, but admission conservatively
            // protects the complete 7N recovery path before any source read.
            set_maximum(&mut bounded, 4 * size);
            let mut read_bytes = 0;
            let error = execute_with_checkpoints(&bounded, bounded.profile.start(), |stage| {
                assert_ne!(stage, Checkpoint::BeforeNative);
                if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
                    read_bytes = total;
                }
                Ok(())
            })
            .unwrap_err();
            assert!(
                error.contains("allowance") || error.contains("budget"),
                "{error}"
            );
            assert_eq!(read_bytes, 0);
            assert!(bounded.destination.join("authority.fsqlite").is_file());
            assert!(!reconstruction_root(&bounded).exists());
            set_maximum(&mut bounded, 7 * size);
            let resumed = parsed(&execute_in(&bounded, bounded.profile.start()).unwrap());
            acquisition(&resumed, 4 * size, 7 * size, &[0, 1]);
            assert_eq!(
                field(field(&resumed, "native"), "already_published"),
                &Value::Bool(true)
            );
            assert_eq!(
                text(
                    field(field(&resumed, "native"), "approval"),
                    "binding_sha256"
                ),
                hex(&selected_binding)
            );
            let replicas = array(field(&resumed, "acquisition"), "replicas");
            assert_eq!(number(&replicas[0], "chunks_used"), 1);
            assert_eq!(number(&replicas[1], "chunks_used"), 0);
            assert_eq!(
                fs::read(bounded.destination.join(".restore-intent")).unwrap(),
                intent
            );
            assert!(!reconstruction_root(&bounded).exists());
            assert_eq!(fs::read(&original).unwrap(), envelope);

            // Reformatting the selected envelope is still an intent change,
            // although the alias names the same authenticated statement.
            fs::write(&original, [b" ".as_slice(), envelope.as_slice()].concat()).unwrap();
            let error = execute_in(&bounded, bounded.profile.start()).unwrap_err();
            assert!(
                error.contains("intent") || error.contains("binding"),
                "{error}"
            );
            assert!(bounded.destination.join("authority.fsqlite").is_file());
            assert_eq!(
                fs::read(bounded.destination.join(".restore-intent")).unwrap(),
                intent
            );
            assert!(reconstruction_root(&bounded).is_dir());
        }
    }
}

#[test]
fn catalog_hints_and_recomputed_catalog_checksums_cannot_replace_the_original_pin() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(
            format,
            b"catalog hints never authenticate replacement bytes",
        );
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        let approval = sign(&fixture, "original", &Statement::new(&fixture));
        let envelope = fs::read(&approval).unwrap();
        let catalog_path = catalog(&fixture, "original", &bytes);
        let catalog_bytes = fs::read(&catalog_path).unwrap();
        for case in ["bad-trailer", "different-original", "independent-pin"] {
            let mut altered = catalog_bytes.clone();
            match case {
                "bad-trailer" => *altered.last_mut().unwrap() ^= 1,
                "different-original" => {
                    altered[16] ^= 1;
                    let trailer = altered.len() - 32;
                    let checksum = digest(&altered[..trailer]);
                    altered[trailer..].copy_from_slice(&checksum);
                }
                _ => {}
            }
            fs::write(&catalog_path, altered).unwrap();
            let mut refused = reconstruction_options(
                &fixture,
                "recover",
                case,
                &catalog_path,
                &[candidate(&fixture.input, &approval)],
                None,
            );
            if case == "independent-pin" {
                refused.expected = [0x42; 32];
            }
            let mut payload = 0;
            let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
                assert_ne!(stage, Checkpoint::BeforeNative);
                if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
                    payload = total;
                }
                Ok(())
            })
            .unwrap_err();
            assert!(
                error.contains("catalog") || error.contains("digest") || error.contains("pin"),
                "{case}: {error}"
            );
            assert_eq!(payload, 0);
            assert!(!refused.destination.exists());
            assert!(!reconstruction_root(&refused).exists());
        }

        // Both the chunk digest and catalog trailer authenticate these altered
        // ranges to each other, while the original signed whole-file pin differs.
        let mut forged = bytes.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_ne!(digest(&forged), fixture.expected);
        let forged_catalog = catalog(&fixture, "forged-hints", &forged);
        fs::write(&fixture.input, &forged).unwrap();
        let refused = reconstruction_options(
            &fixture,
            "recover",
            "forged-content",
            &forged_catalog,
            &[candidate(&fixture.input, &approval)],
            Some(7 * size),
        );
        let mut payload = 0;
        let mut accepted = 0;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            assert_ne!(stage, Checkpoint::BeforeNative);
            if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
                payload = total;
            }
            if matches!(stage, Checkpoint::ReconstructionChunkAccepted { .. }) {
                accepted += 1;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("checksum"), "{error}");
        assert_eq!(accepted, 1);
        assert_eq!(payload, 2 * size);
        assert!(!refused.destination.exists());
        assert!(!reconstruction_root(&refused).exists());
        assert_eq!(fs::read(&fixture.input).unwrap(), forged);
        assert_eq!(fs::read(&approval).unwrap(), envelope);
    }
}

#[test]
fn duplicate_physical_sources_never_spend_the_failed_range_budget_twice() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"deduplicate real hard links");
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = sign(&fixture, "original", &Statement::new(&fixture));
    let catalog = catalog(&fixture, "original", &bytes);
    let first = fixture.root.join("a-damaged.fg");
    let duplicate = fixture.root.join("b-hardlink.fg");
    let healthy = fixture.root.join("z-healthy.fg");
    let mut damaged = bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&first, &damaged).unwrap();
    fs::hard_link(&first, &duplicate).unwrap();
    fs::write(&healthy, &bytes).unwrap();
    fs::remove_file(&fixture.input).unwrap();
    let candidates = [
        candidate(&healthy, &approval),
        candidate(&duplicate, &approval),
        candidate(&first, &approval),
    ];
    let mut bounded = reconstruction_options(
        &fixture,
        "verify-selected",
        "bounded",
        &catalog,
        &candidates,
        Some(5 * size - 1),
    );
    let mut payload = 0;
    let error = execute_with_checkpoints(&bounded, bounded.profile.start(), |stage| {
        assert_ne!(stage, Checkpoint::BeforeNative);
        if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
            payload = total;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        error.contains("allowance") || error.contains("budget"),
        "{error}"
    );
    assert_eq!(payload, size);
    assert!(!bounded.destination.exists());
    assert!(!reconstruction_root(&bounded).exists());

    set_maximum(&mut bounded, 5 * size);
    let value = parsed(&execute_in(&bounded, bounded.profile.start()).unwrap());
    acquisition(&value, 5 * size, 5 * size, &[0, 1, 2]);
    let report = field(&value, "acquisition");
    assert_eq!(number(report, "duplicate_sources_skipped"), 1);
    let replicas = array(report, "replicas");
    assert_eq!(replicas.len(), 3);
    assert_eq!(number(&replicas[0], "chunks_rejected"), 1);
    assert_eq!(number(&replicas[0], "chunks_used"), 0);
    assert_eq!(number(&replicas[1], "duplicate_of"), 0);
    assert_eq!(number(&replicas[1], "chunks_used"), 0);
    assert_eq!(number(&replicas[1], "chunks_rejected"), 0);
    assert_eq!(number(&replicas[2], "chunks_used"), 1);
    assert_eq!(fs::read(&first).unwrap(), damaged);
    assert_eq!(fs::read(&duplicate).unwrap(), damaged);
    assert_eq!(fs::read(&healthy).unwrap(), bytes);
    assert!(!bounded.destination.exists());
    assert!(!reconstruction_root(&bounded).exists());
}

#[test]
fn unavailable_highest_ranges_settle_the_lease_but_prevent_later_witness_rollback() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"remember before reconstructing");
    let bytes = fs::read(&fixture.input).unwrap();
    let original = sign(&fixture, "original", &Statement::new(&fixture));
    let mut higher = Statement::new(&fixture);
    higher.generation += 1;
    let newer = sign(&fixture, "newer", &higher);
    let catalog = catalog(&fixture, "original", &bytes);
    let absent = fixture.root.join("a-missing-highest.fg");
    let candidates = [
        candidate(&fixture.input, &original),
        candidate(&absent, &newer),
    ];
    let directory = fixture.root.join("witness");
    let mut refused = reconstruction_options(
        &fixture,
        "recover",
        "higher-missing",
        &catalog,
        &candidates,
        None,
    );
    assert_eq!(
        refused.reconstruction.as_ref().unwrap().max_read_bytes,
        8 * refused.profile.transfer.max_archive_bytes
    );
    refused.witness = Some(directory.clone());
    initialize(&refused, &directory);
    let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
        assert_ne!(stage, Checkpoint::BeforeNative);
        assert!(!matches!(
            stage,
            Checkpoint::ReconstructionPayloadRead { .. }
        ));
        Ok(())
    })
    .unwrap_err();
    assert!(
        error.contains("range") || error.contains("replica"),
        "{error}"
    );
    assert!(!error.contains("witness_lock_retained=true"), "{error}");
    assert!(!refused.destination.exists());
    assert!(!reconstruction_root(&refused).exists());
    assert!(!directory.join(LOCK).exists());
    assert!(snapshot(&refused, &directory).contains(&format!(
        "\"highest_observed_generation\":\"{}\"",
        higher.generation
    )));
    assert_eq!(fs::read(&fixture.input).unwrap(), bytes);

    // This archive is genuinely native and otherwise independently eligible.
    // Omitting the unavailable higher approval must not erase retained knowledge.
    let mut rollback = reconstruction_options(
        &fixture,
        "recover",
        "rollback",
        &catalog,
        &[candidate(&fixture.input, &original)],
        None,
    );
    rollback.witness = Some(directory.clone());
    let error = execute_with_checkpoints(&rollback, rollback.profile.start(), |stage| {
        assert_ne!(stage, Checkpoint::BeforeReconstruction);
        assert_ne!(stage, Checkpoint::BeforeNative);
        Ok(())
    })
    .unwrap_err();
    assert!(
        error.contains("below the independently retained witness"),
        "{error}"
    );
    assert!(!rollback.destination.exists());
    assert!(!reconstruction_root(&rollback).exists());
    assert!(!directory.join(LOCK).exists());
}

#[test]
fn cancellation_and_expiry_clean_only_settled_owned_reconstruction_state() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"one lifetime and one cleanup owner",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let catalog = catalog(&fixture, "original", &bytes);
    for case in [
        "range-cancel",
        "prepared-cancel",
        "range-expiry",
        "completed-cancel",
    ] {
        let mut statement = Statement::new(&fixture);
        if case == "range-expiry" {
            statement.expires = Some("2030-01-01T00:00:01Z");
        }
        let approval = sign(&fixture, case, &statement);
        let mut bounded = reconstruction_options(
            &fixture,
            "verify-selected",
            case,
            &catalog,
            &[candidate(&fixture.input, &approval)],
            Some(4 * size),
        );
        let clock = Arc::new(AtomicI64::new(NOW));
        bounded.trust.set_test_clock(clock.clone());
        let directory = fixture.root.join(format!("{case}.witness"));
        bounded.witness = Some(directory.clone());
        initialize(&bounded, &directory);
        let mut payload = 0;
        let mut stopped = false;
        let mut native = false;
        let error = execute_with_checkpoints(&bounded, bounded.profile.start(), |stage| {
            if let Checkpoint::ReconstructionPayloadRead { total, .. } = stage {
                payload = total;
                if case == "range-cancel" {
                    stopped = true;
                    return Err("cancelled during actual reconstruction read".into());
                }
            }
            if case == "range-expiry"
                && matches!(stage, Checkpoint::ReconstructionChunkAccepted { .. })
            {
                stopped = true;
                clock.store(NOW + 1_001, Ordering::SeqCst);
            }
            if case == "prepared-cancel" && stage == Checkpoint::ReconstructionPrepared {
                stopped = true;
                return Err("cancelled with a pinned reconstruction before native work".into());
            }
            if stage == Checkpoint::BeforeNative {
                native = true;
                assert_eq!(case, "completed-cancel");
            }
            if case == "completed-cancel" && stage == Checkpoint::NativeCompleted {
                stopped = true;
                return Err("cancelled after completed native verification".into());
            }
            Ok(())
        })
        .unwrap_err();
        assert!(stopped, "{case}: {error}");
        assert_eq!(native, case == "completed-cancel");
        match case {
            "range-cancel" => {
                assert!(payload > 0 && payload <= size);
                assert!(
                    error.contains("cancelled during actual reconstruction read"),
                    "{error}"
                );
            }
            "range-expiry" => {
                assert_eq!(payload, size);
                assert!(error.contains("expir"), "{error}");
            }
            "prepared-cancel" => {
                assert_eq!(payload, 3 * size);
                assert!(
                    error.contains("cancelled with a pinned reconstruction"),
                    "{error}"
                );
            }
            "completed-cancel" => {
                assert_eq!(payload, 4 * size);
                assert!(error.contains("native_operation_complete=true"), "{error}");
            }
            _ => unreachable!(),
        }
        assert!(!bounded.destination.exists());
        assert!(!reconstruction_root(&bounded).exists(), "{case}: {error}");
        assert!(!directory.join(LOCK).exists(), "{case}: {error}");
        assert_eq!(fs::read(&fixture.input).unwrap(), bytes);
    }
}

#[test]
fn frozen_custody_and_native_progress_determine_retained_evidence_and_witness_ownership() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"frozen stage is never silently refrozen",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = sign(&fixture, "original", &Statement::new(&fixture));
    let catalog = catalog(&fixture, "original", &bytes);
    for case in [
        "prepared-stage",
        "replaced-root",
        "native-stage",
        "native-refusal",
        "completed-stage",
    ] {
        let mut bounded = reconstruction_options(
            &fixture,
            "recover",
            case,
            &catalog,
            &[candidate(&fixture.input, &approval)],
            Some(7 * size),
        );
        let directory = fixture.root.join(format!("{case}.witness"));
        bounded.witness = Some(directory.clone());
        initialize(&bounded, &directory);
        let root = reconstruction_root(&bounded).to_path_buf();
        let preserved = fixture.root.join(format!("{case}.preserved"));
        if case == "native-refusal" {
            fs::create_dir(&bounded.destination).unwrap();
        }
        let mut changed = false;
        let mut prepared = 0;
        let mut entered = 0;
        let mut completed = false;
        let mut staged = None;
        let error = execute_with_checkpoints(&bounded, bounded.profile.start(), |stage| {
            assert!(directory.join(LOCK).is_file());
            if stage == Checkpoint::ReconstructionPrepared {
                prepared += 1;
                let path = private_stage(&root);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                staged = Some(path);
            }
            if stage == Checkpoint::BeforeNative {
                entered += 1;
            }
            if stage == Checkpoint::NativeCompleted {
                completed = true;
            }
            if case == "replaced-root" && stage == Checkpoint::ReconstructionPrepared {
                fs::rename(&root, &preserved).unwrap();
                fs::create_dir(&root).unwrap();
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(root.join("unrelated"), b"must not be deleted").unwrap();
                changed = true;
            }
            let mutate = (case == "prepared-stage" && stage == Checkpoint::ReconstructionPrepared)
                || (case == "native-stage" && stage == Checkpoint::BeforeNative)
                || (case == "completed-stage" && stage == Checkpoint::NativeCompleted);
            if mutate {
                let path = staged.as_ref().unwrap();
                let mut altered = fs::read(path).unwrap();
                *altered.last_mut().unwrap() ^= 1;
                fs::write(path, altered).unwrap();
                // Force a distinct metadata fence even on coarse timestamp
                // filesystems; the content mutation alone is intentionally same-length.
                fs::File::open(path)
                    .unwrap()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1234))
                    .unwrap();
                changed = true;
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(prepared, 1, "{case}: {error}");
        assert_eq!(changed, case != "native-refusal");
        let native_started = matches!(case, "native-stage" | "native-refusal" | "completed-stage");
        assert_eq!(entered, usize::from(native_started), "{case}: {error}");
        assert_eq!(completed, case == "completed-stage", "{case}: {error}");
        assert!(root.is_dir(), "{case}: {error}");
        if case == "replaced-root" {
            assert_eq!(
                fs::read(root.join("unrelated")).unwrap(),
                b"must not be deleted"
            );
            assert_eq!(fs::read(private_stage(&preserved)).unwrap(), bytes);
        } else {
            assert!(staged.as_ref().unwrap().is_file(), "{case}: {error}");
        }
        let unresolved_native = native_started && !completed;
        assert_eq!(
            directory.join(LOCK).is_file(),
            unresolved_native,
            "{case}: {error}"
        );
        if unresolved_native {
            assert!(error.contains("witness_lock_retained=true"), "{error}");
        } else {
            assert!(!error.contains("witness_lock_retained=true"), "{error}");
        }
        assert_eq!(
            bounded.destination.join("authority.fsqlite").is_file(),
            completed,
            "{case}: {error}"
        );
        if completed {
            assert!(error.contains("native_operation_complete=true"), "{error}");
        }
        assert_eq!(fs::read(&fixture.input).unwrap(), bytes);
    }
}

#[test]
fn changed_parent_alias_refuses_before_private_root_admission_or_payload_reads() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"separation before reconstruction effects",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let approval = sign(&fixture, "original", &Statement::new(&fixture));
    let catalog = catalog(&fixture, "original", &bytes);
    let safe_parent = fixture.root.join("safe-parent");
    fs::create_dir(&safe_parent).unwrap();
    fs::set_permissions(&safe_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = fixture.root.join("input-parent-alias");
    symlink(&safe_parent, &alias).unwrap();
    let mut bounded = reconstruction_options(
        &fixture,
        "recover",
        "recovered",
        &catalog,
        &[candidate(&fixture.input, &approval)],
        None,
    );
    bounded.reconstruction.as_mut().unwrap().root = alias.join("private-input");
    let directory = fixture.root.join("witness");
    bounded.witness = Some(directory.clone());
    initialize(&bounded, &directory);
    let mut redirected = false;
    let error = execute_with_checkpoints(&bounded, bounded.profile.start(), |stage| {
        assert!(!matches!(
            stage,
            Checkpoint::ReconstructionPayloadRead { .. }
        ));
        assert_ne!(stage, Checkpoint::ReconstructionPrepared);
        assert_ne!(stage, Checkpoint::BeforeNative);
        if stage == Checkpoint::BeforeReconstruction {
            fs::remove_file(&alias).unwrap();
            symlink(&directory, &alias).unwrap();
            redirected = true;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(redirected);
    assert!(
        error.contains("alias") || error.contains("separate"),
        "{error}"
    );
    assert!(!safe_parent.join("private-input").exists());
    assert!(!directory.join("private-input").exists());
    assert!(!bounded.destination.exists());
    assert!(!directory.join(LOCK).exists());
    assert_eq!(fs::read(&fixture.input).unwrap(), bytes);
}
