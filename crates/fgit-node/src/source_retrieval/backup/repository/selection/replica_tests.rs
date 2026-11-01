//! Explicit payload failover uses real signed native archives. Candidate
//! availability never chooses a new approval or creates a new native attempt.

use super::super::super::approval::witness::{self, WitnessGuard};
use super::*;
use fgit_schema::json::{self, Value};

const LOCK: &str = ".witness-lock";
const STATE: &str = "witness.json";

fn replica_options(
    fixture: &Fixture,
    operation: &str,
    name: &str,
    candidates: &[Candidate],
    maximum: Option<u64>,
) -> Options {
    let mut args = arguments(fixture, operation, name, candidates);
    args.push("--replica-failover".into());
    if let Some(maximum) = maximum {
        args.extend(["--max-read-bytes".into(), maximum.to_string()]);
    }
    let mut options = parse(&args).unwrap();
    options.trust.set_test_clock(Arc::new(AtomicI64::new(NOW)));
    options
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
        .unwrap_or_else(|| panic!("{name} is not an exact unsigned number"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name)
        .text()
        .unwrap_or_else(|| panic!("{name} is not text"))
}

fn parsed(receipt: &Receipt) -> Value {
    json::parse(receipt.json().as_bytes()).unwrap()
}

fn attempts(value: &Value) -> &[Value] {
    let Value::Array(attempts) = field(field(value, "acquisition"), "attempts") else {
        panic!("acquisition attempts must be an array");
    };
    attempts
}

fn successful_acquisition(value: &Value, acquired: u64, total_bytes: u64, maximum: u64) {
    let selection = field(value, "selection");
    assert_eq!(number(selection, "selected_index"), 0);
    assert_eq!(field(selection, "replica_failover"), &Value::Bool(true));
    let acquisition = field(value, "acquisition");
    assert_eq!(number(acquisition, "acquired_candidate_index"), acquired);
    assert_eq!(number(acquisition, "payload_bytes_read"), total_bytes);
    assert_eq!(number(acquisition, "max_read_bytes"), maximum);
    assert_eq!(text(acquisition, "read_budget_scope"), "all_archive_passes");
    assert!(number(acquisition, "payload_read_calls") > 0);
}

fn initialize(options: &Options, directory: &Path) {
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline).unwrap();
    witness::initialize(directory, &trust, deadline).unwrap();
}

fn witness_snapshot(options: &Options, directory: &Path) -> String {
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline).unwrap();
    let guard = WitnessGuard::open(directory, &trust, deadline).unwrap();
    let snapshot = guard.snapshot_json();
    guard.finish().unwrap();
    snapshot
}

#[test]
fn explicit_replicas_recover_missing_corrupt_and_truncated_first_payload_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"explicit same-statement replica\0\xff\n");
        let original = fs::read(&fixture.input).unwrap();
        let size = original.len() as u64;
        let approval = sign(&fixture, "replicas", &Statement::new(&fixture));
        for case in ["missing", "corrupt", "truncated"] {
            let first = fixture.root.join(format!("a-{case}.fg"));
            let last = fixture.root.join(format!("z-{case}.fg"));
            fs::write(&last, &original).unwrap();
            match case {
                "corrupt" => {
                    let mut corrupt = original.clone();
                    *corrupt.last_mut().unwrap() ^= 1;
                    fs::write(&first, corrupt).unwrap();
                }
                "truncated" => fs::write(&first, &original[..original.len() - 1]).unwrap(),
                _ => {}
            }
            let options = replica_options(
                &fixture,
                "verify-selected",
                &format!("verified-{case}"),
                &[candidate(&last, &approval), candidate(&first, &approval)],
                None,
            );
            let receipt = execute_in(&options, options.profile.start()).unwrap();
            let value = parsed(&receipt);
            // Metadata rejects a short file before reading it. A same-length
            // corrupt file consumes its complete initial checksum pass.
            let failed_bytes = if case == "corrupt" { size } else { 0 };
            successful_acquisition(
                &value,
                1,
                3 * size + failed_bytes,
                7 * options.profile.transfer.max_archive_bytes,
            );
            assert_eq!(
                number(field(&value, "selection"), "same_statement_replicas"),
                2
            );
            let attempts = attempts(&value);
            assert_eq!(attempts.len(), 2);
            assert_eq!(number(&attempts[0], "candidate_index"), 0);
            assert_eq!(number(&attempts[0], "bytes_read"), failed_bytes);
            assert_eq!(number(&attempts[1], "candidate_index"), 1);
            assert_eq!(text(&attempts[1], "outcome"), "acquired");
            assert_eq!(number(&attempts[1], "bytes_read"), 2 * size);
            if case == "missing" {
                assert_eq!(text(&attempts[0], "outcome"), "unavailable");
            } else {
                assert_eq!(text(&attempts[0], "outcome"), "damaged");
                assert_eq!(
                    text(&attempts[0], "reason"),
                    if case == "corrupt" {
                        "archive_checksum_mismatch"
                    } else {
                        "archive_length_mismatch"
                    }
                );
            }
            assert_eq!(
                field(field(&value, "native"), "object_graph_verified"),
                &Value::Bool(true)
            );
            assert!(!options.destination.exists());
            assert_eq!(fs::read(&last).unwrap(), original);
        }
    }
}

#[test]
fn changing_available_payload_does_not_change_original_envelope_or_signed_resume_binding() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"availability is not approval identity");
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        let original = sign(&fixture, "original", &Statement::new(&fixture));
        let envelope = fs::read(&original).unwrap();
        let reformatted = fixture.root.join("whitespace.approval");
        fs::write(
            &reformatted,
            [b" \n".as_slice(), envelope.as_slice(), b"\n"].concat(),
        )
        .unwrap();
        let first = fixture.root.join("a-original.fg");
        let last = fixture.root.join("z-replica.fg");
        fs::write(&last, &bytes).unwrap();
        let mut options = replica_options(
            &fixture,
            "recover",
            "restored",
            &[candidate(&last, &reformatted), candidate(&first, &original)],
            Some(6 * size),
        );
        let deadline = options.profile.start();
        let trust = options.trust.load(deadline).unwrap();
        let selected_binding = trust
            .inspect_path(&original)
            .unwrap()
            .into_verified(fixture.expected, options.profile.transfer.max_archive_bytes)
            .unwrap()
            .binding_digest();
        let alias_binding = trust
            .inspect_path(&reformatted)
            .unwrap()
            .into_verified(fixture.expected, options.profile.transfer.max_archive_bytes)
            .unwrap()
            .binding_digest();
        assert_ne!(selected_binding, alias_binding);
        let first_receipt = execute_in(&options, options.profile.start()).unwrap();
        let first_value = parsed(&first_receipt);
        successful_acquisition(&first_value, 1, 6 * size, 6 * size);
        assert_eq!(
            text(field(&first_value, "selection"), "approval_sha256"),
            hex(&digest(&envelope))
        );
        assert_eq!(
            text(
                field(field(&first_value, "native"), "approval"),
                "binding_sha256"
            ),
            hex(&selected_binding)
        );
        let intent = fs::read(options.destination.join(".restore-intent")).unwrap();
        assert!(options.destination.join("authority.fsqlite").is_file());

        // Keep the selected approval, candidate set, destination and policy
        // fixed while switching which payload exists for the exact resume.
        fs::write(&first, &bytes).unwrap();
        fs::remove_file(&last).unwrap();
        options.resume = true;
        let resumed = parsed(&execute_in(&options, options.profile.start()).unwrap());
        assert_eq!(
            number(field(&resumed, "acquisition"), "acquired_candidate_index"),
            0
        );
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
        assert_eq!(
            fs::read(options.destination.join(".restore-intent")).unwrap(),
            intent
        );
        assert_eq!(fs::read(&original).unwrap(), envelope);

        // Equivalent envelope JSON does not authorize changing an existing
        // signed intent. An available replica must not mask this native refusal.
        fs::write(&last, &bytes).unwrap();
        fs::write(&original, [b" ".as_slice(), envelope.as_slice()].concat()).unwrap();
        let mut attempted = 0;
        let error = execute_with_checkpoints(&options, options.profile.start(), |stage| {
            if stage == Checkpoint::BeforeReplicaAttempt {
                attempted += 1;
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(attempted, 1, "{error}");
        assert!(
            error.contains("intent") || error.contains("binding"),
            "{error}"
        );
        assert!(options.destination.join("authority.fsqlite").is_file());
        assert_eq!(
            fs::read(options.destination.join(".restore-intent")).unwrap(),
            intent
        );
    }
}

#[test]
fn exact_read_allowances_cover_all_native_passes_and_charge_failed_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"one finite ledger across every native pass");
        let bytes = fs::read(&fixture.input).unwrap();
        let size = bytes.len() as u64;
        let approval = sign(&fixture, "budget", &Statement::new(&fixture));
        let corrupt = fixture.root.join("a-corrupt.fg");
        let mut damaged = bytes.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&corrupt, damaged).unwrap();
        let healthy = fixture.root.join("z-healthy.fg");
        fs::write(&healthy, &bytes).unwrap();
        for (operation, passes) in [("verify-selected", 3_u64), ("recover", 6)] {
            for failed_first in [false, true] {
                let candidates = if failed_first {
                    vec![
                        candidate(&corrupt, &approval),
                        candidate(&healthy, &approval),
                    ]
                } else {
                    vec![candidate(&healthy, &approval)]
                };
                let needed = (passes + u64::from(failed_first)) * size;
                let label = format!("{operation}-{failed_first}");
                let refused = replica_options(
                    &fixture,
                    operation,
                    &format!("short-{label}"),
                    &candidates,
                    Some(needed - 1),
                );
                let mut read_bytes = 0;
                let mut native = false;
                let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
                    if let Checkpoint::ReplicaPayloadRead { total, .. } = stage {
                        read_bytes = total;
                    }
                    native |= stage == Checkpoint::BeforeNative;
                    Ok(())
                })
                .unwrap_err();
                assert!(error.contains("aggregate payload-read"), "{error}");
                assert_eq!(read_bytes, if failed_first { size } else { 0 });
                assert!(!native, "{error}");
                assert!(!refused.destination.exists());

                let allowed = replica_options(
                    &fixture,
                    operation,
                    &format!("exact-{label}"),
                    &candidates,
                    Some(needed),
                );
                let value = parsed(&execute_in(&allowed, allowed.profile.start()).unwrap());
                successful_acquisition(&value, u64::from(failed_first), needed, needed);
                assert_eq!(
                    field(field(&value, "native"), "complete"),
                    &Value::Bool(true)
                );
                if operation == "verify-selected" {
                    assert!(!allowed.destination.exists());
                } else {
                    assert!(allowed.destination.join("authority.fsqlite").is_file());
                }
            }
        }
    }
}

#[test]
fn hard_linked_damaged_aliases_are_not_read_or_charged_twice() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"deduplicate physical source reads",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let size = bytes.len() as u64;
    let approval = sign(&fixture, "dedup", &Statement::new(&fixture));
    let first = fixture.root.join("a-corrupt.fg");
    let duplicate = fixture.root.join("b-same-inode.fg");
    let last = fixture.root.join("z-healthy.fg");
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&first, corrupt).unwrap();
    fs::hard_link(&first, &duplicate).unwrap();
    fs::write(&last, bytes).unwrap();
    let options = replica_options(
        &fixture,
        "verify-selected",
        "deduplicated",
        &[
            candidate(&last, &approval),
            candidate(&duplicate, &approval),
            candidate(&first, &approval),
        ],
        Some(4 * size),
    );
    let value = parsed(&execute_in(&options, options.profile.start()).unwrap());
    successful_acquisition(&value, 2, 4 * size, 4 * size);
    let acquisition = field(&value, "acquisition");
    assert_eq!(number(acquisition, "candidates_attempted"), 3);
    assert_eq!(number(acquisition, "duplicate_sources_skipped"), 1);
    let attempts = attempts(&value);
    assert_eq!(attempts.len(), 3);
    assert_eq!(text(&attempts[0], "outcome"), "damaged");
    assert_eq!(number(&attempts[0], "bytes_read"), size);
    assert_eq!(text(&attempts[1], "outcome"), "duplicate");
    assert_eq!(number(&attempts[1], "bytes_read"), 0);
    assert_eq!(text(&attempts[2], "outcome"), "acquired");
    assert!(!options.destination.exists());
}

#[test]
fn highest_statement_eligibility_and_conflicts_precede_any_replica_attempt() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"no lower checkpoint fallback");
    let original = Statement::new(&fixture);
    let approval = sign(&fixture, "lower", &original);
    let healthy_lower = fixture.root.join("z-healthy-lower.fg");
    fs::copy(&fixture.input, &healthy_lower).unwrap();
    let first = fixture.root.join("a-missing-higher.fg");
    let second = fixture.root.join("b-missing-higher.fg");
    let mut higher = original.clone();
    higher.generation += 1;
    let signed_higher = sign(&fixture, "higher", &higher);
    let unavailable = replica_options(
        &fixture,
        "recover",
        "no-older-recovery",
        &[
            candidate(&healthy_lower, &approval),
            candidate(&second, &signed_higher),
            candidate(&first, &signed_higher),
        ],
        None,
    );
    let mut attempted = 0;
    let error = execute_with_checkpoints(&unavailable, unavailable.profile.start(), |stage| {
        if stage == Checkpoint::BeforeReplicaAttempt {
            attempted += 1;
        }
        assert!(!matches!(stage, Checkpoint::ReplicaPayloadRead { .. }));
        assert_ne!(stage, Checkpoint::BeforeNative);
        Ok(())
    })
    .unwrap_err();
    assert_eq!(attempted, 2, "{error}");
    assert!(
        error.contains("lower checkpoints remain ineligible"),
        "{error}"
    );
    assert!(!unavailable.destination.exists());

    for case in ["expired", "future", "over-budget", "wrong-pin", "conflict"] {
        let mut statement = higher.clone();
        match case {
            "expired" => statement.expires = Some("2030-01-01T00:00:00Z"),
            "future" => statement.issued = "2030-01-01T00:10:00Z",
            "over-budget" => statement.bytes += 1,
            "wrong-pin" => statement.digest = [0x42; 32],
            _ => statement.expires = Some("2040-01-01T00:00:00Z"),
        }
        let changed = sign(&fixture, case, &statement);
        let candidates = [
            candidate(&healthy_lower, &approval),
            candidate(&first, &changed),
            candidate(
                &second,
                if case == "conflict" {
                    &signed_higher
                } else {
                    &changed
                },
            ),
        ];
        let mut refused = replica_options(
            &fixture,
            "recover",
            &format!("ineligible-{case}"),
            &candidates,
            None,
        );
        refused.profile.transfer.max_archive_bytes = original.bytes;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            assert_ne!(stage, Checkpoint::BeforeReplicaAttempt);
            assert_ne!(stage, Checkpoint::BeforeNative);
            assert!(!matches!(stage, Checkpoint::ReplicaPayloadRead { .. }));
            Ok(())
        })
        .unwrap_err();
        let expected = match case {
            "expired" => "expired",
            "future" => "future",
            "over-budget" => "archive",
            "wrong-pin" => "digest",
            _ => "conflicting canonical",
        };
        assert!(error.contains(expected), "{case}: {error}");
        assert!(!refused.destination.exists());
    }
}

#[test]
fn cancellation_and_expiry_between_or_inside_attempts_are_terminal() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        b"one caller lifetime for all replicas",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let mut statement = Statement::new(&fixture);
    statement.expires = Some("2030-01-01T00:00:01Z");
    let approval = sign(&fixture, "expiring", &statement);
    let healthy = fixture.root.join("z-healthy.fg");
    fs::write(&healthy, &bytes).unwrap();
    for case in [
        "cancel-after-unavailable",
        "expire-after-unavailable",
        "cancel-during-read",
        "checksum-shaped-cancellation",
    ] {
        let first = fixture.root.join(format!("a-{case}.fg"));
        let during_read = matches!(case, "cancel-during-read" | "checksum-shaped-cancellation");
        if during_read {
            let mut corrupt = bytes.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            fs::write(&first, corrupt).unwrap();
        }
        let mut refused = replica_options(
            &fixture,
            "recover",
            case,
            &[candidate(&first, &approval), candidate(&healthy, &approval)],
            None,
        );
        let clock = Arc::new(AtomicI64::new(NOW));
        refused.trust.set_test_clock(Arc::clone(&clock));
        let mut attempted = 0;
        let mut unavailable = 0;
        let mut read_bytes = 0;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            match stage {
                Checkpoint::BeforeReplicaAttempt => attempted += 1,
                Checkpoint::ReplicaUnavailable => {
                    unavailable += 1;
                    if case == "expire-after-unavailable" {
                        clock.store(NOW + 1000, Ordering::SeqCst);
                    } else if case == "cancel-after-unavailable" {
                        return Err("caller cancelled between replica attempts".into());
                    }
                }
                Checkpoint::ReplicaPayloadRead { total, .. } => {
                    read_bytes = total;
                    if during_read {
                        return Err(if case == "checksum-shaped-cancellation" {
                            // Spelling a checksum mismatch cannot turn caller
                            // cancellation into typed recoverable damage.
                            "repository backup checksum mismatch".into()
                        } else {
                            "caller cancelled during replica payload read".into()
                        });
                    }
                }
                Checkpoint::BeforeNative => panic!("stopped acquisition entered native work"),
                _ => {}
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(attempted, 1, "{case}: {error}");
        assert_eq!(unavailable, usize::from(!during_read), "{case}: {error}");
        if during_read {
            assert!(read_bytes > 0 && read_bytes <= bytes.len() as u64);
        } else {
            assert_eq!(read_bytes, 0);
        }
        let expected = match case {
            "expire-after-unavailable" => "expired",
            "checksum-shaped-cancellation" => "checksum mismatch",
            _ => "caller cancelled",
        };
        assert!(error.contains(expected), "{case}: {error}");
        assert!(!refused.destination.exists());
    }
    let mut elapsed = replica_options(
        &fixture,
        "recover",
        "expired-deadline",
        &[candidate(&healthy, &approval)],
        None,
    );
    elapsed.profile.timeout = Duration::ZERO;
    let error = execute_with_checkpoints(&elapsed, elapsed.profile.start(), |_| {
        panic!("expired original deadline reached an acquisition checkpoint")
    })
    .unwrap_err();
    assert!(error.contains("deadline"), "{error}");
    assert!(!elapsed.destination.exists());
}

#[test]
fn matching_pin_with_invalid_native_format_and_fatal_open_errors_never_retry() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"fatal is not unavailable");
    let healthy = fixture.root.join("z-healthy.fg");
    fs::copy(&fixture.input, &healthy).unwrap();
    for case in ["invalid-native-format", "fatal-open"] {
        let mut statement = Statement::new(&fixture);
        let first = if case == "invalid-native-format" {
            let malformed = b"this is not a native recovery archive";
            statement.bytes = malformed.len() as u64;
            statement.digest = digest(malformed);
            let path = fixture.root.join("a-malformed.fg");
            fs::write(&path, malformed).unwrap();
            path
        } else {
            // A real Unix filename error is not an unavailable-copy result.
            fixture.root.join(format!("a-{}", "x".repeat(300)))
        };
        let approval = sign(&fixture, case, &statement);
        let mut refused = replica_options(
            &fixture,
            "recover",
            case,
            &[candidate(&first, &approval), candidate(&healthy, &approval)],
            None,
        );
        refused.expected = statement.digest;
        let mut attempted = 0;
        let mut unavailable = 0;
        let mut read_bytes = 0;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            match stage {
                Checkpoint::BeforeReplicaAttempt => attempted += 1,
                Checkpoint::ReplicaUnavailable => unavailable += 1,
                Checkpoint::ReplicaPayloadRead { total, .. } => read_bytes = total,
                Checkpoint::BeforeNative => panic!("fatal admission entered native work"),
                _ => {}
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(attempted, 1, "{case}: {error}");
        assert_eq!(unavailable, 0, "{case}: {error}");
        if case == "invalid-native-format" {
            assert!(read_bytes >= statement.bytes);
        } else {
            assert_eq!(read_bytes, 0);
        }
        assert!(!error.contains("no usable copy"), "{error}");
        assert!(!refused.destination.exists());
    }
}

#[test]
fn accepted_source_custody_or_native_errors_do_not_try_another_copy_and_keep_the_witness_lease() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"one accepted source and native attempt",
    );
    let bytes = fs::read(&fixture.input).unwrap();
    let approval = sign(&fixture, "accepted", &Statement::new(&fixture));
    for case in ["native-existing", "accepted-source-changed"] {
        let first = fixture.root.join(format!("a-{case}.fg"));
        let last = fixture.root.join(format!("z-{case}.fg"));
        fs::write(&first, &bytes).unwrap();
        fs::write(&last, &bytes).unwrap();
        let mut refused = replica_options(
            &fixture,
            "recover",
            case,
            &[candidate(&first, &approval), candidate(&last, &approval)],
            Some(6 * bytes.len() as u64),
        );
        let directory = fixture.root.join(format!("{case}-witness"));
        refused.witness = Some(directory.clone());
        initialize(&refused, &directory);
        if case == "native-existing" {
            fs::create_dir(&refused.destination).unwrap();
            fs::write(
                refused.destination.join("preserved"),
                b"existing owner bytes",
            )
            .unwrap();
        }
        let mut attempted = 0;
        let mut native_entries = 0;
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            assert!(directory.join(LOCK).is_file());
            if stage == Checkpoint::BeforeReplicaAttempt {
                attempted += 1;
            }
            if stage == Checkpoint::BeforeNative {
                native_entries += 1;
                if case == "accepted-source-changed" {
                    let mut changed = bytes.clone();
                    *changed.last_mut().unwrap() ^= 1;
                    fs::write(&first, changed).unwrap();
                }
            }
            assert_ne!(stage, Checkpoint::NativeCompleted);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(attempted, 1, "{case}: {error}");
        assert_eq!(native_entries, 1, "{case}: {error}");
        assert!(error.contains("witness_lock_retained=true"), "{error}");
        assert!(directory.join(LOCK).is_file());
        assert!(!refused.destination.join("authority.fsqlite").exists());
        assert_eq!(fs::read(&last).unwrap(), bytes);
        if case == "native-existing" {
            assert_eq!(
                fs::read(refused.destination.join("preserved")).unwrap(),
                b"existing owner bytes"
            );
        } else {
            assert!(error.contains("changed"), "{error}");
            assert!(!refused.destination.exists());
        }
    }
}

#[test]
fn witness_releases_settled_failover_but_remembers_unavailable_higher_replicas() {
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        b"replicas cannot erase recovery memory",
    );
    let original = Statement::new(&fixture);
    let approval = sign(&fixture, "current", &original);
    let healthy = fixture.root.join("z-healthy-current.fg");
    fs::copy(&fixture.input, &healthy).unwrap();
    let first = fixture.root.join("a-missing-current.fg");
    let directory = fixture.root.join("witness");
    let mut allowed = replica_options(
        &fixture,
        "verify-selected",
        "witnessed-success",
        &[candidate(&first, &approval), candidate(&healthy, &approval)],
        Some(3 * original.bytes),
    );
    allowed.witness = Some(directory.clone());
    initialize(&allowed, &directory);
    let value = parsed(
        &execute_with_checkpoints(&allowed, allowed.profile.start(), |_| {
            assert!(directory.join(LOCK).is_file());
            Ok(())
        })
        .unwrap(),
    );
    successful_acquisition(&value, 1, 3 * original.bytes, 3 * original.bytes);
    assert_eq!(
        field(field(&value, "selection"), "persistent_high_water_enforced"),
        &Value::Bool(true)
    );
    assert!(!directory.join(LOCK).exists());
    assert!(!allowed.destination.exists());

    let mut higher = original.clone();
    higher.generation += 1;
    let higher_approval = sign(&fixture, "unavailable-higher", &higher);
    let mut unavailable = replica_options(
        &fixture,
        "recover",
        "higher-unavailable",
        &[
            candidate(&fixture.root.join("a-newer.fg"), &higher_approval),
            candidate(&fixture.root.join("b-newer.fg"), &higher_approval),
            candidate(&healthy, &approval),
        ],
        None,
    );
    unavailable.witness = Some(directory.clone());
    let mut attempted = 0;
    let error = execute_with_checkpoints(&unavailable, unavailable.profile.start(), |stage| {
        assert!(directory.join(LOCK).is_file());
        if stage == Checkpoint::BeforeReplicaAttempt {
            attempted += 1;
            let retained = fs::read_to_string(directory.join(STATE)).unwrap();
            assert!(retained.contains(&base64(&fs::read(&higher_approval).unwrap())));
        }
        assert_ne!(stage, Checkpoint::BeforeNative);
        assert!(!matches!(stage, Checkpoint::ReplicaPayloadRead { .. }));
        Ok(())
    })
    .unwrap_err();
    assert_eq!(attempted, 2, "{error}");
    assert!(!error.contains("witness_lock_retained=true"), "{error}");
    assert!(!directory.join(LOCK).exists());
    assert!(!unavailable.destination.exists());
    assert!(
        witness_snapshot(&unavailable, &directory).contains(&format!(
            "\"highest_observed_generation\":\"{}\"",
            higher.generation
        ))
    );
    let retained = fs::read(directory.join(STATE)).unwrap();
    let mut rollback = replica_options(
        &fixture,
        "recover",
        "older-alone",
        &[candidate(&healthy, &approval)],
        None,
    );
    rollback.witness = Some(directory.clone());
    let error = execute_with_checkpoints(&rollback, rollback.profile.start(), |stage| {
        assert_ne!(stage, Checkpoint::BeforeReplicaAttempt);
        assert_ne!(stage, Checkpoint::BeforeNative);
        Ok(())
    })
    .unwrap_err();
    assert!(
        error.contains("below the independently retained witness"),
        "{error}"
    );
    assert!(!directory.join(LOCK).exists());
    assert!(!rollback.destination.exists());
    assert_eq!(fs::read(directory.join(STATE)).unwrap(), retained);
}
