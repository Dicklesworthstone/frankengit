//! Real native selected recovery with independently persisted signed evidence.
//! String errors never stand in for proof that native work has settled.

use super::super::super::approval::witness::{self, WitnessGuard};
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

const LOCK: &str = ".witness-lock";
const STATE: &str = "witness.json";

fn initialize(options: &Options, directory: &Path) {
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline).unwrap();
    witness::initialize(directory, &trust, deadline).unwrap();
}

fn snapshot(options: &Options, directory: &Path) -> String {
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline).unwrap();
    let guard = WitnessGuard::open(directory, &trust, deadline).unwrap();
    let json = guard.snapshot_json();
    guard.finish().unwrap();
    json
}

fn attach(mut options: Options, directory: &Path) -> Options {
    options.witness = Some(directory.to_path_buf());
    options
}

#[test]
fn native_witness_spans_the_whole_operation_and_preserves_exact_resume_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"independent native recovery witness\0\xff");
        let approval = approve(&fixture);
        let mut obsolete = lower(&fixture);
        // These absent acquisition directories are not payload dependencies.
        obsolete.input = fixture.root.join("unavailable/older/archive.fg");
        let candidates = [candidate(&fixture.input, &approval), obsolete];
        let directory = fixture.root.join("witness");
        let verify = attach(
            options(&fixture, "verify-selected", "verify", &candidates),
            &directory,
        );
        initialize(&verify, &directory);
        let competing_deadline = verify.profile.start();
        let competing_trust = verify.trust.load(competing_deadline).unwrap();
        let mut checks = 0;
        let receipt = execute_with_checkpoints(&verify, verify.profile.start(), |_| {
            assert!(directory.join(LOCK).is_file());
            assert!(
                WitnessGuard::open(&directory, &competing_trust, competing_deadline)
                    .unwrap_err()
                    .contains("exclusive lease unavailable")
            );
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert!(checks >= 6);
        assert!(
            receipt
                .json()
                .contains("\"persistent_high_water_enforced\":true")
        );
        assert!(receipt.json().contains("\"recovery_witness\":{"));
        assert!(
            receipt
                .json()
                .contains("\"newest_checkpoint_verified\":false")
        );
        assert!(!directory.join(LOCK).exists());
        assert!(!verify.destination.exists());
        let retained = fs::read(directory.join(STATE)).unwrap();
        let envelope = fs::read(&approval).unwrap();
        let mut recover = attach(
            options(&fixture, "recover", "recovered", &candidates),
            &directory,
        );
        assert!(
            execute_in(&recover, recover.profile.start())
                .unwrap()
                .json()
                .contains("\"reopened_and_verified\":true")
        );
        assert!(!directory.join(LOCK).exists());
        recover.resume = true;
        assert!(
            execute_in(&recover, recover.profile.start())
                .unwrap()
                .json()
                .contains("\"already_published\":true")
        );
        assert!(!directory.join(LOCK).exists());
        assert_eq!(fs::read(directory.join(STATE)).unwrap(), retained);
        assert_eq!(fs::read(approval).unwrap(), envelope);
    }
}

#[test]
fn newer_ineligible_or_unavailable_observations_persist_before_native_work_and_prevent_restart_rollback()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, b"remember unusable newer evidence");
        let original = approve(&fixture);
        for case in ["expired", "future", "oversize", "pin", "missing"] {
            let mut higher = Statement::new(&fixture);
            higher.generation += 1;
            match case {
                "expired" => higher.expires = Some("2025-01-01T00:00:00Z"),
                "future" => higher.issued = "2030-01-01T00:00:01Z",
                "oversize" => higher.bytes += 1,
                _ => {}
            }
            let signed = sign(&fixture, case, &higher);
            let candidates = [
                candidate(&fixture.input, &original),
                candidate(&fixture.root.join(format!("missing-{case}.fg")), &signed),
            ];
            let directory = fixture.root.join(format!("witness-{case}"));
            let mut refused = attach(
                options(&fixture, "recover", &format!("restore-{case}"), &candidates),
                &directory,
            );
            if case == "oversize" {
                refused.profile.transfer.max_archive_bytes = higher.bytes - 1;
            }
            if case == "pin" {
                refused.expected = [0x42; 32];
            }
            initialize(&refused, &directory);
            let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
                assert_ne!(stage, Checkpoint::BeforeNative);
                Ok(())
            })
            .unwrap_err();
            assert!(!error.contains("witness_lock_retained=true"), "{error}");
            assert!(!refused.destination.exists());
            assert!(!directory.join(LOCK).exists());
            assert!(snapshot(&refused, &directory).contains(&format!(
                "\"highest_observed_generation\":\"{}\"",
                higher.generation
            )));
            let older = attach(
                options(
                    &fixture,
                    "recover",
                    &format!("rollback-{case}"),
                    &[candidate(&fixture.input, &original)],
                ),
                &directory,
            );
            let error = execute_in(&older, older.profile.start()).unwrap_err();
            assert!(
                error.contains("below the independently retained witness"),
                "{error}"
            );
            assert!(!older.destination.exists());
            assert!(!directory.join(LOCK).exists());
        }
    }
}

#[test]
fn each_authenticated_observation_survives_later_invalid_input_or_cancellation() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"auth then durable observation");
    let mut higher = Statement::new(&fixture);
    higher.generation += 1;
    let signed = sign(&fixture, "higher", &higher);
    let malformed = fixture.root.join("malformed.approval");
    fs::write(&malformed, b"not an authenticated envelope").unwrap();
    for cancel in [false, true] {
        let directory = fixture.root.join(if cancel {
            "cancel-witness"
        } else {
            "invalid-witness"
        });
        let options = attach(
            options(
                &fixture,
                "recover",
                if cancel { "cancel" } else { "invalid" },
                &[
                    candidate(&fixture.root.join("a-missing.fg"), &signed),
                    candidate(&fixture.root.join("z-missing.fg"), &malformed),
                ],
            ),
            &directory,
        );
        initialize(&options, &directory);
        let encoded = base64(&fs::read(&signed).unwrap());
        let mut observations = 0;
        let error = execute_with_checkpoints(&options, options.profile.start(), |stage| {
            if stage == Checkpoint::ApprovalObserved {
                observations += 1;
                // The exact signature bytes are already on disk when the first
                // post-authentication observer or cancellation gate can run.
                let state = fs::read_to_string(directory.join(STATE)).unwrap();
                assert!(state.contains(&encoded));
                if cancel {
                    return Err("cancel after authenticated observation".into());
                }
            }
            assert_ne!(stage, Checkpoint::AllApprovalsAuthenticated);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(observations, 1);
        assert!(!error.contains("witness_lock_retained=true"), "{error}");
        assert!(!directory.join(LOCK).exists());
        assert!(!options.destination.exists());
        assert!(snapshot(&options, &directory).contains(&format!(
            "\"highest_observed_generation\":\"{}\"",
            higher.generation
        )));
    }
}

#[test]
fn highest_conflicts_survive_omission_and_only_strictly_higher_authentication_supersedes_them() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"persistent ambiguity");
    let original = approve(&fixture);
    let mut competing = Statement::new(&fixture);
    competing.digest = [0x37; 32];
    let conflict = sign(&fixture, "conflict", &competing);
    let directory = fixture.root.join("witness");
    let both = attach(
        options(
            &fixture,
            "recover",
            "ambiguous",
            &[
                candidate(&fixture.input, &original),
                candidate(&fixture.root.join("missing-conflict.fg"), &conflict),
            ],
        ),
        &directory,
    );
    initialize(&both, &directory);
    assert!(
        execute_in(&both, both.profile.start())
            .unwrap_err()
            .contains("conflicting canonical")
    );
    assert!(!directory.join(LOCK).exists());
    assert!(snapshot(&both, &directory).contains("\"conflicting_statements\":true"));
    let alone = attach(
        options(
            &fixture,
            "recover",
            "omitted-conflict",
            &[candidate(&fixture.input, &original)],
        ),
        &directory,
    );
    assert!(
        execute_in(&alone, alone.profile.start())
            .unwrap_err()
            .contains("retains conflicting")
    );
    competing.generation += 1;
    competing.digest = fixture.expected;
    competing.expires = Some("2025-01-01T00:00:00Z");
    let newer = sign(&fixture, "higher-expired", &competing);
    let superseding = attach(
        options(
            &fixture,
            "recover",
            "superseding",
            &[candidate(&fixture.root.join("missing-higher.fg"), &newer)],
        ),
        &directory,
    );
    assert!(
        execute_in(&superseding, superseding.profile.start())
            .unwrap_err()
            .contains("expired")
    );
    let state = snapshot(&superseding, &directory);
    assert!(state.contains("\"conflicting_statements\":false"));
    assert!(state.contains(&format!(
        "\"highest_observed_generation\":\"{}\"",
        competing.generation
    )));
    assert!(
        !both.destination.exists()
            && !alone.destination.exists()
            && !superseding.destination.exists()
    );
}

#[test]
fn failed_retention_of_authenticated_higher_evidence_keeps_the_exclusive_lease() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"retention failure is sticky");
    let first = Statement::new(&fixture);
    let original = sign(&fixture, "first", &first);
    let mut higher = first.clone();
    higher.generation += 1;
    let newest = sign(&fixture, "next", &higher);
    let directory = fixture.root.join("witness");
    let options = attach(
        options(
            &fixture,
            "recover",
            "retention-failed",
            &[
                candidate(&fixture.root.join("a-missing.fg"), &original),
                candidate(&fixture.root.join("z-missing.fg"), &newest),
            ],
        ),
        &directory,
    );
    initialize(&options, &directory);
    let mut observed = 0;
    let error = execute_with_checkpoints(&options, options.profile.start(), |stage| {
        if stage == Checkpoint::ApprovalObserved {
            observed += 1;
            assert_eq!(observed, 1);
            // Replace the pathname after a successful first retention. The
            // next authentic higher observation must poison on failed custody.
            fs::rename(
                directory.join(STATE),
                directory.join("preserved-state.json"),
            )
            .unwrap();
            fs::write(directory.join(STATE), b"foreign state").unwrap();
            fs::set_permissions(directory.join(STATE), fs::Permissions::from_mode(0o600)).unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("witness_lock_retained=true"), "{error}");
    assert!(directory.join(LOCK).is_file());
    assert_eq!(fs::read(directory.join(STATE)).unwrap(), b"foreign state");
    assert!(
        fs::read_to_string(directory.join("preserved-state.json"))
            .unwrap()
            .contains(&base64(&fs::read(original).unwrap()))
    );
    assert!(!options.destination.exists());
    let trust = options.trust.load(options.profile.start()).unwrap();
    assert!(
        WitnessGuard::open(&directory, &trust, options.profile.start())
            .unwrap_err()
            .contains("exclusive lease unavailable")
    );
}

#[test]
fn native_errors_retain_but_confirmed_completion_and_failed_receipt_delivery_release_the_lease() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"settled native recovery");
    let original = approve(&fixture);
    let candidates = [candidate(&fixture.input, &original)];
    let failed_directory = fixture.root.join("failed-witness");
    let failed = attach(
        options(&fixture, "verify-selected", "existing", &candidates),
        &failed_directory,
    );
    initialize(&failed, &failed_directory);
    fs::create_dir(&failed.destination).unwrap();
    fs::write(failed.destination.join("preserved"), b"existing user bytes").unwrap();
    let error = execute_in(&failed, failed.profile.start()).unwrap_err();
    assert!(error.contains("witness_lock_retained=true"), "{error}");
    assert!(failed_directory.join(LOCK).is_file());
    assert_eq!(
        fs::read(failed.destination.join("preserved")).unwrap(),
        b"existing user bytes"
    );

    let directory = fixture.root.join("completed-witness");
    let mut completed = attach(
        options(&fixture, "recover", "completed", &candidates),
        &directory,
    );
    initialize(&completed, &directory);
    let error = execute_with_checkpoints(&completed, completed.profile.start(), |stage| {
        if stage == Checkpoint::NativeCompleted {
            Err("late delivery observer failed".into())
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.contains("native_operation_complete=true"), "{error}");
    assert!(completed.destination.join("authority.fsqlite").is_file());
    assert!(!directory.join(LOCK).exists());
    completed.resume = true;
    assert!(
        execute_in(&completed, completed.profile.start())
            .unwrap()
            .json()
            .contains("\"already_published\":true")
    );
    assert!(!directory.join(LOCK).exists());

    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("closed receipt"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut args = arguments(&fixture, "verify-selected", "completed-verify", &candidates);
    args.extend(["--witness".into(), directory.to_str().unwrap().into()]);
    let error = run(&args, &mut Closed, None).unwrap_err();
    assert!(error.contains("native_operation_complete=true"), "{error}");
    assert!(!directory.join(LOCK).exists());
    assert!(!fixture.root.join("completed-verify").exists());
}

#[test]
fn physical_aliases_cannot_place_any_candidate_parent_or_native_destination_inside_the_witness() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"independent physical witness");
    let original = approve(&fixture);
    let directory = fixture.root.join("witness");
    let baseline = attach(
        options(
            &fixture,
            "verify-selected",
            "unused",
            &[candidate(&fixture.input, &original)],
        ),
        &directory,
    );
    initialize(&baseline, &directory);
    let alias = fixture.root.join("alias");
    symlink(&directory, &alias).unwrap();
    for kind in ["destination", "lower-parent", "approval", "key"] {
        let mut candidates = vec![candidate(&fixture.input, &original)];
        if kind == "lower-parent" {
            let mut obsolete = lower(&fixture);
            obsolete.input = alias.join("absent/acquisition/old.fg");
            candidates.push(obsolete);
        }
        if kind == "approval" {
            fs::copy(&original, directory.join("copied.approval")).unwrap();
            candidates[0].approval = alias.join("copied.approval");
        }
        let mut args = arguments(
            &fixture,
            "verify-selected",
            &format!("refused-{kind}"),
            &candidates,
        );
        if kind == "destination" {
            args[1] = alias.join("scratch").to_str().unwrap().into();
        }
        if kind == "key" {
            fs::copy(&fixture.public_key, directory.join("copied.pem")).unwrap();
            let at = args.iter().position(|arg| arg == "--trust-key").unwrap();
            args[at + 1] = alias.join("copied.pem").to_str().unwrap().into();
        }
        args.extend(["--witness".into(), directory.to_str().unwrap().into()]);
        let mut refused = parse(&args).unwrap();
        refused.trust.set_test_clock(Arc::new(AtomicI64::new(NOW)));
        let error = execute_with_checkpoints(&refused, refused.profile.start(), |stage| {
            assert_ne!(stage, Checkpoint::BeforeNative);
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("physically separate"), "{kind}: {error}");
        assert!(!directory.join(LOCK).exists());
        assert!(!refused.destination.exists());
    }
    // Parent aliases are permitted when they remain independent and pinned.
    fs::remove_file(&alias).unwrap();
    symlink(&fixture.root, &alias).unwrap();
    let mut allowed = attach(
        options(
            &fixture,
            "verify-selected",
            "allowed",
            &[candidate(&alias.join("source.fg"), &original)],
        ),
        &directory,
    );
    allowed.destination = alias.join("allowed-scratch");
    assert!(execute_in(&allowed, allowed.profile.start()).is_ok());
    assert!(!directory.join(LOCK).exists());
}

#[test]
fn changing_a_protected_parent_after_selection_is_detected_at_the_native_fence() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"live parent custody");
    let original = approve(&fixture);
    let directory = fixture.root.join("witness");
    let independent = fixture.root.join("independent-parent");
    fs::create_dir(&independent).unwrap();
    let alias = fixture.root.join("parent-alias");
    symlink(&independent, &alias).unwrap();
    let mut options = attach(
        options(
            &fixture,
            "recover",
            "alias-recovery",
            &[candidate(&fixture.input, &original)],
        ),
        &directory,
    );
    options.destination = alias.join("recovered");
    initialize(&options, &directory);
    let error = execute_with_checkpoints(&options, options.profile.start(), |stage| {
        if stage == Checkpoint::BeforeNative {
            fs::remove_file(&alias).unwrap();
            symlink(&directory, &alias).unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("parent alias changed"), "{error}");
    assert!(error.contains("witness_lock_retained=true"), "{error}");
    assert!(directory.join(LOCK).is_file());
    assert!(!options.destination.exists());
    assert!(!independent.join("recovered").exists());
}

#[test]
fn missing_witness_never_initializes_itself_or_authenticates_candidates_and_resume_stays_uncertain()
{
    let fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        b"explicit independent initialization",
    );
    let directory = fixture.root.join("missing-witness");
    let mut options = attach(
        options(
            &fixture,
            "recover",
            "untouched",
            &[candidate(
                &fixture.input,
                &fixture.root.join("also-missing.approval"),
            )],
        ),
        &directory,
    );
    let error = execute_with_checkpoints(&options, options.profile.start(), |_| {
        panic!("missing witness must refuse before candidate authentication")
    })
    .unwrap_err();
    assert!(error.contains("witness"), "{error}");
    assert!(!directory.exists() && !options.destination.exists());
    options.resume = true;
    let error = execute_in(&options, options.profile.start()).unwrap_err();
    assert!(
        error.contains("prior attempt may already have published authority"),
        "{error}"
    );
    assert!(!directory.exists() && !options.destination.exists());
}

#[test]
fn witness_never_reopens_captured_controls_or_rewrites_the_original_signed_resume_binding() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, b"original native signed intent");
    let approval = approve(&fixture);
    let envelope = fs::read(&approval).unwrap();
    let public = fs::read(&fixture.public_key).unwrap();
    let directory = fixture.root.join("witness");
    let mut options = attach(
        options(
            &fixture,
            "recover",
            "recovered",
            &[candidate(&fixture.input, &approval)],
        ),
        &directory,
    );
    initialize(&options, &directory);
    let receipt = execute_with_checkpoints(&options, options.profile.start(), |stage| {
        if stage == Checkpoint::AllApprovalsAuthenticated {
            fs::write(
                &approval,
                b"replacement approval cannot switch captured evidence",
            )
            .unwrap();
            fs::write(
                &fixture.public_key,
                b"replacement key cannot change captured trust",
            )
            .unwrap();
        }
        Ok(())
    })
    .unwrap();
    assert!(receipt.json().contains("\"reopened_and_verified\":true"));
    assert!(!directory.join(LOCK).exists());
    fs::write(&approval, &envelope).unwrap();
    fs::write(&fixture.public_key, &public).unwrap();
    options.resume = true;
    assert!(
        execute_in(&options, options.profile.start())
            .unwrap()
            .json()
            .contains("\"already_published\":true")
    );
    let retained = fs::read(directory.join(STATE)).unwrap();
    fs::write(&approval, [b" ".as_slice(), envelope.as_slice()].concat()).unwrap();
    let error = execute_in(&options, options.profile.start()).unwrap_err();
    assert!(
        error.contains("intent") || error.contains("binding"),
        "{error}"
    );
    assert!(error.contains("witness_lock_retained=true"), "{error}");
    assert_eq!(fs::read(directory.join(STATE)).unwrap(), retained);
    assert!(options.destination.join("authority.fsqlite").is_file());
}

#[test]
fn late_witness_cleanup_failure_cannot_erase_confirmed_native_completion() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, b"monotonic native completion");
    let approval = approve(&fixture);
    let directory = fixture.root.join("witness");
    let options = attach(
        options(
            &fixture,
            "verify-selected",
            "completed",
            &[candidate(&fixture.input, &approval)],
        ),
        &directory,
    );
    initialize(&options, &directory);
    let error = execute_with_checkpoints(&options, options.profile.start(), |stage| {
        if stage == Checkpoint::NativeCompleted {
            assert!(!options.destination.exists());
            fs::write(directory.join(STATE), b"foreign late state").unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("native_operation_complete=true"), "{error}");
    assert!(error.contains("witness_lock_retained=true"), "{error}");
    assert!(directory.join(LOCK).is_file());
    assert!(!options.destination.exists());
    assert_eq!(
        fs::read(directory.join(STATE)).unwrap(),
        b"foreign late state"
    );
}
