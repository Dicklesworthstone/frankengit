//! Highest signed checkpoint selection through real native fg processes.
use super::*;

pub(super) fn selected_arguments(
    export: &Value,
    operation: &str,
    destination: &str,
    candidates: &[(&str, &str)],
) -> Vec<String> {
    let mut args = strings(&[
        "backup",
        operation,
        destination,
        "--trusted-local",
        "--expected-sha256",
        text(export, "sha256"),
        if operation == "recover" {
            "--destination-instance"
        } else {
            "--verification-instance"
        },
        "993",
        "--max-archive-bytes",
        "16777216",
        "--max-objects",
        "250000",
    ]);
    // Selection captures independent trust once, without a single --approval.
    args.extend(Fixture::signed_flags(export).into_iter().skip(2));
    replace(&mut args, "--minimum-head-generation", "1");
    for (archive, approval) in candidates {
        args.extend(strings(&["--candidate", archive, approval]));
    }
    args
}

#[test]
fn native_selected_recovery_keeps_the_highest_checkpoint_and_exact_resume_identity() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let older = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&older, "older.approval.json", "old-attest")));
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("older.fgit")).unwrap();

        let opened = fixture.issue("node", format, false);
        let newer = fixture.export(format);
        assert!(count(&newer, "head_generation") > count(&older, "head_generation"));
        assert!(count(&newer, "bytes") > count(&older, "bytes"));
        receipt(fixture.run(&fixture.attest(&newer, "newer.approval.json", "new-attest")));
        let mut conflicting =
            fixture.attest(&newer, "conflicting.approval.json", "conflict-attest");
        replace(&mut conflicting, "--expires-at", "9998-12-31T23:59:59Z");
        receipt(fixture.run(&conflicting));
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("newer.fgit")).unwrap();
        let bytes = fs::read(fixture.0.join("newer.fgit")).unwrap();
        let approval = fs::read(fixture.0.join("newer.approval.json")).unwrap();
        fs::write(fixture.0.join("replica.fgit"), &bytes).unwrap();
        fs::write(fixture.0.join("replica.approval.json"), &approval).unwrap();
        fs::remove_dir_all(fixture.0.join("node")).unwrap();
        fs::remove_file(fixture.0.join("input.bundle")).unwrap();

        let candidates = [
            ("older.fgit", "older.approval.json"),
            ("newer.fgit", "newer.approval.json"),
            ("replica.fgit", "replica.approval.json"),
        ];
        let verified = receipt(fixture.run(&selected_arguments(
            &newer,
            "verify-selected",
            "selected-preflight",
            &candidates,
        )));
        assert_eq!(
            text(&verified, "type"),
            "repository_source_backup_selected_verify"
        );
        let selection = field(&verified, "selection");
        assert_eq!(count(selection, "selected_index"), 0);
        assert_eq!(count(selection, "candidates_authenticated"), 3);
        assert_eq!(count(selection, "same_statement_replicas"), 2);
        assert_eq!(
            text(selection, "selected_head_generation"),
            count(&newer, "head_generation").to_string()
        );
        assert_eq!(
            field(selection, "highest_supplied_generation_selected"),
            &Value::Bool(true)
        );
        for name in [
            "newest_checkpoint_verified",
            "candidate_set_completeness_verified",
            "replica_failover",
        ] {
            assert_eq!(field(selection, name), &Value::Bool(false), "{name}");
        }
        assert_eq!(
            field(field(&verified, "native"), "signature_verified"),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("selected-preflight").exists());

        // The lower pin cannot hide the higher authenticated checkpoint.
        let pin_error = refused(fixture.run(&selected_arguments(
            &older,
            "recover",
            "wrong-pin",
            &candidates,
        )));
        assert!(
            pin_error.contains("digest") || pin_error.contains("pin"),
            "{pin_error}"
        );
        assert!(!fixture.0.join("wrong-pin").exists());

        // A valid older-size allowance is insufficient for the selected winner.
        let mut bounded = selected_arguments(&newer, "recover", "too-large", &candidates);
        replace(
            &mut bounded,
            "--max-archive-bytes",
            &count(&older, "bytes").to_string(),
        );
        refused(fixture.run(&bounded));
        assert!(!fixture.0.join("too-large").exists());

        // Distinct authentic statements at the same highest generation conflict,
        // even when they name exactly the same payload bytes.
        let ambiguous = [
            ("older.fgit", "older.approval.json"),
            ("newer.fgit", "newer.approval.json"),
            ("replica.fgit", "conflicting.approval.json"),
        ];
        let error = refused(fixture.run(&selected_arguments(
            &newer,
            "recover",
            "ambiguous",
            &ambiguous,
        )));
        assert!(
            error.contains("ambiguous") || error.contains("conflict"),
            "{error}"
        );
        assert!(!fixture.0.join("ambiguous").exists());

        // Authenticate all approvals, including an unselected lower candidate,
        // before attempting to open any archive. Compare exact refusals while
        // payload paths are available and while all of them are absent.
        let mut bad = fs::read(fixture.0.join("older.approval.json")).unwrap();
        let prefix = b"\"sig\":\"";
        let at = bad
            .windows(prefix.len())
            .position(|part| part == prefix)
            .unwrap()
            + prefix.len();
        bad[at] = if bad[at] == b'A' { b'B' } else { b'A' };
        fs::write(fixture.0.join("invalid.approval.json"), bad).unwrap();
        let invalid = [
            ("newer.fgit", "newer.approval.json"),
            ("older.fgit", "invalid.approval.json"),
        ];
        let invalid_args = selected_arguments(&newer, "recover", "invalid", &invalid);
        let before = refused(fixture.run(&invalid_args));
        fs::rename(
            fixture.0.join("newer.fgit"),
            fixture.0.join("saved-newer.fgit"),
        )
        .unwrap();
        fs::rename(
            fixture.0.join("older.fgit"),
            fixture.0.join("saved-older.fgit"),
        )
        .unwrap();
        assert_eq!(refused(fixture.run(&invalid_args)), before);
        assert!(!fixture.0.join("invalid").exists());
        fs::rename(
            fixture.0.join("saved-older.fgit"),
            fixture.0.join("older.fgit"),
        )
        .unwrap();

        // The first lexical identical highest alias is deterministic; no automatic
        // retry can reinterpret failure as permission to use an older archive.
        refused(fixture.run(&selected_arguments(
            &newer,
            "recover",
            "missing",
            &candidates,
        )));
        assert!(!fixture.0.join("missing").exists());
        fs::rename(
            fixture.0.join("saved-newer.fgit"),
            fixture.0.join("newer.fgit"),
        )
        .unwrap();
        let mut corrupt = bytes.clone();
        corrupt[0] ^= 1;
        fs::write(fixture.0.join("newer.fgit"), corrupt).unwrap();
        refused(fixture.run(&selected_arguments(
            &newer,
            "recover",
            "corrupt",
            &candidates,
        )));
        assert!(!fixture.0.join("corrupt").exists());
        fs::write(fixture.0.join("newer.fgit"), &bytes).unwrap();

        let mut recover = selected_arguments(&newer, "recover", "recovered", &candidates);
        let restored = receipt(fixture.run(&recover));
        assert_eq!(text(&restored, "type"), "repository_source_backup_recover");
        assert_eq!(
            field(field(&restored, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
        recover.push("--resume".into());
        let resumed = receipt(fixture.run(&recover));
        assert_eq!(
            field(field(&resumed, "native"), "already_published"),
            &Value::Bool(true)
        );
        assert_eq!(
            field(field(&resumed, "native"), "resume_requested"),
            &Value::Bool(true)
        );
        let replayed = fixture.issue("recovered", format, false);
        for name in [
            "tx_id",
            "decision_sequence",
            "repository_commit_id",
            "refusal_record_id",
            "outcome",
        ] {
            assert_eq!(field(&replayed, name), field(&opened, name), "{name}");
        }
        assert_eq!(
            text(&fixture.issue("recovered", format, true), "outcome"),
            "committed"
        );
        assert_eq!(fs::read(fixture.0.join("newer.fgit")).unwrap(), bytes);
        assert_eq!(
            fs::read(fixture.0.join("newer.approval.json")).unwrap(),
            approval
        );
    }
}
