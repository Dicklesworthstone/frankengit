//! Persistent anti-rollback behavior across separate real fg invocations.
use super::selection::selected_arguments;
use super::*;

fn witness_arguments(export: &Value, operation: &str, floor: u64) -> Vec<String> {
    let mut args = strings(&["backup", "witness", operation, "witness", "--trusted-local"]);
    args.extend(Fixture::signed_flags(export).into_iter().skip(2));
    replace(&mut args, "--minimum-head-generation", &floor.to_string());
    args
}

fn witnessed(
    export: &Value,
    operation: &str,
    destination: &str,
    candidates: &[(&str, &str)],
) -> Vec<String> {
    let mut args = selected_arguments(export, operation, destination, candidates);
    args.extend(strings(&["--witness", "witness"]));
    args
}

fn inspect(fixture: &Fixture, export: &Value, floor: u64) -> Value {
    let value = receipt(fixture.run(&witness_arguments(export, "inspect", floor)));
    assert_eq!(text(&value, "type"), "repository_backup_witness_inspection");
    assert_eq!(field(&value, "repository_changed"), &Value::Bool(false));
    assert!(!fixture.0.join("witness/.witness-lock").exists());
    value
}

#[test]
fn native_witness_remembers_unavailable_checkpoints_conflicts_and_stronger_floors_across_processes()
{
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let older = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&older, "older.approval.json", "attest-old")));
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("older.fgit")).unwrap();

        let opened = fixture.issue("node", format, false);
        let newer = fixture.export(format);
        let generation = count(&newer, "head_generation");
        assert!(generation > count(&older, "head_generation"));
        receipt(fixture.run(&fixture.attest(&newer, "newer.approval.json", "attest-new")));
        let mut conflict = fixture.attest(&newer, "conflict.approval.json", "attest-conflict");
        replace(&mut conflict, "--expires-at", "9998-12-31T23:59:59Z");
        receipt(fixture.run(&conflict));
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("newer.fgit")).unwrap();
        fs::remove_dir_all(fixture.0.join("node")).unwrap();
        fs::remove_file(fixture.0.join("input.bundle")).unwrap();

        let old = [("older.fgit", "older.approval.json")];
        // Normal witnessed use never initializes a missing trust directory.
        refused(fixture.run(&witnessed(&older, "recover", "uninitialized", &old)));
        assert!(!fixture.0.join("witness").exists());
        assert!(!fixture.0.join("uninitialized").exists());
        let initialized = receipt(fixture.run(&witness_arguments(&newer, "init", 1)));
        assert_eq!(
            text(&initialized, "type"),
            "repository_backup_witness_initialized"
        );
        let empty = fs::read(fixture.0.join("witness/witness.json")).unwrap();
        refused(fixture.run(&witness_arguments(&newer, "init", 1)));
        assert_eq!(
            fs::read(fixture.0.join("witness/witness.json")).unwrap(),
            empty
        );

        let permitted_old =
            receipt(fixture.run(&witnessed(&older, "verify-selected", "old-check", &old)));
        assert_eq!(
            field(
                field(&permitted_old, "selection"),
                "persistent_high_water_enforced"
            ),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("old-check").exists());

        // The higher signature becomes durable recovery knowledge before the
        // missing payload is inspected. An ordinary pre-native error releases
        // its lease, while the remembered generation survives the next process.
        let unavailable = [
            ("older.fgit", "older.approval.json"),
            ("unavailable-newer.fgit", "newer.approval.json"),
        ];
        refused(fixture.run(&witnessed(&newer, "recover", "missing-new", &unavailable)));
        assert!(!fixture.0.join("missing-new").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());
        let after_missing = inspect(&fixture, &newer, 1);
        assert_eq!(
            text(
                field(&after_missing, "witness"),
                "highest_observed_generation"
            ),
            generation.to_string()
        );
        let old_error = refused(fixture.run(&witnessed(&older, "recover", "rollback", &old)));
        assert!(old_error.contains("witness"), "{old_error}");
        assert!(!fixture.0.join("rollback").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());

        let current = [
            ("older.fgit", "older.approval.json"),
            ("newer.fgit", "newer.approval.json"),
        ];
        let mut recover = witnessed(&newer, "recover", "recovered", &current);
        let restored = receipt(fixture.run(&recover));
        assert_eq!(
            field(
                field(&restored, "selection"),
                "persistent_high_water_enforced"
            ),
            &Value::Bool(true)
        );
        assert_eq!(
            field(field(&restored, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("witness/.witness-lock").exists());
        recover.push("--resume".into());
        let resumed = receipt(fixture.run(&recover));
        assert_eq!(
            field(field(&resumed, "native"), "already_published"),
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

        // A later invocation cannot hide a conflict by supplying only one of
        // the two highest statements. The original approval bytes stay intact.
        let ambiguous = [
            ("newer.fgit", "newer.approval.json"),
            ("newer.fgit", "conflict.approval.json"),
        ];
        refused(fixture.run(&witnessed(&newer, "recover", "conflicted", &ambiguous)));
        assert!(!fixture.0.join("conflicted").exists());
        let conflict_state = inspect(&fixture, &newer, 1);
        assert_eq!(
            field(field(&conflict_state, "witness"), "conflicting_statements"),
            &Value::Bool(true)
        );
        refused(fixture.run(&witnessed(&newer, "recover", "omitted-conflict", &current)));
        assert!(!fixture.0.join("omitted-conflict").exists());

        // A real subsequent accepted decision, exported from the recovered
        // repository and natively attested, can supersede the old conflict.
        assert_eq!(
            text(&fixture.issue("recovered", format, true), "outcome"),
            "committed"
        );
        let successor = receipt(fixture.fg(&[
            "backup",
            "export",
            "recovered",
            "successor.fgit",
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format,
        ]));
        assert!(count(&successor, "head_generation") > generation);
        let mut attest = fixture.attest(&successor, "successor.approval.json", "attest-successor");
        attest[2] = "successor.fgit".into();
        receipt(fixture.run(&attest));
        let mut successor_check = witnessed(
            &successor,
            "verify-selected",
            "successor-check",
            &[("successor.fgit", "successor.approval.json")],
        );
        // This archive came from destination instance 993; its verifier must
        // own a distinct authority-store instance just as on the original run.
        replace(&mut successor_check, "--verification-instance", "994");
        receipt(fixture.run(&successor_check));
        let next_generation = count(&successor, "head_generation");
        let next = inspect(&fixture, &successor, 1);
        assert_eq!(
            text(field(&next, "witness"), "highest_observed_generation"),
            next_generation.to_string()
        );
        assert_eq!(
            field(field(&next, "witness"), "conflicting_statements"),
            &Value::Bool(false)
        );

        let stronger = inspect(&fixture, &successor, next_generation);
        assert_eq!(
            text(field(&stronger, "witness"), "minimum_head_generation"),
            next_generation.to_string()
        );
        let retained = fs::read(fixture.0.join("witness/witness.json")).unwrap();
        refused(fixture.run(&witness_arguments(&successor, "inspect", 1)));
        assert_eq!(
            fs::read(fixture.0.join("witness/witness.json")).unwrap(),
            retained
        );
        assert!(!fixture.0.join("witness/.witness-lock").exists());
    }
}
