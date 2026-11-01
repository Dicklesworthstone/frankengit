//! Explicit replica acquisition through separate real native fg processes.
use super::selection::selected_arguments;
use super::*;

fn replicated(
    export: &Value,
    operation: &str,
    destination: &str,
    candidates: &[(&str, &str)],
    maximum: u64,
) -> Vec<String> {
    let mut args = selected_arguments(export, operation, destination, candidates);
    args.extend(strings(&[
        "--replica-failover",
        "--max-read-bytes",
        &maximum.to_string(),
        "--witness",
        "witness",
    ]));
    args
}

#[test]
fn native_replica_recovery_preserves_one_approval_and_resume_binding_across_payload_sources() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let older = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&older, "older.approval.json", "old-attest")));
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("older.fgit")).unwrap();

        let opened = fixture.issue("node", format, false);
        let newer = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&newer, "anchor.approval.json", "new-attest")));
        let bytes = fs::read(fixture.0.join("source.fgit")).unwrap();
        let length = bytes.len() as u64;
        let approval = fs::read(fixture.0.join("anchor.approval.json")).unwrap();
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("a-copy.fgit")).unwrap();
        fs::write(fixture.0.join("z-copy.fgit"), &bytes).unwrap();
        // The statement is identical, but the second envelope's original bytes
        // differ. Payload failover must not replace the selected approval.
        fs::write(
            fixture.0.join("copy.approval.json"),
            [b" \n".as_slice(), approval.as_slice()].concat(),
        )
        .unwrap();
        fs::remove_dir_all(fixture.0.join("node")).unwrap();
        fs::remove_file(fixture.0.join("input.bundle")).unwrap();

        let mut initialize = strings(&["backup", "witness", "init", "witness", "--trusted-local"]);
        initialize.extend(Fixture::signed_flags(&newer).into_iter().skip(2));
        replace(&mut initialize, "--minimum-head-generation", "1");
        receipt(fixture.run(&initialize));
        let candidates = [
            ("z-copy.fgit", "copy.approval.json"),
            ("older.fgit", "older.approval.json"),
            ("a-copy.fgit", "anchor.approval.json"),
        ];

        let mut corrupted = bytes.clone();
        corrupted[0] ^= 0x80;
        fs::write(fixture.0.join("a-copy.fgit"), &corrupted).unwrap();
        // Without the opt-in, the existing deterministic one-copy policy stays.
        refused(fixture.run(&selected_arguments(
            &newer,
            "verify-selected",
            "strict-refusal",
            &candidates,
        )));
        assert!(!fixture.0.join("strict-refusal").exists());
        let too_small = refused(fixture.run(&replicated(
            &newer,
            "verify-selected",
            "bounded-refusal",
            &candidates,
            4 * length - 1,
        )));
        assert!(
            too_small.contains("allowance") || too_small.contains("budget"),
            "{too_small}"
        );
        assert!(!fixture.0.join("bounded-refusal").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());
        let verified = receipt(fixture.run(&replicated(
            &newer,
            "verify-selected",
            "verified",
            &candidates,
            4 * length,
        )));
        let selection = field(&verified, "selection");
        let acquisition = field(&verified, "acquisition");
        assert_eq!(count(selection, "selected_index"), 0);
        assert_eq!(count(selection, "same_statement_replicas"), 2);
        assert_eq!(field(selection, "replica_failover"), &Value::Bool(true));
        assert_eq!(count(acquisition, "acquired_candidate_index"), 2);
        assert_eq!(count(acquisition, "candidates_attempted"), 2);
        assert_eq!(count(acquisition, "payload_bytes_read"), 4 * length);
        assert_eq!(text(acquisition, "read_budget_scope"), "all_archive_passes");
        let original_binding = text(selection, "approval_sha256").to_owned();
        assert!(!fixture.0.join("verified").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());

        // The healthy older backup does not grant permission to change the
        // highest authenticated checkpoint's independent expected checksum.
        refused(fixture.run(&replicated(
            &older,
            "recover",
            "lower-pin",
            &candidates,
            6 * length,
        )));
        assert!(!fixture.0.join("lower-pin").exists());
        fs::remove_file(fixture.0.join("a-copy.fgit")).unwrap();
        let mut recover = replicated(&newer, "recover", "recovered", &candidates, 6 * length);
        let restored = receipt(fixture.run(&recover));
        assert_eq!(
            text(field(&restored, "selection"), "approval_sha256"),
            original_binding
        );
        assert_eq!(
            count(field(&restored, "acquisition"), "acquired_candidate_index"),
            2
        );
        assert_eq!(
            count(field(&restored, "acquisition"), "payload_bytes_read"),
            6 * length
        );
        assert_eq!(
            field(field(&restored, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("witness/.witness-lock").exists());

        // A later exact resume uses another physical copy while retaining the
        // original envelope and signed intent, even though the last source is gone.
        fs::write(fixture.0.join("a-copy.fgit"), &bytes).unwrap();
        fs::remove_file(fixture.0.join("z-copy.fgit")).unwrap();
        recover.push("--resume".into());
        let resumed = receipt(fixture.run(&recover));
        assert_eq!(
            text(field(&resumed, "selection"), "approval_sha256"),
            original_binding
        );
        assert_eq!(
            count(field(&resumed, "acquisition"), "acquired_candidate_index"),
            0
        );
        assert_eq!(
            count(field(&resumed, "acquisition"), "payload_bytes_read"),
            3 * length
        );
        assert_eq!(
            field(field(&resumed, "native"), "already_published"),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("witness/.witness-lock").exists());
        let replayed = fixture.issue("recovered", format, false);
        for name in [
            "tx_id",
            "decision_sequence",
            "repository_commit_id",
            "outcome",
        ] {
            assert_eq!(field(&replayed, name), field(&opened, name), "{name}");
        }
        assert_eq!(
            text(&fixture.issue("recovered", format, true), "outcome"),
            "committed"
        );
        assert_eq!(
            fs::read(fixture.0.join("anchor.approval.json")).unwrap(),
            approval
        );
        fixture.assert_no_stages();
    }
}
