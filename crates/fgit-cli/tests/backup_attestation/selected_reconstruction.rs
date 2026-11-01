//! Selected reconstruction feeds its private archive directly into native recovery.
use super::reconstruction::recovery_arguments;
use super::selection::selected_arguments;
use super::*;

fn reconstruct_selected(
    export: &Value,
    operation: &str,
    destination: &str,
    reconstruction_root: &str,
    candidates: &[(&str, &str)],
    maximum: u64,
) -> Vec<String> {
    let mut args = selected_arguments(export, operation, destination, candidates);
    args.extend(strings(&[
        "--reconstruct-catalog",
        "source.chunks",
        "--reconstruction-root",
        reconstruction_root,
        "--max-read-bytes",
        &maximum.to_string(),
        "--witness",
        "witness",
    ]));
    args
}

#[test]
fn native_selected_reconstruction_recovers_and_resumes_under_the_original_signed_approval() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let older = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&older, "older.approval.json", "old-attest")));
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("older.fgit")).unwrap();
        let opened = fixture.issue("node", format, false);
        let newer = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&newer, "source.approval.json", "new-attest")));
        let bytes = fs::read(fixture.0.join("source.fgit")).unwrap();
        let length = bytes.len() as u64;
        assert!(length < 4 * 1024 * 1024, "one native catalog range");
        let approval = fs::read(fixture.0.join("source.approval.json")).unwrap();
        let catalog = receipt(fixture.run(&recovery_arguments(
            &newer,
            "catalog",
            "source.fgit",
            "source.chunks",
            "catalog-check",
            4 * length,
        )));
        assert_eq!(count(&catalog, "chunks"), 1);
        fs::write(
            fixture.0.join("copy.approval.json"),
            [b" \n".as_slice(), approval.as_slice()].concat(),
        )
        .unwrap();
        let mut damaged = bytes.clone();
        damaged[0] ^= 1;
        fs::write(fixture.0.join("a-copy.fgit"), &damaged).unwrap();
        fs::rename(fixture.0.join("source.fgit"), fixture.0.join("z-copy.fgit")).unwrap();
        fs::remove_dir_all(fixture.0.join("node")).unwrap();
        fs::remove_file(fixture.0.join("input.bundle")).unwrap();
        let mut initialize = strings(&["backup", "witness", "init", "witness", "--trusted-local"]);
        initialize.extend(Fixture::signed_flags(&newer).into_iter().skip(2));
        replace(&mut initialize, "--minimum-head-generation", "1");
        receipt(fixture.run(&initialize));
        let candidates = [
            ("z-copy.fgit", "copy.approval.json"),
            ("older.fgit", "older.approval.json"),
            ("a-copy.fgit", "source.approval.json"),
        ];

        let verified = receipt(fixture.run(&reconstruct_selected(
            &newer,
            "verify-selected",
            "verified",
            "verify-input",
            &candidates,
            5 * length,
        )));
        let selection = field(&verified, "selection");
        let acquisition = field(&verified, "acquisition");
        assert_eq!(count(selection, "selected_index"), 0);
        assert_eq!(count(selection, "same_statement_replicas"), 2);
        assert_eq!(field(selection, "range_reconstruction"), &Value::Bool(true));
        assert_eq!(field(selection, "replica_failover"), &Value::Bool(false));
        assert_eq!(field(acquisition, "root_removed"), &Value::Bool(true));
        assert_eq!(
            field(acquisition, "intermediate_archive_published"),
            &Value::Bool(false)
        );
        assert_eq!(text(acquisition, "method"), "reconstructed_ranges");
        assert_eq!(count(acquisition, "payload_bytes_read"), 5 * length);
        assert_eq!(text(acquisition, "read_budget_scope"), "all_archive_passes");
        let original_binding = text(selection, "approval_sha256").to_owned();
        assert!(!fixture.0.join("verified").exists());
        assert!(!fixture.0.join("verify-input").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());

        // A failed range still spends its bytes. Refuse before native entry if
        // the next source cannot leave the entire six-pass restore allowance.
        let error = refused(fixture.run(&reconstruct_selected(
            &newer,
            "recover",
            "bounded-destination",
            "bounded-input",
            &candidates,
            8 * length - 1,
        )));
        assert!(
            error.contains("allowance") || error.contains("budget"),
            "{error}"
        );
        assert!(!fixture.0.join("bounded-destination").exists());
        assert!(!fixture.0.join("bounded-input").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());

        let mut recover = reconstruct_selected(
            &newer,
            "recover",
            "recovered",
            "recover-input",
            &candidates,
            8 * length,
        );
        let restored = receipt(fixture.run(&recover));
        assert_eq!(
            text(field(&restored, "selection"), "approval_sha256"),
            original_binding
        );
        assert_eq!(
            count(field(&restored, "acquisition"), "payload_bytes_read"),
            8 * length
        );
        assert_eq!(
            field(field(&restored, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("recover-input").exists());
        assert!(!fixture.0.join("witness/.witness-lock").exists());
        assert_eq!(fs::read(fixture.0.join("a-copy.fgit")).unwrap(), damaged);

        // A different private input root and a different available source do
        // not replace the exact original approval in the durable resume intent.
        fs::write(fixture.0.join("a-copy.fgit"), &bytes).unwrap();
        fs::remove_file(fixture.0.join("z-copy.fgit")).unwrap();
        replace(&mut recover, "--reconstruction-root", "resume-input");
        replace(&mut recover, "--max-read-bytes", &(7 * length).to_string());
        recover.push("--resume".into());
        let resumed = receipt(fixture.run(&recover));
        assert_eq!(
            text(field(&resumed, "selection"), "approval_sha256"),
            original_binding
        );
        assert_eq!(
            count(field(&resumed, "acquisition"), "payload_bytes_read"),
            4 * length
        );
        assert_eq!(
            field(field(&resumed, "native"), "already_published"),
            &Value::Bool(true)
        );
        assert!(!fixture.0.join("resume-input").exists());
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
            fs::read(fixture.0.join("source.approval.json")).unwrap(),
            approval
        );
        fixture.assert_no_stages();
    }
}
