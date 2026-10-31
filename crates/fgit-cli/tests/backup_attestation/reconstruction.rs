//! Real command composition from a native approval to catalog and repaired bytes.
use super::*;

fn recovery_arguments(
    export: &Value,
    operation: &str,
    input: &str,
    output: &str,
    scratch: &str,
    read_bytes: u64,
) -> Vec<String> {
    let mut args = strings(&[
        "backup",
        operation,
        input,
        output,
        "--trusted-local",
        "--expected-sha256",
        text(export, "sha256"),
        "--verification-root",
        scratch,
        "--verification-instance",
        "992",
        "--max-archive-bytes",
        &count(export, "bytes").to_string(),
        "--max-read-bytes",
        &read_bytes.to_string(),
        "--max-objects",
        "250000",
    ]);
    args.extend(Fixture::signed_flags(export));
    if operation == "reconstruct" {
        // Deliberately reverse CLI order: the damaged copy sorts first.
        args.extend(strings(&[
            "--replica",
            "b-intact.fgit",
            "--replica",
            "a-damaged.fgit",
        ]));
    }
    args
}

#[test]
fn native_catalog_and_reconstruction_charge_failed_copies_and_restore_the_original_bytes() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let export = fixture.export(format);
        let bytes = fs::read(fixture.0.join("source.fgit")).unwrap();
        let size = bytes.len() as u64;
        assert_eq!(size, count(&export, "bytes"));
        assert!(
            size < 4 * 1024 * 1024,
            "this process fixture has one catalog range"
        );
        receipt(fixture.run(&fixture.attest(
            &export,
            "source.approval.json",
            "attestation-scratch",
        )));
        let approval = fs::read(fixture.0.join("source.approval.json")).unwrap();
        let catalog = receipt(fixture.run(&recovery_arguments(
            &export,
            "catalog",
            "source.fgit",
            "source.chunks",
            "catalog-scratch",
            4 * size,
        )));
        assert_eq!(
            text(&catalog, "type"),
            "repository_backup_chunk_catalog_created"
        );
        assert_eq!(count(&catalog, "payload_bytes_read"), 4 * size);
        assert_eq!(count(&catalog, "chunks"), 1);
        assert!(!fixture.0.join("catalog-scratch").exists());

        let mut damaged = bytes.clone();
        damaged[0] ^= 1;
        fs::write(fixture.0.join("a-damaged.fgit"), &damaged).unwrap();
        fs::write(fixture.0.join("b-intact.fgit"), &bytes).unwrap();
        fs::remove_file(fixture.0.join("source.fgit")).unwrap();
        fs::remove_file(fixture.0.join("input.bundle")).unwrap();
        fs::remove_dir_all(fixture.0.join("node")).unwrap();

        let insufficient = recovery_arguments(
            &export,
            "reconstruct",
            "source.chunks",
            "budget-refused.fgit",
            "budget-scratch",
            4 * size,
        );
        let error = refused(fixture.run(&insufficient));
        assert!(
            error.contains("budget") || error.contains("read allowance"),
            "{error}"
        );
        assert!(!fixture.0.join("budget-refused.fgit").exists());
        assert!(!fixture.0.join("budget-scratch").exists());
        fixture.assert_no_stages();

        let recovered = receipt(fixture.run(&recovery_arguments(
            &export,
            "reconstruct",
            "source.chunks",
            "recovered.fgit",
            "recovery-scratch",
            5 * size,
        )));
        assert_eq!(text(&recovered, "type"), "repository_backup_reconstructed");
        assert_eq!(text(&recovered, "publication_state"), "durable");
        assert_eq!(text(&recovered, "sha256"), text(&export, "sha256"));
        assert_eq!(count(&recovered, "payload_bytes_read"), 5 * size);
        assert_eq!(count(&recovered, "payload_read_budget"), 5 * size);
        assert_eq!(count(&recovered, "maximum_read_bytes"), 65536);
        for flag in [
            "native_content_verified",
            "archive_bytes_authenticated",
            "object_graph_verified",
            "original_payload_commitments_verified",
            "node_closed",
            "scratch_removed",
        ] {
            assert_eq!(field(&recovered, flag), &Value::Bool(true), "{flag}");
        }
        for flag in [
            "new_signature_created",
            "catalog_is_authority",
            "destination_authority_published",
        ] {
            assert_eq!(field(&recovered, flag), &Value::Bool(false), "{flag}");
        }
        assert_eq!(fs::read(fixture.0.join("recovered.fgit")).unwrap(), bytes);
        assert_eq!(fs::read(fixture.0.join("a-damaged.fgit")).unwrap(), damaged);
        assert_eq!(fs::read(fixture.0.join("b-intact.fgit")).unwrap(), bytes);
        assert_eq!(
            fs::read(fixture.0.join("source.approval.json")).unwrap(),
            approval
        );
        assert!(!fixture.0.join("recovery-scratch").exists());
        let repeated = recovery_arguments(
            &export,
            "reconstruct",
            "source.chunks",
            "recovered.fgit",
            "repeated-scratch",
            5 * size,
        );
        refused(fixture.run(&repeated));
        assert_eq!(fs::read(fixture.0.join("recovered.fgit")).unwrap(), bytes);
        assert!(!fixture.0.join("repeated-scratch").exists());

        let mut restore = fixture.verify_or_restore(&export, "restore", "restored");
        restore[2] = "recovered.fgit".into();
        let restored = receipt(fixture.run(&restore));
        assert_eq!(field(&restored, "signature_verified"), &Value::Bool(true));
        assert_eq!(
            field(&restored, "reopened_and_verified"),
            &Value::Bool(true)
        );
        let mutation = fixture.issue("restored", format, false);
        assert_eq!(text(&mutation, "outcome"), "committed");
        fixture.assert_no_stages();
    }
}
