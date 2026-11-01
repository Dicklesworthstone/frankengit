//! Native replica publication and recovery through the actual fg executable.
use super::*;
use std::os::unix::fs::MetadataExt;

fn publication_arguments(export: &Value, allowance: u64) -> Vec<String> {
    let mut args = selection::selected_arguments(
        export,
        "replicate",
        "replicas",
        &[
            ("a-source.fgit", "anchor.approval.json"),
            ("z-copy.fgit", "source.approval.json"),
        ],
    );
    args.extend(strings(&[
        "--verification-root",
        "replica-preflight",
        "--max-read-bytes",
        &allowance.to_string(),
    ]));
    args
}

fn inode(path: &std::path::Path) -> (u64, u64) {
    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    (metadata.dev(), metadata.ino())
}

#[test]
fn native_replica_cli_retries_exact_files_then_recovers_after_source_loss_without_helpers() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let opened = fixture.issue("node", format, false);
        let export = fixture.export(format);
        receipt(fixture.run(&fixture.attest(&export, "source.approval.json", "attest")));
        let original = fs::read(fixture.0.join("source.fgit")).unwrap();
        let length = original.len() as u64;
        let approval = fs::read(fixture.0.join("source.approval.json")).unwrap();
        // Equivalent statements do not authorize a differently formatted
        // envelope to replace the first lexical pair's original control bytes.
        let anchor = [b" \n".as_slice(), approval.as_slice(), b"\n"].concat();
        fs::write(fixture.0.join("anchor.approval.json"), &anchor).unwrap();
        fs::rename(
            fixture.0.join("source.fgit"),
            fixture.0.join("a-source.fgit"),
        )
        .unwrap();
        fs::write(fixture.0.join("z-copy.fgit"), &original).unwrap();
        let directory = fixture.0.join("replicas");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = fs::canonicalize(directory).unwrap();

        let error = refused(fixture.run(&publication_arguments(&export, 5 * length - 1)));
        assert!(
            error.contains("allowance") || error.contains("budget"),
            "{error}"
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        assert!(!fixture.0.join("replica-preflight").exists());

        let published = receipt(fixture.run(&publication_arguments(&export, 5 * length)));
        assert_eq!(
            text(&published, "type"),
            "repository_backup_replica_published"
        );
        assert_eq!(text(&published, "publication_state"), "durable");
        for name in [
            "complete",
            "archive_created",
            "approval_created",
            "archive_readback_verified",
            "body_before_approval",
            "files_and_directory_synced",
        ] {
            assert_eq!(field(&published, name), &Value::Bool(true), "{name}");
        }
        for name in [
            "new_signature_created",
            "destination_authority_published",
            "routing_published",
            "complete_capsule_verified",
        ] {
            assert_eq!(field(&published, name), &Value::Bool(false), "{name}");
        }
        assert_eq!(count(&published, "payload_bytes_read"), 5 * length);
        assert_eq!(
            field(field(&published, "native"), "signature_verified"),
            &Value::Bool(true)
        );
        assert_eq!(
            field(field(&published, "native"), "scratch_removed"),
            &Value::Bool(true)
        );
        assert_eq!(
            count(field(&published, "selection"), "same_statement_replicas"),
            2
        );
        let candidate = field(&published, "candidate");
        let input = text(candidate, "input").to_owned();
        let control = text(candidate, "approval").to_owned();
        let archive_path = PathBuf::from(&input);
        let approval_path = PathBuf::from(&control);
        assert!(archive_path.starts_with(&directory));
        assert!(approval_path.starts_with(&directory));
        assert_eq!(fs::read(&archive_path).unwrap(), original);
        assert_eq!(fs::read(&approval_path).unwrap(), anchor);
        assert_eq!(
            archive_path.file_name().unwrap().to_str().unwrap(),
            format!("archive-sha256-{}.fgbackup", text(&export, "sha256"))
        );
        let archive_inode = inode(&archive_path);
        let approval_inode = inode(&approval_path);

        let error = refused(fixture.run(&publication_arguments(&export, 4 * length - 1)));
        assert!(
            error.contains("allowance") || error.contains("budget"),
            "{error}"
        );
        let retried = receipt(fixture.run(&publication_arguments(&export, 4 * length)));
        assert_eq!(count(&retried, "payload_bytes_read"), 4 * length);
        assert_eq!(field(&retried, "candidate"), candidate);
        assert_eq!(field(&retried, "archive_created"), &Value::Bool(false));
        assert_eq!(field(&retried, "approval_created"), &Value::Bool(false));
        assert_eq!(inode(&archive_path), archive_inode);
        assert_eq!(inode(&approval_path), approval_inode);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);

        fs::remove_dir_all(fixture.0.join("node")).unwrap();
        for name in [
            "input.bundle",
            "a-source.fgit",
            "z-copy.fgit",
            "source.approval.json",
            "anchor.approval.json",
            "private.pem",
        ] {
            fs::remove_file(fixture.0.join(name)).unwrap();
        }
        let recovered = receipt(fixture.run(&selection::selected_arguments(
            &export,
            "recover",
            "recovered",
            &[(input.as_str(), control.as_str())],
        )));
        assert_eq!(
            field(field(&recovered, "native"), "reopened_and_verified"),
            &Value::Bool(true)
        );
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
        assert_eq!(fs::read(&archive_path).unwrap(), original);
        assert_eq!(fs::read(&approval_path).unwrap(), anchor);
        assert!(!fixture.0.join("replica-preflight").exists());
        fixture.assert_no_stages();
    }
}
