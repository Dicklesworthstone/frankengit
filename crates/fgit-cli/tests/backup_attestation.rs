#![forbid(unsafe_code)]
#![cfg(unix)]
//! Native backup issuance and signed recovery through actual fg processes.
//! The only signing key is the public RFC 8032 test vector, never a real secret.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_schema::json::{self, Value};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n";
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-backup-attestation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [("private.pem", PRIVATE_PEM), ("public.pem", PUBLIC_PEM)] {
            let path = root.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(root)
    }

    fn run(&self, args: &[String]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg"))
            .args(args)
            .current_dir(&self.0)
            .env("PATH", self.0.join("no-external-programs"))
            .output()
            .unwrap()
    }

    fn fg(&self, args: &[&str]) -> Output {
        self.run(&strings(args))
    }

    fn seed(&self, format: &str) {
        let encoded = match format {
            "sha1" => {
                include_str!("../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex")
            }
            "sha256" => {
                include_str!("../../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex")
            }
            _ => panic!("fixture format"),
        };
        let bytes: Vec<_> = encoded
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        fs::write(self.0.join("input.bundle"), bytes).unwrap();
        accepted(self.fg(&["init", "node", TENANT, REPOSITORY, format]));
        accepted(self.fg(&[
            "bundle",
            "import",
            "node",
            TENANT,
            REPOSITORY,
            "input.bundle",
            "--trusted-local",
            "--object-format",
            format,
            "--principal",
            PRINCIPAL,
            "--idempotency-key",
            "attestation-source-import",
        ]));
    }

    fn issue(&self, root: &str, format: &str, close: bool) -> Value {
        let mut args = vec![
            "issue",
            if close { "close" } else { "open" },
            root,
            TENANT,
            REPOSITORY,
            "7",
            "--trusted-local",
            "--object-format",
            format,
            "--principal",
            PRINCIPAL,
            "--idempotency-key",
            if close {
                "attestation-after-restore"
            } else {
                "attestation-open"
            },
            "--expected-version",
            if close { "1" } else { "0" },
        ];
        if !close {
            args.extend([
                "--title",
                "Recover signed source",
                "--body",
                "Forge state survives source loss",
            ]);
        }
        receipt(self.fg(&args))
    }

    fn export(&self, format: &str) -> Value {
        receipt(self.fg(&[
            "backup",
            "export",
            "node",
            "source.fgit",
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format,
            "--max-objects",
            "250000",
        ]))
    }

    fn attest(&self, export: &Value, output: &str, scratch: &str) -> Vec<String> {
        strings(&[
            "backup",
            "attest",
            "source.fgit",
            output,
            scratch,
            "--private-key",
            "private.pem",
            "--trusted-local",
            "--expected-sha256",
            text(export, "sha256"),
            "--verification-instance",
            "990",
            "--tenant-id",
            TENANT,
            "--repository-id",
            REPOSITORY,
            "--incarnation-id",
            text(export, "incarnation_id"),
            "--object-format",
            text(export, "object_format"),
            "--head-generation",
            &count(export, "head_generation").to_string(),
            "--expires-at",
            "9999-12-31T23:59:59Z",
            "--max-archive-bytes",
            "16777216",
            "--max-blob-bytes",
            "1048576",
            "--max-objects",
            "250000",
            "--timeout-secs",
            "300",
        ])
    }

    fn signed_flags(export: &Value) -> Vec<String> {
        strings(&[
            "--approval",
            "source.approval.json",
            "--trust-key",
            "public.pem",
            "--tenant-id",
            TENANT,
            "--repository-id",
            REPOSITORY,
            "--incarnation-id",
            text(export, "incarnation_id"),
            "--object-format",
            text(export, "object_format"),
            "--minimum-head-generation",
            &count(export, "head_generation").to_string(),
        ])
    }

    fn verify_or_restore(&self, export: &Value, operation: &str, destination: &str) -> Vec<String> {
        let mut args = strings(&[
            "backup",
            operation,
            "source.fgit",
            destination,
            "--trusted-local",
            "--expected-sha256",
            text(export, "sha256"),
            if operation == "verify" {
                "--verification-instance"
            } else {
                "--destination-instance"
            },
            "991",
            "--max-objects",
            "250000",
        ]);
        args.extend(Self::signed_flags(export));
        args
    }

    fn assert_no_stages(&self) {
        for entry in fs::read_dir(&self.0).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".fg-"),
                "unsettled private stage: {name:?}"
            );
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}
fn accepted(output: Output) -> Vec<u8> {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn receipt(output: Output) -> Value {
    json::parse(&accepted(output)).expect("complete native JSON receipt")
}
fn refused(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let value = json::parse(&output.stderr).expect("complete native refusal");
    assert_eq!(text(&value, "type"), "repository_backup_error");
    assert_eq!(field(&value, "complete"), &Value::Bool(false));
    let error = text(&value, "error").to_owned();
    assert!(!error.contains(PRIVATE_PEM));
    assert!(!error.contains("MC4CAQAwBQYDK2VwBCIEIJ1"));
    error
}
fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &value.object().expect("JSON object")[name]
}
fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).text().expect("JSON string")
}
fn count(value: &Value, name: &str) -> u64 {
    field(value, name).unsigned().expect("JSON integer")
}
fn replace(args: &mut [String], flag: &str, value: &str) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    args[at + 1] = value.to_owned();
}

#[test]
fn native_attestation_restores_source_forge_and_retained_outcomes_without_helpers() {
    for (format, tip, tag) in [
        (
            "sha1",
            "8e66527465821b289d8ad275784255bc8825617a",
            "fdf36c252d4e297cc62a161ba48176f6dcafa08a",
        ),
        (
            "sha256",
            "c2a1cfc79b851e01921198e44377712b8ce0593cafe564873b9de729af20ec78",
            "91cf791e6e424d4f8449c7f57012ce46de9c7053ed326b0c34744d522c9da04d",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.seed(format);
        let opened = fixture.issue("node", format, false);
        let checkpoint = receipt(fixture.fg(&[
            "checkpoint",
            "outcomes",
            "node",
            TENANT,
            REPOSITORY,
            "--trusted-local",
        ]));
        assert_eq!(field(&checkpoint, "complete"), &Value::Bool(true));
        let export = fixture.export(format);
        let original = fs::read(fixture.0.join("source.fgit")).unwrap();
        // Every remaining operation must recover from the independent archive.
        fs::remove_dir_all(fixture.0.join("node")).unwrap();
        fs::remove_file(fixture.0.join("input.bundle")).unwrap();

        let args = fixture.attest(&export, "source.approval.json", "attest-scratch");
        let signed = receipt(fixture.run(&args));
        assert_eq!(text(&signed, "type"), "repository_backup_approval_created");
        for name in [
            "complete",
            "native_content_verified",
            "archive_bytes_authenticated",
            "object_graph_verified",
            "original_payload_commitments_verified",
            "node_closed",
            "scratch_removed",
        ] {
            assert_eq!(field(&signed, name), &Value::Bool(true), "{name}");
        }
        assert_eq!(text(&signed, "publication_state"), "durable");
        assert!(text(&signed, "trusted_key_id").starts_with("sha256:"));
        let statement = field(&signed, "statement");
        assert_eq!(
            text(statement, "incarnation_id"),
            text(&export, "incarnation_id")
        );
        assert_eq!(
            text(statement, "head_generation"),
            count(&export, "head_generation").to_string()
        );
        assert_eq!(
            text(field(statement, "artifact"), "sha256"),
            text(&export, "sha256")
        );
        assert_eq!(fs::read(fixture.0.join("source.fgit")).unwrap(), original);
        assert!(!fixture.0.join("attest-scratch").exists());

        let approval = fs::read(fixture.0.join("source.approval.json")).unwrap();
        assert_eq!(
            fs::metadata(fixture.0.join("source.approval.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        refused(fixture.run(&args));
        assert_eq!(
            fs::read(fixture.0.join("source.approval.json")).unwrap(),
            approval
        );

        let verified =
            receipt(fixture.run(&fixture.verify_or_restore(&export, "verify", "verify-scratch")));
        assert_eq!(field(&verified, "signature_verified"), &Value::Bool(true));
        assert_eq!(field(&verified, "scratch_removed"), &Value::Bool(true));
        assert!(!fixture.0.join("verify-scratch").exists());
        let restored =
            receipt(fixture.run(&fixture.verify_or_restore(&export, "restore", "restored")));
        assert_eq!(field(&restored, "signature_verified"), &Value::Bool(true));
        assert_eq!(
            field(&restored, "reopened_and_verified"),
            &Value::Bool(true)
        );
        let refs = String::from_utf8(accepted(fixture.fg(&[
            "refs",
            "restored",
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format,
        ])))
        .unwrap();
        assert!(refs.contains(tip), "{refs}");
        assert!(refs.contains(tag), "{refs}");
        let replayed = fixture.issue("restored", format, false);
        for name in [
            "tx_id",
            "decision_sequence",
            "repository_commit_id",
            "refusal_record_id",
            "outcome",
        ] {
            assert_eq!(field(&replayed, name), field(&opened, name), "{name}");
        }
        let closed = fixture.issue("restored", format, true);
        assert_eq!(text(&closed, "outcome"), "committed");
        assert_ne!(field(&closed, "tx_id"), field(&opened, "tx_id"));
        fixture.assert_no_stages();
    }
}

#[test]
fn attestation_refusals_preserve_outputs_and_do_not_use_a_key_for_false_declarations() {
    let fixture = Fixture::new();
    fixture.seed("sha256");
    let export = fixture.export("sha256");
    let original = fs::read(fixture.0.join("source.fgit")).unwrap();
    let base = fixture.attest(&export, "approval.json", "scratch");
    for (flag, value) in [
        ("--tenant-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("--head-generation", "18446744073709551615"),
        ("--max-objects", "1"),
        ("--expected-sha256", &"00".repeat(32)),
    ] {
        let mut args = base.clone();
        replace(&mut args, flag, value);
        let with_available_key = refused(fixture.run(&args));
        let scratch = fixture.0.join("scratch");
        if scratch.exists() {
            fs::remove_dir_all(&scratch).unwrap();
        }
        replace(&mut args, "--private-key", "missing-private-key.pem");
        let error = refused(fixture.run(&args));
        assert_eq!(
            error, with_available_key,
            "key availability changed the preflight refusal for {flag}"
        );
        assert!(!fixture.0.join("approval.json").exists());
        assert_eq!(fs::read(fixture.0.join("source.fgit")).unwrap(), original);
        // A preflight refusal may retain its exclusively owned diagnostic scratch.
        if scratch.exists() {
            fs::remove_dir_all(scratch).unwrap();
        }
        fixture.assert_no_stages();
    }
    fs::set_permissions(
        fixture.0.join("private.pem"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    refused(fixture.run(&base));
    assert!(!fixture.0.join("approval.json").exists());
    fs::set_permissions(
        fixture.0.join("private.pem"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let scratch = fixture.0.join("scratch");
    if scratch.exists() {
        fs::remove_dir_all(scratch).unwrap();
    }
    let signed = receipt(fixture.run(&base));
    assert_eq!(
        field(&signed, "native_content_verified"),
        &Value::Bool(true)
    );
    fixture.assert_no_stages();
}
