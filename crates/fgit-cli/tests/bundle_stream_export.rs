#![forbid(unsafe_code)]
#![cfg(unix)]
//! Native fg source export, independent file-backed verification, and recovery
//! through real command processes with no foreign executable available.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-stream-export-binary-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg"))
            .args(args)
            .current_dir(&self.0)
            .env("PATH", self.0.join("no-foreign-executables"))
            .output()
            .unwrap()
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
        success(self.run(&["init", "node", TENANT, REPOSITORY, format]));
        success(self.run(&[
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
            "seed-native-stream-export",
        ]));
    }

    fn export(&self, format: &str, path: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "bundle",
            "export",
            "node",
            TENANT,
            REPOSITORY,
            path,
            "--trusted-local",
            "--streaming",
            "--object-format",
            format,
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn refs(&self, format: &str) -> Vec<u8> {
        let output = self.run(&[
            "refs",
            "node",
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format,
        ]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn assert_no_stages(&self) {
        for entry in fs::read_dir(&self.0).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".fg-stream-export-"),
                "{name:?}"
            );
        }
    }

    fn scratch(&self) {
        fs::create_dir(self.0.join("scratch")).unwrap();
        fs::set_permissions(self.0.join("scratch"), fs::Permissions::from_mode(0o700)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert_eq!(report.lines().count(), 1, "{report}");
    report
}

fn refused(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("\"type\":\"bundle_error\""), "{error}");
    error
}

#[test]
fn binary_streams_both_hash_domains_into_file_verification_and_native_recovery() {
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
        fixture.scratch();
        let before = fixture.refs(format);
        let report = success(fixture.export(format, "stream.bundle", &[]));
        for required in [
            "\"type\":\"git_bundle_export\"",
            "\"streaming\":true",
            "\"object_count\":5",
            "\"node_closed\":true",
            "\"publication_state\":\"durable\"",
            "\"bundle_created\":true",
            "\"repository_changed\":false",
            "\"includes_forge_metadata\":false",
        ] {
            assert!(report.contains(required), "{report}");
        }
        let bytes = fs::read(fixture.0.join("stream.bundle")).unwrap();
        let digest = fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&bytes));
        assert!(report.contains(&format!("\"bundle_sha256\":\"{digest}\"")));
        assert!(report.contains(&format!("\"bundle_bytes\":{}", bytes.len())));
        assert_eq!(
            fs::metadata(fixture.0.join("stream.bundle"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let repeated = success(fixture.export(format, "again.bundle", &[]));
        assert_eq!(report, repeated);
        assert_eq!(fs::read(fixture.0.join("again.bundle")).unwrap(), bytes);
        let branch_pin = format!("refs/heads/main={tip}");
        let tag_pin = format!("refs/tags/v1={tag}");
        let verified = success(fixture.run(&[
            "bundle",
            "verify",
            "stream.bundle",
            "--file-backed",
            "--scratch-dir",
            "scratch",
            "--expect-sha256",
            &digest,
            "--expect-format",
            format,
            "--expect-ref",
            &branch_pin,
            "--expect-ref",
            &tag_pin,
            "--exact-refs",
        ]));
        assert!(verified.contains("\"object_graph_verified\":true"));
        assert!(verified.contains("\"caller_expectations_matched\":true"));
        let recovered = success(fixture.run(&[
            "bundle",
            "recover",
            "stream.bundle",
            "restored.git",
            "--trusted-local",
            "--head-ref",
            "refs/heads/main",
            "--file-backed",
            "--scratch-dir",
            "scratch",
            "--expect-sha256",
            &digest,
            "--expect-format",
            format,
        ]));
        assert!(recovered.contains("\"state\":\"durable\""));
        assert_eq!(
            fs::read(fixture.0.join("restored.git/HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        let packed = fs::read_to_string(fixture.0.join("restored.git/packed-refs")).unwrap();
        assert!(packed.contains(&format!("{tip} refs/heads/main")));
        assert!(packed.contains(&format!("{tag} refs/tags/v1")));
        assert_eq!(fixture.refs(format), before);
        assert_eq!(fs::read_dir(fixture.0.join("scratch")).unwrap().count(), 0);
        fixture.assert_no_stages();
    }
}

#[test]
fn real_source_limit_refusals_clean_partial_output_and_preserve_node() {
    let fixture = Fixture::new();
    fixture.seed("sha1");
    let before = fixture.refs("sha1");
    let retained = fixture.0.join("unrelated.partial");
    fs::write(&retained, b"operator residue").unwrap();
    for extra in [
        vec!["--max-objects", "1"],
        vec!["--max-refs", "1"],
        vec!["--max-edges", "1"],
        vec!["--max-compression-work", "1"],
    ] {
        let error = refused(fixture.export("sha1", "refused.bundle", &extra));
        assert!(error.contains("bundle_created=false"), "{error}");
        assert!(!fixture.0.join("refused.bundle").exists());
        assert_eq!(fs::read(&retained).unwrap(), b"operator residue");
        fixture.assert_no_stages();
    }
    success(fixture.export(
        "sha1",
        "allowed.bundle",
        &[
            "--max-objects",
            "5",
            "--max-refs",
            "3",
            "--max-output-mib",
            "1",
            "--max-expanded-mib",
            "1",
            "--max-object-mib",
            "1",
        ],
    ));
    assert_eq!(fixture.refs("sha1"), before);
    fixture.assert_no_stages();
}

#[test]
fn binary_collision_and_global_timeout_never_publish_a_partial_file() {
    let fixture = Fixture::new();
    fixture.seed("sha256");
    fs::write(fixture.0.join("existing.bundle"), b"preserve existing").unwrap();
    refused(fixture.export("sha256", "existing.bundle", &[]));
    assert_eq!(
        fs::read(fixture.0.join("existing.bundle")).unwrap(),
        b"preserve existing"
    );
    let error = refused(fixture.run(&[
        "--timeout-secs",
        "0.000000001",
        "bundle",
        "export",
        "node",
        TENANT,
        REPOSITORY,
        "stopped.bundle",
        "--streaming",
        "--trusted-local",
        "--object-format",
        "sha256",
    ]));
    assert!(error.contains("bundle_created=false"), "{error}");
    assert!(!fixture.0.join("stopped.bundle").exists());
    fixture.assert_no_stages();
}

#[test]
fn explicit_profile_and_bound_validation_precede_source_access() {
    let fixture = Fixture::new();
    for extra in [
        vec!["--max-output-mib", "16385"],
        vec!["--max-object-mib", "33"],
        vec!["--max-objects", "0"],
        vec!["--timeout-secs", "3601"],
        vec!["--max-refs", "1", "--max-refs", "2"],
    ] {
        refused(fixture.export("sha1", "invalid.bundle", &extra));
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
    }
    refused(fixture.run(&[
        "bundle",
        "export",
        "node",
        TENANT,
        REPOSITORY,
        "invalid.bundle",
        "--streaming",
    ]));
    for args in [
        vec!["bundle", "export", "--streaming", "--help"],
        vec!["bundle", "export", "--help"],
        vec!["bundle", "--help"],
    ] {
        let result = fixture.run(&args);
        assert_eq!(result.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&result.stdout).contains("--streaming"));
    }
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}
