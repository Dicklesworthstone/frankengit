#![forbid(unsafe_code)]
//! Execute the fg binary, not an alternate engine or a mocked dispatcher.
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

// Independently generated Python hashlib/zlib full bundles, each containing
// one blob (hello + LF) advertised at refs/tags/blob in the named hash domain.
const SHA1: &str = "23207632206769742062756e646c650a6365303133363235303330626138646261393036663735363936376639653963613339343436346120726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fde0412401f4a9e5f05411f44eaf9c86d46096746";
const SHA256: &str = "23207633206769742062756e646c650a406f626a6563742d666f726d61743d7368613235360a3263663864383364396565323935343362333461383737323734323166646563623765336633613138336433333736333930323564653537366462396562623420726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fa3c5e2a560d25012da705ae0890a05c5c36957d4274db457f92b31bf33510557";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "fg-offline-bundle-binary-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg"))
            .args(args)
            .current_dir(&self.0)
            .env("HOME", &self.0)
            .env("PATH", self.0.join("no-programs"))
            .output()
            .unwrap()
    }
    fn write(&self, hex: &str) -> Vec<u8> {
        let bytes: Vec<_> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        std::fs::write(self.0.join("source.bundle"), &bytes).unwrap();
        bytes
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn binary_verifies_both_formats_without_git_credentials_or_node_storage() {
    for (encoded, format) in [(SHA1, "sha1"), (SHA256, "sha256")] {
        let fixture = Fixture::new();
        let original = fixture.write(encoded);
        let result = fixture.run(&["bundle", "verify", "source.bundle"]);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stderr.is_empty());
        let text = String::from_utf8(result.stdout).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"type\":\"git_bundle_verification\""));
        assert!(text.contains(&format!("\"object_format\":\"{format}\"")));
        assert!(text.contains("\"object_graph_verified\":true"));
        assert!(text.contains("\"repository_opened\":false"));
        assert!(text.contains("\"origin_authenticated\":false"));
        assert_eq!(
            std::fs::read(fixture.0.join("source.bundle")).unwrap(),
            original
        );
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
}

#[test]
fn binary_corruption_and_unsupported_options_return_no_success_on_stdout() {
    let fixture = Fixture::new();
    let mut input = fixture.write(SHA1);
    *input.last_mut().unwrap() ^= 1;
    std::fs::write(fixture.0.join("source.bundle"), &input).unwrap();
    for args in [
        vec!["bundle", "verify", "source.bundle"],
        vec!["bundle", "verify", "source.bundle", "--force"],
        vec!["bundle", "verify", "missing.bundle", "--max-input-mib", "0"],
    ] {
        let result = fixture.run(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("\"type\":\"bundle_error\""));
    }
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn binary_help_and_literal_path_require_no_repository_configuration() {
    let fixture = Fixture::new();
    for args in [vec!["bundle", "verify", "--help"], vec!["bundle", "--help"]] {
        let result = fixture.run(&args);
        assert_eq!(result.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&result.stdout).contains("fg bundle verify"));
    }
    fixture.write(SHA256);
    std::fs::rename(
        fixture.0.join("source.bundle"),
        fixture.0.join("--literal.bundle"),
    )
    .unwrap();
    let result = fixture.run(&["bundle", "verify", "--", "--literal.bundle"]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[cfg(unix)]
fn private_scratch(fixture: &Fixture) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let directory = fixture.0.join("scratch");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[cfg(unix)]
#[test]
fn binary_file_backed_verification_checks_both_formats_and_cleans_private_scratch() {
    for (encoded, format) in [(SHA1, "sha1"), (SHA256, "sha256")] {
        let fixture = Fixture::new();
        let original = fixture.write(encoded);
        let scratch = private_scratch(&fixture);
        let digest = fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&original));
        let result = fixture.run(&[
            "bundle",
            "verify",
            "source.bundle",
            "--max-input-mib",
            "512",
            "--max-expanded-mib",
            "512",
            "--scratch-dir",
            "scratch",
            "--file-backed",
            "--expect-sha256",
            &digest,
        ]);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report = String::from_utf8(result.stdout).unwrap();
        assert_eq!(report.lines().count(), 1);
        assert!(report.contains(&format!("\"object_format\":\"{format}\"")));
        assert!(report.contains("\"storage_profile\":\"file-backed-native-full-bundle-v1\""));
        assert!(report.contains("\"scratch_removed\":true"));
        assert!(report.contains("\"caller_expectations_matched\":true"));
        assert!(report.contains("\"object_graph_verified\":true"));
        assert!(report.contains("\"repository_changed\":false"));
        assert_eq!(std::fs::read_dir(scratch).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(fixture.0.join("source.bundle")).unwrap(),
            original
        );
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
    }
}

#[cfg(unix)]
#[test]
fn binary_file_backed_refusals_preserve_source_and_unrelated_scratch_files() {
    let fixture = Fixture::new();
    let original = fixture.write(SHA1);
    let scratch = private_scratch(&fixture);
    let retained = scratch.join("previous-attempt.scratch");
    std::fs::write(&retained, b"operator's previous residue").unwrap();
    let wrong = "0".repeat(64);
    for args in [
        vec![
            "bundle",
            "verify",
            "source.bundle",
            "--file-backed",
            "--scratch-dir",
            "scratch",
            "--expect-sha256",
            &wrong,
        ],
        vec![
            "bundle",
            "verify",
            "source.bundle",
            "--max-input-mib",
            "129",
        ],
        vec!["bundle", "verify", "source.bundle", "--file-backed"],
        vec![
            "--timeout-secs",
            "0.000000001",
            "bundle",
            "verify",
            "source.bundle",
            "--file-backed",
            "--scratch-dir",
            "scratch",
        ],
    ] {
        let result = fixture.run(&args);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        assert_eq!(
            std::fs::read(&retained).unwrap(),
            b"operator's previous residue"
        );
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(fixture.0.join("source.bundle")).unwrap(),
            original
        );
    }
}

#[cfg(unix)]
#[test]
fn binary_file_backed_layout_exports_metadata_without_materializing_a_repository() {
    let fixture = Fixture::new();
    let bundle = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"
    ));
    fixture.write(bundle.trim());
    let scratch = private_scratch(&fixture);
    let result = fixture.run(&[
        "bundle",
        "verify",
        "source.bundle",
        "--file-backed",
        "--scratch-dir",
        "scratch",
        "--recovery-head-hex",
        "726566732f68656164732f6d61696e",
    ]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = String::from_utf8(result.stdout).unwrap();
    let encoded = report
        .split_once("\"index_hex\":\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    let index: Vec<_> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let expected = "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579";
    assert_eq!(
        fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&index)),
        expected
    );
    assert!(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/native_bundle_recovery/metadata.json"
        ))
        .contains(expected)
    );
    assert!(report.contains("\"repository_changed\":false"));
    assert!(!report.contains("\"pack_hex\""));
    assert_eq!(std::fs::read_dir(scratch).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
}
