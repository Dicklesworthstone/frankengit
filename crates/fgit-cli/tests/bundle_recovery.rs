#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real fg processes materialize independently encoded native bundle fixtures.
//! No Git or JavaScript executable is available on these command paths.
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-native-recover-binary-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg"))
            .args(args)
            .current_dir(&self.0)
            .env("PATH", self.0.join("no-executables"))
            .env("HOME", &self.0)
            .output()
            .unwrap()
    }
    fn recover(&self, tail: &[&str]) -> Output {
        let mut args = vec![
            "bundle",
            "recover",
            "input.bundle",
            "restored.git",
            "--trusted-local",
            "--head-ref",
            "refs/heads/main",
        ];
        args.extend_from_slice(tail);
        self.run(&args)
    }
    fn write(&self, hex: &str) -> Vec<u8> {
        let bytes: Vec<u8> = hex
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        fs::write(self.0.join("input.bundle"), &bytes).unwrap();
        bytes
    }
    fn scratch(&self) {
        fs::create_dir(self.0.join("scratch")).unwrap();
        fs::set_permissions(self.0.join("scratch"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn recover_file(&self, tail: &[&str]) -> Output {
        let mut args = vec!["--file-backed", "--scratch-dir", "scratch"];
        args.extend_from_slice(tail);
        self.recover(&args)
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
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("\"type\":\"git_bundle_recovery\""));
    assert!(text.contains("\"state\":\"durable\""));
    for name in [
        "object_graph_verified",
        "head_published",
        "files_synchronized",
        "publication_directories_synchronized",
    ] {
        assert!(text.contains(&format!("\"{name}\":true")));
    }
    for name in [
        "authority_changed",
        "forge_state_restored",
        "signatures_verified",
        "origin_authenticated",
        "current_branch_verified",
        "gitlink_targets_verified",
    ] {
        assert!(text.contains(&format!("\"{name}\":false")));
    }
    text
}
fn refused(output: Output, reason: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("\"type\":\"bundle_error\""), "{error}");
    assert!(error.contains(reason), "{error}");
}

#[test]
fn binary_recovers_sha1_and_sha256_with_native_index_goldens_and_exact_resume() {
    for (format, input, offset, checksum, index_hash) in [
        (
            "sha1",
            include_str!("../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"),
            128,
            "2c774238758f7919f693d532f8eeea2abed537dc",
            "7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7",
        ),
        (
            "sha256",
            include_str!("../../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"),
            198,
            "fa21f8dd38157fa90ab57fbe341e9404c1a9d25c3bd8709a7ca607647b14214d",
            "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579",
        ),
    ] {
        let fixture = Fixture::new();
        let bytes = fixture.write(input);
        let digest = fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&bytes));
        let first =
            success(fixture.recover(&["--expect-sha256", &digest, "--expect-format", format]));
        assert!(first.contains("\"already_published\":false"));
        assert!(first.contains("\"resumed\":false"));
        assert!(first.contains("\"caller_expectations_matched\":true"));
        assert!(first.contains("\"object_count\":5"));
        let target = fixture.0.join("restored.git");
        assert_eq!(
            fs::read(target.join("HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        assert_eq!(
            fs::read(target.join(format!("objects/pack/pack-{checksum}.pack"))).unwrap(),
            bytes[offset..]
        );
        let index = fs::read(target.join(format!("objects/pack/pack-{checksum}.idx"))).unwrap();
        assert_eq!(
            fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&index)),
            index_hash
        );
        let config = fs::read_to_string(target.join("config")).unwrap();
        assert_eq!(config.contains("objectformat = sha256"), format == "sha256");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        refused(fixture.recover(&[]), "destination_exists");
        let repeated = success(fixture.recover(&["--resume", "--expect-sha256", &digest]));
        assert!(repeated.contains("\"resumed\":true"));
        assert!(repeated.contains("\"already_published\":true"));
        // Resume a real interrupted prefix in a new command process. Test-only
        // mutation removes HEAD before reducing one staged metadata body.
        fs::remove_file(target.join("HEAD")).unwrap();
        let partial = target.join("config.fg-recovery-part");
        fs::rename(target.join("config"), &partial).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .mode(0o600)
            .open(&partial)
            .unwrap()
            .set_len(7)
            .unwrap();
        let resumed = success(fixture.recover(&["--resume", "--expect-sha256", &digest]));
        assert!(resumed.contains("\"already_published\":false"));
        assert_eq!(fs::read_to_string(target.join("config")).unwrap(), config);
        assert!(!partial.exists());
        assert_eq!(fs::read(fixture.0.join("input.bundle")).unwrap(), bytes);
    }
}

#[test]
fn input_refusals_never_create_a_destination_or_replace_a_completed_one() {
    let fixture = Fixture::new();
    let original = fixture.write(include_str!(
        "../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
    ));
    refused(
        fixture.recover(&["--expect-sha256", &"0".repeat(64)]),
        "expected_bundle_artifact_mismatch",
    );
    refused(fixture.recover(&["--max-objects", "4"]), "limit");
    assert!(!fixture.0.join("restored.git").exists());
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(fixture.0.join("input.bundle"), &corrupt).unwrap();
    refused(fixture.recover(&[]), "bundle_pack:");
    assert!(!fixture.0.join("restored.git").exists());
    fs::write(fixture.0.join("input.bundle"), &original).unwrap();
    success(fixture.recover(&[]));
    let head = fs::read(fixture.0.join("restored.git/HEAD")).unwrap();
    fs::write(fixture.0.join("input.bundle"), &corrupt).unwrap();
    let resumed = fixture.recover(&["--resume"]);
    let error = String::from_utf8_lossy(&resumed.stderr);
    assert!(error.contains("state=publication_uncertain"), "{error}");
    assert!(
        error.contains("no_destination_write_this_attempt=true"),
        "{error}"
    );
    refused(resumed, "bundle_pack:");
    assert_eq!(fs::read(fixture.0.join("restored.git/HEAD")).unwrap(), head);
}

#[test]
fn binary_help_and_invalid_write_options_require_no_runtime_or_files() {
    let fixture = Fixture::new();
    let help = fixture.run(&["bundle", "recover", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("fg bundle recover"));
    refused(
        fixture.run(&[
            "bundle",
            "recover",
            "input",
            "output",
            "--head-ref",
            "refs/heads/main",
        ]),
        "--trusted-local",
    );
    refused(
        fixture.recover(&["--force"]),
        "unknown bundle recovery option",
    );
    refused(
        fixture.recover(&["--timeout-secs", "0"]),
        "positive canonical decimal",
    );
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}

#[test]
fn global_deadline_also_bounds_offline_verification_before_destination_creation() {
    let fixture = Fixture::new();
    fixture.write(include_str!(
        "../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
    ));
    refused(
        fixture.run(&[
            "--timeout-secs",
            "0.000000001",
            "bundle",
            "recover",
            "input.bundle",
            "restored.git",
            "--trusted-local",
            "--head-ref",
            "refs/heads/main",
            "--timeout-secs",
            "3600",
        ]),
        "stopped",
    );
    assert!(!fixture.0.join("restored.git").exists());
    success(fixture.recover(&[]));
}

#[test]
fn binary_file_backed_recovery_preserves_original_packs_and_resumes_partial_packs() {
    for (format, encoded, offset, checksum, index_hash) in [
        (
            "sha1",
            include_str!("../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"),
            128,
            "2c774238758f7919f693d532f8eeea2abed537dc",
            "7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7",
        ),
        (
            "sha256",
            include_str!("../../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"),
            198,
            "fa21f8dd38157fa90ab57fbe341e9404c1a9d25c3bd8709a7ca607647b14214d",
            "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.scratch();
        let bytes = fixture.write(encoded);
        let digest = fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&bytes));
        let report = success(fixture.recover_file(&[
            "--max-input-mib",
            "512",
            "--max-expanded-mib",
            "512",
            "--expect-format",
            format,
            "--expect-sha256",
            &digest,
        ]));
        assert!(
            report.contains("\"storage_profile\":\"file-backed-native-bare-source-recovery-v1\"")
        );
        assert!(report.contains("\"scratch_removed\":true"));
        assert!(report.contains(&format!(
            "\"pack_sha256\":\"{}\"",
            fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&bytes[offset..]))
        )));
        let target = fixture.0.join("restored.git");
        let pack = target.join(format!("objects/pack/pack-{checksum}.pack"));
        assert_eq!(fs::read(&pack).unwrap(), bytes[offset..]);
        let index = fs::read(target.join(format!("objects/pack/pack-{checksum}.idx"))).unwrap();
        assert_eq!(
            fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&index)),
            index_hash
        );
        assert_eq!(fs::read_dir(fixture.0.join("scratch")).unwrap().count(), 0);
        let report = success(fixture.recover(&["--resume", "--expect-sha256", &digest]));
        assert!(report.contains("\"already_published\":true"));
        let part = pack.with_extension("pack.fg-recovery-part");
        fs::remove_file(target.join("HEAD")).unwrap();
        fs::rename(&pack, &part).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&part)
            .unwrap()
            .set_len(7)
            .unwrap();
        let report = success(fixture.recover_file(&["--resume", "--expect-sha256", &digest]));
        assert!(report.contains("\"already_published\":false"));
        assert!(!part.exists());
        assert_eq!(fs::read(&pack).unwrap(), bytes[offset..]);
        assert_eq!(
            fs::read(target.join("HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        assert_eq!(fs::read_dir(fixture.0.join("scratch")).unwrap().count(), 0);
    }
}

#[test]
fn file_backed_refusal_preserves_scratch_residue_and_rejects_scratch_in_a_live_destination() {
    let fixture = Fixture::new();
    fixture.scratch();
    fixture.write(include_str!(
        "../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
    ));
    let residue = fixture.0.join("scratch/previous.scratch");
    fs::write(&residue, b"keep this unrelated file").unwrap();
    refused(
        fixture.recover_file(&["--expect-sha256", &"0".repeat(64)]),
        "expected_bundle_artifact_mismatch",
    );
    assert!(!fixture.0.join("restored.git").exists());
    assert_eq!(fs::read_dir(fixture.0.join("scratch")).unwrap().count(), 1);
    success(fixture.recover_file(&[]));
    let head = fs::read(fixture.0.join("restored.git/HEAD")).unwrap();
    let record = fs::read(
        fixture
            .0
            .join("restored.git/.frankengit-native-source-recovery"),
    )
    .unwrap();
    let result = fixture.recover(&["--resume", "--file-backed", "--scratch-dir", "restored.git"]);
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("state=publication_uncertain"), "{error}");
    assert!(
        error.contains("no_destination_write_this_attempt=true"),
        "{error}"
    );
    refused(result, "outside the recovery destination");
    assert_eq!(fs::read(fixture.0.join("restored.git/HEAD")).unwrap(), head);
    assert_eq!(
        fs::read(
            fixture
                .0
                .join("restored.git/.frankengit-native-source-recovery")
        )
        .unwrap(),
        record
    );
    assert_eq!(fs::read(&residue).unwrap(), b"keep this unrelated file");
}

#[test]
fn global_deadline_precedes_file_backed_scratch_creation_and_publication() {
    let fixture = Fixture::new();
    fixture.scratch();
    fixture.write(include_str!(
        "../../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
    ));
    refused(
        fixture.run(&[
            "--timeout-secs",
            "0.000000001",
            "bundle",
            "recover",
            "input.bundle",
            "restored.git",
            "--trusted-local",
            "--head-ref",
            "refs/heads/main",
            "--file-backed",
            "--scratch-dir",
            "scratch",
            "--timeout-secs",
            "3600",
        ]),
        "stopped",
    );
    assert!(!fixture.0.join("restored.git").exists());
    assert_eq!(fs::read_dir(fixture.0.join("scratch")).unwrap().count(), 0);
    success(fixture.recover_file(&[]));
}
