#![cfg(unix)]
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SHA1: &str = "23207632206769742062756e646c650a6365303133363235303330626138646261393036663735363936376639653963613339343436346120726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fde0412401f4a9e5f05411f44eaf9c86d46096746";
const SHA256: &str = "23207633206769742062756e646c650a406f626a6563742d666f726d61743d7368613235360a3263663864383364396565323935343362333461383737323734323166646563623765336633613138336433333736333930323564653537366462396562623420726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fa3c5e2a560d25012da705ae0890a05c5c36957d4274db457f92b31bf33510557";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-file-bundle-engine-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn input(&self, encoded: &str) -> (PathBuf, Vec<u8>) {
        let path = self.0.join("source.bundle");
        let bytes = anchors::unhex(encoded, 4096).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        (path, bytes)
    }
    fn options(&self, input: &Path, extra: &[&str]) -> Options {
        let mut args = vec![
            input.to_str().unwrap().to_owned(),
            "--file-backed".into(),
            "--scratch-dir".into(),
            self.0.to_str().unwrap().to_owned(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        super::super::parse(&args).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn disk_and_memory_profiles_agree_on_independent_bundles_in_both_native_formats() {
    for encoded in [SHA1, SHA256] {
        let directory = Directory::new();
        let (path, bytes) = directory.input(encoded);
        let digest = lowercase_hex(&fgit_crypto::sha256_digest(&bytes));
        let options = directory.options(
            &path,
            &[
                "--expect-sha256",
                &digest,
                "--max-input-mib",
                "512",
                "--max-expanded-mib",
                "512",
            ],
        );
        let disk = execute(&options, &mut || true).unwrap();
        let memory = super::super::parse(&[
            path.to_str().unwrap().to_owned(),
            "--expect-sha256".into(),
            digest,
        ])
        .unwrap();
        let memory = execute(&memory, &mut || true).unwrap();
        assert!(disk.starts_with(memory.strip_suffix('}').unwrap()));
        assert!(disk.contains("\"storage_profile\":\"file-backed-native-full-bundle-v1\""));
        assert!(disk.contains("\"scratch_removed\":true"));
        assert!(disk.contains("\"caller_expectations_matched\":true"));
        assert!(disk.contains("\"object_graph_verified\":true"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }
}

#[test]
fn wrong_pins_precede_pack_inflation_and_matching_pins_still_validate_the_pack() {
    let directory = Directory::new();
    let (path, mut bytes) = directory.input(SHA1);
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let wrong = directory.options(&path, &["--expect-sha256", &"0".repeat(64)]);
    assert!(
        execute(&wrong, &mut || true)
            .unwrap_err()
            .contains("expected_bundle_artifact_mismatch")
    );
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    let digest = lowercase_hex(&fgit_crypto::sha256_digest(&bytes));
    let matching = directory.options(&path, &["--expect-sha256", &digest]);
    assert!(
        execute(&matching, &mut || true)
            .unwrap_err()
            .contains("bundle_pack:")
    );
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn cancellation_removes_owned_scratch_and_preserves_input_and_unrelated_residue() {
    let directory = Directory::new();
    let (path, bytes) = directory.input(SHA256);
    let residue = directory.0.join("previous-unrelated.scratch");
    std::fs::write(&residue, b"keep this").unwrap();
    let options = directory.options(&path, &[]);
    for stop_at in [1_usize, 4, 8, 12, 20, 40] {
        let mut calls = 0_usize;
        let result = execute(&options, &mut || {
            calls += 1;
            calls < stop_at
        });
        assert!(
            result.is_err(),
            "stop checkpoint {stop_at} was not observed"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read(&residue).unwrap(), b"keep this");
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 2);
    }
}

#[test]
fn a_source_changed_after_opening_cannot_emit_a_success_report() {
    let directory = Directory::new();
    let (path, _) = directory.input(SHA1);
    let options = directory.options(&path, &[]);
    let mut calls = 0_usize;
    let result = execute(&options, &mut || {
        calls += 1;
        if calls == 12 {
            std::fs::write(&path, b"changed after opening").unwrap();
        }
        true
    });
    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn file_backed_recovery_layout_preserves_independent_native_index_goldens() {
    for (bundle, index_sha256) in [
        (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
            )),
            "7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7",
        ),
        (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"
            )),
            "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579",
        ),
    ] {
        let directory = Directory::new();
        let (path, _) = directory.input(bundle.trim());
        let options = directory.options(
            &path,
            &["--recovery-head-hex", "726566732f68656164732f6d61696e"],
        );
        let result = execute(&options, &mut || true).unwrap();
        let encoded = result
            .split_once("\"index_hex\":\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        let index = anchors::unhex(encoded, 16 * 1024 * 1024).unwrap();
        assert_eq!(
            lowercase_hex(&fgit_crypto::sha256_digest(&index)),
            index_sha256
        );
        assert!(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/native_bundle_recovery/metadata.json"
            ))
            .contains(index_sha256)
        );
        assert!(result.contains("\"profile\":\"native-bare-source-layout-v1\""));
        assert!(!result.contains("\"pack_hex\""));
        assert!(result.contains("\"scratch_removed\":true"));
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }
}
