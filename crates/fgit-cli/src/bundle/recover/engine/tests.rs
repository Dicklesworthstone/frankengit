use super::*;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const RECORD: &str = ".frankengit-native-source-recovery";
const SHA1: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
));
const SHA256: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"
));
const GOLDENS: [(&str, &str, usize, &str, &str); 2] = [
    (
        "sha1",
        SHA1,
        128,
        "2c774238758f7919f693d532f8eeea2abed537dc",
        "7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7",
    ),
    (
        "sha256",
        SHA256,
        198,
        "fa21f8dd38157fa90ab57fbe341e9404c1a9d25c3bd8709a7ca607647b14214d",
        "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579",
    ),
];

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-file-recovery-engine-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path);
        private_directory(&path.join("scratch"));
        Self(path)
    }
    fn input(&self, encoded: &str) -> Vec<u8> {
        let bytes = encoded
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        fs::write(self.0.join("source.bundle"), &bytes).unwrap();
        bytes
    }
    fn options(&self, file_backed: bool, extra: &[&str]) -> Options {
        let mut args = vec![
            self.0.join("source.bundle").to_str().unwrap().to_owned(),
            self.0.join("restored.git").to_str().unwrap().to_owned(),
            "--trusted-local".into(),
            "--head-ref".into(),
            "refs/heads/main".into(),
        ];
        if file_backed {
            args.extend([
                "--file-backed".into(),
                "--scratch-dir".into(),
                self.0.join("scratch").to_str().unwrap().to_owned(),
            ]);
        }
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        super::super::parse(&args).unwrap()
    }
    fn scratch_clean(&self) {
        assert_eq!(fs::read_dir(self.0.join("scratch")).unwrap().count(), 0);
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn success(result: Result<String, String>) -> String {
    let report = result.unwrap();
    assert!(report.contains("\"type\":\"git_bundle_recovery\""));
    assert!(report.contains("\"state\":\"durable\""));
    assert!(report.contains("\"object_graph_verified\":true"));
    assert!(report.contains("\"head_published\":true"));
    assert!(report.contains("\"authority_changed\":false"));
    assert!(report.contains("\"forge_state_restored\":false"));
    report
}

#[test]
fn file_backed_publication_preserves_both_native_pack_and_independent_index_goldens() {
    for (format, encoded, offset, checksum, index_sha256) in GOLDENS {
        let directory = Directory::new();
        let bytes = directory.input(encoded);
        let digest = lowercase_hex(&sha256_digest(&bytes));
        let options = directory.options(
            true,
            &[
                "--expect-format",
                format,
                "--expect-sha256",
                &digest,
                "--max-input-mib",
                "512",
                "--max-expanded-mib",
                "512",
            ],
        );
        let target = &options.destination;
        let mut observed_destination = false;
        let report = success(execute(&options, &mut || {
            if target.exists() {
                observed_destination = true;
                directory.scratch_clean();
            }
            true
        }));
        assert!(observed_destination);
        assert!(report.contains("\"caller_expectations_matched\":true"));
        assert!(
            report.contains("\"storage_profile\":\"file-backed-native-bare-source-recovery-v1\"")
        );
        assert!(report.contains("\"scratch_removed\":true"));
        assert!(report.contains(&format!(
            "\"pack_sha256\":\"{}\"",
            lowercase_hex(&sha256_digest(&bytes[offset..]))
        )));
        assert!(!report.contains("pack_hex"));
        assert!(!report.contains("index_hex"));
        assert_eq!(
            fs::read(target.join("HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        assert_eq!(
            fs::read(target.join(format!("objects/pack/pack-{checksum}.pack"))).unwrap(),
            bytes[offset..]
        );
        let index = fs::read(target.join(format!("objects/pack/pack-{checksum}.idx"))).unwrap();
        assert_eq!(lowercase_hex(&sha256_digest(&index)), index_sha256);
        assert!(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/native_bundle_recovery/metadata.json"
            ))
            .contains(index_sha256)
        );
        let config = fs::read_to_string(target.join("config")).unwrap();
        assert_eq!(config.contains("objectformat = sha256"), format == "sha256");
        assert_eq!(fs::read(directory.0.join("source.bundle")).unwrap(), bytes);
        directory.scratch_clean();
    }
}

#[test]
fn memory_and_file_backed_profiles_share_exact_records_and_resume_each_other() {
    for file_first in [false, true] {
        let directory = Directory::new();
        directory.input(SHA256);
        let first = directory.options(file_first, &[]);
        let first_report = success(execute(&first, &mut || true));
        assert!(first_report.contains("\"already_published\":false"));
        let record = fs::read(first.destination.join(RECORD)).unwrap();
        let head = fs::read(first.destination.join("HEAD")).unwrap();
        let second = directory.options(!file_first, &["--resume"]);
        let report = success(execute(&second, &mut || true));
        assert!(report.contains("\"already_published\":true"));
        assert!(report.contains("\"resumed\":true"));
        assert_eq!(report.contains("\"storage_profile\""), !file_first);
        assert_eq!(fs::read(first.destination.join(RECORD)).unwrap(), record);
        assert_eq!(fs::read(first.destination.join("HEAD")).unwrap(), head);
        directory.scratch_clean();
    }
}

#[test]
fn a_real_partial_pack_is_reverified_and_appended_before_head_is_republished() {
    let directory = Directory::new();
    let bytes = directory.input(SHA256);
    let options = directory.options(true, &[]);
    success(execute(&options, &mut || true));
    let pack = options
        .destination
        .join(format!("objects/pack/pack-{}.pack", GOLDENS[1].3));
    let partial = pack.with_extension("pack.fg-recovery-part");
    fs::remove_file(options.destination.join("HEAD")).unwrap();
    fs::rename(&pack, &partial).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&partial)
        .unwrap()
        .set_len(7)
        .unwrap();
    let options = directory.options(true, &["--resume"]);
    let report = success(execute(&options, &mut || true));
    assert!(report.contains("\"already_published\":false"));
    assert_eq!(fs::read(&pack).unwrap(), bytes[GOLDENS[1].2..]);
    assert!(!partial.exists());
    assert_eq!(
        fs::read(options.destination.join("HEAD")).unwrap(),
        b"ref: refs/heads/main\n"
    );
    directory.scratch_clean();
}

#[test]
fn verification_refusal_and_cancellation_clean_only_own_scratch_before_destination_writes() {
    let directory = Directory::new();
    let bytes = directory.input(SHA1);
    let residue = directory.0.join("scratch/previous-unrelated.scratch");
    fs::write(&residue, b"preserve unrelated residue").unwrap();
    for tail in [
        vec![
            "--expect-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        vec!["--max-objects", "4"],
    ] {
        let options = directory.options(true, &tail);
        let error = execute(&options, &mut || true).unwrap_err();
        assert!(error.contains("state=unchanged"), "{error}");
        assert!(
            error.contains("no_destination_write_this_attempt=true"),
            "{error}"
        );
        assert!(!options.destination.exists());
        assert_eq!(
            fs::read_dir(directory.0.join("scratch")).unwrap().count(),
            1
        );
    }
    let options = directory.options(true, &[]);
    let mut stopped = false;
    let error = execute(&options, &mut || {
        if fs::read_dir(directory.0.join("scratch"))
            .unwrap()
            .any(|entry| {
                let entry = entry.unwrap();
                entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".fg-bundle-")
                    && entry.metadata().unwrap().len() > 0
            })
        {
            stopped = true;
        }
        !stopped
    })
    .unwrap_err();
    assert!(stopped);
    assert!(error.contains("stopped"), "{error}");
    assert!(
        error.contains("no_destination_write_this_attempt=true"),
        "{error}"
    );
    assert!(!options.destination.exists());
    assert_eq!(
        fs::read_dir(directory.0.join("scratch")).unwrap().count(),
        1
    );
    assert_eq!(fs::read(&residue).unwrap(), b"preserve unrelated residue");
    assert_eq!(fs::read(directory.0.join("source.bundle")).unwrap(), bytes);
}

#[test]
fn resume_verification_failure_preserves_an_existing_publication_and_reports_uncertainty() {
    let directory = Directory::new();
    let mut bytes = directory.input(SHA1);
    let options = directory.options(true, &[]);
    success(execute(&options, &mut || true));
    let head = fs::read(options.destination.join("HEAD")).unwrap();
    let record = fs::read(options.destination.join(RECORD)).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(directory.0.join("source.bundle"), &bytes).unwrap();
    let resumed = directory.options(true, &["--resume"]);
    let error = execute(&resumed, &mut || true).unwrap_err();
    assert!(error.contains("state=publication_uncertain"), "{error}");
    assert!(
        error.contains("no_destination_write_this_attempt=true"),
        "{error}"
    );
    assert_eq!(fs::read(options.destination.join("HEAD")).unwrap(), head);
    assert_eq!(fs::read(options.destination.join(RECORD)).unwrap(), record);
    directory.scratch_clean();
}

#[test]
fn source_changed_after_verification_refuses_publication_and_restored_source_can_resume() {
    let directory = Directory::new();
    let bytes = directory.input(SHA1);
    let options = directory.options(true, &[]);
    let mut changed = false;
    let error = execute(&options, &mut || {
        if !changed && options.destination.join(RECORD).exists() {
            directory.scratch_clean();
            let mut source = fs::OpenOptions::new()
                .write(true)
                .open(directory.0.join("source.bundle"))
                .unwrap();
            source.seek(SeekFrom::End(-1)).unwrap();
            source.write_all(&[bytes.last().unwrap() ^ 1]).unwrap();
            changed = true;
        }
        true
    })
    .unwrap_err();
    assert!(changed);
    assert!(error.contains("state=staged"), "{error}");
    assert!(error.contains("code=verified_source_changed"), "{error}");
    assert!(!options.destination.join("HEAD").exists());
    directory.scratch_clean();
    fs::write(directory.0.join("source.bundle"), &bytes).unwrap();
    let resumed = directory.options(true, &["--resume"]);
    let report = success(execute(&resumed, &mut || true));
    assert!(report.contains("\"already_published\":false"));
}

#[test]
fn scratch_cleanup_failure_prevents_any_destination_mutation() {
    let directory = Directory::new();
    directory.input(SHA1);
    let options = directory.options(true, &[]);
    let scratch = directory.0.join("scratch");
    let mut changed = false;
    let error = execute(&options, &mut || {
        if !changed
            && fs::read_dir(&scratch)
                .unwrap()
                .any(|entry| entry.unwrap().metadata().unwrap().len() > 0)
        {
            fs::set_permissions(&scratch, fs::Permissions::from_mode(0o750)).unwrap();
            changed = true;
        }
        true
    })
    .unwrap_err();
    assert!(changed);
    assert!(error.contains("scratch_cleanup_incomplete"), "{error}");
    assert!(
        error.contains("no_destination_write_this_attempt=true"),
        "{error}"
    );
    assert!(!options.destination.exists());
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 1);
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn scratch_cannot_share_or_descend_into_a_destination_even_through_parent_aliases() {
    let directory = Directory::new();
    directory.input(SHA1);
    let mut options = directory.options(true, &["--resume"]);
    private_directory(&options.destination);
    fs::write(options.destination.join("HEAD"), b"preserve visible HEAD").unwrap();
    let inside = options.destination.join("private");
    private_directory(&inside);
    symlink(&directory.0, directory.0.join("alias")).unwrap();
    for (target, scratch) in [
        (options.destination.clone(), options.destination.clone()),
        (options.destination.clone(), inside.clone()),
        (directory.0.join("alias/restored.git"), inside.clone()),
    ] {
        options.destination = target;
        options.verification.scratch_directory = Some(scratch);
        let error = execute(&options, &mut || true).unwrap_err();
        assert!(
            error.contains("outside the recovery destination"),
            "{error}"
        );
        assert!(error.contains("state=publication_uncertain"), "{error}");
        assert!(
            error.contains("no_destination_write_this_attempt=true"),
            "{error}"
        );
        assert_eq!(
            fs::read(options.destination.join("HEAD")).unwrap(),
            b"preserve visible HEAD"
        );
        assert_eq!(fs::read_dir(&inside).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&options.destination).unwrap().count(), 2);
    }
}

#[test]
fn scratch_siblings_and_parents_are_allowed_but_fresh_scratch_filename_aliases_refuse() {
    let directory = Directory::new();
    directory.input(SHA1);
    let mut options = directory.options(true, &[]);
    success(execute(&options, &mut || true));
    options.destination = directory.0.join("parent-scratch.git");
    options.verification.scratch_directory = Some(directory.0.clone());
    success(execute(&options, &mut || true));
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 4);
    options.destination = directory
        .0
        .join(format!(".fg-bundle-{}-0.scratch", std::process::id()));
    let error = execute(&options, &mut || true).unwrap_err();
    assert!(error.contains("reserved scratch filename"), "{error}");
    assert!(
        error.contains("no_destination_write_this_attempt=true"),
        "{error}"
    );
    assert!(!options.destination.exists());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 4);
}
