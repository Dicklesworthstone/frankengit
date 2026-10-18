use super::*;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-artifact-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn options(&self, bytes: &[u8]) -> options::Options {
        let mut values = put();
        values[1] = self.0.to_str().unwrap().into();
        let source = self.0.join("input");
        fs::write(&source, bytes).unwrap();
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, bytes);
        for (flag, value) in [
            ("--source", source.to_str().unwrap().to_owned()),
            (
                "--payload-sha256",
                output::hex(&DigestHasher::finish(hasher)),
            ),
            ("--payload-bytes", bytes.len().to_string()),
        ] {
            let index = values.iter().position(|s| s == flag).unwrap() + 1;
            values[index] = value;
        }
        options::parse(&values).unwrap()
    }
    fn payload(&self) -> PathBuf {
        let scope = fs::read_dir(&self.0)
            .unwrap()
            .map(Result::unwrap)
            .find(|e| e.file_name().to_string_lossy().starts_with("scope-"))
            .unwrap()
            .path();
        let paths: Vec<_> = fs::read_dir(scope).unwrap().map(Result::unwrap).collect();
        assert_eq!(paths.len(), 1);
        paths[0].path()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn identity(options: &options::Options) -> fgit_object_fabric::ArtifactIdentity {
    let options::Selection::Put { identity, .. } = &options.selection else {
        panic!()
    };
    identity.clone()
}
fn run(options: &options::Options, live: &dyn Fn() -> bool) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = execute::run(options, Duration::from_secs(30), live, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}
#[test]
fn artifact_cli_real_bytes_retry_reopen_and_no_overwrite() {
    let temp = Temp::new();
    let bytes: Vec<_> = (0..150000).map(|i| (i % 251) as u8).collect();
    let mut options = temp.options(&bytes);
    let id = identity(&options).artifact_id().clone();
    let first = run(&options, &|| true);
    assert_eq!(first.0, 0, "{}", first.2);
    assert!(first.1.contains("\"disposition\":\"created\""));
    let stored = temp.payload();
    let original = fs::read(&stored).unwrap();
    let repeat = run(&options, &|| true);
    assert_eq!(repeat.0, 0);
    assert!(repeat.1.contains("already_present"));
    assert_eq!(fs::read(stored).unwrap(), original);
    fs::remove_file(temp.0.join("input")).unwrap();
    options.selection = options::Selection::Inspect { id: id.clone() };
    let read = run(&options, &|| true);
    assert_eq!(read.0, 0);
    assert!(read.1.contains(&output::hash(&id)));
    assert!(read.1.contains("\"payload_verified\":true"));
    let target = temp.0.join("export");
    options.selection = options::Selection::Export {
        id,
        output: target.clone(),
    };
    assert_eq!(run(&options, &|| true).0, 0);
    assert_eq!(fs::read(&target).unwrap(), bytes);
    assert_eq!(run(&options, &|| true).0, 2);
    assert_eq!(fs::read(target).unwrap(), bytes);
}
#[test]
fn artifact_cli_corruption_and_foreign_scope_never_disclose_output() {
    let temp = Temp::new();
    let mut options = temp.options(b"retained bytes");
    let id = identity(&options).artifact_id().clone();
    assert_eq!(run(&options, &|| true).0, 0);
    let stored = temp.payload();
    let saved = fs::read(&stored).unwrap();
    let target = temp.0.join("no-output");
    options.selection = options::Selection::Export {
        id,
        output: target.clone(),
    };
    options.trust = "other".into();
    assert_eq!(run(&options, &|| true).0, 2);
    assert!(!target.exists());
    options.trust = "build".into();
    let mut corrupt = saved;
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&stored, &corrupt).unwrap();
    assert_eq!(run(&options, &|| true).0, 2);
    assert!(!target.exists());
    assert_eq!(fs::read(stored).unwrap(), corrupt);
}
#[test]
fn artifact_cli_refuses_symlinks_directories_and_digest_mismatch() {
    let temp = Temp::new();
    let mut options = temp.options(b"verified");
    let options::Selection::Put { source, .. } = &mut options.selection else {
        panic!()
    };
    let alias = temp.0.join("alias");
    symlink(&source, &alias).unwrap();
    *source = alias;
    assert_eq!(run(&options, &|| true).0, 2);
    let options::Selection::Put { source, .. } = &mut options.selection else {
        panic!()
    };
    *source = temp.0.clone();
    assert_eq!(run(&options, &|| true).0, 2);
    let options::Selection::Put { source, .. } = &mut options.selection else {
        panic!()
    };
    *source = temp.0.join("input");
    fs::write(source, b"mismatch").unwrap();
    assert_eq!(run(&options, &|| true).0, 2);
    fs::write(temp.0.join("input"), b"verified").unwrap();
    assert_eq!(run(&options, &|| true).0, 0);
    let id = identity(&options).artifact_id().clone();
    options.selection = options::Selection::Export {
        id,
        output: temp.0.join("alias"),
    };
    assert_eq!(run(&options, &|| true).0, 2);
    assert!(
        fs::symlink_metadata(temp.0.join("alias"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
#[test]
fn artifact_cli_stop_and_deadline_refuse_before_opening_storage() {
    let temp = Temp::new();
    let mut options = temp.options(b"cancelled");
    options.root = Path::new("/missing/never-created").into();
    assert_eq!(run(&options, &|| false).0, 2);
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        execute::run(&options, Duration::ZERO, &|| true, &mut out, &mut err),
        2
    );
    assert!(out.is_empty());
    options.root = temp.0.clone();
    let ticks = Cell::new(0);
    let result = run(&options, &|| {
        ticks.set(ticks.get() + 1);
        ticks.get() < 6
    });
    assert_eq!(result.0, 2);
    assert!(result.1.is_empty());
    // Mid-operation cancellation may retain an empty scope directory, but
    // neither a final payload nor an owned stage is allowed to remain.
    for entry in temp.0.read_dir().unwrap().map(Result::unwrap) {
        if entry.file_name().to_string_lossy().starts_with("scope-") {
            assert_eq!(entry.path().read_dir().unwrap().count(), 0);
        }
    }
    assert_eq!(run(&options, &|| true).0, 0);
}
#[test]
fn artifact_cli_output_failure_does_not_undo_persisted_payload() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let temp = Temp::new();
    let mut options = temp.options(b"keep after EPIPE");
    let id = identity(&options).artifact_id().clone();
    let mut err = Vec::new();
    assert_eq!(
        execute::run(
            &options,
            Duration::from_secs(30),
            &|| true,
            &mut Broken,
            &mut err
        ),
        4
    );
    assert!(String::from_utf8(err).unwrap().contains("retained_result"));
    options.selection = options::Selection::Inspect { id };
    assert_eq!(run(&options, &|| true).0, 0);
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run(&options, &|| true).0, 2);
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o700)).unwrap();
}
