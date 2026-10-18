#![cfg(unix)]
use super::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-file-bundle-owner-{}-{}-{}",
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
    fn input(&self) -> PathBuf {
        let path = self.0.join("input.bundle");
        std::fs::write(&path, b"original input body").unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn stable_input_retains_one_seekable_descriptor_and_never_changes_the_source() {
    let directory = Directory::new();
    let path = directory.input();
    let mut input = StableInput::open(&path, 1024, &mut || true).unwrap();
    assert_eq!(input.len(), 19);
    let mut data = Vec::new();
    input.file_mut().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"original input body");
    input.file_mut().seek(SeekFrom::Start(9)).unwrap();
    data.clear();
    input.file_mut().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"input body");
    input.recheck(&mut || true).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"original input body");
}

#[test]
fn changed_content_metadata_or_path_refuses_the_success_recheck() {
    for replacement in [false, true] {
        let directory = Directory::new();
        let path = directory.input();
        let input = StableInput::open(&path, 1024, &mut || true).unwrap();
        if replacement {
            let other = directory.0.join("replacement");
            std::fs::write(&other, b"original input body").unwrap();
            std::fs::rename(other, &path).unwrap();
        } else {
            std::fs::write(&path, b"different").unwrap();
        }
        assert!(input.recheck(&mut || true).is_err());
    }
    let directory = Directory::new();
    let path = directory.input();
    let input = StableInput::open(&path, 1024, &mut || true).unwrap();
    let mode = std::fs::metadata(&path).unwrap().mode();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
    assert!(input.recheck(&mut || true).is_err());
}

#[test]
fn input_bounds_symlinks_and_nonregular_paths_refuse_before_reading() {
    let directory = Directory::new();
    let path = directory.input();
    assert!(StableInput::open(&path, 18, &mut || true).is_err());
    assert!(StableInput::open(&directory.0, 1024, &mut || true).is_err());
    let link = directory.0.join("input-link");
    symlink(&path, &link).unwrap();
    assert!(StableInput::open(&link, 1024, &mut || true).is_err());
    let parent_link = directory.0.join("linked-parent");
    symlink(&directory.0, &parent_link).unwrap();
    assert!(StableInput::open(&parent_link.join("input.bundle"), 1024, &mut || true).is_err());
    assert!(StableInput::open(&directory.0.join("../input.bundle"), 1024, &mut || true).is_err());
    std::fs::write(&path, []).unwrap();
    assert!(StableInput::open(&path, 1024, &mut || true).is_err());
}

#[test]
fn input_recheck_detects_namespace_replacement_by_a_symlink() {
    let directory = Directory::new();
    let path = directory.input();
    let input = StableInput::open(&path, 1024, &mut || true).unwrap();
    let retained = directory.0.join("retained-input");
    std::fs::rename(&path, &retained).unwrap();
    symlink(&retained, &path).unwrap();
    assert!(input.recheck(&mut || true).is_err());
    assert_eq!(std::fs::read(retained).unwrap(), b"original input body");
}

#[test]
fn scratch_is_private_seekable_fresh_and_cleanup_preserves_other_entries() {
    let directory = Directory::new();
    let old = directory.0.join("previous-residue.scratch");
    std::fs::write(&old, b"operator-owned residue").unwrap();
    let mut first = OwnedScratch::create(&directory.0, &mut || true).unwrap();
    let mut second = OwnedScratch::create(&directory.0, &mut || true).unwrap();
    assert_ne!(first.path, second.path);
    assert_eq!(
        first.file_mut().unwrap().metadata().unwrap().mode() & 0o777,
        0o600
    );
    first
        .file_mut()
        .unwrap()
        .write_all(b"resolved native payload")
        .unwrap();
    first.file_mut().unwrap().rewind().unwrap();
    let mut data = Vec::new();
    first.file_mut().unwrap().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"resolved native payload");
    first.recheck().unwrap();
    first.cleanup().unwrap();
    first.cleanup().unwrap();
    assert!(!first.path.exists());
    assert!(second.path.exists());
    assert_eq!(std::fs::read(&old).unwrap(), b"operator-owned residue");
    second.cleanup().unwrap();
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn scratch_requires_an_existing_private_ordinary_directory() {
    let directory = Directory::new();
    assert!(OwnedScratch::create(&directory.0.join("missing"), &mut || true).is_err());
    let file = directory.input();
    assert!(OwnedScratch::create(&file, &mut || true).is_err());
    let link = directory.0.join("directory-link");
    symlink(&directory.0, &link).unwrap();
    assert!(OwnedScratch::create(&link, &mut || true).is_err());
    assert!(OwnedScratch::create(&link.join("."), &mut || true).is_err());
    let trailing_slash = PathBuf::from(format!("{}/", link.display()));
    assert!(OwnedScratch::create(&trailing_slash, &mut || true).is_err());
    // The same suffix on an ordinary private directory is permitted.
    OwnedScratch::create(&directory.0.join("."), &mut || true)
        .unwrap()
        .cleanup()
        .unwrap();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(OwnedScratch::create(&directory.0, &mut || true).is_err());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    OwnedScratch::create(&directory.0, &mut || true)
        .unwrap()
        .cleanup()
        .unwrap();
}

#[test]
fn scratch_cleanup_refuses_replacements_and_unowned_hardlinks() {
    let directory = Directory::new();
    let mut scratch = OwnedScratch::create(&directory.0, &mut || true).unwrap();
    let retained = directory.0.join("original-scratch");
    std::fs::rename(&scratch.path, &retained).unwrap();
    std::fs::write(&scratch.path, b"unrelated replacement").unwrap();
    assert!(
        scratch
            .cleanup()
            .unwrap_err()
            .contains("scratch_cleanup_incomplete")
    );
    assert_eq!(
        std::fs::read(&scratch.path).unwrap(),
        b"unrelated replacement"
    );
    drop(scratch);
    assert!(retained.exists());
    let mut scratch = OwnedScratch::create(&directory.0, &mut || true).unwrap();
    let alias = directory.0.join("unowned-alias");
    std::fs::hard_link(&scratch.path, &alias).unwrap();
    assert!(scratch.cleanup().is_err());
    assert!(scratch.path.exists());
    std::fs::remove_file(alias).unwrap();
    scratch.cleanup().unwrap();
}

#[test]
fn scratch_cleanup_survives_cancellation_but_refuses_changed_directory_ownership() {
    let directory = Directory::new();
    let path = directory.input();
    assert!(StableInput::open(&path, 1024, &mut || false).is_err());
    let input = StableInput::open(&path, 1024, &mut || true).unwrap();
    assert!(input.recheck(&mut || false).is_err());
    let mut calls = 0_usize;
    assert!(
        OwnedScratch::create(&directory.0, &mut || {
            calls += 1;
            calls < 3
        })
        .is_err()
    );
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    let mut scratch = OwnedScratch::create(&directory.0, &mut || true).unwrap();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(scratch.cleanup().is_err());
    assert!(scratch.path.exists());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    scratch.cleanup().unwrap();
}

#[test]
fn normal_scope_exit_removes_only_the_owned_scratch() {
    let directory = Directory::new();
    let path = {
        let mut scratch = OwnedScratch::create(&directory.0, &mut || true).unwrap();
        scratch
            .file_mut()
            .unwrap()
            .write_all(b"untrusted partial output")
            .unwrap();
        scratch.path.clone()
    };
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
}
