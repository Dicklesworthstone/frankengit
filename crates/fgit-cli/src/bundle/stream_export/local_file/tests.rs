#![cfg(unix)]
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-stream-export-files-{}-{}-{}",
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
    fn destination(&self) -> PathBuf {
        self.0.join("source.bundle")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn complete_stream_is_private_until_create_only_durable_publication() {
    let directory = Directory::new();
    let destination = directory.destination();
    let retained = directory.0.join("prior-attempt.tmp");
    fs::write(&retained, b"operator-owned residue").unwrap();
    let mut stage = OwnedExport::create(&destination, 3 * CHUNK_BYTES as u64).unwrap();
    let body = vec![0xa5; 2 * CHUNK_BYTES + 7];
    assert_eq!(stage.write(&body).unwrap(), CHUNK_BYTES);
    stage.write_all(&body[CHUNK_BYTES..]).unwrap();
    assert!(!destination.exists());
    assert_eq!(fs::metadata(&stage.path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(stage.state(), State::Staged);
    stage.publish(body.len() as u64, &mut || true).unwrap();
    assert_eq!(stage.state(), State::Durable);
    assert!(stage.removed);
    assert!(!stage.path.exists());
    assert_eq!(fs::read(&destination).unwrap(), body);
    assert_eq!(fs::metadata(&destination).unwrap().nlink(), 1);
    assert_eq!(fs::read(&retained).unwrap(), b"operator-owned residue");
    stage.cleanup().unwrap();
    drop(stage);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[test]
fn native_refusal_and_cancelled_publication_remove_only_this_attempt() {
    let directory = Directory::new();
    let retained = directory.0.join("old.partial");
    fs::write(&retained, b"unrelated").unwrap();
    for cancelled in [false, true] {
        let destination = directory.destination();
        let mut stage = OwnedExport::create(&destination, 1024).unwrap();
        stage.write_all(b"partial native bytes").unwrap();
        if cancelled {
            let error = stage.publish(20, &mut || false).unwrap_err();
            assert_eq!(error.state, State::Staged);
            assert!(error.to_string().contains("bundle_created=false"));
        }
        // A native refusal never calls publish. Cleanup still runs after stop.
        stage.cleanup().unwrap();
        assert!(!destination.exists());
        assert_eq!(fs::read(&retained).unwrap(), b"unrelated");
    }
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn byte_limit_and_receipt_mismatch_never_publish_partial_output() {
    for wrong_count in [false, true] {
        let directory = Directory::new();
        let destination = directory.destination();
        let mut stage = OwnedExport::create(&destination, 4).unwrap();
        stage.write_all(b"four").unwrap();
        if !wrong_count {
            assert!(stage.write_all(b"!").is_err());
            assert!(stage.write(b"").is_err());
        }
        let count = if wrong_count { 5 } else { 4 };
        assert!(stage.publish(count, &mut || true).is_err());
        stage.cleanup().unwrap();
        assert!(!destination.exists());
    }
    let directory = Directory::new();
    let mut stage = OwnedExport::create(&directory.destination(), 4).unwrap();
    stage.write_all(b"four").unwrap();
    stage.publish(4, &mut || true).unwrap();
    assert_eq!(fs::read(directory.destination()).unwrap(), b"four");
}

#[test]
fn output_collision_before_or_during_work_never_clobbers() {
    let directory = Directory::new();
    let destination = directory.destination();
    fs::write(&destination, b"existing destination").unwrap();
    assert!(OwnedExport::create(&destination, 1024).is_err());
    fs::remove_file(&destination).unwrap();
    let mut stage = OwnedExport::create(&destination, 1024).unwrap();
    stage.write_all(b"new bytes").unwrap();
    fs::write(&destination, b"concurrent destination").unwrap();
    let error = stage.publish(9, &mut || true).unwrap_err();
    assert_eq!(error.state, State::Staged);
    stage.cleanup().unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"concurrent destination");
}

#[test]
fn replacement_stage_is_never_removed_or_published() {
    let directory = Directory::new();
    let destination = directory.destination();
    let mut stage = OwnedExport::create(&destination, 1024).unwrap();
    stage.write_all(b"owned native bytes").unwrap();
    let moved = directory.0.join("saved-owned-stage");
    fs::rename(&stage.path, &moved).unwrap();
    fs::write(&stage.path, b"foreign replacement").unwrap();
    assert!(stage.publish(18, &mut || true).is_err());
    let error = stage.cleanup().unwrap_err();
    assert!(error.to_string().contains("export_cleanup_incomplete"));
    let path = stage.path.clone();
    drop(stage);
    assert_eq!(fs::read(path).unwrap(), b"foreign replacement");
    assert_eq!(fs::read(moved).unwrap(), b"owned native bytes");
    assert!(!destination.exists());
}

#[test]
fn aliased_or_permission_changed_stages_fail_ownership_checks() {
    for alias in [false, true] {
        let directory = Directory::new();
        let mut stage = OwnedExport::create(&directory.destination(), 1024).unwrap();
        stage.write_all(b"owned").unwrap();
        if alias {
            fs::hard_link(&stage.path, directory.0.join("unexpected-alias")).unwrap();
        } else {
            fs::set_permissions(&stage.path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(stage.publish(5, &mut || true).is_err());
        assert!(stage.cleanup().is_err());
        assert!(stage.path.exists());
        assert!(!directory.destination().exists());
    }
}

#[test]
fn replaced_parent_never_redirects_publication_or_cleanup() {
    let directory = Directory::new();
    let parent = directory.0.join("output");
    fs::create_dir(&parent).unwrap();
    let mut stage = OwnedExport::create(&parent.join("source.bundle"), 1024).unwrap();
    stage.write_all(b"owned").unwrap();
    let moved = directory.0.join("retained-parent");
    fs::rename(&parent, &moved).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::write(&stage.path, b"unrelated new-parent file").unwrap();
    assert!(stage.publish(5, &mut || true).is_err());
    assert!(stage.cleanup().is_err());
    let temporary = stage.path.file_name().unwrap().to_owned();
    drop(stage);
    assert_eq!(
        fs::read(parent.join(&temporary)).unwrap(),
        b"unrelated new-parent file"
    );
    assert_eq!(fs::read(moved.join(temporary)).unwrap(), b"owned");
    assert!(!parent.join("source.bundle").exists());
}

#[test]
fn symlink_traversal_and_nonregular_destinations_refuse_before_staging() {
    let directory = Directory::new();
    let link = directory.0.join("linked");
    symlink(&directory.0, &link).unwrap();
    for path in [
        link.join("out.bundle"),
        directory.0.join("../out.bundle"),
        directory.0.clone(),
        directory.0.join("missing/out.bundle"),
    ] {
        assert!(OwnedExport::create(&path, 1024).is_err(), "{path:?}");
    }
    let destination = directory.destination();
    symlink(directory.0.join("missing"), &destination).unwrap();
    assert!(OwnedExport::create(&destination, 1024).is_err());
    assert!(fs::symlink_metadata(destination).unwrap().is_symlink());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[test]
fn final_directory_sync_error_retains_visible_file_truth() {
    let directory = Directory::new();
    let destination = directory.destination();
    let mut stage = OwnedExport::create(&destination, 1024).unwrap();
    stage.write_all(b"complete bundle").unwrap();
    let error = stage
        .publish_with_sync(15, &mut || true, |_| {
            Err(io::Error::other("injected sync fault"))
        })
        .unwrap_err();
    assert_eq!(error.state, State::Visible);
    assert!(error.to_string().contains("bundle_created=true"));
    assert!(!error.to_string().contains("no bundle"));
    stage.cleanup().unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"complete bundle");
    assert!(!stage.path.exists());
}

#[test]
fn no_empty_or_oversized_profile_is_accepted() {
    let directory = Directory::new();
    for maximum in [0, 16 * 1024 * 1024 * 1024 + 1] {
        assert!(OwnedExport::create(&directory.destination(), maximum).is_err());
    }
    let mut empty = OwnedExport::create(&directory.destination(), 1024).unwrap();
    assert!(empty.publish(0, &mut || true).is_err());
    empty.cleanup().unwrap();
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
}
