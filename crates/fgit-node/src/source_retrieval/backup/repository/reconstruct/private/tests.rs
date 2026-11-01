//! Actual private-file ownership and cleanup boundaries, independent of native
//! graph fixtures. No test substitutes an observation for verified content.

use super::super::super::profile::Profile;
use super::*;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-private-reconstruction-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn only_stage(root: &Path) -> PathBuf {
    let entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_file());
    entries[0].clone()
}

fn frozen(root: &Path) -> PrivateReconstruction {
    let deadline = Profile::default().start();
    let mut owner = PrivateReconstruction::reserve(root, deadline).unwrap();
    owner.stage.file().write_all(b"abc").unwrap();
    owner.stage.synchronize_content(3, deadline).unwrap();
    owner.check_frozen().unwrap();
    owner
}

#[test]
fn settled_frozen_cleanup_removes_only_its_stage_and_empty_root() {
    let scratch = Scratch::new();
    let sentinel = scratch.child("preserved");
    fs::write(&sentinel, b"parent belongs to caller").unwrap();
    let root = scratch.child("private");
    let owner = frozen(&root);
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    let stage = only_stage(&root);
    assert_eq!(fs::metadata(&stage).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::read(&stage).unwrap(), b"abc");
    assert!(
        !root.join("archive.fgit").exists(),
        "private assembly never publishes an intermediate archive"
    );
    owner.finish().unwrap();
    assert!(!root.exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"parent belongs to caller");
}

#[test]
fn contained_partial_abort_cleans_but_drop_and_unsettled_finish_never_guess_completion() {
    let scratch = Scratch::new();
    let root = scratch.child("partial");
    let mut owner = PrivateReconstruction::reserve(&root, Profile::default().start()).unwrap();
    owner
        .stage
        .file()
        .write_all(b"unverified partial bytes")
        .unwrap();
    assert!(owner.check_frozen().is_err());
    let error = owner.failure("range budget exhausted before native work".into());
    assert!(
        error.contains("private_reconstruction_removed=true"),
        "{error}"
    );
    assert!(!root.exists());

    let root = scratch.child("not-settled");
    let mut owner = PrivateReconstruction::reserve(&root, Profile::default().start()).unwrap();
    owner.stage.file().write_all(b"still incomplete").unwrap();
    let stage = only_stage(&root);
    let error = owner.finish().unwrap_err();
    assert!(
        error.contains("private_reconstruction_retained=true"),
        "{error}"
    );
    assert_eq!(fs::read(&stage).unwrap(), b"still incomplete");

    let root = scratch.child("dropped");
    let owner = frozen(&root);
    let stage = only_stage(&root);
    drop(owner);
    assert_eq!(
        fs::read(&stage).unwrap(),
        b"abc",
        "Drop must only release descriptors"
    );
}

#[test]
fn same_length_postfreeze_write_is_never_accepted_as_a_new_cleanup_fence() {
    let scratch = Scratch::new();
    for native_started in [false, true] {
        let root = scratch.child(if native_started { "native" } else { "prepared" });
        let mut owner = frozen(&root);
        let stage = only_stage(&root);
        owner.stage.file().seek(SeekFrom::Start(0)).unwrap();
        owner.stage.file().write_all(b"xyz").unwrap();
        // Deterministically distinguish the original metadata even on a host
        // whose filesystem timestamps have coarser precision than this test.
        owner
            .stage
            .file()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1234))
            .unwrap();
        assert!(owner.check_frozen().unwrap_err().contains("changed"));
        let error = if native_started {
            owner.finish().unwrap_err()
        } else {
            owner.failure("prepared content changed".into())
        };
        assert!(
            error.contains("private_reconstruction_retained=true"),
            "{error}"
        );
        assert_eq!(fs::read(&stage).unwrap(), b"xyz");
    }
}

#[test]
fn substituted_stage_root_and_parent_are_preserved_instead_of_deleted() {
    let scratch = Scratch::new();
    for case in ["stage", "root", "parent"] {
        let parent = scratch.child(case);
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let root = parent.join("private");
        let owner = frozen(&root);
        let stage = only_stage(&root);
        let (foreign, original) = match case {
            "stage" => {
                let original = root.join("retained-original");
                fs::rename(&stage, &original).unwrap();
                fs::write(&stage, b"foreign replacement").unwrap();
                fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
                (stage, original)
            }
            "root" => {
                let moved = parent.join("retained-root");
                fs::rename(&root, &moved).unwrap();
                DirBuilder::new().mode(0o700).create(&root).unwrap();
                let foreign = root.join("foreign");
                fs::write(&foreign, b"foreign replacement").unwrap();
                (foreign, moved.join(stage.file_name().unwrap()))
            }
            _ => {
                let moved = scratch.child("retained-parent");
                fs::rename(&parent, &moved).unwrap();
                DirBuilder::new().mode(0o700).create(&parent).unwrap();
                let foreign = parent.join("foreign");
                fs::write(&foreign, b"foreign replacement").unwrap();
                (
                    foreign,
                    moved.join("private").join(stage.file_name().unwrap()),
                )
            }
        };
        assert!(owner.check_frozen().is_err());
        let error = owner.failure("ownership changed before native work".into());
        assert!(
            error.contains("private_reconstruction_retained=true"),
            "{case}: {error}"
        );
        assert_eq!(fs::read(&foreign).unwrap(), b"foreign replacement");
        assert_eq!(fs::read(&original).unwrap(), b"abc");
    }
}

#[test]
fn unexpected_children_block_root_removal_without_recursive_cleanup() {
    let scratch = Scratch::new();
    let root = scratch.child("private");
    let owner = frozen(&root);
    let stage = only_stage(&root);
    let foreign = root.join("unrelated-owner-file");
    fs::write(&foreign, b"preserve unrelated bytes").unwrap();
    let error = owner.finish().unwrap_err();
    assert!(
        error.contains("private_reconstruction_retained=true"),
        "{error}"
    );
    assert!(
        !stage.exists(),
        "the unchanged owned stage was explicitly removed"
    );
    assert_eq!(fs::read(&foreign).unwrap(), b"preserve unrelated bytes");
}

#[test]
fn reservation_refusals_preserve_existing_roots_and_setup_cleanup_is_empty_only() {
    let scratch = Scratch::new();
    let root = scratch.child("existing");
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    let sentinel = root.join("preserved");
    fs::write(&sentinel, b"existing caller state").unwrap();
    assert!(PrivateReconstruction::reserve(&root, Profile::default().start()).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"existing caller state");

    let parent = Directory::open(&scratch.0).unwrap();
    let empty = scratch.child("setup-empty");
    DirBuilder::new().mode(0o700).create(&empty).unwrap();
    let directory = Directory::open(&empty).unwrap();
    let error = cleanup_setup_failure("stage reservation failed".into(), &parent, &directory);
    assert!(
        error.contains("private_reconstruction_removed=true"),
        "{error}"
    );
    assert!(!empty.exists());

    let public_parent = scratch.child("public-parent");
    DirBuilder::new()
        .mode(0o700)
        .create(&public_parent)
        .unwrap();
    fs::set_permissions(&public_parent, fs::Permissions::from_mode(0o755)).unwrap();
    let refused = public_parent.join("new-root");
    assert!(PrivateReconstruction::reserve(&refused, Profile::default().start()).is_err());
    assert!(!refused.exists());
}
