//! FG-035 source/key boundary drills.
//!
//! These tests construct a tiny checkout object store directly with
//! first-party object identities and zlib bytes.  They never shell out to Git:
//! the permitted twin proves the release assembler itself resolves loose
//! commit/tree/blob objects, while the paired dirty and wrong-domain probes
//! prove it does not silently fall back to ambient state.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id};
use fgit_deflate::{DeflateLimits, DeflateProfile, deflate_zlib};
use fgit_release::{
    FileReleaseKeyProvider, GitObjectTreeAssembler, ReleaseKeyProvider, ReleaseKeyRefusal,
    SourceSnapshotRefusal,
};
use fgit_types::native::{GitHashAlgorithm, GitOid};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let unique = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fgit-release-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn write_loose(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(GitHashAlgorithm::Sha1, kind, body);
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let compressed = deflate_zlib(&framed, DeflateLimits::GIT_OBJECT, DeflateProfile::DEFAULT)
        .expect("first-party fixture deflate");
    let text = oid.to_string();
    let object_path = root.join(".git/objects").join(&text[..2]).join(&text[2..]);
    fs::create_dir_all(object_path.parent().expect("loose parent")).expect("loose parent");
    fs::write(object_path, compressed).expect("loose object");
    oid
}

fn tiny_checkout() -> (TempRoot, GitOid) {
    let root = TempRoot::new("source-boundary");
    fs::create_dir_all(root.path().join(".git/objects")).expect("object store");
    fs::write(
        root.path().join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n",
    )
    .expect("git config");
    fs::write(root.path().join("hello.txt"), b"hello release\n").expect("working tree file");
    let blob = write_loose(root.path(), GitObjectKind::Blob, b"hello release\n");
    let mut tree = b"100644 hello.txt\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = write_loose(root.path(), GitObjectKind::Tree, &tree);
    let commit = format!(
        "tree {tree}\nauthor Release Test <release@example.test> 0 +0000\ncommitter Release Test <release@example.test> 0 +0000\n\nsource boundary\n"
    );
    let commit = write_loose(root.path(), GitObjectKind::Commit, commit.as_bytes());
    (root, commit)
}

#[test]
fn commit_object_tree_is_assembled_and_worktree_twin_must_match() {
    let (root, commit) = tiny_checkout();
    let assembler = GitObjectTreeAssembler::new(root.path());
    let snapshot = assembler
        .assemble_clean(commit)
        .expect("first-party loose commit/tree/blob path is permitted");
    assert_eq!(snapshot.commit(), commit);
    assert_eq!(snapshot.tree().len(), 1);

    fs::write(root.path().join("hello.txt"), b"tampered\n").expect("tamper worktree");
    assert!(matches!(
        assembler.assemble_clean(commit),
        Err(SourceSnapshotRefusal::DirtyWorktree { ref path }) if path == "hello.txt"
    ));
}

#[test]
fn unknown_commit_is_refused_without_selecting_a_ref_or_head() {
    let (root, _) = tiny_checkout();
    let unknown = GitOid::from_hex(
        GitHashAlgorithm::Sha1,
        "1111111111111111111111111111111111111111",
    )
    .expect("typed test oid");
    assert!(matches!(
        GitObjectTreeAssembler::new(root.path()).assemble(unknown),
        Err(SourceSnapshotRefusal::UnknownCommit { commit }) if commit == unknown
    ));
}

#[cfg(unix)]
#[test]
fn file_key_provider_accepts_owner_only_release_key_and_refuses_wrong_domain() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempRoot::new("key-boundary");
    let path = root.path().join("release.key");
    fs::write(
        &path,
        "FGIT_RELEASE_KEY_V1\npurpose=package-release\nepoch=1\nroot-secret=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .expect("key fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only fixture");
    let key = FileReleaseKeyProvider::new(&path)
        .load_release_key()
        .expect("owner-only package-release key is permitted");
    let signature = key.sign(
        IdentityDomain::ReleaseAsset,
        fgit_release::RELEASE_MANIFEST_SCHEMA,
        b"bound",
    );
    signature
        .verify_with(
            &key.verifying_key(),
            IdentityDomain::ReleaseAsset,
            fgit_release::RELEASE_MANIFEST_SCHEMA,
            b"bound",
        )
        .expect("loaded key is the typed release domain");

    fs::write(
        &path,
        "FGIT_RELEASE_KEY_V1\npurpose=identity\nepoch=1\nroot-secret=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .expect("wrong-domain key fixture");
    assert!(matches!(
        FileReleaseKeyProvider::new(&path).load_release_key(),
        Err(ReleaseKeyRefusal::WrongKeyDomain { ref observed }) if observed == "identity"
    ));
}
