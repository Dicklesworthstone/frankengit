//! Native local-source fixtures: no external Git engine is called by these tests.
use super::*;
use crate::NodeConfig;
use crate::loose_import::control::ImportControl;
use crate::loose_import::layout::SourceLayout;
use fgit_admission::CanonicalRefState;
use fgit_types::{RefName, RefusalCode};

struct LinkedSource {
    worktree: PathBuf,
    common: PathBuf,
    private: PathBuf,
    main: GitOid,
    topic: GitOid,
}

fn put(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = fgit_crypto::git_object_id(format, kind, body);
    let hex = oid.to_string();
    let path = root.join("objects").join(&hex[..2]).join(&hex[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    fs::write(path, zlib_stored_member(&framed)).unwrap();
    oid
}

fn linked_source(root: &Path, format: GitHashAlgorithm) -> LinkedSource {
    // Canonicalize only the caller-selected scratch root: on macOS /var or
    // /tmp itself may be an OS symlink, rather than a source-selected link.
    let root = fs::canonicalize(root).unwrap();
    let worktree = root.join("linked checkout");
    let common = root.join("main checkout/.git");
    let private = common.join("worktrees/linked");
    fs::create_dir_all(&worktree).unwrap();
    fs::create_dir_all(&private).unwrap();
    let blob = put(&common, format, GitObjectKind::Blob, b"linked source\n");
    let mut tree = b"100644 source.txt\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = put(&common, format, GitObjectKind::Tree, &tree);
    let main_body = format!(
        "tree {tree}\nauthor Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\nmain\n"
    );
    let main = put(&common, format, GitObjectKind::Commit, main_body.as_bytes());
    let topic_body = format!(
        "tree {tree}\nparent {main}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\ntopic\n"
    );
    let topic = put(
        &common,
        format,
        GitObjectKind::Commit,
        topic_body.as_bytes(),
    );
    fs::create_dir_all(common.join("refs/heads")).unwrap();
    fs::write(common.join("refs/heads/main"), format!("{main}\n")).unwrap();
    fs::write(common.join("refs/heads/topic"), format!("{topic}\n")).unwrap();
    fs::write(common.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(private.join("HEAD"), "ref: refs/heads/topic\n").unwrap();
    fs::write(private.join("commondir"), "../..\n").unwrap();
    fs::write(
        worktree.join(".git"),
        "gitdir: ../main checkout/.git/worktrees/linked\n",
    )
    .unwrap();
    LinkedSource {
        worktree,
        common,
        private,
        main,
        topic,
    }
}

fn formatted_node(root: PathBuf, format: GitHashAlgorithm) -> OneNode {
    OneNode::init(
        NodeConfig::new(
            root,
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2),
    )
    .unwrap()
    .0
}

#[test]
fn linked_worktrees_import_shared_objects_and_selected_private_refs_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let source = linked_source(&scratch.0, format);
        // Other worktrees' private state must not be read or selected. These
        // bodies would refuse if import accidentally treated them as shared.
        for namespace in ["bisect", "rewritten", "worktree"] {
            fs::create_dir_all(source.common.join("refs").join(namespace)).unwrap();
            fs::write(
                source.common.join("refs").join(namespace).join("foreign"),
                b"invalid\n",
            )
            .unwrap();
            fs::create_dir_all(source.private.join("refs").join(namespace)).unwrap();
            fs::write(
                source.private.join("refs").join(namespace).join("selected"),
                format!("{}\n", source.topic),
            )
            .unwrap();
        }
        fs::create_dir_all(source.private.join("refs/heads")).unwrap();
        fs::write(source.private.join("refs/heads/not-shared"), b"invalid\n").unwrap();
        fs::write(
            source.private.join("packed-refs"),
            b"invalid private packed refs\n",
        )
        .unwrap();
        fs::write(
            source.common.join("packed-refs"),
            format!(
                "# pack-refs with: peeled\n{} refs/tags/v1\ninvalid refs/bisect/packed-foreign\n",
                source.main
            ),
        )
        .unwrap();
        let node = formatted_node(scratch.0.join("node"), format);
        let staged = node.stage_loose_git_import(&source.worktree).unwrap();
        assert_eq!(staged.object_count(), 4);
        assert_eq!(
            staged.refs().head_target(),
            Some(&RefName::try_new(b"refs/heads/topic").unwrap())
        );
        assert_eq!(staged.refs().refs().len(), 6);
        assert_eq!(
            staged
                .refs()
                .refs()
                .get(&RefName::try_new(b"refs/heads/main").unwrap()),
            Some(&source.main)
        );
        assert_eq!(
            staged
                .refs()
                .refs()
                .get(&RefName::try_new(b"refs/heads/topic").unwrap()),
            Some(&source.topic)
        );
        for namespace in ["bisect", "rewritten", "worktree"] {
            assert_eq!(
                staged.refs().refs().get(
                    &RefName::try_new(format!("refs/{namespace}/selected").as_bytes()).unwrap()
                ),
                Some(&source.topic)
            );
        }
        // An absolute gitfile and commondir select the same bytes and namespace.
        fs::write(
            source.worktree.join(".git"),
            format!("gitdir: {}\r\n", source.private.display()),
        )
        .unwrap();
        fs::write(
            source.private.join("commondir"),
            source.common.as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(
            node.stage_loose_git_import(&source.worktree).unwrap(),
            staged
        );
        assert_eq!(
            node.stage_loose_git_import(&source.private).unwrap(),
            staged
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn separate_git_directory_without_commondir_keeps_the_existing_import_result() {
    let scratch = ScratchDirectory::new();
    let source = linked_source(&scratch.0, GitHashAlgorithm::Sha1);
    let node = formatted_node(scratch.0.join("node"), GitHashAlgorithm::Sha1);
    let baseline = node.stage_loose_git_import(&source.common).unwrap();
    fs::write(
        source.worktree.join(".git"),
        "gitdir: ../main checkout/.git\n",
    )
    .unwrap();
    assert_eq!(
        node.stage_loose_git_import(&source.worktree).unwrap(),
        baseline
    );
    assert_eq!(
        node.stage_loose_git_import(source.common.parent().unwrap())
            .unwrap(),
        baseline
    );
    node.shutdown().unwrap();
}

#[test]
fn malformed_and_oversized_directory_controls_refuse_before_object_placement() {
    let scratch = ScratchDirectory::new();
    let source = linked_source(&scratch.0, GitHashAlgorithm::Sha1);
    let node = formatted_node(scratch.0.join("node"), GitHashAlgorithm::Sha1);
    let gitfile = source.worktree.join(".git");
    let original = fs::read(&gitfile).unwrap();
    for bytes in [
        b"".as_slice(),
        b"gitdir: \n",
        b"gitdir:/tmp/source\n",
        b"gitdir: one\ntwo\n",
        b"gitdir: one\0two\n",
        b"gitdir: .\n",
    ] {
        fs::write(&gitfile, bytes).unwrap();
        assert!(
            matches!(
                node.stage_loose_git_import(&source.worktree),
                Err(LooseGitImportRefusal::DirectoryControlInvalid { .. })
            ),
            "bytes: {bytes:?}"
        );
        assert!(node.read_git_object(source.topic).is_err());
    }
    fs::write(&gitfile, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(matches!(
        node.stage_loose_git_import(&source.worktree),
        Err(LooseGitImportRefusal::DirectoryInputBytesExceeded {
            limit: 16_384,
            observed: 16_385,
            ..
        })
    ));
    fs::write(&gitfile, original).unwrap();
    let common_file = source.private.join("commondir");
    for bytes in [b"".as_slice(), b".\n", b"../..\n../..\n", b"../..\0\n"] {
        fs::write(&common_file, bytes).unwrap();
        assert!(matches!(
            node.stage_loose_git_import(&source.worktree),
            Err(LooseGitImportRefusal::DirectoryControlInvalid { .. })
        ));
    }
    fs::write(&common_file, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(matches!(
        node.stage_loose_git_import(&source.worktree),
        Err(LooseGitImportRefusal::DirectoryInputBytesExceeded { .. })
    ));
    fs::write(&common_file, "../..\n").unwrap();
    fs::write(source.common.join("commondir"), "worktrees/linked\n").unwrap();
    assert!(matches!(
        node.stage_loose_git_import(&source.worktree),
        Err(LooseGitImportRefusal::DirectoryControlInvalid { .. })
    ));
    fs::remove_file(source.common.join("commondir")).unwrap();
    assert!(node.read_git_object(source.topic).is_err());
    assert_eq!(
        node.stage_loose_git_import(&source.worktree)
            .unwrap()
            .object_count(),
        4
    );
    node.shutdown().unwrap();
}

#[test]
fn linked_source_revalidation_detects_controls_head_refs_and_alternates_changes() {
    for change in 0..6 {
        let scratch = ScratchDirectory::new();
        let source = linked_source(&scratch.0, GitHashAlgorithm::Sha1);
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let layout = SourceLayout::resolve(&source.worktree, &control).unwrap();
        let refs = CanonicalRefState::new_with_head_target(
            layout
                .read_refs(GitHashAlgorithm::Sha1, 3, &control)
                .unwrap(),
            layout.read_head(&control).unwrap(),
        )
        .unwrap();
        layout
            .revalidate(GitHashAlgorithm::Sha1, 3, &refs, &control)
            .unwrap();
        match change {
            0 => fs::write(
                source.worktree.join(".git"),
                format!("gitdir: {}\n", source.private.display()),
            )
            .unwrap(),
            1 => fs::write(
                source.private.join("commondir"),
                source.common.as_os_str().as_encoded_bytes(),
            )
            .unwrap(),
            2 => fs::write(source.private.join("HEAD"), "ref: refs/heads/main\n").unwrap(),
            3 => fs::write(
                source.common.join("refs/heads/topic"),
                format!("{}\n", source.main),
            )
            .unwrap(),
            4 => fs::write(
                source.common.join("packed-refs"),
                format!("{} refs/tags/new\n", source.main),
            )
            .unwrap(),
            _ => {
                fs::create_dir_all(source.common.join("objects/info")).unwrap();
                fs::write(source.common.join("objects/info/alternates"), "outside\n").unwrap();
            }
        }
        let error = layout
            .revalidate(GitHashAlgorithm::Sha1, 3, &refs, &control)
            .unwrap_err();
        if change == 5 {
            assert!(matches!(
                error,
                LooseGitImportRefusal::ObjectAlternatesUnsupported(_)
            ));
        } else {
            assert!(
                matches!(error, LooseGitImportRefusal::SourceLayoutChanged(_)),
                "change {change}: {error:?}"
            );
        }
    }
}

#[test]
fn shared_and_private_refs_use_one_limit_and_cancelled_discovery_stays_cancelled() {
    let scratch = ScratchDirectory::new();
    let source = linked_source(&scratch.0, GitHashAlgorithm::Sha256);
    fs::create_dir_all(source.private.join("refs/worktree")).unwrap();
    fs::write(
        source.private.join("refs/worktree/pin"),
        format!("{}\n", source.topic),
    )
    .unwrap();
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let layout = SourceLayout::resolve(&source.worktree, &control).unwrap();
    assert!(matches!(
        layout.read_refs(GitHashAlgorithm::Sha256, 2, &control),
        Err(LooseGitImportRefusal::RefLimitExceeded {
            observed: 3,
            limit: 2
        })
    ));
    assert_eq!(
        layout
            .read_refs(GitHashAlgorithm::Sha256, 3, &control)
            .unwrap()
            .len(),
        3
    );
    let mut stopped = || false;
    let cancelled = ImportControl::new(&mut stopped);
    assert!(matches!(
        SourceLayout::resolve(&source.worktree, &cancelled),
        Err(LooseGitImportRefusal::Interrupted {
            code: RefusalCode::CancellationInProgress,
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn source_selected_symlinks_are_never_followed_in_directory_indirection() {
    use std::os::unix::fs::symlink;
    for attack in 0..5 {
        let scratch = ScratchDirectory::new();
        let source = linked_source(&scratch.0, GitHashAlgorithm::Sha1);
        match attack {
            0 => {
                symlink(&source.private, source.worktree.join("alias")).unwrap();
                fs::write(source.worktree.join(".git"), "gitdir: alias\n").unwrap();
            }
            1 => {
                symlink(&source.common, source.worktree.join("alias")).unwrap();
                fs::write(
                    source.worktree.join(".git"),
                    "gitdir: alias/worktrees/linked\n",
                )
                .unwrap();
            }
            2 => {
                symlink(&source.common, source.worktree.join("alias")).unwrap();
                fs::write(
                    source.worktree.join(".git"),
                    "gitdir: alias/../main checkout/.git\n",
                )
                .unwrap();
            }
            3 => {
                let common_file = source.private.join("commondir");
                fs::remove_file(&common_file).unwrap();
                fs::write(source.private.join("actual-common"), "../..\n").unwrap();
                symlink("actual-common", &common_file).unwrap();
            }
            _ => {
                fs::create_dir_all(source.private.join("refs")).unwrap();
                symlink(
                    source.common.join("refs"),
                    source.private.join("refs/worktree"),
                )
                .unwrap();
            }
        }
        let node = formatted_node(scratch.0.join("node"), GitHashAlgorithm::Sha1);
        assert!(
            matches!(
                node.stage_loose_git_import(&source.worktree),
                Err(LooseGitImportRefusal::SymbolicLink(_))
            ),
            "attack {attack}"
        );
        assert!(node.read_git_object(source.topic).is_err());
        node.shutdown().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn gitfile_directory_paths_preserve_native_non_utf8_bytes() {
    use std::os::unix::ffi::OsStrExt;
    let scratch = ScratchDirectory::new();
    let source = linked_source(&scratch.0, GitHashAlgorithm::Sha1);
    let common = source
        .common
        .with_file_name(std::ffi::OsStr::from_bytes(b"metadata-\xff"));
    fs::rename(&source.common, &common).unwrap();
    let private = common.join("worktrees/linked");
    let mut gitfile = b"gitdir: ".to_vec();
    gitfile.extend_from_slice(private.as_os_str().as_bytes());
    gitfile.push(b'\n');
    fs::write(source.worktree.join(".git"), gitfile).unwrap();
    let node = formatted_node(scratch.0.join("node"), GitHashAlgorithm::Sha1);
    assert_eq!(
        node.stage_loose_git_import(&source.worktree)
            .unwrap()
            .object_count(),
        4
    );
    node.shutdown().unwrap();
}
