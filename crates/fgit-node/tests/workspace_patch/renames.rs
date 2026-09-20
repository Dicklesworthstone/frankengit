//! Exercise relocation through the real file-backed node, exporter and admission.
use super::*;

fn rename(from: &str, to: &str) -> String {
    format!("diff --git a/{from} b/{to}\nsimilarity index 100%\nrename from {from}\nrename to {to}\n")
}
fn removed(f: &Fixture) -> GitOid {
    git_object_id(f.format, GitObjectKind::Blob, b"remove\n")
}
fn edited_rename(old: GitOid, new: GitOid) -> String {
    format!("diff --git a/edit.txt b/dir/renamed.txt\nold mode 100644\nnew mode 100755\nsimilarity index 50%\nrename from edit.txt\nrename to dir/renamed.txt\nindex {old}..{new}\n--- a/edit.txt\n+++ b/dir/renamed.txt\n@@ -1 +1 @@\n-before\n+after\n")
}

#[test]
fn rename_prepares_one_exact_tree_publishes_once_and_survives_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let before = f.observed();
        let patch = rename("edit.txt", "renamed.txt");
        // One file section may have two effects, without consuming two file slots.
        let limits = PatchLimits { max_files: 1, ..PatchLimits::default() };
        let candidate = f.prepare(patch.as_bytes(), limits).unwrap();
        assert_eq!(f.observed(), before);
        assert_eq!(candidate.source_commit, f.base);
        assert_eq!(candidate.patch_sha256, sha256_digest(patch.as_bytes()));
        assert_eq!(candidate.bundle_bytes(), f.prepare(patch.as_bytes(), limits).unwrap().bundle_bytes());
        assert_eq!(candidate.paths.iter().map(|path| path.path.as_slice()).collect::<Vec<_>>(),
            vec![b"edit.txt".as_slice(), b"renamed.txt"]);
        assert_eq!(candidate.paths[0].old_blob, Some(f.old));
        assert_eq!(candidate.paths[0].new_blob, None);
        assert_eq!(candidate.paths[0].new_mode, None);
        assert_eq!(candidate.paths[1].old_blob, None);
        assert_eq!(candidate.paths[1].new_blob, Some(f.old));
        assert_eq!(candidate.paths[1].new_mode, Some(0o100644));
        let removed = removed(&f);
        let tree_bytes = [b"100644 keep.txt\0".as_slice(), f.kept.as_bytes(),
            b"100644 remove.txt\0", removed.as_bytes(), b"100644 renamed.txt\0", f.old.as_bytes()].concat();
        assert_eq!(candidate.root_tree, git_object_id(format, GitObjectKind::Tree, &tree_bytes));
        let terminal = apply(&f, &candidate, b"rename-publication");
        assert!(matches!(terminal.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(f.node().read_git_object(candidate.root_tree).unwrap().payload(), tree_bytes);
        assert_eq!(f.node().read_git_object(f.old).unwrap().payload(), b"before\n");
        let published = f.observed();
        assert_eq!(published.0, candidate.candidate_commit);
        assert_eq!(apply(&f, &candidate, b"rename-publication"), terminal);
        assert_eq!(f.observed(), published);
        f.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(config(&f.root, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        f.node = Some(node);
        assert_eq!(f.observed(), published);
        assert_eq!(apply(&f, &candidate, b"rename-publication"), terminal);
        assert_eq!(f.observed(), published);
    }
}

#[test]
fn edited_rename_builds_exact_nested_tree_and_verifies_both_native_indexes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let before = f.observed();
        let after = git_object_id(format, GitObjectKind::Blob, b"after\n");
        for (old, new) in [(f.kept, after), (f.old, f.kept)] {
            assert!(matches!(f.prepare(edited_rename(old, new).as_bytes(), PatchLimits::default()),
                Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_))));
            assert_eq!(f.observed(), before);
        }
        let patch = edited_rename(f.old, after);
        let candidate = f.prepare(patch.as_bytes(), PatchLimits::default()).unwrap();
        assert_eq!(f.observed(), before);
        let nested = [b"100755 renamed.txt\0".as_slice(), after.as_bytes()].concat();
        let nested_id = git_object_id(format, GitObjectKind::Tree, &nested);
        let removed = removed(&f);
        let root = [b"40000 dir\0".as_slice(), nested_id.as_bytes(),
            b"100644 keep.txt\0", f.kept.as_bytes(), b"100644 remove.txt\0", removed.as_bytes()].concat();
        assert_eq!(candidate.root_tree, git_object_id(format, GitObjectKind::Tree, &root));
        assert_eq!(candidate.paths.iter().map(|path| path.path.as_slice()).collect::<Vec<_>>(),
            vec![b"dir/renamed.txt".as_slice(), b"edit.txt"]);
        assert_eq!(candidate.paths[0].old_blob, None);
        assert_eq!(candidate.paths[0].new_blob, Some(after));
        assert_eq!(candidate.paths[0].new_mode, Some(0o100755));
        assert_eq!(candidate.paths[0].hunks, 1);
        assert_eq!(candidate.paths[1].old_blob, Some(f.old));
        assert_eq!(candidate.paths[1].new_blob, None);
        assert_eq!(candidate.paths[1].hunks, 0);
        assert!(matches!(apply(&f, &candidate, b"edited-rename").commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }));
        assert_eq!(f.node().read_git_object(candidate.root_tree).unwrap().payload(), root);
        assert_eq!(f.node().read_git_object(nested_id).unwrap().payload(), nested);
        assert_eq!(f.node().read_git_object(after).unwrap().payload(), b"after\n");
        assert_eq!(f.node().read_git_object(f.kept).unwrap().payload(), b"preserve\0me\n");
    }
}

#[test]
fn pure_binary_rename_preserves_verified_bytes_and_unedited_siblings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let patch = rename("keep.txt", "binary.bin") + &format!("index {}..{} 100644\n", f.kept, f.kept);
        let candidate = f.prepare(patch.as_bytes(), PatchLimits::default()).unwrap();
        let removed = removed(&f);
        let root = [b"100644 binary.bin\0".as_slice(), f.kept.as_bytes(),
            b"100644 edit.txt\0", f.old.as_bytes(), b"100644 remove.txt\0", removed.as_bytes()].concat();
        assert_eq!(candidate.root_tree, git_object_id(format, GitObjectKind::Tree, &root));
        assert_eq!(candidate.paths[0].path.as_slice(), b"binary.bin");
        assert_eq!(candidate.paths[0].new_blob, Some(f.kept));
        assert_eq!(candidate.paths[1].path.as_slice(), b"keep.txt");
        assert_eq!(candidate.paths[1].new_blob, None);
        assert!(matches!(apply(&f, &candidate, b"binary-rename").commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }));
        assert_eq!(f.node().read_git_object(candidate.root_tree).unwrap().payload(), root);
        assert_eq!(f.node().read_git_object(f.kept).unwrap().payload(), b"preserve\0me\n");
    }
}

#[test]
fn both_paths_require_read_and_write_scope_before_any_fetch() {
    let f = Fixture::new(GitHashAlgorithm::Sha1);
    let node = f.node(); let request = node.request_context(); let before = f.observed();
    let patch = rename("edit.txt", "renamed.txt");
    let path = |name: &[u8]| TreePath::parse_default(name).unwrap();
    let read_names: [&[u8]; 4] = [b"edit.txt", b"keep.txt", b"remove.txt", b"renamed.txt"];
    let reads = || read_names.iter().map(|name| path(name)).collect::<Vec<_>>();
    let writes = || vec![path(b"edit.txt"), path(b"renamed.txt")];
    for (reads, writes) in [
        (reads(), vec![path(b"edit.txt")]),
        (reads(), vec![path(b"renamed.txt")]),
        (reads().into_iter().filter(|p| p.as_bytes() != b"edit.txt").collect(), writes()),
        (reads().into_iter().filter(|p| p.as_bytes() != b"renamed.txt").collect(), writes()),
    ] {
        let mut capability = TreeCapability::new(WorkspaceId::from_bytes([0xd4; 16]), REPOSITORY, reads, writes);
        let result = node.runtime().block_on(node.prepare_workspace_patch_in::<Sha1>(&request,
            &reference(), f.base, &RefVisibility::new(), &mut capability,
            patch.as_bytes(), 0, &metadata(), PatchLimits::default()));
        assert!(matches!(result, Err(NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(_)))));
        assert_eq!(capability.fetched_bytes(), 0);
        assert_eq!(capability.fetched_files(), 0);
        assert_eq!(f.observed(), before);
    }
    let mut capability = TreeCapability::new(WorkspaceId::from_bytes([0xd4; 16]), REPOSITORY, reads(), writes());
    let scoped = node.runtime().block_on(node.prepare_workspace_patch_in::<Sha1>(&request,
        &reference(), f.base, &RefVisibility::new(), &mut capability,
        patch.as_bytes(), 0, &metadata(), PatchLimits::default())).unwrap();
    let trusted = f.prepare(patch.as_bytes(), PatchLimits::default()).unwrap();
    assert_eq!(scoped.bundle_bytes(), trusted.bundle_bytes());
    assert_eq!(scoped.paths, trusted.paths);
    assert_eq!(f.observed(), before);
}

#[test]
fn occupied_or_missing_paths_and_false_identity_never_change_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format); let before = f.observed();
        assert!(matches!(f.prepare(rename("edit.txt", "keep.txt").as_bytes(), PatchLimits::default()),
            Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("rename destination already exists"))));
        assert!(matches!(f.prepare(rename("missing.txt", "new.txt").as_bytes(), PatchLimits::default()),
            Err(NodeWorkspaceRefusal::WorkspacePatch(PatchError::SourcePresence))));
        assert!(f.prepare(rename("edit.txt", "keep.txt/child").as_bytes(), PatchLimits::default()).is_err());
        let false_identity = rename("edit.txt", "new.txt") + "--- a/edit.txt\n+++ b/new.txt\n@@ -1 +1 @@\n-before\n+after\n";
        assert!(f.prepare(false_identity.as_bytes(), PatchLimits::default()).is_err());
        for unsupported in ["GIT binary patch\nliteral 1\nx\n", "copy from edit.txt\ncopy to new.txt\n",
            "old mode 120000\nnew mode 100644\n"] {
            assert!(f.prepare((rename("edit.txt", "new.txt") + unsupported).as_bytes(), PatchLimits::default()).is_err());
        }
        assert_eq!(f.observed(), before);
        assert!(f.prepare(rename("edit.txt", "new.txt").as_bytes(), PatchLimits::default()).is_ok());
        assert_eq!(f.observed(), before);
    }
}

#[test]
fn later_failure_and_aggregate_budget_cannot_publish_half_a_rename() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format); let before = f.observed();
        let start = rename("edit.txt", "a.txt");
        let bad = start.clone() + "diff --git a/remove.txt b/remove.txt\n--- a/remove.txt\n+++ b/remove.txt\n@@ -1 +1 @@\n-wrong\n+replacement\n";
        assert!(matches!(f.prepare(bad.as_bytes(), PatchLimits::default()),
            Err(NodeWorkspaceRefusal::WorkspacePatch(PatchError::ContextMismatch { .. }))));
        assert_eq!(f.observed(), before);
        let good = bad.replace("-wrong\n", "-remove\n");
        let candidate = f.prepare(good.as_bytes(), PatchLimits::default()).unwrap();
        assert_eq!(candidate.paths.len(), 3);
        assert_eq!(candidate.paths[0].path.as_slice(), b"a.txt");
        assert_eq!(candidate.paths[1].path.as_slice(), b"edit.txt");
        assert_eq!(candidate.paths[2].path.as_slice(), b"remove.txt");
        let two = start + &rename("remove.txt", "z.txt");
        assert!(f.prepare(two.as_bytes(), PatchLimits { max_output_bytes: 14, ..PatchLimits::default() }).is_ok());
        assert!(matches!(f.prepare(two.as_bytes(), PatchLimits { max_output_bytes: 13, ..PatchLimits::default() }),
            Err(NodeWorkspaceRefusal::WorkspacePatch(PatchError::Budget("aggregate result bytes")))));
        assert!(matches!(f.prepare(two.as_bytes(), PatchLimits { max_files: 1, ..PatchLimits::default() }),
            Err(NodeWorkspaceRefusal::WorkspacePatch(PatchError::Budget("patch files")))));
        assert_eq!(f.observed(), before);
    }
}

#[test]
fn stale_or_cancelled_rename_requires_a_fresh_live_request() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format); let node = f.node(); let before = f.observed();
        let patch = rename("edit.txt", "renamed.txt");
        let request = node.request_context();
        assert!(matches!(node.runtime().block_on(node.prepare_trusted_patch_in(&request,
            &reference(), f.old, [0xd4; 16], patch.as_bytes(), &metadata(), PatchLimits::default())),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)));
        request.cancel();
        assert!(node.runtime().block_on(node.prepare_trusted_patch_in(&request,
            &reference(), f.base, [0xd4; 16], patch.as_bytes(), &metadata(), PatchLimits::default())).is_err());
        assert_eq!(f.observed(), before);
        assert!(f.prepare(patch.as_bytes(), PatchLimits::default()).is_ok());
        assert_eq!(f.observed(), before);
    }
}

#[test]
fn rename_out_of_last_child_prunes_empty_ancestors_and_never_replaces_a_directory() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let seed = b"diff --git a/dir/deep/file b/dir/deep/file\nnew file mode 100644\n--- /dev/null\n+++ b/dir/deep/file\n@@ -0,0 +1 @@\n+nested\n";
        let initial = f.prepare(seed, PatchLimits::default()).unwrap();
        assert!(matches!(apply(&f, &initial, b"rename-nested-seed").commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }));
        f.base = initial.candidate_commit;
        let before = f.observed();
        assert!(matches!(f.prepare(rename("edit.txt", "dir").as_bytes(), PatchLimits::default()),
            Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("rename destination already exists"))));
        assert_eq!(f.observed(), before);
        let candidate = f.prepare(rename("dir/deep/file", "moved.txt").as_bytes(), PatchLimits::default()).unwrap();
        assert_eq!(f.observed(), before);
        let nested = git_object_id(format, GitObjectKind::Blob, b"nested\n");
        let removed = removed(&f);
        let root = [b"100644 edit.txt\0".as_slice(), f.old.as_bytes(),
            b"100644 keep.txt\0", f.kept.as_bytes(), b"100644 moved.txt\0", nested.as_bytes(),
            b"100644 remove.txt\0", removed.as_bytes()].concat();
        assert_eq!(candidate.root_tree, git_object_id(format, GitObjectKind::Tree, &root));
        assert!(matches!(apply(&f, &candidate, b"rename-prune").commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }));
        assert_eq!(f.node().read_git_object(candidate.root_tree).unwrap().payload(), root);
    }
}
