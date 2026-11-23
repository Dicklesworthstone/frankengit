#![forbid(unsafe_code)]
//! Native-byte path witnesses, including hostile sources and complete bounded
//! failure. This is an object-source fixture, not an authority substitute.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fgit_admission::ProjectionFailure;
use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::protection::path_reviews::{
    MAX_MERGE_CHANGED_PATH_BYTES, MAX_MERGE_CHANGED_PATHS, MAX_MERGE_PATH_BYTES,
    MAX_MERGE_PATH_DEPTH, verify_merge_paths, verify_rebase_paths, verify_source_paths,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::agent_credential::SourcePublicationScope;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RefusalCode};

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, CanonicalPackObject>,
    reads: RefCell<Vec<GitOid>>,
}
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.bodies.insert(
            id,
            // The false edge metadata must never influence the native parser.
            CanonicalPackObject::new(id, kind, body, vec![id], 0, 0),
        );
        id
    }
    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&[u8], &[u8], GitOid)]) -> GitOid {
        let mut body = Vec::new();
        for (mode, name, id) in entries {
            body.extend_from_slice(mode);
            body.push(b' ');
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(id.as_bytes());
        }
        self.put(format, GitObjectKind::Tree, body)
    }
    fn commit(&mut self, tree: GitOid, parent: Option<GitOid>, label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = parent {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
        body.push_str(label);
        self.put(tree.algorithm(), GitObjectKind::Commit, body.into_bytes())
    }
    fn merge(&mut self, before: GitOid, after: GitOid) -> NativeMerge {
        let target = self.commit(before, None, "target\n");
        let candidate = self.commit(after, Some(target), "candidate\n");
        NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_tip: candidate,
            base_tip: target,
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            target_tip_before: target,
            merge_commit: candidate,
        }
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.borrow_mut().push(*id);
        self.bodies
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

fn blob(format: GitHashAlgorithm, bytes: &[u8]) -> GitOid {
    // Payloads and gitlink targets need not be read to prove tree-entry changes.
    git_object_id(format, GitObjectKind::Blob, bytes)
}
fn paths(objects: &Objects, merge: &NativeMerge) -> Vec<Vec<u8>> {
    let witness =
        verify_merge_paths(objects, merge, MergeObjectLimits::default(), &mut || true).unwrap();
    assert_eq!(witness.merge(), merge);
    witness.changed_paths().to_vec()
}

fn source_paths(objects: &Objects, merge: &NativeMerge) -> Vec<Vec<u8>> {
    let witness = verify_source_paths(
        objects,
        merge.target_tip_before,
        merge.merge_commit,
        MergeObjectLimits::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(witness.before(), merge.target_tip_before);
    assert_eq!(witness.after(), merge.merge_commit);
    witness.changed_paths().to_vec()
}

fn source_scope(prefix: &[u8]) -> SourcePublicationScope {
    let reference: String = b"refs/heads/main"
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    SourcePublicationScope::new(&format!("exact:{reference}"), vec![prefix.to_vec()]).unwrap()
}

#[test]
fn complete_actual_delta_includes_structural_replacements_and_raw_leaf_identity_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let old = blob(format, b"old");
        let new = blob(format, b"new");
        let empty = objects.tree(format, &[]);
        let old_child = objects.tree(format, &[(b"100644", b"secret", old)]);
        let new_child = objects.tree(format, &[(b"100644", b"secret", new)]);
        let old_deep = objects.tree(format, &[(b"40000", b"deep", old_child)]);
        let stable = objects.tree(format, &[(b"100644", b"untouched", old)]);
        let before = objects.tree(
            format,
            &[
                (b"40000", b"deleted", old_deep),
                (b"40000", b"dir_to_file", old_deep),
                (b"100644", b"file_to_dir", old),
                (b"160000", b"gitlink", old),
                (b"100644", b"mode", old),
                (b"40000", b"nested", old_child),
                (b"100644", b"old-name", old),
                (b"100644", b"raw\xff", old),
                (b"40000", b"stable", stable),
                (b"120000", b"symlink", old),
            ],
        );
        let after = objects.tree(
            format,
            &[
                (b"40000", b"added", new_child),
                (b"100644", b"dir_to_file", new),
                (b"40000", b"empty", empty),
                (b"40000", b"file_to_dir", new_child),
                (b"160000", b"gitlink", new),
                (b"100755", b"mode", old),
                (b"40000", b"nested", new_child),
                (b"100644", b"new-name", old),
                (b"100644", b"raw\xff", new),
                (b"40000", b"stable", stable),
                (b"120000", b"symlink", new),
            ],
        );
        let merge = objects.merge(before, after);
        objects.bodies.remove(&stable);
        let mut expected: Vec<Vec<u8>> = [
            b"added".as_slice(),
            b"added/secret",
            b"deleted",
            b"deleted/deep",
            b"deleted/deep/secret",
            b"dir_to_file",
            b"dir_to_file/deep",
            b"dir_to_file/deep/secret",
            b"empty",
            b"file_to_dir",
            b"file_to_dir/secret",
            b"gitlink",
            b"mode",
            b"nested/secret",
            b"old-name",
            b"new-name",
            b"raw\xff",
            b"symlink",
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
        expected.sort_unstable();
        assert_eq!(paths(&objects, &merge), expected);
        // Source scope elides only pure nonempty directory containers.
        // Replacements, empty entries, executable modes, gitlinks, symlinks,
        // raw names and both rename endpoints remain independent path facts.
        let expected_source: Vec<_> = [
            b"added/secret".as_slice(),
            b"deleted/deep/secret",
            b"dir_to_file",
            b"dir_to_file/deep/secret",
            b"empty",
            b"file_to_dir",
            b"file_to_dir/secret",
            b"gitlink",
            b"mode",
            b"nested/secret",
            b"new-name",
            b"old-name",
            b"raw\xff",
            b"symlink",
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
        assert_eq!(source_paths(&objects, &merge), expected_source);
        assert!(!objects.reads.borrow().contains(&stable));
        assert!(!objects.reads.borrow().contains(&old));
        assert!(!objects.reads.borrow().contains(&new));
    }
}

#[test]
fn equal_tree_identity_needs_only_verified_commit_bodies_and_ignores_source_side_claims() {
    let format = GitHashAlgorithm::Sha256;
    let mut objects = Objects::default();
    let tree = objects.tree(format, &[]);
    let merge = objects.merge(tree, tree);
    objects.bodies.remove(&tree);
    assert!(paths(&objects, &merge).is_empty());
    assert_eq!(
        *objects.reads.borrow(),
        [merge.target_tip_before, merge.merge_commit]
    );
}

fn small() -> (Objects, NativeMerge, GitOid) {
    let format = GitHashAlgorithm::Sha256;
    let mut objects = Objects::default();
    let before = objects.tree(format, &[(b"100644", b"file", blob(format, b"old"))]);
    let after = objects.tree(format, &[(b"100644", b"file", blob(format, b"new"))]);
    let merge = objects.merge(before, after);
    (objects, merge, after)
}

#[test]
fn missing_wrong_identity_wrong_kind_and_corrupt_selected_bytes_never_mint_a_witness() {
    let invalid = ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid);
    for wrong in 0..4 {
        let (mut objects, merge, tree) = small();
        let original = objects.bodies.remove(&tree).unwrap();
        match wrong {
            0 => {}
            1 => {
                let other = blob(tree.algorithm(), b"claimed different key");
                objects.bodies.insert(
                    tree,
                    CanonicalPackObject::new(
                        other,
                        GitObjectKind::Tree,
                        original.body().to_vec(),
                        Vec::new(),
                        0,
                        0,
                    ),
                );
            }
            2 => {
                objects.bodies.insert(
                    tree,
                    CanonicalPackObject::new(
                        tree,
                        GitObjectKind::Blob,
                        original.body().to_vec(),
                        Vec::new(),
                        0,
                        0,
                    ),
                );
            }
            _ => {
                let mut body = original.body().to_vec();
                body[7] ^= 1;
                objects.bodies.insert(
                    tree,
                    CanonicalPackObject::new(tree, GitObjectKind::Tree, body, Vec::new(), 0, 0),
                );
            }
        }
        assert_eq!(
            verify_merge_paths(&objects, &merge, Default::default(), &mut || true).unwrap_err(),
            if wrong == 0 {
                ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing)
            } else {
                invalid
            }
        );
    }
    let (mut objects, merge, _) = small();
    let original = objects.bodies[&merge.merge_commit].clone();
    let mut body = original.body().to_vec();
    body.extend_from_slice(b"changed message");
    objects.bodies.insert(
        merge.merge_commit,
        CanonicalPackObject::new(
            merge.merge_commit,
            GitObjectKind::Commit,
            body,
            Vec::new(),
            0,
            0,
        ),
    );
    assert_eq!(
        verify_merge_paths(&objects, &merge, Default::default(), &mut || true).unwrap_err(),
        invalid
    );
}

#[test]
fn every_read_entry_byte_and_cancellation_bound_fails_without_a_partial_result() {
    let (objects, merge, _) = small();
    for limits in [
        MergeObjectLimits {
            max_objects: 1,
            ..Default::default()
        },
        MergeObjectLimits {
            max_edges: 1,
            ..Default::default()
        },
        MergeObjectLimits {
            max_object_bytes: 1,
            ..Default::default()
        },
        MergeObjectLimits {
            max_total_bytes: 1,
            ..Default::default()
        },
        MergeObjectLimits {
            max_edges: 0,
            ..Default::default()
        },
        MergeObjectLimits {
            max_objects: MergeObjectLimits::default().max_objects + 1,
            ..Default::default()
        },
    ] {
        assert_eq!(
            verify_merge_paths(&objects, &merge, limits, &mut || true).unwrap_err(),
            ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
        );
    }
    let mut checkpoints = 0;
    verify_merge_paths(&objects, &merge, Default::default(), &mut || {
        checkpoints += 1;
        true
    })
    .unwrap();
    for stop in 0..checkpoints {
        let mut visits = 0;
        assert_eq!(
            verify_merge_paths(&objects, &merge, Default::default(), &mut || {
                let live = visits != stop;
                visits += 1;
                live
            })
            .unwrap_err(),
            ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)
        );
    }
    assert_eq!(paths(&objects, &merge), [b"file".to_vec()]);
}

#[test]
fn compatible_import_cannot_hide_changes_in_duplicate_or_ambiguous_components() {
    let format = GitHashAlgorithm::Sha1;
    for name in [b"".as_slice(), b".", b"..", b"a/b"] {
        let mut objects = Objects::default();
        let before = objects.tree(format, &[]);
        let after = objects.tree(format, &[(b"100644", name, blob(format, b"content"))]);
        let merge = objects.merge(before, after);
        assert_eq!(
            verify_merge_paths(&objects, &merge, Default::default(), &mut || true).unwrap_err(),
            ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)
        );
    }
    let mut objects = Objects::default();
    let before = objects.tree(format, &[]);
    let after = objects.tree(
        format,
        &[
            (b"100644", b"duplicate", blob(format, b"one")),
            (b"100755", b"duplicate", blob(format, b"two")),
        ],
    );
    let merge = objects.merge(before, after);
    assert_eq!(
        verify_merge_paths(&objects, &merge, Default::default(), &mut || true).unwrap_err(),
        ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn changed_path_count_depth_length_and_total_bytes_have_complete_boundaries() {
    let format = GitHashAlgorithm::Sha256;
    for count in [MAX_MERGE_CHANGED_PATHS, MAX_MERGE_CHANGED_PATHS + 1] {
        let mut objects = Objects::default();
        let before = objects.tree(format, &[]);
        let names: Vec<_> = (0..count)
            .map(|n| format!("file-{n:05}").into_bytes())
            .collect();
        let entries: Vec<_> = names
            .iter()
            .map(|name| {
                (
                    b"100644".as_slice(),
                    name.as_slice(),
                    blob(format, b"content"),
                )
            })
            .collect();
        let after = objects.tree(format, &entries);
        let merge = objects.merge(before, after);
        let result = verify_merge_paths(&objects, &merge, Default::default(), &mut || true);
        if count == MAX_MERGE_CHANGED_PATHS {
            assert_eq!(result.unwrap().changed_paths().len(), count);
        } else {
            assert_eq!(
                result.unwrap_err(),
                ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
            );
        }
    }
    for depth in [MAX_MERGE_PATH_DEPTH, MAX_MERGE_PATH_DEPTH + 1] {
        let mut objects = Objects::default();
        let before = objects.tree(format, &[]);
        let mut after = objects.tree(format, &[(b"100644", b"leaf", blob(format, b"content"))]);
        for _ in 1..depth {
            after = objects.tree(format, &[(b"40000", b"dir", after)]);
        }
        let merge = objects.merge(before, after);
        let result = verify_merge_paths(&objects, &merge, Default::default(), &mut || true);
        if depth == MAX_MERGE_PATH_DEPTH {
            assert_eq!(result.unwrap().changed_paths().len(), depth);
        } else {
            assert_eq!(
                result.unwrap_err(),
                ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
            );
        }
    }
    for length in [MAX_MERGE_PATH_BYTES, MAX_MERGE_PATH_BYTES + 1] {
        let mut objects = Objects::default();
        let before = objects.tree(format, &[]);
        let name = vec![b'a'; length];
        let after = objects.tree(format, &[(b"100644", &name, blob(format, b"content"))]);
        let merge = objects.merge(before, after);
        let result = verify_merge_paths(&objects, &merge, Default::default(), &mut || true);
        if length == MAX_MERGE_PATH_BYTES {
            assert_eq!(result.unwrap().changed_paths(), &[name]);
        } else {
            assert_eq!(
                result.unwrap_err(),
                ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
            );
        }
    }
    let mut objects = Objects::default();
    let before = objects.tree(format, &[]);
    let count = MAX_MERGE_CHANGED_PATH_BYTES / MAX_MERGE_PATH_BYTES + 1;
    let names: Vec<_> = (0..count)
        .map(|n| {
            let mut name = format!("{n:04}").into_bytes();
            name.resize(MAX_MERGE_PATH_BYTES, b'x');
            name
        })
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| {
            (
                b"100644".as_slice(),
                name.as_slice(),
                blob(format, b"content"),
            )
        })
        .collect();
    let after = objects.tree(format, &entries);
    let merge = objects.merge(before, after);
    assert_eq!(
        verify_merge_paths(&objects, &merge, Default::default(), &mut || true).unwrap_err(),
        ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
    );
}


#[test]
fn narrow_source_scope_can_create_first_and_remove_last_nested_file() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let empty = objects.tree(format, &[]);
        let component = objects.tree(format, &[(b"100644", b"lib.rs", blob(format, b"new"))]);
        let new = objects.tree(format, &[(b"40000", b"component", component)]);
        let src = objects.tree(format, &[(b"40000", b"new", new)]);
        let nested = objects.tree(format, &[(b"40000", b"src", src)]);
        let scope = source_scope(b"src/new/component");
        let exact_file = source_scope(b"src/new/component/lib.rs");
        assert!(!scope.permits_path(b"src"));
        assert!(!scope.permits_path(b"src/new"));
        for (before, after) in [(empty, nested), (nested, empty)] {
            let merge = objects.merge(before, after);
            let changed = source_paths(&objects, &merge);
            assert_eq!(changed, [b"src/new/component/lib.rs".to_vec()]);
            assert!(changed.iter().all(|path| scope.permits_path(path)));
            assert!(changed.iter().all(|path| exact_file.permits_path(path)));

            // The source-specific rule must not weaken merge/rebase reviewers.
            let structural = [
                b"src".to_vec(),
                b"src/new".to_vec(),
                b"src/new/component".to_vec(),
                b"src/new/component/lib.rs".to_vec(),
            ];
            assert_eq!(paths(&objects, &merge), structural);
            let rebase = verify_rebase_paths(
                &objects,
                &merge,
                MergeObjectLimits::default(),
                &mut || true,
            )
            .unwrap();
            assert_eq!(rebase.changed_paths(), structural.as_slice());
        }
    }
}

#[test]
fn narrow_source_scope_cannot_replace_an_ungranted_file_with_a_directory_or_back() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let content = blob(format, b"content");
        let leaf = objects.tree(format, &[(b"100644", b"file", content)]);
        let nested = objects.tree(format, &[(b"40000", b"component", leaf)]);
        let directory = objects.tree(format, &[(b"40000", b"src", nested)]);
        let scope = source_scope(b"src/component");
        for mode in [b"100644".as_slice(), b"120000", b"160000"] {
            let scalar = objects.tree(format, &[(mode, b"src", content)]);
            for (before, after) in [(scalar, directory), (directory, scalar)] {
                let merge = objects.merge(before, after);
                let changed = source_paths(&objects, &merge);
                assert_eq!(
                    changed,
                    [b"src".to_vec(), b"src/component/file".to_vec()]
                );
                assert!(!changed.iter().all(|path| scope.permits_path(path)));
            }
        }
    }
}

#[test]
fn narrow_source_scope_retains_unrelated_empty_trees_and_sibling_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let empty = objects.tree(format, &[]);
        let component = objects.tree(format, &[(b"100644", b"lib.rs", blob(format, b"new"))]);
        let scope = source_scope(b"src/new/component");
        // An explicitly added/removed empty directory is not justified merely
        // because its path is an ancestor of some possible granted child.
        let empty_new = objects.tree(format, &[(b"40000", b"new", empty)]);
        let empty_ancestor = objects.tree(format, &[(b"40000", b"src", empty_new)]);
        for (before, after) in [(empty, empty_ancestor), (empty_ancestor, empty)] {
            let merge = objects.merge(before, after);
            let changed = source_paths(&objects, &merge);
            assert_eq!(changed, [b"src/new".to_vec()]);
            assert!(!changed.iter().all(|path| scope.permits_path(path)));
        }

        for mode in [b"40000".as_slice(), b"100644"] {
            let outside = if mode == b"40000" {
                empty
            } else {
                blob(format, b"unauthorized")
            };
            let new = objects.tree(
                format,
                &[
                    (b"40000", b"component", component),
                    (mode, b"outside", outside),
                ],
            );
            let src = objects.tree(format, &[(b"40000", b"new", new)]);
            let mixed = objects.tree(format, &[(b"40000", b"src", src)]);
            for (before, after) in [(empty, mixed), (mixed, empty)] {
                let merge = objects.merge(before, after);
                let changed = source_paths(&objects, &merge);
                assert_eq!(
                    changed,
                    [
                        b"src/new/component/lib.rs".to_vec(),
                        b"src/new/outside".to_vec(),
                    ]
                );
                assert!(!changed.iter().all(|path| scope.permits_path(path)));
            }
        }
    }
}
