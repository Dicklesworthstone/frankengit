//! Native-ID fixtures, independently serialized expected trees and refusal twins.
use super::super::{
    CommitInput, GitHashAlgorithm, MergeMetadata, MergePreparation, MergeProfile, MergeSourceError,
    PreparationLimits, PreparedMerge, prepare_merge, prepare_merge_with_profile,
};
use super::*;
use std::cell::Cell;
use std::fmt::Write as _;

type File<'a> = (&'a [u8], &'a [u8], u32);
struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    calls: Cell<usize>,
    stop: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            commits: BTreeMap::new(),
            trees: BTreeMap::new(),
            blobs: BTreeMap::new(),
            calls: Cell::new(0),
            stop: Cell::new(usize::MAX),
        }
    }
    fn write_tree(&mut self, files: &[File<'_>]) -> GitOid {
        let mut leaves = Vec::new();
        let mut directories: BTreeMap<Vec<u8>, Vec<File<'_>>> = BTreeMap::new();
        for &(path, body, mode) in files {
            if let Some(slash) = path.iter().position(|b| *b == b'/') {
                directories
                    .entry(path[..slash].to_vec())
                    .or_default()
                    .push((&path[slash + 1..], body, mode));
            } else {
                let oid = git_object_id(self.format, GitObjectKind::Blob, body);
                self.blobs.insert(oid, body.to_vec());
                leaves.push(MergeEntry {
                    name: path.to_vec(),
                    mode,
                    oid,
                });
            }
        }
        for (name, files) in directories {
            let oid = self.write_tree(&files);
            leaves.push(MergeEntry {
                name,
                mode: 0o040000,
                oid,
            });
        }
        self.directory(leaves)
    }
    fn directory(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
        entries.sort_by_key(|entry| {
            let mut name = entry.name.clone();
            if entry.mode == 0o040000 {
                name.push(b'/');
            }
            name
        });
        let mut body = Vec::new();
        for e in &entries {
            body.extend_from_slice(format!("{:o} ", e.mode).as_bytes());
            body.extend_from_slice(&e.name);
            body.push(0);
            body.extend_from_slice(e.oid.as_bytes());
        }
        let oid = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(oid, entries);
        oid
    }
    fn write_commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            let _ = write!(body, "parent {parent}\n");
        }
        let _ = write!(
            body,
            "author T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\n{label}"
        );
        let oid = git_object_id(self.format, GitObjectKind::Commit, body.as_bytes());
        self.commits.insert(
            oid,
            CommitInput {
                tree,
                parents: parents.to_vec(),
            },
        );
        oid
    }
    fn pair(&mut self, b: &[File<'_>], o: &[File<'_>], t: &[File<'_>]) -> (GitOid, GitOid) {
        let root = self.write_tree(b);
        let base = self.write_commit(root, &[], "base");
        let root = self.write_tree(o);
        let ours = self.write_commit(root, &[base], "ours");
        let root = self.write_tree(t);
        let theirs = self.write_commit(root, &[base], "theirs");
        (ours, theirs)
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let n = self.calls.get();
        self.calls.set(n + 1);
        if n >= self.stop.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blobs
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "T <t@x>".into(),
        committer: "T <t@x>".into(),
        timestamp: 2,
        message: b"merged\n".to_vec(),
    }
}
fn run(s: &Source, o: GitOid, t: GitOid) -> Result<MergePreparation, PreparationError> {
    prepare_merge_with_profile(
        s,
        s.format,
        o,
        t,
        &metadata(),
        PreparationLimits::default(),
        MergeProfile::ExactRenamesV1,
    )
}
fn clean(result: Result<MergePreparation, PreparationError>) -> PreparedMerge {
    let MergePreparation::Clean(plan) = result.unwrap() else {
        panic!("expected clean candidate");
    };
    plan
}

#[test]
fn cross_directory_rename_transports_edits_and_mode_without_rewriting_parents() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for swap in [false, true] {
            let mut s = Source::new(format);
            let (mut o, mut t) = s.pair(
                &[(b"old/file", b"base\n", 0o100644)],
                &[(b"new/nested/name", b"base\n", 0o100755)],
                &[(b"old/file", b"edited\n", 0o100644)],
            );
            if swap {
                std::mem::swap(&mut o, &mut t);
            }
            let expected = s.write_tree(&[(b"new/nested/name", b"edited\n", 0o100755)]);
            let plan = clean(run(&s, o, t));
            assert_eq!(plan.tree, expected);
            assert_eq!(plan.target, o);
            assert_eq!(plan.source, t);
            assert_eq!(plan.base, s.commits[&o].parents[0]);
            assert_eq!(
                run(&s, o, t).unwrap(),
                MergePreparation::Clean(plan.clone())
            );
            let commit = plan.objects.iter().find(|x| x.id == plan.commit).unwrap();
            assert!(
                commit
                    .body
                    .starts_with(format!("tree {expected}\nparent {o}\nparent {t}\n").as_bytes())
            );
            for object in &plan.objects {
                assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
                assert_ne!(
                    object.kind,
                    GitObjectKind::Blob,
                    "rename+edit borrows the original edited blob"
                );
            }
            // Independently serialized expected tree nodes are the entire new
            // reachable tree closure here. Virtual base-only nodes must vanish.
            let mut reachable = BTreeSet::new();
            let mut pending = vec![expected];
            while let Some(id) = pending.pop() {
                if !reachable.insert(id) {
                    continue;
                }
                for entry in &s.trees[&id] {
                    if entry.mode == 0o040000 {
                        pending.push(entry.oid);
                    }
                }
            }
            assert!(
                plan.objects
                    .iter()
                    .all(|x| x.kind == GitObjectKind::Commit || reachable.contains(&x.id))
            );
            assert!(matches!(
                prepare_merge(&s, format, o, t, &metadata(), PreparationLimits::default()).unwrap(),
                MergePreparation::Conflicted { .. }
            ));
        }
    }
}

#[test]
fn same_destination_on_both_sides_preserves_independent_mode_change() {
    let mut s = Source::new(GitHashAlgorithm::Sha256);
    let (o, t) = s.pair(
        &[(b"old", b"base", 0o100644)],
        &[(b"new", b"base", 0o100755)],
        &[(b"new", b"base", 0o100644)],
    );
    let expected = s.write_tree(&[(b"new", b"base", 0o100755)]);
    assert_eq!(clean(run(&s, o, t)).tree, expected);
}

#[test]
fn rename_delete_and_divergent_rename_never_choose_a_survivor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::new(format);
        let (o, t) = s.pair(
            &[(b"old", b"base", 0o100644)],
            &[(b"new", b"base", 0o100644)],
            &[],
        );
        assert!(
            matches!(run(&s, o, t), Err(PreparationError::Rename(RenameRefusal::RenameDelete { from, to })) if from == b"old" && to == b"new")
        );
        let (o, t) = s.pair(
            &[(b"old", b"base", 0o100644)],
            &[(b"new", b"base", 0o100644)],
            &[(b"different", b"base", 0o100644)],
        );
        assert!(
            matches!(run(&s, o, t), Err(PreparationError::Rename(RenameRefusal::Divergent { from, target, source })) if from == b"old" && target == b"new" && source == b"different")
        );
    }
}

#[test]
fn duplicate_deleted_or_added_identities_refuse_instead_of_using_path_order() {
    let cases: &[(&[File<'_>], &[File<'_>], &[File<'_>])] = &[
        (
            &[(b"a", b"same", 0o100644), (b"b", b"same", 0o100644)],
            &[(b"new", b"same", 0o100644)],
            &[(b"a", b"changed", 0o100644), (b"b", b"same", 0o100644)],
        ),
        (
            &[(b"old", b"same", 0o100644)],
            &[(b"a", b"same", 0o100644), (b"b", b"same", 0o100644)],
            &[(b"old", b"changed", 0o100644)],
        ),
    ];
    for (base, ours, theirs) in cases {
        let mut s = Source::new(GitHashAlgorithm::Sha1);
        let (o, t) = s.pair(base, ours, theirs);
        assert!(matches!(
            run(&s, o, t),
            Err(PreparationError::Rename(RenameRefusal::AmbiguousIdentity {
                side: RenameSide::Target,
                ..
            }))
        ));
    }
}

#[test]
fn copies_are_not_renames_and_unrelated_deletions_remain_deletions() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let (o, t) = s.pair(
        &[(b"old", b"base", 0o100644), (b"gone", b"delete", 0o100644)],
        &[(b"old", b"base", 0o100644), (b"copy", b"base", 0o100644)],
        &[
            (b"old", b"edited", 0o100644),
            (b"gone", b"delete", 0o100644),
        ],
    );
    let expected = s.write_tree(&[(b"old", b"edited", 0o100644), (b"copy", b"base", 0o100644)]);
    assert_eq!(clean(run(&s, o, t)).tree, expected);
}

#[test]
fn destinations_and_ancestor_file_collisions_do_not_overwrite_other_work() {
    for (destination, theirs) in [
        (
            b"new".as_slice(),
            vec![
                (b"old".as_slice(), b"edited".as_slice(), 0o100644),
                (b"new".as_slice(), b"other".as_slice(), 0o100644),
            ],
        ),
        (
            b"dir/file".as_slice(),
            vec![
                (b"old".as_slice(), b"edited".as_slice(), 0o100644),
                (b"dir".as_slice(), b"other".as_slice(), 0o100644),
            ],
        ),
    ] {
        let mut s = Source::new(GitHashAlgorithm::Sha1);
        let (o, t) = s.pair(
            &[(b"old", b"base", 0o100644)],
            &[(destination, b"base", 0o100644)],
            &theirs,
        );
        assert!(matches!(
            run(&s, o, t),
            Err(PreparationError::Rename(
                RenameRefusal::DestinationOccupied { .. }
            ))
        ));
    }
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let (o, t) = s.pair(
        &[(b"a", b"A", 0o100644), (b"b", b"B", 0o100644)],
        &[(b"dest", b"A", 0o100644), (b"b", b"B", 0o100644)],
        &[(b"a", b"A", 0o100644), (b"dest", b"B", 0o100644)],
    );
    assert!(matches!(
        run(&s, o, t),
        Err(PreparationError::Rename(
            RenameRefusal::DestinationOccupied { .. }
        ))
    ));
}

#[test]
fn type_changes_and_attribute_context_changes_are_explicit_refusals() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let (o, t) = s.pair(
        &[(b"old", b"base", 0o100644)],
        &[(b"new", b"base", 0o100644)],
        &[(b"old", b"link", 0o120000)],
    );
    assert!(
        matches!(run(&s, o, t), Err(PreparationError::Rename(RenameRefusal::UnsupportedEntry { path })) if path == b"old")
    );
    for attr in [
        b".gitattributes".as_slice(),
        b"dir/.gitattributes".as_slice(),
    ] {
        let (o, t) = s.pair(
            &[(b"old", b"base", 0o100644)],
            &[
                (b"dir/new", b"base", 0o100644),
                (attr, b"* merge=custom", 0o100644),
            ],
            &[(b"old", b"edited", 0o100644)],
        );
        assert!(matches!(
            run(&s, o, t),
            Err(PreparationError::Rename(
                RenameRefusal::AttributesRequireDriver { .. }
            ))
        ));
    }
}

#[test]
fn source_side_new_files_do_not_follow_a_directory_rename_inference() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let (o, t) = s.pair(
        &[(b"old/a", b"base", 0o100644)],
        &[(b"new/a", b"base", 0o100644)],
        &[
            (b"old/a", b"edited", 0o100644),
            (b"old/added", b"keep here", 0o100644),
        ],
    );
    let expected = s.write_tree(&[
        (b"new/a", b"edited", 0o100644),
        (b"old/added", b"keep here", 0o100644),
    ]);
    assert_eq!(clean(run(&s, o, t)).tree, expected);
}

#[test]
fn raw_non_utf8_paths_are_preserved_and_unrelated_text_uses_the_existing_merge() {
    let mut s = Source::new(GitHashAlgorithm::Sha256);
    let (o, t) = s.pair(
        &[
            (b"old\xff", b"base", 0o100644),
            (b"text", b"a\nb\nc\nd\ne\n", 0o100644),
        ],
        &[
            (b"dir/new\xfe", b"base", 0o100644),
            (b"text", b"A\nb\nc\nd\ne\n", 0o100644),
        ],
        &[
            (b"old\xff", b"edited", 0o100644),
            (b"text", b"a\nb\nc\nd\nE\n", 0o100644),
        ],
    );
    let expected = s.write_tree(&[
        (b"dir/new\xfe", b"edited", 0o100644),
        (b"text", b"A\nb\nc\nd\nE\n", 0o100644),
    ]);
    assert_eq!(clean(run(&s, o, t)).tree, expected);
}

#[test]
fn every_cancellation_checkpoint_and_each_narrowed_resource_ceiling_refuses() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let (o, t) = s.pair(
        &[(b"old/a", b"base", 0o100644)],
        &[(b"new/a", b"base", 0o100644)],
        &[(b"old/a", b"edited", 0o100644)],
    );
    clean(run(&s, o, t));
    let checkpoints = s.calls.get();
    for stop in 0..checkpoints {
        s.calls.set(0);
        s.stop.set(stop);
        assert!(run(&s, o, t).is_err(), "checkpoint {stop} of {checkpoints}");
    }
    s.stop.set(usize::MAX);
    for limits in [
        PreparationLimits {
            max_tree_entries: 1,
            ..PreparationLimits::default()
        },
        PreparationLimits {
            max_path_bytes: 3,
            ..PreparationLimits::default()
        },
        PreparationLimits {
            max_objects: 1,
            ..PreparationLimits::default()
        },
        PreparationLimits {
            max_output_bytes: 16,
            ..PreparationLimits::default()
        },
    ] {
        assert!(matches!(
            prepare_merge_with_profile(
                &s,
                s.format,
                o,
                t,
                &metadata(),
                limits,
                MergeProfile::ExactRenamesV1
            ),
            Err(PreparationError::Budget(_))
        ));
    }
}

#[test]
fn explicit_empty_directories_survive_beside_emptied_rename_parents() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let empty = s.directory(vec![]);
    let keep = MergeEntry {
        name: b"keep".to_vec(),
        mode: 0o040000,
        oid: empty,
    };
    let mut tips = Vec::new();
    for (files, label) in [
        (
            vec![(b"old/a".as_slice(), b"base".as_slice(), 0o100644)],
            "base",
        ),
        (
            vec![(b"new/a".as_slice(), b"base".as_slice(), 0o100644)],
            "ours",
        ),
        (
            vec![(b"old/a".as_slice(), b"edited".as_slice(), 0o100644)],
            "theirs",
        ),
    ] {
        let root = s.write_tree(&files);
        let mut entries = s.trees[&root].clone();
        entries.push(keep.clone());
        let root = s.directory(entries);
        let parents = if tips.is_empty() {
            vec![]
        } else {
            vec![tips[0]]
        };
        tips.push(s.write_commit(root, &parents, label));
    }
    let root = s.write_tree(&[(b"new/a", b"edited", 0o100644)]);
    let mut entries = s.trees[&root].clone();
    entries.push(keep);
    let expected = s.directory(entries);
    assert_eq!(clean(run(&s, tips[1], tips[2])).tree, expected);
}

#[test]
fn rename_count_is_a_hard_ceiling_even_for_tiny_files() {
    let s = Source::new(GitHashAlgorithm::Sha1);
    let planner = Planner::new(&s, s.format, PreparationLimits::default());
    let mut b = Flat::new();
    let mut o = Flat::new();
    let mut budget = PathBudget {
        used: 0,
        maximum: MAX_PATH_STORAGE_BYTES,
    };
    for index in 0..=MAX_RENAMES {
        let name = format!("old-{index}").into_bytes();
        let oid = git_object_id(s.format, GitObjectKind::Blob, &index.to_be_bytes());
        b.insert(
            name.clone(),
            MergeEntry {
                name,
                mode: 0o100644,
                oid,
            },
        );
        let name = format!("new-{index}").into_bytes();
        o.insert(
            name.clone(),
            MergeEntry {
                name,
                mode: 0o100644,
                oid,
            },
        );
        if index + 1 == MAX_RENAMES {
            assert_eq!(
                detect(&planner, &b, &o, RenameSide::Target, &mut budget)
                    .unwrap()
                    .len(),
                MAX_RENAMES
            );
        }
    }
    assert!(matches!(
        detect(&planner, &b, &o, RenameSide::Target, &mut budget),
        Err(PreparationError::Budget("renames"))
    ));
}
