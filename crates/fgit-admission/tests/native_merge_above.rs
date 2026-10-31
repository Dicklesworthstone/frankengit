#![forbid(unsafe_code)]
//! frankengit-lh8z: merge, squash and fast-forward validation above the
//! authority-selected closure. Native object fixtures, not an authority
//! substitute; the full-closure validators are the comparison oracle.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, validate_fast_forward_objects, validate_fast_forward_objects_above,
    validate_merge_objects, validate_merge_objects_above, validate_squash_objects,
    validate_squash_objects_above,
};
use fgit_admission::{PermittedObjectClosure, ProjectionFailure, permitted_object_closure_root};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_git_object::ObjectType;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RefusalCode};

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: Cell<usize>,
}
impl Objects {
    fn add(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        let kind = match kind {
            GitObjectKind::Commit => ObjectType::Commit,
            GitObjectKind::Tree => ObjectType::Tree,
            GitObjectKind::Blob => ObjectType::Blob,
            GitObjectKind::Tag => ObjectType::Tag,
        };
        self.bodies.insert(id, (kind, body));
        id
    }
    fn blob(&mut self, format: GitHashAlgorithm, text: &str) -> GitOid {
        self.add(format, GitObjectKind::Blob, text.as_bytes().to_vec())
    }
    /// Entries must be given in Git tree order.
    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&str, &str, GitOid)]) -> GitOid {
        let body = entries
            .iter()
            .flat_map(|(mode, name, id)| {
                [
                    format!("{mode} {name}\0").into_bytes(),
                    id.as_bytes().to_vec(),
                ]
                .concat()
            })
            .collect();
        self.add(format, GitObjectKind::Tree, body)
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid], seconds: u64, message: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        writeln!(
            body,
            "author Fixture <test@example.invalid> {seconds} +0000"
        )
        .unwrap();
        writeln!(
            body,
            "committer Fixture <test@example.invalid> {seconds} +0000\n"
        )
        .unwrap();
        body.push_str(message);
        self.add(tree.algorithm(), GitObjectKind::Commit, body.into_bytes())
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.set(self.reads.get() + 1);
        let (kind, body) = self
            .bodies
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

struct History {
    objects: Objects,
    /// Every object before the merge: what the authority has already selected.
    selected: BTreeSet<GitOid>,
    merge: NativeMerge,
    /// main's tip tree: f.txt only.
    target_tree: GitOid,
    /// topic's blob, g.txt.
    topic_blob: GitOid,
    main: Vec<GitOid>,
    topic: GitOid,
}

/// main is `count` dated commits rewriting f.txt; topic adds g.txt on
/// main~`back`. The candidate merges topic into main: f.txt from main, g.txt
/// from topic.
fn history(format: GitHashAlgorithm, count: usize, back: usize) -> History {
    let mut objects = Objects::default();
    let mut main = Vec::new();
    let mut tree = None;
    for step in 0..count {
        let blob = objects.blob(format, &format!("v{step}\n"));
        let next = objects.tree(format, &[("100644", "f.txt", blob)]);
        let parents = main.last().map(|tip| vec![*tip]).unwrap_or_default();
        main.push(objects.commit(next, &parents, 1_700_000_000 + step as u64, "main\n"));
        tree = Some((next, blob));
    }
    let (target_tree, target_blob) = tree.unwrap();
    let base = main[count - 1 - back];
    // The base rewrote f.txt to its own step's content.
    let base_blob = git_object_id(
        format,
        GitObjectKind::Blob,
        format!("v{}\n", count - 1 - back).as_bytes(),
    );
    let topic_blob = objects.blob(format, "topic\n");
    let topic_tree = objects.tree(
        format,
        &[
            ("100644", "f.txt", base_blob),
            ("100644", "g.txt", topic_blob),
        ],
    );
    let topic = objects.commit(topic_tree, &[base], 1_800_000_000, "topic\n");
    let selected = objects.bodies.keys().copied().collect();
    let merged_tree = objects.tree(
        format,
        &[
            ("100644", "f.txt", target_blob),
            ("100644", "g.txt", topic_blob),
        ],
    );
    let target = *main.last().unwrap();
    let candidate = objects.commit(merged_tree, &[target, topic], 1_800_000_001, "merge\n");
    History {
        objects,
        selected,
        merge: NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_tip: topic,
            base_tip: base,
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            target_tip_before: target,
            merge_commit: candidate,
        },
        target_tree,
        topic_blob,
        main,
        topic,
    }
}

fn root(objects: &BTreeSet<GitOid>) -> fgit_types::Digest {
    permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone())).unwrap()
}

fn merged_tree_of(history: &History) -> GitOid {
    let (_, body) = &history.objects.bodies[&history.merge.merge_commit];
    let hex =
        std::str::from_utf8(&body[5..5 + history.merge.merge_commit.algorithm().digest_len() * 2])
            .unwrap();
    GitOid::from_hex(history.merge.merge_commit.algorithm(), hex).unwrap()
}

#[test]
fn merge_above_names_its_new_objects_and_the_four_commits_only() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let h = history(format, 30, 5);
        let limits = MergeObjectLimits::default();
        let above =
            validate_merge_objects_above(&h.objects, &h.merge, &h.selected, limits, &mut || true)
                .unwrap();
        // New: the merge commit and its tree. Both blobs were already selected.
        let expected: BTreeSet<_> = [
            h.merge.merge_commit,
            merged_tree_of(&h),
            h.merge.base_tip,
            h.merge.target_tip_before,
            h.merge.source_tip,
        ]
        .into();
        assert_eq!(above.objects, expected);
        assert_eq!(above.object_closure_root, root(&expected));
        // The full-closure oracle accepts the same candidate; it names the
        // whole reachable history, a superset.
        let full = validate_merge_objects(&h.objects, &h.merge, limits, &mut || true).unwrap();
        assert!(full.objects.is_superset(&above.objects));
        assert!(full.objects.len() > 3 * 30);
        // Selected plus what this merge names covers everything reachable.
        let union: BTreeSet<_> = h.selected.union(&above.objects).copied().collect();
        assert!(union.is_superset(&full.objects));
    }
}

#[test]
fn a_long_history_is_read_only_at_the_frontier() {
    let format = GitHashAlgorithm::Sha256;
    let h = history(format, 5_000, 10);
    // The full walk needs every object (15,000+); a 1,000-object profile
    // refuses it. The frontier needs a handful.
    let narrow = MergeObjectLimits {
        max_objects: 1_000,
        ..MergeObjectLimits::default()
    };
    assert!(matches!(
        validate_merge_objects(&h.objects, &h.merge, narrow, &mut || true),
        Err(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded
        ))
    ));
    h.objects.reads.set(0);
    let above =
        validate_merge_objects_above(&h.objects, &h.merge, &h.selected, narrow, &mut || true)
            .unwrap();
    assert_eq!(above.objects.len(), 5);
    // Candidate, its tree, two blobs and two parents for kinds; then main~0..10,
    // topic and the base's parent for ancestry, twice (source and target).
    assert!(
        h.objects.reads.get() < 60,
        "{} reads",
        h.objects.reads.get()
    );
}

#[test]
fn a_frontier_object_of_the_wrong_kind_refuses_beside_its_twin() {
    let format = GitHashAlgorithm::Sha1;
    let mut h = history(format, 8, 2);
    // g.txt named with blob mode but pointing at a selected TREE.
    let wrong = h.objects.tree(
        format,
        &[
            ("100644", "f.txt", h.topic_blob),
            ("100644", "g.txt", h.target_tree),
        ],
    );
    let right = h.objects.tree(
        format,
        &[
            ("100644", "f.txt", h.topic_blob),
            ("40000", "g.txt", h.target_tree),
        ],
    );
    for (tree, accepted) in [(wrong, false), (right, true)] {
        let candidate = h.objects.commit(
            tree,
            &[h.merge.target_tip_before, h.merge.source_tip],
            1_800_000_002,
            "kind\n",
        );
        let merge = NativeMerge {
            merge_commit: candidate,
            ..h.merge.clone()
        };
        let result = validate_merge_objects_above(
            &h.objects,
            &merge,
            &h.selected,
            MergeObjectLimits::default(),
            &mut || true,
        );
        if accepted {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(
                matches!(
                    result,
                    Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
                ),
                "{result:?}"
            );
        }
    }
}

#[test]
fn a_false_base_and_a_rewound_fast_forward_refuse_beside_their_twins() {
    let format = GitHashAlgorithm::Sha256;
    let h = history(format, 20, 6);
    let limits = MergeObjectLimits::default();
    // main~1 is an ancestor of the target but not of topic (which branched at
    // main~6): not a common base.
    let false_base = NativeMerge {
        base_tip: h.main[h.main.len() - 2],
        ..h.merge.clone()
    };
    assert!(matches!(
        validate_merge_objects_above(&h.objects, &false_base, &h.selected, limits, &mut || true),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
    ));
    assert!(validate_merge_objects(&h.objects, &false_base, limits, &mut || true).is_err());
    // A fast-forward of main from main~3 to its tip is permitted and adds
    // nothing; rewinding it is refused.
    let forward = NativeMerge {
        source_tip: *h.main.last().unwrap(),
        merge_commit: *h.main.last().unwrap(),
        base_tip: h.main[h.main.len() - 4],
        target_tip_before: h.main[h.main.len() - 4],
        ..h.merge.clone()
    };
    let ok =
        validate_fast_forward_objects_above(&h.objects, &forward, &h.selected, limits, &mut || {
            true
        })
        .unwrap();
    assert_eq!(
        ok.objects,
        [forward.source_tip, forward.target_tip_before].into()
    );
    assert!(ok.objects.is_subset(&h.selected));
    assert!(validate_fast_forward_objects(&h.objects, &forward, limits, &mut || true).is_ok());
    let rewind = NativeMerge {
        source_tip: h.main[h.main.len() - 4],
        merge_commit: h.main[h.main.len() - 4],
        base_tip: *h.main.last().unwrap(),
        target_tip_before: *h.main.last().unwrap(),
        ..h.merge.clone()
    };
    assert!(matches!(
        validate_fast_forward_objects_above(&h.objects, &rewind, &h.selected, limits, &mut || true),
        Err(ProjectionFailure::Refuse(
            RefusalCode::NonFastForwardRefused
        ))
    ));
}

#[test]
fn squash_above_names_its_new_objects_and_matches_the_full_oracle() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut h = history(format, 12, 3);
        let tree = merged_tree_of(&h);
        let squash = h.objects.commit(
            tree,
            &[h.merge.target_tip_before],
            1_800_000_003,
            "squash\n",
        );
        let merge = NativeMerge {
            merge_commit: squash,
            ..h.merge.clone()
        };
        let limits = MergeObjectLimits::default();
        let above =
            validate_squash_objects_above(&h.objects, &merge, &h.selected, limits, &mut || true)
                .unwrap();
        assert_eq!(
            above.objects,
            [
                squash,
                tree,
                merge.base_tip,
                merge.target_tip_before,
                merge.source_tip
            ]
            .into()
        );
        let full = validate_squash_objects(&h.objects, &merge, limits, &mut || true).unwrap();
        assert!(full.objects.is_superset(&above.objects));
        // A squash naming a base that is not an ancestor of the source refuses.
        let false_base = NativeMerge {
            base_tip: h.topic,
            ..merge.clone()
        };
        assert!(
            validate_squash_objects_above(
                &h.objects,
                &false_base,
                &h.selected,
                limits,
                &mut || true
            )
            .is_err()
        );
    }
}

#[test]
fn a_parent_outside_the_selected_closure_and_the_store_is_unavailable() {
    let format = GitHashAlgorithm::Sha1;
    let mut h = history(format, 6, 2);
    let tree = merged_tree_of(&h);
    let absent = git_object_id(format, GitObjectKind::Commit, b"never stored");
    let candidate = h.objects.commit(
        tree,
        &[h.merge.target_tip_before, absent],
        1_800_000_004,
        "x\n",
    );
    let merge = NativeMerge {
        source_tip: absent,
        merge_commit: candidate,
        ..h.merge.clone()
    };
    let result = validate_merge_objects_above(
        &h.objects,
        &merge,
        &h.selected,
        MergeObjectLimits::default(),
        &mut || true,
    );
    assert!(
        matches!(
            result,
            Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
        ),
        "{result:?}"
    );
}
