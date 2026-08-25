#![forbid(unsafe_code)]
//! Conformance tests for Git notes object, tree, fanout, and merge operations.

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::notes::{
    NotesMergeConflict, NotesMergeStrategy, NotesTree, emit_notes_tree, merge_note_blob_bytes,
    parse_notes_tree,
};
use fgit_git_object::{AcceptanceProfile, ParseLimits};

fn sha1_limits() -> ParseLimits {
    ParseLimits {
        tree_reference_bytes: 20,
        ..ParseLimits::default()
    }
}

fn sha256_limits() -> ParseLimits {
    ParseLimits {
        tree_reference_bytes: 32,
        ..ParseLimits::default()
    }
}

fn create_blob_oid<A: GitHashAlgorithm>(content: &[u8]) -> GitOid<A> {
    <GitOid<A> as NativeObjectIdentity>::of_object(GitObjectKind::Blob, content)
}

fn create_commit_oid<A: GitHashAlgorithm>(label: &str) -> GitOid<A> {
    let body = format!("tree {}\n\n{}", "0".repeat(A::HEX_LEN), label);
    <GitOid<A> as NativeObjectIdentity>::of_object(GitObjectKind::Commit, body.as_bytes())
}

#[test]
fn flat_notes_tree_sha1_round_trip() {
    let limits = sha1_limits();
    let mut notes = NotesTree::<Sha1>::new();

    let commit1 = create_commit_oid::<Sha1>("commit 1");
    let commit2 = create_commit_oid::<Sha1>("commit 2");
    let commit3 = create_commit_oid::<Sha1>("commit 3");

    let note_blob1 = create_blob_oid::<Sha1>(b"Note for commit 1\n");
    let note_blob2 = create_blob_oid::<Sha1>(b"Note for commit 2\n");
    let note_blob3 = create_blob_oid::<Sha1>(b"Note for commit 3\n");

    notes
        .attach(commit1, note_blob1, false)
        .expect("attach note 1");
    notes
        .attach(commit2, note_blob2, false)
        .expect("attach note 2");
    notes
        .attach(commit3, note_blob3, false)
        .expect("attach note 3");

    assert_eq!(notes.len(), 3);
    assert_eq!(notes.get(&commit1), Some(&note_blob1));
    assert_eq!(notes.get(&commit2), Some(&note_blob2));
    assert_eq!(notes.get(&commit3), Some(&note_blob3));

    let emission = emit_notes_tree(&notes, &limits).expect("emission succeeds");
    assert_eq!(
        emission.all_trees.len(),
        1,
        "flat tree should produce exactly one tree object"
    );

    let parsed = parse_notes_tree::<Sha1, _>(
        &emission.root_tree_body,
        AcceptanceProfile::StrictCreate,
        &limits,
        |_| panic!("flat tree should not require fetching subtrees"),
    )
    .expect("parsing flat tree succeeds");

    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed.get(&commit1), Some(&note_blob1));
    assert_eq!(parsed.get(&commit2), Some(&note_blob2));
    assert_eq!(parsed.get(&commit3), Some(&note_blob3));
}

#[test]
fn flat_notes_tree_sha256_round_trip() {
    let limits = sha256_limits();
    let mut notes = NotesTree::<Sha256>::new();

    let commit1 = create_commit_oid::<Sha256>("commit 1 sha256");
    let commit2 = create_commit_oid::<Sha256>("commit 2 sha256");

    let note1 = create_blob_oid::<Sha256>(b"sha256 note 1\n");
    let note2 = create_blob_oid::<Sha256>(b"sha256 note 2\n");

    notes.attach(commit1, note1, false).expect("attach note 1");
    notes.attach(commit2, note2, false).expect("attach note 2");

    let emission = emit_notes_tree(&notes, &limits).expect("emission succeeds");
    assert_eq!(emission.all_trees.len(), 1);

    let parsed = parse_notes_tree::<Sha256, _>(
        &emission.root_tree_body,
        AcceptanceProfile::StrictCreate,
        &limits,
        |_| panic!("flat tree should not fetch subtrees"),
    )
    .expect("parsing sha256 flat notes tree succeeds");

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.get(&commit1), Some(&note1));
    assert_eq!(parsed.get(&commit2), Some(&note2));
}

#[test]
fn fanout_notes_tree_transition_and_round_trip() {
    let limits = sha1_limits();
    // Use threshold of 3 so adding 4 notes triggers 2-hex fanout subtrees
    let mut notes = NotesTree::<Sha1>::with_fanout_threshold(3);

    let mut map = std::collections::BTreeMap::new();
    for i in 0..10 {
        let commit = create_commit_oid::<Sha1>(&format!("commit {i}"));
        let blob = create_blob_oid::<Sha1>(&format!("note body {i}\n").into_bytes());
        notes.attach(commit, blob, false).expect("attach note");
        map.insert(commit, blob);
    }

    assert_eq!(notes.len(), 10);
    assert!(notes.len() > notes.fanout_threshold());

    let emission = emit_notes_tree(&notes, &limits).expect("fanout emission succeeds");
    assert!(
        emission.all_trees.len() > 1,
        "fanout tree must produce root tree plus subtrees"
    );

    // Build subtree lookup table
    let subtree_lookup: std::collections::BTreeMap<GitOid<Sha1>, Vec<u8>> =
        emission.all_trees.iter().cloned().collect();

    let parsed = parse_notes_tree::<Sha1, _>(
        &emission.root_tree_body,
        AcceptanceProfile::StrictCreate,
        &limits,
        |oid| {
            subtree_lookup.get(oid).cloned().ok_or_else(|| {
                fgit_git_object::notes::NotesError::InvalidOid {
                    details: format!("missing subtree {oid:?}"),
                }
            })
        },
    )
    .expect("parsing fanout notes tree succeeds");

    assert_eq!(parsed.len(), 10);
    for (commit, blob) in &map {
        assert_eq!(parsed.get(commit), Some(blob));
    }
}

#[test]
fn notes_crud_operations_and_pruning() {
    let mut notes = NotesTree::<Sha1>::new();
    let commit1 = create_commit_oid::<Sha1>("commit 1");
    let commit2 = create_commit_oid::<Sha1>("commit 2");
    let commit3 = create_commit_oid::<Sha1>("commit 3");

    let note1 = create_blob_oid::<Sha1>(b"initial note 1\n");
    let note2 = create_blob_oid::<Sha1>(b"initial note 2\n");
    let note1_v2 = create_blob_oid::<Sha1>(b"edited note 1\n");

    // Attach
    notes.attach(commit1, note1, false).expect("attach 1");
    notes.attach(commit2, note2, false).expect("attach 2");

    // Re-attach without force should fail
    assert!(notes.attach(commit1, note1_v2, false).is_err());

    // Attach with force should overwrite
    notes
        .attach(commit1, note1_v2, true)
        .expect("force attach 1");
    assert_eq!(notes.get(&commit1), Some(&note1_v2));

    // Edit
    notes.edit(commit2, note1).expect("edit 2");
    assert_eq!(notes.get(&commit2), Some(&note1));

    // Copy
    notes.copy(&commit1, commit3, false).expect("copy 1 to 3");
    assert_eq!(notes.get(&commit3), Some(&note1_v2));

    // Remove
    let removed = notes.remove(&commit2).expect("remove 2");
    assert_eq!(removed, note1);
    assert!(!notes.contains(&commit2));

    // Prune: keep only commit1, commit3 is pruned
    let live_objects = vec![commit1];
    let pruned = notes.prune(|oid| live_objects.contains(oid));
    assert_eq!(pruned, vec![commit3]);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes.get(&commit1), Some(&note1_v2));
}

#[test]
fn notes_merge_3way_manual_conflict_detection() {
    let commit_common = create_commit_oid::<Sha1>("common commit");
    let commit_ours = create_commit_oid::<Sha1>("ours commit");
    let commit_theirs = create_commit_oid::<Sha1>("theirs commit");
    let commit_conflicted = create_commit_oid::<Sha1>("conflicted commit");

    let base_blob = create_blob_oid::<Sha1>(b"base note\n");
    let ours_blob = create_blob_oid::<Sha1>(b"ours note modification\n");
    let theirs_blob = create_blob_oid::<Sha1>(b"theirs note modification\n");

    let mut base = NotesTree::<Sha1>::new();
    base.attach(commit_common, base_blob, false).unwrap();
    base.attach(commit_conflicted, base_blob, false).unwrap();

    let mut ours = NotesTree::<Sha1>::new();
    ours.attach(commit_common, base_blob, false).unwrap(); // unchanged
    ours.attach(commit_ours, ours_blob, false).unwrap(); // added in ours
    ours.attach(commit_conflicted, ours_blob, false).unwrap(); // modified in ours

    let mut theirs = NotesTree::<Sha1>::new();
    theirs.attach(commit_common, base_blob, false).unwrap(); // unchanged
    theirs.attach(commit_theirs, theirs_blob, false).unwrap(); // added in theirs
    theirs
        .attach(commit_conflicted, theirs_blob, false)
        .unwrap(); // modified in theirs

    // Manual strategy -> conflict on commit_conflicted
    let (merged, conflicts) = ours
        .merge(
            &theirs,
            Some(&base),
            NotesMergeStrategy::Manual,
            |_, _, _| unreachable!(),
        )
        .expect("merge execution");

    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0],
        NotesMergeConflict {
            target: commit_conflicted,
            ours: Some(ours_blob),
            theirs: Some(theirs_blob),
            base: Some(base_blob),
        }
    );

    // Non-conflicting items merged cleanly
    assert_eq!(merged.get(&commit_common), Some(&base_blob));
    assert_eq!(merged.get(&commit_ours), Some(&ours_blob));
    assert_eq!(merged.get(&commit_theirs), Some(&theirs_blob));
}

#[test]
fn notes_merge_strategies_ours_theirs_union_catsortuniq() {
    let commit = create_commit_oid::<Sha1>("target commit");
    let base_blob = create_blob_oid::<Sha1>(b"base\n");
    let ours_blob = create_blob_oid::<Sha1>(b"line B\nline A\n");
    let theirs_blob = create_blob_oid::<Sha1>(b"line C\nline A\n");

    let mut base = NotesTree::<Sha1>::new();
    base.attach(commit, base_blob, false).unwrap();

    let mut ours = NotesTree::<Sha1>::new();
    ours.attach(commit, ours_blob, false).unwrap();

    let mut theirs = NotesTree::<Sha1>::new();
    theirs.attach(commit, theirs_blob, false).unwrap();

    // 1. Ours strategy
    let (merged_ours, conflicts) = ours
        .merge(
            &theirs,
            Some(&base),
            NotesMergeStrategy::Ours,
            |_, _, _| unreachable!(),
        )
        .unwrap();
    assert!(conflicts.is_empty());
    assert_eq!(merged_ours.get(&commit), Some(&ours_blob));

    // 2. Theirs strategy
    let (merged_theirs, conflicts) = ours
        .merge(
            &theirs,
            Some(&base),
            NotesMergeStrategy::Theirs,
            |_, _, _| unreachable!(),
        )
        .unwrap();
    assert!(conflicts.is_empty());
    assert_eq!(merged_theirs.get(&commit), Some(&theirs_blob));

    // 3. Union helper
    let union_bytes = merge_note_blob_bytes(
        b"line B\nline A\n",
        b"line C\nline A\n",
        NotesMergeStrategy::Union,
    );
    assert_eq!(union_bytes, b"line B\nline A\nline C\nline A\n");

    // 4. CatSortUniq helper
    let csu_bytes = merge_note_blob_bytes(
        b"line B\nline A\n",
        b"line C\nline A\n",
        NotesMergeStrategy::CatSortUniq,
    );
    assert_eq!(csu_bytes, b"line A\nline B\nline C\n");
}
