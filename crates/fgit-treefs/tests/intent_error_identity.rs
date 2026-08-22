//! Which `IntentError` an evaluation raises, not merely that it raises one.
//!
//! WHY THIS FILE EXISTS. A sweep for typed variants named by no test flagged
//! four `IntentError` variants in this crate. Unlike the two host-profile path
//! refusals — which turned out to be exercised, just asserted through
//! `is_err()` — these four were genuinely unexercised: `RenameSourceMissing`,
//! `NotAFile` and `UnderDeletedAncestor` each have a real producer in
//! `intent.rs` that no test reached, and nothing pinned the DISCRIMINATION
//! between them.
//!
//! That distinction is the point. `IntentError` is a typed refusal a caller
//! branches on: "your rename source is gone" and "that path is not a file" call
//! for different responses from an agent replaying a log. An evaluation that
//! collapsed the three into whichever variant it reached first would still
//! refuse every forbidden case and still accept every permitted one, so a test
//! asserting only "this errors" would stay green while the refusal stopped
//! carrying information.
//!
//! Every forbidden case below is paired with a near-identical permitted one, so
//! a mapping that simply refused everything fails here rather than passing
//! (AGENTS.md §16.3).

use fgit_treefs::intent::{BasisEntry, IntentError, IntentLog, NetEffect, TreeEditIntent};
use fgit_treefs::overlay::{EntryClass, FileMode, Overlay};
use fgit_treefs::path::TreePath;

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("test path parses")
}

fn write(target: &[u8], body: &[u8]) -> TreeEditIntent {
    TreeEditIntent::Write {
        path: path(target),
        content: body.to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    }
}

/// Nothing is base-resident, so every effect comes from the log itself.
const fn empty_base(_path: &TreePath) -> bool {
    false
}

fn evaluate(intents: Vec<TreeEditIntent>) -> (Overlay, Vec<NetEffect>) {
    evaluate_against(intents, &empty_base)
}

/// Evaluate against a caller-supplied base predicate.
///
/// Needed because a `basis_entry` on the intent is NOT by itself enough to make
/// a path basis-resident: `intent.rs` gates the basis arm on `base_exists(path)`
/// as well. A test that supplied only the basis entry, against a base that
/// answers false for everything, is asking about a path that exists nowhere --
/// which is a different question and gets a different answer.
fn evaluate_against(
    intents: Vec<TreeEditIntent>,
    base_exists: &dyn Fn(&TreePath) -> bool,
) -> (Overlay, Vec<NetEffect>) {
    let mut log = IntentLog::new();
    for intent in intents {
        log.push(intent);
    }
    let (overlay, evaluation) = log.evaluate(base_exists);
    (overlay, evaluation.outcomes().to_vec())
}

/// The error raised by the intent at `index`, or a panic naming what came out.
fn error_at(outcomes: &[NetEffect], index: usize) -> IntentError {
    match &outcomes[index] {
        NetEffect::Error(error) => error.clone(),
        other => panic!("intent {index} was expected to fail; it produced {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// UnderDeletedAncestor
// ---------------------------------------------------------------------------

/// Writing beneath a directory this log deleted names the ancestor.
///
/// Carrying the ancestor matters: the caller needs to know WHICH deletion
/// shadowed the write, because the offending directory is usually not the
/// parent of the path they asked for.
#[test]
fn a_write_under_a_deleted_ancestor_names_the_ancestor() {
    let (_overlay, outcomes) = evaluate(vec![
        write(b"a/keep.txt", b"first\n"),
        TreeEditIntent::Delete { path: path(b"a") },
        write(b"a/nested/deep.txt", b"shadowed\n"),
    ]);

    let error = error_at(&outcomes, 2);
    match error {
        IntentError::UnderDeletedAncestor {
            path: target,
            ancestor,
        } => {
            assert_eq!(target.as_bytes(), b"a/nested/deep.txt");
            assert_eq!(
                ancestor.as_bytes(),
                b"a",
                "the ancestor reported must be the deleted directory, not the immediate parent"
            );
        }
        other => panic!("expected UnderDeletedAncestor, got {other:?}"),
    }
}

/// The permitted twin: a sibling subtree the deletion never covered.
///
/// Without this, the test above is satisfied by an evaluation that refuses
/// every write following any delete.
#[test]
fn a_write_beside_a_deleted_subtree_is_permitted() {
    let (overlay, outcomes) = evaluate(vec![
        TreeEditIntent::Delete { path: path(b"a") },
        write(b"b/nested/deep.txt", b"unaffected\n"),
    ]);

    assert!(
        !matches!(outcomes[1], NetEffect::Error(_)),
        "a write outside the deleted subtree must proceed; got {:?}",
        outcomes[1]
    );
    assert!(
        overlay.entries().contains_key(&path(b"b/nested/deep.txt")),
        "the permitted write must actually land in the overlay"
    );
}

// ---------------------------------------------------------------------------
// RenameSourceMissing
// ---------------------------------------------------------------------------

/// Renaming from a path this log already deleted is refused by source, not by
/// destination.
#[test]
fn a_rename_from_a_deleted_source_names_the_source() {
    let (_overlay, outcomes) = evaluate(vec![
        write(b"src/old.rs", b"body\n"),
        TreeEditIntent::Delete {
            path: path(b"src/old.rs"),
        },
        TreeEditIntent::Rename {
            from: path(b"src/old.rs"),
            to: path(b"src/new.rs"),
            basis_entry: None,
        },
    ]);

    match error_at(&outcomes, 2) {
        IntentError::RenameSourceMissing { from } => {
            assert_eq!(
                from.as_bytes(),
                b"src/old.rs",
                "the refusal must name the SOURCE; naming the destination would send a caller \
                 looking in the wrong place"
            );
        }
        other => panic!("expected RenameSourceMissing, got {other:?}"),
    }
}

/// The permitted twin: renaming a source this log actually staged.
#[test]
fn a_rename_from_a_staged_source_is_permitted() {
    let (overlay, outcomes) = evaluate(vec![
        write(b"src/old.rs", b"body\n"),
        TreeEditIntent::Rename {
            from: path(b"src/old.rs"),
            to: path(b"src/new.rs"),
            basis_entry: None,
        },
    ]);

    assert!(
        !matches!(outcomes[1], NetEffect::Error(_)),
        "renaming a staged file must proceed; got {:?}",
        outcomes[1]
    );
    assert!(
        overlay.entries().contains_key(&path(b"src/new.rs")),
        "the destination must exist after a permitted rename"
    );
}

// ---------------------------------------------------------------------------
// NotAFile
// ---------------------------------------------------------------------------

/// Changing the mode of something that is not a file names the path.
///
/// A directory created earlier in the same log occupies the path, so the chmod
/// has a target but not a file one.
#[test]
fn a_chmod_of_a_non_file_names_the_path() {
    let (_overlay, outcomes) = evaluate(vec![
        TreeEditIntent::CreateDirectory {
            path: path(b"assets"),
        },
        TreeEditIntent::Chmod {
            path: path(b"assets"),
            basis_entry: None,
            after: FileMode::Executable,
        },
    ]);

    match error_at(&outcomes, 1) {
        IntentError::NotAFile { path: target } => {
            assert_eq!(target.as_bytes(), b"assets");
        }
        other => panic!("expected NotAFile, got {other:?}"),
    }
}

/// The permitted twin: the same chmod against an actual staged file.
#[test]
fn a_chmod_of_a_staged_file_is_permitted() {
    let (_overlay, outcomes) = evaluate(vec![
        write(b"script.sh", b"#!/bin/sh\n"),
        TreeEditIntent::Chmod {
            path: path(b"script.sh"),
            basis_entry: None,
            after: FileMode::Executable,
        },
    ]);

    assert!(
        !matches!(outcomes[1], NetEffect::Error(_)),
        "chmod of a staged regular file must proceed; got {:?}",
        outcomes[1]
    );
}

// ---------------------------------------------------------------------------
// the three are distinguished from one another
// ---------------------------------------------------------------------------

/// The three refusals are distinct, which is what makes each test above mean
/// something.
///
/// An evaluation that returned a single catch-all error would satisfy every
/// "this is refused" assertion in this file. Requiring three different variants
/// out of three different situations is the check that cannot be passed that
/// way. This is the presence case for the whole module.
#[test]
fn the_three_refusals_are_not_collapsed_into_one() {
    let (_o1, deleted_ancestor) = evaluate(vec![
        TreeEditIntent::Delete { path: path(b"a") },
        write(b"a/x.txt", b"body\n"),
    ]);
    let (_o2, rename_missing) = evaluate(vec![TreeEditIntent::Rename {
        from: path(b"gone.txt"),
        to: path(b"there.txt"),
        basis_entry: None,
    }]);
    let (_o3, not_a_file) = evaluate(vec![
        TreeEditIntent::CreateDirectory { path: path(b"dir") },
        TreeEditIntent::Chmod {
            path: path(b"dir"),
            basis_entry: None,
            after: FileMode::Executable,
        },
    ]);

    let a = error_at(&deleted_ancestor, 1);
    let b = error_at(&rename_missing, 0);
    let c = error_at(&not_a_file, 1);

    assert!(
        matches!(a, IntentError::UnderDeletedAncestor { .. }),
        "got {a:?}"
    );
    assert!(
        matches!(
            b,
            IntentError::RenameSourceMissing { .. } | IntentError::MissingBasisEntry { .. }
        ),
        "a rename with no source at all is refused by source, got {b:?}"
    );
    assert!(matches!(c, IntentError::NotAFile { .. }), "got {c:?}");

    // Discriminants differ pairwise: three situations, three answers.
    assert_ne!(
        core::mem::discriminant(&a),
        core::mem::discriminant(&c),
        "a shadowed write and a non-file chmod must not report the same refusal"
    );
    assert_ne!(
        core::mem::discriminant(&b),
        core::mem::discriminant(&c),
        "a missing rename source and a non-file chmod must not report the same refusal"
    );
}

/// A `BasisEntry` is accepted where the intent declares one.
///
/// Kept deliberately: it is the one path above that exercises the
/// `basis_entry: Some(..)` arm, so the `None` cases elsewhere are not silently
/// the only shape ever evaluated.
#[test]
fn a_basis_resident_chmod_is_evaluated_rather_than_refused() {
    let basis = BasisEntry {
        oid: vec![0x11; 20],
        mode: FileMode::Regular,
    };
    let tracked = |candidate: &TreePath| candidate.as_bytes() == b"tracked.sh";
    let (_overlay, outcomes) = evaluate_against(
        vec![TreeEditIntent::Chmod {
            path: path(b"tracked.sh"),
            basis_entry: Some(basis.clone()),
            after: FileMode::Executable,
        }],
        &tracked,
    );

    assert!(
        !matches!(outcomes[0], NetEffect::Error(IntentError::NotAFile { .. })),
        "a chmod of a base-resident file must not be refused as a non-file; got {:?}",
        outcomes[0]
    );

    // The contrast that makes the line above informative: the SAME intent, with
    // the same basis entry, against a base that does not hold the path. This is
    // what my first draft accidentally tested, and it is a genuinely different
    // question -- "change the mode of a file that exists nowhere" -- so a
    // different answer is correct rather than a defect. Pinned so the
    // distinction cannot quietly collapse.
    let (_overlay, absent) = evaluate_against(
        vec![TreeEditIntent::Chmod {
            path: path(b"tracked.sh"),
            basis_entry: Some(basis),
            after: FileMode::Executable,
        }],
        &empty_base,
    );
    assert!(
        matches!(absent[0], NetEffect::Error(IntentError::NotAFile { .. })),
        "a chmod of a path the base does not hold is refused; a basis_entry on the intent is not \
         itself evidence the file exists. got {:?}",
        absent[0]
    );
}
