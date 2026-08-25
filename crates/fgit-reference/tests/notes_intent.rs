#![forbid(unsafe_code)]
//! Tests for Git notes ref namespace validation, lifecycle intents, and lowering to RefIntent.

use fgit_reference::intent::{
    DEFAULT_NOTES_REF, NotesIntent, NotesIntentRefusal, NotesRefName, RefIntent,
};
use fgit_reference::refs::{ExpectedRefState, is_canonical, scope_of};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::refs::RefName;

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("valid ref name")
}

fn oid(val: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([val; GitOidSha1::LEN]))
}

#[test]
fn notes_ref_namespace_admission() {
    assert!(is_canonical(&name(DEFAULT_NOTES_REF)));
    assert_eq!(scope_of(&name(DEFAULT_NOTES_REF)), Some(&b"notes"[..]));

    for valid in [
        "refs/notes/commits",
        "refs/notes/custom",
        "refs/notes/review/team1",
    ] {
        let ref_n = name(valid);
        assert!(NotesRefName::try_new(ref_n).is_ok());
    }

    for invalid in ["refs/heads/main", "refs/tags/v1.0", "refs/pull/1/head"] {
        let ref_n = name(invalid);
        let err = NotesRefName::try_new(ref_n);
        assert!(matches!(
            err,
            Err(NotesIntentRefusal::OutsideNotesNamespace(_))
        ));
    }
}

#[test]
fn notes_ref_from_subpath_and_default() {
    let default_notes = NotesRefName::default_commits();
    assert_eq!(
        default_notes.as_ref_name().as_str().unwrap(),
        "refs/notes/commits"
    );

    let custom = NotesRefName::from_subpath("review").expect("valid subpath");
    assert_eq!(custom.as_ref_name().as_str().unwrap(), "refs/notes/review");
}

#[test]
fn notes_intent_update_and_delete_lowering() {
    let notes_ref = name("refs/notes/commits");
    let commit_oid = oid(42);
    let expected = ExpectedRefState::Absent;

    // 1. Update intent
    let update_intent = NotesIntent::update(notes_ref.clone(), expected, commit_oid, false)
        .expect("valid update intent");

    assert_eq!(update_intent.target().as_ref_name(), &notes_ref);
    assert_eq!(*update_intent.expected(), expected);

    let lowered = update_intent.into_ref_intent();
    assert_eq!(
        lowered,
        RefIntent::Update {
            name: notes_ref.clone(),
            expected,
            new: commit_oid,
            force: false,
        }
    );

    // 2. Delete intent
    let delete_intent = NotesIntent::delete(notes_ref.clone(), ExpectedRefState::Exact(commit_oid))
        .expect("valid delete intent");

    assert_eq!(delete_intent.target().as_ref_name(), &notes_ref);
    assert_eq!(
        *delete_intent.expected(),
        ExpectedRefState::Exact(commit_oid)
    );

    let lowered_del = delete_intent.into_ref_intent();
    assert_eq!(
        lowered_del,
        RefIntent::Delete {
            name: notes_ref,
            expected: ExpectedRefState::Exact(commit_oid),
        }
    );
}

#[test]
fn planted_negative_notes_intent_outside_namespace_refused() {
    let branch = name("refs/heads/main");
    let result = NotesIntent::update(branch.clone(), ExpectedRefState::Absent, oid(1), false);
    assert!(matches!(
        result,
        Err(NotesIntentRefusal::OutsideNotesNamespace(_))
    ));

    let result_del = NotesIntent::delete(branch, ExpectedRefState::Any);
    assert!(matches!(
        result_del,
        Err(NotesIntentRefusal::OutsideNotesNamespace(_))
    ));
}
