#![forbid(unsafe_code)]
//! Planted negative tests for Git notes object, tree, and fanout operations.

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::notes::{
    NotesError, NotesTree, oid_from_bytes, oid_from_hex, parse_notes_tree,
};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};

fn sha1_limits() -> ParseLimits {
    ParseLimits {
        tree_reference_bytes: 20,
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
fn planted_negative_attach_without_force_fails_on_existing_note() {
    let mut notes = NotesTree::<Sha1>::new();
    let commit = create_commit_oid::<Sha1>("commit 1");
    let blob1 = create_blob_oid::<Sha1>(b"note 1");
    let blob2 = create_blob_oid::<Sha1>(b"note 2");

    notes.attach(commit, blob1, false).expect("initial attach");
    let result = notes.attach(commit, blob2, false);

    assert!(matches!(
        result,
        Err(NotesError::TargetAlreadyHasNote { .. })
    ));
}

#[test]
fn planted_negative_edit_or_remove_on_missing_target_fails() {
    let mut notes = NotesTree::<Sha1>::new();
    let commit = create_commit_oid::<Sha1>("missing commit");
    let blob = create_blob_oid::<Sha1>(b"note");

    assert!(matches!(
        notes.edit(commit, blob),
        Err(NotesError::TargetNoteNotFound { .. })
    ));

    assert!(matches!(
        notes.remove(&commit),
        Err(NotesError::TargetNoteNotFound { .. })
    ));

    let commit2 = create_commit_oid::<Sha1>("dest commit");
    assert!(matches!(
        notes.copy(&commit, commit2, false),
        Err(NotesError::TargetNoteNotFound { .. })
    ));
}

#[test]
fn planted_negative_target_oid_confusion_across_sha1_and_sha256() {
    // A 40-hex SHA-1 string must fail when parsed as a SHA-256 OID
    let sha1_hex = "a".repeat(40);
    let result_sha256 = oid_from_hex::<Sha256>(&sha1_hex);
    assert!(
        result_sha256.is_err(),
        "SHA-1 hex length cannot parse as SHA-256 OID"
    );

    // A 64-hex SHA-256 string must fail when parsed as a SHA-1 OID
    let sha256_hex = "b".repeat(64);
    let result_sha1 = oid_from_hex::<Sha1>(&sha256_hex);
    assert!(
        result_sha1.is_err(),
        "SHA-256 hex length cannot parse as SHA-1 OID"
    );

    // Wrong digest byte lengths
    assert!(oid_from_bytes::<Sha1>(&[0u8; 32]).is_err());
    assert!(oid_from_bytes::<Sha256>(&[0u8; 20]).is_err());
}

#[test]
fn planted_negative_malformed_fanout_directory_name_refused() {
    let limits = sha1_limits();
    // Tree containing a directory named "abc" (3 chars instead of 2)
    let bad_tree = vec![TreeEntry {
        mode: b"40000".to_vec(),
        name: b"abc".to_vec(),
        object_id: vec![0u8; 20],
    }];
    let tree_body = emit_tree(&bad_tree, AcceptanceProfile::StrictCreate, &limits).unwrap();

    let result =
        parse_notes_tree::<Sha1, _>(&tree_body, AcceptanceProfile::StrictCreate, &limits, |_| {
            Ok(vec![])
        });

    assert!(matches!(
        result,
        Err(NotesError::InvalidNotesTreeEntry { .. })
    ));
}

#[test]
fn planted_negative_non_hexdigit_fanout_directory_name_refused() {
    let limits = sha1_limits();
    // Tree containing a directory named "zz" (non-hex chars)
    let bad_tree = vec![TreeEntry {
        mode: b"40000".to_vec(),
        name: b"zz".to_vec(),
        object_id: vec![0u8; 20],
    }];
    let tree_body = emit_tree(&bad_tree, AcceptanceProfile::StrictCreate, &limits).unwrap();

    let result =
        parse_notes_tree::<Sha1, _>(&tree_body, AcceptanceProfile::StrictCreate, &limits, |_| {
            Ok(vec![])
        });

    assert!(matches!(
        result,
        Err(NotesError::InvalidNotesTreeEntry { .. })
    ));
}

#[test]
fn planted_negative_leaf_target_hex_length_mismatch_refused() {
    let limits = sha1_limits();
    // Tree containing a leaf named 39 chars (instead of 40 for root leaf)
    let bad_tree = vec![TreeEntry {
        mode: b"100644".to_vec(),
        name: "c".repeat(39).into_bytes(),
        object_id: vec![0u8; 20],
    }];
    let tree_body = emit_tree(&bad_tree, AcceptanceProfile::StrictCreate, &limits).unwrap();

    let result =
        parse_notes_tree::<Sha1, _>(&tree_body, AcceptanceProfile::StrictCreate, &limits, |_| {
            Ok(vec![])
        });

    assert!(matches!(
        result,
        Err(NotesError::InvalidNotesTreeEntry { .. })
    ));
}

#[test]
fn planted_negative_duplicate_target_note_in_tree_refused() {
    let limits = sha1_limits();
    let target_hex = "d".repeat(40);
    // Tree containing duplicate leaf entries for the same target
    let bad_tree = vec![
        TreeEntry {
            mode: b"100644".to_vec(),
            name: target_hex.as_bytes().to_vec(),
            object_id: vec![1u8; 20],
        },
        TreeEntry {
            mode: b"100644".to_vec(),
            name: target_hex.as_bytes().to_vec(),
            object_id: vec![2u8; 20],
        },
    ];
    // In GitCompatibleImport to bypass strict creation duplicate tree entry check
    let tree_body = emit_tree(&bad_tree, AcceptanceProfile::GitCompatibleImport, &limits).unwrap();

    let result = parse_notes_tree::<Sha1, _>(
        &tree_body,
        AcceptanceProfile::GitCompatibleImport,
        &limits,
        |_| Ok(vec![]),
    );

    assert!(matches!(
        result,
        Err(NotesError::DuplicateNoteTarget { .. })
    ));
}
