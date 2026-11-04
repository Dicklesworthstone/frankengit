use super::*;
use fgit_forge::event::protection::PathReviewScope;
use fgit_types::{GitOid, GitOidSha1, RefName};
use std::sync::atomic::{AtomicUsize, Ordering};

fn oid(value: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([value; 20]))
}
fn merge() -> NativeMerge {
    NativeMerge {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_tip: oid(1),
        base_tip: oid(2),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        target_tip_before: oid(3),
        merge_commit: oid(4),
    }
}
fn rule(path: &[u8], scope: PathReviewScope, reviewer: u8) -> PathReviewRule {
    PathReviewRule {
        path: path.to_vec(),
        scope,
        reviewers: vec![PrincipalId::from_bytes([reviewer; 16])],
        required_approvals: 1,
    }
}
fn paths(values: &[&[u8]]) -> VerifiedMergePaths {
    VerifiedMergePaths {
        merge: merge(),
        changed_paths: values.iter().map(|path| path.to_vec()).collect(),
    }
}

#[test]
fn every_overlapping_selector_is_required_without_precedence_or_unrelated_matches() {
    let rules = vec![
        rule(b"docs", PathReviewScope::Subtree, 1),
        rule(b"src", PathReviewScope::Exact, 2),
        rule(b"src", PathReviewScope::Subtree, 3),
        rule(b"src/security", PathReviewScope::Subtree, 4),
        rule(b"src/security/key.rs", PathReviewScope::Exact, 5),
        rule(b"src/security/key.rs", PathReviewScope::Subtree, 6),
        rule(b"src/security-old", PathReviewScope::Subtree, 7),
    ];
    let proof = paths(&[b"src/security/key.rs"]);
    assert_eq!(
        matching_rules(&merge(), &rules, Some(&proof), &|| false).unwrap(),
        vec![&rules[2], &rules[3], &rules[4], &rules[5]],
    );
    // A structural directory replacement independently matches its own entry.
    let proof = paths(&[b"src", b"src/security/key.rs"]);
    assert_eq!(
        matching_rules(&merge(), &rules, Some(&proof), &|| false).unwrap(),
        vec![&rules[1], &rules[2], &rules[3], &rules[4], &rules[5]],
    );
}

#[test]
fn no_witness_or_any_mismatched_native_coordinate_cannot_satisfy_path_policy() {
    let rules = [rule(b"src", PathReviewScope::Subtree, 3)];
    assert!(matches!(
        matching_rules(&merge(), &rules, None, &|| false),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))
    ));
    for field in 0..6 {
        let mut proof = paths(&[b"unrelated"]);
        match field {
            0 => proof.merge.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            1 => proof.merge.source_tip = oid(9),
            2 => proof.merge.base_tip = oid(9),
            3 => proof.merge.target_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            4 => proof.merge.target_tip_before = oid(9),
            _ => proof.merge.merge_commit = oid(9),
        }
        assert!(matches!(
            matching_rules(&merge(), &rules, Some(&proof), &|| false),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale))
        ));
    }
    let proof = paths(&[b"unrelated"]);
    assert!(
        matching_rules(&merge(), &rules, Some(&proof), &|| false)
            .unwrap()
            .is_empty()
    );
    assert!(
        matching_rules(&merge(), &[], None, &|| false)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn raw_names_never_alias_and_one_rule_is_counted_once_per_candidate() {
    let rules = [
        rule(b"SRC", PathReviewScope::Subtree, 3),
        rule(b"src/\xef\xbf\xbd", PathReviewScope::Subtree, 4),
        rule(b"src/\xff", PathReviewScope::Subtree, 5),
    ];
    let proof = paths(&[b"src/\xff/a", b"src/\xff/b", b"src/\xff/c"]);
    assert_eq!(
        matching_rules(&merge(), &rules, Some(&proof), &|| false).unwrap(),
        vec![&rules[2]],
    );
    assert_eq!(proof.merge(), &merge());
    assert_eq!(proof.changed_paths().len(), 3);
}

#[test]
fn cancellation_is_checked_during_matching_even_without_an_applicable_rule() {
    let rules = [rule(b"protected", PathReviewScope::Subtree, 3)];
    let proof = paths(&[b"a", b"b", b"c", b"d"]);
    let calls = AtomicUsize::new(0);
    assert!(matches!(
        matching_rules(&merge(), &rules, Some(&proof), &|| calls
            .fetch_add(1, Ordering::SeqCst)
            >= 4),
        Err(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    assert!(calls.load(Ordering::SeqCst) >= 5);
    assert!(matching_rules(&merge(), &[], None, &|| true).is_err());
}
