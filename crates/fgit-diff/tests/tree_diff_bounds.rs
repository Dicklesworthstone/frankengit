#![forbid(unsafe_code)]

//! frankengit-s27o: the two bounds guarding exact-object rename detection.
//!
//! Rename detection is a quadratic scan over deletions against additions, so it
//! needs a hard candidate budget (AGENTS.md §7, bounds enforced before the
//! work) and it takes a caller-supplied similarity threshold that must be
//! validated rather than trusted. Neither bound had a test anywhere in the
//! workspace, counting the crate's own in-src module.
//!
//! # The threshold has two guards in sequence, and only one value survives both
//!
//! ```text
//! lib.rs:1278   if minimum_similarity_percent > 100  -> InvalidSimilarityThreshold
//! lib.rs:1283   if minimum_similarity_percent != 100 -> UnsupportedSimilarityThreshold
//! ```
//!
//! So 101 is out of range, 99 is in range but unimplemented, and 100 is the
//! only accepted value. The in-src module already covers the 99 case; the
//! out-of-range case and the accepted case are what this file adds.
//!
//! That split is what makes the first test below an ORDERING probe for free:
//! delete the `> 100` guard and 101 falls through to the `!= 100` guard, which
//! reports a DIFFERENT variant. The assertion is therefore sensitive to which
//! guard ran, not merely to the fact that something refused.
//!
//! # Both bounds are one edit from an over-strict version
//!
//! `> 100` written as `>= 100` rejects the only threshold the code supports.
//! `candidate_pairs == max` written as `<=` rejects a scan that exactly fits its
//! budget. Neither is visible to a refusal probe, so each refusal here is paired
//! with the nearest input that must be ACCEPTED.

use fgit_diff::{
    RenameProfile, TreeChange, TreeDiffError, TreeDiffOptions, TreeEntry, TreeMode, diff_trees,
};

/// An ordinary non-executable blob; the mode is irrelevant to both bounds and
/// is held constant so it cannot be what a refusal is attributable to.
const BLOB: TreeMode = TreeMode(0o100_644);

fn entry(path: &[u8], object: u8) -> TreeEntry<u8> {
    TreeEntry {
        path: path.to_vec(),
        mode: BLOB,
        object,
    }
}

fn renames(minimum_similarity_percent: u8, max_candidate_pairs: usize) -> TreeDiffOptions {
    TreeDiffOptions {
        rename: RenameProfile::ExactObject {
            minimum_similarity_percent,
            max_candidate_pairs,
        },
        ..TreeDiffOptions::default()
    }
}

/// One path deleted and one path added carrying the SAME object: exactly one
/// candidate pair, and a genuine rename.
fn one_rename() -> (Vec<TreeEntry<u8>>, Vec<TreeEntry<u8>>) {
    (vec![entry(b"old", 7)], vec![entry(b"new", 7)])
}

/// A similarity threshold above 100 percent is refused as out of range.
///
/// This is also the ordering probe. Remove the range guard and 101 reaches the
/// `!= 100` guard instead, which returns `UnsupportedSimilarityThreshold` --
/// a different variant -- so this assertion fails. It distinguishes "the value
/// was rejected" from "the value was rejected as out of range", which are
/// different answers to give a caller who passed 101 by mistake.
///
/// Empty trees, so no candidate pair exists and the budget cannot be what
/// fires.
#[test]
fn a_similarity_threshold_above_one_hundred_is_refused_as_out_of_range() {
    assert_eq!(
        diff_trees::<u8, _, _>(Vec::new(), Vec::new(), renames(101, 1)),
        Err(TreeDiffError::InvalidSimilarityThreshold { requested: 101 }),
    );
}

/// The permitted twin at the exact inclusive boundary: 100 percent is accepted.
///
/// The guard is `> 100`. A probe showing only that 101 is refused is equally
/// consistent with `>= 100`, which would reject the ONLY threshold the
/// implementation supports and make rename detection unreachable entirely.
/// One hundred is the smallest input separating the two readings.
///
/// Empty trees again, isolating the threshold from the candidate budget.
#[test]
fn a_similarity_threshold_of_exactly_one_hundred_is_accepted() {
    let diff = diff_trees::<u8, _, _>(Vec::new(), Vec::new(), renames(100, 1))
        .expect("100 percent is the one threshold exact-object rename detection implements");

    assert!(diff.changes.is_empty(), "two empty trees differ in nothing",);
}

/// A rename scan that would exceed its candidate budget is refused.
///
/// The fixture offers exactly one deletion/addition pair, so a budget of zero
/// is exceeded by the first candidate the scan considers. §7 wants the bound
/// enforced during the scan rather than after it.
#[test]
fn a_rename_scan_over_its_candidate_budget_is_refused() {
    let (old, new) = one_rename();

    assert_eq!(
        diff_trees(old, new, renames(100, 0)),
        Err(TreeDiffError::RenameCandidateLimitExceeded { limit: 0 }),
    );
}

/// The permitted twin at the exact inclusive boundary: a scan of exactly the
/// budget is accepted, and finds the rename.
///
/// The guard is `candidate_pairs == max_candidate_pairs`, checked BEFORE the
/// counter is incremented, so a budget of one admits exactly one candidate.
/// Written as `<=` it would refuse every scan that exactly fits, while the
/// budget-of-zero probe above would still pass.
///
/// The success is asserted on the resulting change rather than on `is_ok`: a
/// scan that silently produced no rename would satisfy a weaker assertion while
/// defeating the entire feature.
#[test]
fn a_rename_scan_of_exactly_its_candidate_budget_is_accepted() {
    let (old, new) = one_rename();

    let diff = diff_trees(old, new, renames(100, 1))
        .expect("one candidate pair fits a budget of exactly one");

    assert_eq!(
        diff.changes,
        vec![TreeChange::Renamed {
            before: entry(b"old", 7),
            after: entry(b"new", 7),
            similarity_percent: 100,
        }],
        "the pair carries one object, so it is an exact rename at 100 percent",
    );
}
