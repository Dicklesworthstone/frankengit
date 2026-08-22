#![forbid(unsafe_code)]

//! frankengit-32v2: the base-count dispatch in `merge_content_many`.
//!
//! A three-way content merge is defined against a base. `merge_content_many`
//! takes a *slice* of bases and dispatches on how many there are:
//!
//! ```text
//! merge.rs:271   bases.is_empty()   -> ContentMergeError::NoMergeBase
//! merge.rs:275   bases.len() == 1   -> the ordinary three-way merge
//! merge.rs:278+  otherwise          -> recursive/virtual-base merge
//! ```
//!
//! `NoMergeBase` had no test anywhere in the workspace, and neither boundary
//! between the three arms was pinned. That matters because the arms are not
//! interchangeable: the one-base arm is the ordinary merge every caller hits,
//! and mis-dispatching a two-base merge into it would silently drop a base and
//! produce a *different merge result* rather than an error.
//!
//! Each accepted arm is asserted on `receipt.base_count`, which the merge
//! records, rather than on `is_ok`. A dispatch that took the wrong arm would
//! still return `Ok`; only the recorded count catches it.

use fgit_diff::{
    ContentMergeError, ContentMergeOptions, ContentMergeOutcome, MergeProfile, VirtualBaseProfile,
    merge_content_many,
};

/// Edits are placed far apart on purpose. An earlier draft changed adjacent
/// lines and the merge CONFLICTED: at this diff granularity the two edits fell
/// in one overlapping span. Measured, then widened.
const BASE: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n";
const OURS: &[u8] = b"ONE\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n";
const THEIRS: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\nseven\nEIGHT\n";

/// A second, slightly different base, so the many-base arm is exercised with
/// genuinely distinct inputs rather than a duplicated slice.
const OTHER_BASE: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\n";

fn merge(bases: &[&[u8]]) -> Result<fgit_diff::ContentMergeResult, ContentMergeError> {
    merge_content_many(bases, OURS, THEIRS, ContentMergeOptions::default())
}

/// The same merge with the recursive virtual-base profile enabled.
fn merge_recursive(bases: &[&[u8]]) -> Result<fgit_diff::ContentMergeResult, ContentMergeError> {
    let options = ContentMergeOptions {
        profile: MergeProfile {
            virtual_base: VirtualBaseProfile::RecursiveConflictPreservingV1,
            ..MergeProfile::default()
        },
        ..ContentMergeOptions::default()
    };
    merge_content_many(bases, OURS, THEIRS, options)
}

/// A merge with no base at all is refused.
///
/// An empty base slice is not a degenerate merge to be guessed at -- there is
/// no three-way merge without a base, and inventing one would be exactly the
/// silent fallback §3.1 forbids.
#[test]
fn a_merge_with_no_base_is_refused() {
    assert_eq!(merge(&[]), Err(ContentMergeError::NoMergeBase));
}

/// The permitted twin at the exact inclusive boundary: one base is accepted.
///
/// One is the smallest admissible input, and the guard is `is_empty()`.
/// Written `bases.len() <= 1` it would reject the ORDINARY three-way merge --
/// the overwhelmingly common call -- while the empty-slice probe above still
/// passed.
///
/// Asserted on `receipt.base_count` and on a clean result, not on `is_ok`.
#[test]
fn a_merge_with_exactly_one_base_is_accepted() {
    let result = merge(&[BASE]).expect("one base is an ordinary three-way merge");

    assert_eq!(result.receipt.base_count, 1);
    assert!(
        matches!(result.outcome, ContentMergeOutcome::Clean { .. }),
        "edits on different lines merge cleanly; got {:?}",
        result.outcome,
    );
}

/// Several bases are REFUSED under the default single-base profile.
///
/// This is the arm I got wrong before measuring, and it is the one worth
/// having. `ContentMergeOptions::default()` carries
/// `VirtualBaseProfile::RequireSingle`, so a two-base merge does not fall
/// through to a recursive merge -- it is refused outright with a DIFFERENT
/// variant. The base count alone does not decide the arm; the count and the
/// profile decide it together.
#[test]
fn several_bases_are_refused_under_the_default_single_base_profile() {
    assert_eq!(
        merge(&[BASE, OTHER_BASE]),
        Err(ContentMergeError::MultipleBasesRequireVirtualBase),
    );
}

/// Several bases are accepted once the recursive virtual-base profile is
/// selected, and the count it consumed is recorded.
///
/// The permitted twin for the refusal above: the same two bases, the same
/// inputs, one option changed. Without it, that refusal is equally consistent
/// with multiple bases being rejected unconditionally.
///
/// Asserted on `receipt.base_count`, not `is_ok`. The dispatch is
/// `bases.len() == 1`; written `>= 1` a two-base merge would silently take the
/// single-base path, use only `bases[0]`, and report a count of one -- a
/// different merge returned as `Ok`, with no error anywhere.
#[test]
fn several_bases_are_accepted_under_the_recursive_virtual_base_profile() {
    let result =
        merge_recursive(&[BASE, OTHER_BASE]).expect("two bases fold under the recursive profile");

    assert_eq!(
        result.receipt.base_count, 2,
        "the receipt must record how many bases the merge actually consumed",
    );
}
