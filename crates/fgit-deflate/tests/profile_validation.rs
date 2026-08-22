#![forbid(unsafe_code)]

//! frankengit-deflate-profile-validation-2vwo: the profile validator, one
//! condition at a time.
//!
//! `DeflateLimits::validate` rejects a profile through a five-way disjunction
//! plus two `match` arms — seven independent ways to be refused, all collapsing
//! into `DeflateRefusal::InvalidProfile`, a **unit variant with no payload**.
//! Nothing in the refusal says which condition fired, so a per-*site* coverage
//! claim would be unfalsifiable. Per *condition* is falsifiable, and that is the
//! unit used here: every probe below violates exactly one condition and
//! satisfies the rest.
//!
//! `validate` is private, so these drive it through `Deflater::new`, whose first
//! act is `limits.validate(profile)?`.
//!
//! # Two of the seven are unreachable, and are recorded rather than probed
//!
//! **`profile.window_bytes > RFC1951_MAX_WINDOW_BYTES`.** The limits guard runs
//! first and contains both `max_window_bytes > RFC1951_MAX_WINDOW_BYTES` and
//! `max_window_bytes < profile.window_bytes`. So `max_window_bytes` can never
//! exceed 32768, and any profile window above 32768 trips the *limits* guard and
//! returns `ResourceLimit` before the profile disjunction is evaluated.
//!
//! **The `max_match_chain != 0` half of the block-kind arm.** Isolating it needs
//! a zero window with a nonzero chain, which the earlier
//! `max_match_chain > window_bytes` disjunct refuses first with the same
//! variant. See `a_chain_without_a_window_is_refused_before_the_block_kind_arm_is_reached`,
//! which pins that ordering so a future reorder is visible.
//!
//! Both are **dominated**, not merely untested. No probe is manufactured for
//! either, and neither is counted as covered — six of the seven conditions are.
//!
//! §7 requires bounds enforced before allocation and work; §8 requires closed
//! deterministic policies. This validator is what stops a nondeterministic or
//! unbounded profile reaching the encoder — `lazy_matching` is refused outright
//! rather than supported, which is a determinism decision worth pinning as
//! behaviour instead of leaving implicit in a struct field.

use fgit_deflate::{
    DeflateBlockKind, DeflateLimits, DeflateProfile, DeflateRefusal, Deflater,
    RFC1951_MAX_WINDOW_BYTES,
};

const LIMITS: DeflateLimits = DeflateLimits::GIT_OBJECT;

/// The refusal `Deflater::new` gives for a profile, or a panic if it accepted.
fn refused(profile: DeflateProfile) -> DeflateRefusal {
    Deflater::new(LIMITS, profile).expect_err("this profile must be refused")
}

fn accepted(profile: DeflateProfile) {
    assert!(
        Deflater::new(LIMITS, profile).is_ok(),
        "this profile satisfies every condition and must be accepted",
    );
}

#[test]
fn a_zero_block_size_is_refused() {
    accepted(DeflateProfile::DEFAULT);
    assert_eq!(
        refused(DeflateProfile {
            block_bytes: 0,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
    );
}

#[test]
fn a_block_size_past_the_u16_ceiling_is_refused_and_the_ceiling_itself_is_not() {
    let ceiling = usize::from(u16::MAX);

    accepted(DeflateProfile {
        block_bytes: ceiling,
        ..DeflateProfile::DEFAULT
    });
    assert_eq!(
        refused(DeflateProfile {
            block_bytes: ceiling + 1,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
        "the bound is inclusive; only one past it may refuse",
    );
}

#[test]
fn a_match_chain_longer_than_the_window_is_refused_and_an_equal_one_is_not() {
    accepted(DeflateProfile {
        max_match_chain: RFC1951_MAX_WINDOW_BYTES,
        ..DeflateProfile::DEFAULT
    });
    assert_eq!(
        refused(DeflateProfile {
            max_match_chain: RFC1951_MAX_WINDOW_BYTES + 1,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
        "a chain may reach the window exactly but not exceed it",
    );
}

/// Lazy matching is refused outright rather than supported.
///
/// Pinned as behaviour because it is a determinism decision, not an omission: a
/// future contributor reading only the struct field could reasonably assume
/// setting it is permitted.
#[test]
fn lazy_matching_is_refused_rather_than_honoured() {
    assert_eq!(
        refused(DeflateProfile {
            lazy_matching: true,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
    );
}

/// A history-free block kind carrying a window is refused.
///
/// `Stored` and `Dynamic` retain no match history, so a nonzero window is a
/// contradiction rather than a harmless extra.
///
/// # Only the window half of that arm is reachable
///
/// The arm is `window_bytes != 0 || max_match_chain != 0`. Isolating the chain
/// half needs `window_bytes == 0` with `max_match_chain != 0` — but that trips
/// the earlier `max_match_chain > window_bytes` disjunct, which refuses first
/// with the same variant. So the chain half is **dominated** and no probe is
/// written for it: any input reaching it has already been refused. Setting both
/// (as a naive probe would) tests the window half over again while appearing to
/// test the chain.
#[test]
fn a_history_free_block_kind_carrying_a_window_is_refused() {
    for kind in [DeflateBlockKind::Stored, DeflateBlockKind::Dynamic] {
        let base = DeflateProfile {
            block_kind: kind,
            window_bytes: 0,
            max_match_chain: 0,
            ..DeflateProfile::DEFAULT
        };
        accepted(base);

        assert_eq!(
            refused(DeflateProfile {
                window_bytes: 1,
                ..base
            }),
            DeflateRefusal::InvalidProfile,
            "{kind:?} keeps no history, so a window is a contradiction",
        );
    }
}

/// The chain-half domination above, pinned as behaviour rather than left as a
/// comment.
///
/// A history-free kind with a chain but no window is refused by the disjunct,
/// not by the block-kind arm. This test exists so that if someone later reorders
/// those two checks, the change is visible here instead of silently altering
/// which condition owns this input.
#[test]
fn a_chain_without_a_window_is_refused_before_the_block_kind_arm_is_reached() {
    assert_eq!(
        refused(DeflateProfile {
            block_kind: DeflateBlockKind::Stored,
            window_bytes: 0,
            max_match_chain: 1,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
        "chain > window refuses first; the block-kind arm never sees this input",
    );
}

/// The mirror image: a matching block kind without the parameters it needs.
#[test]
fn a_matching_block_kind_without_history_parameters_is_refused() {
    assert_eq!(
        refused(DeflateProfile {
            window_bytes: 0,
            max_match_chain: 0,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
        "Fixed searches history, so a zero window cannot be honoured",
    );
    assert_eq!(
        refused(DeflateProfile {
            max_match_chain: 0,
            ..DeflateProfile::DEFAULT
        }),
        DeflateRefusal::InvalidProfile,
        "Fixed searches history, so a zero chain cannot be honoured",
    );
}

/// The permitted twins. Without these, a validator that refused everything would
/// satisfy every expectation above.
#[test]
fn the_three_named_profiles_all_validate() {
    for profile in [
        DeflateProfile::FAST_STORED,
        DeflateProfile::DEFAULT,
        DeflateProfile::DYNAMIC,
    ] {
        assert!(
            Deflater::new(LIMITS, profile).is_ok(),
            "the shipped profile {} must validate",
            profile.id,
        );
    }
}

/// Order: the limits guard runs before the profile guard.
///
/// Only observable from an input that fails BOTH — here the limits are
/// unusable *and* the profile sets `lazy_matching`. A per-guard corpus, however
/// complete, is blind to a stage swap.
#[test]
fn limits_are_checked_before_the_profile() {
    let unusable = DeflateLimits {
        max_input_bytes: 0,
        ..DeflateLimits::GIT_OBJECT
    };
    let also_bad = DeflateProfile {
        lazy_matching: true,
        ..DeflateProfile::DEFAULT
    };

    let refusal =
        Deflater::new(unusable, also_bad).expect_err("both the limits and the profile are invalid");
    assert!(
        matches!(refusal, DeflateRefusal::ResourceLimit { .. }),
        "the limits guard is evaluated first, so it must be what reports; got {refusal:?}",
    );
}
