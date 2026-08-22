// Closed vocabularies: ALL is a COMPLETE enumeration, not merely a consistent one.
//
// Each code-point vocabulary in this crate pairs an exhaustive encoder with a
// decoder that searches a hand-maintained array:
//
//     code_point(self) -> u16      an exhaustive `match self`. EVERY variant
//                                  encodes, whether or not it is listed.
//     from_code_point(u16)         Self::ALL.iter().find(..). ONLY listed
//                                  variants decode.
//
// So a variant omitted from `ALL` is not just untested. It is a value this
// crate will put on the wire and then refuse to read back, reported as
// `TypeRefusal::CodePointUnknown` — indistinguishable from a code point sent by
// a newer peer this build has never heard of.
//
// The pre-existing suite is NOT blind to a member deleted from `ALL`: the
// dimension-count test pins thirty and thirty-one, so any deletion moves a
// count. It is blind to the drift that actually happens. Adding a variant makes
// the compiler demand arms in `code_point`, `as_str` and the completeness
// guard, and demand nothing of `ALL` — the two counts still read thirty and
// thirty-one, so the whole pre-existing suite passes while the new member
// cannot be decoded.
//
// Measured rather than assumed: that mutation compiles, and exactly one test in
// this crate of seventy fails — `all_enumerates_every_refusal_code`, below.
//
// `frankengit-0eu0` found this drift here once already (a test named "every"
// covering seven of eight), and its fix added the `_every_*_is_listed`
// compile-time guards beside the arrays. Those guards state their own limit:
// they force a new variant to be CONSIDERED beside the array, but cannot force
// it to be ADDED. The mutation above is that limit, executed.
//
// This file closes that residual. `variant_count` reads the variant total from
// the type itself, so the corpus here is DERIVED and cannot drift. A fourth
// hand-written list would have drifted in exactly the same way as `ALL` and
// proved nothing — which is why this file contains no list of variants.
#![forbid(unsafe_code)]
#![feature(variant_count)]

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::mem::variant_count;

use fgit_types::TypeRefusal;
use fgit_types::vocabulary::{MismatchPolicy, PublicationEpoch, RefusalCode, RequestRejectionCode};

/// Proves `all` enumerates every variant of its type exactly once.
///
/// Distinctness plus a count equal to the type's variant total is sufficient:
/// `all.len()` distinct members drawn from a type with `all.len()` variants
/// leaves no variant unlisted. Neither half suffices alone — a duplicate entry
/// would inflate the length to match while still omitting a variant.
fn assert_all_enumerates_every_variant<T: Copy + Ord + Debug>(
    all: &[T],
    variants: usize,
    vocabulary: &str,
) {
    let distinct: BTreeSet<T> = all.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        all.len(),
        "{vocabulary}: ALL lists the same member twice, so its length overstates its coverage"
    );
    assert_eq!(
        all.len(),
        variants,
        "{vocabulary}: ALL lists {} of the type's {variants} variants. An unlisted variant still \
         encodes via code_point but cannot be recovered by from_code_point",
        all.len()
    );
}

/// The decodable wire surface must be exactly the encodable one.
///
/// Scans the whole `u16` space rather than the members, so it is measuring the
/// decoder's real acceptance set rather than restating the array.
fn assert_decodable_surface_matches_members<T, F>(
    all: &[T],
    decode: F,
    code_point: fn(T) -> u16,
    vocabulary: &str,
) where
    T: Copy + Ord + Debug,
    F: Fn(u16) -> Result<T, TypeRefusal>,
{
    let encodable: BTreeSet<u16> = all.iter().copied().map(code_point).collect();
    let decodable: BTreeSet<u16> = (u16::MIN..=u16::MAX)
        .filter(|p| decode(*p).is_ok())
        .collect();
    assert_eq!(
        decodable, encodable,
        "{vocabulary}: the set of code points that decode differs from the set that encode"
    );
}

#[test]
fn all_enumerates_every_request_rejection_code() {
    assert_all_enumerates_every_variant(
        RequestRejectionCode::ALL,
        variant_count::<RequestRejectionCode>(),
        "RequestRejectionCode",
    );
}

#[test]
fn all_enumerates_every_refusal_code() {
    assert_all_enumerates_every_variant(
        RefusalCode::ALL,
        variant_count::<RefusalCode>(),
        "RefusalCode",
    );
}

#[test]
fn all_enumerates_every_mismatch_policy() {
    assert_all_enumerates_every_variant(
        MismatchPolicy::ALL,
        variant_count::<MismatchPolicy>(),
        "MismatchPolicy",
    );
}

#[test]
fn all_enumerates_every_publication_epoch() {
    assert_all_enumerates_every_variant(
        PublicationEpoch::ALL,
        variant_count::<PublicationEpoch>(),
        "PublicationEpoch",
    );
}

#[test]
fn the_refusal_code_wire_surface_is_exactly_its_members() {
    assert_decodable_surface_matches_members(
        RefusalCode::ALL,
        RefusalCode::from_code_point,
        RefusalCode::code_point,
        "RefusalCode",
    );
}

#[test]
fn the_request_rejection_wire_surface_is_exactly_its_members() {
    assert_decodable_surface_matches_members(
        RequestRejectionCode::ALL,
        RequestRejectionCode::from_code_point,
        RequestRejectionCode::code_point,
        "RequestRejectionCode",
    );
}

/// The permitted twin of the refusal below: a listed member survives the round
/// trip. Without this, a decoder that refused EVERYTHING would satisfy the
/// unknown-code-point expectation.
#[test]
fn a_listed_member_still_recovers_from_its_own_code_point() {
    for code in RefusalCode::ALL {
        let recovered = RefusalCode::from_code_point(code.code_point())
            .expect("a member listed in ALL must decode");
        assert_eq!(recovered, *code);
    }
}

/// What an unlisted variant would look like from the outside, stated as
/// behaviour: the decoder reports it as a code point it does not know, which is
/// the same answer it gives for a genuinely newer peer's code.
#[test]
fn a_code_point_no_member_encodes_is_refused_as_unknown() {
    let encodable: BTreeSet<u16> = RefusalCode::ALL
        .iter()
        .map(|code| code.code_point())
        .collect();
    let unused = (u16::MIN..=u16::MAX)
        .find(|point| !encodable.contains(point))
        .expect("the vocabulary cannot occupy the whole u16 space");

    let refusal = RefusalCode::from_code_point(unused)
        .expect_err("an unencodable code point must not resolve to some existing member");
    assert_eq!(
        refusal,
        TypeRefusal::CodePointUnknown {
            field: "RefusalCode",
            observed: u32::from(unused),
        },
        "an omitted member and an unknown peer code are reported identically, which is why the \
         completeness of ALL cannot be checked from the decoder alone"
    );
}
