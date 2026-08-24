#![forbid(unsafe_code)]
//! Independent canonical vectors for the shared hidden-ref policy body.
//!
//! This body is named by a configuration's `policy_root` and is shared by both
//! carrier families, so its bytes are the one authoritative definition of what a
//! repository hides. The vectors below are written directly from the frame and
//! payload specification; they are **not** produced by the encoder under test. A
//! round trip through `encode_body` and back cannot see a symmetric defect,
//! because a field mis-encoded and mis-decoded the same way still compares
//! equal.
//!
//! Order is the property most worth pinning here. `RefVisibility::hides` is
//! last-match-wins and a rule may begin with `!`, so the encoding must be a
//! sequence and never a canonical set — sorting would silently change which rule
//! wins, and `!` (0x21) sorts before the `r` of `refs/…`.

use fgit_codec::{
    CanonicalBody, DecodeLimits, HiddenRefPolicyBody, canonical_body_bytes, decode_body,
    encode_body, read_frame_header,
};

/// An empty policy at schema 1.0: a `u32` rule count of zero and nothing else.
const EMPTY_POLICY_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x1ffrankengit/hidden-ref-policy/v1\
    \x00\x00\x00\x11hidden-ref-policy\
    \x00\x01\x00\x00\
    \x00\x00\x00\x04\x00\x00\x00\x00";

/// Two ordered rules: a count of two, then each rule length-prefixed.
const RULED_POLICY_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x1ffrankengit/hidden-ref-policy/v1\
    \x00\x00\x00\x11hidden-ref-policy\
    \x00\x01\x00\x00\
    \x00\x00\x00\x2e\x00\x00\x00\x02\
    \x00\x00\x00\x0drefs/internal\
    \x00\x00\x00\x15!refs/internal/public";

fn ruled_policy() -> HiddenRefPolicyBody {
    HiddenRefPolicyBody {
        rules: vec![b"refs/internal".to_vec(), b"!refs/internal/public".to_vec()],
    }
}

#[test]
fn an_empty_policy_matches_the_independent_golden() {
    let expected = HiddenRefPolicyBody::default();
    let (header, _) = read_frame_header(EMPTY_POLICY_GOLDEN, DecodeLimits::DEFAULT)
        .expect("the independently written empty-policy frame is structurally valid");
    assert_eq!(header.schema, HiddenRefPolicyBody::schema_id());
    assert_eq!(
        canonical_body_bytes(&expected).expect("the empty policy encodes"),
        [0, 0, 0, 0],
        "an empty policy is exactly a zero rule count"
    );
    assert_eq!(
        decode_body::<HiddenRefPolicyBody>(EMPTY_POLICY_GOLDEN, DecodeLimits::DEFAULT)
            .expect("the empty-policy golden decodes"),
        expected
    );
    assert_eq!(
        encode_body(&expected).expect("the empty policy re-encodes"),
        EMPTY_POLICY_GOLDEN,
        "the encoder must reproduce the independently written frame"
    );
}

#[test]
fn a_two_rule_policy_matches_the_independent_golden() {
    // The empty vector cannot see a defect in the per-rule framing: a count of
    // zero never reaches `write_bytes`/`read_bytes` at all. This is the vector
    // that pins the sequence encoding.
    let expected = ruled_policy();
    assert_eq!(
        encode_body(&expected).expect("the two-rule policy encodes"),
        RULED_POLICY_GOLDEN,
        "the encoder must reproduce the independently written two-rule frame"
    );
    assert_eq!(
        decode_body::<HiddenRefPolicyBody>(RULED_POLICY_GOLDEN, DecodeLimits::DEFAULT)
            .expect("the two-rule golden decodes"),
        expected
    );
}

#[test]
fn the_stored_order_survives_and_is_not_sorted_order() {
    // Order is load-bearing: `hides` is last-match-wins, so the trailing
    // negation only re-exposes if it stays last. The chosen data makes a
    // canonical-set encoding OBSERVABLE — `!` is 0x21 and sorts before the `r`
    // of `refs/internal`, so sorted order is the reverse of stored order. If any
    // step sorted the rules, the first assertion below would fail.
    let decoded = decode_body::<HiddenRefPolicyBody>(RULED_POLICY_GOLDEN, DecodeLimits::DEFAULT)
        .expect("the two-rule golden decodes");

    assert_eq!(
        decoded.rules,
        vec![b"refs/internal".to_vec(), b"!refs/internal/public".to_vec()],
        "the broad rule must still precede its negation after a round trip"
    );
    assert!(
        decoded.rules[0] > decoded.rules[1],
        "the stored order is deliberately NOT sorted order, so a canonical-set \
         encoding would be observable here rather than silent"
    );
}
