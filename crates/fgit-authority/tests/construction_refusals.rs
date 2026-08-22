//! frankengit-pl27: the construction-time refusals nothing was exercising.
//!
//! A refusal-variant sweep of this crate's eleven refusal enums found four
//! directly-constructed variants with zero assertions anywhere in the
//! workspace. They guard two surfaces:
//!
//! * **key admission** — `MAX_KEY_BYTES` is described in `keys.rs` as part of
//!   the *contract*, not a backend detail: "a caller that derives longer keys
//!   must be refused identically by every profile". Nothing checked that.
//! * **identity derivation** — `canonical_body_id` refuses to identify a body
//!   under a domain that is not its own. That is NPC §5.2's "one seal body owns
//!   one logical identity; key reuse with different semantics fails closed",
//!   enforced at the point a body becomes an identity, and it is also the
//!   bridge between the two unrelated `domain` vocabularies (`IdentityDomain`
//!   and `DomainTag`) — exactly where a confusion would land.
//!
//! Every bound here is `>` against its limit, so *exactly* the limit is
//! admissible. Each refusal is therefore paired with a permitted twin sitting
//! on that exact value, which is the case a `>`/`>=` slip flips and the one
//! that makes the refusal evidence of a bound rather than merely evidence of a
//! refusal.

use fgit_authority::{
    HeadKey, IdempotencyKey, IdentityRefusal, ImmutableKey, KeyError, MAX_IDEMPOTENCY_KEY_BYTES,
    MAX_KEY_BYTES, canonical_body_id,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;

/// An authority-head body, whose `CanonicalBody::DOMAIN` is
/// `frankengit/authority-head/v1`.
fn head_body() -> RepositoryAuthorityHeadBody {
    fgit_codec::harness::genesis_head()
}

/// An empty key is refused by both key types.
///
/// Both entry points are checked because `HeadKey::new` and `ImmutableKey::new`
/// share one `validate`. A test on one alone would not notice the other
/// dropping its call to it.
#[test]
fn both_key_types_refuse_an_empty_key() {
    assert!(
        matches!(HeadKey::new(Vec::new()), Err(KeyError::Empty)),
        "an empty head key must be refused",
    );
    assert!(
        matches!(ImmutableKey::new(Vec::new()), Err(KeyError::Empty)),
        "an empty immutable key must be refused",
    );

    // The permitted twin: one byte is a key.
    HeadKey::new(vec![b'k']).expect("a one-byte head key is admissible");
    ImmutableKey::new(vec![b'k']).expect("a one-byte immutable key is admissible");
}

/// An over-long key is refused, and the refusal reports its own length and
/// limit.
///
/// Asserting only the variant would not catch a refusal that fires correctly
/// but reports the wrong numbers, which is what an operator reads to find out
/// why their key was rejected.
#[test]
fn both_key_types_refuse_a_key_past_max_key_bytes_reporting_len_and_limit() {
    let over = vec![b'k'; MAX_KEY_BYTES + 1];

    let head = HeadKey::new(over.clone()).expect_err("one byte past the bound must refuse");
    assert!(
        matches!(head, KeyError::TooLong { len, limit }
            if len == MAX_KEY_BYTES + 1 && limit == MAX_KEY_BYTES),
        "the head-key refusal must report its own length and limit; got {head:?}",
    );

    let immutable = ImmutableKey::new(over).expect_err("one byte past the bound must refuse");
    assert!(
        matches!(immutable, KeyError::TooLong { len, limit }
            if len == MAX_KEY_BYTES + 1 && limit == MAX_KEY_BYTES),
        "the immutable-key refusal must report its own length and limit; got {immutable:?}",
    );
}

/// The permitted twin at exactly `MAX_KEY_BYTES`.
///
/// `validate` is `bytes.len() > MAX_KEY_BYTES`, so a key of exactly the limit
/// is admissible. Without this the bound could be off by one in the
/// conservative direction and every refusal test above would still pass.
#[test]
fn both_key_types_permit_a_key_of_exactly_max_key_bytes() {
    HeadKey::new(vec![b'k'; MAX_KEY_BYTES]).expect("exactly MAX_KEY_BYTES is inside the bound");
    ImmutableKey::new(vec![b'k'; MAX_KEY_BYTES])
        .expect("exactly MAX_KEY_BYTES is inside the bound");
}

/// The idempotency-key bound, refusal and permitted twin together.
#[test]
fn an_idempotency_key_past_its_bound_is_refused_and_exactly_the_bound_is_not() {
    IdempotencyKey::new(vec![b'i'; MAX_IDEMPOTENCY_KEY_BYTES])
        .expect("exactly MAX_IDEMPOTENCY_KEY_BYTES is inside the bound");

    let refusal = IdempotencyKey::new(vec![b'i'; MAX_IDEMPOTENCY_KEY_BYTES + 1])
        .expect_err("one byte past the bound must refuse");
    assert!(
        matches!(refusal, IdentityRefusal::IdempotencyKeyTooLong { observed, limit }
            if observed == MAX_IDEMPOTENCY_KEY_BYTES + 1 && limit == MAX_IDEMPOTENCY_KEY_BYTES),
        "the refusal must report what it observed and the bound it enforced; got {refusal:?}",
    );
}

/// §5.2: a body cannot be identified under a domain that is not its own.
///
/// `RepositoryAuthorityHeadBody::DOMAIN` is `frankengit/authority-head/v1`.
/// Asking for the decision-batch domain must fail closed rather than mint an
/// identity that would collide with a different body class — that is how "one
/// seal body owns one logical identity" is enforced at derivation.
///
/// Both payload fields are asserted, because a transposed `expected`/`observed`
/// pair reports the mismatch backwards and would survive a variant-only check.
#[test]
fn a_body_refuses_to_be_identified_under_another_domain() {
    let body = head_body();

    let refusal = canonical_body_id(
        IdentityDomain::RepositoryDecisionBatch,
        CANONICAL_CODEC_VERSION,
        &body,
    )
    .expect_err("an authority head must not take a decision-batch identity");

    let IdentityRefusal::DomainMismatch { expected, observed } = refusal else {
        panic!("expected DomainMismatch, got {refusal:?}");
    };
    assert_eq!(
        *expected,
        <RepositoryAuthorityHeadBody as fgit_codec::CanonicalBody>::DOMAIN,
        "`expected` must be the body's own domain",
    );
    assert_eq!(
        *observed,
        IdentityDomain::RepositoryDecisionBatch.domain_tag(),
        "`observed` must be the domain the caller asked for",
    );
}

/// The permitted twin: the body's own domain identifies it.
///
/// Without this the refusal above is satisfied by a `canonical_body_id` that
/// refuses everything, which would prove nothing about domain matching.
#[test]
fn a_body_identified_under_its_own_domain_succeeds() {
    let body = head_body();

    canonical_body_id(
        IdentityDomain::RepositoryAuthorityHead,
        CANONICAL_CODEC_VERSION,
        &body,
    )
    .expect("an authority head takes an authority-head identity");
}
