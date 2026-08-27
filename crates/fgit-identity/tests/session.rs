//! Session establishment, strength binding, and rotation.
//!
//! The load-bearing property is that ROTATION CANNOT BUY ANYTHING. Refreshing a
//! session proves the holder still holds what they already had; if that could
//! raise the authentication strength or push the deadline out, rotation would
//! be a privilege-escalation primitive operated by the party it is meant to
//! bound. Every refusal below is therefore paired with the near-identical
//! permitted case, so a passing suite cannot be satisfied by a `rotate` that
//! simply always refuses.

use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_identity::{
    AuthenticationStrength, RevocationEvidence, Session, SessionId, SessionRefusal,
};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{PrincipalId, RepositoryId};

const EXPIRES_AT: u64 = 1_000;

const fn repository(tag: u8) -> RepositoryId {
    RepositoryId::from_bytes([tag; OPAQUE_ID_LEN])
}

const fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x33; OPAQUE_ID_LEN])
}

const fn session_id(value: u64) -> SessionId {
    SessionId::try_new(value).expect("nonzero")
}

const fn session(strength: AuthenticationStrength) -> Session {
    Session::establish(
        session_id(1),
        principal(),
        repository(0x11),
        strength,
        EXPIRES_AT,
    )
}

/// The strength lattice is ordered as declared, and the order is what rotation
/// is checked against.
///
/// `Ord` on `AuthenticationStrength` is derived from declaration order, so the
/// order IS the rule. Pinning it here means a future reordering of the variants
/// fails this test rather than silently changing what rotation permits — the
/// enum has no other guard against that, because a reorder still compiles.
#[test]
fn the_strength_lattice_is_ordered_weakest_to_strongest() {
    use AuthenticationStrength::{DeployKey, MultiFactor, SingleFactor, Token};
    assert!(DeployKey < Token);
    assert!(Token < SingleFactor);
    assert!(SingleFactor < MultiFactor);

    // And every pair is ordered, not merely the adjacent ones: a star-shaped
    // set of comparisons against one pivot would leave the non-adjacent pairs
    // unasserted.
    let ascending = [DeployKey, Token, SingleFactor, MultiFactor];
    for (index, weaker) in ascending.iter().enumerate() {
        for stronger in &ascending[index + 1..] {
            assert!(
                weaker < stronger,
                "{weaker} must rank below {stronger} for the rotation rule to mean anything"
            );
        }
    }
    assert_eq!(
        ascending.len(),
        4,
        "a new strength must be placed in this lattice deliberately, not appended by default"
    );
}

/// Rotation may not raise the authentication strength; it may lower it, and it
/// may keep it.
///
/// This is the acceptance's "strength binding" made structural. The three cases
/// are the whole rule: raising is refused, holding is permitted, lowering is
/// permitted.
#[test]
fn rotation_may_weaken_or_hold_the_strength_but_never_raise_it() {
    let established = session(AuthenticationStrength::SingleFactor);

    // REFUSED: rotation asking for more than was ever authenticated.
    assert_eq!(
        established.rotate(
            session_id(2),
            AuthenticationStrength::MultiFactor,
            EXPIRES_AT,
            0,
            RevocationEvidence::Live,
        ),
        Err(SessionRefusal::RotationWouldStrengthen {
            established: AuthenticationStrength::SingleFactor,
            requested: AuthenticationStrength::MultiFactor,
        })
    );

    // PERMITTED TWIN: the identical call holding the strength it already had.
    let held = established
        .rotate(
            session_id(2),
            AuthenticationStrength::SingleFactor,
            EXPIRES_AT,
            0,
            RevocationEvidence::Live,
        )
        .expect("holding the established strength is not a widening");
    assert_eq!(held.strength(), AuthenticationStrength::SingleFactor);
    assert_eq!(
        held.id(),
        session_id(2),
        "rotation moves onto the new handle"
    );

    // PERMITTED: voluntary de-escalation. A holder narrowing itself is the same
    // direction token attenuation allows.
    let weakened = established
        .rotate(
            session_id(3),
            AuthenticationStrength::DeployKey,
            EXPIRES_AT,
            0,
            RevocationEvidence::Live,
        )
        .expect("lowering strength is attenuation, not escalation");
    assert_eq!(weakened.strength(), AuthenticationStrength::DeployKey);
}

/// Rotation may not extend the deadline, and the boundary is pinned at the
/// exact flip.
///
/// `expires_at + 1` and `expires_at` are the two values where `>` and `>=`
/// differ, which is the comparison this rule turns on.
#[test]
fn rotation_cannot_extend_the_deadline_and_the_boundary_is_exact() {
    let established = session(AuthenticationStrength::Token);

    // REFUSED: one tick past the established deadline.
    assert_eq!(
        established.rotate(
            session_id(2),
            AuthenticationStrength::Token,
            EXPIRES_AT + 1,
            0,
            RevocationEvidence::Live,
        ),
        Err(SessionRefusal::RotationWouldExtend {
            expires_at: EXPIRES_AT,
            requested: EXPIRES_AT + 1,
        })
    );

    // PERMITTED TWIN: exactly the established deadline.
    assert_eq!(
        established
            .rotate(
                session_id(2),
                AuthenticationStrength::Token,
                EXPIRES_AT,
                0,
                RevocationEvidence::Live,
            )
            .expect("keeping the deadline is not an extension")
            .expires_at(),
        EXPIRES_AT
    );

    // PERMITTED: pulling the deadline in.
    assert_eq!(
        established
            .rotate(
                session_id(2),
                AuthenticationStrength::Token,
                EXPIRES_AT - 1,
                0,
                RevocationEvidence::Live,
            )
            .expect("shortening is attenuation")
            .expires_at(),
        EXPIRES_AT - 1
    );
}

/// Rotation carries the principal and repository over, so it cannot move a
/// session to another identity.
///
/// There is no parameter through which it could, which is the point — this test
/// pins that the absence is deliberate rather than an oversight that a later
/// signature change could quietly fill in.
#[test]
fn rotation_cannot_move_a_session_to_another_principal_or_repository() {
    let established = session(AuthenticationStrength::Token);
    let rotated = established
        .rotate(
            session_id(2),
            AuthenticationStrength::Token,
            EXPIRES_AT,
            0,
            RevocationEvidence::Live,
        )
        .expect("rotates");
    assert_eq!(rotated.principal(), established.principal());
    assert_eq!(rotated.repository(), established.repository());
}

/// A revoked session cannot be rotated, and a live one can.
///
/// Rotating a revoked session would let a revocation mint its own successor,
/// which is the one thing revocation must not permit.
#[test]
fn a_revoked_session_cannot_rotate_and_a_live_one_can() {
    let established = session(AuthenticationStrength::Token);

    assert_eq!(
        established.rotate(
            session_id(2),
            AuthenticationStrength::Token,
            EXPIRES_AT,
            0,
            RevocationEvidence::Revoked,
        ),
        Err(SessionRefusal::Revoked)
    );
    assert_eq!(
        established.rotate(
            session_id(2),
            AuthenticationStrength::Token,
            EXPIRES_AT,
            0,
            RevocationEvidence::NotChecked,
        ),
        Err(SessionRefusal::RevocationEvidenceRequired)
    );
    // The permitted twin: identical call, record consulted and live.
    assert!(
        established
            .rotate(
                session_id(2),
                AuthenticationStrength::Token,
                EXPIRES_AT,
                0,
                RevocationEvidence::Live,
            )
            .is_ok()
    );
}

/// An expired session cannot be rotated, and the boundary is pinned at the
/// exact flip.
///
/// Otherwise a holder who let a session lapse could revive it indefinitely and
/// the deadline would bound nothing.
#[test]
fn an_expired_session_cannot_be_rotated_back_to_life() {
    let established = session(AuthenticationStrength::Token);

    assert_eq!(
        established.rotate(
            session_id(2),
            AuthenticationStrength::Token,
            EXPIRES_AT,
            EXPIRES_AT,
            RevocationEvidence::Live,
        ),
        Err(SessionRefusal::Expired {
            expires_at: EXPIRES_AT,
            now: EXPIRES_AT,
        }),
        "now == expires_at is already expired"
    );
    // The permitted twin: one tick earlier.
    assert!(
        established
            .rotate(
                session_id(2),
                AuthenticationStrength::Token,
                EXPIRES_AT,
                EXPIRES_AT - 1,
                RevocationEvidence::Live,
            )
            .is_ok(),
        "expires_at - 1 is still live"
    );
}

/// Using a session checks repository, strength, revocation and expiry, and the
/// permit hands back the principal.
#[test]
fn authorization_checks_every_bound_and_returns_the_principal() {
    let established = session(AuthenticationStrength::SingleFactor);
    let repo = repository(0x11);

    // The permitted case.
    assert_eq!(
        established.authorize(
            repo,
            AuthenticationStrength::Token,
            0,
            RevocationEvidence::Live
        ),
        Ok(principal()),
        "a SingleFactor session satisfies a Token requirement"
    );

    // Wrong repository.
    assert_eq!(
        established.authorize(
            repository(0x22),
            AuthenticationStrength::Token,
            0,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::RepositoryMismatch)
    );

    // Not strong enough, and the refusal names both sides.
    assert_eq!(
        established.authorize(
            repo,
            AuthenticationStrength::MultiFactor,
            0,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::StrengthInsufficient {
            established: AuthenticationStrength::SingleFactor,
            required: AuthenticationStrength::MultiFactor,
        })
    );

    // Revocation is required for every use, not a high-impact subset: a session
    // IS the thing a request acts under.
    assert_eq!(
        established.authorize(
            repo,
            AuthenticationStrength::Token,
            0,
            RevocationEvidence::NotChecked
        ),
        Err(SessionRefusal::RevocationEvidenceRequired)
    );
    assert_eq!(
        established.authorize(
            repo,
            AuthenticationStrength::Token,
            0,
            RevocationEvidence::Revoked
        ),
        Err(SessionRefusal::Revoked)
    );

    // Expiry, at the exact flip, and its permitted twin.
    assert_eq!(
        established.authorize(
            repo,
            AuthenticationStrength::Token,
            EXPIRES_AT,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::Expired {
            expires_at: EXPIRES_AT,
            now: EXPIRES_AT,
        })
    );
    assert_eq!(
        established.authorize(
            repo,
            AuthenticationStrength::Token,
            EXPIRES_AT - 1,
            RevocationEvidence::Live
        ),
        Ok(principal())
    );
}

/// A revoked-and-expired session reports the revocation, not the expiry.
///
/// "It expired anyway" is how a revocation that never propagated escapes
/// notice, so the ordering is load-bearing and gets its own test rather than
/// being left to the order assertions happen to run in.
#[test]
fn a_revoked_and_expired_session_reports_the_revocation() {
    let established = session(AuthenticationStrength::Token);
    assert_eq!(
        established.authorize(
            repository(0x11),
            AuthenticationStrength::Token,
            EXPIRES_AT + 5,
            RevocationEvidence::Revoked,
        ),
        Err(SessionRefusal::Revoked)
    );
}

/// Every session survives encode/decode as itself.
#[test]
fn a_session_survives_the_roundtrip_as_itself() {
    for strength in [
        AuthenticationStrength::DeployKey,
        AuthenticationStrength::Token,
        AuthenticationStrength::SingleFactor,
        AuthenticationStrength::MultiFactor,
    ] {
        let established = session(strength);
        let bytes = encode_body(&established).expect("encodes");
        let decoded: Session = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded, established);
        assert_eq!(decoded.strength(), strength);
    }
}

/// An unknown strength tag on the wire is refused; the known one it replaced is
/// not.
///
/// The tag is located by diffing two frames that differ ONLY in the strength,
/// so both payloads are the same length and the divergence cannot be a length
/// prefix.
#[test]
fn an_unknown_strength_tag_on_the_wire_is_refused_and_a_known_one_is_not() {
    let token = encode_body(&session(AuthenticationStrength::Token)).expect("encodes");
    let multi = encode_body(&session(AuthenticationStrength::MultiFactor)).expect("encodes");
    assert_eq!(
        token.len(),
        multi.len(),
        "the two frames must be the same length for the locator to be sound"
    );
    let divergence = token
        .iter()
        .zip(multi.iter())
        .position(|(left, right)| left != right)
        .expect("the two frames differ at the strength tag");

    // The permitted twin: untampered, it decodes.
    assert!(decode_body::<Session>(&token, DecodeLimits::DEFAULT).is_ok());

    let mut tampered = token;
    tampered[divergence] = 0x7f;
    let refusal = decode_body::<Session>(&tampered, DecodeLimits::DEFAULT)
        .expect_err("an unknown strength tag is refused");
    assert!(
        matches!(
            refusal,
            CodecRefusal::VariantUnknown {
                field: "session.strength",
                ..
            }
        ),
        "expected an unknown-variant refusal naming the strength field, got {refusal:?}"
    );
}

/// A zero session id cannot be decoded.
///
/// Zero is the reserved not-a-value, so a zeroed buffer must not name a live
/// session.
#[test]
fn a_zero_session_id_on_the_wire_is_refused() {
    let one = encode_body(&Session::establish(
        session_id(1),
        principal(),
        repository(0x11),
        AuthenticationStrength::Token,
        EXPIRES_AT,
    ))
    .expect("encodes");
    let two = encode_body(&Session::establish(
        session_id(2),
        principal(),
        repository(0x11),
        AuthenticationStrength::Token,
        EXPIRES_AT,
    ))
    .expect("encodes");
    let divergence = one
        .iter()
        .zip(two.iter())
        .position(|(left, right)| left != right)
        .expect("the frames differ at the id");

    let mut tampered = one.clone();
    tampered[divergence] = 0;
    let refusal = decode_body::<Session>(&tampered, DecodeLimits::DEFAULT)
        .expect_err("a zero session id is refused");
    assert!(
        matches!(
            refusal,
            CodecRefusal::ValueUnrepresentable {
                field: "session.id",
                observed: 0,
                limit: 1,
            }
        ),
        "expected a zero-id refusal naming the id field, got {refusal:?}"
    );

    // The permitted twin: the same frame untampered decodes.
    assert!(decode_body::<Session>(&one, DecodeLimits::DEFAULT).is_ok());
}
