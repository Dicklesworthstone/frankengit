//! Token lifecycle: audience confusion, revocation propagation, delegation
//! narrowing, and the exact boundaries of expiry and budget.
//!
//! Every refusal is paired with its near-identical permitted twin. A suite of
//! refusals alone is satisfied by a predicate that always says no, which would
//! pass while authorising nothing — so each test also proves the permitted case
//! still works.

use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_identity::{RevocationEvidence, TokenGrant, TokenHandle, TokenOperation, TokenRefusal};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{PrincipalId, RepositoryId};

const AUDIENCE: &[u8] = b"fgit-node/receive-pack";
const OTHER_AUDIENCE: &[u8] = b"fgit-node/upload-pack";
const EXPIRES_AT: u64 = 1_000;
const BUDGET: u64 = 10;

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x33; OPAQUE_ID_LEN])
}

fn repository(tag: u8) -> RepositoryId {
    RepositoryId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn handle(value: u64) -> TokenHandle {
    TokenHandle::try_new(value).expect("nonzero handle")
}

fn grant(operations: &[TokenOperation]) -> TokenGrant {
    TokenGrant::issue(
        handle(1),
        principal(),
        AUDIENCE,
        repository(0x11),
        operations,
        BUDGET,
        EXPIRES_AT,
    )
    .expect("issues")
}

/// A token minted for one audience is refused when replayed against another.
#[test]
fn a_token_presented_to_the_wrong_audience_is_refused_and_the_right_one_is_not() {
    let token = grant(&[TokenOperation::Read]);
    assert_eq!(
        token.authorize(
            OTHER_AUDIENCE,
            repository(0x11),
            TokenOperation::Read,
            1,
            0,
            RevocationEvidence::Live,
        ),
        Err(TokenRefusal::AudienceMismatch)
    );
    assert!(
        token
            .authorize(
                AUDIENCE,
                repository(0x11),
                TokenOperation::Read,
                1,
                0,
                RevocationEvidence::Live,
            )
            .is_ok()
    );
}

/// A token confined to one repository does not authorise another.
#[test]
fn a_token_does_not_authorise_the_repository_it_is_not_confined_to() {
    let token = grant(&[TokenOperation::Read]);
    assert_eq!(
        token.authorize(
            AUDIENCE,
            repository(0x22),
            TokenOperation::Read,
            1,
            0,
            RevocationEvidence::Live,
        ),
        Err(TokenRefusal::RepositoryMismatch)
    );
    assert!(
        token
            .authorize(
                AUDIENCE,
                repository(0x11),
                TokenOperation::Read,
                1,
                0,
                RevocationEvidence::Live,
            )
            .is_ok()
    );
}

/// No operation is implied by another.
#[test]
fn no_token_operation_implies_another() {
    let reader = grant(&[TokenOperation::Read]);
    for denied in [TokenOperation::Write, TokenOperation::Administer] {
        assert_eq!(
            reader.authorize(
                AUDIENCE,
                repository(0x11),
                denied,
                1,
                0,
                RevocationEvidence::Live,
            ),
            Err(TokenRefusal::OperationNotGranted { requested: denied })
        );
    }
    let admin = grant(&[TokenOperation::Administer]);
    assert_eq!(
        admin.authorize(
            AUDIENCE,
            repository(0x11),
            TokenOperation::Write,
            1,
            0,
            RevocationEvidence::Live,
        ),
        Err(TokenRefusal::OperationNotGranted {
            requested: TokenOperation::Write
        })
    );
    // The permitted twin: each grants exactly what it names.
    assert!(
        admin
            .authorize(
                AUDIENCE,
                repository(0x11),
                TokenOperation::Administer,
                1,
                0,
                RevocationEvidence::Live,
            )
            .is_ok()
    );
}

/// A revoked handle fails the next use, and a live one does not.
#[test]
fn a_revoked_handle_fails_the_next_use() {
    let token = grant(&[TokenOperation::Write]);
    assert_eq!(
        token.authorize(
            AUDIENCE,
            repository(0x11),
            TokenOperation::Write,
            1,
            0,
            RevocationEvidence::Revoked,
        ),
        Err(TokenRefusal::Revoked)
    );
    assert!(
        token
            .authorize(
                AUDIENCE,
                repository(0x11),
                TokenOperation::Write,
                1,
                0,
                RevocationEvidence::Live,
            )
            .is_ok()
    );
}

/// High-impact operations cannot be authorised on expiry alone.
///
/// This is the structural form of "no TTL-only revocation for high-impact
/// scopes". The low-impact twin is included because the point is a LINE, not a
/// blanket: if `NotChecked` were refused for everything the test would pass
/// while saying nothing about where the obligation actually falls.
#[test]
fn high_impact_operations_refuse_without_revocation_evidence_and_read_does_not() {
    let token = grant(&[
        TokenOperation::Read,
        TokenOperation::Write,
        TokenOperation::Administer,
    ]);
    for high in [TokenOperation::Write, TokenOperation::Administer] {
        assert_eq!(
            token.authorize(
                AUDIENCE,
                repository(0x11),
                high,
                1,
                0,
                RevocationEvidence::NotChecked,
            ),
            Err(TokenRefusal::RevocationEvidenceRequired { requested: high }),
            "{high} must not be authorised without the revocation record"
        );
        // And with evidence, the same call succeeds — so the refusal is about
        // the missing evidence, not about the operation.
        assert!(
            token
                .authorize(
                    AUDIENCE,
                    repository(0x11),
                    high,
                    1,
                    0,
                    RevocationEvidence::Live,
                )
                .is_ok()
        );
    }
    assert!(
        token
            .authorize(
                AUDIENCE,
                repository(0x11),
                TokenOperation::Read,
                1,
                0,
                RevocationEvidence::NotChecked,
            )
            .is_ok(),
        "a read may proceed on expiry alone; that is where the line is drawn"
    );
}

/// A revoked token that has also expired reports the revocation.
///
/// "It expired anyway" is exactly how a revocation that never propagated
/// escapes notice, so the order of these checks is load-bearing rather than
/// incidental.
#[test]
fn a_revoked_and_expired_token_reports_the_revocation_not_the_expiry() {
    let token = grant(&[TokenOperation::Write]);
    assert_eq!(
        token.authorize(
            AUDIENCE,
            repository(0x11),
            TokenOperation::Write,
            EXPIRES_AT + 500,
            0,
            RevocationEvidence::Revoked,
        ),
        Err(TokenRefusal::Revoked)
    );
}

/// Expiry is exclusive at the boundary: `now == expires_at` is expired.
#[test]
fn expiry_is_checked_at_its_exact_boundary() {
    let token = grant(&[TokenOperation::Read]);
    let call = |now| {
        token.authorize(
            AUDIENCE,
            repository(0x11),
            TokenOperation::Read,
            now,
            0,
            RevocationEvidence::Live,
        )
    };
    assert!(call(EXPIRES_AT - 1).is_ok(), "the last usable instant");
    assert_eq!(
        call(EXPIRES_AT),
        Err(TokenRefusal::Expired {
            expires_at: EXPIRES_AT,
            now: EXPIRES_AT
        }),
        "the expiry instant itself is expired"
    );
}

/// Budget is exhausted at `spent == budget`, not one use later.
#[test]
fn budget_is_checked_at_its_exact_boundary() {
    let token = grant(&[TokenOperation::Read]);
    let call = |spent| {
        token.authorize(
            AUDIENCE,
            repository(0x11),
            TokenOperation::Read,
            1,
            spent,
            RevocationEvidence::Live,
        )
    };
    assert!(call(BUDGET - 1).is_ok(), "the last granted use");
    assert_eq!(
        call(BUDGET),
        Err(TokenRefusal::BudgetExhausted {
            spent: BUDGET,
            budget: BUDGET
        })
    );
}

/// Delegation may only narrow, on every axis.
#[test]
fn delegation_narrows_and_never_widens() {
    let parent = grant(&[TokenOperation::Read, TokenOperation::Write]);

    // Narrowing on every axis at once is permitted.
    let child = parent
        .attenuate(
            handle(2),
            &[TokenOperation::Read],
            BUDGET - 1,
            EXPIRES_AT - 1,
        )
        .expect("a strictly narrower delegate is admissible");
    assert_eq!(child.operations(), [TokenOperation::Read]);
    assert_eq!(child.budget(), BUDGET - 1);
    assert_eq!(child.expires_at(), EXPIRES_AT - 1);
    assert_eq!(child.handle(), handle(2), "a delegate gets its own handle");

    // Widening any single axis is refused, with the others held at the parent's
    // values so each failure is attributable to one axis.
    assert_eq!(
        parent.attenuate(handle(3), &[TokenOperation::Administer], BUDGET, EXPIRES_AT),
        Err(TokenRefusal::AttenuationWouldWiden { axis: "operations" })
    );
    assert_eq!(
        parent.attenuate(handle(3), &[TokenOperation::Read], BUDGET + 1, EXPIRES_AT),
        Err(TokenRefusal::AttenuationWouldWiden { axis: "budget" })
    );
    assert_eq!(
        parent.attenuate(handle(3), &[TokenOperation::Read], BUDGET, EXPIRES_AT + 1),
        Err(TokenRefusal::AttenuationWouldWiden { axis: "expiry" })
    );

    // Equality is not widening: a delegate may hold exactly the parent's bounds.
    assert!(
        parent
            .attenuate(
                handle(4),
                &[TokenOperation::Read, TokenOperation::Write],
                BUDGET,
                EXPIRES_AT
            )
            .is_ok()
    );
}

/// A delegate that would grant nothing is refused.
#[test]
fn a_delegate_granting_nothing_is_refused() {
    let parent = grant(&[TokenOperation::Read]);
    assert_eq!(
        parent.attenuate(handle(2), &[], BUDGET, EXPIRES_AT),
        Err(TokenRefusal::NoOperations)
    );
    assert!(
        parent
            .attenuate(handle(2), &[TokenOperation::Read], BUDGET, EXPIRES_AT)
            .is_ok()
    );
}

/// Issuing a token that grants nothing is refused.
#[test]
fn a_token_granting_nothing_is_refused_and_one_operation_is_not() {
    let issue = |operations: &[TokenOperation]| {
        TokenGrant::issue(
            handle(1),
            principal(),
            AUDIENCE,
            repository(0x11),
            operations,
            BUDGET,
            EXPIRES_AT,
        )
    };
    assert_eq!(issue(&[]), Err(TokenRefusal::NoOperations));
    assert!(issue(&[TokenOperation::Read]).is_ok());
}

/// A grant survives encode/decode as itself, and duplicates collapse.
#[test]
fn a_grant_survives_the_roundtrip_and_duplicate_operations_collapse() {
    let token = grant(&[
        TokenOperation::Write,
        TokenOperation::Read,
        TokenOperation::Read,
    ]);
    assert_eq!(
        token.operations(),
        [TokenOperation::Read, TokenOperation::Write],
        "operations are sorted and deduplicated"
    );
    let bytes = encode_body(&token).expect("encodes");
    let decoded: TokenGrant = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded, token);
    assert_eq!(decoded.audience(), AUDIENCE);
    assert_eq!(decoded.principal(), principal());
}

/// An unknown operation tag on the wire is refused; the tag it replaced is not.
#[test]
fn an_unknown_operation_tag_on_the_wire_is_refused_and_a_known_one_is_not() {
    let read = grant(&[TokenOperation::Read]);
    let write = grant(&[TokenOperation::Write]);
    let read_bytes = encode_body(&read).expect("encodes");
    let write_bytes = encode_body(&write).expect("encodes");
    assert_eq!(
        read_bytes.len(),
        write_bytes.len(),
        "same-length frames keep the locator sound"
    );

    assert!(decode_body::<TokenGrant>(&read_bytes, DecodeLimits::DEFAULT).is_ok());

    let divergence = read_bytes
        .iter()
        .zip(write_bytes.iter())
        .position(|(left, right)| left != right)
        .expect("the frames differ at the operation tag");
    let mut tampered = read_bytes.clone();
    tampered[divergence] = 0x6b;
    let refusal = decode_body::<TokenGrant>(&tampered, DecodeLimits::DEFAULT)
        .expect_err("an unknown operation tag is refused");
    assert!(
        matches!(
            refusal,
            CodecRefusal::VariantUnknown {
                field: "token.operation",
                ..
            }
        ),
        "expected an unknown-variant refusal naming the operation field, got {refusal:?}"
    );
}

/// A zero handle on the wire is refused: zero is the reserved not-a-value.
#[test]
fn a_zero_handle_on_the_wire_is_refused() {
    let token = grant(&[TokenOperation::Read]);
    let bytes = encode_body(&token).expect("encodes");
    let position = bytes
        .windows(8)
        .position(|w| w == 1_u64.to_be_bytes())
        .expect("the handle is present as a big-endian one");
    let mut tampered = bytes.clone();
    tampered[position..position + 8].copy_from_slice(&0_u64.to_be_bytes());
    assert!(
        decode_body::<TokenGrant>(&tampered, DecodeLimits::DEFAULT).is_err(),
        "a zero handle must not decode into a live token"
    );
    assert!(decode_body::<TokenGrant>(&bytes, DecodeLimits::DEFAULT).is_ok());
}
