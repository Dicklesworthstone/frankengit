//! Whether this crate's canonical bodies can receive canonical identities.
//!
//! # Why this file exists
//!
//! A credential record exists so something else can point at it, and a body
//! that cannot be named by identity cannot be pointed at. `body_id` refuses any
//! body whose domain is absent from `fgit-crypto`'s `DOMAIN_REGISTRY`, so
//! "defines a `CanonicalBody`" and "can be named" are two different facts.
//!
//! They came apart once. `frankengit/deploy-key-binding/v1` and
//! `frankengit/token-grant/v1` shipped in `f13638e` and `de1f5be` with no
//! registry row, and 21 passing tests said nothing, because every one of them
//! exercised `encode_body`/`decode_body` — neither of which consults the
//! registry. The axis was untested, not merely broken. `33d4d36` pinned the gap
//! as a deliberate tripwire that asserted the refusals, with the instruction
//! that whoever added the rows should delete it and assert the opposite.
//!
//! The rows are in (registry ids 50, 51 and 52). This file is that replacement,
//! and it asserts strictly more than the tripwire did: every canonical body
//! this crate defines identifies, and `body_id` is still capable of refusing.
//!
//! # The negative twin is the load-bearing half
//!
//! Four `is_ok()` assertions would also pass if `body_id` had been changed to
//! compute an identity for anything at all — which is exactly the failure the
//! registry exists to prevent. `an_unregistered_domain_is_still_refused` plants
//! a body under a domain that is deliberately absent from the registry and
//! requires the refusal, so the positive results above it mean "these domains
//! are registered" rather than "nothing is ever refused".

use fgit_codec::attest::body_id;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, CryptoBodyIdentity, Decoder, Encoder};
use fgit_crypto::{PUBLIC_KEY_BYTES, VerifyingKey};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, PullRequestNumber};
use fgit_identity::{
    AuthenticationStrength, DeployKeyBinding, DeployKeyScope, Session, SessionId, TokenGrant,
    TokenHandle, TokenOperation,
};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{DomainTag, PrincipalId, RepositoryId, SchemaFamily};

fn binding() -> DeployKeyBinding {
    DeployKeyBinding::register(
        RepositoryId::from_bytes([0x11; OPAQUE_ID_LEN]),
        PrincipalId::from_bytes([0x33; OPAQUE_ID_LEN]),
        VerifyingKey::from_bytes([0x40; PUBLIC_KEY_BYTES]),
        &[DeployKeyScope::Read],
    )
    .expect("registers")
}

fn token() -> TokenGrant {
    TokenGrant::issue(
        TokenHandle::try_new(1).expect("nonzero"),
        PrincipalId::from_bytes([0x33; OPAQUE_ID_LEN]),
        b"fgit-node/receive-pack".to_vec(),
        RepositoryId::from_bytes([0x11; OPAQUE_ID_LEN]),
        &[TokenOperation::Read],
        10,
        1_000,
    )
    .expect("issues")
}

fn session() -> Session {
    Session::establish(
        SessionId::try_new(1).expect("nonzero"),
        PrincipalId::from_bytes([0x33; OPAQUE_ID_LEN]),
        RepositoryId::from_bytes([0x11; OPAQUE_ID_LEN]),
        AuthenticationStrength::Token,
        1_000,
    )
}

/// A body under a domain that is deliberately NOT in the registry.
///
/// The tag is nonsense on purpose. If someone ever registers it, this test
/// fails loudly rather than quietly becoming vacuous — which is the failure
/// mode a planted negative has to be protected against.
struct UnregisteredBody;

impl CanonicalBody for UnregisteredBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/deliberately-unregistered/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("deliberately-unregistered");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(0_u64);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        input.read_scalar::<u64>("unregistered.value")?;
        Ok(Self)
    }
}

/// The control: a body owned by another crate, whose domain has been registered
/// since long before this bead.
///
/// Without it, a refusal below could be read as "something about this crate's
/// encodings" rather than "that domain has no row". This pins that the
/// difference is the registry row and nothing else.
#[test]
fn a_registered_domain_from_another_crate_can_receive_a_canonical_id() {
    let event = ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(7).expect("nonzero")),
        version: AggregateVersion::try_new(1).expect("nonzero"),
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
    };
    assert!(
        body_id(&CryptoBodyIdentity, &event).is_ok(),
        "frankengit/forge-event/v1 is registry row 12 and must identify"
    );
}

/// Every canonical body this crate defines can be named by identity.
///
/// This is the assertion the tripwire in `33d4d36` asked its remover to write.
/// It covers all three rather than the two that were originally missing,
/// because the property is "this crate does not define a body it cannot name",
/// not "those two specific bodies were fixed".
#[test]
fn every_canonical_body_in_this_crate_can_receive_a_canonical_id() {
    assert!(
        body_id(&CryptoBodyIdentity, &binding()).is_ok(),
        "frankengit/deploy-key-binding/v1 is registry row 50 and must identify"
    );
    assert!(
        body_id(&CryptoBodyIdentity, &token()).is_ok(),
        "frankengit/token-grant/v1 is registry row 51 and must identify"
    );
    assert!(
        body_id(&CryptoBodyIdentity, &session()).is_ok(),
        "frankengit/session/v1 is registry row 52 and must identify"
    );
}

/// The identities are DISTINCT across bodies, pairwise.
///
/// Three bodies that all "identify" would also satisfy the test above if they
/// collapsed onto one value. Domain separation is the property that makes an
/// identity mean which body it names, so it is asserted rather than assumed —
/// and every pair is compared, not each against one pivot, because N-1
/// comparisons against a single pivot leave the other pairs unasserted.
#[test]
fn the_three_bodies_receive_pairwise_distinct_identities() {
    let identities = [
        (
            "deploy-key-binding",
            body_id(&CryptoBodyIdentity, &binding()),
        ),
        ("token-grant", body_id(&CryptoBodyIdentity, &token())),
        ("session", body_id(&CryptoBodyIdentity, &session())),
    ]
    .map(|(name, result)| (name, result.expect("every domain above is registered")));

    for (index, (left_name, left)) in identities.iter().enumerate() {
        for (right_name, right) in &identities[index + 1..] {
            assert_ne!(
                left, right,
                "{left_name} and {right_name} must not share an identity"
            );
        }
    }
}

/// `body_id` still refuses a domain the registry does not know.
///
/// The negative twin. Without it, the positive assertions above are consistent
/// with `body_id` having been changed to compute an identity for anything —
/// the precise failure the registry exists to prevent, since an identity under
/// an unregistered domain is one nothing else could verify.
#[test]
fn an_unregistered_domain_is_still_refused() {
    let refusal =
        body_id(&CryptoBodyIdentity, &UnregisteredBody).expect_err("the domain has no row");
    match refusal {
        CodecRefusal::IdentityDomainUnregistered { ref domain } => {
            assert_eq!(
                &**domain, "frankengit/deliberately-unregistered/v1",
                "the refusal must name the domain that is missing a row"
            );
        }
        other => panic!(
            "expected IdentityDomainUnregistered, got {other:?}. If this body now identifies, \
             someone registered the deliberately-unregistered domain and this test has become \
             vacuous -- pick a new unregistered tag rather than deleting the check."
        ),
    }
}
