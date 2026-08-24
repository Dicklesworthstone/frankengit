//! Whether this crate's canonical bodies can receive canonical identities.
//!
//! # Why this file asserts a DEFECT rather than the behaviour we want
//!
//! Neither `frankengit/deploy-key-binding/v1` nor `frankengit/token-grant/v1`
//! is registered in `fgit-crypto`'s `DOMAIN_REGISTRY`, so `body_id` refuses
//! both with `IdentityDomainUnregistered`. That is a real defect: a credential
//! record exists so something else can point at it, and a body that cannot be
//! named by identity cannot be pointed at.
//!
//! It shipped in `f13638e` and `de1f5be` and survived 21 passing tests, because
//! every one of those exercises `encode_body`/`decode_body`, which never
//! consult the registry. The axis was untested, not merely broken.
//!
//! The registry lives in another crate and its export is a golden, so adding
//! the rows is the fgit-codec owner's call, not something to regenerate on the
//! way past. Until then the honest thing is to pin what is actually true, so
//! the gap is visible in the suite instead of invisible.
//!
//! # This is a tripwire, and it is meant to fail
//!
//! The moment the two rows land, `the_identity_bodies_cannot_yet_receive_
//! canonical_ids` FAILS. That is the point: it cannot be quietly outlived.
//! Whoever adds the rows should delete that test and keep
//! `a_registered_domain_can_receive_a_canonical_id` as the positive assertion,
//! extending it to cover both identity bodies.

use fgit_codec::CodecRefusal;
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::attest::body_id;
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, PullRequestNumber};
use fgit_identity::{DeployKeyBinding, DeployKeyScope, TokenGrant, TokenHandle, TokenOperation};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes, PrincipalId, RepositoryId};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn binding() -> DeployKeyBinding {
    DeployKeyBinding::register(
        RepositoryId::from_bytes([0x11; OPAQUE_ID_LEN]),
        digest(0x40),
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

/// The control: a body whose domain IS registered receives an id.
///
/// Without this, the refusals below would be consistent with `body_id` being
/// broken for everything, or with `CryptoBodyIdentity` being misused here. This
/// pins that the difference is the registry row and nothing else.
#[test]
fn a_registered_domain_can_receive_a_canonical_id() {
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

/// KNOWN DEFECT, pinned so it is visible. Delete this when the rows land.
#[test]
fn the_identity_bodies_cannot_yet_receive_canonical_ids() {
    for (what, refusal) in [
        (
            "frankengit/deploy-key-binding/v1",
            body_id(&CryptoBodyIdentity, &binding()).expect_err("unregistered today"),
        ),
        (
            "frankengit/token-grant/v1",
            body_id(&CryptoBodyIdentity, &token()).expect_err("unregistered today"),
        ),
    ] {
        match refusal {
            CodecRefusal::IdentityDomainUnregistered { ref domain } => {
                assert_eq!(
                    &**domain, what,
                    "the refusal must name the domain that is missing a row"
                );
            }
            other => panic!(
                "{what}: expected IdentityDomainUnregistered, got {other:?}. If this body now \
                 identifies, the registry rows have landed -- delete this test and extend \
                 a_registered_domain_can_receive_a_canonical_id to cover both bodies."
            ),
        }
    }
}
