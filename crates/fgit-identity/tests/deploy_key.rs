//! Deploy-key registration: binding, scope, and canonical-encoding tests.
//!
//! The load-bearing property is the BINDING. A deploy key that answers "yes" on
//! a repository it was not registered against is not a narrower credential than
//! a password, it is a wider one, because it looks scoped while being global.
//! Every permit test therefore pairs the refusal with its near-identical
//! permitted twin, so a passing suite cannot be satisfied by a predicate that
//! simply always refuses.

use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_identity::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes, RepositoryId};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn repository(tag: u8) -> RepositoryId {
    RepositoryId::from_bytes([tag; OPAQUE_ID_LEN])
}

/// A key bound to one repository does not authorise another, and the twin does.
#[test]
fn a_deploy_key_does_not_permit_the_repository_it_is_not_bound_to() {
    let bound = repository(0x11);
    let other = repository(0x22);
    let binding = DeployKeyBinding::register(bound, digest(0x40), &[DeployKeyScope::Write])
        .expect("a single-scope registration is admissible");

    // The refusal: identical scope, wrong repository.
    assert!(
        !binding.permits(other, DeployKeyScope::Write),
        "a Write grant on {bound} must not authorise Write on {other}"
    );
    // The permitted twin: same scope, the repository it was bound to.
    assert!(
        binding.permits(bound, DeployKeyScope::Write),
        "the binding must authorise the repository it names"
    );
    assert_eq!(binding.repository_id(), bound);
}

/// `Write` does not confer `Read`. No capability is implied by another.
#[test]
fn write_does_not_imply_read_and_read_does_not_imply_write() {
    let repo = repository(0x11);
    let writer = DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Write])
        .expect("registers");
    assert!(writer.permits(repo, DeployKeyScope::Write));
    assert!(
        !writer.permits(repo, DeployKeyScope::Read),
        "Write must not silently confer Read"
    );

    let reader =
        DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Read]).expect("registers");
    assert!(reader.permits(repo, DeployKeyScope::Read));
    assert!(
        !reader.permits(repo, DeployKeyScope::Write),
        "Read must not silently confer Write"
    );

    // And the both-scopes case really does grant both, so the two assertions
    // above are about implication rather than about the predicate being broken.
    let both = DeployKeyBinding::register(
        repo,
        digest(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");
    assert!(both.permits(repo, DeployKeyScope::Read));
    assert!(both.permits(repo, DeployKeyScope::Write));
}

/// An empty grant is refused; a one-scope grant is not.
#[test]
fn a_registration_granting_nothing_is_refused_and_a_single_scope_is_not() {
    let repo = repository(0x11);
    assert_eq!(
        DeployKeyBinding::register(repo, digest(0x40), &[]),
        Err(DeployKeyRefusal::NoScopes)
    );
    assert!(DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Read]).is_ok());
}

/// Duplicate scopes collapse, so equal grants have equal bytes and equal identity.
#[test]
fn duplicate_scopes_collapse_to_one_canonical_encoding() {
    let repo = repository(0x11);
    let once =
        DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Read]).expect("registers");
    let twice = DeployKeyBinding::register(
        repo,
        digest(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Read],
    )
    .expect("registers");
    assert_eq!(once, twice);
    assert_eq!(once.scopes(), [DeployKeyScope::Read]);
    assert_eq!(
        encode_body(&once).expect("encodes"),
        encode_body(&twice).expect("encodes"),
        "two grants of the same thing must have the same canonical bytes"
    );

    // Order of presentation must not change the bytes either.
    let forward = DeployKeyBinding::register(
        repo,
        digest(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");
    let reversed = DeployKeyBinding::register(
        repo,
        digest(0x40),
        &[DeployKeyScope::Write, DeployKeyScope::Read],
    )
    .expect("registers");
    assert_eq!(
        encode_body(&forward).expect("encodes"),
        encode_body(&reversed).expect("encodes"),
    );
}

/// Every binding survives encode/decode as itself.
#[test]
fn a_binding_survives_the_roundtrip_as_itself() {
    let grants = [
        vec![DeployKeyScope::Read],
        vec![DeployKeyScope::Write],
        vec![DeployKeyScope::Read, DeployKeyScope::Write],
    ];
    for scopes in grants {
        let binding =
            DeployKeyBinding::register(repository(0x11), digest(0x40), &scopes).expect("registers");
        let bytes = encode_body(&binding).expect("encodes");
        let decoded: DeployKeyBinding =
            decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded, binding);
        assert_eq!(decoded.scopes(), binding.scopes());
        assert_eq!(decoded.key(), binding.key());
    }
}

/// An unknown scope tag on the wire is refused; the known one it replaced is not.
///
/// The tag is located by diffing two frames that differ ONLY in the scope, so
/// both payloads are the same length. Diffing against a frame with a different
/// number of scopes would first diverge at the collection's count prefix rather
/// than at the tag.
#[test]
fn an_unknown_scope_tag_on_the_wire_is_refused_and_a_known_one_is_not() {
    let repo = repository(0x11);
    let read =
        DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Read]).expect("registers");
    let write = DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Write])
        .expect("registers");
    let read_bytes = encode_body(&read).expect("encodes");
    let write_bytes = encode_body(&write).expect("encodes");
    assert_eq!(
        read_bytes.len(),
        write_bytes.len(),
        "the two frames must be the same length for the locator to be sound"
    );

    let divergence = read_bytes
        .iter()
        .zip(write_bytes.iter())
        .position(|(left, right)| left != right)
        .expect("the two frames differ at the scope tag");

    // The permitted twin: untampered, it decodes.
    assert!(decode_body::<DeployKeyBinding>(&read_bytes, DecodeLimits::DEFAULT).is_ok());

    // The refusal: a tag this build does not implement, at that exact byte.
    let mut tampered = read_bytes.clone();
    tampered[divergence] = 0x7f;
    let refusal = decode_body::<DeployKeyBinding>(&tampered, DecodeLimits::DEFAULT)
        .expect_err("an unknown scope tag is refused");
    assert!(
        matches!(
            refusal,
            CodecRefusal::VariantUnknown {
                field: "deploy_key.scope",
                ..
            }
        ),
        "expected an unknown-variant refusal naming the scope field, got {refusal:?}"
    );
}

/// The wire cannot mint a binding that permits nothing.
///
/// `read_payload` routes through the same checked constructor the public API
/// uses, so the no-empty-grant invariant holds for decoded values too.
///
/// LIMIT, stated rather than implied: tampering the count to zero leaves the
/// element bytes in place, so the refusal that actually fires may be a framing
/// one rather than the empty-grant one. What this test pins is the property
/// that matters -- no byte sequence reachable by this tamper yields a
/// scope-less binding -- not which refusal names it. A frame that is
/// well-formed AND empty is not constructible from a valid encoding by
/// changing bytes alone, because the payload length prefix would also have to
/// be rewritten.
#[test]
fn a_scopeless_binding_cannot_be_decoded() {
    let repo = repository(0x11);
    let one =
        DeployKeyBinding::register(repo, digest(0x40), &[DeployKeyScope::Read]).expect("registers");
    let two = DeployKeyBinding::register(
        repo,
        digest(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");
    let one_bytes = encode_body(&one).expect("encodes");
    let two_bytes = encode_body(&two).expect("encodes");

    // The count prefix is the first place a one-scope and a two-scope frame
    // diverge: everything before it (repository id, key digest) is identical.
    let count_at = one_bytes
        .iter()
        .zip(two_bytes.iter())
        .position(|(left, right)| left != right)
        .expect("the frames differ at the scope count");

    let mut tampered = one_bytes.clone();
    tampered[count_at] = 0;
    assert!(
        decode_body::<DeployKeyBinding>(&tampered, DecodeLimits::DEFAULT).is_err(),
        "a frame claiming zero scopes must not decode into a binding"
    );

    // The permitted twin: the same frame untampered decodes and grants exactly
    // what it recorded, so the refusal above is about the tamper.
    let decoded: DeployKeyBinding =
        decode_body(&one_bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded.scopes(), [DeployKeyScope::Read]);
}
