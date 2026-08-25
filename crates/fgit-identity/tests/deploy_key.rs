//! Deploy-key registration: binding, scope, and canonical-encoding tests.
//!
//! The load-bearing property is the BINDING. A deploy key that answers "yes" on
//! a repository it was not registered against is not a narrower credential than
//! a password, it is a wider one, because it looks scoped while being global.
//! Every permit test therefore pairs the refusal with its near-identical
//! permitted twin, so a passing suite cannot be satisfied by a predicate that
//! simply always refuses.

use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_crypto::{ED25519_CODE_POINT, PUBLIC_KEY_BYTES, VerifyingKey};
use fgit_identity::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope, RevocationEvidence};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{PrincipalId, RepositoryId};

fn key(tag: u8) -> VerifyingKey {
    VerifyingKey::from_bytes([tag; PUBLIC_KEY_BYTES])
}

fn repository(tag: u8) -> RepositoryId {
    RepositoryId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x33; OPAQUE_ID_LEN])
}

/// A key bound to one repository does not authorise another, and the twin does.
#[test]
fn a_deploy_key_does_not_permit_the_repository_it_is_not_bound_to() {
    let bound = repository(0x11);
    let other = repository(0x22);
    let binding =
        DeployKeyBinding::register(bound, principal(), key(0x40), &[DeployKeyScope::Write])
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
    let writer = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Write])
        .expect("registers");
    assert!(writer.permits(repo, DeployKeyScope::Write));
    assert!(
        !writer.permits(repo, DeployKeyScope::Read),
        "Write must not silently confer Read"
    );

    let reader = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
        .expect("registers");
    assert!(reader.permits(repo, DeployKeyScope::Read));
    assert!(
        !reader.permits(repo, DeployKeyScope::Write),
        "Read must not silently confer Write"
    );

    // And the both-scopes case really does grant both, so the two assertions
    // above are about implication rather than about the predicate being broken.
    let both = DeployKeyBinding::register(
        repo,
        principal(),
        key(0x40),
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
        DeployKeyBinding::register(repo, principal(), key(0x40), &[]),
        Err(DeployKeyRefusal::NoScopes)
    );
    assert!(
        DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read]).is_ok()
    );
}

/// Duplicate scopes collapse, so equal grants have equal bytes and equal identity.
#[test]
fn duplicate_scopes_collapse_to_one_canonical_encoding() {
    let repo = repository(0x11);
    let once = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
        .expect("registers");
    let twice = DeployKeyBinding::register(
        repo,
        principal(),
        key(0x40),
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
        principal(),
        key(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");
    let reversed = DeployKeyBinding::register(
        repo,
        principal(),
        key(0x40),
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
        let binding = DeployKeyBinding::register(repository(0x11), principal(), key(0x40), &scopes)
            .expect("registers");
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
    let read = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
        .expect("registers");
    let write = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Write])
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
    let one = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
        .expect("registers");
    let two = DeployKeyBinding::register(
        repo,
        principal(),
        key(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");
    let one_bytes = encode_body(&one).expect("encodes");
    let two_bytes = encode_body(&two).expect("encodes");

    // The count prefix is the first place a one-scope and a two-scope frame
    // diverge: everything before it (repository id, principal, scheme, key)
    // is identical.
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

/// A deploy key resolves to the principal it speaks as, and a different key
/// presented against the same binding does not.
///
/// This is the property the authenticated transport (`fg047`/`hh37`) depends
/// on: SSH proves the peer controls a public key, and this is the step that
/// turns that key into a `PrincipalId` the rest of the system authorises
/// against. Without the mismatch half, a binding that returned its principal
/// for any key at all would pass.
#[test]
fn a_deploy_key_authorizes_as_the_principal_it_speaks_as_and_a_foreign_key_does_not() {
    let repo = repository(0x11);
    let binding = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
        .expect("registers");

    // The permitted case: the key that was registered.
    assert_eq!(
        binding.authorize(
            &key(0x40),
            repo,
            DeployKeyScope::Read,
            RevocationEvidence::Live
        ),
        Ok(principal()),
        "the registered key must authorize as the principal the binding names"
    );
    assert_eq!(binding.principal(), principal());

    // The refusal: a different key, everything else identical.
    assert_eq!(
        binding.authorize(
            &key(0x41),
            repo,
            DeployKeyScope::Read,
            RevocationEvidence::Live
        ),
        Err(DeployKeyRefusal::KeyMismatch),
        "a key the binding did not register must not authorize as its principal"
    );

    // And the repository half is still checked at the authorize entry point,
    // not only in `permits`.
    assert_eq!(
        binding.authorize(
            &key(0x40),
            repository(0x22),
            DeployKeyScope::Read,
            RevocationEvidence::Live
        ),
        Err(DeployKeyRefusal::RepositoryMismatch)
    );
    assert_eq!(
        binding.authorize(
            &key(0x40),
            repo,
            DeployKeyScope::Write,
            RevocationEvidence::Live
        ),
        Err(DeployKeyRefusal::ScopeNotGranted {
            requested: DeployKeyScope::Write
        })
    );
}

/// receive-pack cannot be authorised without revocation evidence; upload-pack
/// can.
///
/// This is the structural form of "no TTL-only revocation for high-impact
/// scopes". Refusing `NotChecked` for BOTH scopes would also pass a test that
/// only checked the refusal, while saying nothing about where the obligation
/// falls -- so both sides are pinned.
#[test]
fn receive_pack_refuses_without_revocation_evidence_and_upload_pack_does_not() {
    let repo = repository(0x11);
    let binding = DeployKeyBinding::register(
        repo,
        principal(),
        key(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");

    // High-impact: the answer is a refusal to answer, not a pass.
    assert_eq!(
        binding.authorize(
            &key(0x40),
            repo,
            DeployKeyScope::Write,
            RevocationEvidence::NotChecked
        ),
        Err(DeployKeyRefusal::RevocationEvidenceRequired {
            requested: DeployKeyScope::Write
        })
    );
    // The permitted twin on the same binding: the same unchecked evidence, a
    // scope that does not demand it.
    assert_eq!(
        binding.authorize(
            &key(0x40),
            repo,
            DeployKeyScope::Read,
            RevocationEvidence::NotChecked
        ),
        Ok(principal())
    );
    // And with the record actually consulted, the high-impact scope proceeds --
    // so the refusal above is about the missing evidence and not about Write.
    assert_eq!(
        binding.authorize(
            &key(0x40),
            repo,
            DeployKeyScope::Write,
            RevocationEvidence::Live
        ),
        Ok(principal())
    );
}

/// A revoked binding fails the next authority-relevant use, on every scope.
///
/// Including the `Read` case is the point: revocation is not a high-impact-only
/// mechanism, it is the answer whenever the record was consulted and said so.
#[test]
fn a_revoked_binding_fails_the_next_use_on_every_scope_it_holds() {
    let repo = repository(0x11);
    let binding = DeployKeyBinding::register(
        repo,
        principal(),
        key(0x40),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("registers");

    for scope in [DeployKeyScope::Read, DeployKeyScope::Write] {
        assert_eq!(
            binding.authorize(&key(0x40), repo, scope, RevocationEvidence::Revoked),
            Err(DeployKeyRefusal::Revoked),
            "a revoked binding must refuse {scope}"
        );
        // The permitted twin: the identical call with a live record.
        assert_eq!(
            binding.authorize(&key(0x40), repo, scope, RevocationEvidence::Live),
            Ok(principal()),
            "the same call with a live record must proceed, or the refusal above proves nothing"
        );
    }
}

/// Resolution selects the unique binding for a key on a repository, refuses
/// when nothing matches, and refuses when more than one does.
///
/// The ambiguity case is the one worth having. Two bindings for one key on one
/// repository disagree about what that key may do, and any silent resolution --
/// first, widest, narrowest -- would make an iteration order into an
/// authorization decision.
#[test]
fn resolution_finds_the_unique_binding_and_refuses_absence_or_ambiguity() {
    let repo = repository(0x11);
    let other = repository(0x22);
    let read_here =
        DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
            .expect("registers");
    let write_elsewhere =
        DeployKeyBinding::register(other, principal(), key(0x40), &[DeployKeyScope::Write])
            .expect("registers");
    let different_key =
        DeployKeyBinding::register(repo, principal(), key(0x41), &[DeployKeyScope::Write])
            .expect("registers");

    let registry = [
        read_here.clone(),
        write_elsewhere.clone(),
        different_key.clone(),
    ];

    // The permitted case: exactly one binding matches this key on this
    // repository, and it is the one bound HERE, not the same key bound
    // elsewhere.
    let found = DeployKeyBinding::resolve(&registry, &key(0x40), repo).expect("one match");
    assert_eq!(found, &read_here);
    assert_eq!(found.scopes(), [DeployKeyScope::Read]);

    // The same key on the repository it is not bound to is still found there,
    // with the scopes IT was granted -- the binding is per repository.
    let elsewhere = DeployKeyBinding::resolve(&registry, &key(0x40), other).expect("one match");
    assert_eq!(elsewhere.scopes(), [DeployKeyScope::Write]);

    // Absence.
    assert_eq!(
        DeployKeyBinding::resolve(&registry, &key(0x42), repo),
        Err(DeployKeyRefusal::NoBindingForKey)
    );

    // Ambiguity: the same key registered twice on one repository.
    let duplicate =
        DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Write])
            .expect("registers");
    let ambiguous = [read_here, duplicate];
    assert_eq!(
        DeployKeyBinding::resolve(&ambiguous, &key(0x40), repo),
        Err(DeployKeyRefusal::AmbiguousBinding { matched: 2 })
    );
}

/// A key under a signature scheme this build cannot hold is refused, and the
/// registered scheme in the same call shape is not.
///
/// The scheme registry belongs to `fgit-crypto` and is consulted rather than
/// assumed: this crate does not get to decide what a signature scheme is.
#[test]
fn an_unusable_signature_scheme_is_refused_and_ed25519_is_not() {
    let repo = repository(0x11);

    // The permitted twin: the one registered production scheme.
    assert!(
        DeployKeyBinding::register_under_scheme(
            repo,
            principal(),
            ED25519_CODE_POINT,
            key(0x40),
            &[DeployKeyScope::Read],
        )
        .is_ok(),
        "ed25519 is registry row 1 and must register"
    );

    // The refusal: a code point no production scheme is registered under.
    let unregistered: u16 = 0x4242;
    assert_eq!(
        DeployKeyBinding::register_under_scheme(
            repo,
            principal(),
            unregistered,
            key(0x40),
            &[DeployKeyScope::Read],
        ),
        Err(DeployKeyRefusal::KeySchemeUnusable {
            code_point: unregistered
        })
    );

    // Zero is not a scheme either, and a zeroed buffer must not decode into a
    // usable binding by naming scheme 0.
    assert_eq!(
        DeployKeyBinding::register_under_scheme(
            repo,
            principal(),
            0,
            key(0x40),
            &[DeployKeyScope::Read],
        ),
        Err(DeployKeyRefusal::KeySchemeUnusable { code_point: 0 })
    );
}

/// An unusable scheme code point on the wire is refused; the registered one it
/// replaced is not.
///
/// Registering through the constructor cannot reach this path -- `register`
/// hard-codes ed25519 and `register_under_scheme` refuses anything else, so the
/// decoder is the only place a hostile scheme number can arrive, and it is the
/// place that has to refuse it. That also rules out the usual locator here:
/// there is no second valid frame differing only in the scheme to diff against,
/// because only one scheme is registered.
///
/// So the field is located structurally instead. The payload writes the
/// repository id, then the principal id, then the scheme -- both ids are fixed
/// `OPAQUE_ID_LEN` width and the principal fixture byte (0x33) appears nowhere
/// else in the frame, so the run of 0x33s ends exactly where the scheme begins.
/// The test asserts that uniqueness rather than assuming it.
#[test]
fn an_unusable_scheme_on_the_wire_is_refused_and_the_registered_one_is_not() {
    let repo = repository(0x11);
    let binding = DeployKeyBinding::register(repo, principal(), key(0x40), &[DeployKeyScope::Read])
        .expect("registers");
    let bytes = encode_body(&binding).expect("encodes");

    // The permitted twin: untampered, it decodes and names the registered
    // scheme.
    let decoded: DeployKeyBinding = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded.scheme(), ED25519_CODE_POINT);
    assert_eq!(decoded, binding);

    let needle = [0x33_u8; OPAQUE_ID_LEN];
    let occurrences = bytes
        .windows(OPAQUE_ID_LEN)
        .filter(|window| *window == needle)
        .count();
    assert_eq!(
        occurrences, 1,
        "the principal id must occur exactly once for this locator to be sound"
    );
    let principal_at = bytes
        .windows(OPAQUE_ID_LEN)
        .position(|window| window == needle)
        .expect("the principal id is in the frame");
    let scheme_at = principal_at + OPAQUE_ID_LEN;

    // The refusal: a code point no production scheme is registered under,
    // written over the two scheme bytes and nothing else.
    let mut tampered = bytes.clone();
    tampered[scheme_at] = 0x42;
    tampered[scheme_at + 1] = 0x42;
    assert_eq!(
        tampered.len(),
        bytes.len(),
        "the tamper must not change the frame length"
    );
    let refusal = decode_body::<DeployKeyBinding>(&tampered, DecodeLimits::DEFAULT)
        .expect_err("an unusable scheme code point is refused");
    assert!(
        matches!(
            refusal,
            CodecRefusal::VariantUnknown {
                field: "deploy_key.scheme",
                ..
            }
        ),
        "expected an unknown-variant refusal naming the scheme field, got {refusal:?}"
    );
}
