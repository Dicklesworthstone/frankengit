//! Tenant envelope encryption: golden vectors and domain-binding behaviour.
//!
//! The vectors in `goldens/seal_vectors.tsv` were produced by
//! `goldens/seal.py`, which never calls into this crate. HKDF and HMAC there
//! come from Python's `hashlib`; `ChaCha20`-Poly1305 comes from `OpenSSL` through
//! `cryptography`; only `HChaCha20` is written longhand, and that script
//! validates it against the published draft-irtf-cfrg-xchacha section 2.2.1
//! vector before deriving anything, so a mistake in it fails there instead of
//! agreeing with a matching mistake here.
//!
//! Nothing in this file regenerates a vector from `fgit-crypto` output.

use fgit_crypto::{
    EnvelopeError, EnvelopeNonce, KeyEpoch, KeyScope, RootSecret, SealedEnvelope, SecretKey,
    TenantEncryption, XCHACHA20_POLY1305_CODE_POINT, resolve_aead_scheme,
};

const SEAL_VECTORS: &str = include_str!("../goldens/seal_vectors.tsv");

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex has an even length");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("golden hex is valid"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key(root_byte: u8, epoch: u32, tenant: &[u8], repository: &[u8]) -> SecretKey<TenantEncryption> {
    let root = RootSecret::from_bytes([root_byte; 32]);
    let scope = KeyScope { tenant, repository };
    SecretKey::<TenantEncryption>::derive(
        &root,
        KeyEpoch::new(epoch).expect("a golden epoch is non-zero"),
        scope,
    )
}

#[test]
fn the_independent_oracle_vectors_reproduce_exactly() {
    let rows: Vec<Vec<&str>> = SEAL_VECTORS
        .lines()
        .skip(2)
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').collect())
        .collect();
    assert!(rows.len() >= 10, "the corpus must not silently shrink");

    for row in rows {
        let [
            label,
            root_byte,
            epoch,
            tenant_hex,
            repository_hex,
            nonce_byte,
            aad_hex,
            plaintext_hex,
            commitment_hex,
            ciphertext_hex,
            tag_hex,
        ] = row.as_slice()
        else {
            panic!("a seal vector row has eleven columns");
        };

        let root_byte = u8::from_str_radix(root_byte, 16).expect("a root byte is hex");
        let epoch: u32 = epoch.parse().expect("an epoch is a number");
        let tenant = decode_hex(tenant_hex);
        let repository = decode_hex(repository_hex);
        let nonce_byte = u8::from_str_radix(nonce_byte, 16).expect("a nonce byte is hex");
        let aad = decode_hex(aad_hex);
        let plaintext = decode_hex(plaintext_hex);

        let key = key(root_byte, epoch, &tenant, &repository);
        assert_eq!(
            hex(key.id().commitment()),
            *commitment_hex,
            "{label}: key commitment"
        );

        let sealed = key.seal(
            EnvelopeNonce::from_bytes([nonce_byte; 24]),
            &aad,
            &plaintext,
        );
        assert_eq!(
            hex(sealed.ciphertext()),
            *ciphertext_hex,
            "{label}: ciphertext"
        );
        assert_eq!(hex(sealed.tag()), *tag_hex, "{label}: tag");

        // Round trip through this crate's own opener, so the corpus also pins
        // decryption rather than only encryption.
        assert_eq!(
            key.open(&sealed, &aad),
            Ok(plaintext),
            "{label}: round trip"
        );
    }
}

#[test]
fn two_tenants_do_not_produce_the_same_ciphertext_from_one_plaintext() {
    // The two `tenant-scope` / `other-tenant` rows differ only in the tenant,
    // and share a nonce. Asserted here as a property rather than left implicit
    // in the corpus.
    let plaintext = b"one canonical tenant body";
    let nonce = EnvelopeNonce::from_bytes([0x22; 24]);
    let left = key(0x5A, 1, b"tenant-a", b"").seal(nonce, b"", plaintext);
    let right = key(0x5A, 1, b"tenant-b", b"").seal(nonce, b"", plaintext);
    assert_ne!(left.ciphertext(), right.ciphertext());
    assert_ne!(left.key_commitment(), right.key_commitment());
}

#[test]
fn a_ciphertext_carried_to_another_tenant_is_refused_as_a_placement_error() {
    // Plan sections 12.5 and 13.7: a ciphertext copied across incompatible key
    // domains is not a valid placement. The refusal names the placement rather
    // than reporting a generic authentication failure.
    let plaintext = b"one canonical tenant body";
    let source = key(0x5A, 1, b"tenant-a", b"");
    let destination = key(0x5A, 1, b"tenant-b", b"");
    let sealed = source.seal(EnvelopeNonce::from_bytes([0x22; 24]), b"", plaintext);

    assert_eq!(
        destination.open(&sealed, b""),
        Err(EnvelopeError::KeyDomainMismatch)
    );
    assert_eq!(
        source.open(&sealed, b""),
        Ok(plaintext.to_vec()),
        "the same envelope in its own domain must still open"
    );
}

#[test]
fn a_ciphertext_carried_to_another_repository_is_refused() {
    let plaintext = b"one canonical tenant body";
    let source = key(0x5A, 1, b"tenant-a", b"repo-1");
    let destination = key(0x5A, 1, b"tenant-a", b"repo-2");
    let sealed = source.seal(EnvelopeNonce::from_bytes([0x33; 24]), b"", plaintext);

    assert_eq!(
        destination.open(&sealed, b""),
        Err(EnvelopeError::KeyDomainMismatch)
    );
}

#[test]
fn a_ciphertext_from_another_epoch_is_refused() {
    let plaintext = b"one canonical tenant body";
    let first = key(0x5A, 1, b"tenant-a", b"");
    let second = key(0x5A, 2, b"tenant-a", b"");
    let sealed = first.seal(EnvelopeNonce::from_bytes([0x44; 24]), b"", plaintext);

    assert_eq!(
        second.open(&sealed, b""),
        Err(EnvelopeError::KeyDomainMismatch)
    );
}

#[test]
fn different_associated_data_does_not_authenticate() {
    // The caller's associated data reaches the tag, so a placement fact a
    // caller bound cannot be changed without detection. This one IS an
    // authentication failure rather than a domain mismatch, because the key
    // domain genuinely matches.
    let plaintext = b"one canonical tenant body";
    let key = key(0x5A, 1, b"tenant-a", b"");
    let sealed = key.seal(
        EnvelopeNonce::from_bytes([0x55; 24]),
        b"segment-7",
        plaintext,
    );

    assert_eq!(
        key.open(&sealed, b"segment-8"),
        Err(EnvelopeError::Unauthenticated)
    );
    assert_eq!(
        key.open(&sealed, b"segment-7"),
        Ok(plaintext.to_vec()),
        "the original associated data must still open it"
    );
}

#[test]
fn a_flipped_ciphertext_bit_does_not_authenticate() {
    let plaintext = b"one canonical tenant body";
    let key = key(0x5A, 1, b"tenant-a", b"");
    let sealed = key.seal(EnvelopeNonce::from_bytes([0x11; 24]), b"", plaintext);

    let mut bytes = sealed.ciphertext().to_vec();
    bytes[0] ^= 0x01;
    let tampered = SealedEnvelope::from_parts(
        sealed.scheme(),
        sealed.purpose(),
        sealed.epoch(),
        *sealed.key_commitment(),
        *sealed.nonce(),
        bytes,
        *sealed.tag(),
    );

    assert_eq!(
        key.open(&tampered, b""),
        Err(EnvelopeError::Unauthenticated)
    );
}

#[test]
fn a_flipped_tag_bit_does_not_authenticate() {
    let key = key(0x5A, 1, b"tenant-a", b"");
    let sealed = key.seal(EnvelopeNonce::from_bytes([0x11; 24]), b"", b"body");

    let mut tag = *sealed.tag();
    tag[0] ^= 0x01;
    let tampered = SealedEnvelope::from_parts(
        sealed.scheme(),
        sealed.purpose(),
        sealed.epoch(),
        *sealed.key_commitment(),
        *sealed.nonce(),
        sealed.ciphertext().to_vec(),
        tag,
    );

    assert_eq!(
        key.open(&tampered, b""),
        Err(EnvelopeError::Unauthenticated)
    );
}

#[test]
fn a_substituted_nonce_does_not_authenticate() {
    let key = key(0x5A, 1, b"tenant-a", b"");
    let sealed = key.seal(EnvelopeNonce::from_bytes([0x11; 24]), b"", b"body");

    let tampered = SealedEnvelope::from_parts(
        sealed.scheme(),
        sealed.purpose(),
        sealed.epoch(),
        *sealed.key_commitment(),
        [0x12; 24],
        sealed.ciphertext().to_vec(),
        *sealed.tag(),
    );

    assert_eq!(
        key.open(&tampered, b""),
        Err(EnvelopeError::Unauthenticated)
    );
}

#[test]
fn an_unimplemented_aead_scheme_is_refused_before_the_key_is_touched() {
    let key = key(0x5A, 1, b"tenant-a", b"");
    let sealed = key.seal(EnvelopeNonce::from_bytes([0x11; 24]), b"", b"body");

    let foreign = SealedEnvelope::from_parts(
        9,
        sealed.purpose(),
        sealed.epoch(),
        *sealed.key_commitment(),
        *sealed.nonce(),
        sealed.ciphertext().to_vec(),
        *sealed.tag(),
    );

    assert_eq!(
        key.open(&foreign, b""),
        Err(EnvelopeError::UnsupportedScheme { code_point: 9 })
    );
}

#[test]
fn sealing_an_empty_plaintext_still_authenticates_the_key_domain() {
    // A zero-length body is the case where an implementation is most likely to
    // skip the AEAD entirely and return something that looks fine.
    let tenant_key = key(0x5A, 1, b"", b"");
    let sealed = tenant_key.seal(EnvelopeNonce::from_bytes([0x00; 24]), b"", b"");
    assert_eq!(sealed.ciphertext(), b"");
    assert_eq!(tenant_key.open(&sealed, b""), Ok(Vec::new()));

    let other = key(0xA5, 1, b"", b"");
    assert_eq!(
        other.open(&sealed, b""),
        Err(EnvelopeError::KeyDomainMismatch)
    );
}

#[test]
fn the_registry_resolves_xchacha20_poly1305_and_agrees_with_the_implementation() {
    let row = resolve_aead_scheme(XCHACHA20_POLY1305_CODE_POINT)
        .expect("xchacha20-poly1305 is registered");
    assert_eq!(row.name, "xchacha20-poly1305");

    let tenant_key = key(0x5A, 1, b"", b"");
    let sealed = tenant_key.seal(EnvelopeNonce::from_bytes([0x00; 24]), b"", b"body");
    assert_eq!(row.nonce_len, sealed.nonce().len());
    assert_eq!(row.tag_len, sealed.tag().len());
}

// --- The cryptographic-erasure drill ---------------------------------------
//
// Erasure is a state, not an absence (ADR-0003, plan section 19.4). These
// tests exercise the composition a caller is required to make: consult the key
// history, then open. They are written to assert what is actually true and to
// say plainly what is not, because an erasure test that over-claims is worse
// than none.

use fgit_crypto::{KeyHistory, KeyLifecycleError, Recoverability};

/// The only sanctioned way to open: ask the registry first.
///
/// `SecretKey::open` cannot do this itself — a key does not know its own
/// history — so the authorization step is the caller's, and this helper is
/// what a caller is expected to write.
fn authorized_open(
    history: &KeyHistory<TenantEncryption>,
    key: &SecretKey<TenantEncryption>,
    sealed: &SealedEnvelope,
    associated_data: &[u8],
) -> Result<Vec<u8>, KeyLifecycleError> {
    history.authorize_verify(sealed.epoch())?;
    Ok(key
        .open(sealed, associated_data)
        .expect("an authorized envelope in its own key domain opens"))
}

#[test]
fn rotation_keeps_old_ciphertext_readable_while_new_writes_use_the_new_epoch() {
    let first = key(0x5A, 1, b"tenant-a", b"");
    let second = key(0x5A, 2, b"tenant-a", b"");
    let mut history = KeyHistory::new(&first);

    let old = first.seal(
        EnvelopeNonce::from_bytes([0x01; 24]),
        b"",
        b"written before rotation",
    );
    history.rotate(&second).expect("rotation to epoch two");

    assert_eq!(
        history.issuing_epoch(),
        Ok(KeyEpoch::new(2).expect("epoch two")),
        "new writes use the new epoch"
    );
    assert_eq!(
        authorized_open(&history, &first, &old, b""),
        Ok(b"written before rotation".to_vec()),
        "data written under the retired epoch is still readable"
    );
    assert_eq!(
        history.authorize_issue(KeyEpoch::FIRST),
        Err(KeyLifecycleError::EpochRetired {
            epoch: KeyEpoch::FIRST,
            active: KeyEpoch::new(2).expect("epoch two"),
        }),
        "the retired epoch may verify but must not issue"
    );
}

#[test]
fn revocation_withholds_the_epoch_without_destroying_anything() {
    let first = key(0x5A, 1, b"tenant-a", b"");
    let second = key(0x5A, 2, b"tenant-a", b"");
    let mut history = KeyHistory::new(&first);
    let sealed = first.seal(EnvelopeNonce::from_bytes([0x02; 24]), b"", b"body");
    history.rotate(&second).expect("rotation to epoch two");

    history.revoke(KeyEpoch::FIRST).expect("revoking epoch one");

    assert_eq!(
        authorized_open(&history, &first, &sealed, b""),
        Err(KeyLifecycleError::EpochRevoked {
            epoch: KeyEpoch::FIRST
        })
    );
    assert_eq!(
        history.recoverability(KeyEpoch::FIRST),
        Ok(Recoverability::WithheldByRevocation),
        "revocation withholds; it does not claim the material is gone"
    );
}

#[test]
fn erasure_makes_dependent_ciphertext_typed_unrecoverable_and_never_unknown() {
    let first = key(0x5A, 1, b"tenant-a", b"");
    let second = key(0x5A, 2, b"tenant-a", b"");
    let mut history = KeyHistory::new(&first);
    let sealed = first.seal(EnvelopeNonce::from_bytes([0x03; 24]), b"", b"tenant body");
    history.rotate(&second).expect("rotation to epoch two");

    // Readable right up to the erasure, so the refusal below is caused by the
    // erasure and not by the rotation that preceded it.
    assert_eq!(
        authorized_open(&history, &first, &sealed, b""),
        Ok(b"tenant body".to_vec())
    );

    let receipt = history.erase(KeyEpoch::FIRST).expect("erasing epoch one");

    assert_eq!(
        authorized_open(&history, &first, &sealed, b""),
        Err(KeyLifecycleError::MaterialErased {
            epoch: KeyEpoch::FIRST
        }),
        "the refusal must name erasure, never EpochUnknown: unknown invites a \
         retry, a resynchronisation, or a corruption diagnosis, and each of \
         those is a route by which deleted data is resurrected"
    );
    assert_eq!(
        history.recoverability(KeyEpoch::FIRST),
        Ok(Recoverability::PermanentlyUnrecoverable)
    );
    assert!(
        !receipt.canonical_body().is_empty(),
        "every transition emits evidence as a body, not a log line"
    );

    // The surviving epoch is untouched: erasure is scoped, not a purge.
    let still_live = second.seal(EnvelopeNonce::from_bytes([0x04; 24]), b"", b"after erasure");
    assert_eq!(
        authorized_open(&history, &second, &still_live, b""),
        Ok(b"after erasure".to_vec())
    );
}

#[test]
fn erasure_is_a_registry_decision_and_this_test_says_what_it_does_not_reach() {
    // The honest boundary, asserted rather than left to a doc comment.
    //
    // `KeyHistory` records lifecycle for epochs; it does not hold key material
    // and cannot reach a copy the caller already has. In this crate keys are
    // DERIVED from a `RootSecret`, so anyone still holding the root can
    // recompute an erased epoch's key and open the ciphertext directly. That
    // is not a defect in erasure -- it is the scope of the claim, and it is
    // why erasure evidence is a claim about the key registry rather than
    // about every byte that ever held the key.
    //
    // Deployments that need erasure to be cryptographic rather than
    // administrative must not retain the root: they store wrapped material and
    // destroy it. Wiring that to fg033's deletion states is the remaining
    // follow-up, and it is recorded as open rather than implied to be done.
    let first = key(0x5A, 1, b"tenant-a", b"");
    let second = key(0x5A, 2, b"tenant-a", b"");
    let mut history = KeyHistory::new(&first);
    let sealed = first.seal(EnvelopeNonce::from_bytes([0x05; 24]), b"", b"tenant body");
    history.rotate(&second).expect("rotation to epoch two");
    history.erase(KeyEpoch::FIRST).expect("erasing epoch one");

    // The sanctioned path refuses.
    assert!(matches!(
        authorized_open(&history, &first, &sealed, b""),
        Err(KeyLifecycleError::MaterialErased { .. })
    ));

    // Re-deriving from a retained root still opens it. Asserted so that the
    // limitation is a fact this suite records, not a surprise a reader of the
    // test above would be entitled to be shocked by.
    let rederived = key(0x5A, 1, b"tenant-a", b"");
    assert_eq!(
        rederived.open(&sealed, b""),
        Ok(b"tenant body".to_vec()),
        "erasure of a registry epoch does not erase a retained root secret"
    );
}
