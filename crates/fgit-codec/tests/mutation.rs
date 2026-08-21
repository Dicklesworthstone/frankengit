// The adversarial mutation campaign.
//
// One property, applied to every mutant of every canonical vector:
//
//     a mutant either refuses, or decodes to something whose identity differs
//     from the canonical form's.
//
// The failure this hunts is the third possibility — a mutant that decodes to
// the *same* value, which would mean two byte strings for one identity. That
// is the one outcome a content-addressed system cannot survive, because a
// compare-and-exchange that should have lost would win and a duplicate that
// should have been suppressed would not be.
//
// Mutants are generated exhaustively where that is cheap (every bit of every
// byte) and systematically otherwise. Nothing here is random, so a failure
// names an exact byte and bit.

mod support {
    pub use fgit_codec::harness::*;
}

use std::collections::BTreeMap;

use fgit_codec::attest::SignedEnvelopeBody;
use fgit_codec::harness::{GoldenCase, load_goldens};
use fgit_codec::schema::{
    RefusalRecordBody, RepositoryAuthorityHeadBody, RepositoryCommitRecord,
    RepositoryDecisionBatchBody, TransactionSealBody,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, DetachedSignature,
    SignatureSchemeId, body_id_of_frame, decode_body, encode_body,
};
use fgit_types::identity::InternalObjectId;

/// What happened to one mutant.
#[derive(Debug)]
enum Outcome {
    /// Refused, with the refusal's stable kind.
    Refused(&'static str),
    /// Decoded, and to a genuinely different body.
    DecodedDistinct,
}

/// Runs the property for one mutant of one canonical vector.
///
/// Returns the outcome, or a description of the violation.
fn classify<B>(
    canonical: &[u8],
    canonical_id: &InternalObjectId,
    mutant: &[u8],
) -> Result<Outcome, String>
where
    B: CanonicalBody + PartialEq,
{
    let limits = DecodeLimits::DEFAULT;
    match decode_body::<B>(mutant, limits) {
        Err(refusal) => Ok(Outcome::Refused(refusal.kind())),
        Ok(value) => {
            // It decoded. Two things must hold.
            //
            // First: re-encoding must reproduce the mutant, not the canonical
            // bytes. If it reproduces the canonical bytes then the mutant was
            // a second, non-canonical encoding of one value.
            let re_encoded = encode_body(&value)
                .map_err(|error| format!("decoded mutant failed to re-encode: {error}"))?;
            if re_encoded == canonical {
                return Err(
                    "mutant decoded to the canonical value: two byte strings, one value".to_owned(),
                );
            }
            if re_encoded != mutant {
                return Err(format!(
                    "mutant decoded but re-encoded to different bytes ({} vs {} bytes): \
                     a non-canonical encoding was accepted",
                    re_encoded.len(),
                    mutant.len()
                ));
            }

            // Second, and the acceptance line: it must not share an identity.
            let mutant_id = body_id_of_frame(&CryptoBodyIdentity, mutant, limits)
                .map_err(|error| format!("decoded mutant has no identity: {error}"))?;
            if &mutant_id == canonical_id {
                return Err("mutant decoded to a DIFFERENT body with the SAME identity".to_owned());
            }
            Ok(Outcome::DecodedDistinct)
        }
    }
}

/// Applies the campaign to one canonical vector, returning per-outcome counts.
fn campaign<B>(name: &str, canonical: &[u8]) -> BTreeMap<String, usize>
where
    B: CanonicalBody + PartialEq,
{
    let limits = DecodeLimits::DEFAULT;
    let canonical_id = body_id_of_frame(&CryptoBodyIdentity, canonical, limits)
        .unwrap_or_else(|error| panic!("{name}: canonical vector has no identity: {error}"));
    assert!(
        decode_body::<B>(canonical, limits).is_ok(),
        "{name}: the canonical vector must decode, or the campaign proves nothing"
    );

    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut record = |mutant: &[u8], what: &str| {
        // A mutation that happens to reproduce the canonical bytes is not a
        // mutant; skipping it keeps the tally honest.
        if mutant == canonical {
            return;
        }
        match classify::<B>(canonical, &canonical_id, mutant) {
            Ok(Outcome::Refused(kind)) => {
                *tally.entry(format!("refused:{kind}")).or_default() += 1;
            }
            Ok(Outcome::DecodedDistinct) => {
                *tally.entry("decoded_distinct".to_owned()).or_default() += 1;
            }
            Err(violation) => panic!("{name}: {what}: {violation}"),
        }
    };

    // 1. Every bit of every byte. Exhaustive, and the densest source of
    //    payload-interior mutants the corpus has.
    let mut mutant = canonical.to_vec();
    for index in 0..canonical.len() {
        for bit in 0..8_u8 {
            mutant[index] ^= 1 << bit;
            record(&mutant, &format!("bit flip at byte {index} bit {bit}"));
            mutant[index] ^= 1 << bit;
        }
    }

    // 2. Truncation at every length.
    for length in 0..canonical.len() {
        record(&canonical[..length], &format!("truncated to {length}"));
    }

    // 3. Trailing bytes.
    for extra in [1_usize, 2, 8, 64] {
        let mut extended = canonical.to_vec();
        extended.extend(std::iter::repeat_n(0_u8, extra));
        record(&extended, &format!("{extra} trailing bytes"));
    }

    // 4. Length-prefix tampering on the frame's payload prefix, whose position
    //    is derivable rather than guessed.
    if let Ok((_, payload)) = fgit_codec::split_frame(canonical, limits) {
        let prefix_at = canonical.len() - payload.len() - 4;
        for value in [0_u32, 1, u32::MAX, u32::MAX / 2] {
            let mut tampered = canonical.to_vec();
            tampered[prefix_at..prefix_at + 4].copy_from_slice(&value.to_be_bytes());
            record(&tampered, &format!("payload length prefix set to {value}"));
        }
    }

    // 5. Version bumps at their fixed offsets: codec major and minor sit at
    //    bytes 4..6 and 6..8 immediately after the magic.
    for offset in [4_usize, 6] {
        for delta in [1_u16, 0xff00] {
            let mut bumped = canonical.to_vec();
            let current = u16::from_be_bytes([bumped[offset], bumped[offset + 1]]);
            let next = current.wrapping_add(delta);
            bumped[offset..offset + 2].copy_from_slice(&next.to_be_bytes());
            record(&bumped, &format!("version at {offset} bumped by {delta}"));
        }
    }

    tally
}

fn canonical_bytes(cases: &[GoldenCase], name: &str) -> Vec<u8> {
    cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing golden {name}"))
        .bytes
        .clone()
}

/// The counts must show the campaign actually ran and actually varied.
fn assert_campaign_is_substantive(name: &str, tally: &BTreeMap<String, usize>) {
    let total: usize = tally.values().sum();
    assert!(
        total > 500,
        "{name}: only {total} mutants classified; the campaign is too thin to mean anything"
    );
    let refusal_kinds = tally
        .keys()
        .filter(|key| key.starts_with("refused:"))
        .count();
    assert!(
        refusal_kinds >= 3,
        "{name}: only {refusal_kinds} distinct refusal kinds across {total} mutants, \
         which suggests the decoder is failing for one blunt reason rather than \
         diagnosing: {tally:?}"
    );
}

#[test]
fn no_mutant_of_the_transaction_seal_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "txn-seal__canonical");
    let tally = campaign::<TransactionSealBody>("txn-seal", &canonical);
    assert_campaign_is_substantive("txn-seal", &tally);
}

#[test]
fn no_mutant_of_the_commit_record_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "rcr__canonical");
    let tally = campaign::<RepositoryCommitRecord>("rcr", &canonical);
    assert_campaign_is_substantive("rcr", &tally);
}

#[test]
fn no_mutant_of_the_decision_batch_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "decision-batch__canonical");
    let tally = campaign::<RepositoryDecisionBatchBody>("decision-batch", &canonical);
    assert_campaign_is_substantive("decision-batch", &tally);
}

#[test]
fn no_mutant_of_either_authority_head_shares_its_identity() {
    let cases = load_goldens();
    for name in ["authority-head__genesis", "authority-head__advanced"] {
        let canonical = canonical_bytes(&cases, name);
        let tally = campaign::<RepositoryAuthorityHeadBody>(name, &canonical);
        assert_campaign_is_substantive(name, &tally);
    }
}

#[test]
fn no_mutant_of_the_refusal_record_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "refusal-record__canonical");
    let tally = campaign::<RefusalRecordBody>("refusal-record", &canonical);
    assert_campaign_is_substantive("refusal-record", &tally);
}

#[test]
fn no_mutant_of_any_signed_envelope_shares_its_identity() {
    let cases = load_goldens();
    for name in [
        "signed-envelope__unsigned",
        "signed-envelope__one-signature",
        "signed-envelope__two-signatures",
    ] {
        let canonical = canonical_bytes(&cases, name);
        let tally = campaign::<SignedEnvelopeBody>(name, &canonical);
        assert_campaign_is_substantive(name, &tally);
    }
}

#[test]
fn a_reordered_collection_is_refused_rather_than_accepted_as_a_second_encoding() {
    // Byte mutation cannot easily produce a validly-encoded-but-misordered
    // collection, so it is built here. This is the mutation class that would
    // otherwise give two byte strings for one value.
    let seal = support::transaction_seal();
    let identity = |envelope: &SignedEnvelopeBody| {
        envelope
            .carried_body_id(&CryptoBodyIdentity, DecodeLimits::DEFAULT)
            .expect("identifies")
    };

    let mut envelope = SignedEnvelopeBody::seal(&seal).expect("seals");
    let body_id = fgit_codec::body_id(&CryptoBodyIdentity, &seal).expect("identifies");
    for key in [&b"key-a"[..], b"key-b"] {
        envelope
            .attach(
                DetachedSignature {
                    scheme: SignatureSchemeId::try_new(1).expect("nonzero"),
                    key_id: key.to_vec(),
                    body_id,
                    signature: vec![0xa0; 32],
                },
                DecodeLimits::DEFAULT,
            )
            .expect("attaches");
    }
    let ascending = encode_body(&envelope).expect("encodes");

    // Attaching in the opposite order must produce identical bytes, because
    // the encoder sorts. If it did not, the set would not be canonical.
    let mut reversed = SignedEnvelopeBody::seal(&seal).expect("seals");
    for key in [&b"key-b"[..], b"key-a"] {
        reversed
            .attach(
                DetachedSignature {
                    scheme: SignatureSchemeId::try_new(1).expect("nonzero"),
                    key_id: key.to_vec(),
                    body_id,
                    signature: vec![0xa0; 32],
                },
                DecodeLimits::DEFAULT,
            )
            .expect("attaches");
    }
    assert_eq!(
        encode_body(&reversed).expect("encodes"),
        ascending,
        "attachment order must not reach the bytes"
    );
    assert_eq!(identity(&envelope), identity(&reversed));

    // Now hand-build the descending encoding, which no encoder would emit, and
    // require the decoder to refuse it. Without this check a peer could offer
    // two byte strings for one envelope.
    let (_, payload) = fgit_codec::split_frame(&ascending, DecodeLimits::DEFAULT).expect("splits");
    let element_count_at = payload.len() - 2 * signature_span(payload) - 4;
    let span = signature_span(payload);
    let first = element_count_at + 4;
    let second = first + span;
    let mut swapped_payload = payload.to_vec();
    swapped_payload[first..second].copy_from_slice(&payload[second..second + span]);
    swapped_payload[second..second + span].copy_from_slice(&payload[first..second]);
    assert_ne!(
        swapped_payload, payload,
        "the swap must actually change bytes"
    );

    let swapped_frame = reframe(&ascending, payload.len(), &swapped_payload);
    let refusal = decode_body::<SignedEnvelopeBody>(&swapped_frame, DecodeLimits::DEFAULT)
        .expect_err("a descending collection is not canonical and must be refused");
    assert!(
        matches!(refusal, CodecRefusal::CollectionUnordered { .. }),
        "expected an ordering refusal, got {refusal}"
    );

    // Permitted counterpart: the untouched frame still decodes.
    assert!(decode_body::<SignedEnvelopeBody>(&ascending, DecodeLimits::DEFAULT).is_ok());
}

/// Byte span of one encoded signature in the two-signature envelope payload.
fn signature_span(payload: &[u8]) -> usize {
    // The payload is: u32 body_frame length, body frame, u32 count, then the
    // signatures. With two identical-shaped signatures the remainder splits
    // evenly, which is all this needs.
    let declared = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let body_len = usize::try_from(declared).expect("a corpus body fits in usize");
    let after_body = 4 + body_len + 4;
    (payload.len() - after_body) / 2
}

/// Rebuilds a frame around a replacement payload of the same length.
fn reframe(original: &[u8], payload_len: usize, payload: &[u8]) -> Vec<u8> {
    assert_eq!(payload_len, payload.len(), "reframe preserves length");
    let mut out = original.to_vec();
    let start = original.len() - payload_len;
    out[start..].copy_from_slice(payload);
    out
}

#[test]
fn a_duplicate_collection_element_has_no_encoding_and_no_decoding() {
    // Both directions of the duplicate rule, since a set that refuses on the
    // way out but accepts on the way in would still admit two byte strings.
    let seal = support::transaction_seal();
    let body_id = fgit_codec::body_id(&CryptoBodyIdentity, &seal).expect("identifies");
    let signature = DetachedSignature {
        scheme: SignatureSchemeId::try_new(1).expect("nonzero"),
        key_id: b"key-a".to_vec(),
        body_id,
        signature: vec![0xa0; 32],
    };

    let mut envelope = SignedEnvelopeBody::seal(&seal).expect("seals");
    envelope
        .attach(signature.clone(), DecodeLimits::DEFAULT)
        .expect("first attaches");
    envelope
        .attach(signature, DecodeLimits::DEFAULT)
        .expect("attach itself does not deduplicate");

    let refusal = encode_body(&envelope).expect_err("a repeated element has no canonical encoding");
    assert!(
        matches!(refusal, CodecRefusal::CollectionDuplicate { .. }),
        "expected a duplicate refusal, got {refusal}"
    );

    // Permitted counterpart: two distinct signatures encode.
    let mut distinct = SignedEnvelopeBody::seal(&seal).expect("seals");
    for key in [&b"key-a"[..], b"key-b"] {
        distinct
            .attach(
                DetachedSignature {
                    scheme: SignatureSchemeId::try_new(1).expect("nonzero"),
                    key_id: key.to_vec(),
                    body_id,
                    signature: vec![0xa0; 32],
                },
                DecodeLimits::DEFAULT,
            )
            .expect("attaches");
    }
    assert!(encode_body(&distinct).is_ok());
}

#[test]
fn a_higher_minor_is_refused_strictly_even_when_it_carries_no_new_fields() {
    // Found by the mutation campaign: bumping the codec minor leaves the
    // payload untouched, so before this rule a mutant decoded to the canonical
    // VALUE while carrying different bytes. The identity differed, because the
    // codec version travels in it — but `encode(decode(b)) == b` did not hold,
    // and that is the invariant the corpus exists to defend.
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "txn-seal__canonical");

    let mut bumped = canonical.clone();
    bumped[6..8].copy_from_slice(&1_u16.to_be_bytes());
    let refusal = decode_body::<TransactionSealBody>(&bumped, DecodeLimits::DEFAULT)
        .expect_err("a strict decode must refuse a codec minor it cannot reproduce");
    assert!(
        matches!(
            refusal,
            CodecRefusal::CodecMinorUnsupported {
                observed: 1,
                supported: 0
            }
        ),
        "expected a codec-minor refusal, got {refusal}"
    );

    // The preserving path still accepts it and reproduces the bytes exactly,
    // which is what makes the strict refusal safe rather than merely strict.
    let preserved =
        fgit_codec::decode_body_preserving::<TransactionSealBody>(&bumped, DecodeLimits::DEFAULT)
            .expect("the preserving path accepts a newer minor");
    assert_eq!(preserved.codec_minor, 1);
    assert_eq!(
        fgit_codec::encode_preserved(&preserved).expect("re-encodes"),
        bumped,
        "relaying a newer-minor body must reproduce its bytes exactly"
    );

    // Permitted counterpart: the untouched vector decodes strictly.
    assert!(decode_body::<TransactionSealBody>(&canonical, DecodeLimits::DEFAULT).is_ok());
}
