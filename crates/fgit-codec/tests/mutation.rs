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
// byte, every byte substituted with four values) and systematically otherwise.
// The coordinated multi-bit pass is sampled rather than exhaustive — the space
// is far too large — but it is seeded from a fixed constant and the seed and
// the exact bits touched are printed on failure, so a hit replays exactly.
// Nothing here draws on wall time or a system generator.

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

    // 6. Byte substitution, which a bit flip cannot express: replacing a byte
    //    outright reaches values several bits away in one step.
    for index in 0..canonical.len() {
        for replacement in [0x00_u8, 0xff, 0x80, 0x01] {
            if canonical[index] == replacement {
                continue;
            }
            let mut substituted = canonical.to_vec();
            substituted[index] = replacement;
            record(
                &substituted,
                &format!("byte {index} replaced with {replacement:#04x}"),
            );
        }
    }

    // 7. Coordinated multi-bit mutations. Single-bit flips are exhaustive but
    //    cannot express a defect that needs two edits at once, so this samples
    //    combinations deterministically. The seed is fixed and printed on
    //    failure, so a hit replays exactly.
    let mut rng = MutationRng::new(MULTI_BIT_SEED ^ seed_of(name));
    for round in 0..MULTI_BIT_ROUNDS {
        for width in 2..=4_usize {
            let mut multi = canonical.to_vec();
            let mut touched = Vec::with_capacity(width);
            for _ in 0..width {
                let index = rng.below(canonical.len());
                let bit = u8::try_from(rng.below(8)).unwrap_or(0);
                multi[index] ^= 1 << bit;
                touched.push((index, bit));
            }
            record(
                &multi,
                &format!(
                    "multi-bit round {round} width {width} seed {:#x} touched {touched:?}",
                    MULTI_BIT_SEED ^ seed_of(name)
                ),
            );
        }
    }

    // 8. Length-prefix compensation: the classic canonicalization attack.
    //    Shrink one length prefix and grow the following one by the same
    //    amount, so the frame's total length is unchanged and only the
    //    internal split moves. A single bit flip cannot express this, and a
    //    decoder that did not re-verify full consumption would accept it as a
    //    second encoding of the same bytes.
    if let Ok((_, payload)) = fgit_codec::split_frame(canonical, limits) {
        let payload_at = canonical.len() - payload.len();
        for position in candidate_length_prefixes(payload) {
            for delta in [1_i64, -1] {
                if let Some(shifted) = shift_length_prefix(payload, position, delta) {
                    let mut framed = canonical.to_vec();
                    framed[payload_at..].copy_from_slice(&shifted);
                    record(
                        &framed,
                        &format!("length prefix at payload offset {position} shifted by {delta}"),
                    );
                }
            }
        }
    }

    tally
}

/// Seed for the coordinated multi-bit pass. Fixed, so the corpus is the same
/// on every machine and every run.
const MULTI_BIT_SEED: u64 = 0x0c0d_ec00_3b17_5eed;

/// How many rounds of each width to draw.
const MULTI_BIT_ROUNDS: usize = 64;

/// Derives a per-vector seed offset from the vector's name, so two vectors do
/// not draw the same index sequence.
fn seed_of(name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in name.as_bytes() {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// `SplitMix64`, so the coordinated pass replays from its seed alone.
struct MutationRng(u64);

impl MutationRng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let draw = usize::try_from(self.next_u64() >> 16).unwrap_or(0);
        draw % bound
    }
}

/// Offsets in a payload where a big-endian `u32` reads as a length that would
/// fit in the bytes that follow.
///
/// A heuristic, deliberately: it does not need to find every real prefix, only
/// enough plausible ones to drive the compensation mutation.
fn candidate_length_prefixes(payload: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    for position in 0..payload.len().saturating_sub(4) {
        let declared = u32::from_be_bytes([
            payload[position],
            payload[position + 1],
            payload[position + 2],
            payload[position + 3],
        ]);
        let Ok(length) = usize::try_from(declared) else {
            continue;
        };
        if length > 0 && position + 4 + length <= payload.len() {
            found.push(position);
        }
        if found.len() >= 32 {
            break;
        }
    }
    found
}

/// Moves `delta` bytes across a length prefix, keeping the payload's total
/// length unchanged so only the internal split differs.
fn shift_length_prefix(payload: &[u8], position: usize, delta: i64) -> Option<Vec<u8>> {
    let declared = u32::from_be_bytes([
        payload[position],
        payload[position + 1],
        payload[position + 2],
        payload[position + 3],
    ]);
    let current = i64::from(declared);
    let next = current.checked_add(delta)?;
    if next < 0 {
        return None;
    }
    let next = u32::try_from(next).ok()?;
    let length = usize::try_from(next).ok()?;
    if position + 4 + length > payload.len() {
        return None;
    }
    let mut out = payload.to_vec();
    out[position..position + 4].copy_from_slice(&next.to_be_bytes());
    Some(out)
}

fn canonical_bytes(cases: &[GoldenCase], name: &str) -> Vec<u8> {
    cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing golden {name}"))
        .bytes
        .clone()
}

/// Prints the per-vector outcome tally.
///
/// The acceptance line asks for refusal codes to be logged, not merely
/// counted: a campaign that classifies thousands of mutants and reports only
/// pass/fail hides which refusals actually fired, and a decoder that quietly
/// stopped diagnosing would look identical to one that still does. `cargo test`
/// captures this unless a test fails or `--nocapture` is given, which is the
/// right default — it is diagnostic output, not a result.
fn log_tally(name: &str, tally: &BTreeMap<String, usize>) {
    let total: usize = tally.values().sum();
    println!("mutation campaign {name}: {total} mutants classified");
    for (outcome, count) in tally {
        println!("  {outcome:40} {count:>7}");
    }
}

/// Logs the tally and then asserts the campaign was substantive.
fn log_tally_and_assert(name: &str, tally: &BTreeMap<String, usize>) {
    log_tally(name, tally);
    assert_campaign_is_substantive(name, tally);
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
    log_tally_and_assert("txn-seal", &tally);
}

#[test]
fn no_mutant_of_the_commit_record_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "rcr__canonical");
    let tally = campaign::<RepositoryCommitRecord>("rcr", &canonical);
    log_tally_and_assert("rcr", &tally);
}

#[test]
fn no_mutant_of_the_decision_batch_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "decision-batch__canonical");
    let tally = campaign::<RepositoryDecisionBatchBody>("decision-batch", &canonical);
    log_tally_and_assert("decision-batch", &tally);
}

#[test]
fn no_mutant_of_either_authority_head_shares_its_identity() {
    let cases = load_goldens();
    for name in ["authority-head__genesis", "authority-head__advanced"] {
        let canonical = canonical_bytes(&cases, name);
        let tally = campaign::<RepositoryAuthorityHeadBody>(name, &canonical);
        log_tally_and_assert(name, &tally);
    }
}

#[test]
fn no_mutant_of_the_refusal_record_shares_its_identity() {
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "refusal-record__canonical");
    let tally = campaign::<RefusalRecordBody>("refusal-record", &canonical);
    log_tally_and_assert("refusal-record", &tally);
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
        log_tally_and_assert(name, &tally);
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
                    scheme: SignatureSchemeId::try_new(
                        support::FIXTURE_SIGNATURE_SCHEME_CODE_POINT,
                    )
                    .expect("nonzero"),
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
                    scheme: SignatureSchemeId::try_new(
                        support::FIXTURE_SIGNATURE_SCHEME_CODE_POINT,
                    )
                    .expect("nonzero"),
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
        scheme: SignatureSchemeId::try_new(support::FIXTURE_SIGNATURE_SCHEME_CODE_POINT)
            .expect("nonzero"),
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
                    scheme: SignatureSchemeId::try_new(
                        support::FIXTURE_SIGNATURE_SCHEME_CODE_POINT,
                    )
                    .expect("nonzero"),
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

#[test]
fn the_refusal_tally_is_stable_across_runs() {
    // "Refusal codes logged and stable" is two claims. Logging is
    // `log_tally`; this is stability, and it is asserted rather than assumed
    // because the campaign draws coordinated mutants from a generator, and a
    // generator seeded from anything ambient would make every run a different
    // experiment and every logged tally unfalsifiable.
    //
    // One vector rather than all nine: the property is a property of the
    // generator and the decoder, not of any particular corpus entry, and
    // running the full campaign twice would double the suite's cost to
    // re-prove the same thing eight more times.
    let cases = load_goldens();
    let canonical = canonical_bytes(&cases, "txn-seal__canonical");

    // The SAME name both times, and that is load-bearing rather than cosmetic:
    // the coordinated pass seeds its generator from `MULTI_BIT_SEED ^
    // seed_of(name)` so that different vectors draw different mutants. Passing
    // two distinct labels here — which the first version of this test did —
    // seeds two different generators and asserts a property that is both false
    // and undesirable, namely that campaigns with different seeds agree. The
    // claim worth making is that one campaign is reproducible.
    let first = campaign::<TransactionSealBody>("txn-seal", &canonical);
    let second = campaign::<TransactionSealBody>("txn-seal", &canonical);

    assert_eq!(
        first, second,
        "the campaign is not deterministic: two runs over identical bytes \
         produced different outcome tallies, so any logged tally is unfalsifiable"
    );
    assert!(
        first.keys().any(|key| key.starts_with("refused:")),
        "a stable tally of nothing would satisfy the equality above vacuously"
    );
    log_tally("txn-seal (reproduced)", &first);
}
