// Round-trip and canonical-ordering properties.
//
// The sweeps are deterministic: one fixed seed, logged in every failure
// message together with the iteration and a digest of the input, so a failing
// case is reproducible from the log alone.

mod support;

use fgit_codec::schema::{
    RefusalRecordBody, RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecision,
    RepositoryDecisionBatchBody, TransactionSealBody,
};
use fgit_codec::wire::{CODEC_MAJOR, CODEC_MINOR, FRAME_MAGIC};
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, decode_body,
    decode_body_preserving, encode_body, encode_preserved,
};
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::numeric::{DecisionSequence, HeadGeneration, PolicyEpoch, RepositorySequence};
use fgit_types::{DecisionOutcome, DomainTag, RefusalCode, SchemaFamily, SchemaId};

use support::{CorpusDigest, SplitMix64, digest_of};

const SEED: u64 = 0x0c0d_ec00_5eed_0001;

fn fingerprint(bytes: &[u8]) -> String {
    use fgit_codec::attest::BodyDigest;
    CorpusDigest.digest(bytes).to_string()
}

/// Encodes, decodes, and re-encodes, asserting both round-trip directions.
fn assert_round_trips<B>(label: &str, body: &B)
where
    B: CanonicalBody + PartialEq + std::fmt::Debug,
{
    let bytes =
        encode_body(body).unwrap_or_else(|refusal| panic!("{label}: encode failed with {refusal}"));
    let decoded = decode_body::<B>(&bytes, DecodeLimits::DEFAULT).unwrap_or_else(|refusal| {
        panic!(
            "{label}: decode failed with {refusal}; seed={SEED:#x} input={}",
            fingerprint(&bytes)
        )
    });
    assert_eq!(
        &decoded,
        body,
        "{label}: decode(encode(value)) must reproduce the value; seed={SEED:#x} input={}",
        fingerprint(&bytes)
    );
    let re_encoded = encode_body(&decoded)
        .unwrap_or_else(|refusal| panic!("{label}: re-encode failed with {refusal}"));
    assert_eq!(
        re_encoded,
        bytes,
        "{label}: encode(decode(bytes)) must reproduce the bytes; seed={SEED:#x} input={}",
        fingerprint(&bytes)
    );
}

#[test]
fn every_fixture_round_trips_in_both_directions() {
    assert_round_trips("txn-seal", &support::transaction_seal());
    assert_round_trips("rcr", &support::commit_record());
    assert_round_trips("decision-batch", &support::decision_batch());
    assert_round_trips("authority-head/genesis", &support::genesis_head());
    assert_round_trips("authority-head/advanced", &support::advanced_head());
    assert_round_trips("refusal-record", &support::refusal_record());
}

#[test]
fn a_seeded_corpus_of_generated_bodies_round_trips() {
    let mut rng = SplitMix64::new(SEED);
    for iteration in 0_u32..512 {
        let draw = rng.next_u64();
        let mut body = support::commit_record();
        body.repository_sequence = RepositorySequence::try_new(1 + (draw % 4096)).expect("nonzero");
        body.policy_epoch = PolicyEpoch::try_new(1 + (draw >> 20 & 0xff)).expect("nonzero");
        body.parent_rcr_id = if draw & 1 == 0 {
            None
        } else {
            Some(support::commit_id())
        };
        let fill = u8::try_from(draw & 0xff).expect("masked");
        body.ref_delta_root = digest_of(fill);
        assert_round_trips(&format!("generated/{iteration}"), &body);

        let mut head = support::advanced_head();
        head.generation = HeadGeneration::try_new(1 + (draw >> 8 & 0xffff)).expect("nonzero");
        head.latest_decision_sequence = if draw & 2 == 0 {
            None
        } else {
            Some(DecisionSequence::try_new(1 + (draw >> 32 & 0xffff)).expect("nonzero"))
        };
        head.last_checkpoint_id = if draw & 4 == 0 {
            None
        } else {
            Some(support::capsule_id())
        };
        assert_round_trips(&format!("generated-head/{iteration}"), &head);
    }
}

#[test]
fn both_terminal_outcomes_round_trip_inside_a_batch() {
    let mut batch = support::decision_batch();
    for code in [
        RefusalCode::ExpectedOldRefMismatch,
        RefusalCode::InternalInvariantBreach,
        RefusalCode::CanonicalBoundExceeded,
        RefusalCode::IntentExpired,
    ] {
        batch.decisions = vec![
            RepositoryDecision {
                tx_id: support::tx_id(),
                decision_sequence: DecisionSequence::FIRST,
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: support::commit_id(),
                },
            },
            RepositoryDecision {
                tx_id: support::tx_id(),
                decision_sequence: DecisionSequence::try_new(2).expect("nonzero"),
                outcome: DecisionOutcome::Refused {
                    code,
                    refusal_record_id: support::refusal_record_id(),
                },
            },
        ];
        assert_round_trips(&format!("batch/{}", code.as_str()), &batch);
    }
}

#[test]
fn shuffling_a_canonical_set_never_changes_the_bytes() {
    // The acceptance property: logically identical input in any order must
    // produce one byte string.
    let mut rng = SplitMix64::new(SEED ^ 0xa5a5_a5a5_a5a5_a5a5);
    let values: Vec<u64> = (1..=64).collect();

    let canonical = {
        let mut encoder = Encoder::new();
        encoder
            .write_canonical_set("sweep", &values, |out, value| {
                out.write_scalar(*value);
                Ok(())
            })
            .expect("distinct values encode");
        encoder.into_bytes()
    };

    for iteration in 0_u32..256 {
        let mut shuffled = values.clone();
        rng.shuffle(&mut shuffled);
        let mut encoder = Encoder::new();
        encoder
            .write_canonical_set("sweep", &shuffled, |out, value| {
                out.write_scalar(*value);
                Ok(())
            })
            .expect("distinct values encode");
        let observed = encoder.into_bytes();
        assert_eq!(
            observed,
            canonical,
            "shuffled input produced different bytes; seed={:#x} iteration={iteration} order={shuffled:?}",
            SEED ^ 0xa5a5_a5a5_a5a5_a5a5
        );
    }
}

#[test]
fn shuffling_a_canonical_map_never_changes_the_bytes() {
    let mut rng = SplitMix64::new(SEED ^ 0x5a5a_5a5a_5a5a_5a5a);
    let entries: Vec<(u32, u64)> = (1_u32..=32).map(|key| (key, u64::from(key) * 7)).collect();

    let write = |input: &[(u32, u64)]| -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write_canonical_map(
                "sweep",
                input,
                |out, key| {
                    out.write_scalar(*key);
                    Ok(())
                },
                |out, value| {
                    out.write_scalar(*value);
                    Ok(())
                },
            )
            .expect("distinct keys encode");
        encoder.into_bytes()
    };

    let canonical = write(&entries);
    for iteration in 0_u32..128 {
        let mut shuffled = entries.clone();
        rng.shuffle(&mut shuffled);
        assert_eq!(
            write(&shuffled),
            canonical,
            "shuffled map produced different bytes; seed={:#x} iteration={iteration}",
            SEED ^ 0x5a5a_5a5a_5a5a_5a5a
        );
    }
}

#[test]
fn a_repeated_element_is_refused_and_a_distinct_one_is_not() {
    let mut encoder = Encoder::new();
    let refusal = encoder
        .write_canonical_set("dupes", &[7_u64, 9, 7], |out, value| {
            out.write_scalar(*value);
            Ok(())
        })
        .expect_err("a repeat has no canonical encoding");
    assert!(matches!(
        refusal,
        CodecRefusal::CollectionDuplicate { field: "dupes", .. }
    ));
    assert_eq!(
        refusal.refusal_code(),
        fgit_types::RefusalCode::CanonicalBoundExceeded
    );

    // Permitted counterpart: the same shape with distinct elements.
    let mut encoder = Encoder::new();
    assert!(
        encoder
            .write_canonical_set("dupes", &[7_u64, 9, 8], |out, value| {
                out.write_scalar(*value);
                Ok(())
            })
            .is_ok()
    );
}

#[test]
fn a_repeated_map_key_is_refused_and_a_distinct_one_is_not() {
    let mut encoder = Encoder::new();
    let refusal = encoder
        .write_canonical_map(
            "entries",
            &[(1_u32, 10_u64), (1_u32, 20_u64)],
            |out, key| {
                out.write_scalar(*key);
                Ok(())
            },
            |out, value| {
                out.write_scalar(*value);
                Ok(())
            },
        )
        .expect_err("one key cannot carry two values");
    assert!(matches!(
        refusal,
        CodecRefusal::CollectionDuplicate {
            field: "entries",
            ..
        }
    ));

    let mut encoder = Encoder::new();
    assert!(
        encoder
            .write_canonical_map(
                "entries",
                &[(1_u32, 10_u64), (2_u32, 20_u64)],
                |out, key| {
                    out.write_scalar(*key);
                    Ok(())
                },
                |out, value| {
                    out.write_scalar(*value);
                    Ok(())
                },
            )
            .is_ok()
    );
}

#[test]
fn a_set_that_arrives_out_of_order_is_refused_on_the_way_in() {
    // The encoder sorts, so this state can only arrive from a peer. Without
    // the decoder's check a peer could offer two byte strings for one value.
    let mut encoder = Encoder::new();
    encoder.write_scalar(2_u32);
    encoder.write_scalar(9_u64);
    encoder.write_scalar(7_u64);
    let descending = encoder.into_bytes();

    let mut decoder = Decoder::new(&descending, DecodeLimits::DEFAULT);
    let refusal = decoder
        .read_canonical_set("sweep", |input| input.read_scalar::<u64>("element"))
        .expect_err("descending order is not canonical");
    assert!(matches!(
        refusal,
        CodecRefusal::CollectionUnordered { field: "sweep", .. }
    ));

    // Permitted counterpart: the same two elements, ascending.
    let mut encoder = Encoder::new();
    encoder.write_scalar(2_u32);
    encoder.write_scalar(7_u64);
    encoder.write_scalar(9_u64);
    let ascending = encoder.into_bytes();
    let mut decoder = Decoder::new(&ascending, DecodeLimits::DEFAULT);
    assert_eq!(
        decoder
            .read_canonical_set("sweep", |input| input.read_scalar::<u64>("element"))
            .expect("ascending order is canonical"),
        vec![7_u64, 9]
    );
}

#[test]
fn scalar_widths_are_fixed_so_a_value_has_one_byte_string() {
    let mut encoder = Encoder::new();
    encoder.write_scalar(1_u8);
    encoder.write_scalar(1_u16);
    encoder.write_scalar(1_u32);
    encoder.write_scalar(1_u64);
    assert_eq!(
        encoder.as_bytes(),
        &[
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01
        ]
    );

    let mut encoder = Encoder::new();
    encoder.write_scalar(-1_i32);
    encoder.write_scalar(0_i32);
    encoder.write_scalar(1_i32);
    // Zigzag: 0 -> 0, -1 -> 1, 1 -> 2, all four bytes wide.
    assert_eq!(
        encoder.as_bytes(),
        &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        ]
    );
}

/// Builds a raw frame, for cases that must not go through [`encode_body`].
pub fn raw_frame(
    domain: DomainTag,
    family: SchemaFamily,
    schema_major: u16,
    schema_minor: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Encoder::new();
    frame.write_raw(&FRAME_MAGIC);
    frame.write_scalar(CODEC_MAJOR);
    frame.write_scalar(CODEC_MINOR);
    frame.write_domain_tag(domain).expect("label fits");
    frame
        .write_schema_id(SchemaId::new(family, schema_major, schema_minor))
        .expect("label fits");
    frame.write_bytes("payload", payload).expect("payload fits");
    frame.into_bytes()
}

#[test]
fn a_future_minor_is_readable_and_relayable_without_losing_identity() {
    // Forward direction: a body from a newer minor carries fields this build
    // does not know. It must still decode, and re-encoding must reproduce the
    // original bytes exactly, or relaying it would change its identity.
    let seal = support::transaction_seal();
    let mut payload = Encoder::new();
    seal.write_payload(&mut payload).expect("encodes");
    let mut payload = payload.into_bytes();
    payload.extend_from_slice(b"\x00\x00\x00\x04future");

    let future = raw_frame(
        TransactionSealBody::DOMAIN,
        TransactionSealBody::SCHEMA_FAMILY,
        TransactionSealBody::SCHEMA_MAJOR,
        TransactionSealBody::SCHEMA_MINOR + 1,
        &payload,
    );

    let decoded = decode_body_preserving::<TransactionSealBody>(&future, DecodeLimits::DEFAULT)
        .expect("a higher minor is additive and must decode");
    assert!(decoded.has_unknown_fields(), "the suffix must be preserved");
    assert_eq!(decoded.schema_minor, TransactionSealBody::SCHEMA_MINOR + 1);
    assert_eq!(decoded.body, seal, "the known fields must still be read");
    assert_eq!(
        encode_preserved(&decoded).expect("re-encodes"),
        future,
        "relaying a newer body must reproduce its bytes exactly"
    );

    // Reverse direction: at a minor this build implements, there is no
    // suffix, and a suffix there is a second byte string for one value.
    let same_minor = raw_frame(
        TransactionSealBody::DOMAIN,
        TransactionSealBody::SCHEMA_FAMILY,
        TransactionSealBody::SCHEMA_MAJOR,
        TransactionSealBody::SCHEMA_MINOR,
        &payload,
    );
    let refusal = decode_body_preserving::<TransactionSealBody>(&same_minor, DecodeLimits::DEFAULT)
        .expect_err("an unexplained suffix at a known minor is refused");
    assert!(matches!(refusal, CodecRefusal::TrailingBytes { .. }));

    // And the strict decoder refuses the future body outright, because it
    // cannot hand back a value that would re-encode to different bytes.
    let strict = decode_body::<TransactionSealBody>(&future, DecodeLimits::DEFAULT)
        .expect_err("the strict decoder must not silently drop unknown fields");
    assert!(matches!(strict, CodecRefusal::TrailingBytes { .. }));

    // Permitted counterpart: the same body at this build's own minor.
    assert!(
        decode_body::<TransactionSealBody>(
            &encode_body(&seal).expect("encodes"),
            DecodeLimits::DEFAULT
        )
        .is_ok()
    );
}

#[test]
fn digest_bodies_of_different_lengths_stay_distinguishable() {
    let short = Digest::new(
        support::algorithm(),
        DigestBytes::try_new(&[0x01; 16]).expect("16 bytes"),
    );
    let long = Digest::new(
        support::algorithm(),
        DigestBytes::try_new(&[0x01; 32]).expect("32 bytes"),
    );
    let mut encoder = Encoder::new();
    encoder.write_digest(&short).expect("encodes");
    let short_bytes = encoder.into_bytes();
    let mut encoder = Encoder::new();
    encoder.write_digest(&long).expect("encodes");
    let long_bytes = encoder.into_bytes();
    assert_ne!(short_bytes, long_bytes);
    assert!(!long_bytes.starts_with(&short_bytes));
}

#[test]
fn a_refusal_record_at_the_detail_bound_encodes_and_one_byte_over_does_not() {
    let mut record = support::refusal_record();
    record.detail = "d".repeat(fgit_codec::MAX_REFUSAL_DETAIL_LEN);
    assert_round_trips("refusal-record/at-bound", &record);

    record.detail = "d".repeat(fgit_codec::MAX_REFUSAL_DETAIL_LEN + 1);
    let refusal = encode_body(&record).expect_err("one byte over the bound is refused");
    assert!(matches!(
        refusal,
        CodecRefusal::ValueUnrepresentable {
            field: "RefusalRecordBody.detail",
            ..
        }
    ));
}

#[test]
fn unused_schema_types_are_exercised_so_the_suite_covers_them() {
    // Keeps the imports honest: every identity-bearing schema is referenced.
    let _: RepositoryAuthorityHeadBody = support::genesis_head();
    let _: RepositoryCommitRecord = support::commit_record();
    let _: RepositoryDecisionBatchBody = support::decision_batch();
    let _: RefusalRecordBody = support::refusal_record();
    let _: TransactionSealBody = support::transaction_seal();
}
