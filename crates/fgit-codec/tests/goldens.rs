// The golden corpus.
//
// The committed bytes were derived from the written format specification by a
// second implementation, not emitted by the encoder under test, so agreement
// here is agreement between two independent readings of the spec rather than
// the encoder confirming itself. The suite only ever reads the corpus; it
// never rewrites it.

use fgit_codec::harness as support;

use fgit_codec::attest::{BodyIdentity, SignedEnvelopeBody, body_id_of_frame};
use fgit_codec::schema::{
    RefusalRecordBody, RepositoryAuthorityHeadBody, RepositoryCommitRecord,
    RepositoryDecisionBatchBody, TransactionSealBody,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, canonical_body_bytes, decode_body, encode_body,
};

use fgit_codec::harness::{CorpusIdentity, GoldenCase, corpus_digest, load_goldens};

/// Decodes one golden and re-encodes it, asserting the bytes are reproduced.
fn round_trip<B: CanonicalBody + PartialEq + std::fmt::Debug>(case: &GoldenCase) {
    let decoded = decode_body::<B>(&case.bytes, DecodeLimits::DEFAULT)
        .unwrap_or_else(|refusal| panic!("{}: golden must decode, got {refusal}", case.name));
    let re_encoded = encode_body(&decoded).unwrap_or_else(|refusal| {
        panic!("{}: decoded golden must encode, got {refusal}", case.name)
    });
    assert_eq!(
        re_encoded, case.bytes,
        "{}: encode(decode(bytes)) must reproduce the golden bytes",
        case.name
    );
    if let Some(expected) = case.canonical_body_len {
        let payload = canonical_body_bytes(&decoded).expect("payload encodes");
        assert_eq!(
            payload.len(),
            expected,
            "{}: canonical body length disagrees with the corpus",
            case.name
        );
    }
}

/// Asserts the recorded identity is what the corpus digest produces.
fn check_body_id(case: &GoldenCase) {
    let Some(expected) = case.body_id.as_ref() else {
        // A malformed frame has no well-defined identity, so a planted defect
        // legitimately carries no `body_id` line. A VALID vector always does,
        // and the skip must not cover that case: an unconditional early return
        // means a valid golden whose `body_id` line was lost -- by a hand edit
        // or a regeneration bug -- stops being identity-checked while this
        // suite keeps reporting green. The check would silently stop checking.
        assert_ne!(
            case.kind, "valid",
            "{}: a valid golden must record the identity its bytes produce; without it this \
             check silently does nothing",
            case.name
        );
        return;
    };
    let observed = body_id_of_frame(&CorpusIdentity, &case.bytes, DecodeLimits::DEFAULT)
        .unwrap_or_else(|refusal| panic!("{}: identity must compute, got {refusal}", case.name));
    assert_eq!(
        &observed.to_string(),
        expected,
        "{}: recorded identity disagrees with the identity of these bytes",
        case.name
    );
}

fn dispatch_valid(case: &GoldenCase) {
    match case.schema.as_str() {
        "txn-seal" => round_trip::<TransactionSealBody>(case),
        "rcr" => round_trip::<RepositoryCommitRecord>(case),
        "decision-batch" => round_trip::<RepositoryDecisionBatchBody>(case),
        "authority-head" => round_trip::<RepositoryAuthorityHeadBody>(case),
        "refusal-record" => round_trip::<RefusalRecordBody>(case),
        "signed-envelope" => round_trip::<SignedEnvelopeBody>(case),
        other => panic!("{}: unknown schema {other:?}", case.name),
    }
    check_body_id(case);
}

fn dispatch_invalid(case: &GoldenCase) -> CodecRefusal {
    let limits = DecodeLimits::DEFAULT;
    let refusal = match case.schema.as_str() {
        "txn-seal" => decode_body::<TransactionSealBody>(&case.bytes, limits).err(),
        "rcr" => decode_body::<RepositoryCommitRecord>(&case.bytes, limits).err(),
        "decision-batch" => decode_body::<RepositoryDecisionBatchBody>(&case.bytes, limits).err(),
        "authority-head" => decode_body::<RepositoryAuthorityHeadBody>(&case.bytes, limits).err(),
        "refusal-record" => decode_body::<RefusalRecordBody>(&case.bytes, limits).err(),
        "signed-envelope" => decode_body::<SignedEnvelopeBody>(&case.bytes, limits).err(),
        other => panic!("{}: unknown schema {other:?}", case.name),
    };
    refusal.unwrap_or_else(|| {
        panic!(
            "{}: planted defect {:?} decoded successfully",
            case.name,
            case.mutation.as_deref().unwrap_or("unnamed")
        )
    })
}

#[test]
fn the_corpus_covers_every_identity_bearing_schema() {
    let cases = load_goldens();
    let mut schemas: Vec<&str> = cases
        .iter()
        .filter(|case| case.kind == "valid")
        .map(|case| case.schema.as_str())
        .collect();
    schemas.sort_unstable();
    schemas.dedup();
    assert_eq!(
        schemas,
        vec![
            "authority-head",
            "decision-batch",
            "rcr",
            "refusal-record",
            "signed-envelope",
            "txn-seal",
        ],
        "every identity-bearing schema needs at least one canonical golden"
    );
}

#[test]
fn every_valid_schema_has_at_least_three_planted_defects() {
    let cases = load_goldens();
    for valid in cases.iter().filter(|case| case.kind == "valid") {
        let planted = cases
            .iter()
            .filter(|case| case.kind == "invalid" && case.name.starts_with(&valid.name))
            .count();
        assert!(
            planted >= 3,
            "{}: only {planted} planted defects; the corpus requires at least three",
            valid.name
        );
    }
}

#[test]
fn every_valid_golden_round_trips_byte_for_byte() {
    let cases = load_goldens();
    let mut checked = 0;
    for case in cases.iter().filter(|case| case.kind == "valid") {
        dispatch_valid(case);
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected a golden per schema, checked {checked}"
    );
}

#[test]
fn every_planted_defect_is_refused_with_the_recorded_reason() {
    let cases = load_goldens();
    let mut checked = 0;
    for case in cases.iter().filter(|case| case.kind == "invalid") {
        let refusal = dispatch_invalid(case);
        let expected = case
            .expect
            .as_deref()
            .unwrap_or_else(|| panic!("{}: invalid golden has no expected reason", case.name));
        assert_eq!(
            refusal.kind(),
            expected,
            "{}: refused for the wrong reason ({refusal})",
            case.name
        );
        checked += 1;
    }
    assert!(
        checked >= 18,
        "expected many planted defects, checked {checked}"
    );
}

#[test]
fn the_encoder_reproduces_the_independently_derived_bytes() {
    // The strongest check in the suite: fixtures rebuilt here in Rust must
    // encode to exactly the bytes the second implementation produced.
    let cases = load_goldens();
    let expect = |name: &str| -> Vec<u8> {
        cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("missing golden {name}"))
            .bytes
            .clone()
    };

    assert_eq!(
        encode_body(&support::transaction_seal()).expect("encodes"),
        expect("txn-seal__canonical")
    );
    assert_eq!(
        encode_body(&support::commit_record()).expect("encodes"),
        expect("rcr__canonical")
    );
    assert_eq!(
        encode_body(&support::decision_batch()).expect("encodes"),
        expect("decision-batch__canonical")
    );
    assert_eq!(
        encode_body(&support::genesis_head()).expect("encodes"),
        expect("authority-head__genesis")
    );
    assert_eq!(
        encode_body(&support::advanced_head()).expect("encodes"),
        expect("authority-head__advanced")
    );
    assert_eq!(
        encode_body(&support::refusal_record()).expect("encodes"),
        expect("refusal-record__canonical")
    );
}

#[test]
fn a_signature_never_changes_the_body_it_signs() {
    // The signed-envelope convention, checked against the corpus: three
    // envelopes carrying the same body with zero, one, and two signatures must
    // agree on the carried body's bytes and on its identity, while differing
    // from each other as envelopes.
    let cases = load_goldens();
    let envelope = |name: &str| -> SignedEnvelopeBody {
        let case = cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("missing golden {name}"));
        decode_body::<SignedEnvelopeBody>(&case.bytes, DecodeLimits::DEFAULT)
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"))
    };

    let unsigned = envelope("signed-envelope__unsigned");
    let single = envelope("signed-envelope__one-signature");
    let double = envelope("signed-envelope__two-signatures");

    assert_eq!(unsigned.signatures().len(), 0);
    assert_eq!(single.signatures().len(), 1);
    assert_eq!(double.signatures().len(), 2);

    assert_eq!(
        unsigned.body_frame(),
        single.body_frame(),
        "attaching a signature must not touch the carried body's bytes"
    );
    assert_eq!(
        single.body_frame(),
        double.body_frame(),
        "attaching a second signature must not touch the carried body's bytes"
    );

    let identity = |envelope: &SignedEnvelopeBody| {
        envelope
            .carried_body_id(&CorpusIdentity, DecodeLimits::DEFAULT)
            .expect("identity computes")
    };
    assert_eq!(identity(&unsigned), identity(&single));
    assert_eq!(identity(&single), identity(&double));

    // The carried body is the seal, and its identity is the same value the
    // seal's own golden records.
    let seal = cases
        .iter()
        .find(|case| case.name == "txn-seal__canonical")
        .expect("seal golden");
    assert_eq!(
        identity(&unsigned).to_string(),
        seal.body_id
            .clone()
            .expect("seal golden records an identity")
    );
    assert_eq!(
        unsigned
            .carried_body::<TransactionSealBody>(DecodeLimits::DEFAULT)
            .expect("carried body decodes"),
        support::transaction_seal()
    );

    // The envelopes themselves differ, so a signature is observable.
    let bytes = |envelope: &SignedEnvelopeBody| encode_body(envelope).expect("encodes");
    assert_ne!(bytes(&unsigned), bytes(&single));
    assert_ne!(bytes(&single), bytes(&double));
}

#[test]
fn the_corpus_identity_depends_on_every_byte_and_on_the_domain() {
    // A tripwire for the tripwire: if the corpus function ignored its input,
    // every identity assertion above would pass vacuously.
    let seal = canonical_body_bytes(&support::transaction_seal()).expect("encodes");
    let mut altered = seal.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;
    assert_ne!(
        corpus_digest(&seal).as_bytes(),
        corpus_digest(&altered).as_bytes(),
        "a one-bit change must change the digest"
    );
    assert_ne!(
        corpus_digest(&seal).as_bytes(),
        corpus_digest(&[]).as_bytes()
    );

    // The same bytes under two domains are two identities. This is the
    // property domain separation exists for, so the corpus must show it.
    let under_seal = CorpusIdentity
        .identify(
            TransactionSealBody::DOMAIN,
            TransactionSealBody::schema_id(),
            fgit_types::CANONICAL_CODEC_VERSION,
            &seal,
        )
        .expect("the corpus function knows every domain");
    let under_rcr = CorpusIdentity
        .identify(
            RepositoryCommitRecord::DOMAIN,
            RepositoryCommitRecord::schema_id(),
            fgit_types::CANONICAL_CODEC_VERSION,
            &seal,
        )
        .expect("the corpus function knows every domain");
    assert_ne!(under_seal, under_rcr);
    assert_ne!(under_seal.digest(), under_rcr.digest());
}

#[test]
fn a_bodys_identity_does_not_depend_on_its_transport_framing() {
    // Canonical body bytes exclude transport framing, so the identity computed
    // from a frame must equal the identity computed from the body alone.
    let seal = support::transaction_seal();
    let from_body = fgit_codec::body_id(&CorpusIdentity, &seal).expect("identity computes");
    let framed = encode_body(&seal).expect("encodes");
    let from_frame =
        body_id_of_frame(&CorpusIdentity, &framed, DecodeLimits::DEFAULT).expect("identity");
    assert_eq!(from_body, from_frame);

    // And the frame is strictly larger than what was identified.
    let payload = canonical_body_bytes(&seal).expect("encodes");
    assert!(framed.len() > payload.len());
}
