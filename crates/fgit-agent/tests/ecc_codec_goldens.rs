#![forbid(unsafe_code)]

//! frankengit-fg030b: an Evidence-Carrying Change round-trips through the
//! canonical codec, byte for byte, against a corpus this crate did not emit.
//!
//! The vectors under `tests/goldens/` were produced by `generate.py`, a second
//! implementation that reads the documented layout tables and cannot link a
//! Rust crate. That directory's `README.md` states exactly how far the
//! independence reaches and what it does not cover; this suite does not repeat
//! the stronger claim the `fgit-codec` corpus is entitled to.
//!
//! The suite only ever *reads* the corpus. Nothing here can rewrite a vector to
//! make itself pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fgit_agent::{
    EvidenceCarryingChange, EvidenceClass, IndependenceDimension, RequirementDisposition,
    classify_independence,
};
use fgit_codec::{CanonicalBody, DecodeLimits, canonical_body_bytes, decode_body, encode_body};

struct GoldenCase {
    name: String,
    kind: String,
    expect: Option<String>,
    frame_len: usize,
    canonical_body_len: usize,
    bytes: Vec<u8>,
}

fn goldens_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
}

fn parse_golden(path: &Path) -> GoldenCase {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{}: malformed line {line:?}", path.display()));
        fields.insert(key.trim(), value.trim());
    }
    let field = |key: &str| -> &str {
        fields
            .get(key)
            .unwrap_or_else(|| panic!("{}: missing field {key}", path.display()))
    };
    let hex = field("bytes");
    assert!(
        hex.len().is_multiple_of(2),
        "{}: odd-length hex",
        path.display()
    );
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|error| panic!("{}: bad hex: {error}", path.display()))
        })
        .collect::<Vec<u8>>();

    GoldenCase {
        name: path
            .file_stem()
            .expect("golden has a file stem")
            .to_string_lossy()
            .into_owned(),
        kind: field("kind").to_owned(),
        expect: fields.get("expect").map(|value| (*value).to_owned()),
        frame_len: field("frame_len").parse().expect("frame_len is a number"),
        canonical_body_len: field("canonical_body_len")
            .parse()
            .expect("canonical_body_len is a number"),
        bytes,
    }
}

fn load_goldens() -> Vec<GoldenCase> {
    let directory = goldens_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "golden")
        })
        .collect();
    paths.sort();
    paths.iter().map(|path| parse_golden(path)).collect()
}

/// The corpus must actually be on disk with both kinds in it.
///
/// Without this, a lost or renamed directory turns every loop below into a
/// no-op over an empty vector and the whole suite reports green while checking
/// nothing. A corpus that is missing its defects is the same failure in
/// miniature: the round-trip cases alone would pass against an encoder that
/// accepts anything.
#[test]
fn the_corpus_is_present_and_has_both_kinds() {
    let cases = load_goldens();
    assert_eq!(cases.len(), 11, "corpus size changed; update this count");

    let valid = cases.iter().filter(|case| case.kind == "valid").count();
    let defects = cases.iter().filter(|case| case.kind == "defect").count();
    assert_eq!(valid, 3, "expected 3 valid vectors");
    assert_eq!(defects, 8, "expected 8 planted defects");
    assert_eq!(valid + defects, cases.len(), "a case has an unknown kind");

    for case in &cases {
        assert_eq!(
            case.bytes.len(),
            case.frame_len,
            "{}: frame_len disagrees with the bytes",
            case.name
        );
        assert_eq!(
            case.kind == "defect",
            case.expect.is_some(),
            "{}: a defect states its refusal and a valid vector does not",
            case.name
        );
    }
}

/// Every valid vector decodes, and re-encoding reproduces its bytes exactly.
#[test]
fn valid_goldens_round_trip_byte_for_byte() {
    let cases = load_goldens();
    let mut checked = 0;
    for case in cases.iter().filter(|case| case.kind == "valid") {
        let decoded = decode_body::<EvidenceCarryingChange>(&case.bytes, DecodeLimits::DEFAULT)
            .unwrap_or_else(|refusal| panic!("{}: must decode, got {refusal}", case.name));

        let re_encoded = encode_body(&decoded)
            .unwrap_or_else(|refusal| panic!("{}: must re-encode, got {refusal}", case.name));
        assert_eq!(
            re_encoded, case.bytes,
            "{}: encode(decode(bytes)) must reproduce the corpus bytes",
            case.name
        );

        let payload = canonical_body_bytes(&decoded).expect("payload encodes");
        assert_eq!(
            payload.len(),
            case.canonical_body_len,
            "{}: payload length disagrees with the corpus",
            case.name
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "every valid vector must have been exercised");
}

/// Every planted defect is refused, with the refusal the corpus names.
///
/// The refusal *kind* is asserted, not merely that decoding failed: an
/// `is_err()` check cannot tell a domain mismatch from a truncated payload, so
/// it would stay green if one guard started doing the other's job.
#[test]
fn planted_defects_are_refused_with_the_named_refusal() {
    let cases = load_goldens();
    let mut checked = 0;
    for case in cases.iter().filter(|case| case.kind == "defect") {
        let expected = case.expect.as_deref().expect("a defect names its refusal");
        let refusal = decode_body::<EvidenceCarryingChange>(&case.bytes, DecodeLimits::DEFAULT)
            .expect_err(&format!("{}: must be refused, but it decoded", case.name));

        let actual = format!("{refusal:?}");
        let variant = actual
            .split(['{', '('])
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        assert_eq!(
            variant, expected,
            "{}: expected {expected}, got {actual}",
            case.name
        );
        checked += 1;
    }
    assert_eq!(checked, 8, "every planted defect must have been exercised");
}

/// The populated vector decodes to the values the corpus describes.
///
/// Byte equality alone would be satisfied by a decoder that produced the wrong
/// values and an encoder that made the same mistake in reverse. This pins the
/// meaning: in particular the requirement whose disposition is absent must
/// survive as a `None` in place, because §10.2 forbids a missing requirement
/// from disappearing.
#[test]
fn the_populated_vector_decodes_to_the_documented_values() {
    let case = load_goldens()
        .into_iter()
        .find(|case| case.name == "ecc__populated")
        .expect("the populated vector is in the corpus");
    let decoded = decode_body::<EvidenceCarryingChange>(&case.bytes, DecodeLimits::DEFAULT)
        .expect("populated vector decodes");

    assert_eq!(decoded.intent_run, 0x0A1B_2C3D);

    // One record per class, in EvidenceClass::ALL order.
    let classes: Vec<EvidenceClass> = decoded.evidence.iter().map(|r| r.class).collect();
    assert_eq!(classes, EvidenceClass::ALL.to_vec());

    assert_eq!(
        decoded.requirement_dispositions,
        vec![
            Some(RequirementDisposition::SatisfiedWithEvidence),
            None,
            Some(RequirementDisposition::PartiallySatisfied),
            Some(RequirementDisposition::NotApplicable),
            Some(RequirementDisposition::BlockedByRefusal),
            Some(RequirementDisposition::Unsatisfied),
        ],
        "the absent disposition must round-trip as an absence in position 1",
    );

    assert_eq!(decoded.non_claims, vec![0xC1, 0xC2]);

    // The second verifier shares the producer's workspace identity exactly, so
    // the corpus carries a real non-independent case and not only clean ones.
    assert_eq!(decoded.verifiers.len(), 2);
    assert!(decoded.verifiers[0].upheld);
    assert!(!decoded.verifiers[1].upheld);
    assert_ne!(
        decoded.verifiers[0].facts.workspace,
        decoded.producer.workspace
    );
    assert_eq!(
        decoded.verifiers[1].facts.workspace,
        decoded.producer.workspace
    );
    // Everything in this vector is reported; the unreported state has its own.
    for dimension in IndependenceDimension::ALL {
        assert!(decoded.producer.on(*dimension).is_some());
    }
}

/// The unreported vector decodes back to unreported, not to an identity.
///
/// Byte equality already forces the encoder and decoder to agree, but they
/// could agree on the wrong thing: a decoder that mapped an absent option to
/// some default identity, paired with an encoder that wrote that default back
/// out as absent, would round-trip perfectly while manufacturing independence
/// out of missing evidence. This pins the decoded values.
#[test]
fn the_unreported_vector_keeps_its_absences() {
    let case = load_goldens()
        .into_iter()
        .find(|case| case.name == "ecc__unreported_dimensions")
        .expect("the unreported vector is in the corpus");
    let decoded = decode_body::<EvidenceCarryingChange>(&case.bytes, DecodeLimits::DEFAULT)
        .expect("unreported vector decodes");

    // Producer: oracle and sponsor unreported, the other five stated.
    assert_eq!(decoded.producer.oracle, None);
    assert_eq!(decoded.producer.sponsor, None);
    for dimension in [
        IndependenceDimension::Workspace,
        IndependenceDimension::Credentials,
        IndependenceDimension::ModelHarness,
        IndependenceDimension::Context,
        IndependenceDimension::Human,
    ] {
        assert!(
            decoded.producer.on(dimension).is_some(),
            "{dimension} was stated and must survive as stated",
        );
    }

    // Verifier: human unreported.
    let verifier = &decoded.verifiers[0];
    assert_eq!(verifier.facts.human, None);

    // And the whole point: that absence defeats independence.
    let classification = classify_independence(&decoded.producer, verifier);
    assert!(!classification.is_fully_independent());
    assert!(classification.is_unreported_on(IndependenceDimension::Human));
    assert!(classification.is_unreported_on(IndependenceDimension::Oracle));
    assert!(classification.is_independent_on(IndependenceDimension::Workspace));
}

/// The domain tag and schema identifier are what the corpus was framed under.
#[test]
fn the_body_declares_its_own_domain_and_schema() {
    assert_eq!(
        EvidenceCarryingChange::DOMAIN.as_str(),
        "frankengit/evidence-carrying-change/v1"
    );
    assert_eq!(
        EvidenceCarryingChange::SCHEMA_FAMILY.as_str(),
        "evidence-carrying-change"
    );
    assert_eq!(EvidenceCarryingChange::SCHEMA_MAJOR, 1);
}
