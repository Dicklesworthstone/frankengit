#![forbid(unsafe_code)]
//! FG-077a checkpoint identities pinned against a checked-in, independently
//! derived corpus rather than literals stored beside the implementation.

use std::collections::{BTreeMap, BTreeSet};

use fgit_raptorq::checkpoint::{CheckpointClass, CheckpointScope};

const VECTORS: &str = include_str!("../goldens/checkpoint_vectors.tsv");
const MARKER: &str = "# franken-registry-v1";
const HEADER: &str = "case_id\tdurable_class\tcanonical_body_hex\tcheckpoint_digest_hex";

#[derive(Debug)]
struct Vector<'a> {
    case_id: &'a str,
    class: CheckpointClass,
    body: Vec<u8>,
    expected_digest: &'a str,
}

fn decode_hex(value: &str, field: &str, line_number: usize) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "line {line_number}: {field} must contain complete hexadecimal octets"
    );

    value
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(offset, pair)| {
            let text = std::str::from_utf8(pair)
                .expect("TSV hex is ASCII because only byte pairs reach this parser");
            u8::from_str_radix(text, 16).unwrap_or_else(|_| {
                panic!("line {line_number}: {field} has invalid hex at byte offset {offset}")
            })
        })
        .collect()
}

fn checkpoint_class(value: &str, line_number: usize) -> CheckpointClass {
    match value {
        "DUR-012" => CheckpointClass::ForgeEvent,
        "DUR-014" => CheckpointClass::PolicyKey,
        _ => panic!("line {line_number}: unknown durable checkpoint class {value:?}"),
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vectors() -> Vec<Vector<'static>> {
    let mut lines = VECTORS.lines().enumerate();
    let (marker_line, marker) = lines.next().expect("vector corpus has a marker row");
    assert_eq!(marker, MARKER, "line {}: corpus marker", marker_line + 1);
    let (header_line, header) = lines.next().expect("vector corpus has a header row");
    assert_eq!(header, HEADER, "line {}: corpus header", header_line + 1);

    lines
        .filter_map(|(index, line)| {
            let line_number = index + 1;
            if line.is_empty() {
                return None;
            }

            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                4,
                "line {line_number}: expected case, class, body, and digest columns"
            );
            assert!(
                !fields[0].is_empty(),
                "line {line_number}: case identifier must not be empty"
            );
            assert_eq!(
                fields[3].len(),
                64,
                "line {line_number}: SHA-256 digest must have 64 hex characters"
            );

            let body = decode_hex(fields[2], "canonical_body_hex", line_number);
            assert!(
                !body.is_empty(),
                "line {line_number}: empty checkpoint bodies are outside this profile"
            );
            let _ = decode_hex(fields[3], "checkpoint_digest_hex", line_number);

            Some(Vector {
                case_id: fields[0],
                class: checkpoint_class(fields[1], line_number),
                body,
                expected_digest: fields[3],
            })
        })
        .collect()
}

#[test]
fn checkpoint_identity_vectors_match_the_public_checkpoint_scope() {
    let vectors = vectors();
    assert_eq!(
        vectors.len(),
        8,
        "the four corpus bodies must retain both durable classes"
    );

    let mut per_case = BTreeMap::<&str, BTreeMap<&str, String>>::new();
    let mut body_lengths = BTreeSet::new();
    for vector in vectors {
        let scope = CheckpointScope::from_canonical_bytes(vector.class, &vector.body)
            .expect("independent vector body must be within the published checkpoint envelope");
        let actual_digest = lowercase_hex(scope.checkpoint_digest());
        assert_eq!(
            actual_digest, vector.expected_digest,
            "{} {:?} identity drifted from the independent vector",
            vector.case_id, vector.class
        );

        body_lengths.insert(vector.body.len());
        let prior = per_case
            .entry(vector.case_id)
            .or_default()
            .insert(vector.class.durable_class(), actual_digest);
        assert!(
            prior.is_none(),
            "{} repeats a durable-class vector",
            vector.case_id
        );
    }

    assert_eq!(
        body_lengths,
        BTreeSet::from([1, 42, 128, 129]),
        "vectors must retain short, legacy, one-symbol, and one-symbol-plus-one lengths"
    );
    assert_eq!(per_case.len(), 4, "the corpus must retain every body case");
    for (case_id, identities) in per_case {
        assert_eq!(
            identities.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from(["DUR-012", "DUR-014"]),
            "{case_id} must retain both durable classes"
        );
        assert_ne!(
            identities
                .get("DUR-012")
                .expect("the durable-class denominator was just asserted"),
            identities
                .get("DUR-014")
                .expect("the durable-class denominator was just asserted"),
            "{case_id} must keep the two durable-class domains separated"
        );
    }
}
