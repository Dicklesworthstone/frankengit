#![forbid(unsafe_code)]
//! Deterministic, bounded adversarial coverage for every public object parser.
//!
//! This is intentionally a structured mutation campaign rather than a claim of
//! coverage-guided fuzzing.  Inputs are capped before they reach the parsers;
//! each parser surface is exercised under small, explicit resource ceilings.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use fgit_git_object::{
    AcceptanceProfile, InflateLimits, LooseObjectDecoder, ObjectError, ObjectType, ParseLimits,
    ZlibLooseObjectDecoder, parse_commit, parse_loose_framed, parse_object_body, parse_tag,
    parse_tree, parse_zlib_loose,
};

const CORPUS: &str = include_str!("corpus/adversarial-refusals.tsv");
const CORPUS_SCHEMA: &str = "frankengit.object-adversarial-refusal-corpus.v1";
const CAMPAIGN_SEED: u64 = 0x0f15_c0de_5eed_1234;
const MUTATIONS_PER_SEED: usize = 64;
const MAX_MUTATED_BYTES: usize = 96;

#[derive(Debug)]
struct CorpusRow {
    label: String,
    target: String,
    profile: AcceptanceProfile,
    limits: String,
    input: Vec<u8>,
    expected: String,
    classification: String,
    oracle_evidence: String,
}

fn parse_corpus() -> Vec<CorpusRow> {
    let mut schema_seen = false;
    let mut rows = Vec::new();

    for (line_number, line) in CORPUS.lines().enumerate() {
        if let Some(schema) = line.strip_prefix("# schema=") {
            assert_eq!(schema, CORPUS_SCHEMA, "corpus schema at line {line_number}");
            schema_seen = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 8, "corpus field count at line {line_number}");
        let profile = match fields[2] {
            "strict" => AcceptanceProfile::StrictCreate,
            "import" => AcceptanceProfile::GitCompatibleImport,
            other => panic!("unknown corpus profile {other} at line {line_number}"),
        };
        rows.push(CorpusRow {
            label: fields[0].to_owned(),
            target: fields[1].to_owned(),
            profile,
            limits: fields[3].to_owned(),
            input: decode_escaped(fields[4]).unwrap_or_else(|error| {
                panic!("invalid escaped input at line {line_number}: {error}")
            }),
            expected: fields[5].to_owned(),
            classification: fields[6].to_owned(),
            oracle_evidence: fields[7].to_owned(),
        });
    }

    assert!(schema_seen, "corpus must declare its schema");
    assert!(!rows.is_empty(), "corpus must contain at least one row");
    rows
}

fn decode_escaped(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        if byte != b'\\' {
            decoded.push(byte);
            index += 1;
            continue;
        }
        let escaped = *bytes
            .get(index + 1)
            .ok_or_else(|| "trailing escape".to_owned())?;
        match escaped {
            b'0' => decoded.push(0),
            b'n' => decoded.push(b'\n'),
            b'r' => decoded.push(b'\r'),
            b't' => decoded.push(b'\t'),
            b'\\' => decoded.push(b'\\'),
            b'x' => {
                let high = *bytes
                    .get(index + 2)
                    .ok_or_else(|| "incomplete hex escape".to_owned())?;
                let low = *bytes
                    .get(index + 3)
                    .ok_or_else(|| "incomplete hex escape".to_owned())?;
                decoded.push((hex_value(high)? << 4) | hex_value(low)?);
                index += 2;
            }
            other => return Err(format!("unsupported escape \\{}", char::from(other))),
        }
        index += 2;
    }
    Ok(decoded)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("non-hex byte {}", char::from(byte))),
    }
}

fn parse_limits(label: &str) -> ParseLimits {
    let mut limits = ParseLimits::default();
    match label {
        "default" => {}
        "object32" => limits.max_object_bytes = 32,
        "tree1" => limits.max_tree_entries = 1,
        "headers4" => limits.max_header_lines = 4,
        other => panic!("unknown corpus limits {other}"),
    }
    limits
}

fn execute_row(row: &CorpusRow) -> Result<(), ObjectError> {
    let limits = parse_limits(&row.limits);
    match row.target.as_str() {
        "loose" => parse_loose_framed(&row.input, limits).map(|_| ()),
        "tree" => parse_tree(&row.input, row.profile, &limits).map(|_| ()),
        "commit" => parse_commit(&row.input, row.profile, &limits).map(|_| ()),
        "tag" => parse_tag(&row.input, row.profile, &limits).map(|_| ()),
        "object-blob" => {
            parse_object_body(ObjectType::Blob, &row.input, row.profile, &limits).map(|_| ())
        }
        other => panic!("unknown corpus target {other}"),
    }
}

fn outcome<T>(result: Result<T, ObjectError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("{error:?}")
            .split(|byte: char| matches!(byte, ' ' | '{'))
            .next()
            .expect("Debug ObjectError name is nonempty")
            .to_owned(),
    }
}

#[test]
fn refusal_corpus_is_stable_and_surfaces_the_epoch_zero_divergence() {
    let rows = parse_corpus();
    let divergences: Vec<&CorpusRow> = rows
        .iter()
        .filter(|row| row.classification == "git_accepts_we_refuse")
        .collect();
    assert_eq!(
        divergences.len(),
        1,
        "the known Git acceptance divergence must stay classified, not disappear"
    );
    let epoch_zero = divergences[0];
    assert_eq!(epoch_zero.label, "epoch-zero-strict-divergence");
    assert_eq!(epoch_zero.expected, "MalformedSignatureDate");
    assert_eq!(
        epoch_zero.oracle_evidence,
        "git-2.54.0-fsck-strict-accepts:ad9ebc4102db7fd671a2fcdb2f7f1f62b7e90f60"
    );

    for row in &rows {
        let first = outcome(execute_row(row));
        assert_eq!(
            first, row.expected,
            "{} must preserve its classified outcome",
            row.label
        );
        for replay in 1..=3 {
            assert_eq!(
                outcome(execute_row(row)),
                first,
                "{} changed typed outcome on replay {replay}",
                row.label
            );
        }
    }
}

fn bounded_campaign_limits() -> ParseLimits {
    ParseLimits {
        max_object_bytes: 64,
        max_loose_header_bytes: 32,
        max_tree_entries: 2,
        max_header_lines: 4,
        max_header_line_bytes: 64,
        tree_reference_bytes: 20,
    }
}

fn bounded_inflate_limits() -> InflateLimits {
    let mut limits = InflateLimits::GIT_OBJECT;
    limits.max_input_bytes = 128;
    limits.max_pending_input_bytes = 128;
    limits.max_output_bytes = 128;
    limits.max_expansion_ratio = Some(16);
    limits.max_work_units = 4_096;
    limits
}

fn next_word(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut word = *state;
    word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}

fn campaign_inputs() -> Vec<Vec<u8>> {
    const SEEDS: &[&[u8]] = &[
        b"",
        b"blob 1\0x",
        b"blob 18446744073709551616\0",
        b"100644 name\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        b"tree 0000000000000000000000000000000000000000\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nm",
        b"object 0000000000000000000000000000000000000000\ntype commit\ntag v1\ntagger A <a@b> 1 +0000\n\nm",
        b"gpgsig first\n second\n third\n fourth\n fifth\n\nm",
        &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01],
    ];

    let mut inputs = Vec::with_capacity(SEEDS.len() * MUTATIONS_PER_SEED);
    for (seed_index, seed) in SEEDS.iter().enumerate() {
        let mut state = CAMPAIGN_SEED ^ u64::try_from(seed_index).expect("seed index fits u64");
        for mutation in 0..MUTATIONS_PER_SEED {
            let mut input = seed.to_vec();
            let word = next_word(&mut state);
            match mutation % 5 {
                0 => {
                    if input.is_empty() {
                        input.push(word.to_le_bytes()[0]);
                    } else {
                        let index = usize::try_from(word % input.len() as u64)
                            .expect("bounded index fits usize");
                        input[index] ^= word.to_le_bytes()[1];
                    }
                }
                1 => {
                    let length = usize::try_from(word % (input.len() as u64 + 1))
                        .expect("bounded length fits usize");
                    input.truncate(length);
                }
                2 => input.push(0),
                3 => {
                    let index = usize::try_from(word % (input.len() as u64 + 1))
                        .expect("bounded insertion index fits usize");
                    input.insert(index, b'\n');
                }
                _ => {
                    input.extend_from_slice(b"blob ");
                    input.extend_from_slice((word % 10_000).to_string().as_bytes());
                    input.push(0);
                }
            }
            input.truncate(MAX_MUTATED_BYTES);
            assert!(input.len() <= MAX_MUTATED_BYTES);
            inputs.push(input);
        }
    }
    inputs
}

fn exercise_all_parser_surfaces(input: &[u8], limits: &ParseLimits) -> usize {
    let inflate_limits = bounded_inflate_limits();
    let mut calls = 0;

    let _ = parse_loose_framed(input, limits.clone());
    calls += 1;

    let mut loose = LooseObjectDecoder::new(limits.clone());
    let mut loose_refused = false;
    for chunk in input.chunks(3) {
        if loose.push(chunk).is_err() {
            loose_refused = true;
            break;
        }
    }
    if !loose_refused {
        let _ = loose.finish();
    }
    calls += 1;

    let _ = parse_zlib_loose(input, inflate_limits, limits.clone());
    calls += 1;

    let mut zlib = ZlibLooseObjectDecoder::new(inflate_limits, limits.clone())
        .expect("bounded inflater configuration is valid");
    let mut zlib_refused = false;
    for chunk in input.chunks(5) {
        if zlib.push(chunk).is_err() {
            zlib_refused = true;
            break;
        }
    }
    if !zlib_refused {
        let _ = zlib.finish();
    }
    calls += 1;

    for profile in [
        AcceptanceProfile::StrictCreate,
        AcceptanceProfile::GitCompatibleImport,
    ] {
        let _ = parse_tree(input, profile, limits);
        let _ = parse_commit(input, profile, limits);
        let _ = parse_tag(input, profile, limits);
        calls += 3;
    }
    for object_type in [
        ObjectType::Blob,
        ObjectType::Tree,
        ObjectType::Commit,
        ObjectType::Tag,
    ] {
        let _ = parse_object_body(object_type, input, AcceptanceProfile::StrictCreate, limits);
        calls += 1;
    }
    calls
}

#[test]
fn deterministic_structured_campaign_has_no_panics_under_budgets() {
    let started = Instant::now();
    let inputs = campaign_inputs();
    assert_eq!(
        inputs,
        campaign_inputs(),
        "campaign seed must replay exactly"
    );

    let result = catch_unwind(AssertUnwindSafe(|| {
        let limits = bounded_campaign_limits();
        inputs
            .iter()
            .map(|input| exercise_all_parser_surfaces(input, &limits))
            .sum::<usize>()
    }));
    assert!(result.is_ok(), "a bounded parser campaign must not panic");
    let parser_calls = result.expect("checked above");
    assert!(parser_calls > 0, "campaign must execute parser calls");

    println!(
        "FG-015C-FUZZ-EVIDENCE schema=frankengit.object-fuzz-evidence.v1 corpus_rows={} campaign_inputs={} parser_calls={} duration_ms={} coverage=loose,streaming_loose,zlib,streaming_zlib,tree,commit,tag,generic_body bounded_input_bytes={}",
        parse_corpus().len(),
        inputs.len(),
        parser_calls,
        started.elapsed().as_millis(),
        MAX_MUTATED_BYTES,
    );
}
