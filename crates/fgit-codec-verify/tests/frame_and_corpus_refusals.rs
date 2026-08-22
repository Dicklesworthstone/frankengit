#![forbid(unsafe_code)]
//! The independent oracle's own refusals, named and discriminated
//! (`frankengit-3o87`).
//!
//! **Nothing in the tree named any `VerifyError` variant.** `tests/corpus.rs`
//! has 13 thoughtful tests, but every refusal assertion in it is
//! `parse_frame(..).is_err()`.
//!
//! # Why "it refused" is not enough *here*
//!
//! This crate is the independent oracle. Its own doc says it exists to
//! disagree with `fgit-codec` when one of them is wrong, and deliberately does
//! not mirror that crate's refusal taxonomy, because matching taxonomies would
//! be a way of sharing a bug. `scripts/e2e/suites/codec/codec_adversarial.sh`
//! enforces that independence structurally: it scans the whole manifest for any
//! `fgit-` mention other than this crate's own name *and* checks the resolved
//! lockfile entry, because the crate has no `[dependencies]` section at all.
//!
//! For an oracle, "it refused" and "it refused for the right reason" are
//! different claims. `is_err()` cannot tell one guard from another, so a defect
//! caught by a guard unrelated to the planted defect is indistinguishable from
//! a correct rejection, and a guard that silently subsumes another is
//! invisible.
//!
//! `VerifyError` is deliberately coarse — three variants — so **the detail
//! string is the discriminator**, and asserting it is the only way to say which
//! guard fired.
//!
//! # A concrete instance, not a hypothetical
//!
//! `a_frame_with_a_lying_length_prefix_is_rejected` in `tests/corpus.rs`
//! inflates a payload length prefix to `u32::MAX` and asserts `is_err()` with
//! the stated reason "must be refused before allocating". Two different guards
//! can refuse that input: the bound check in `take_bytes`, and the
//! declared-versus-remaining slice check below it. Its sibling case deflates
//! the prefix to zero, intending the *trailing bytes* guard, with the same gap.
//! Both are pinned to a named guard below, so those comments become verified
//! statements rather than intentions.
//!
//! # Measured: what `is_err()` can and cannot see
//!
//! Two mutations, each `cargo check`ed first, and the contrast between them is
//! the finding:
//!
//! ```text
//! A: the MAX_FRAME bound in take_bytes DELETED, so an absurd declared length
//!    is still refused -- by the slice check below it, for a different reason
//!      tests/corpus.rs (13 tests)   13 passed  0 failed   COMPLETELY BLIND
//!      this file                    21 passed  2 failed   caught it
//!
//! B: the trailing-bytes guard weakened, so trailing bytes are ACCEPTED
//!      tests/corpus.rs (13 tests)   11 passed  2 failed   caught it
//!      this file                    20 passed  3 failed   caught it
//! ```
//!
//! Under A the crate still refuses every input it refused before, so no
//! `is_err()` assertion anywhere notices that the guard which exists to stop a
//! corrupt length *before* the slice is gone. That includes
//! `a_frame_with_a_lying_length_prefix_is_rejected`, whose own comment says the
//! input "must be refused before allocating" -- the property it names is the
//! one A removes, and it stays green.
//!
//! Under B the input is no longer refused at all, and the existing suite
//! catches it immediately.
//!
//! **That is the whole distinction**: an `is_err()` corpus measures *whether*
//! input is refused, and is blind to *which guard* refused it. For an oracle
//! whose purpose is to disagree for a stated reason, the second is the claim.
//!
//! # Non-claims
//!
//! This tests the **verifier**, not `fgit-codec`. Making the oracle's refusals
//! discriminated says nothing about whether the codec is correct; it says the
//! oracle can be trusted to disagree for a stated reason. Nothing here imports
//! another `fgit-` crate, and nothing here modifies
//! `crates/fgit-codec-verify/src/**`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use fgit_codec_verify::{VerifyError, default_corpus_directory, load_corpus, parse_frame};

/// Mirrors the crate-private `MAX_FRAME`. If that bound ever moves, the two
/// boundary tests below fail and say so, which is the point of restating it.
const MAX_FRAME: usize = 1 << 20;

const MAGIC: &[u8; 4] = b"FGC1";

// ---------------------------------------------------------------------------
// Building frames, so every refusal is a ONE-FIELD departure from one that
// parses.
// ---------------------------------------------------------------------------

fn push_length_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("test values fit in u32");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
}

fn frame_bytes(
    codec_major: u16,
    domain: &[u8],
    family: &[u8],
    schema_major: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&codec_major.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes()); // codec minor
    push_length_prefixed(&mut out, domain);
    push_length_prefixed(&mut out, family);
    out.extend_from_slice(&schema_major.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes()); // schema minor
    push_length_prefixed(&mut out, payload);
    out
}

fn conforming_frame() -> Vec<u8> {
    frame_bytes(1, b"txn", b"seal", 1, b"payload-bytes")
}

/// Everything before the payload's own length prefix: magic, codec version,
/// two length-prefixed labels, and the schema version.
const fn header_len(domain: &[u8], family: &[u8]) -> usize {
    4 + 2 + 2 + (4 + domain.len()) + (4 + family.len()) + 2 + 2 + 4
}

/// The refusal detail, or a panic naming what came back instead.
#[track_caller]
fn frame_refusal(bytes: &[u8], what: &str) -> String {
    match parse_frame(bytes) {
        Err(VerifyError::Frame(detail)) => detail,
        Err(other) => panic!("{what}: expected a Frame refusal, got {other:?}"),
        Ok(frame) => panic!("{what}: expected a refusal, but it parsed as {frame:?}"),
    }
}

#[track_caller]
fn corpus_refusal(directory: &Path, what: &str) -> String {
    match load_corpus(directory) {
        Err(VerifyError::Corpus(detail)) => detail,
        Err(other) => panic!("{what}: expected a Corpus refusal, got {other:?}"),
        Ok(records) => panic!(
            "{what}: expected a refusal, loaded {} records",
            records.len()
        ),
    }
}

fn scratch_corpus(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fgit-codec-verify-3o87-{}-{tag}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create scratch corpus");
    root
}

/// A golden that loads, so each corpus refusal below is a one-line departure.
fn write_golden(directory: &Path, name: &str, body: &str) {
    fs::write(directory.join(format!("{name}.golden")), body).expect("write golden");
}

fn conforming_golden_body() -> String {
    let hex: String = conforming_frame()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("# a comment line is skipped\nschema = txn-seal\nkind = valid\nbytes = {hex}\n")
}

// ---------------------------------------------------------------------------
// The permitted direction, built first
// ---------------------------------------------------------------------------

#[test]
fn a_conforming_frame_parses_and_every_field_round_trips() {
    let frame = parse_frame(&conforming_frame()).expect("the fixture must parse");
    assert_eq!(frame.codec_major, 1);
    assert_eq!(frame.codec_minor, 0);
    assert_eq!(frame.domain, "txn");
    assert_eq!(frame.family, "seal");
    assert_eq!(frame.schema_major, 1);
    assert_eq!(frame.schema_minor, 0);
    assert_eq!(frame.payload, b"payload-bytes");
}

// ---------------------------------------------------------------------------
// Every parse_frame guard, named by the detail it carries
// ---------------------------------------------------------------------------

#[test]
fn bytes_shorter_than_the_magic_are_refused_as_such() {
    for length in 0..4_usize {
        let detail = frame_refusal(&conforming_frame()[..length], "short input");
        assert_eq!(
            detail, "shorter than the magic",
            "{length} bytes cannot even carry the magic"
        );
    }
}

/// The boundary of the guard above: exactly four bytes *do* carry the magic,
/// so a correct magic of exactly four bytes gets past it and is refused by the
/// next guard instead. Without this, the test above would also pass against a
/// reader that rejected every short input for the same reason.
#[test]
fn exactly_the_magic_gets_past_the_length_guard_and_fails_at_the_next_one() {
    let detail = frame_refusal(MAGIC, "magic only");
    assert_eq!(detail, "truncated u16 at 4");
}

#[test]
fn a_frame_whose_magic_is_not_the_format_is_refused_as_bad_magic() {
    let mut bytes = conforming_frame();
    bytes[0] = b'X';
    let detail = frame_refusal(&bytes, "corrupt magic");
    assert!(
        detail.starts_with("bad magic"),
        "the refusal must name the magic it saw, got {detail:?}"
    );
}

#[test]
fn a_codec_major_this_reader_does_not_implement_is_refused_by_number() {
    let bytes = frame_bytes(2, b"txn", b"seal", 1, b"payload-bytes");
    let detail = frame_refusal(&bytes, "bumped codec major");
    assert_eq!(detail, "codec major 2 is not 1");
}

#[test]
fn a_truncated_length_prefix_names_the_offset_it_stopped_at() {
    // Cut inside the domain label's u32 length prefix, which begins at 8.
    let bytes = conforming_frame();
    let detail = frame_refusal(&bytes[..10], "cut inside a u32");
    assert_eq!(detail, "truncated u32 at 8");
}

/// **The bound guard.** A declared length over `MAX_FRAME` is refused by the
/// bound, before anything looks at what actually remains.
#[test]
fn a_declared_length_over_the_bound_is_refused_by_the_bound() {
    let mut bytes = conforming_frame();
    let over = u32::try_from(MAX_FRAME + 1).expect("fits");
    bytes[8..12].copy_from_slice(&over.to_be_bytes());
    let detail = frame_refusal(&bytes, "domain length over the bound");
    assert_eq!(detail, format!("length {} over the bound", MAX_FRAME + 1));
}

/// **A different guard, and this is the pairing that matters.** A declared
/// length *within* the bound but past the end of the input is refused by the
/// slice check, which reports what actually remains.
///
/// Paired with the test above so the two are shown to be distinguishable: an
/// `is_err()` assertion cannot tell them apart, and a change that let the bound
/// guard swallow this case would be invisible without both.
#[test]
fn a_declared_length_within_the_bound_but_past_the_end_reports_what_remains() {
    let mut bytes = conforming_frame();
    let within_bound = 1_000_u32;
    bytes[8..12].copy_from_slice(&within_bound.to_be_bytes());
    let detail = frame_refusal(&bytes, "domain length past the end");
    let remaining = bytes.len() - 12;
    assert_eq!(
        detail,
        format!("declared 1000 bytes at 12 but only {remaining} remain")
    );
}

#[test]
fn a_label_that_is_not_text_is_refused_as_such() {
    // 0xff is never valid UTF-8 in any position.
    let bytes = frame_bytes(1, &[0xff, 0xfe], b"seal", 1, b"payload-bytes");
    let detail = frame_refusal(&bytes, "non-text label");
    assert_eq!(detail, "label is not text");
}

#[test]
fn trailing_bytes_after_the_payload_are_refused_and_counted() {
    let mut bytes = conforming_frame();
    bytes.extend_from_slice(b"xyz");
    let detail = frame_refusal(&bytes, "trailing bytes");
    assert_eq!(detail, "3 trailing bytes after the payload");
}

/// **The frame-length bound at its exact boundary, both directions.**
///
/// A frame of exactly `MAX_FRAME` bytes is admitted by the length guard; one
/// byte more is refused by it. The guard reads `>`, and a refusal-only probe
/// could not tell that from `>=`.
#[test]
fn the_frame_length_bound_admits_exactly_the_maximum_and_refuses_one_more() {
    let domain: &[u8] = b"txn";
    let family: &[u8] = b"seal";
    let payload_at_bound = vec![0_u8; MAX_FRAME - header_len(domain, family)];
    let at_bound = frame_bytes(1, domain, family, 1, &payload_at_bound);
    assert_eq!(at_bound.len(), MAX_FRAME);
    let frame = parse_frame(&at_bound).expect("a frame of exactly the bound is admissible");
    assert_eq!(frame.payload.len(), payload_at_bound.len());

    let mut payload_past_bound = payload_at_bound;
    payload_past_bound.push(0);
    let past_bound = frame_bytes(1, domain, family, 1, &payload_past_bound);
    assert_eq!(past_bound.len(), MAX_FRAME + 1);
    let detail = frame_refusal(&past_bound, "one byte past the bound");
    assert_eq!(detail, format!("frame of {} bytes", MAX_FRAME + 1));
}

// ---------------------------------------------------------------------------
// The discrimination the existing suite states but does not verify
// ---------------------------------------------------------------------------

/// The two lying-length-prefix cases from `tests/corpus.rs`, pinned to the
/// guard each one is *described* as testing.
///
/// Inflating to `u32::MAX` is refused by the bound ("before allocating", as
/// that test's comment says); shrinking to zero is refused because the payload
/// bytes become trailing bytes. Both assert `is_err()` there, which cannot
/// distinguish the two, so this is what makes those comments true.
#[test]
fn the_two_lying_length_prefixes_are_refused_by_two_different_guards() {
    let bytes = conforming_frame();
    let payload_len = b"payload-bytes".len();
    let prefix_at = bytes.len() - payload_len - 4;

    let mut inflated = bytes.clone();
    inflated[prefix_at..prefix_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        frame_refusal(&inflated, "inflated payload length"),
        format!("length {} over the bound", u32::MAX),
        "an absurd length is stopped by the bound, not by what remains"
    );

    let mut deflated = bytes;
    deflated[prefix_at..prefix_at + 4].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        frame_refusal(&deflated, "deflated payload length"),
        format!("{payload_len} trailing bytes after the payload"),
        "shrinking the payload leaves its bytes trailing"
    );
}

// ---------------------------------------------------------------------------
// VerifyError::Corpus — the loader, which every corpus-driven test depends on
// ---------------------------------------------------------------------------

#[test]
fn a_directory_that_does_not_exist_is_a_corpus_fault() {
    let missing = std::env::temp_dir().join(format!(
        "fgit-codec-verify-3o87-{}-absent",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&missing);
    let detail = corpus_refusal(&missing, "absent directory");
    assert!(
        detail.starts_with(&missing.display().to_string()),
        "the refusal must name the directory it could not read, got {detail:?}"
    );
}

/// **Fails closed on an empty set.** This is the backstop that stops the whole
/// suite from passing over nothing, which is the defect class `f703e5c` fixed
/// in a different form.
#[test]
fn a_directory_with_no_goldens_fails_closed() {
    let directory = scratch_corpus("empty");
    assert_eq!(
        corpus_refusal(&directory, "empty directory"),
        "no golden files"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

/// The loader filters by extension, so a file that is not a `.golden` is
/// **silently skipped** — recorded here as behaviour rather than assumed. A
/// directory holding only such files is therefore empty as far as the loader
/// is concerned, and fails closed rather than loading nothing quietly.
#[test]
fn a_non_golden_file_is_skipped_and_leaves_the_set_empty() {
    let directory = scratch_corpus("skipped");
    fs::write(directory.join("notes.txt"), b"not a golden").expect("write");
    fs::write(directory.join("vector.golden.bak"), b"nor this").expect("write");
    assert_eq!(
        corpus_refusal(&directory, "only non-goldens"),
        "no golden files",
        "a directory of files the loader ignores is not a corpus"
    );

    // ...and with one real golden alongside them, exactly that one loads.
    write_golden(&directory, "vector", &conforming_golden_body());
    let records = load_corpus(&directory).expect("the one golden loads");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name, "vector");
    fs::remove_dir_all(&directory).expect("clean up");
}

/// The conforming golden loads, so each malformed case below is a one-line
/// departure from it.
#[test]
fn a_conforming_golden_loads_with_its_fields() {
    let directory = scratch_corpus("valid");
    write_golden(&directory, "vector", &conforming_golden_body());
    let records = load_corpus(&directory).expect("the golden loads");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].schema, "txn-seal");
    assert!(records[0].is_valid(), "kind = valid must read as valid");
    assert_eq!(
        parse_frame(&records[0].bytes)
            .expect("the recorded bytes parse")
            .domain,
        "txn"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

#[test]
fn a_line_without_a_separator_is_refused_and_quotes_the_line() {
    let directory = scratch_corpus("malformed-line");
    let body = format!("{}this line has no separator\n", conforming_golden_body());
    write_golden(&directory, "vector", &body);
    assert_eq!(
        corpus_refusal(&directory, "malformed line"),
        "vector: malformed line \"this line has no separator\"",
        "the refusal names the record and quotes the offending line"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

#[test]
fn an_unknown_key_is_refused_and_names_the_key() {
    let directory = scratch_corpus("unknown-key");
    let body = format!("{}surprise = 1\n", conforming_golden_body());
    write_golden(&directory, "vector", &body);
    assert_eq!(
        corpus_refusal(&directory, "unknown key"),
        "vector: unknown key \"surprise\"",
        "a corpus key the reader does not implement is refused, never ignored"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

/// The two numeric fields are **separate** refusals, so a reader that parsed
/// one into the other would be caught.
#[test]
fn the_two_numeric_fields_are_distinct_refusals() {
    let directory = scratch_corpus("bad-numbers");
    write_golden(
        &directory,
        "vector",
        &format!("{}frame_len = not-a-number\n", conforming_golden_body()),
    );
    assert_eq!(
        corpus_refusal(&directory, "bad frame_len"),
        "vector: bad frame_len"
    );

    write_golden(
        &directory,
        "vector",
        &format!(
            "{}canonical_body_len = not-a-number\n",
            conforming_golden_body()
        ),
    );
    assert_eq!(
        corpus_refusal(&directory, "bad canonical_body_len"),
        "vector: bad canonical_body_len"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

/// The two hex faults are **separate** refusals: a length fault is found
/// before any digit is examined.
#[test]
fn an_odd_hex_length_and_a_bad_hex_digit_are_distinct_refusals() {
    let directory = scratch_corpus("bad-hex");
    write_golden(
        &directory,
        "vector",
        "schema = txn-seal\nkind = valid\nbytes = abc\n",
    );
    assert_eq!(
        corpus_refusal(&directory, "odd hex length"),
        "vector: odd hex length"
    );

    write_golden(
        &directory,
        "vector",
        "schema = txn-seal\nkind = valid\nbytes = abcz\n",
    );
    assert_eq!(
        corpus_refusal(&directory, "bad hex digit"),
        "vector: bad hex digit"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

/// A golden that declares everything except the bytes is refused. Without this
/// the loader would hand back a record whose `bytes` is empty, and every
/// frame-level assertion downstream would run against nothing.
#[test]
fn a_golden_carrying_no_bytes_is_refused() {
    let directory = scratch_corpus("no-bytes");
    write_golden(&directory, "vector", "schema = txn-seal\nkind = valid\n");
    assert_eq!(
        corpus_refusal(&directory, "no bytes"),
        "vector: no bytes",
        "a record with no frame cannot verify anything"
    );
    fs::remove_dir_all(&directory).expect("clean up");
}

// ---------------------------------------------------------------------------
// The corpus's planted defects, refused for FOUR different reasons
// ---------------------------------------------------------------------------

/// `every_planted_defect_that_targets_the_frame_is_also_rejected_here` in
/// `tests/corpus.rs` asserts `is_err()` for four mutation classes at once.
/// That is true but weak: it would pass if all four collapsed onto one guard,
/// or if a class were caught by a guard unrelated to what it plants.
///
/// This asserts each class is refused by a **discriminator characteristic of
/// that class**, and that the four discriminators are pairwise distinct.
/// Added alongside that test, not in place of it: it still owns the "every
/// planted defect is rejected" claim, and the `checked` floor that keeps it
/// from passing over an empty corpus.
///
/// The mapping was **measured, not predicted** — the corpus is committed data
/// and a guessed discriminator would have been a guess about someone else's
/// fixtures.
#[test]
fn the_four_frame_level_defect_classes_are_refused_for_four_different_reasons() {
    let records = load_corpus(&default_corpus_directory()).expect("the corpus loads");

    // (planted mutation, the guard that must catch it)
    let expected = [
        ("magic_corrupted", "bad magic"),
        ("codec_major_bumped", "codec major"),
        ("payload_truncated", "declared"),
        ("trailing_byte_appended", "trailing bytes after the payload"),
    ];

    let mut checked = 0_usize;
    for (mutation, discriminator) in expected {
        let mut seen_for_this_class = 0_usize;
        for record in records.iter().filter(|record| !record.is_valid()) {
            if record.mutation.as_deref() != Some(mutation) {
                continue;
            }
            let detail = frame_refusal(&record.bytes, record.name.as_str());
            assert!(
                detail.contains(discriminator),
                "{}: a {mutation} defect must be caught by the {discriminator:?} guard, \
                 got {detail:?}",
                record.name
            );
            seen_for_this_class += 1;
            checked += 1;
        }
        assert!(
            seen_for_this_class > 0,
            "the corpus plants no {mutation} defect, so this class proves nothing"
        );
    }
    assert!(
        checked >= 20,
        "expected many planted defects, saw {checked}"
    );

    // The claim is DISCRIMINATION, so the four guards must differ from one
    // another. Four classes all reported by one string would satisfy every
    // assertion above and none of the intent.
    let discriminators: std::collections::BTreeSet<&str> =
        expected.iter().map(|(_, guard)| *guard).collect();
    assert_eq!(
        discriminators.len(),
        expected.len(),
        "the four classes must be told apart, not merely refused"
    );
}

/// The two defect classes a frame reader **cannot** judge still parse cleanly.
///
/// `tests/corpus.rs` states this in prose and asserts it for one example each.
/// It belongs next to the test above: it is what stops "refuse more" from
/// looking like an improvement. A reader learns the domain and the schema major
/// *from the frame*, so it has nothing to compare them against.
#[test]
fn the_two_defect_classes_a_frame_reader_cannot_judge_still_parse() {
    let records = load_corpus(&default_corpus_directory()).expect("the corpus loads");
    let mut checked = 0_usize;
    for record in records.iter().filter(|record| !record.is_valid()) {
        let Some(mutation) = record.mutation.as_deref() else {
            continue;
        };
        if mutation != "domain_swapped" && mutation != "schema_major_bumped" {
            continue;
        }
        assert!(
            parse_frame(&record.bytes).is_ok(),
            "{}: a {mutation} defect is well-formed at the frame level and must parse; \
             refusing it here would mean this reader invented an expectation",
            record.name
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "the corpus plants neither class, so this proves nothing"
    );
}
