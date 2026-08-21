#![forbid(unsafe_code)]
//! FG-019c: receive-pack advertisement, differentially against pinned upstream Git.
//!
//! The bridge half of `scripts/e2e/suites/wire/receivepack_differential.sh`.
//! It is `#[ignore]`d because it is meaningless without a corpus captured from
//! the sandboxed oracle; the suite supplies one through [`CORPUS_ENV`] and
//! reads the verdict back from [`OUTPUT_ENV`].
//!
//! ## Why this direction, and what it can actually decide
//!
//! FG-018c established the counterpart for `upload-pack`. This is the
//! `receive-pack` side of the same boundary: for one repository state, real
//! `git receive-pack --advertise-refs` and our [`advertise_receive_pack`] must
//! frame the same thing the same way.
//!
//! **Capabilities are expected to differ and that is not the finding.** Git
//! advertises what Git implements, including `agent=git/2.54.0-Linux`; we
//! advertise what we implement. A byte-equality assertion over the whole
//! advertisement would therefore be red for a reason that says nothing about
//! compatibility, and "fixing" it would mean copying Git's capability string
//! into our server — claiming support we do not have. So the capability section
//! is classified as an **accepted divergence with rationale**, and the
//! comparison is made over the part where agreement is a real obligation:
//!
//! * the pkt-line framing — the four-hex declared length must land exactly on
//!   the terminating flush, checked by reading what follows the packet rather
//!   than by re-deriving the length from the slice it produced;
//! * the pre-NUL segment `<oid> <refname>`, byte for byte;
//! * the position of the NUL that opens the capability section;
//! * the trailing LF, present or absent identically;
//! * the flush packet that terminates the advertisement.
//!
//! Those are exactly the cells where a client that talks to Git would break
//! against us. An off-by-one pkt length, a missing LF, a space where Git writes
//! NUL: each is invisible to any in-process test of ours and fatal on the wire.
//!
//! ## The empty-repository cell
//!
//! Git advertises a repository with no refs using the `capabilities^{}`
//! pseudo-ref against an all-zero object id, rather than inventing a branch.
//! [`advertise_receive_pack`] documents that it does the same. That claim is
//! checked here against what Git actually emits, because a documented
//! intention and an observed byte string are different kinds of evidence and
//! this file exists to convert the first into the second.
//!
//! ## Non-claims
//!
//! * **Advertisement only.** Nothing here pushes anything. Differential
//!   *push* behaviour — feeding one client's command stream and pack to both
//!   servers and comparing report-status — is a larger slice and is not
//!   attempted; this file must not be cited as evidence for it.
//! * Agreement with Git 2.54.0 is agreement with **one pinned version**, not
//!   with the protocol in general.
//! * The oracle is a sandboxed, pinned differential reference. No production
//!   path reaches it (AGENTS.md §3.1).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fgit_wire::receive::{
    ReceiveContext, ReceiveLimits, SignedPushProfile, advertise_receive_pack,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, WireLimits, encode_packets,
};

/// Where the suite leaves transcripts captured from the pinned oracle.
const CORPUS_ENV: &str = "FGIT_RECEIVEPACK_CORPUS_DIR";

/// Where this bridge writes our advertisement bytes and the verdict.
const OUTPUT_ENV: &str = "FGIT_RECEIVEPACK_OUTPUT_DIR";

/// The capability set this server actually implements.
///
/// Deliberately **not** Git's string. Advertising a capability we do not honour
/// would turn a differential test into a compatibility lie, which is the exact
/// failure this corpus is supposed to detect rather than commit.
const SERVER_CAPABILITIES: &[u8] = b"report-status delete-refs atomic ofs-delta object-format=sha1";

// ---------------------------------------------------------------------------
// A decomposed pkt-line advertisement
// ---------------------------------------------------------------------------

/// The first advertised ref, split at the boundaries a client parses on.
#[derive(Debug, Eq, PartialEq)]
struct RefLine {
    /// The four-hex length the sender declared.
    declared_len: usize,
    /// Whether everything after this packet is exactly a flush.
    ///
    /// This is how the declared length is checked **without circularity**. The
    /// payload is sliced *using* `declared_len`, so comparing it against a
    /// length derived from that same slice can only ever be true — an earlier
    /// version of this struct did exactly that and produced a cell that could
    /// not fail. Reading the remainder instead is independent: if the declared
    /// length were off by even one byte, what follows would not be `0000`.
    remainder_is_flush: bool,
    /// Everything before the capability NUL: `<oid> <refname>`.
    before_nul: Vec<u8>,
    /// Everything after it, minus any trailing LF.
    capabilities: Vec<u8>,
    /// Whether the payload ended with LF.
    trailing_lf: bool,
}

/// Splits the first pkt-line of an advertisement.
///
/// Returns `Err` with a reason rather than panicking, so a malformed oracle
/// transcript is reported as a classified cell instead of a test crash.
fn split_first_ref_line(bytes: &[u8]) -> Result<RefLine, String> {
    if bytes.len() < 4 {
        return Err(format!("advertisement is {} bytes, too short", bytes.len()));
    }
    let header =
        std::str::from_utf8(&bytes[..4]).map_err(|_| "pkt header is not ASCII".to_owned())?;
    let declared_len = usize::from_str_radix(header, 16)
        .map_err(|_| format!("pkt header {header:?} is not hex"))?;
    if declared_len < 4 || declared_len > bytes.len() {
        return Err(format!(
            "declared length {declared_len} is outside the {} available bytes",
            bytes.len()
        ));
    }
    let mut payload = &bytes[4..declared_len];
    let trailing_lf = payload.last() == Some(&b'\n');
    if trailing_lf {
        payload = &payload[..payload.len() - 1];
    }
    let nul = payload.iter().position(|byte| *byte == 0);
    let (before_nul, capabilities) = match nul {
        Some(index) => (payload[..index].to_vec(), payload[index + 1..].to_vec()),
        None => (payload.to_vec(), Vec::new()),
    };
    Ok(RefLine {
        declared_len,
        remainder_is_flush: &bytes[declared_len..] == b"0000",
        before_nul,
        capabilities,
        trailing_lf,
    })
}

/// Whether an advertisement ends with a flush packet.
fn ends_with_flush(bytes: &[u8]) -> bool {
    bytes.ends_with(b"0000")
}

// ---------------------------------------------------------------------------
// Producing our side
// ---------------------------------------------------------------------------

fn context() -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(SERVER_CAPABILITIES, &WireLimits::default())
            .expect("server capability set parses"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("receive context")
}

fn encode(packets: &[Packet], label: &str) -> Vec<u8> {
    encode_packets(packets, &WireLimits::default())
        .unwrap_or_else(|error| panic!("encode {label}: {error}"))
}

/// Our advertisement for the same ref the oracle advertised.
fn ours_for(oid_hex: &str, ref_name: &[u8]) -> Vec<u8> {
    let reference = AdvertisedRef::new(
        AnyGitOid::from_hex(GitObjectFormat::Sha1, oid_hex).expect("oracle object id parses"),
        ref_name,
        &WireLimits::default(),
    )
    .expect("advertised ref");
    encode(
        &advertise_receive_pack(vec![reference], &context()).expect("populated advertisement"),
        "populated advertisement",
    )
}

/// Our advertisement for a repository that has no refs at all.
fn ours_empty() -> Vec<u8> {
    encode(
        &advertise_receive_pack(Vec::new(), &context()).expect("empty advertisement"),
        "empty advertisement",
    )
}

// ---------------------------------------------------------------------------
// Verdict accumulation
// ---------------------------------------------------------------------------

/// One classified comparison cell, in the vocabulary FG-018c established.
enum Verdict {
    Match,
    AcceptedDivergence(&'static str),
    Defect(String),
}

impl Verdict {
    fn render(&self) -> String {
        match self {
            Self::Match => "match".to_owned(),
            Self::AcceptedDivergence(rationale) => {
                format!("accepted-divergence-with-rationale:{rationale}")
            }
            Self::Defect(detail) => format!("defect:{detail}"),
        }
    }
}

/// Compares one field and classifies it, so a disagreement is recorded rather
/// than aborting the run and hiding every later cell.
fn compare<T: PartialEq + std::fmt::Debug>(oracle: &T, ours: &T, what: &str) -> Verdict {
    if oracle == ours {
        Verdict::Match
    } else {
        Verdict::Defect(format!("{what}: oracle {oracle:?} vs ours {ours:?}"))
    }
}

fn read_corpus(corpus: &Path, name: &str) -> Vec<u8> {
    fs::read(corpus.join(name))
        .unwrap_or_else(|error| panic!("the suite must supply {name}: {error}"))
}

fn write_output(output: &Path, name: &str, bytes: &[u8]) {
    fs::write(output.join(name), bytes)
        .unwrap_or_else(|error| panic!("writing {name} failed: {error}"));
}

/// Compares the populated and empty advertisements and writes `verdict.tsv`.
///
/// Ignored by default: without the oracle corpus there is nothing to compare,
/// and a version that silently passed when the corpus was absent would be the
/// worst possible outcome for a differential test.
#[test]
#[ignore = "requires the pinned-oracle corpus supplied by receivepack_differential.sh"]
fn our_receive_pack_advertisement_frames_what_git_frames() {
    let corpus = PathBuf::from(
        env::var(CORPUS_ENV).unwrap_or_else(|_| panic!("{CORPUS_ENV} must name the oracle corpus")),
    );
    let output = PathBuf::from(
        env::var(OUTPUT_ENV)
            .unwrap_or_else(|_| panic!("{OUTPUT_ENV} must name an output directory")),
    );
    fs::create_dir_all(&output).expect("output directory");

    let mut cells: Vec<(&str, Verdict)> = Vec::new();

    // ---- populated repository --------------------------------------------
    let oracle_populated = read_corpus(&corpus, "oracle-populated.pkt");
    let oracle_line = match split_first_ref_line(&oracle_populated) {
        Ok(line) => line,
        Err(reason) => {
            cells.push(("oracle_transcript_parses", Verdict::Defect(reason)));
            write_verdict(&output, &cells);
            panic!("the oracle transcript could not be decomposed; see verdict.tsv");
        }
    };
    cells.push(("oracle_transcript_parses", Verdict::Match));

    // The oid and name Git advertised, taken from Git's own bytes so both sides
    // describe the same repository state rather than a state we assumed.
    let (oid_hex, ref_name) = {
        let before = &oracle_line.before_nul;
        let space = before
            .iter()
            .position(|byte| *byte == b' ')
            .expect("Git's ref line separates oid and name with a space");
        (
            String::from_utf8(before[..space].to_vec()).expect("oid is ASCII hex"),
            before[space + 1..].to_vec(),
        )
    };

    let ours_populated = ours_for(&oid_hex, &ref_name);
    write_output(&output, "fgit-populated.pkt", &ours_populated);
    let ours_line =
        split_first_ref_line(&ours_populated).expect("our own advertisement must decompose");

    cells.push((
        "populated_ref_identity_and_name",
        compare(
            &oracle_line.before_nul,
            &ours_line.before_nul,
            "pre-NUL segment",
        ),
    ));
    // The framing cell that can actually fail: an off-by-one declared length
    // leaves the remainder unparseable as the terminating flush.
    cells.push((
        "populated_declared_length_frames_the_packet",
        compare(
            &oracle_line.remainder_is_flush,
            &ours_line.remainder_is_flush,
            "the declared length lands exactly on the flush",
        ),
    ));
    cells.push((
        "populated_capability_section_opens_with_nul",
        compare(
            &!oracle_line.capabilities.is_empty(),
            &!ours_line.capabilities.is_empty(),
            "capability section present",
        ),
    ));
    cells.push((
        "populated_trailing_lf",
        compare(
            &oracle_line.trailing_lf,
            &ours_line.trailing_lf,
            "trailing LF",
        ),
    ));
    cells.push((
        "populated_flush_terminator",
        compare(
            &ends_with_flush(&oracle_populated),
            &ends_with_flush(&ours_populated),
            "flush terminator",
        ),
    ));

    // The one difference that is intended, named rather than hidden.
    cells.push((
        "capability_set",
        if oracle_line.capabilities == ours_line.capabilities {
            // Not a pass: identical capability strings would mean we claim
            // Git's whole feature set, which we do not implement.
            Verdict::Defect(
                "our advertisement claims Git's exact capability set, which we do not implement"
                    .to_owned(),
            )
        } else {
            Verdict::AcceptedDivergence(
                "each-server-advertises-only-what-it-implements;Git-adds-agent-and-features-fgit-does-not-claim",
            )
        },
    ));

    // ---- empty repository -------------------------------------------------
    let oracle_empty = read_corpus(&corpus, "oracle-empty.pkt");
    let ours_empty_bytes = ours_empty();
    write_output(&output, "fgit-empty.pkt", &ours_empty_bytes);

    match (
        split_first_ref_line(&oracle_empty),
        split_first_ref_line(&ours_empty_bytes),
    ) {
        (Ok(oracle_empty_line), Ok(ours_empty_line)) => {
            cells.push((
                "empty_repository_pseudo_ref",
                compare(
                    &oracle_empty_line.before_nul,
                    &ours_empty_line.before_nul,
                    "empty-repository pseudo-ref line",
                ),
            ));
            cells.push((
                "empty_repository_trailing_lf",
                compare(
                    &oracle_empty_line.trailing_lf,
                    &ours_empty_line.trailing_lf,
                    "empty-repository trailing LF",
                ),
            ));
        }
        (oracle_result, ours_result) => {
            cells.push((
                "empty_repository_pseudo_ref",
                Verdict::Defect(format!(
                    "one side did not decompose: oracle {oracle_result:?}, ours {ours_result:?}"
                )),
            ));
        }
    }
    cells.push((
        "empty_repository_flush_terminator",
        compare(
            &ends_with_flush(&oracle_empty),
            &ends_with_flush(&ours_empty_bytes),
            "empty-repository flush terminator",
        ),
    ));

    write_verdict(&output, &cells);

    // The suite asserts over verdict.tsv, but failing here too means a bare
    // `cargo test -- --ignored` is still a real check rather than a file writer.
    let defects: Vec<&str> = cells
        .iter()
        .filter(|(_, verdict)| matches!(verdict, Verdict::Defect(_)))
        .map(|(name, _)| *name)
        .collect();
    assert!(
        defects.is_empty(),
        "receive-pack advertisement diverges from pinned Git in: {defects:?}"
    );

    // Non-vacuity: a corpus that produced no comparisons would write an empty
    // verdict and pass the assertion above.
    assert!(
        cells.len() >= 9,
        "only {} cells were classified, so the corpus did not drive the comparison",
        cells.len()
    );
}

/// The comparator detects a divergence that is one byte wide.
///
/// Every cell above reports `match`, which is the outcome that most needs a
/// reason to be believed. This runs the same decomposition over a deliberately
/// corrupted advertisement — the declared pkt length lowered by one — and
/// requires the framing cell to notice. Without it, "our advertisement matches
/// Git" would rest on a comparator never observed rejecting anything.
///
/// It needs no oracle, so it is **not** `#[ignore]`d: it guards the bridge on
/// every ordinary `cargo test` run, including on machines with no oracle
/// installed.
#[test]
fn the_comparator_rejects_an_advertisement_whose_declared_length_is_wrong() {
    let honest = ours_for(
        "15130a3d017cc0baa9b07dee1c764e8570768be6",
        b"refs/heads/master",
    );
    let honest_line = split_first_ref_line(&honest).expect("our advertisement decomposes");
    assert!(
        honest_line.remainder_is_flush,
        "the unmodified advertisement must frame its packet exactly"
    );

    // Lower the declared length by one: the packet now claims to end one byte
    // early, so the remainder can no longer be the terminating flush.
    let mut corrupted = honest.clone();
    let declared = honest_line.declared_len;
    let shortened = format!("{:04x}", declared - 1);
    corrupted[..4].copy_from_slice(shortened.as_bytes());

    let corrupted_line =
        split_first_ref_line(&corrupted).expect("a shortened packet still decomposes");
    assert!(
        !corrupted_line.remainder_is_flush,
        "a declared length one byte short must stop framing the packet, but the check passed"
    );

    // And the cell built from it must classify as a defect rather than a match.
    let verdict = compare(
        &honest_line.remainder_is_flush,
        &corrupted_line.remainder_is_flush,
        "the declared length lands exactly on the flush",
    );
    assert!(
        matches!(verdict, Verdict::Defect(_)),
        "the framing comparison must report a defect, got {}",
        verdict.render()
    );
}

fn write_verdict(output: &Path, cells: &[(&str, Verdict)]) {
    let mut rendered = String::new();
    for (name, verdict) in cells {
        rendered.push_str(name);
        rendered.push('=');
        rendered.push_str(&verdict.render());
        rendered.push('\n');
    }
    write_output(output, "verdict.tsv", rendered.as_bytes());
}
