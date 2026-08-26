#![forbid(unsafe_code)]
//! E3 notes differential test driven by the pinned upstream-Git oracle.
//!
//! STAGED for fg084 (MagentaJay, 2026-08-25). Lands in
//! `crates/fgit-git-object/tests/notes_differential.rs` together with
//! `scripts/e2e/oracle/notes_corpus.sh` only if the fg084 owner accepts
//! disposition (a); the corpus generator supplies the environment below.
//!
//! Keeping this test ignored in ordinary crate runs is intentional: an
//! absent pinned-oracle corpus is an unavailable E3 lane, never a false
//! local pass against ambient Git.
//!
//! Oracle truth asserted here:
//! 1. snapshot rows: our parser reads git's notes tree into exactly git's
//!    map, and our emitter reproduces git's root tree body byte-for-byte at
//!    counts 1, 255, 256, 257 (fanout boundary);
//! 2. oddwidth row: git functionally accepts a 3-hex fanout directory; our
//!    parser must accept it too and read the same map (emission equality is
//!    NOT asserted: our emitter only produces flat/2-hex layouts);
//! 3. mergeunion / mergecsu rows: our blob-content merge helper matches the
//!    bytes `git notes merge --strategy=...` actually committed.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fgit_crypto::{GitHashAlgorithm, GitOid, Sha1, Sha256};
use fgit_git_object::notes::{oid_from_hex, oid_to_hex};
use fgit_git_object::{
    AcceptanceProfile, NotesError, NotesMergeStrategy, ParseLimits, emit_notes_tree,
    merge_note_blob_bytes, parse_notes_tree,
};

const CORPUS_ENV: &str = "FGIT_NOTES_DIFFERENTIAL_CORPUS";
const RECEIPT_ALGORITHM_KEY: &str = "algorithm";

fn corpus_directory() -> PathBuf {
    let value = env::var_os(CORPUS_ENV).unwrap_or_else(|| {
        panic!("missing required environment {CORPUS_ENV}; generate it with notes_corpus.sh")
    });
    let path = PathBuf::from(value);
    assert!(
        path.is_dir(),
        "{CORPUS_ENV} is not a directory: {}",
        path.display()
    );
    path
}

fn transcript_bytes(corpus: &Path, label: &str) -> Vec<u8> {
    fs::read(corpus.join("transcripts").join(label).join("stdout.bin"))
        .unwrap_or_else(|error| panic!("cannot read oracle transcript {label}: {error}"))
}

fn receipt_field(corpus: &Path, key: &str) -> String {
    let receipt =
        fs::read_to_string(corpus.join("receipt.tsv")).expect("corpus receipt.tsv is readable");
    receipt
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")).map(str::to_owned))
        .unwrap_or_else(|| panic!("corpus receipt lacks {key}"))
}

fn manifest_rows(corpus: &Path) -> Vec<Vec<String>> {
    let manifest = fs::read_to_string(corpus.join("manifest.tsv")).expect("manifest.tsv readable");
    manifest
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect()
}

fn hex_map<A: GitHashAlgorithm>(tree: &fgit_git_object::NotesTree<A>) -> BTreeMap<String, String>
where
    GitOid<A>: Ord,
{
    tree.iter()
        .map(|(target, blob)| (oid_to_hex(target), oid_to_hex(blob)))
        .collect()
}

fn ls_tree_map(ls_bytes: &[u8]) -> BTreeMap<String, String> {
    let text = std::str::from_utf8(ls_bytes).expect("ls-tree output is UTF-8");
    let mut map = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (meta, path) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("ls-tree line lacks tab separator: {line}"));
        let oid = meta
            .split_whitespace()
            .nth(2)
            .unwrap_or_else(|| panic!("ls-tree line lacks object OID: {line}"))
            .to_owned();
        let target: String = path.chars().filter(|character| *character != '/').collect();
        map.insert(target, oid);
    }
    map
}

/// Fetcher over the exact oracle-captured subtree bodies stored under
/// `<corpus>/trees/<case>/<oid-hex>.body` by the generator. A miss is a
/// corpus-shape failure, never a reason to consult ambient state.
fn subtree_fetcher<A: GitHashAlgorithm>(
    corpus: PathBuf,
) -> impl Fn(&GitOid<A>) -> Result<Vec<u8>, NotesError> {
    move |oid: &GitOid<A>| {
        let hex = oid_to_hex(oid);
        fs::read(corpus.join("trees").join(format!("{hex}.body"))).map_err(|error| {
            NotesError::InvalidNotesTreeEntry {
                reason: format!("corpus lacks captured body for subtree {hex}: {error}"),
            }
        })
    }
}

fn verify_corpus<A>()
where
    A: GitHashAlgorithm,
    GitOid<A>: Ord,
{
    let corpus = corpus_directory();
    // tree_reference_bytes MUST match the algorithm domain: the default is
    // SHA-1's 20 bytes, and a 20-byte read width on SHA-256 bodies misaligns
    // every subsequent entry (misread later as mode garbage).
    let mut limits = ParseLimits::default();
    limits.tree_reference_bytes = A::HEX_LEN / 2;
    // Full-corpus evaluation: every row reports, no early abort, so one
    // confirmed divergence cannot mask another row's verdict.
    let mut failures: Vec<String> = Vec::new();

    for row in manifest_rows(&corpus) {
        match row[0].as_str() {
            "snapshot" => {
                assert!(
                    row.len() == 4 || row.len() == 5 || row.len() == 6,
                    "snapshot row shape: {row:?}"
                );
                let label = format!("snapshot {}", row[1]);
                // Ground truth for note count is the ORACLE'S ls-tree leaves,
                // never the generator's nominal add counter: resume/replay
                // drift can make nominal != served, and the parser must be
                // judged against what git actually serves.
                let oracle_tree = transcript_bytes(&corpus, &row[3]);
                let oracle_map = ls_tree_map(&transcript_bytes(&corpus, &row[4]));
                let count = oracle_map.len();

                let fetch = subtree_fetcher::<A>(corpus.clone());
                let parsed = match parse_notes_tree::<A, _>(
                    &oracle_tree,
                    AcceptanceProfile::GitCompatibleImport,
                    &limits,
                    &fetch,
                ) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        failures.push(format!("{label}: parser refused git's tree: {error}"));
                        continue;
                    }
                };

                if parsed.len() != count {
                    failures.push(format!(
                        "{label}: parsed {} notes, git has {}",
                        parsed.len(),
                        count
                    ));
                }
                if hex_map(&parsed) != oracle_map {
                    failures.push(format!("{label}: parsed map differs from git's"));
                }

                let emission =
                    emit_notes_tree(&parsed, &limits).expect("our emission of the parsed tree");
                // Accepted-divergence rows (accepted:FG084-DIV-001) skip byte
                // equality: upstream writer fanout shape proved
                // history-dependent (two pinned runs disagree at equal
                // counts), so only PARSE equality is asserted for them.
                let accepted_divergence =
                    row.last().map(String::as_str) == Some("accepted:FG084-DIV-001");
                if !accepted_divergence {
                    if emission.root_tree_body != oracle_tree {
                        failures.push(format!(
                            "{label}: EMIT-DIVERGENCE re-emitted root tree bytes differ from git's"
                        ));
                    }
                }
                let oracle_root =
                    String::from_utf8(transcript_bytes(&corpus, &row[2])).expect("OID transcript");
                if !accepted_divergence && oid_to_hex(&emission.root_oid) != oracle_root.trim() {
                    failures.push(format!(
                        "{label}: EMIT-DIVERGENCE re-emitted root OID differs"
                    ));
                }
            }
            "oddwidth" => {
                // DECLARED DIVERGENCE, pinned by the pinned-oracle corpus:
                // upstream git (verified against git-2.54.0) SILENTLY IGNORES
                // a structurally valid odd-width fanout directory -- `notes
                // list` exits 0 with empty output and `notes show` reports
                // "no note found". Our parser refuses it loudly instead.
                // Same observable content served (none), different failure
                // style; the refusal is the fail-closed side of AGENTS.md 3.1
                // and must not be "fixed" into silent tolerance without a
                // compatibility-matrix decision.
                assert!(row.len() == 5, "oddwidth row shape: {row:?}");
                let oracle_tree = transcript_bytes(&corpus, &row[2]);

                let fetch = subtree_fetcher::<A>(corpus.clone());
                let parse_outcome = parse_notes_tree::<A, _>(
                    &oracle_tree,
                    AcceptanceProfile::GitCompatibleImport,
                    &limits,
                    &fetch,
                );
                if parse_outcome.is_ok() {
                    failures.push(
                        "oddwidth: odd-width fanout dir accepted; declared divergence expects typed refusal"
                            .to_string(),
                    );
                }
                let list = transcript_bytes(&corpus, &row[4]);
                if !list.is_empty() {
                    failures.push(
                        "oddwidth: upstream changed, notes list emitted bytes; re-run disposition"
                            .to_string(),
                    );
                }
            }
            kind @ ("union" | "cat_sort_uniq") => {
                // Row shape: <kind> <variant a|b> <merged-bytes-label>.
                // Side bytes are documented fixture constants (fast-import
                // built): a = both sides end NL; b = neither does.
                assert!(row.len() == 3, "{kind} row shape: {row:?}");
                let (ours, theirs): (&[u8], &[u8]) = match row[1].as_str() {
                    "a" => (b"alpha line\n", b"bravo line\n"),
                    "b" => (b"alpha line, no NL", b"bravo line, no NL"),
                    other => panic!("unknown merge fixture variant {other}"),
                };
                let merged = transcript_bytes(&corpus, &row[2]);
                let strategy = if kind == "union" {
                    NotesMergeStrategy::Union
                } else {
                    NotesMergeStrategy::CatSortUniq
                };
                let produced = merge_note_blob_bytes(ours, theirs, strategy);
                if produced != merged {
                    failures.push(format!(
                        "{kind}({}): MERGE-DIVERGENCE git={merged:?} frankengit={produced:?}",
                        row[1]
                    ));
                    eprintln!(
                        "FINDING-DETAIL {kind}({}): git={merged:?} frankengit={produced:?}",
                        row[1]
                    );
                }
            }
            other => panic!("unknown manifest row kind: {other}"),
        }
    }

    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("FINDING: {failure}");
        }
    }
    assert!(
        failures.is_empty(),
        "{} differential finding(s): {}",
        failures.len(),
        failures.join(" | ")
    );

    let denominator: usize = receipt_field(&corpus, "corpus_denominator")
        .parse()
        .expect("positive corpus denominator");
    let rows = manifest_rows(&corpus).len();
    assert_eq!(
        rows, denominator,
        "manifest rows must equal the receipt denominator"
    );
    assert!(rows > 0, "an empty corpus proves nothing");
}

#[test]
#[ignore = "requires the pinned shell notes corpus from notes_differential.sh"]
fn notes_sha1_differential() {
    if receipt_field(&corpus_directory(), RECEIPT_ALGORITHM_KEY) != "sha1" {
        eprintln!("corpus is not sha1; this entry point is unavailable for it");
        return;
    }
    verify_corpus::<Sha1>();
}

#[test]
#[ignore = "requires the pinned shell notes corpus from notes_differential.sh"]
fn notes_sha256_differential() {
    if receipt_field(&corpus_directory(), RECEIPT_ALGORITHM_KEY) != "sha256" {
        eprintln!("corpus is not sha256; this entry point is unavailable for it");
        return;
    }
    verify_corpus::<Sha256>();
}

/// Isolated evaluation of the merge-blob rows so a confirmed fanout-boundary
/// divergence cannot mask the union/cat_sort_uniq verdicts.
#[test]
#[ignore = "requires the pinned shell notes corpus from notes_differential.sh"]
fn notes_merge_rows_only() {
    let corpus = corpus_directory();
    let mut divergences = 0usize;
    for row in manifest_rows(&corpus) {
        let kind = row[0].as_str();
        if kind != "mergeunion" && kind != "mergecsu" {
            continue;
        }
        assert!(row.len() == 4, "{kind} row shape: {row:?}");
        let ours = transcript_bytes(&corpus, &row[1]);
        let theirs = transcript_bytes(&corpus, &row[2]);
        let merged = transcript_bytes(&corpus, &row[3]);
        let strategy = if kind == "mergeunion" {
            NotesMergeStrategy::Union
        } else {
            NotesMergeStrategy::CatSortUniq
        };
        let produced = merge_note_blob_bytes(&ours, &theirs, strategy);
        if produced != merged {
            eprintln!(
                "DIVERGENCE {kind}:\n  git         = {merged:?}\n  frankengit  = {produced:?}"
            );
            divergences += 1;
        }
    }
    assert_eq!(
        divergences, 0,
        "{divergences} merge-strategy byte divergence(s) against pinned oracle"
    );
}
