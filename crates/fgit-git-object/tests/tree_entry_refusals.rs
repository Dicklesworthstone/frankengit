#![forbid(unsafe_code)]
//! The tree-entry parser's refusals (`frankengit-xd45`).
//!
//! Sibling of `frankengit-v788`, which pinned the loose-object envelope
//! `type SPACE size NUL body`. This is the entry body one layer in:
//! `mode SPACE name NUL raw-oid`, repeated. Same §6 rationale — native Git
//! object identity is preserved exactly, and refusal behaviour **is** a
//! compatibility semantic, not an implementation detail.
//!
//! Measured per variant with a both-trees grep; the crate has no suite-like
//! module in `src/`, so a `tests/` scan is sound here (checked, after
//! `fgit-authority`'s `src/suite.rs` made a covered variant look untested).
//!
//! ```text
//! MissingTreeModeSeparator   untested   1 site
//! MissingTreeNameTerminator  untested   2 sites — one unreachable, see below
//! MalformedTreeMode          untested   2 axes in one condition
//! ```
//!
//! # The profile pair is the twin that matters
//!
//! `100664` is a perfectly well-formed octal mode that Git has historically
//! written and that `FrankenGit` will not create. Under
//! `GitCompatibleImport` it **parses**; under `StrictCreate` it is refused as
//! `NonCanonicalTreeMode`. The same bytes, two answers — so "malformed" and
//! "non-canonical" are genuinely different claims about a tree, and a corpus
//! that only ever parsed under one profile could not tell them apart.
//! [`a_non_canonical_octal_mode_is_admitted_on_import_and_refused_on_strict`]
//! asserts both halves in one test.
//!
//! # One site of `MissingTreeNameTerminator` cannot fire
//!
//! `mode_end.checked_add(1)` maps an arithmetic overflow onto that variant.
//! `mode_end` is a byte position **inside** `body`, so `mode_end + 1` cannot
//! overflow `usize` for any slice that exists. Unreachable, documented here
//! rather than given a manufactured fixture, and **not** counted as a covered
//! site. The other site — the missing-NUL scan — is reachable and probed.
//! That is the eleventh defensive arm this sweep has surfaced.
//!
//! # A sixth data point for the ordering-convention question
//!
//! `validate_strict_tree` **splits** its two faults:
//! `DuplicateTreeEntry` and `TreeEntriesOutOfOrder`. Both are already covered
//! by the crate's inline `cfg(test)` module, so they are **not** claimed as new
//! here — but naming them from `tests/` costs one probe and adds a sixth
//! measured case to an open question:
//!
//! ```text
//! fgit-atp-git TransferManifest   SPLIT
//! fgit-atp-git piece list         SPLIT
//! fgit-atp-git peer availability  COLLAPSE   name silent
//! fgit-object-fabric x2           COLLAPSE   names silent
//! fgit-wire advertisement         COLLAPSE   name truthful
//! fgit-git-object strict tree     SPLIT      <- this file
//! ```
//!
//! Recorded, not judged. Which convention the codebase wants is a ruling, and I
//! have already had to correct one over-tidy summary of it.
//!
//! **And the inline module is not blind to a merge here** — measured, not
//! assumed. Merging the two variants fails
//! `tests::strict_tree_rejects_bad_mode_duplicate_and_unsafe_name` in
//! `src/lib.rs`, which asserts `Err(DuplicateTreeEntry)` exactly. That makes
//! this crate the exception among the nine I mutated today: everywhere else the
//! pre-existing suites stayed green. So the two probes below are a **second**
//! detector reachable from `tests/`, not a first one, and saying otherwise
//! would overstate them.
//!
//! # Non-claims
//!
//! Newly covered: `MissingTreeModeSeparator`, `MissingTreeNameTerminator`
//! (reachable site only), `MalformedTreeMode`. Named from `tests/` but
//! **already covered inline**, so not counted: `NonCanonicalTreeMode`,
//! `DuplicateTreeEntry`, `TreeEntriesOutOfOrder`. Documented unreachable and
//! not counted: the `checked_add` site. `v788` closed four of sixteen; this
//! adds three, and the two must not be summed with the already-covered ones.
//!
//! Nothing here modifies `crates/fgit-git-object/src/**`.

use fgit_git_object::{
    AcceptanceProfile, ObjectError, ParseLimits, TreeEntry, emit_tree, parse_tree,
};

/// SHA-1 tree references are 20 raw bytes.
const REFERENCE_BYTES: usize = 20;

fn limits() -> ParseLimits {
    ParseLimits::default()
}

fn reference(tag: u8) -> Vec<u8> {
    vec![tag; REFERENCE_BYTES]
}

/// One raw tree-entry record: `mode SPACE name NUL raw-oid`.
fn record(mode: &[u8], name: &[u8], tag: u8) -> Vec<u8> {
    let mut bytes = mode.to_vec();
    bytes.push(b' ');
    bytes.extend_from_slice(name);
    bytes.push(0);
    bytes.extend_from_slice(&reference(tag));
    bytes
}

fn entry(mode: &[u8], name: &[u8], tag: u8) -> TreeEntry {
    TreeEntry {
        mode: mode.to_vec(),
        name: name.to_vec(),
        object_id: reference(tag),
    }
}

fn parse(body: &[u8], profile: AcceptanceProfile) -> Result<Vec<TreeEntry>, ObjectError> {
    parse_tree(body, profile, &limits())
}

fn refusal(body: &[u8], profile: AcceptanceProfile, what: &str) -> ObjectError {
    match parse(body, profile) {
        Ok(entries) => panic!(
            "{what} must be refused, but parsed {} entries",
            entries.len()
        ),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// The accepted paths, built first
// ---------------------------------------------------------------------------

/// A canonical single-entry tree parses under both profiles.
///
/// Built and made to pass before any refusal probe. Without it every refusal
/// below could be attributable to a malformed fixture rather than to the guard
/// it names — which is exactly what happened on three of my last seven beads
/// when I wrote the refusals first.
#[test]
fn a_canonical_tree_entry_parses_under_both_profiles() {
    let body = record(b"100644", b"README", 0x11);
    for profile in [
        AcceptanceProfile::GitCompatibleImport,
        AcceptanceProfile::StrictCreate,
    ] {
        let entries = parse(&body, profile).expect("a canonical entry parses under every profile");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mode, b"100644");
        assert_eq!(entries[0].name, b"README");
        assert_eq!(entries[0].object_id, reference(0x11));
    }
}

/// Every mode `FrankenGit` will create parses under the strict profile.
#[test]
fn the_five_canonical_modes_parse_under_strict_create() {
    for mode in [&b"40000"[..], b"100644", b"100755", b"120000", b"160000"] {
        let body = record(mode, b"entry", 0x22);
        parse(&body, AcceptanceProfile::StrictCreate).unwrap_or_else(|error| {
            panic!(
                "the canonical mode {:?} must parse under StrictCreate, got {error:?}",
                String::from_utf8_lossy(mode)
            )
        });
    }
}

/// **The profile pair.** The same bytes are admitted on import and refused on
/// strict create.
///
/// `100664` is well-formed octal that Git has historically written and that
/// `FrankenGit` will not create. So "malformed" and "non-canonical" are different
/// claims about a tree, and a corpus parsing under only one profile could not
/// distinguish them.
#[test]
fn a_non_canonical_octal_mode_is_admitted_on_import_and_refused_on_strict() {
    let body = record(b"100664", b"legacy", 0x33);

    let imported = parse(&body, AcceptanceProfile::GitCompatibleImport)
        .expect("a historically tolerated octal mode has a bounded unambiguous parse");
    assert_eq!(imported[0].mode, b"100664");

    let refused = refusal(
        &body,
        AcceptanceProfile::StrictCreate,
        "a non-canonical octal mode under StrictCreate",
    );
    assert_eq!(
        refused,
        ObjectError::NonCanonicalTreeMode,
        "the same bytes are non-canonical rather than malformed"
    );
}

// ---------------------------------------------------------------------------
// The entry framing
// ---------------------------------------------------------------------------

/// No space at all: the mode never ends.
#[test]
fn an_entry_without_a_mode_separator_is_refused() {
    let error = refusal(
        b"100644README",
        AcceptanceProfile::GitCompatibleImport,
        "an entry with no mode separator",
    );
    assert_eq!(error, ObjectError::MissingTreeModeSeparator);
}

/// The reachable `MissingTreeNameTerminator` site: the name is never
/// NUL-terminated.
///
/// Passes through: the mode separator is present and `100644` is a valid mode,
/// so this reaches the name scan rather than an earlier guard.
#[test]
fn an_entry_without_a_name_terminator_is_refused() {
    let error = refusal(
        b"100644 README",
        AcceptanceProfile::GitCompatibleImport,
        "an entry whose name is never terminated",
    );
    assert_eq!(error, ObjectError::MissingTreeNameTerminator);
}

// ---------------------------------------------------------------------------
// MalformedTreeMode — two axes in one condition
// ---------------------------------------------------------------------------

/// Axis 1: an empty mode.
#[test]
fn an_empty_mode_is_refused() {
    let mut body = Vec::new();
    body.push(b' ');
    body.extend_from_slice(b"README");
    body.push(0);
    body.extend_from_slice(&reference(0x44));

    let error = refusal(
        &body,
        AcceptanceProfile::GitCompatibleImport,
        "an entry with an empty mode",
    );
    assert_eq!(error, ObjectError::MalformedTreeMode);
}

/// Axis 2: a byte outside the octal digits.
///
/// One condition covers both shapes, so both get a probe. `8` and `9` are the
/// interesting non-octal digits — they look like a mode to a reader and are
/// not one.
#[test]
fn a_non_octal_mode_is_refused() {
    for mode in [&b"1006x4"[..], b"100648", b"100649"] {
        let body = record(mode, b"README", 0x55);
        let error = refusal(
            &body,
            AcceptanceProfile::GitCompatibleImport,
            "an entry with a non-octal mode",
        );
        assert_eq!(
            error,
            ObjectError::MalformedTreeMode,
            "the mode {:?} is not octal",
            String::from_utf8_lossy(mode)
        );
    }
}

// ---------------------------------------------------------------------------
// Ordering — bodies wrong twice
// ---------------------------------------------------------------------------

/// The mode separator is found **before** the mode is validated.
///
/// This body is wrong twice: there is no space *and* the leading bytes are not
/// a valid mode. It must report the separator. Single-fault probes cannot see
/// this — each supplies a separator by construction and so always reaches the
/// mode check.
#[test]
fn a_missing_separator_outranks_a_malformed_mode() {
    let error = refusal(
        b"xxxxxxREADME",
        AcceptanceProfile::GitCompatibleImport,
        "an entry with neither a separator nor a valid mode",
    );
    assert_eq!(
        error,
        ObjectError::MissingTreeModeSeparator,
        "the separator is located before the mode is validated"
    );
}

/// The mode is validated **before** the name terminator is sought.
///
/// Wrong twice again: a non-octal mode *and* no NUL. It must report the mode —
/// the opposite end of the entry from the probe above, so the two together pin
/// the order rather than one adjacency of it.
#[test]
fn a_malformed_mode_outranks_a_missing_name_terminator() {
    let error = refusal(
        b"1006x4 README",
        AcceptanceProfile::GitCompatibleImport,
        "an entry with a bad mode and no terminator",
    );
    assert_eq!(
        error,
        ObjectError::MalformedTreeMode,
        "the mode is validated before the name terminator is sought"
    );
}

// ---------------------------------------------------------------------------
// The strict tree validator SPLITS its two faults
// ---------------------------------------------------------------------------

/// A duplicate and an ordering fault report **different** refusals.
///
/// Both variants are already covered by the crate's inline `cfg(test)` module,
/// so this is not new coverage — it is named from `tests/` because the split is
/// a sixth measured data point for the ordering-convention question, and
/// because a probe asserting only that validation failed would pass against a
/// version that merged the arms.
#[test]
fn a_duplicate_entry_and_an_ordering_fault_are_different_refusals() {
    let duplicate = emit_tree(
        &[
            entry(b"100644", b"same", 0x11),
            entry(b"100644", b"same", 0x22),
        ],
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect_err("one name cannot appear twice in a tree");

    let unordered = emit_tree(
        &[entry(b"100644", b"b", 0x11), entry(b"100644", b"a", 0x22)],
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect_err("tree entries are canonically ordered");

    assert_eq!(duplicate, ObjectError::DuplicateTreeEntry);
    assert_eq!(unordered, ObjectError::TreeEntriesOutOfOrder);
    assert_ne!(
        duplicate, unordered,
        "this crate distinguishes a duplicate from a misorder"
    );
}

/// The duplicate scan runs **before** the ordering walk.
///
/// Two identical names are both a duplicate and — since equal entries are not
/// strictly increasing — an ordering fault. The duplicate is reported, because
/// `validate_strict_tree` completes its name set before comparing neighbours.
#[test]
fn a_duplicate_outranks_the_ordering_walk() {
    let error = emit_tree(
        &[
            entry(b"100644", b"same", 0x11),
            entry(b"100644", b"same", 0x22),
        ],
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect_err("an input wrong in two ways must still refuse");
    assert_eq!(
        error,
        ObjectError::DuplicateTreeEntry,
        "the duplicate scan completes before the ordering comparison begins"
    );
}

/// The permitted twin for the strict validator: distinct, ordered entries emit.
#[test]
fn distinct_ordered_entries_emit_under_strict_create() {
    let body = emit_tree(
        &[entry(b"100644", b"a", 0x11), entry(b"100644", b"b", 0x22)],
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("distinct ordered entries are canonical");
    let reparsed = parse(&body, AcceptanceProfile::StrictCreate).expect("the emitted body parses");
    assert_eq!(reparsed.len(), 2);
    assert_eq!(reparsed[0].name, b"a");
    assert_eq!(reparsed[1].name, b"b");
}
