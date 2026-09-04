//! Coverage of the canonical bodies this crate is responsible for describing.
//!
//! `frankengit-ovv2`. The defect this replaces: `conformance.rs` asserted that
//! `UNDESCRIBED` is empty under a message claiming *"every canonical body is
//! described"*. Those are different statements. `DESCRIBED` and `UNDESCRIBED`
//! are two hand-maintained tables, and a body that appears in **neither** makes
//! the emptiness assertion true and the sentence false. Two live bodies were in
//! exactly that state when this file was written.
//!
//! # What "covered" means here, and why it is not "every canonical body"
//!
//! `fgit-schema` is **L2**. Canonical bodies live at L2 (`fgit-codec`,
//! `fgit-verified-read`), L3 (`fgit-identity`) and L4 (`fgit-admission`,
//! `fgit-node`). An L2 crate may not depend on L3 or L4, so this crate cannot
//! name most canonical bodies by type without an inverted layer edge that the
//! constitutional checker forbids — and should forbid.
//!
//! So the covered set is stated explicitly rather than implied: the bodies of
//! the two L2 crates this crate can legally link. Roughly two dozen further
//! families exist above L2 and are **not** described here. That is a
//! program-level question, recorded on the bead; what this file guarantees is
//! that nothing inside the covered set can go missing silently.
//!
//! # Why the set is derived twice
//!
//! Neither derivation is trusted alone, because each is blind to what the other
//! catches:
//!
//! * **By type** — `<Body as CanonicalBody>::SCHEMA_FAMILY`. The compiler
//!   resolves it, so renames and removals break the build. It is blind to a
//!   body being *added*, which is precisely the failure that produced this bead.
//! * **By source scan** — reads the two crates' sources. It sees additions. It
//!   is fragile in ways that are easy to miss: the first scan written for this
//!   work was line-oriented and **under-read `fgit-verified-read` by half**,
//!   because `rustfmt` had wrapped two declarations across lines.
//!
//! Requiring the two to agree turns each one's blind spot into a test failure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fgit_codec::CanonicalBody;
use fgit_schema::registry;

/// Every canonical body of the two crates this crate covers, named by type.
///
/// The compiler checks each entry. A removed or renamed body fails to compile
/// here rather than quietly shrinking the set the coverage check runs against.
fn families_by_type() -> BTreeSet<String> {
    let mut families = BTreeSet::new();
    // `fgit-codec`. Three distinct types share the `repository-configuration`
    // family across schema majors, so this is a set of FAMILIES and not a count
    // of types; collapsing them is correct, not a loss.
    families.insert(fgit_codec::attest::SignedEnvelopeBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::TransactionSealBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::RepositoryCommitRecord::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::RepositoryDecisionBatchBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::RepositoryAuthorityHeadBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::RefusalRecordBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::RepositoryConfigurationBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::CreationAttemptBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::schema::HiddenRefPolicyBody::SCHEMA_FAMILY.to_string());
    // The canonical forge-position and outbox state maps. Both are registered
    // as undescribable rather than described; see `registry::UNDESCRIBED`.
    families.insert(fgit_codec::CanonicalForgePositionState::SCHEMA_FAMILY.to_string());
    families.insert(fgit_codec::CanonicalOutboxState::SCHEMA_FAMILY.to_string());
    // `fgit-verified-read`.
    families.insert(fgit_verified_read::MerkleProofBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_verified_read::RefStateNonMembershipProofBody::SCHEMA_FAMILY.to_string());
    families
        .insert(fgit_verified_read::ObjectClosureNonMembershipProofBody::SCHEMA_FAMILY.to_string());
    families.insert(fgit_verified_read::VerifiedReadEnvelope::SCHEMA_FAMILY.to_string());
    families
}

/// The crates whose bodies this crate is responsible for describing.
fn covered_crates() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf();
    vec![
        root.join("crates/fgit-codec/src"),
        root.join("crates/fgit-verified-read/src"),
    ]
}

fn rust_sources(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `(literal families, unresolvable declarations)` scanned from source.
///
/// Whitespace is collapsed before scanning, because the declaration is
/// frequently wrapped across lines. A line-oriented version of this scan missed
/// half of `fgit-verified-read`, and reported a confident, wrong, smaller set.
fn families_by_scan() -> (BTreeSet<String>, Vec<String>) {
    const DECLARATION: &str = "const SCHEMA_FAMILY";
    const CONSTRUCTOR: &str = "SchemaFamily::from_static(";

    let mut families = BTreeSet::new();
    let mut unresolvable = Vec::new();
    let mut files = Vec::new();
    for directory in covered_crates() {
        rust_sources(&directory, &mut files);
    }
    assert!(
        !files.is_empty(),
        "the scan found no sources at all, so any empty result below would be \
         an artifact of a wrong path rather than a fact about the code"
    );

    for path in files {
        let raw = std::fs::read_to_string(&path).expect("a listed source file reads");
        let flat: String = {
            let mut out = String::with_capacity(raw.len());
            let mut in_space = false;
            for character in raw.chars() {
                if character.is_whitespace() {
                    in_space = true;
                } else {
                    if in_space && !out.is_empty() {
                        out.push(' ');
                    }
                    in_space = false;
                    out.push(character);
                }
            }
            out
        };

        let mut cursor = 0;
        while let Some(found) = flat[cursor..].find(DECLARATION) {
            let at = cursor + found;
            cursor = at + DECLARATION.len();
            let Some(open) = flat[at..].find(CONSTRUCTOR) else {
                continue;
            };
            let argument_start = at + open + CONSTRUCTOR.len();
            let Some(close) = flat[argument_start..].find(')') else {
                continue;
            };
            let argument = flat[argument_start..argument_start + close].trim();
            if let Some(literal) = argument
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
            {
                families.insert(literal.to_owned());
            } else {
                // A family built from a constant or a macro parameter. The scan
                // cannot resolve it, and saying so is the point: silently
                // skipping it would make the scan under-read exactly where it
                // is least able to notice.
                unresolvable.push(format!("{}: {argument}", path.display()));
            }
        }
    }
    (families, unresolvable)
}

#[test]
fn the_two_derivations_of_the_covered_set_agree() {
    // The cross-check. By-type is blind to an added body; by-scan is fragile
    // about how declarations are formatted. Agreement is what makes either
    // usable, and disagreement names which body and which direction.
    let by_type = families_by_type();
    let (by_scan, unresolvable) = families_by_scan();

    assert!(
        unresolvable.is_empty(),
        "a covered crate declares SCHEMA_FAMILY from a non-literal, which the \
         scan cannot resolve; the scan would silently under-read: {unresolvable:?}"
    );
    assert_eq!(
        by_type,
        by_scan,
        "the two derivations of the covered set disagree. In by-scan only: {:?}. \
         In by-type only: {:?}. The first means a body was added and this test's \
         type list was not updated; the second means a body was removed or renamed",
        by_scan.difference(&by_type).collect::<Vec<_>>(),
        by_type.difference(&by_scan).collect::<Vec<_>>(),
    );
    assert!(
        by_type.len() >= 13,
        "the covered set collapsed to {} families, which is fewer than were \
         present when this test was written; a shrinking set makes every \
         coverage assertion below weaker without failing it",
        by_type.len()
    );
}

#[test]
fn every_covered_body_is_either_described_or_justified_as_undescribable() {
    // THE CORRECTED ASSERTION. The one it replaces checked that `UNDESCRIBED`
    // is empty, which says nothing about whether `DESCRIBED` is complete: a
    // body in NEITHER table satisfies it while making its message false.
    let covered = families_by_type();

    let described: BTreeSet<String> = registry::DESCRIBED
        .iter()
        .map(|entry| entry.family.to_owned())
        .collect();
    let undescribed: BTreeSet<String> = registry::UNDESCRIBED
        .iter()
        .map(|entry| entry.family.to_owned())
        .collect();

    let overlap: Vec<&String> = described.intersection(&undescribed).collect();
    assert!(
        overlap.is_empty(),
        "a family is in BOTH tables, so `descriptor_for` would resolve it while \
         the registry also claims it cannot be described: {overlap:?}"
    );

    let accounted: BTreeSet<String> = described.union(&undescribed).cloned().collect();

    let missing: Vec<&String> = covered.difference(&accounted).collect();
    assert!(
        missing.is_empty(),
        "these canonical bodies are in NEITHER table, so `descriptor_for` \
         reports them as `FamilyUnregistered` -- which this crate documents as \
         \"does not exist\" -- when they exist and are encoded today: {missing:?}"
    );

    let phantom: Vec<&String> = accounted.difference(&covered).collect();
    assert!(
        phantom.is_empty(),
        "these families are registered here but no covered crate declares them, \
         so the registry describes something that is not a canonical body: {phantom:?}"
    );
}

#[test]
fn the_undescribed_table_names_a_construct_rather_than_an_excuse() {
    // `UNDESCRIBED` means "the descriptor format cannot express this shape",
    // not "nobody has got to it yet". Without this, the table becomes a place
    // to park work and the coverage assertion above becomes trivially
    // satisfiable by listing everything as undescribable.
    for entry in registry::UNDESCRIBED {
        assert!(
            !entry.construct.trim().is_empty(),
            "{} is undescribed with no construct named",
            entry.family
        );
        assert!(
            entry.construct.len() >= 20,
            "{} names its blocking construct as {:?}, which is too short to be \
             a reason someone could act on",
            entry.family,
            entry.construct
        );
    }
}
