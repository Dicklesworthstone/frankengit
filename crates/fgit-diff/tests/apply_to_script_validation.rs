#![forbid(unsafe_code)]

//! frankengit-5q0i: `DiffResult::apply_to`'s script-validation refusals.
//!
//! A diff script is only meaningful against the exact input it was computed
//! from. `apply_to` re-validates that binding as it walks the edits rather than
//! trusting the caller to supply the right bytes:
//!
//! ```text
//! lib.rs:193  old_span.byte_start != cursor || old_span.byte_end > old.len()
//! lib.rs:205  cursor != old.len()   (after every edit has been applied)
//! ```
//!
//! Both raise `MalformedScript`, and neither had a test. AGENTS.md §4 names "a
//! decoder result accepted without original commitments" as a forbidden
//! substitute; applying a script to bytes it was not derived from is exactly
//! that, and the guards are what stop it producing a plausible wrong answer.
//!
//! # The two sites are reached by differently-shaped wrong inputs
//!
//! Truncate the input and a span runs past its end — caught mid-walk at `:193`.
//! Extend the input and every span still resolves, but the walk finishes with
//! bytes left over — caught only at `:205`, after the output has been fully
//! built. Same variant, different moment, and a test that only ever passed a
//! short input would leave the second entirely unexercised.

use fgit_diff::{DiffLimits, DiffOptions, DiffProfile, SequenceGranularity, diff};

const OLD: &[u8] = b"alpha\nbravo\ncharlie\ndelta\n";
const NEW: &[u8] = b"alpha\nBRAVO\ncharlie\ndelta\n";

fn script() -> fgit_diff::DiffResult {
    diff(OLD, NEW, DiffOptions::myers_lines(DiffLimits::default()))
        .expect("a small line diff is well formed")
}

/// The permitted twin: the script applied to the input it was computed from
/// reproduces the new bytes exactly.
///
/// Load-bearing rather than decorative. Both refusals below are `apply_to`
/// declining to produce output; without this, a guard that refused every input
/// would satisfy them and still be catastrophically wrong.
#[test]
fn a_script_applied_to_its_own_input_reproduces_the_new_bytes() {
    let applied = script()
        .apply_to(OLD)
        .expect("a script must apply to the input it was derived from");

    assert_eq!(
        applied, NEW,
        "the round trip is the whole contract: old plus script equals new",
    );
}

/// A script applied to a TRUNCATED input is refused mid-walk.
///
/// Some span now runs past the end of the shortened input, which `:193` catches
/// while walking. Without it the very next line indexes `old[start..end]` out of
/// bounds — the refusal is what keeps a wrong input from becoming a panic.
#[test]
fn a_script_applied_to_a_truncated_input_is_refused() {
    let truncated = &OLD[..OLD.len() / 2];

    assert_eq!(
        script().apply_to(truncated),
        Err(fgit_diff::DiffError::MalformedScript),
    );
}

/// A script applied to an EXTENDED input is refused at the end of the walk.
///
/// This is the site a short-input test cannot reach. Every span still resolves —
/// the prefix is identical, so nothing is out of bounds and the output is built
/// in full — and only the final `cursor != old.len()` notices that trailing
/// bytes were never accounted for.
///
/// Without it, applying a script to a file that has since grown would return a
/// silently truncated result rather than an error: the appended bytes would
/// simply vanish from the output.
#[test]
fn a_script_applied_to_an_extended_input_is_refused_after_the_walk() {
    let mut extended = OLD.to_vec();
    extended.extend_from_slice(b"echo\n");

    assert_eq!(
        script().apply_to(&extended),
        Err(fgit_diff::DiffError::MalformedScript),
        "trailing bytes the script never covers must refuse, not be dropped",
    );
}

/// The script's own shape is pinned, so the probes above cannot be satisfied by
/// a degenerate diff.
///
/// If `diff` returned a single whole-file replacement, the truncated case would
/// still refuse but for an uninteresting reason. Asserting the script has more
/// than one edit keeps the fixture honest about what it is exercising.
#[test]
fn the_fixture_script_is_not_a_single_whole_file_replacement() {
    let result = script();

    assert_eq!(result.granularity, SequenceGranularity::Lines);
    assert_eq!(result.profile, DiffProfile::MyersMinimal);
    assert!(
        result.edits.len() > 1,
        "a one-edit script would make the span probes vacuous; got {:?}",
        result.edits,
    );
}
