//! Planted-defect detection for the intent-to-effect mapping (FG-026d).
//!
//! `overlay_and_intents.rs` already asserts that every source intent maps to
//! exactly one outcome. That establishes the mapping is TOTAL. It does not
//! establish that the mapping is SENSITIVE — that a log which quietly lost,
//! duplicated, or reordered an intent would actually look different afterwards.
//! A totality check alone is satisfied by a mapping that ignores its input.
//!
//! So each test here plants one specific corruption in a known-good log and
//! requires it to be observable. The pairing matters as much as the mutation:
//!
//!   * reordering two intents that touch the SAME path must change the result,
//!     because the later write legitimately wins;
//!   * reordering two intents that touch DIFFERENT paths must NOT change it,
//!     because AGENTS.md §5.3 requires a target-disjoint net-effect normal form
//!     and disjoint edits commute by construction.
//!
//! A test that only checked the first would pass just as happily against an
//! implementation that made ordering matter everywhere, which would be a
//! different and equally wrong system.

use fgit_treefs::intent::{IntentLog, NetEffect, NoOpReason, TreeEditIntent};
use fgit_treefs::overlay::{EntryClass, FileMode, Overlay};
use fgit_treefs::path::TreePath;

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("test path parses")
}

fn write(target: &[u8], body: &[u8]) -> TreeEditIntent {
    TreeEditIntent::Write {
        path: path(target),
        content: body.to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    }
}

/// Nothing exists in the base, so every effect here comes from the log itself.
const fn empty_base(_path: &TreePath) -> bool {
    false
}

fn log_of(intents: Vec<TreeEditIntent>) -> IntentLog {
    let mut log = IntentLog::new();
    for intent in intents {
        log.push(intent);
    }
    log
}

/// The known-good log every mutation below is derived from.
///
/// Three distinct paths plus one supersession, so the corpus contains both a
/// surviving-effect case and a named-no-op case.
fn baseline_intents() -> Vec<TreeEditIntent> {
    vec![
        write(b"src/a.rs", b"a one\n"),
        write(b"src/b.rs", b"b one\n"),
        write(b"src/a.rs", b"a two\n"),
        write(b"docs/readme.md", b"# readme\n"),
    ]
}

fn overlay_of(intents: Vec<TreeEditIntent>) -> Overlay {
    let (overlay, _evaluation) = log_of(intents).evaluate(&empty_base);
    overlay
}

/// Sanity: the baseline behaves the way the mutations below assume.
#[test]
fn the_baseline_log_supersedes_exactly_once_and_is_total() {
    let log = log_of(baseline_intents());
    let (_overlay, evaluation) = log.evaluate(&empty_base);

    assert_eq!(
        evaluation.outcomes().len(),
        4,
        "the totality map holds exactly one outcome per source intent"
    );
    assert_eq!(
        evaluation.surviving(),
        3,
        "three paths survive: src/a.rs, src/b.rs and docs/readme.md"
    );
    assert!(
        matches!(
            evaluation.outcomes()[0],
            NetEffect::NoOp(NoOpReason::SupersededByLaterIntent { by_index: 2 })
        ),
        "the first write to src/a.rs is superseded by index 2, and says so; got {:?}",
        evaluation.outcomes()[0]
    );
}

// ---------------------------------------------------------------------------
// planted omission
// ---------------------------------------------------------------------------

/// Dropping a surviving intent must change the net effect.
#[test]
fn a_planted_omission_is_detected() {
    let baseline = overlay_of(baseline_intents());

    // Drop index 1, the only write to src/b.rs, so its effect cannot survive.
    let mut corrupted = baseline_intents();
    corrupted.remove(1);
    let mutated = overlay_of(corrupted);

    assert_ne!(
        baseline.entries(),
        mutated.entries(),
        "losing an intent must be visible in the net effect, or an omission could pass unnoticed"
    );
    assert!(
        !mutated.entries().contains_key(&path(b"src/b.rs")),
        "the omitted intent's path must be absent, not merely different"
    );
}

/// Dropping an intent that was superseded anyway must NOT change the net effect
/// — and must still be visible in the totality map.
///
/// This is the counterpart that stops the test above from being satisfied by an
/// implementation where any edit at all perturbs the output. The overlay is the
/// same because the intent contributed nothing to it; the evaluation differs
/// because there is one fewer source intent to account for.
#[test]
fn dropping_a_superseded_intent_changes_the_ledger_but_not_the_bytes() {
    let baseline = overlay_of(baseline_intents());

    let mut corrupted = baseline_intents();
    corrupted.remove(0); // the superseded first write to src/a.rs
    let mutated = overlay_of(corrupted.clone());

    assert_eq!(
        baseline.entries(),
        mutated.entries(),
        "a superseded intent contributes no bytes, so removing it must not move the net effect"
    );

    let (_overlay, evaluation) = log_of(corrupted).evaluate(&empty_base);
    assert_eq!(
        evaluation.outcomes().len(),
        3,
        "the totality map still reports one outcome per surviving source intent"
    );
}

// ---------------------------------------------------------------------------
// planted duplication
// ---------------------------------------------------------------------------

/// A duplicated intent must be NAMED, not silently absorbed.
///
/// The bytes are unchanged — writing the same body twice is idempotent — so the
/// only way a duplication is detectable at all is through the totality map. If
/// the duplicate vanished from the ledger, an agent replaying its own log could
/// not tell "I issued this once" from "I issued it twice".
#[test]
fn a_planted_duplication_is_named_in_the_ledger() {
    let baseline = overlay_of(baseline_intents());

    let mut corrupted = baseline_intents();
    corrupted.insert(3, write(b"src/a.rs", b"a two\n")); // duplicate of index 2
    let mutated = overlay_of(corrupted.clone());

    assert_eq!(
        baseline.entries(),
        mutated.entries(),
        "a duplicated identical write is idempotent in bytes"
    );

    let (_overlay, evaluation) = log_of(corrupted).evaluate(&empty_base);
    assert_eq!(
        evaluation.outcomes().len(),
        5,
        "every source intent gets an outcome, duplicates included"
    );

    // The original at index 2 is now superseded by the duplicate at 3, and the
    // duplicate itself is a no-op because it changed nothing. Either way both
    // must be accounted for by name rather than dropped.
    let named_no_ops = evaluation
        .outcomes()
        .iter()
        .filter(|outcome| matches!(outcome, NetEffect::NoOp(_)))
        .count();
    assert!(
        named_no_ops >= 2,
        "the duplicate and the intent it shadows must both be named as no-ops; outcomes: {:?}",
        evaluation.outcomes()
    );
}

// ---------------------------------------------------------------------------
// planted reordering
// ---------------------------------------------------------------------------

/// Reordering two writes to the SAME path must change the surviving bytes.
#[test]
fn a_planted_same_path_reorder_is_detected() {
    let baseline = overlay_of(baseline_intents());

    // Swap the two writes to src/a.rs so the earlier body wins instead.
    let mut corrupted = baseline_intents();
    corrupted.swap(0, 2);
    let mutated = overlay_of(corrupted);

    assert_ne!(
        baseline.entries(),
        mutated.entries(),
        "the last write to a path must win; if reordering same-path writes is invisible, \
         read-your-own-writes is not being applied"
    );
}

/// Reordering two intents on DIFFERENT paths must NOT change anything.
///
/// AGENTS.md §5.3 requires a target-disjoint net-effect normal form. Disjoint
/// edits commute, so this ordering must be unobservable in the result — and the
/// evaluation must not depend on map iteration order either, which is why the
/// comparison is over the full entry map rather than a count.
#[test]
fn a_disjoint_reorder_is_correctly_invisible() {
    let baseline = overlay_of(baseline_intents());

    // src/b.rs (index 1) and docs/readme.md (index 3) share no path.
    let mut reordered = baseline_intents();
    reordered.swap(1, 3);
    let mutated = overlay_of(reordered);

    assert_eq!(
        baseline.entries(),
        mutated.entries(),
        "disjoint edits commute; if this differs, the net effect is not target-disjoint"
    );
}

/// Evaluation is a pure function: the same log twice yields the same bytes.
///
/// Cheap, and it is what makes every `assert_ne!` above meaningful — a mapping
/// that varied run to run would fail those comparisons for reasons unrelated to
/// the planted defect.
#[test]
fn evaluation_is_pure_so_the_mutation_comparisons_mean_something() {
    let first = overlay_of(baseline_intents());
    let second = overlay_of(baseline_intents());
    assert_eq!(
        first.entries(),
        second.entries(),
        "evaluating the same log twice must produce identical bytes"
    );
}
