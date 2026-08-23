// Reference-name validation: which complaint wins when a name breaks two rules.
//
// `RefName::validate` runs twelve refusal guards in sequence, and every probe in
// `tests/refs.rs` violates exactly one of them. That suite is good — it asserts
// the distinct reason per rule and pairs the subtle ones with permitted
// counterparts — but a single-fault corpus, however complete, **cannot see the
// order**. Swap two guards and all ten of its structural probes still pass with
// their expected reasons.
//
// Order is observable only from an input that fails MORE THAN ONE guard, and it
// matters here rather than being tidiness: §6 makes refusal behaviour a
// compatibility semantic, and this is FrankenGit's own `git check-ref-format`.
// A caller may branch on the refusal, and the first two guards do not even share
// a variant with the rest — `LengthOutOfRange` and `ByteNotPermitted` are
// different *types* of answer from the `RefNameStructureInvalid` family, so a
// swap across that boundary changes the refusal's shape, not just its text.
//
// # Every test here proves BOTH faults are present
//
// An order test is worthless if the input only really breaks one rule — it would
// silently degenerate into a restatement of the single-fault suite. So each case
// below asserts the combined input's winner, then removes the winning fault and
// asserts the loser's reason appears. If the second half ever stops holding, the
// probe has stopped testing order.

use fgit_types::TypeRefusal;
use fgit_types::refs::{MAX_REF_NAME_LEN, RefName};

fn reason_of(refusal: &TypeRefusal) -> &'static str {
    match refusal {
        TypeRefusal::RefNameStructureInvalid { reason, .. } => reason,
        other => panic!("expected a structural refusal, observed {other}"),
    }
}

fn refuse(source: &[u8]) -> TypeRefusal {
    RefName::try_new(source).expect_err("this name breaks a rule and must be refused")
}

/// Guard 1 (length) precedes guard 2 (forbidden byte), and the answer changes
/// TYPE rather than only text.
#[test]
fn the_length_bound_beats_a_forbidden_byte() {
    let mut over = b"refs/heads/".to_vec();
    over.resize(MAX_REF_NAME_LEN, b'a');
    over.push(b' '); // forbidden anywhere, and pushes the name one past the bound
    assert_eq!(over.len(), MAX_REF_NAME_LEN + 1);

    assert!(
        matches!(
            refuse(&over),
            TypeRefusal::LengthOutOfRange {
                field: "RefName",
                ..
            }
        ),
        "the length bound is checked before the byte scan",
    );

    // The forbidden byte really is there: inside the bound it is what refuses.
    let mut within = b"refs/heads/a b".to_vec();
    within.truncate(14);
    assert!(matches!(
        refuse(&within),
        TypeRefusal::ByteNotPermitted { byte: b' ', .. }
    ));
}

/// Guard 2 (forbidden byte) precedes the whole structural family.
#[test]
fn a_forbidden_byte_beats_a_structural_rule() {
    assert!(
        matches!(
            refuse(b"refs/heads/a..b c"),
            TypeRefusal::ByteNotPermitted { byte: b' ', .. }
        ),
        "the byte scan runs before any structural rule",
    );

    // The `..` really is there: without the space it is what refuses.
    assert_eq!(reason_of(&refuse(b"refs/heads/a..bc")), "double_dot");
}

/// `..` and `@{` are NOT two ordered guards — they share one `windows(2)` scan,
/// so whichever appears EARLIER in the name wins.
///
/// This is the case a reader is most likely to get wrong from the source: the
/// two `if`s sit one above the other and look like a fixed precedence, but they
/// are inside the same loop body, so position decides.
#[test]
fn the_double_dot_and_at_brace_scan_is_positional_not_prioritised() {
    assert_eq!(
        reason_of(&refuse(b"refs/heads/a..b@{c")),
        "double_dot",
        "the `..` occurs first, so it wins",
    );
    assert_eq!(
        reason_of(&refuse(b"refs/heads/a@{b..c")),
        "at_brace_sequence",
        "the at-brace occurs first, so it wins - the same two faults, opposite answer",
    );
}

/// Guard 6 (trailing dot) precedes guard 8 (leading slash).
#[test]
fn a_trailing_dot_beats_a_leading_slash() {
    assert_eq!(reason_of(&refuse(b"/refs/heads/a.")), "name_ends_with_dot");

    // The leading slash really is there.
    assert_eq!(
        reason_of(&refuse(b"/refs/heads/a")),
        "name_starts_with_slash"
    );
}

/// Guard 7 (trailing slash) also precedes guard 8 (leading slash).
#[test]
fn a_trailing_slash_beats_a_leading_slash() {
    assert_eq!(
        reason_of(&refuse(b"/refs/heads/a/")),
        "name_ends_with_slash"
    );
    assert_eq!(
        reason_of(&refuse(b"/refs/heads/a")),
        "name_starts_with_slash"
    );
}

/// Within the component walk, an earlier component's fault wins over a later
/// one's — the loop returns on the first bad component.
#[test]
fn an_earlier_bad_component_beats_a_later_one() {
    assert_eq!(reason_of(&refuse(b"refs//.hidden")), "empty_component");

    // The later component really is bad on its own.
    assert_eq!(
        reason_of(&refuse(b"refs/.hidden")),
        "component_starts_with_dot"
    );
}

/// Within ONE component the checks are ordered: leading dot before `.lock`.
#[test]
fn a_dot_prefix_beats_a_dot_lock_suffix_in_the_same_component() {
    assert_eq!(
        reason_of(&refuse(b"refs/heads/.a.lock")),
        "component_starts_with_dot"
    );

    // The `.lock` suffix really is there.
    assert_eq!(
        reason_of(&refuse(b"refs/heads/a.lock")),
        "component_ends_with_dot_lock"
    );
}

/// Guard 3 (the bare `@`) precedes guard 12 (one-level), which would otherwise
/// also refuse it.
#[test]
fn the_bare_at_sign_beats_the_one_level_rule() {
    assert_eq!(reason_of(&refuse(b"@")), "name_is_bare_at_sign");

    // A one-level name that is not `@` reaches the later guard.
    assert_eq!(reason_of(&refuse(b"a")), "name_is_one_level");
}

/// A structural fault anywhere precedes guard 12, the last guard in the chain.
#[test]
fn a_structural_fault_beats_the_one_level_rule() {
    assert_eq!(
        reason_of(&refuse(b".hidden")),
        "component_starts_with_dot",
        "the component walk runs before the one-level count",
    );

    // Without the dot the same shape is refused for being one level.
    assert_eq!(reason_of(&refuse(b"hidden")), "name_is_one_level");
}
