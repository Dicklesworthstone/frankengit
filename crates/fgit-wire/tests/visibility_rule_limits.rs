#![forbid(unsafe_code)]

//! Per-call limits cannot be bypassed by an already larger policy.

use fgit_wire::visibility::RefVisibility;
use fgit_wire::{WireError, WireLimits};

fn limits(maximum: usize) -> WireLimits {
    WireLimits {
        max_ref_prefixes: maximum,
        ..WireLimits::default()
    }
}

#[test]
fn tightening_a_limit_refuses_new_exceptions_without_mutating_the_policy() {
    let mut policy = RefVisibility::new();
    policy.push_rule(b"refs/private", &limits(2)).expect("first rule");
    policy.push_rule(b"refs/internal", &limits(2)).expect("second rule");
    let before = policy.clone();
    let error = policy.push_rule(b"!refs/private", &limits(1)).unwrap_err();
    assert!(matches!(
        error,
        WireError::TooManyObjectIds {
            field: "visibility rule",
            limit: 1,
        }
    ));
    assert_eq!(policy, before);
    assert!(policy.hides(b"refs/private/tip"));
    assert!(policy.hides(b"refs/internal/tip"));
}

#[test]
fn a_zero_limit_refuses_additions_to_both_empty_and_nonempty_policies() {
    let mut existing = RefVisibility::new();
    existing.push_rule(b"refs/private", &limits(1)).expect("initial rule");
    for mut policy in [RefVisibility::new(), existing] {
        let before = policy.clone();
        assert!(matches!(
            policy.push_rule(b"!refs/private", &limits(0)),
            Err(WireError::TooManyObjectIds {
                field: "visibility rule",
                limit: 0,
            })
        ));
        assert_eq!(policy, before);
    }
}

#[test]
fn explicitly_raising_the_limit_permits_the_same_exception_and_then_stops_at_capacity() {
    let mut policy = RefVisibility::new();
    policy.push_rule(b"refs/private", &limits(1)).expect("initial rule");
    assert!(policy.push_rule(b"!refs/private", &limits(1)).is_err());
    assert!(policy.hides(b"refs/private/tip"));
    policy
        .push_rule(b"!refs/private", &limits(2))
        .expect("the larger explicit budget permits the exception");
    assert!(!policy.hides(b"refs/private/tip"));
    let before = policy.clone();
    assert!(policy.push_rule(b"refs/private", &limits(2)).is_err());
    assert_eq!(policy, before);
}
