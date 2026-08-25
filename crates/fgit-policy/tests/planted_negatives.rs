//! The planted negatives, each beside the permitted case it differs from.
//!
//! Three are named in FG-043a's dispatch and get their own section: an unknown
//! construct, a rule that would read the clock, and a non-deterministic
//! ordering. The rest are the ordinary type and declaration errors, and they
//! are here for the same reason: a refusal that never fires and a refusal that
//! fires on everything look identical from a green test run, so every refusal
//! below is stated together with a near-identical source that compiles.

use fgit_policy::error::{PolicyCompileRefusal, PolicySyntaxRefusal, RefPatternRefusal};
use fgit_policy::{compile, program};

fn refuses(source: &str) -> PolicyCompileRefusal {
    match compile(source) {
        Ok(policy) => panic!("compiled when it must refuse: {policy:?}"),
        Err(refusal) => refusal,
    }
}

fn compiles(source: &str) {
    if let Err(refusal) = compile(source) {
        panic!("must compile: {refusal}\n\n{source}");
    }
}

fn wrap(body: &str) -> String {
    format!("policy planted {{\n{body}\n  default allow\n}}")
}

fn rule(condition: &str) -> String {
    wrap(&format!(
        "  rule probe {{\n    when {condition}\n    then deny \"probe\"\n  }}"
    ))
}

// ---------------------------------------------------------------------------
// Planted negative 1: an unknown construct.
// ---------------------------------------------------------------------------

#[test]
fn an_invented_operator_is_refused_at_compile_time() {
    let refusal = refuses(&rule(r#"ref.name flargle "refs/heads/main""#));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::UnknownOperator { operator, .. })
                if &**operator == "flargle"
        ),
        "expected an unknown-operator refusal, got {refusal:?}"
    );
    // The permitted twin: the same rule with a defined operator.
    compiles(&rule(r#"ref.name matches "refs/heads/main""#));
}

#[test]
fn an_invented_declaration_is_refused_at_compile_time() {
    let refusal = refuses(&wrap(r#"  import "https://example.invalid/rules""#));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::UnknownDeclaration { keyword, .. })
                if &**keyword == "import"
        ),
        "expected an unknown-declaration refusal, got {refusal:?}"
    );
    // The permitted twin: a declaration this language does define.
    compiles(&wrap("  aggregate open-incidents"));
}

#[test]
fn an_invented_decision_is_refused_at_compile_time() {
    let refusal = refuses(&wrap(
        "  rule probe {\n    when true\n    then quarantine\n  }",
    ));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::UnknownDecision { keyword, .. })
                if &**keyword == "quarantine"
        ),
        "expected an unknown-decision refusal, got {refusal:?}"
    );
    compiles(&wrap("  rule probe {\n    when true\n    then allow\n  }"));
}

#[test]
fn an_unknown_enumeration_literal_is_refused_with_the_admitted_set() {
    let refusal = refuses(&rule("ref.update == rebase"));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::UnknownEnumLiteral { literal, admits, .. }
                if &**literal == "rebase" && admits.contains("fast_forward")
        ),
        "expected an unknown-literal refusal naming the admitted set, got {refusal:?}"
    );
    compiles(&rule("ref.update == fast_forward"));
}

// ---------------------------------------------------------------------------
// Planted negative 2: a rule that would read the clock, the environment, or a
// file. None of these is a special case in the compiler; all three are simply
// names that are not facts.
// ---------------------------------------------------------------------------

#[test]
fn a_rule_that_would_read_ambient_state_is_refused_at_compile_time() {
    for selector in [
        "now.seconds",
        "clock.unix",
        "env.home",
        "file.contents",
        "random.value",
        "http.status",
    ] {
        let refusal = refuses(&rule(&format!("{selector} > 100")));
        assert!(
            matches!(
                &refusal,
                PolicyCompileRefusal::UnknownSelector { selector: named, rule }
                    if &**named == selector && &**rule == "probe"
            ),
            "expected `{selector}` to be an unknown selector, got {refusal:?}"
        );
    }
}

#[test]
fn the_permitted_twin_of_a_clock_read_is_a_declared_aggregate() {
    // The refusal above is about the name not being a fact, and not about
    // comparing something to a number: the identical comparison against a
    // declared aggregate compiles.
    compiles(&wrap(
        "  aggregate wall-clock\n  rule probe {\n    when aggregate.wall-clock > 100\n    then deny \"probe\"\n  }",
    ));
}

#[test]
fn an_undeclared_aggregate_is_refused_even_though_it_is_spelled_correctly() {
    let refusal = refuses(&rule("aggregate.open-incidents > 0"));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::UnknownAggregate { name, .. } if &**name == "open-incidents"
        ),
        "expected an unknown-aggregate refusal, got {refusal:?}"
    );
    compiles(&wrap(
        "  aggregate open-incidents\n  rule probe {\n    when aggregate.open-incidents > 0\n    then deny \"probe\"\n  }",
    ));
}

#[test]
fn an_undeclared_evidence_kind_is_refused() {
    let refusal = refuses(&rule("evidence code-review"));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::UnknownEvidenceKind { kind, .. } if &**kind == "code-review"
        ),
        "expected an unknown-evidence refusal, got {refusal:?}"
    );
    compiles(&wrap(
        "  evidence code-review { issuer forge.review }\n  rule probe {\n    when evidence code-review\n    then deny \"probe\"\n  }",
    ));
}

// ---------------------------------------------------------------------------
// The type rules: every selector admits some operators and refuses the rest.
// ---------------------------------------------------------------------------

#[test]
fn an_operator_the_selector_does_not_admit_is_refused() {
    for (condition, selector, operator) in [
        (r#"ref.update matches "create""#, "ref.update", "matches"),
        (r#"actor.teams == "platform""#, "actor.teams", "=="),
        ("ref.name contains platform", "ref.name", "contains"),
        ("actor.kind >= human", "actor.kind", ">="),
        (
            r#"ref.force_requested == "yes""#,
            "ref.force_requested",
            "==",
        ),
    ] {
        let refusal = refuses(&rule(condition));
        assert!(
            matches!(
                &refusal,
                PolicyCompileRefusal::OperatorNotApplicable { selector: named, operator: used, .. }
                    if &**named == selector && *used == operator
            ),
            "expected `{operator}` on `{selector}` to be refused, got {refusal:?}"
        );
    }
    // The permitted twins, one per selector above.
    compiles(&rule("ref.update == create"));
    compiles(&rule("actor.teams contains platform"));
    compiles(&rule(r#"ref.name == "refs/heads/main""#));
    compiles(&rule("actor.kind == human"));
    compiles(&rule("ref.force_requested"));
}

#[test]
fn an_operand_of_the_wrong_shape_is_refused() {
    for (condition, expected) in [
        ("ref.name == 3", "a quoted string"),
        (r#"ref.update == "create""#, "a bare name"),
        (r#"ref.name in { "a", 3 }"#, "a set of quoted strings"),
        ("actor.teams contains 7", "a bare name"),
    ] {
        let refusal = refuses(&rule(condition));
        assert!(
            matches!(
                &refusal,
                PolicyCompileRefusal::OperandTypeMismatch { expected: named, .. }
                    if *named == expected
            ),
            "expected `{condition}` to be an operand mismatch, got {refusal:?}"
        );
    }
    compiles(&rule(r#"ref.name == "3""#));
    compiles(&rule("ref.update == create"));
    compiles(&rule(r#"ref.name in { "a", "b" }"#));
    compiles(&rule("actor.teams contains seven"));
}

#[test]
fn a_bare_selector_that_is_not_truth_valued_is_refused() {
    let refusal = refuses(&rule("ref.name"));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::OperatorNotApplicable { operator, .. }
                if *operator == "(no operator)"
        ),
        "expected a bare non-boolean selector to be refused, got {refusal:?}"
    );
    // The permitted twin: the one selector that IS truth-valued.
    compiles(&rule("ref.force_requested"));
}

// ---------------------------------------------------------------------------
// Declaration and structure errors.
// ---------------------------------------------------------------------------

#[test]
fn a_policy_without_a_default_is_refused_rather_than_given_one() {
    let refusal =
        refuses("policy planted {\n  rule probe {\n    when true\n    then allow\n  }\n}");
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::MissingDefaultDecision { .. })
        ),
        "expected a missing-default refusal, got {refusal:?}"
    );
    compiles(
        "policy planted {\n  rule probe {\n    when true\n    then allow\n  }\n  default deny \"none\"\n}",
    );
}

#[test]
fn a_repeated_rule_identifier_is_refused() {
    let refusal = refuses(&wrap(
        "  rule probe {\n    when true\n    then allow\n  }\n  rule probe {\n    when false\n    then allow\n  }",
    ));
    assert!(
        matches!(&refusal, PolicyCompileRefusal::DuplicateRuleId { id } if &**id == "probe"),
        "expected a duplicate-rule refusal, got {refusal:?}"
    );
    compiles(&wrap(
        "  rule probe {\n    when true\n    then allow\n  }\n  rule other {\n    when false\n    then allow\n  }",
    ));
}

#[test]
fn a_repeated_declaration_is_refused() {
    let refusal = refuses(&wrap(
        "  aggregate open-incidents\n  aggregate open-incidents",
    ));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::DuplicateDeclaration { kind, name }
                if *kind == "aggregate" && &**name == "open-incidents"
        ),
        "expected a duplicate-declaration refusal, got {refusal:?}"
    );
    compiles(&wrap("  aggregate open-incidents\n  aggregate queue-depth"));
}

#[test]
fn a_reserved_word_cannot_be_a_declared_name() {
    let refusal = refuses(&wrap("  rule when {\n    when true\n    then allow\n  }"));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::LabelInvalid { name, .. })
                if &**name == "when"
        ),
        "expected a reserved word to be refused as a rule identifier, got {refusal:?}"
    );
    compiles(&wrap(
        "  rule whenever {\n    when true\n    then allow\n  }",
    ));
}

#[test]
fn source_after_the_closing_brace_is_refused() {
    let refusal = refuses(&format!("{}\npolicy second {{ default allow }}", wrap("")));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::TrailingSource { .. })
        ),
        "expected trailing source to be refused, got {refusal:?}"
    );
    compiles(&wrap(""));
}

#[test]
fn a_malformed_ref_pattern_is_refused_with_the_pattern_reason() {
    let refusal = refuses(&rule(r#"ref.name matches "refs/**/main""#));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::RefPatternInvalid {
                reason: RefPatternRefusal::DoubleStarNotTrailing { index: 1 },
                ..
            }
        ),
        "expected a pattern refusal, got {refusal:?}"
    );
    compiles(&rule(r#"ref.name matches "refs/heads/**""#));
}

#[test]
fn integer_literals_have_one_spelling_each() {
    let refusal = refuses(&wrap(
        "  aggregate n\n  rule probe {\n    when aggregate.n == 007\n    then allow\n  }",
    ));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::IntegerLeadingZero { .. })
        ),
        "expected a leading-zero refusal, got {refusal:?}"
    );
    compiles(&wrap(
        "  aggregate n\n  rule probe {\n    when aggregate.n == 7\n    then allow\n  }",
    ));
    // Zero itself is one digit and is not a leading zero.
    compiles(&wrap(
        "  aggregate n\n  rule probe {\n    when aggregate.n == 0\n    then allow\n  }",
    ));
}

#[test]
fn an_undefined_string_escape_is_refused() {
    let refusal = refuses(&rule(r#"ref.name == "refs\nheads""#));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::UnsupportedEscape { byte: b'n', .. })
        ),
        "expected an unsupported-escape refusal, got {refusal:?}"
    );
    // The permitted twins: the two escapes the language does define.
    compiles(&rule(r#"ref.name == "a\\b""#));
    compiles(&rule(r#"ref.name == "a\"b""#));
}

#[test]
fn a_predicate_deeper_than_the_bound_is_refused_and_one_at_the_bound_is_not() {
    let limit = usize::try_from(program::MAX_PREDICATE_DEPTH).expect("the bound fits in a usize");
    let at_bound = format!("{}true{}", "not ".repeat(limit - 1), "");
    compiles(&rule(&at_bound));

    let over_bound = format!("{}true", "not ".repeat(limit));
    let refusal = refuses(&rule(&over_bound));
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::NestingTooDeep { .. })
        ),
        "expected a nesting refusal, got {refusal:?}"
    );
}

#[test]
fn a_source_over_the_size_bound_is_refused_and_one_at_the_bound_is_not() {
    let body = wrap("");
    let padding = fgit_policy::syntax::MAX_SOURCE_LEN - body.len();
    let at_bound = format!("{}{}", " ".repeat(padding), body);
    assert_eq!(at_bound.len(), fgit_policy::syntax::MAX_SOURCE_LEN);
    compiles(&at_bound);

    let over_bound = format!(" {at_bound}");
    let refusal = refuses(&over_bound);
    assert!(
        matches!(
            &refusal,
            PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::SourceTooLarge { .. })
        ),
        "expected a source-size refusal, got {refusal:?}"
    );
}
