#![forbid(unsafe_code)]
//! Synthesized protection policies built from data, never interpolated source.
//!
//! Keep the existing policy names, rule IDs, predicates and outcomes: ordinary
//! names must retain their content-addressed snapshot identities. Untrusted
//! names occupy AST operands only; quotes cannot terminate a source literal.

use fgit_policy::program::MAX_RULES;
use fgit_policy::syntax::{
    MAX_SOURCE_LEN, SourceExpr, SourceOperand, SourceOperator, SourceOutcome, SourcePolicy,
    SourceRule, Spanned,
};
use fgit_policy::{PolicyCompileRefusal, PolicySnapshot, PolicySnapshotBody, PolicySyntaxRefusal};

// Preserve the old source-size envelope even though no dynamic source is parsed.
const DELETION_OVERHEAD: usize = concat!(
    "policy branch_protection {\n    rule protect {\n        when ref.name matches \"",
    "\" and ref.update == delete\n        then deny \"ref deletion is prohibited\"\n",
    "    }\n    default allow\n}"
)
.len();
const NAMED_POLICY_OVERHEAD: usize =
    concat!("policy forge_branch_protection {\n", "    default allow\n}").len();

fn bounded_source_length(observed: usize) -> Result<(), PolicyCompileRefusal> {
    if observed > MAX_SOURCE_LEN {
        return Err(PolicyCompileRefusal::Syntax(
            PolicySyntaxRefusal::SourceTooLarge {
                observed,
                limit: MAX_SOURCE_LEN,
            },
        ));
    }
    Ok(())
}

fn written(value: impl Into<Box<str>>) -> Spanned<Box<str>> {
    // These are generated facts, not offsets into client-supplied source.
    Spanned::new(value.into(), 0)
}

fn comparison(
    selector: &'static str,
    operator: SourceOperator,
    operand: SourceOperand,
) -> SourceExpr {
    SourceExpr::Comparison {
        selector: written(selector),
        operator,
        operator_offset: 0,
        operand,
    }
}

fn ref_matches(pattern: &str) -> SourceExpr {
    comparison(
        "ref.name",
        SourceOperator::Matches,
        SourceOperand::Text(written(pattern)),
    )
}

fn seal(policy: &SourcePolicy) -> Result<PolicySnapshot, PolicyCompileRefusal> {
    // Resolve through the public compiler, retaining its pattern, rule, label,
    // selector, operand and normalization checks. Do not construct a compiled
    // snapshot directly and bypass those checks.
    let compiled = fgit_policy::resolve(policy)?;
    PolicySnapshot::seal(PolicySnapshotBody::new(compiled))
        .map_err(|refusal| PolicyCompileRefusal::SnapshotIdentity { refusal })
}

pub(super) fn branch_deletion(pattern: &str) -> Result<PolicySnapshot, PolicyCompileRefusal> {
    bounded_source_length(DELETION_OVERHEAD.saturating_add(pattern.len()))?;
    seal(&SourcePolicy {
        name: written("branch_protection"),
        declarations: Vec::new(),
        rules: vec![SourceRule {
            id: written("protect"),
            predicate: SourceExpr::All(vec![
                ref_matches(pattern),
                comparison(
                    "ref.update",
                    SourceOperator::Equal,
                    SourceOperand::Name(written("delete")),
                ),
            ]),
            outcome: SourceOutcome::Deny("ref deletion is prohibited".into()),
        }],
        default_outcome: SourceOutcome::Allow,
    })
}

pub(super) fn named_branches<'a, I>(branches: I) -> Result<PolicySnapshot, PolicyCompileRefusal>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut rules = Vec::new();
    let mut source_length = NAMED_POLICY_OVERHEAD;
    for branch in branches {
        if rules.len() == MAX_RULES {
            return Err(PolicyCompileRefusal::RuleCountExceeded {
                observed: MAX_RULES + 1,
                limit: MAX_RULES,
            });
        }
        let index = rules.len() + 1;
        let prefix = if branch.starts_with("refs/") {
            ""
        } else {
            "refs/heads/"
        };
        // Count BEFORE copying an untrusted name. This is the exact byte count
        // of the previous template, without ever treating that template as code.
        let overhead = format!(
            "    rule protect_branch_{index} {{\n        when ref.name matches \"\"\n        then deny \"direct update to protected branch  prohibited\"\n    }}\n"
        )
        .len();
        source_length = source_length
            .saturating_add(overhead)
            .saturating_add(prefix.len())
            .saturating_add(branch.len())
            .saturating_add(branch.len());
        bounded_source_length(source_length)?;
        let pattern = format!("{prefix}{branch}");
        rules.push(SourceRule {
            id: written(format!("protect_branch_{index}")),
            predicate: ref_matches(&pattern),
            outcome: SourceOutcome::Deny(
                format!("direct update to protected branch {branch} prohibited").into_boxed_str(),
            ),
        });
    }
    seal(&SourcePolicy {
        name: written("forge_branch_protection"),
        declarations: Vec::new(),
        rules,
        default_outcome: SourceOutcome::Allow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_policy::{Decision, PolicyInstant, RefUpdateFact, RefUpdateKind};
    use fgit_types::{GitOid, GitOidSha1, PrincipalId, RefName};

    fn allows(snapshot: &PolicySnapshot, name: &str, delete: bool) -> bool {
        let old = GitOid::Sha1(GitOidSha1::from_bytes([1; 20]));
        let new = GitOid::Sha1(GitOidSha1::from_bytes([2; 20]));
        let update = RefUpdateFact::try_new(
            RefName::try_new(name.as_bytes()).unwrap(),
            Some(old),
            if delete { None } else { Some(new) },
            if delete {
                RefUpdateKind::Delete
            } else {
                RefUpdateKind::FastForward
            },
            false,
        )
        .unwrap();
        let input = crate::policy_bridge::build_input_root(
            PrincipalId::from_bytes([7; 16]),
            crate::policy_bridge::default_principal_snapshot_id(),
            vec![update],
            PolicyInstant::from_seconds(7),
        )
        .unwrap();
        matches!(
            fgit_policy::evaluate(snapshot, &input).unwrap().decision(),
            Decision::Allow
        )
    }

    #[test]
    fn ordinary_deletion_policy_retains_its_snapshot_identity() {
        let expected = fgit_policy::compile_and_seal(
            "policy branch_protection { rule protect { when ref.name matches \"refs/heads/*\" and ref.update == delete then deny \"ref deletion is prohibited\" } default allow }",
        )
        .unwrap();
        let actual = branch_deletion("refs/heads/*").unwrap();
        assert_eq!(actual.id(), expected.id());
        assert!(!allows(&actual, "refs/heads/main", true));
        assert!(allows(&actual, "refs/heads/main", false));
        assert!(allows(&actual, "refs/tags/v1", true));
    }

    #[test]
    fn ordinary_named_policy_retains_its_snapshot_identity() {
        let expected = fgit_policy::compile_and_seal(
            "policy forge_branch_protection { rule protect_branch_1 { when ref.name matches \"refs/heads/main\" then deny \"direct update to protected branch main prohibited\" } rule protect_branch_2 { when ref.name matches \"refs/heads/release\" then deny \"direct update to protected branch refs/heads/release prohibited\" } default allow }",
        )
        .unwrap();
        let actual = named_branches(["main", "refs/heads/release"]).unwrap();
        assert_eq!(actual.id(), expected.id());
        assert!(!allows(&actual, "refs/heads/main", false));
        assert!(!allows(&actual, "refs/heads/release", true));
        assert!(allows(&actual, "refs/heads/topic", false));
    }

    #[test]
    fn quoted_ref_is_data_for_deletion_policy_and_does_not_expand_its_scope() {
        for name in ["refs/heads/plain", "refs/heads/release\"or\"true"] {
            let first = branch_deletion(name).unwrap();
            assert_eq!(first.id(), branch_deletion(name).unwrap().id());
            assert!(!allows(&first, name, true));
            assert!(allows(&first, name, false));
            assert!(allows(&first, "refs/heads/unrelated", true));
        }
    }

    #[test]
    fn quotes_in_named_branches_and_deny_reasons_never_enter_the_parser() {
        for name in ["plain", "release\"or\"true", "a\"}default/allow#"] {
            let policy = named_branches([name]).unwrap();
            let full_name = format!("refs/heads/{name}");
            assert!(!allows(&policy, &full_name, false));
            assert!(!allows(&policy, &full_name, true));
            assert!(allows(&policy, "refs/heads/unrelated", false));
            assert_eq!(policy.id(), named_branches([name]).unwrap().id());
        }
    }

    #[test]
    fn oversized_names_keep_the_source_budget_refusal() {
        let huge = "x".repeat(MAX_SOURCE_LEN);
        assert!(matches!(
            branch_deletion(&huge),
            Err(PolicyCompileRefusal::Syntax(
                PolicySyntaxRefusal::SourceTooLarge { .. }
            ))
        ));
        assert!(matches!(
            named_branches([huge.as_str()]),
            Err(PolicyCompileRefusal::Syntax(
                PolicySyntaxRefusal::SourceTooLarge { .. }
            ))
        ));
        assert!(branch_deletion("refs/heads/main").is_ok());
        assert!(named_branches(["main"]).is_ok());
    }

    #[test]
    fn named_policy_stops_consuming_an_unbounded_rule_iterator() {
        let mut consumed = 0;
        let names = std::iter::from_fn(|| {
            consumed += 1;
            Some("main")
        });
        assert!(named_branches(names).is_err());
        assert!(consumed <= MAX_RULES + 1);
        assert!(named_branches(std::iter::empty::<&str>()).is_ok());
    }

    #[test]
    fn pattern_length_boundary_keeps_its_permitted_twin() {
        let short_name = "x".repeat(fgit_policy::glob::MAX_PATTERN_LEN - "refs/heads/".len());
        let at_limit = format!("refs/heads/{short_name}");
        let over_limit = format!("{at_limit}x");
        assert!(branch_deletion(&at_limit).is_ok());
        assert!(branch_deletion(&over_limit).is_err());
        assert!(named_branches([short_name.as_str()]).is_ok());
        let too_long = format!("{short_name}x");
        assert!(named_branches([too_long.as_str()]).is_err());
    }

    #[test]
    fn malformed_patterns_still_use_the_compilers_typed_refusal() {
        assert!(branch_deletion("refs/**/main").is_err());
        assert!(branch_deletion("refs/heads/**").is_ok());
        assert!(named_branches(["refs/**/main"]).is_err());
        assert!(named_branches(["refs/heads/main"]).is_ok());
    }
}
