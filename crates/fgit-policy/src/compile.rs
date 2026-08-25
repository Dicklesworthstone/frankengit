//! Static validation: resolving a source policy into a compiled one.
//!
//! This is where an unknown construct stops. A selector is resolved against
//! [`Selector::ALL`] and the declared aggregates; an operator is checked
//! against the selector's [`crate::program::ValueKind`]; an operand is checked
//! against the operator; an evidence kind is checked against the policy's own
//! declarations. Every one of those checks refuses with a value that names the
//! rule, so a policy author is told which rule is wrong rather than that the
//! policy is.
//!
//! Nothing here defers a check to evaluation. That is the constitutional
//! requirement in FG-043a's acceptance: a construct this build does not
//! understand is refused before a snapshot exists, never at the moment a push
//! is being decided.

use crate::basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, IssuerLabel, LabelName, PrincipalKind,
    RefUpdateKind,
};
use crate::error::{PolicyCompileRefusal, PolicySyntaxRefusal, refusal_name};
use crate::glob::RefPattern;
use crate::program::{
    Compare, CompiledPolicy, CompiledRule, DenyReason, EvidenceRequirement, MAX_RULES, PolicyName,
    Predicate, RuleId, RuleOutcome, Selector, TextLiteral, ValueKind,
};
use crate::syntax::{
    SourceDeclaration, SourceExpr, SourceOperand, SourceOperator, SourceOutcome, SourcePolicy,
    SourceRule, Spanned, is_keyword, parse,
};

/// Reads and validates a policy source text.
pub fn compile(source: &str) -> Result<CompiledPolicy, PolicyCompileRefusal> {
    let parsed = parse(source)?;
    resolve(&parsed)
}

/// Validates an already-parsed policy.
pub fn resolve(parsed: &SourcePolicy) -> Result<CompiledPolicy, PolicyCompileRefusal> {
    let name = declared_name::<PolicyName>("policy name", &parsed.name, PolicyName::try_new)?;

    let mut aggregates: Vec<AggregateName> = Vec::new();
    let mut evidence: Vec<EvidenceRequirement> = Vec::new();
    for declaration in &parsed.declarations {
        match declaration {
            SourceDeclaration::Aggregate(written) => {
                let aggregate = declared_name::<AggregateName>(
                    "aggregate name",
                    written,
                    AggregateName::try_new,
                )?;
                if aggregates.contains(&aggregate) {
                    return Err(PolicyCompileRefusal::DuplicateDeclaration {
                        kind: "aggregate",
                        name: refusal_name(&written.value),
                    });
                }
                aggregates.push(aggregate);
            }
            SourceDeclaration::Evidence {
                kind,
                issuer,
                max_age_seconds,
            } => {
                let declared =
                    declared_name::<EvidenceKind>("evidence kind", kind, EvidenceKind::try_new)?;
                let issuer = declared_name::<IssuerLabel>("issuer", issuer, IssuerLabel::try_new)?;
                if evidence
                    .iter()
                    .any(|requirement| requirement.kind() == declared)
                {
                    return Err(PolicyCompileRefusal::DuplicateDeclaration {
                        kind: "evidence",
                        name: refusal_name(&kind.value),
                    });
                }
                evidence.push(EvidenceRequirement::new(declared, issuer, *max_age_seconds));
            }
        }
    }

    if parsed.rules.len() > MAX_RULES {
        return Err(PolicyCompileRefusal::RuleCountExceeded {
            observed: parsed.rules.len(),
            limit: MAX_RULES,
        });
    }

    let scope = Scope {
        aggregates: &aggregates,
        evidence: &evidence,
    };

    let mut rules: Vec<CompiledRule> = Vec::with_capacity(parsed.rules.len());
    for rule in &parsed.rules {
        let compiled = compile_rule(rule, scope)?;
        if rules.iter().any(|existing| existing.id() == compiled.id()) {
            return Err(PolicyCompileRefusal::DuplicateRuleId {
                id: refusal_name(&rule.id.value),
            });
        }
        rules.push(compiled);
    }

    Ok(CompiledPolicy::new(
        name,
        aggregates,
        evidence,
        rules,
        outcome(&parsed.default_outcome),
    ))
}

#[derive(Clone, Copy)]
struct Scope<'a> {
    aggregates: &'a [AggregateName],
    evidence: &'a [EvidenceRequirement],
}

impl Scope<'_> {
    fn declares_aggregate(self, name: AggregateName) -> bool {
        self.aggregates.contains(&name)
    }

    fn declares_evidence(self, kind: EvidenceKind) -> bool {
        self.evidence
            .iter()
            .any(|requirement| requirement.kind() == kind)
    }
}

fn compile_rule(rule: &SourceRule, scope: Scope<'_>) -> Result<CompiledRule, PolicyCompileRefusal> {
    let id = declared_name::<RuleId>("rule identifier", &rule.id, RuleId::try_new)?;
    let predicate = compile_expr(&rule.id.value, &rule.predicate, scope)?;
    Ok(CompiledRule::new(id, predicate, outcome(&rule.outcome)))
}

fn outcome(written: &SourceOutcome) -> RuleOutcome {
    match written {
        SourceOutcome::Allow => RuleOutcome::Allow,
        SourceOutcome::Deny(reason) => RuleOutcome::Deny(DenyReason::new_truncating(reason)),
    }
}

fn declared_name<T>(
    field: &'static str,
    written: &Spanned<Box<str>>,
    build: fn(&[u8]) -> Result<T, fgit_types::TypeRefusal>,
) -> Result<T, PolicyCompileRefusal> {
    if is_keyword(&written.value) {
        return Err(PolicyCompileRefusal::Syntax(
            PolicySyntaxRefusal::LabelInvalid {
                offset: written.offset,
                field,
                name: written.value.clone(),
            },
        ));
    }
    build(written.value.as_bytes()).map_err(|_| {
        PolicyCompileRefusal::Syntax(PolicySyntaxRefusal::LabelInvalid {
            offset: written.offset,
            field,
            name: written.value.clone(),
        })
    })
}

fn compile_expr(
    rule: &str,
    expr: &SourceExpr,
    scope: Scope<'_>,
) -> Result<Predicate, PolicyCompileRefusal> {
    match expr {
        SourceExpr::Literal(true) => Ok(Predicate::Always),
        SourceExpr::Literal(false) => Ok(Predicate::Never),
        SourceExpr::All(operands) => Ok(Predicate::All(compile_operands(rule, operands, scope)?)),
        SourceExpr::Any(operands) => Ok(Predicate::Any(compile_operands(rule, operands, scope)?)),
        SourceExpr::Not(inner) => Ok(Predicate::Not(Box::new(compile_expr(rule, inner, scope)?))),
        SourceExpr::Bare(written) => compile_bare(rule, written, scope),
        SourceExpr::Comparison {
            selector,
            operator,
            operand,
            ..
        } => compile_comparison(rule, selector, *operator, operand, scope),
        SourceExpr::Evidence(written) => {
            let kind =
                declared_name::<EvidenceKind>("evidence kind", written, EvidenceKind::try_new)?;
            if scope.declares_evidence(kind) {
                Ok(Predicate::EvidenceAccepted(kind))
            } else {
                Err(PolicyCompileRefusal::UnknownEvidenceKind {
                    rule: refusal_name(rule),
                    kind: refusal_name(&written.value),
                })
            }
        }
    }
}

fn compile_operands(
    rule: &str,
    operands: &[SourceExpr],
    scope: Scope<'_>,
) -> Result<Vec<Predicate>, PolicyCompileRefusal> {
    operands
        .iter()
        .map(|operand| compile_expr(rule, operand, scope))
        .collect()
}

fn compile_bare(
    rule: &str,
    written: &Spanned<Box<str>>,
    scope: Scope<'_>,
) -> Result<Predicate, PolicyCompileRefusal> {
    match resolve_selector(rule, written, scope)? {
        Resolved::Fixed(Selector::RefForceRequested) => Ok(Predicate::ForceRequested),
        Resolved::Fixed(selector) => Err(PolicyCompileRefusal::OperatorNotApplicable {
            rule: refusal_name(rule),
            selector: refusal_name(selector.token()),
            operator: "(no operator)",
            admits: selector.value_kind().admits(),
        }),
        Resolved::Aggregate(_) => Err(PolicyCompileRefusal::OperatorNotApplicable {
            rule: refusal_name(rule),
            selector: refusal_name(&written.value),
            operator: "(no operator)",
            admits: "`==`, `!=`, `<`, `<=`, `>`, and `>=`",
        }),
    }
}

enum Resolved {
    Fixed(Selector),
    Aggregate(AggregateName),
}

fn resolve_selector(
    rule: &str,
    written: &Spanned<Box<str>>,
    scope: Scope<'_>,
) -> Result<Resolved, PolicyCompileRefusal> {
    if let Some(selector) = Selector::from_token(&written.value) {
        return Ok(Resolved::Fixed(selector));
    }
    if let Some(suffix) = written.value.strip_prefix(Selector::AGGREGATE_PREFIX) {
        let spanned = Spanned::new(suffix.to_owned().into_boxed_str(), written.offset);
        let name =
            declared_name::<AggregateName>("aggregate name", &spanned, AggregateName::try_new)?;
        if scope.declares_aggregate(name) {
            return Ok(Resolved::Aggregate(name));
        }
        return Err(PolicyCompileRefusal::UnknownAggregate {
            rule: refusal_name(rule),
            name: refusal_name(suffix),
        });
    }
    Err(PolicyCompileRefusal::UnknownSelector {
        rule: refusal_name(rule),
        selector: refusal_name(&written.value),
    })
}

fn compile_comparison(
    rule: &str,
    selector: &Spanned<Box<str>>,
    operator: SourceOperator,
    operand: &SourceOperand,
    scope: Scope<'_>,
) -> Result<Predicate, PolicyCompileRefusal> {
    match resolve_selector(rule, selector, scope)? {
        Resolved::Aggregate(name) => compile_aggregate(rule, selector, name, operator, operand),
        Resolved::Fixed(fixed) => match fixed.value_kind() {
            ValueKind::Text => compile_text(rule, fixed, operator, operand),
            ValueKind::UpdateKind => compile_update_kind(rule, fixed, operator, operand),
            ValueKind::PrincipalKind => compile_principal_kind(rule, fixed, operator, operand),
            ValueKind::Authentication => compile_authentication(rule, fixed, operator, operand),
            ValueKind::LabelSet => compile_label_set(rule, fixed, operator, operand),
            ValueKind::Boolean => Err(not_applicable(rule, fixed, operator)),
        },
    }
}

fn not_applicable(
    rule: &str,
    selector: Selector,
    operator: SourceOperator,
) -> PolicyCompileRefusal {
    PolicyCompileRefusal::OperatorNotApplicable {
        rule: refusal_name(rule),
        selector: refusal_name(selector.token()),
        operator: operator.token(),
        admits: selector.value_kind().admits(),
    }
}

fn mismatch(
    rule: &str,
    selector: Selector,
    expected: &'static str,
    operand: &SourceOperand,
) -> PolicyCompileRefusal {
    PolicyCompileRefusal::OperandTypeMismatch {
        rule: refusal_name(rule),
        selector: refusal_name(selector.token()),
        expected,
        found: operand.shape(),
    }
}

fn text_operand(operand: &SourceOperand) -> Option<&str> {
    match operand {
        SourceOperand::Text(value) => Some(&value.value),
        _ => None,
    }
}

fn name_operand(operand: &SourceOperand) -> Option<&str> {
    match operand {
        SourceOperand::Name(value) => Some(&value.value),
        _ => None,
    }
}

fn set_operand(operand: &SourceOperand) -> Option<&[SourceOperand]> {
    match operand {
        SourceOperand::Set(value) => Some(&value.value),
        _ => None,
    }
}

fn compile_text(
    rule: &str,
    selector: Selector,
    operator: SourceOperator,
    operand: &SourceOperand,
) -> Result<Predicate, PolicyCompileRefusal> {
    match operator {
        SourceOperator::Equal | SourceOperator::NotEqual => {
            let text = text_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a quoted string", operand))?;
            let equals = Predicate::TextEquals {
                selector,
                value: TextLiteral::new(text),
            };
            Ok(negate_if(operator, equals))
        }
        SourceOperator::Matches => {
            let text = text_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a quoted string", operand))?;
            let pattern = RefPattern::compile(text).map_err(|reason| {
                PolicyCompileRefusal::RefPatternInvalid {
                    rule: refusal_name(rule),
                    pattern: refusal_name(text),
                    reason,
                }
            })?;
            Ok(Predicate::TextMatches { selector, pattern })
        }
        SourceOperator::In => {
            let elements = set_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a set of quoted strings", operand))?;
            let mut values = Vec::with_capacity(elements.len());
            for element in elements {
                let text = text_operand(element)
                    .ok_or_else(|| mismatch(rule, selector, "a set of quoted strings", element))?;
                values.push(TextLiteral::new(text));
            }
            Ok(Predicate::TextIn { selector, values })
        }
        SourceOperator::Contains
        | SourceOperator::Less
        | SourceOperator::LessOrEqual
        | SourceOperator::Greater
        | SourceOperator::GreaterOrEqual => Err(not_applicable(rule, selector, operator)),
    }
}

fn compile_update_kind(
    rule: &str,
    selector: Selector,
    operator: SourceOperator,
    operand: &SourceOperand,
) -> Result<Predicate, PolicyCompileRefusal> {
    let admits = "`create`, `fast_forward`, `non_fast_forward`, `delete`";
    match operator {
        SourceOperator::Equal | SourceOperator::NotEqual => {
            let literal = name_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a bare name", operand))?;
            let kind = RefUpdateKind::from_token(literal).ok_or_else(|| {
                PolicyCompileRefusal::UnknownEnumLiteral {
                    rule: refusal_name(rule),
                    selector: refusal_name(selector.token()),
                    literal: refusal_name(literal),
                    admits: refusal_name(admits),
                }
            })?;
            Ok(negate_if(operator, Predicate::UpdateKindEquals(kind)))
        }
        SourceOperator::In => {
            let elements = set_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a set of bare names", operand))?;
            let mut kinds = Vec::with_capacity(elements.len());
            for element in elements {
                let literal = name_operand(element)
                    .ok_or_else(|| mismatch(rule, selector, "a set of bare names", element))?;
                kinds.push(RefUpdateKind::from_token(literal).ok_or_else(|| {
                    PolicyCompileRefusal::UnknownEnumLiteral {
                        rule: refusal_name(rule),
                        selector: refusal_name(selector.token()),
                        literal: refusal_name(literal),
                        admits: refusal_name(admits),
                    }
                })?);
            }
            Ok(Predicate::UpdateKindIn(kinds))
        }
        SourceOperator::Matches
        | SourceOperator::Contains
        | SourceOperator::Less
        | SourceOperator::LessOrEqual
        | SourceOperator::Greater
        | SourceOperator::GreaterOrEqual => Err(not_applicable(rule, selector, operator)),
    }
}

fn compile_principal_kind(
    rule: &str,
    selector: Selector,
    operator: SourceOperator,
    operand: &SourceOperand,
) -> Result<Predicate, PolicyCompileRefusal> {
    let admits = "`human`, `machine`, `agent`, `service`";
    match operator {
        SourceOperator::Equal | SourceOperator::NotEqual => {
            let literal = name_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a bare name", operand))?;
            let kind = PrincipalKind::from_token(literal).ok_or_else(|| {
                PolicyCompileRefusal::UnknownEnumLiteral {
                    rule: refusal_name(rule),
                    selector: refusal_name(selector.token()),
                    literal: refusal_name(literal),
                    admits: refusal_name(admits),
                }
            })?;
            Ok(negate_if(operator, Predicate::PrincipalKindEquals(kind)))
        }
        SourceOperator::In => {
            let elements = set_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a set of bare names", operand))?;
            let mut kinds = Vec::with_capacity(elements.len());
            for element in elements {
                let literal = name_operand(element)
                    .ok_or_else(|| mismatch(rule, selector, "a set of bare names", element))?;
                kinds.push(PrincipalKind::from_token(literal).ok_or_else(|| {
                    PolicyCompileRefusal::UnknownEnumLiteral {
                        rule: refusal_name(rule),
                        selector: refusal_name(selector.token()),
                        literal: refusal_name(literal),
                        admits: refusal_name(admits),
                    }
                })?);
            }
            Ok(Predicate::PrincipalKindIn(kinds))
        }
        SourceOperator::Matches
        | SourceOperator::Contains
        | SourceOperator::Less
        | SourceOperator::LessOrEqual
        | SourceOperator::Greater
        | SourceOperator::GreaterOrEqual => Err(not_applicable(rule, selector, operator)),
    }
}

fn compile_authentication(
    rule: &str,
    selector: Selector,
    operator: SourceOperator,
    operand: &SourceOperand,
) -> Result<Predicate, PolicyCompileRefusal> {
    let admits = "`none`, `single_factor`, `multi_factor`, `hardware_backed`";
    let strength = |literal: &str| -> Result<AuthenticationStrength, PolicyCompileRefusal> {
        AuthenticationStrength::from_token(literal).ok_or_else(|| {
            PolicyCompileRefusal::UnknownEnumLiteral {
                rule: refusal_name(rule),
                selector: refusal_name(selector.token()),
                literal: refusal_name(literal),
                admits: refusal_name(admits),
            }
        })
    };
    match operator {
        SourceOperator::In => {
            let elements = set_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a set of bare names", operand))?;
            let mut alternatives = Vec::with_capacity(elements.len());
            for element in elements {
                let literal = name_operand(element)
                    .ok_or_else(|| mismatch(rule, selector, "a set of bare names", element))?;
                alternatives.push(Predicate::AuthenticationCompare {
                    operator: Compare::Equal,
                    value: strength(literal)?,
                });
            }
            Ok(Predicate::Any(alternatives))
        }
        SourceOperator::Matches | SourceOperator::Contains => {
            Err(not_applicable(rule, selector, operator))
        }
        _ => {
            let literal = name_operand(operand)
                .ok_or_else(|| mismatch(rule, selector, "a bare name", operand))?;
            let value = strength(literal)?;
            let compare =
                compare_of(operator).ok_or_else(|| not_applicable(rule, selector, operator))?;
            Ok(negate_if(
                operator,
                Predicate::AuthenticationCompare {
                    operator: compare,
                    value,
                },
            ))
        }
    }
}

fn compile_label_set(
    rule: &str,
    selector: Selector,
    operator: SourceOperator,
    operand: &SourceOperand,
) -> Result<Predicate, PolicyCompileRefusal> {
    if operator != SourceOperator::Contains {
        return Err(not_applicable(rule, selector, operator));
    }
    let SourceOperand::Name(written) = operand else {
        return Err(mismatch(rule, selector, "a bare name", operand));
    };
    let label = declared_name::<LabelName>("label", written, LabelName::try_new)?;
    Ok(Predicate::LabelContains { selector, label })
}

fn compile_aggregate(
    rule: &str,
    selector: &Spanned<Box<str>>,
    name: AggregateName,
    operator: SourceOperator,
    operand: &SourceOperand,
) -> Result<Predicate, PolicyCompileRefusal> {
    let Some(compare) = compare_of(operator) else {
        return Err(PolicyCompileRefusal::OperatorNotApplicable {
            rule: refusal_name(rule),
            selector: refusal_name(&selector.value),
            operator: operator.token(),
            admits: "`==`, `!=`, `<`, `<=`, `>`, and `>=`",
        });
    };
    let SourceOperand::Integer(value) = operand else {
        return Err(PolicyCompileRefusal::OperandTypeMismatch {
            rule: refusal_name(rule),
            selector: refusal_name(&selector.value),
            expected: "an integer",
            found: operand.shape(),
        });
    };
    Ok(negate_if(
        operator,
        Predicate::AggregateCompare {
            name,
            operator: compare,
            value: value.value,
        },
    ))
}

/// The ordering comparison an operator carries, if it carries one.
///
/// `!=` maps to `Equal` and is wrapped by [`negate_if`], so the compiled form
/// has one equality node and one negation rather than a second equality
/// variant that normalization would have to know about.
const fn compare_of(operator: SourceOperator) -> Option<Compare> {
    match operator {
        SourceOperator::Equal | SourceOperator::NotEqual => Some(Compare::Equal),
        SourceOperator::Less => Some(Compare::Less),
        SourceOperator::LessOrEqual => Some(Compare::LessOrEqual),
        SourceOperator::Greater => Some(Compare::Greater),
        SourceOperator::GreaterOrEqual => Some(Compare::GreaterOrEqual),
        SourceOperator::Matches | SourceOperator::In | SourceOperator::Contains => None,
    }
}

fn negate_if(operator: SourceOperator, predicate: Predicate) -> Predicate {
    if operator == SourceOperator::NotEqual {
        Predicate::Not(Box::new(predicate))
    } else {
        predicate
    }
}
