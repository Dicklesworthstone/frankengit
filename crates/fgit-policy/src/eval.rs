//! The evaluator: a pure function from a snapshot and an input root to a
//! decision and a trace.
//!
//! ## Purity, concretely
//!
//! [`evaluate`] takes two shared references and returns a value. It reads no
//! clock, opens nothing, and mutates nothing. Everything it needs is a field
//! of the input root, including the instant evidence expiry is decided
//! against. Two calls with equal arguments return equal results, and
//! [`render_trace`] of those results is byte-identical.
//!
//! ## Every rule is consulted
//!
//! There is no first-match exit. Every rule in the policy is evaluated for
//! every subject and appears in that subject's trace with its verdict, which
//! is what makes the explainability requirement checkable rather than
//! aspirational: a rule that did not fire is visibly present and visibly
//! unmatched, so "why was this allowed" and "why did that rule not stop it"
//! have the same answer in the same place.
//!
//! ## Deny overrides
//!
//! Among the rules that matched, a denial wins. Rules are consulted in
//! canonical identifier order, and the first denying rule is named as the
//! governing one. If no rule matched, the policy's declared default applies —
//! there is no implicit default, because the compiler refuses a policy that
//! does not state one.
//!
//! An exception to a denial is written inside the denying rule's condition,
//! not as a competing rule: `when ... and not evidence break_glass`. That is a
//! deliberate restriction. Rule-level overrides make the meaning of a policy
//! depend on a precedence table that has to be read alongside it, and the
//! precedence table is where protected-branch implementations go wrong.
//!
//! ## A refusal is not an allow
//!
//! [`PolicyEvalRefusal`] means the input root did not carry a fact the policy
//! reads. Every caller treats it as a denial of the whole input root; it is
//! returned as an error rather than as `Decision::Deny` so that a caller
//! cannot log it as an ordinary policy denial and lose the fact that the
//! policy never actually ran.

use core::fmt::Write as _;

use crate::basis::{
    AggregateName, EvidenceKind, EvidenceReceipt, IssuerLabel, PolicyInputRoot, PolicyInstant,
    RefUpdateFact, RefUpdateKind,
};
use crate::content::{PolicySnapshot, PolicySnapshotId};
use crate::error::{PolicyEvalRefusal, refusal_name};
use crate::program::{
    CompiledPolicy, Decision, DenyReason, PolicyName, Predicate, RuleId, RuleOutcome, Selector,
};

/// One rule, as consulted for one subject.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleVisit {
    rule: RuleId,
    matched: bool,
    outcome: RuleOutcome,
}

impl RuleVisit {
    /// The rule consulted.
    #[must_use]
    pub const fn rule(&self) -> RuleId {
        self.rule
    }

    /// Whether its condition held.
    #[must_use]
    pub const fn matched(&self) -> bool {
        self.matched
    }

    /// What the rule would say if its condition held.
    #[must_use]
    pub const fn outcome(&self) -> &RuleOutcome {
        &self.outcome
    }
}

/// One receipt a policy accepted while deciding one subject.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvidenceUse {
    kind: EvidenceKind,
    issuer: IssuerLabel,
    issued_at: PolicyInstant,
    expires_at: PolicyInstant,
}

impl EvidenceUse {
    /// The class of evidence.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// The issuer of the accepted receipt.
    #[must_use]
    pub const fn issuer(&self) -> IssuerLabel {
        self.issuer
    }

    /// When the accepted receipt became live.
    #[must_use]
    pub const fn issued_at(&self) -> PolicyInstant {
        self.issued_at
    }

    /// When it stops being live.
    #[must_use]
    pub const fn expires_at(&self) -> PolicyInstant {
        self.expires_at
    }
}

/// The decision for one ref command, with the trace behind it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectOutcome {
    index: usize,
    name: Vec<u8>,
    update: RefUpdateKind,
    decision: Decision,
    governing_rule: Option<RuleId>,
    reason: Option<DenyReason>,
    visits: Vec<RuleVisit>,
    evidence: Vec<EvidenceUse>,
}

impl SubjectOutcome {
    /// Position of the ref command in the input root.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// The ref, as bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// The shape of the ref command.
    #[must_use]
    pub const fn update(&self) -> RefUpdateKind {
        self.update
    }

    /// The verdict for this command.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        self.decision
    }

    /// The rule that decided it, absent when the default applied.
    #[must_use]
    pub const fn governing_rule(&self) -> Option<RuleId> {
        self.governing_rule
    }

    /// The reason, when the verdict is a denial.
    #[must_use]
    pub const fn reason(&self) -> Option<&DenyReason> {
        self.reason.as_ref()
    }

    /// Every rule consulted, in canonical order.
    #[must_use]
    pub fn visits(&self) -> &[RuleVisit] {
        &self.visits
    }

    /// Every receipt accepted while deciding this command.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceUse] {
        &self.evidence
    }
}

/// The decision for a whole input root, with the trace behind it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyEvaluation {
    policy: PolicyName,
    snapshot: PolicySnapshotId,
    decision: Decision,
    subjects: Vec<SubjectOutcome>,
}

impl PolicyEvaluation {
    /// The name of the policy that decided.
    #[must_use]
    pub const fn policy(&self) -> PolicyName {
        self.policy
    }

    /// The policy snapshot the decision was made under.
    #[must_use]
    pub const fn snapshot(&self) -> PolicySnapshotId {
        self.snapshot
    }

    /// The verdict for the whole input root.
    ///
    /// A denial of any one ref command denies the whole root: a receive-pack
    /// command list publishes together or not at all, so a per-command allow
    /// beside a per-command deny is not a state that can be acted on.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        self.decision
    }

    /// The per-command outcomes, in the order the caller supplied them.
    #[must_use]
    pub fn subjects(&self) -> &[SubjectOutcome] {
        &self.subjects
    }
}

/// Decides an input root against a policy snapshot.
pub fn evaluate(
    snapshot: &PolicySnapshot,
    input: &PolicyInputRoot,
) -> Result<PolicyEvaluation, PolicyEvalRefusal> {
    let policy = snapshot.policy();
    require_aggregates(policy, input)?;

    let actor_id = input.principal().principal().to_string();
    let actor_snapshot = input.principal().snapshot().to_string();

    let mut subjects = Vec::with_capacity(input.updates().len());
    let mut overall = Decision::Allow;
    for (index, update) in input.updates().iter().enumerate() {
        let facts = Facts {
            policy,
            input,
            subject: update,
            actor_id: &actor_id,
            actor_snapshot: &actor_snapshot,
        };
        let outcome = decide_subject(index, &facts);
        if outcome.decision == Decision::Deny {
            overall = Decision::Deny;
        }
        subjects.push(outcome);
    }

    Ok(PolicyEvaluation {
        policy: policy.name(),
        snapshot: snapshot.id(),
        decision: overall,
        subjects,
    })
}

/// Refuses before any subject is decided when a declared aggregate is absent.
///
/// Checked up front rather than where a predicate happens to read it, because
/// a conjunction that stops early would otherwise decide some input roots
/// against a missing fact and refuse others, purely on the order of the other
/// operands. A policy either has the facts it reads or it does not run.
fn require_aggregates(
    policy: &CompiledPolicy,
    input: &PolicyInputRoot,
) -> Result<(), PolicyEvalRefusal> {
    for rule in policy.rules() {
        for name in rule.predicate().aggregates() {
            if !input.aggregates().contains_key(&name) {
                return Err(PolicyEvalRefusal::AggregateMissing {
                    rule: refusal_name(rule.id().as_str()),
                    name,
                });
            }
        }
    }
    Ok(())
}

struct Facts<'a> {
    policy: &'a CompiledPolicy,
    input: &'a PolicyInputRoot,
    subject: &'a RefUpdateFact,
    actor_id: &'a str,
    actor_snapshot: &'a str,
}

impl Facts<'_> {
    fn text(&self, selector: Selector) -> &[u8] {
        match selector {
            Selector::RefName => self.subject.name().as_bytes(),
            Selector::RefScope => self.subject.scope(),
            Selector::ActorId => self.actor_id.as_bytes(),
            Selector::ActorSnapshot => self.actor_snapshot.as_bytes(),
            // Reached only through a compiled predicate, and the compiler only
            // builds text comparisons for the four selectors above.
            _ => &[],
        }
    }

    fn accepted(&self, kind: EvidenceKind) -> Option<&EvidenceReceipt> {
        let requirement = self.policy.requirement(kind)?;
        let instant = self.input.instant();
        self.input.receipts().iter().find(|receipt| {
            receipt.kind() == kind
                && receipt.subject() == self.subject.name()
                && receipt.issuer() == requirement.issuer()
                && receipt.is_live_at(instant)
                && requirement
                    .max_age_seconds()
                    .is_none_or(|max_age| instant.saturating_since(receipt.issued_at()) <= max_age)
        })
    }

    fn aggregate(&self, name: AggregateName) -> Option<u64> {
        self.input.aggregates().get(&name).copied()
    }
}

fn decide_subject(index: usize, facts: &Facts<'_>) -> SubjectOutcome {
    let mut visits = Vec::with_capacity(facts.policy.rules().len());
    let mut denial: Option<(RuleId, DenyReason)> = None;
    let mut permission: Option<RuleId> = None;

    for rule in facts.policy.rules() {
        let matched = holds(rule.predicate(), facts);
        if matched {
            match rule.outcome() {
                RuleOutcome::Deny(reason) => {
                    if denial.is_none() {
                        denial = Some((rule.id(), reason.clone()));
                    }
                }
                RuleOutcome::Allow => {
                    if permission.is_none() {
                        permission = Some(rule.id());
                    }
                }
            }
        }
        visits.push(RuleVisit {
            rule: rule.id(),
            matched,
            outcome: rule.outcome().clone(),
        });
    }

    let (decision, governing_rule, reason) = match (denial, permission) {
        (Some((rule, reason)), _) => (Decision::Deny, Some(rule), Some(reason)),
        (None, Some(rule)) => (Decision::Allow, Some(rule), None),
        (None, None) => match facts.policy.default_outcome() {
            RuleOutcome::Allow => (Decision::Allow, None, None),
            RuleOutcome::Deny(reason) => (Decision::Deny, None, Some(reason.clone())),
        },
    };

    SubjectOutcome {
        index,
        name: facts.subject.name().as_bytes().to_vec(),
        update: facts.subject.kind(),
        decision,
        governing_rule,
        reason,
        visits,
        evidence: accepted_evidence(facts),
    }
}

/// Every receipt the policy accepted for this subject, in canonical order.
///
/// Computed from the union of the evidence kinds the policy's rules name,
/// independently of which rules matched and independently of whether a
/// conjunction stopped early. A trace that only listed the receipts a
/// short-circuiting evaluation happened to look at would vary with facts that
/// have nothing to do with the evidence.
fn accepted_evidence(facts: &Facts<'_>) -> Vec<EvidenceUse> {
    let mut kinds: Vec<EvidenceKind> = facts
        .policy
        .rules()
        .iter()
        .flat_map(|rule| rule.predicate().evidence_kinds())
        .collect();
    kinds.sort();
    kinds.dedup();
    kinds
        .into_iter()
        .filter_map(|kind| {
            facts.accepted(kind).map(|receipt| EvidenceUse {
                kind,
                issuer: receipt.issuer(),
                issued_at: receipt.issued_at(),
                expires_at: receipt.expires_at(),
            })
        })
        .collect()
}

fn holds(predicate: &Predicate, facts: &Facts<'_>) -> bool {
    match predicate {
        Predicate::Always => true,
        Predicate::Never => false,
        Predicate::All(operands) => operands.iter().all(|operand| holds(operand, facts)),
        Predicate::Any(operands) => operands.iter().any(|operand| holds(operand, facts)),
        Predicate::Not(inner) => !holds(inner, facts),
        Predicate::TextEquals { selector, value } => {
            facts.text(*selector) == value.as_str().as_bytes()
        }
        Predicate::TextIn { selector, values } => {
            let observed = facts.text(*selector);
            values
                .iter()
                .any(|value| observed == value.as_str().as_bytes())
        }
        Predicate::TextMatches { selector, pattern } => pattern.matches(facts.text(*selector)),
        Predicate::UpdateKindEquals(kind) => facts.subject.kind() == *kind,
        Predicate::UpdateKindIn(kinds) => kinds.contains(&facts.subject.kind()),
        Predicate::PrincipalKindEquals(kind) => facts.input.principal().kind() == *kind,
        Predicate::PrincipalKindIn(kinds) => kinds.contains(&facts.input.principal().kind()),
        Predicate::AuthenticationCompare { operator, value } => operator.holds(
            facts.input.principal().authentication().rank(),
            value.rank(),
        ),
        Predicate::LabelContains { selector, label } => match selector {
            Selector::ActorTeams => facts.input.principal().teams().contains(label),
            Selector::ActorCapabilities => facts.input.principal().capabilities().contains(label),
            // Reached only through a compiled predicate, and the compiler only
            // builds label containment for the two selectors above.
            _ => false,
        },
        Predicate::ForceRequested => facts.subject.force_requested(),
        Predicate::AggregateCompare {
            name,
            operator,
            value,
        } => facts
            .aggregate(*name)
            .is_some_and(|reading| operator.holds(reading, *value)),
        Predicate::EvidenceAccepted(kind) => facts.accepted(*kind).is_some(),
    }
}

/// Renders a decision trace in the exact form the goldens hold.
///
/// The format is deliberately line-oriented, deliberately free of digests, and
/// deliberately complete: one `consulted` line per rule per subject, whether or
/// not it matched. It carries no snapshot identity, because a golden that
/// embedded one would have to be regenerated whenever any unrelated part of
/// the encoding moved, and regenerating goldens is how a suite stops noticing
/// changes. The identity is on [`PolicyEvaluation::snapshot`], and the tests
/// assert it by equality rather than against a literal.
///
/// ```text
/// policy protected_main
/// decision deny
/// subject 0 refs/heads/main non_fast_forward -> deny
///   governed-by deny_force_on_protected
///   reason "forced update to a protected ref"
///   consulted allow_reviewed_fast_forward unmatched allow
///   consulted deny_force_on_protected matched deny
/// ```
#[must_use]
pub fn render_trace(evaluation: &PolicyEvaluation) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "policy {}", evaluation.policy);
    let _ = writeln!(text, "decision {}", evaluation.decision.token());
    for subject in &evaluation.subjects {
        let _ = writeln!(
            text,
            "subject {} {} {} -> {}",
            subject.index,
            String::from_utf8_lossy(&subject.name),
            subject.update.token(),
            subject.decision.token()
        );
        let _ = match subject.governing_rule {
            Some(rule) => writeln!(text, "  governed-by {rule}"),
            None => writeln!(text, "  governed-by (default)"),
        };
        let _ = match &subject.reason {
            Some(reason) => writeln!(text, "  reason \"{reason}\""),
            None => writeln!(text, "  reason (none)"),
        };
        for used in &subject.evidence {
            let _ = writeln!(
                text,
                "  evidence {} {} issued {} expires {}",
                used.kind, used.issuer, used.issued_at, used.expires_at
            );
        }
        for visit in &subject.visits {
            let _ = writeln!(
                text,
                "  consulted {} {} {}",
                visit.rule,
                if visit.matched {
                    "matched"
                } else {
                    "unmatched"
                },
                visit.outcome.decision().token()
            );
        }
    }
    text
}
