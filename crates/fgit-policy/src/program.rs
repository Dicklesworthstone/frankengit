//! The compiled policy: the closed form a snapshot is built from and an
//! evaluation runs against.
//!
//! Everything here is a closed enumeration. That is the structural guarantee
//! the constitution asks for: a [`Predicate`] has no call form, no free
//! identifier, and no variant that reads anything outside the input root, so a
//! compiled policy cannot express ambient I/O even if a source text tried to.
//! There is nothing to sandbox because there is nothing to escape.
//!
//! ## Normalization
//!
//! [`Predicate::normalize`] is the function that makes two source texts
//! stating the same thing in a different order compile to the same bytes:
//!
//! * `not not p` folds to `p`, and `not` of a constant folds to the other
//!   constant;
//! * nested `all` flattens into one `all`, and likewise `any`;
//! * an `all` drops its `always` operands, collapses to `never` if any operand
//!   is `never`, and sorts and deduplicates what is left; `any` is the dual;
//! * an `all` or `any` with one operand becomes that operand, and with none
//!   becomes its unit (`always` for `all`, `never` for `any`);
//! * set literals sort and deduplicate, an empty set folds to `never`, and a
//!   one-element set folds to the corresponding equality.
//!
//! It is idempotent by construction: every rule above either removes a node or
//! puts one into a canonical order that reapplying leaves alone.

use crate::basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, IssuerLabel, LabelName, PrincipalKind,
    RefUpdateKind,
};
use crate::glob::RefPattern;

slug_newtype!(RuleId, "RuleId", "The identifier of one policy rule.");
slug_newtype!(PolicyName, "PolicyName", "The name of one policy.");

/// Largest accepted number of rules in one policy.
pub const MAX_RULES: usize = 1_024;

/// Largest accepted nesting depth of a predicate.
pub const MAX_PREDICATE_DEPTH: u32 = 32;

/// Largest accepted number of elements in a set literal.
pub const MAX_SET_ELEMENTS: usize = 256;

/// Largest accepted length of a deny reason, in bytes.
pub const MAX_DENY_REASON_LEN: usize = 256;

/// Largest accepted length of a text literal, in bytes.
pub const MAX_TEXT_LITERAL_LEN: usize = 1_024;

/// The verdict a policy reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Decision {
    /// The request may proceed.
    Allow,
    /// The request may not proceed.
    Deny,
}

impl Decision {
    /// The stable lowercase token used in traces.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// The stable numeric code point used in canonical bytes.
    #[must_use]
    pub const fn code_point(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
        }
    }

    /// Resolves a code point, refusing one the closed set does not name.
    #[must_use]
    pub const fn from_code_point(code_point: u8) -> Option<Self> {
        match code_point {
            1 => Some(Self::Allow),
            2 => Some(Self::Deny),
            _ => None,
        }
    }
}

/// The human-readable reason a rule denies.
///
/// Bounded, because it is reflected to a client: an unbounded reason would let
/// a policy author choose how many bytes every refused push costs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DenyReason(Box<str>);

impl DenyReason {
    /// Builds a reason, truncating nothing and refusing an over-long one.
    #[must_use]
    pub fn new_truncating(text: &str) -> Self {
        let mut end = text.len().min(MAX_DENY_REASON_LEN);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(text[..end].to_owned().into_boxed_str())
    }

    /// The reason text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for DenyReason {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What one rule says when its predicate holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleOutcome {
    /// The rule permits the update.
    Allow,
    /// The rule refuses it, and says why.
    Deny(DenyReason),
}

impl RuleOutcome {
    /// The verdict this outcome carries.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        match self {
            Self::Allow => Decision::Allow,
            Self::Deny(_) => Decision::Deny,
        }
    }

    /// The reason, when this outcome is a denial.
    #[must_use]
    pub const fn reason(&self) -> Option<&DenyReason> {
        match self {
            Self::Allow => None,
            Self::Deny(reason) => Some(reason),
        }
    }
}

/// An ordering comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Compare {
    /// Equal.
    Equal,
    /// Strictly less.
    Less,
    /// Less or equal.
    LessOrEqual,
    /// Strictly greater.
    Greater,
    /// Greater or equal.
    GreaterOrEqual,
}

impl Compare {
    /// Every comparison, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Equal,
        Self::Less,
        Self::LessOrEqual,
        Self::Greater,
        Self::GreaterOrEqual,
    ];

    /// The stable token used in source text and in traces.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::Less => "<",
            Self::LessOrEqual => "<=",
            Self::Greater => ">",
            Self::GreaterOrEqual => ">=",
        }
    }

    /// The stable numeric code point used in canonical bytes.
    #[must_use]
    pub const fn code_point(self) -> u8 {
        match self {
            Self::Equal => 1,
            Self::Less => 2,
            Self::LessOrEqual => 3,
            Self::Greater => 4,
            Self::GreaterOrEqual => 5,
        }
    }

    /// Resolves a code point, refusing one the closed set does not name.
    #[must_use]
    pub const fn from_code_point(code_point: u8) -> Option<Self> {
        match code_point {
            1 => Some(Self::Equal),
            2 => Some(Self::Less),
            3 => Some(Self::LessOrEqual),
            4 => Some(Self::Greater),
            5 => Some(Self::GreaterOrEqual),
            _ => None,
        }
    }

    /// Applies the comparison to two ordinals.
    #[must_use]
    pub const fn holds(self, left: u64, right: u64) -> bool {
        match self {
            Self::Equal => left == right,
            Self::Less => left < right,
            Self::LessOrEqual => left <= right,
            Self::Greater => left > right,
            Self::GreaterOrEqual => left >= right,
        }
    }
}

/// The shape of the value a selector reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ValueKind {
    /// A byte string, compared by equality, membership, or ref pattern.
    Text,
    /// A closed enumeration of ref update shapes.
    UpdateKind,
    /// A closed enumeration of principal kinds.
    PrincipalKind,
    /// An ordered closed enumeration of authentication strengths.
    Authentication,
    /// A set of labels, tested with `contains`.
    LabelSet,
    /// A truth value, used bare.
    Boolean,
}

impl ValueKind {
    /// The operators this shape admits, for a refusal message.
    #[must_use]
    pub const fn admits(self) -> &'static str {
        match self {
            Self::Text => "`==`, `!=`, `in`, and `matches`",
            Self::UpdateKind | Self::PrincipalKind => "`==`, `!=`, and `in`",
            Self::Authentication => "`==`, `!=`, `in`, `<`, `<=`, `>`, and `>=`",
            Self::LabelSet => "`contains`",
            Self::Boolean => "no operator; write it bare or under `not`",
        }
    }
}

/// A fact a predicate may read.
///
/// The list is closed and complete. A source text naming anything else is
/// refused at compile time with
/// [`crate::PolicyCompileRefusal::UnknownSelector`], which is why a rule that
/// tried to read a clock, an environment variable, or a file has nowhere to
/// put the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Selector {
    /// The full name of the ref being decided.
    RefName,
    /// The protection scope of that ref: `heads` for `refs/heads/main`.
    RefScope,
    /// The shape of the ref command.
    RefUpdate,
    /// Whether the client asked for a forced update.
    RefForceRequested,
    /// The authenticated principal's identity, in lowercase hexadecimal.
    ActorId,
    /// The principal snapshot the attributes were read from.
    ActorSnapshot,
    /// What kind of principal it is.
    ActorKind,
    /// How strongly the principal authenticated.
    ActorAuthentication,
    /// The principal's team memberships.
    ActorTeams,
    /// The principal's capabilities.
    ActorCapabilities,
}

impl Selector {
    /// Every selector, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::RefName,
        Self::RefScope,
        Self::RefUpdate,
        Self::RefForceRequested,
        Self::ActorId,
        Self::ActorSnapshot,
        Self::ActorKind,
        Self::ActorAuthentication,
        Self::ActorTeams,
        Self::ActorCapabilities,
    ];

    /// The prefix under which aggregate readings are named.
    pub const AGGREGATE_PREFIX: &'static str = "aggregate.";

    /// The stable dotted name used in source text and in traces.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::RefName => "ref.name",
            Self::RefScope => "ref.scope",
            Self::RefUpdate => "ref.update",
            Self::RefForceRequested => "ref.force_requested",
            Self::ActorId => "actor.id",
            Self::ActorSnapshot => "actor.snapshot",
            Self::ActorKind => "actor.kind",
            Self::ActorAuthentication => "actor.authentication",
            Self::ActorTeams => "actor.teams",
            Self::ActorCapabilities => "actor.capabilities",
        }
    }

    /// Resolves a dotted name, refusing anything not in the closed list.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.token() == token)
    }

    /// The shape of the value this selector reads.
    #[must_use]
    pub const fn value_kind(self) -> ValueKind {
        match self {
            Self::RefName | Self::RefScope | Self::ActorId | Self::ActorSnapshot => ValueKind::Text,
            Self::RefUpdate => ValueKind::UpdateKind,
            Self::RefForceRequested => ValueKind::Boolean,
            Self::ActorKind => ValueKind::PrincipalKind,
            Self::ActorAuthentication => ValueKind::Authentication,
            Self::ActorTeams | Self::ActorCapabilities => ValueKind::LabelSet,
        }
    }

    /// The stable numeric code point used in canonical bytes.
    #[must_use]
    pub const fn code_point(self) -> u8 {
        match self {
            Self::RefName => 1,
            Self::RefScope => 2,
            Self::RefUpdate => 3,
            Self::RefForceRequested => 4,
            Self::ActorId => 5,
            Self::ActorSnapshot => 6,
            Self::ActorKind => 7,
            Self::ActorAuthentication => 8,
            Self::ActorTeams => 9,
            Self::ActorCapabilities => 10,
        }
    }

    /// Resolves a code point, refusing one the closed list does not name.
    #[must_use]
    pub fn from_code_point(code_point: u8) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|selector| selector.code_point() == code_point)
    }
}

/// A text literal a policy compares a text selector against.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TextLiteral(Box<str>);

impl TextLiteral {
    /// Wraps a literal.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned().into_boxed_str())
    }

    /// The literal text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for TextLiteral {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A condition over the input root.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Predicate {
    /// Holds always.
    Always,
    /// Holds never.
    Never,
    /// Holds when every operand holds.
    All(Vec<Self>),
    /// Holds when any operand holds.
    Any(Vec<Self>),
    /// Holds when the operand does not.
    Not(Box<Self>),
    /// A text selector equals a literal.
    TextEquals {
        /// The selector read.
        selector: Selector,
        /// The literal compared against.
        value: TextLiteral,
    },
    /// A text selector equals one of several literals.
    TextIn {
        /// The selector read.
        selector: Selector,
        /// The literals, sorted and deduplicated.
        values: Vec<TextLiteral>,
    },
    /// A text selector matches a ref pattern.
    TextMatches {
        /// The selector read.
        selector: Selector,
        /// The pattern.
        pattern: RefPattern,
    },
    /// The ref command has this shape.
    UpdateKindEquals(RefUpdateKind),
    /// The ref command has one of these shapes.
    UpdateKindIn(Vec<RefUpdateKind>),
    /// The principal is of this kind.
    PrincipalKindEquals(PrincipalKind),
    /// The principal is of one of these kinds.
    PrincipalKindIn(Vec<PrincipalKind>),
    /// The principal's authentication strength compares this way.
    AuthenticationCompare {
        /// The comparison.
        operator: Compare,
        /// The strength compared against.
        value: AuthenticationStrength,
    },
    /// A label set contains a label.
    LabelContains {
        /// Which label set.
        selector: Selector,
        /// The label.
        label: LabelName,
    },
    /// The client asked for a forced update.
    ForceRequested,
    /// An aggregate reading compares this way.
    AggregateCompare {
        /// The aggregate read.
        name: AggregateName,
        /// The comparison.
        operator: Compare,
        /// The value compared against.
        value: u64,
    },
    /// A live receipt of this evidence kind was offered for the subject.
    EvidenceAccepted(EvidenceKind),
}

impl Predicate {
    /// Rewrites the predicate into canonical form.
    ///
    /// Idempotent: `normalize(normalize(p)) == normalize(p)` for every `p`,
    /// which `crates/fgit-policy/tests/normalization.rs` asserts over a
    /// generated corpus rather than by inspection.
    #[must_use]
    pub fn normalize(self) -> Self {
        match self {
            Self::Not(inner) => match inner.normalize() {
                Self::Always => Self::Never,
                Self::Never => Self::Always,
                Self::Not(twice) => *twice,
                normalized => Self::Not(Box::new(normalized)),
            },
            Self::All(operands) => Self::normalize_junction(operands, true),
            Self::Any(operands) => Self::normalize_junction(operands, false),
            Self::TextIn { selector, values } => {
                let mut values = sorted_unique(values);
                if values.is_empty() {
                    Self::Never
                } else if values.len() == 1 {
                    Self::TextEquals {
                        selector,
                        value: values.remove(0),
                    }
                } else {
                    Self::TextIn { selector, values }
                }
            }
            Self::UpdateKindIn(values) => {
                let values = sorted_unique(values);
                if values.is_empty() {
                    Self::Never
                } else if values.len() == 1 {
                    Self::UpdateKindEquals(values[0])
                } else {
                    Self::UpdateKindIn(values)
                }
            }
            Self::PrincipalKindIn(values) => {
                let values = sorted_unique(values);
                if values.is_empty() {
                    Self::Never
                } else if values.len() == 1 {
                    Self::PrincipalKindEquals(values[0])
                } else {
                    Self::PrincipalKindIn(values)
                }
            }
            leaf => leaf,
        }
    }

    fn normalize_junction(operands: Vec<Self>, conjunction: bool) -> Self {
        let (absorbing, unit) = if conjunction {
            (Self::Never, Self::Always)
        } else {
            (Self::Always, Self::Never)
        };

        let mut flattened: Vec<Self> = Vec::with_capacity(operands.len());
        for operand in operands {
            let normalized = operand.normalize();
            if normalized == absorbing {
                return absorbing;
            }
            if normalized == unit {
                continue;
            }
            match normalized {
                Self::All(inner) if conjunction => flattened.extend(inner),
                Self::Any(inner) if !conjunction => flattened.extend(inner),
                other => flattened.push(other),
            }
        }

        flattened.sort();
        flattened.dedup();
        if flattened.is_empty() {
            unit
        } else if flattened.len() == 1 {
            flattened.remove(0)
        } else if conjunction {
            Self::All(flattened)
        } else {
            Self::Any(flattened)
        }
    }

    /// The nesting depth of this predicate, with a leaf at one.
    #[must_use]
    pub fn depth(&self) -> u32 {
        match self {
            Self::All(operands) | Self::Any(operands) => {
                1 + operands.iter().map(Self::depth).max().unwrap_or(0)
            }
            Self::Not(inner) => 1 + inner.depth(),
            _ => 1,
        }
    }

    /// Every aggregate this predicate reads, in canonical order.
    #[must_use]
    pub fn aggregates(&self) -> Vec<AggregateName> {
        let mut found = Vec::new();
        self.collect_aggregates(&mut found);
        found.sort();
        found.dedup();
        found
    }

    fn collect_aggregates(&self, found: &mut Vec<AggregateName>) {
        match self {
            Self::All(operands) | Self::Any(operands) => {
                for operand in operands {
                    operand.collect_aggregates(found);
                }
            }
            Self::Not(inner) => inner.collect_aggregates(found),
            Self::AggregateCompare { name, .. } => found.push(*name),
            _ => {}
        }
    }

    /// Every evidence kind this predicate consults, in canonical order.
    #[must_use]
    pub fn evidence_kinds(&self) -> Vec<EvidenceKind> {
        let mut found = Vec::new();
        self.collect_evidence(&mut found);
        found.sort();
        found.dedup();
        found
    }

    fn collect_evidence(&self, found: &mut Vec<EvidenceKind>) {
        match self {
            Self::All(operands) | Self::Any(operands) => {
                for operand in operands {
                    operand.collect_evidence(found);
                }
            }
            Self::Not(inner) => inner.collect_evidence(found),
            Self::EvidenceAccepted(kind) => found.push(*kind),
            _ => {}
        }
    }
}

fn sorted_unique<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort();
    values.dedup();
    values
}

/// What a policy accepts as one class of evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvidenceRequirement {
    kind: EvidenceKind,
    issuer: IssuerLabel,
    max_age_seconds: Option<u64>,
}

impl EvidenceRequirement {
    /// Declares a requirement.
    #[must_use]
    pub const fn new(
        kind: EvidenceKind,
        issuer: IssuerLabel,
        max_age_seconds: Option<u64>,
    ) -> Self {
        Self {
            kind,
            issuer,
            max_age_seconds,
        }
    }

    /// The class of evidence.
    #[must_use]
    pub const fn kind(self) -> EvidenceKind {
        self.kind
    }

    /// The issuer the policy accepts.
    #[must_use]
    pub const fn issuer(self) -> IssuerLabel {
        self.issuer
    }

    /// The additional age bound the policy imposes, if any.
    ///
    /// Independent of the receipt's own expiry, and both are checked: a
    /// receipt live for a week does not satisfy a policy that wants evidence
    /// no older than an hour.
    #[must_use]
    pub const fn max_age_seconds(self) -> Option<u64> {
        self.max_age_seconds
    }
}

/// One compiled rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompiledRule {
    id: RuleId,
    predicate: Predicate,
    outcome: RuleOutcome,
}

impl CompiledRule {
    /// Builds a rule, normalizing its predicate.
    #[must_use]
    pub fn new(id: RuleId, predicate: Predicate, outcome: RuleOutcome) -> Self {
        Self {
            id,
            predicate: predicate.normalize(),
            outcome,
        }
    }

    /// The rule's identifier.
    #[must_use]
    pub const fn id(&self) -> RuleId {
        self.id
    }

    /// The rule's condition.
    #[must_use]
    pub const fn predicate(&self) -> &Predicate {
        &self.predicate
    }

    /// What the rule says when its condition holds.
    #[must_use]
    pub const fn outcome(&self) -> &RuleOutcome {
        &self.outcome
    }
}

/// A compiled, normalized policy.
///
/// The rules are sorted by identifier and the declarations are sorted by name,
/// so two source texts differing only in the order they state independent
/// things produce the same value and therefore the same snapshot identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompiledPolicy {
    name: PolicyName,
    aggregates: Vec<AggregateName>,
    evidence: Vec<EvidenceRequirement>,
    rules: Vec<CompiledRule>,
    default_outcome: RuleOutcome,
}

impl CompiledPolicy {
    /// Assembles a policy from already-validated parts, sorting them.
    ///
    /// Sorting here rather than trusting the caller is what makes the identity
    /// a function of the policy's meaning: `crate::compile` produces the parts
    /// in source order, and source order is not meaning.
    #[must_use]
    pub fn new(
        name: PolicyName,
        mut aggregates: Vec<AggregateName>,
        mut evidence: Vec<EvidenceRequirement>,
        mut rules: Vec<CompiledRule>,
        default_outcome: RuleOutcome,
    ) -> Self {
        aggregates.sort();
        evidence.sort_by_key(|requirement| requirement.kind());
        rules.sort_by_key(|rule| rule.id());
        Self {
            name,
            aggregates,
            evidence,
            rules,
            default_outcome,
        }
    }

    /// The policy's name.
    #[must_use]
    pub const fn name(&self) -> PolicyName {
        self.name
    }

    /// The aggregates the policy declares, in canonical order.
    #[must_use]
    pub fn aggregates(&self) -> &[AggregateName] {
        &self.aggregates
    }

    /// The evidence classes the policy accepts, in canonical order.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceRequirement] {
        &self.evidence
    }

    /// The rules, in canonical order.
    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// What the policy says when no rule matches.
    #[must_use]
    pub const fn default_outcome(&self) -> &RuleOutcome {
        &self.default_outcome
    }

    /// The requirement for one evidence class, if the policy declares it.
    #[must_use]
    pub fn requirement(&self, kind: EvidenceKind) -> Option<EvidenceRequirement> {
        self.evidence
            .iter()
            .copied()
            .find(|requirement| requirement.kind() == kind)
    }
}
