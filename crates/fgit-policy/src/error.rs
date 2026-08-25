//! The typed refusals this crate returns.
//!
//! Nothing here is an "internal error", and nothing is a default. Every
//! variant names what was expected, what was observed, and where, so a
//! rejected policy or a refused evaluation can be diagnosed from one line.
//!
//! The split matters. A [`PolicySyntaxRefusal`] and a
//! [`PolicyCompileRefusal`] both happen before anything is published, which is
//! the constitutional requirement: an unknown construct is refused by the
//! compiler and never becomes a snapshot that some later evaluation has to
//! decide what to do with. A [`PolicyEvalRefusal`] happens after publication
//! and is therefore about the input root, never about the policy.

use core::fmt;

use fgit_codec::CodecRefusal;

use crate::basis::{AggregateName, EvidenceKind, LabelName, PolicyInstant, RefUpdateKind};

/// Stores a borrowed name compactly in a refusal.
fn owned(value: &str) -> Box<str> {
    value.to_owned().into_boxed_str()
}

/// Renders bytes that are not guaranteed to be `UTF-8`.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Why a ref pattern could not be compiled.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefPatternRefusal {
    /// The pattern was empty.
    Empty,
    /// The pattern was longer than the bound.
    TooLong {
        /// Length observed, in bytes.
        observed: usize,
        /// Largest accepted length, in bytes.
        limit: usize,
    },
    /// The pattern had more `/`-separated segments than the bound.
    TooManySegments {
        /// Count observed.
        observed: usize,
        /// Largest accepted count.
        limit: usize,
    },
    /// A segment was empty, which means the pattern had `//`, a leading `/`,
    /// or a trailing `/`.
    SegmentEmpty {
        /// Index of the empty segment.
        index: usize,
    },
    /// `**` appeared somewhere other than the final segment.
    ///
    /// A `**` in the middle would need a matcher that can backtrack across
    /// segment boundaries. Refusing it keeps matching linear and keeps the
    /// meaning of every accepted pattern obvious.
    DoubleStarNotTrailing {
        /// Index of the offending segment.
        index: usize,
    },
    /// A byte outside the accepted set appeared in the pattern.
    ByteNotPermitted {
        /// Offset of the byte within the pattern.
        offset: usize,
        /// The byte.
        byte: u8,
    },
}

impl fmt::Display for RefPatternRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a ref pattern cannot be empty"),
            Self::TooLong { observed, limit } => write!(
                formatter,
                "ref pattern is {observed} bytes, over the {limit}-byte bound"
            ),
            Self::TooManySegments { observed, limit } => write!(
                formatter,
                "ref pattern has {observed} segments, over the bound of {limit}"
            ),
            Self::SegmentEmpty { index } => {
                write!(formatter, "ref pattern segment {index} is empty")
            }
            Self::DoubleStarNotTrailing { index } => write!(
                formatter,
                "`**` is only accepted as the final segment; it appeared at segment {index}"
            ),
            Self::ByteNotPermitted { offset, byte } => write!(
                formatter,
                "byte {byte:#04x} at offset {offset} is not accepted in a ref pattern"
            ),
        }
    }
}

impl std::error::Error for RefPatternRefusal {}

/// Why a policy source text could not be read.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicySyntaxRefusal {
    /// The source was larger than the bound.
    SourceTooLarge {
        /// Length observed, in bytes.
        observed: usize,
        /// Largest accepted length, in bytes.
        limit: usize,
    },
    /// A byte outside the accepted source character set appeared.
    ByteNotPermitted {
        /// Byte offset within the source.
        offset: usize,
        /// The byte.
        byte: u8,
    },
    /// A string literal ran to the end of the source without closing.
    UnterminatedString {
        /// Offset of the opening quote.
        offset: usize,
    },
    /// A backslash escape this language does not define appeared in a string.
    ///
    /// Only `\\` and `\"` are defined. Anything else is refused rather than
    /// passed through, so a pattern cannot mean one thing here and another in
    /// a tool that expanded more escapes.
    UnsupportedEscape {
        /// Byte offset of the escape.
        offset: usize,
        /// The byte after the backslash.
        byte: u8,
    },
    /// An integer literal did not fit in a `u64`.
    IntegerOutOfRange {
        /// Byte offset of the literal.
        offset: usize,
    },
    /// An integer literal had a redundant leading zero.
    ///
    /// One decimal spelling per value, so a policy's bytes do not depend on
    /// how its author padded a number.
    IntegerLeadingZero {
        /// Byte offset of the literal.
        offset: usize,
    },
    /// The source ended while something was still expected.
    UnexpectedEnd {
        /// What was expected.
        expected: &'static str,
    },
    /// A token appeared where something else was expected.
    UnexpectedToken {
        /// Byte offset of the token.
        offset: usize,
        /// What was expected.
        expected: &'static str,
        /// What was found.
        found: Box<str>,
    },
    /// A declaration keyword this language does not define appeared.
    ///
    /// This is the unknown-construct refusal at the top level, and it happens
    /// at compile time.
    UnknownDeclaration {
        /// Byte offset of the keyword.
        offset: usize,
        /// The keyword.
        keyword: Box<str>,
    },
    /// A comparison operator this language does not define appeared.
    UnknownOperator {
        /// Byte offset of the operator.
        offset: usize,
        /// The operator.
        operator: Box<str>,
    },
    /// A decision keyword this language does not define appeared.
    UnknownDecision {
        /// Byte offset of the keyword.
        offset: usize,
        /// The keyword.
        keyword: Box<str>,
    },
    /// A name did not meet the canonical label rules.
    LabelInvalid {
        /// Byte offset of the name.
        offset: usize,
        /// Which name it was.
        field: &'static str,
        /// The name as written.
        name: Box<str>,
    },
    /// An expression nested deeper than the bound.
    NestingTooDeep {
        /// Byte offset where the bound was hit.
        offset: usize,
        /// Largest accepted depth.
        limit: u32,
    },
    /// A set literal had more elements than the bound.
    SetTooLarge {
        /// Byte offset of the literal.
        offset: usize,
        /// Count observed.
        observed: usize,
        /// Largest accepted count.
        limit: usize,
    },
    /// A string literal was longer than the bound.
    StringTooLong {
        /// Byte offset of the literal.
        offset: usize,
        /// Length observed, in bytes.
        observed: usize,
        /// Largest accepted length, in bytes.
        limit: usize,
    },
    /// The policy did not state a default decision.
    ///
    /// There is no implicit default. A policy that does not say what happens
    /// when no rule matches is incomplete, and guessing on its behalf would
    /// make the safest reading of a policy depend on this crate's opinion
    /// rather than on its author's.
    MissingDefaultDecision {
        /// Byte offset of the policy's closing brace.
        offset: usize,
    },
    /// The source held something after the policy's closing brace.
    TrailingSource {
        /// Byte offset of the trailing token.
        offset: usize,
    },
}

impl fmt::Display for PolicySyntaxRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge { observed, limit } => write!(
                formatter,
                "policy source is {observed} bytes, over the {limit}-byte bound"
            ),
            Self::ByteNotPermitted { offset, byte } => write!(
                formatter,
                "byte {byte:#04x} at offset {offset} is not accepted in policy source"
            ),
            Self::UnterminatedString { offset } => write!(
                formatter,
                "string literal opened at offset {offset} is never closed"
            ),
            Self::UnsupportedEscape { offset, byte } => write!(
                formatter,
                "escape `\\{}` at offset {offset} is not defined; only `\\\\` and `\\\"` are",
                char::from(*byte)
            ),
            Self::IntegerOutOfRange { offset } => write!(
                formatter,
                "integer literal at offset {offset} does not fit in 64 bits"
            ),
            Self::IntegerLeadingZero { offset } => write!(
                formatter,
                "integer literal at offset {offset} has a redundant leading zero"
            ),
            Self::UnexpectedEnd { expected } => {
                write!(formatter, "source ended while expecting {expected}")
            }
            Self::UnexpectedToken {
                offset,
                expected,
                found,
            } => write!(
                formatter,
                "expected {expected} at offset {offset}, found `{found}`"
            ),
            Self::UnknownDeclaration { offset, keyword } => write!(
                formatter,
                "`{keyword}` at offset {offset} is not a policy declaration"
            ),
            Self::UnknownOperator { offset, operator } => write!(
                formatter,
                "`{operator}` at offset {offset} is not a comparison operator"
            ),
            Self::UnknownDecision { offset, keyword } => write!(
                formatter,
                "`{keyword}` at offset {offset} is not a decision"
            ),
            Self::LabelInvalid {
                offset,
                field,
                name,
            } => write!(
                formatter,
                "`{name}` at offset {offset} is not a canonical {field} label"
            ),
            Self::NestingTooDeep { offset, limit } => write!(
                formatter,
                "expression at offset {offset} nests deeper than the bound of {limit}"
            ),
            Self::SetTooLarge {
                offset,
                observed,
                limit,
            } => write!(
                formatter,
                "set literal at offset {offset} has {observed} elements, over the bound of {limit}"
            ),
            Self::StringTooLong {
                offset,
                observed,
                limit,
            } => write!(
                formatter,
                "string at offset {offset} is {observed} bytes, over the {limit}-byte bound"
            ),
            Self::MissingDefaultDecision { offset } => write!(
                formatter,
                "policy closing at offset {offset} states no `default` decision"
            ),
            Self::TrailingSource { offset } => write!(
                formatter,
                "source continues at offset {offset} after the policy closed"
            ),
        }
    }
}

impl std::error::Error for PolicySyntaxRefusal {}

/// Why a policy could not be compiled.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyCompileRefusal {
    /// The source could not be read at all.
    Syntax(PolicySyntaxRefusal),
    /// A rule named a fact selector this language does not define.
    ///
    /// This is the refusal that makes ambient I/O unreachable rather than
    /// merely discouraged: `now.seconds`, `env.home`, and `file.contents` are
    /// all just unknown selectors, and they are refused here, at compile time.
    UnknownSelector {
        /// The rule that named it.
        rule: Box<str>,
        /// The selector as written.
        selector: Box<str>,
    },
    /// A rule applied an operator the selector's type does not admit.
    OperatorNotApplicable {
        /// The rule that did it.
        rule: Box<str>,
        /// The selector.
        selector: Box<str>,
        /// The operator.
        operator: &'static str,
        /// What the selector's type does admit.
        admits: &'static str,
    },
    /// A rule compared a selector against an operand of the wrong shape.
    OperandTypeMismatch {
        /// The rule that did it.
        rule: Box<str>,
        /// The selector.
        selector: Box<str>,
        /// The operand shape that was required.
        expected: &'static str,
        /// The operand shape that was written.
        found: &'static str,
    },
    /// A rule used a bare literal for an enumerated selector that has no such
    /// value.
    UnknownEnumLiteral {
        /// The rule that did it.
        rule: Box<str>,
        /// The selector.
        selector: Box<str>,
        /// The literal as written.
        literal: Box<str>,
        /// The literals the selector does admit.
        admits: Box<str>,
    },
    /// A rule referred to an evidence kind the policy never declared.
    UnknownEvidenceKind {
        /// The rule that referred to it.
        rule: Box<str>,
        /// The kind.
        kind: Box<str>,
    },
    /// A rule referred to an aggregate the policy never declared.
    UnknownAggregate {
        /// The rule that referred to it.
        rule: Box<str>,
        /// The aggregate.
        name: Box<str>,
    },
    /// Two rules carried the same identifier.
    DuplicateRuleId {
        /// The identifier.
        id: Box<str>,
    },
    /// Two declarations carried the same name.
    DuplicateDeclaration {
        /// Which kind of declaration.
        kind: &'static str,
        /// The name.
        name: Box<str>,
    },
    /// A rule's ref pattern could not be compiled.
    RefPatternInvalid {
        /// The rule that held it.
        rule: Box<str>,
        /// The pattern as written.
        pattern: Box<str>,
        /// Why it was refused.
        reason: RefPatternRefusal,
    },
    /// A policy declared more rules than the bound.
    RuleCountExceeded {
        /// Count observed.
        observed: usize,
        /// Largest accepted count.
        limit: usize,
    },
    /// The compiled policy has no identity, because its domain separation tag
    /// is not registered in the cryptographic registry.
    SnapshotIdentity {
        /// The refusal the identity path returned.
        refusal: CodecRefusal,
    },
}

impl fmt::Display for PolicyCompileRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(refusal) => fmt::Display::fmt(refusal, formatter),
            Self::UnknownSelector { rule, selector } => write!(
                formatter,
                "rule `{rule}` names `{selector}`, which is not a policy fact"
            ),
            Self::OperatorNotApplicable {
                rule,
                selector,
                operator,
                admits,
            } => write!(
                formatter,
                "rule `{rule}` applies `{operator}` to `{selector}`, which admits {admits}"
            ),
            Self::OperandTypeMismatch {
                rule,
                selector,
                expected,
                found,
            } => write!(
                formatter,
                "rule `{rule}` compares `{selector}` against {found}, but it requires {expected}"
            ),
            Self::UnknownEnumLiteral {
                rule,
                selector,
                literal,
                admits,
            } => write!(
                formatter,
                "rule `{rule}` compares `{selector}` against `{literal}`; it admits {admits}"
            ),
            Self::UnknownEvidenceKind { rule, kind } => write!(
                formatter,
                "rule `{rule}` requires evidence `{kind}`, which the policy never declared"
            ),
            Self::UnknownAggregate { rule, name } => write!(
                formatter,
                "rule `{rule}` reads aggregate `{name}`, which the policy never declared"
            ),
            Self::DuplicateRuleId { id } => {
                write!(formatter, "two rules carry the identifier `{id}`")
            }
            Self::DuplicateDeclaration { kind, name } => {
                write!(formatter, "two {kind} declarations carry the name `{name}`")
            }
            Self::RefPatternInvalid {
                rule,
                pattern,
                reason,
            } => write!(
                formatter,
                "rule `{rule}` holds the pattern `{pattern}`: {reason}"
            ),
            Self::RuleCountExceeded { observed, limit } => write!(
                formatter,
                "policy declares {observed} rules, over the bound of {limit}"
            ),
            Self::SnapshotIdentity { refusal } => {
                write!(formatter, "compiled policy has no identity: {refusal}")
            }
        }
    }
}

impl std::error::Error for PolicyCompileRefusal {}

impl From<PolicySyntaxRefusal> for PolicyCompileRefusal {
    fn from(refusal: PolicySyntaxRefusal) -> Self {
        Self::Syntax(refusal)
    }
}

/// Why an input root could not be built.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyInputRefusal {
    /// A collection was larger than its bound.
    CountExceeded {
        /// Which collection.
        field: &'static str,
        /// Count observed.
        observed: usize,
        /// Largest accepted count.
        limit: usize,
    },
    /// A ref command's basis values contradict its declared kind.
    UpdateShapeInconsistent {
        /// The ref, as bytes.
        name: Vec<u8>,
        /// The declared kind.
        kind: RefUpdateKind,
        /// Whether a previous value was supplied.
        previous_present: bool,
        /// Whether a next value was supplied.
        next_present: bool,
    },
    /// Two ref commands target the same ref.
    DuplicateSubject {
        /// The ref, as bytes.
        name: Vec<u8>,
    },
    /// Two identical evidence receipts were offered.
    DuplicateReceipt {
        /// The class of the repeated receipt.
        kind: EvidenceKind,
    },
    /// Two readings were offered for one aggregate.
    DuplicateAggregate {
        /// The aggregate.
        name: AggregateName,
    },
    /// A principal carried the same label twice.
    DuplicateLabel {
        /// Which label set.
        field: &'static str,
        /// The label.
        label: LabelName,
    },
    /// A receipt's validity window is empty.
    ReceiptWindowEmpty {
        /// The class of receipt.
        kind: EvidenceKind,
        /// When it claims to have been issued.
        issued_at: PolicyInstant,
        /// When it claims to expire.
        expires_at: PolicyInstant,
    },
}

impl fmt::Display for PolicyInputRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountExceeded {
                field,
                observed,
                limit,
            } => write!(
                formatter,
                "input root carries {observed} {field}, over the bound of {limit}"
            ),
            Self::UpdateShapeInconsistent {
                name,
                kind,
                previous_present,
                next_present,
            } => write!(
                formatter,
                "ref command for `{}` declares `{}` but supplies previous={} next={}",
                lossy(name),
                kind.token(),
                previous_present,
                next_present
            ),
            Self::DuplicateSubject { name } => {
                write!(formatter, "two ref commands target `{}`", lossy(name))
            }
            Self::DuplicateReceipt { kind } => {
                write!(formatter, "receipt of kind `{kind}` was offered twice")
            }
            Self::DuplicateAggregate { name } => {
                write!(
                    formatter,
                    "two readings were offered for aggregate `{name}`"
                )
            }
            Self::DuplicateLabel { field, label } => {
                write!(formatter, "principal {field} carry `{label}` twice")
            }
            Self::ReceiptWindowEmpty {
                kind,
                issued_at,
                expires_at,
            } => write!(
                formatter,
                "receipt of kind `{kind}` expires at {expires_at}, at or before its issue at {issued_at}"
            ),
        }
    }
}

impl std::error::Error for PolicyInputRefusal {}

/// Why an evaluation refused.
///
/// A refusal is not an allow. Every caller treats it as a denial of the whole
/// input root, because the alternative is deciding against facts the policy
/// said it needed and did not get.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyEvalRefusal {
    /// A rule reads an aggregate the input root did not supply a reading for.
    ///
    /// Defaulting the reading to zero would be a decision this crate is not
    /// entitled to make: zero open incidents and no incident data available
    /// are different facts, and only one of them should let a push through.
    AggregateMissing {
        /// The rule that reads it.
        rule: Box<str>,
        /// The aggregate.
        name: AggregateName,
    },
}

impl fmt::Display for PolicyEvalRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AggregateMissing { rule, name } => write!(
                formatter,
                "rule `{rule}` reads aggregate `{name}`, which the input root did not supply"
            ),
        }
    }
}

impl std::error::Error for PolicyEvalRefusal {}

/// Builds a boxed name for a refusal.
#[must_use]
pub(crate) fn refusal_name(value: &str) -> Box<str> {
    owned(value)
}
