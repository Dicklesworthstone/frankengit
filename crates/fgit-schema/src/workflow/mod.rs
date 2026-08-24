//! Versioned workflow schema and the bounded GitHub-Actions-subset lowering.
//!
//! # What D12 requires of this module
//!
//! ADR-0008 D12 is binding and it decides the shape: *"'GitHub-compatible' is
//! the single easiest false claim in this domain... A blanket compatibility
//! statement is unfalsifiable marketing; a measured per-endpoint registry is a
//! fact."* So [`registry`] — a status and a reason for every construct — is the
//! deliverable, and the parser exists to enforce it. A construct outside the
//! subset is refused **by name**; nothing is silently ignored.
//!
//! # Why the parser is written here rather than depended upon
//!
//! A general YAML crate would need a `registries/dependency_policy.tsv` row and
//! a constitutional exception. It would also be the wrong instrument: this
//! module must refuse anchors, aliases, tags, flow style and multi-document
//! input, and enforce pre-allocation limits on depth, node count and scalar
//! length. A permissive parser would accept all of it and leave the refusal to
//! a later pass, which is exactly the "silent partial success" §3.1 forbids.
//!
//! # Every byte is accounted for
//!
//! [`yaml::Node`] carries a [`yaml::Span`] on every node, and every refusal
//! carries the span that caused it. The bead's acceptance — *"every input byte
//! maps to a node/source span or explicit ignored-by-version/refusal record; no
//! silent drop"* — is therefore checkable rather than asserted, and
//! `tests/workflow_spans.rs` checks it.

pub mod graph;
pub mod registry;
pub mod yaml;

pub use graph::{Job, Step, Trigger, WorkflowGraph};
pub use registry::{CONSTRUCTS, ConstructStatus};
pub use yaml::{Limits, Node, Span};

use core::fmt;

/// Scans and lowers a workflow document in one step.
///
/// The entry point the command and the tests both use, so neither can exercise
/// a path the other does not.
pub fn compile(source: &str, limits: &Limits) -> Result<WorkflowGraph, WorkflowRefusal> {
    let document = yaml::scan(source, limits)?;
    graph::lower(&document)
}

/// Why a workflow document could not be scanned or lowered.
///
/// Every variant carries a [`Span`] because a refusal without a location is a
/// refusal the author cannot act on, and hostile input is exactly the case
/// where "somewhere in your file" is useless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkflowRefusal {
    /// A YAML construct outside the accepted subset.
    ///
    /// The construct is named from [`CONSTRUCTS`], so the refusal and the
    /// published registry cannot disagree about what is supported.
    ConstructUnsupported {
        /// Registry key of the construct.
        construct: &'static str,
        /// Why the subset excludes it.
        reason: &'static str,
        /// Where it appeared.
        span: Span,
    },
    /// A pre-allocation limit was reached.
    ///
    /// Raised **before** the allocation it bounds, never after: the point of a
    /// limit is that a hostile document cannot make the process reserve the
    /// memory in the first place.
    LimitExceeded {
        /// Which limit.
        limit: &'static str,
        /// The configured bound.
        allowed: usize,
        /// What the document asked for.
        observed: usize,
        /// Where the bound was crossed.
        span: Span,
    },
    /// The document is not well formed within the accepted subset.
    Malformed {
        /// What the scanner expected.
        expected: &'static str,
        /// Where.
        span: Span,
    },
    /// A required workflow field is absent.
    FieldMissing {
        /// Dotted path of the absent field.
        path: &'static str,
        /// Span of the enclosing node.
        span: Span,
    },
    /// A field carries the wrong shape for its schema.
    FieldShape {
        /// Dotted path of the field.
        path: &'static str,
        /// What the schema requires.
        expected: &'static str,
        /// What the document supplied.
        observed: &'static str,
        /// Where.
        span: Span,
    },
    /// A mapping key appears twice.
    ///
    /// A duplicate is refused rather than last-wins, because last-wins makes
    /// the meaning of a document depend on parse order.
    DuplicateKey {
        /// The repeated key.
        key: Box<str>,
        /// Where the repeat appeared.
        span: Span,
    },
    /// A field the schema does not define.
    ///
    /// Refused rather than ignored: an ignored field is a silent drop, and a
    /// workflow whose unknown key does nothing is worse than one that refuses.
    FieldUnknown {
        /// The unrecognised key.
        key: Box<str>,
        /// Dotted path of the enclosing object.
        parent: &'static str,
        /// Where.
        span: Span,
    },
    /// A job depends on a job that does not exist.
    NeedsUnknown {
        /// The job that declared the dependency.
        job: Box<str>,
        /// The name it depends on.
        needs: Box<str>,
        /// Where.
        span: Span,
    },
    /// The dependency graph contains a cycle.
    ///
    /// Carries the cycle in deterministic order so two runs report the same
    /// path rather than whichever member the traversal happened to reach first.
    NeedsCycle {
        /// The jobs in the cycle, lexicographically rotated to a fixed start.
        cycle: Vec<Box<str>>,
        /// Where the cycle was closed.
        span: Span,
    },
}

impl WorkflowRefusal {
    /// Stable machine-readable discriminant.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ConstructUnsupported { .. } => "construct_unsupported",
            Self::LimitExceeded { .. } => "limit_exceeded",
            Self::Malformed { .. } => "malformed",
            Self::FieldMissing { .. } => "field_missing",
            Self::FieldShape { .. } => "field_shape",
            Self::DuplicateKey { .. } => "duplicate_key",
            Self::FieldUnknown { .. } => "field_unknown",
            Self::NeedsUnknown { .. } => "needs_unknown",
            Self::NeedsCycle { .. } => "needs_cycle",
        }
    }

    /// Where the refusal happened.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::ConstructUnsupported { span, .. }
            | Self::LimitExceeded { span, .. }
            | Self::Malformed { span, .. }
            | Self::FieldMissing { span, .. }
            | Self::FieldShape { span, .. }
            | Self::DuplicateKey { span, .. }
            | Self::FieldUnknown { span, .. }
            | Self::NeedsUnknown { span, .. }
            | Self::NeedsCycle { span, .. } => *span,
        }
    }
}

impl fmt::Display for WorkflowRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let span = self.span();
        match self {
            Self::ConstructUnsupported {
                construct, reason, ..
            } => write!(
                formatter,
                "{span}: {construct} is outside the accepted subset: {reason}"
            ),
            Self::LimitExceeded {
                limit,
                allowed,
                observed,
                ..
            } => write!(
                formatter,
                "{span}: {limit} limit is {allowed}, document needs {observed}"
            ),
            Self::Malformed { expected, .. } => {
                write!(formatter, "{span}: expected {expected}")
            }
            Self::FieldMissing { path, .. } => {
                write!(formatter, "{span}: required field {path} is missing")
            }
            Self::FieldShape {
                path,
                expected,
                observed,
                ..
            } => write!(
                formatter,
                "{span}: {path} must be {expected}, found {observed}"
            ),
            Self::DuplicateKey { key, .. } => {
                write!(formatter, "{span}: key {key} appears more than once")
            }
            Self::FieldUnknown { key, parent, .. } => write!(
                formatter,
                "{span}: {parent} has no field {key}; unknown fields are refused, not ignored"
            ),
            Self::NeedsUnknown { job, needs, .. } => write!(
                formatter,
                "{span}: job {job} needs {needs}, which is not a job in this workflow"
            ),
            Self::NeedsCycle { cycle, .. } => {
                let path = cycle
                    .iter()
                    .map(|name| name.to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                write!(formatter, "{span}: job dependency cycle {path}")
            }
        }
    }
}

impl core::error::Error for WorkflowRefusal {}
