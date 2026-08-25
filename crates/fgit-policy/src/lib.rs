#![forbid(unsafe_code)]
//! The `FrankenGit` policy engine: a declarative rule language over typed
//! facts, a compiler to a normalized content-addressed snapshot, and a pure
//! evaluator that returns a decision together with a trace naming every rule
//! it consulted.
//!
//! ## Four stages, four typed refusals
//!
//! ```text
//! source text ──parse──► source form ──compile──► compiled policy ──seal──► snapshot
//!      │                      │                        │                       │
//!      └─ [`PolicySyntaxRefusal`]                      └─ [`PolicySnapshotId`] │
//!                             └─ [`PolicyCompileRefusal`]                      │
//!                                                                              ▼
//!                                        (snapshot, input root) ──evaluate──► decision + trace
//!                                                    │                            │
//!                                                    └─ [`PolicyInputRefusal`]     └─ [`PolicyEvalRefusal`]
//! ```
//!
//! Every stage that can fail fails with a value that names what was expected,
//! what was observed, and where. Nothing degrades to a default, and nothing
//! that could not be understood is carried forward to be reinterpreted later.
//!
//! ## The language cannot express ambient I/O, structurally
//!
//! This is the constitutional requirement, and it is met by construction
//! rather than by review. A predicate is a [`program::Predicate`], a closed
//! enumeration whose leaves are comparisons against a [`program::Selector`] —
//! itself a closed enumeration of the facts an input root carries. There is no
//! call form, no free identifier, no host escape, and no variant that reads
//! anything the caller did not supply.
//!
//! The consequence for a policy author is exact: a source text that says
//! `now.seconds`, `env.home`, or `file.contents` does not evaluate to
//! something surprising and does not fail at publication. It fails to compile,
//! with [`PolicyCompileRefusal::UnknownSelector`] naming the rule and the
//! selector. The clock is not ambient either: an evaluation instant is a field
//! of [`basis::PolicyInputRoot`], supplied by the caller, so evidence expiry is
//! decided against a time the caller can reproduce.
//!
//! ## Determinism
//!
//! Compilation normalizes: rules sort by identifier, conjunctions and
//! disjunctions flatten, their operands sort and deduplicate by canonical
//! order, set literals sort and deduplicate, and constant sub-predicates fold.
//! Two source texts that differ only in the order they state independent
//! things therefore compile to the same bytes and so to the same
//! [`PolicySnapshotId`].
//!
//! Evaluation never iterates a hash container: every collection in this crate
//! is a `BTreeMap`, a `BTreeSet`, or a sequence whose order is semantic.
//!
//! ## One vocabulary, shared with receive-pack
//!
//! [`basis::PolicyInputRoot`] is the receive-pack basis: the ref updates being
//! decided, the principal facts behind them, the evidence receipts offered
//! with them, the aggregate states they are decided against, and the instant
//! they are decided at. FG-043b and FG-043r rewire the protected-ref checks
//! onto this crate, and they do it by constructing this type — not by
//! translating into a second vocabulary that would then have to be kept in
//! agreement with this one.
//!
//! ## Non-claims
//!
//! * This crate decides nothing about objects. Whether an update is a
//!   fast-forward is a fact the caller supplies
//!   ([`basis::RefUpdateKind`]); computing it needs the commit graph, which
//!   lives elsewhere.
//! * A principal's attributes are likewise supplied
//!   ([`basis::PrincipalFacts`]). This crate does not authenticate anyone and
//!   does not read a principal snapshot body.
//! * An accepted evidence receipt is accepted against the policy's own
//!   declaration. Verifying that a receipt was really issued by the issuer it
//!   names is a signature question, and this crate checks no signatures.

/// Declares a bounded lowercase ASCII label newtype.
///
/// The labels this crate names -- evidence kinds, issuers, aggregates,
/// membership labels, rule identifiers, policy names -- are all the same
/// thing: a value that must mean exactly one byte string, must not change
/// meaning under case folding or Unicode normalization, and must be `Copy` so
/// it can travel through a predicate without an allocation. Declaring them
/// through one macro is what keeps that true of all six.
macro_rules! slug_newtype {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// The value is a bounded lowercase ASCII label, so it can never
        /// change meaning under case folding or Unicode normalization.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name($crate::__reexport::AsciiSlug);

        impl $name {
            /// Builds the label from runtime bytes.
            pub fn try_new(source: &[u8]) -> Result<Self, $crate::__reexport::TypeRefusal> {
                $crate::__reexport::AsciiSlug::try_new($field, source).map(Self)
            }

            /// Builds the label in a `const` context.
            #[must_use]
            pub const fn from_static(source: &'static str) -> Self {
                Self($crate::__reexport::AsciiSlug::from_static(source))
            }

            /// The label bytes, without padding.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// The label as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, formatter)
            }
        }
    };
}

/// Types the `slug_newtype!` expansion names by absolute path.
#[doc(hidden)]
pub mod __reexport {
    pub use fgit_types::{AsciiSlug, TypeRefusal};
}

pub mod basis;
pub mod break_glass;
pub mod compile;
pub mod content;
pub mod error;
pub mod eval;
pub mod glob;
pub mod program;
pub mod protected_ref;
pub mod rollout;
pub mod syntax;

pub use basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, EvidenceReceipt, IssuerLabel, LabelName,
    PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind, RefUpdateFact, RefUpdateKind,
};
pub use break_glass::{
    BreakGlassIntent, BreakGlassReceipt, BreakGlassRefusal, MAX_BREAK_GLASS_DURATION_SECS,
    MAX_BREAK_GLASS_REASON_LEN, evaluate_break_glass,
};
pub use compile::{compile, resolve};
pub use content::{
    POLICY_SNAPSHOT_DOMAIN, POLICY_SNAPSHOT_SCHEMA_FAMILY, PolicySnapshot, PolicySnapshotBody,
    PolicySnapshotId,
};
pub use error::{
    PolicyCompileRefusal, PolicyEvalRefusal, PolicyInputRefusal, PolicySyntaxRefusal,
    RefPatternRefusal,
};
pub use eval::{EvidenceUse, PolicyEvaluation, RuleVisit, SubjectOutcome, evaluate, render_trace};
pub use glob::RefPattern;
pub use program::{
    Compare, CompiledPolicy, CompiledRule, Decision, DenyReason, EvidenceRequirement, PolicyName,
    Predicate, RuleId, RuleOutcome, Selector, TextLiteral, ValueKind,
};
pub use protected_ref::{
    DurabilityProfile, MAX_PROTECTED_RULES, MAX_REQUIRED_CHECKS, ProtectedRefEvaluation,
    ProtectedRefRule, ProtectionBits, RequirementVerdict, ReviewRequirement,
    StatusCheckRequirement, VerifierClass, evaluate_protected_ref,
};
pub use rollout::{
    CanaryLifecycleEvent, DecisionDivergence, PolicyDiff, RolloutCohort, RolloutConfiguration,
    RolloutEvaluation, RolloutMode, evaluate_rollout,
};

/// Compiles source text and seals the result into a content-addressed
/// snapshot in one step.
///
/// The two halves are public separately because they refuse for different
/// reasons: a source text that does not compile never reaches the identity
/// path, and a compiled policy whose domain is unregistered has no identity
/// even though it is perfectly well formed.
pub fn compile_and_seal(source: &str) -> Result<PolicySnapshot, PolicyCompileRefusal> {
    let compiled = compile(source)?;
    PolicySnapshot::seal(PolicySnapshotBody::new(compiled))
        .map_err(|refusal| PolicyCompileRefusal::SnapshotIdentity { refusal })
}
