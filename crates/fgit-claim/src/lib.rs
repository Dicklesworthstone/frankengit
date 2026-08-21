#![forbid(unsafe_code)]
//! Closed claim-strength lattice and typed evidence admission.
//!
//! A claim can only be promoted by evidence at least as strong as the claim.
//! The ordering is deliberately closed:
//!
//! ```text
//! invariant > proof > bounded_model > statistical > slo > benchmark
//! ```
//!
//! This crate owns the type and value-level portion of that rule. It does not
//! compute evidence identities or retain evidence bodies; those responsibilities
//! belong to the immutable evidence-envelope layer. Keeping this rule separate
//! lets a registry checker refuse an overclaim before any user-facing status is
//! generated.

use core::fmt;
use core::marker::PhantomData;

/// The maximum length of a claim identifier or scope.
pub const MAX_CLAIM_TEXT_BYTES: usize = 160;

/// The closed, ordered strength classes used by public claims and evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ClaimRank {
    /// A reproducible benchmark over a named configuration.
    Benchmark,
    /// An operational objective over a named deployment and horizon.
    Slo,
    /// Identity-bound statistical evidence with assumptions and a window.
    Statistical,
    /// A bounded model exploration with its complete bound and replay.
    BoundedModel,
    /// A formal proof artifact with assumptions and a checker.
    Proof,
    /// A machine-checked invariant or exhaustive proof within its named model.
    Invariant,
}

impl ClaimRank {
    /// All ranks from weakest to strongest, in their stable registry order.
    pub const ALL: [Self; 6] = [
        Self::Benchmark,
        Self::Slo,
        Self::Statistical,
        Self::BoundedModel,
        Self::Proof,
        Self::Invariant,
    ];

    /// Stable registry spelling.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Benchmark => "benchmark",
            Self::Slo => "slo",
            Self::Statistical => "statistical",
            Self::BoundedModel => "bounded_model",
            Self::Proof => "proof",
            Self::Invariant => "invariant",
        }
    }

    /// Parses a stable registry spelling.
    pub fn parse(value: &str) -> Result<Self, ClaimRefusal> {
        match value {
            "benchmark" => Ok(Self::Benchmark),
            "slo" => Ok(Self::Slo),
            "statistical" => Ok(Self::Statistical),
            "bounded_model" => Ok(Self::BoundedModel),
            "proof" => Ok(Self::Proof),
            "invariant" => Ok(Self::Invariant),
            _ => Err(ClaimRefusal::UnknownRank {
                observed: value.to_owned(),
            }),
        }
    }

    /// Whether evidence at this rank can justify a claim at `claim_rank`.
    #[must_use]
    pub const fn justifies(self, claim_rank: Self) -> bool {
        (self as u8) >= (claim_rank as u8)
    }
}

impl fmt::Display for ClaimRank {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// A claim-lattice refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimRefusal {
    /// A registry or caller named a class outside the closed lattice.
    UnknownRank {
        /// Unrecognised token.
        observed: String,
    },
    /// Evidence is weaker than the claim it attempts to justify.
    EvidenceTooWeak {
        /// Claimed strength.
        claim: ClaimRank,
        /// Available evidence strength.
        evidence: ClaimRank,
    },
    /// A claim identifier, scope, or artifact reference is not canonical text.
    InvalidText {
        /// Field that was rejected.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
}

impl fmt::Display for ClaimRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRank { observed } => {
                write!(formatter, "unknown closed claim rank `{observed}`")
            }
            Self::EvidenceTooWeak { claim, evidence } => write!(
                formatter,
                "evidence rank `{evidence}` cannot justify stronger claim rank `{claim}`"
            ),
            Self::InvalidText { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for ClaimRefusal {}

/// Canonically restricted identifier text shared by claims, scopes, and
/// artifact references.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClaimText(String);

impl ClaimText {
    /// Parses an ASCII identifier with no whitespace or control characters.
    pub fn parse(field: &'static str, value: &str) -> Result<Self, ClaimRefusal> {
        if value.is_empty() {
            return Err(ClaimRefusal::InvalidText {
                field,
                reason: "must not be empty",
            });
        }
        if value.len() > MAX_CLAIM_TEXT_BYTES {
            return Err(ClaimRefusal::InvalidText {
                field,
                reason: "exceeds the bounded canonical length",
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\t')
        {
            return Err(ClaimRefusal::InvalidText {
                field,
                reason: "must contain only printable ASCII without whitespace",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The canonical text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClaimText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A compile-time marker for one member of the closed claim lattice.
pub trait ClaimClass: sealed::Sealed {
    /// The value-level rank corresponding to this marker.
    const RANK: ClaimRank;
}

/// Benchmark claim marker.
pub enum Benchmark {}
/// Operational-SLO claim marker.
pub enum Slo {}
/// Statistical claim marker.
pub enum Statistical {}
/// Bounded-model claim marker.
pub enum BoundedModel {}
/// Formal-proof claim marker.
pub enum Proof {}
/// Machine-checked-invariant claim marker.
pub enum Invariant {}

macro_rules! claim_class {
    ($marker:ty, $rank:expr) => {
        impl sealed::Sealed for $marker {}
        impl ClaimClass for $marker {
            const RANK: ClaimRank = $rank;
        }
    };
}

claim_class!(Benchmark, ClaimRank::Benchmark);
claim_class!(Slo, ClaimRank::Slo);
claim_class!(Statistical, ClaimRank::Statistical);
claim_class!(BoundedModel, ClaimRank::BoundedModel);
claim_class!(Proof, ClaimRank::Proof);
claim_class!(Invariant, ClaimRank::Invariant);

/// Evidence whose class may justify a claim marker `C`.
///
/// This trait has no blanket implementation: each permitted edge is explicit,
/// so adding a seventh class cannot silently create a promotion route.
pub trait Justifies<C: ClaimClass>: ClaimClass {}

macro_rules! justification_edges {
    ($evidence:ty => [$($claim:ty),+ $(,)?]) => {
        $(impl Justifies<$claim> for $evidence {})+
    };
}

justification_edges!(Benchmark => [Benchmark]);
justification_edges!(Slo => [Benchmark, Slo]);
justification_edges!(Statistical => [Benchmark, Slo, Statistical]);
justification_edges!(BoundedModel => [Benchmark, Slo, Statistical, BoundedModel]);
justification_edges!(Proof => [Benchmark, Slo, Statistical, BoundedModel, Proof]);
justification_edges!(Invariant => [Benchmark, Slo, Statistical, BoundedModel, Proof, Invariant]);

/// One public claim at a compile-time-known lattice rank.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim<C: ClaimClass> {
    id: ClaimText,
    scope: ClaimText,
    marker: PhantomData<C>,
}

impl<C: ClaimClass> Claim<C> {
    /// Builds a typed claim from canonical identifier and scope text.
    pub fn new(id: ClaimText, scope: ClaimText) -> Self {
        Self {
            id,
            scope,
            marker: PhantomData,
        }
    }

    /// Claim identifier.
    #[must_use]
    pub const fn id(&self) -> &ClaimText {
        &self.id
    }

    /// Claim scope.
    #[must_use]
    pub const fn scope(&self) -> &ClaimText {
        &self.scope
    }

    /// Value-level lattice rank.
    #[must_use]
    pub const fn rank(&self) -> ClaimRank {
        C::RANK
    }
}

/// Evidence at a compile-time-known lattice rank.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence<E: ClaimClass> {
    artifact: ClaimText,
    marker: PhantomData<E>,
}

impl<E: ClaimClass> Evidence<E> {
    /// Builds an evidence reference from canonical artifact text.
    pub fn new(artifact: ClaimText) -> Self {
        Self {
            artifact,
            marker: PhantomData,
        }
    }

    /// Artifact reference as recorded by the evidence layer.
    #[must_use]
    pub const fn artifact(&self) -> &ClaimText {
        &self.artifact
    }

    /// Value-level lattice rank.
    #[must_use]
    pub const fn rank(&self) -> ClaimRank {
        E::RANK
    }
}

/// A typed claim/evidence pair whose lattice edge was admitted at compile time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JustifiedClaim<C: ClaimClass, E: ClaimClass> {
    claim: Claim<C>,
    evidence: Evidence<E>,
}

impl<C: ClaimClass, E: ClaimClass> JustifiedClaim<C, E>
where
    E: Justifies<C>,
{
    /// Binds a typed claim to typed evidence along an admissible lattice edge.
    #[must_use]
    pub fn new(claim: Claim<C>, evidence: Evidence<E>) -> Self {
        Self { claim, evidence }
    }

    /// The admitted claim.
    #[must_use]
    pub const fn claim(&self) -> &Claim<C> {
        &self.claim
    }

    /// The evidence that justifies it.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence<E> {
        &self.evidence
    }
}

/// Checks a dynamic registry edge against the same closed order used by the
/// typed constructors.
pub fn validate_justification(claim: ClaimRank, evidence: ClaimRank) -> Result<(), ClaimRefusal> {
    if evidence.justifies(claim) {
        Ok(())
    } else {
        Err(ClaimRefusal::EvidenceTooWeak { claim, evidence })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Benchmark, Claim, ClaimClass, ClaimRank, ClaimText, Evidence, Invariant, JustifiedClaim,
        Proof, Slo, Statistical, validate_justification,
    };

    fn text(value: &str) -> ClaimText {
        ClaimText::parse("test", value).expect("canonical test text")
    }

    #[test]
    fn dynamic_lattice_refuses_weaker_evidence() {
        let refusal = validate_justification(ClaimRank::Statistical, ClaimRank::Benchmark)
            .expect_err("benchmark cannot justify statistical evidence");
        assert_eq!(
            refusal.to_string(),
            "evidence rank `benchmark` cannot justify stronger claim rank `statistical`"
        );
    }

    #[test]
    fn strongest_rank_justifies_every_closed_rank() {
        for claim in ClaimRank::ALL {
            validate_justification(claim, ClaimRank::Invariant)
                .expect("invariant must justify every closed rank");
        }
    }

    #[test]
    fn typed_admissible_edge_constructs_a_justified_claim() {
        let claim = Claim::<Statistical>::new(text("CLAIM-EXAMPLE"), text("parser"));
        let evidence = Evidence::<Proof>::new(text("sha256:proof-artifact"));
        let justified = JustifiedClaim::new(claim, evidence);
        assert_eq!(justified.claim().rank(), ClaimRank::Statistical);
        assert_eq!(justified.evidence().rank(), ClaimRank::Proof);
    }

    #[test]
    fn text_refuses_whitespace_and_non_ascii() {
        assert!(ClaimText::parse("id", "contains space").is_err());
        assert!(ClaimText::parse("id", "caf\u{e9}").is_err());
        assert!(ClaimText::parse("id", "").is_err());
    }

    #[test]
    fn marker_ranks_are_closed_and_stable() {
        assert_eq!(Benchmark::RANK, ClaimRank::Benchmark);
        assert_eq!(Slo::RANK, ClaimRank::Slo);
        assert_eq!(Invariant::RANK, ClaimRank::Invariant);
    }
}
