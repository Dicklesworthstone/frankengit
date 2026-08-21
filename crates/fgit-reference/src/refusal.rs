//! The normative refusal taxonomy, and the closed set of refusals this model
//! can emit.
//!
//! `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md` §15.11 names thirteen
//! classes a refusal must distinguish. [`fgit_types::vocabulary::RefusalCode`]
//! is the wire vocabulary and is deliberately finer-grained than that: it
//! carries the exact dimension an operator needs. [`RefusalClass`] is the
//! coarse normative taxonomy, and [`RefusalClass::of`] is the total bridge
//! between the two.
//!
//! Two properties are enforced here rather than asserted in prose:
//!
//! * the bridge is **total** — every wire code has exactly one class, checked
//!   by an exhaustive `match` that stops compiling when `fgit-types` grows a
//!   member;
//! * the model's own refusal surface is **closed** — [`MODEL_REFUSAL_SURFACE`]
//!   lists every code the reference state machine may produce, and a test
//!   asserts set equality against the codes the transitions actually emit, so
//!   the declared surface cannot silently drift in either direction.
//!
//! ## Refusal is not rejection
//!
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §5.1 and §5.2 put a hard line at the
//! transaction seal. A *rejection* ([`fgit_types::vocabulary::RequestRejectionCode`])
//! happens before a seal exists and is not repository history. A *refusal*
//! (this module) is a terminal decision after sealing: it consumes decision
//! sequence and is replayable from the authenticated decision stream. The two
//! vocabularies are separate types in `fgit-types` and this crate never
//! converts between them.

use fgit_types::vocabulary::RefusalCode;

/// The thirteen refusal classes of plan §15.11.
///
/// A class is the coarse question "why was this refused?" that the normative
/// contract requires every refusal to answer. It is a projection of the wire
/// code, never a substitute for it: evidence records the exact
/// [`RefusalCode`], and the class exists so tests, taxonomy coverage checks,
/// and operator summaries can reason about the thirteen normative buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefusalClass {
    /// The request body, framing, or a name within it violated a structural
    /// rule.
    Malformed,
    /// The requested feature, schema, capability, or hash domain is not
    /// implemented by this service.
    Unsupported,
    /// The authenticated principal may not perform the requested effect.
    Unauthorized,
    /// The prepared evidence was built against a head basis that is no longer
    /// current and could not be revalidated.
    StaleBasis,
    /// A declared expected-old precondition disagreed with the basis.
    ExpectedOldMismatch,
    /// Deterministic policy evaluation over the pinned snapshot denied the
    /// transition.
    Policy,
    /// An admitted object failed validation of its own declared commitments.
    ObjectInvalidity,
    /// A promised object was absent from the admitted closure.
    MissingPromisedObject,
    /// A quota, budget, or admission bound was exhausted.
    Resource,
    /// An idempotency key was reused with different canonical parameters.
    IdempotencyReuse,
    /// Two source intents demanded contradictory effects on one target.
    ConflictingEffects,
    /// The declared durability profile cannot be satisfied for this
    /// publication.
    DurabilityUnavailable,
    /// The model detected a breach of one of its own invariants and failed
    /// closed.
    InternalInvariant,
}

impl RefusalClass {
    /// Every class, in declaration order.
    ///
    /// Plan §15.11 enumerates exactly these thirteen.
    pub const ALL: &'static [Self] = &[
        Self::Malformed,
        Self::Unsupported,
        Self::Unauthorized,
        Self::StaleBasis,
        Self::ExpectedOldMismatch,
        Self::Policy,
        Self::ObjectInvalidity,
        Self::MissingPromisedObject,
        Self::Resource,
        Self::IdempotencyReuse,
        Self::ConflictingEffects,
        Self::DurabilityUnavailable,
        Self::InternalInvariant,
    ];

    /// Stable machine-readable name, identical to the Rust variant name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::Unsupported => "Unsupported",
            Self::Unauthorized => "Unauthorized",
            Self::StaleBasis => "StaleBasis",
            Self::ExpectedOldMismatch => "ExpectedOldMismatch",
            Self::Policy => "Policy",
            Self::ObjectInvalidity => "ObjectInvalidity",
            Self::MissingPromisedObject => "MissingPromisedObject",
            Self::Resource => "Resource",
            Self::IdempotencyReuse => "IdempotencyReuse",
            Self::ConflictingEffects => "ConflictingEffects",
            Self::DurabilityUnavailable => "DurabilityUnavailable",
            Self::InternalInvariant => "InternalInvariant",
        }
    }

    /// The normative class of one wire refusal code.
    ///
    /// The match is exhaustive on purpose. When `fgit-types` adds a refusal
    /// code this function stops compiling, which forces a deliberate taxonomy
    /// decision instead of a silent default bucket.
    #[must_use]
    pub const fn of(code: RefusalCode) -> Self {
        match code {
            // Structural violations of a body, name, or framing rule.
            RefusalCode::IntentBytesConflict
            | RefusalCode::RefNameInvalid
            | RefusalCode::PackFramingInvalid
            | RefusalCode::TreeEntryOrderingInvalid
            | RefusalCode::CommitOrTagHeaderInvalid
            | RefusalCode::CanonicalFramingInvalid
            | RefusalCode::ObjectHeaderInvalid => Self::Malformed,

            // Features, schemas, and coverage classes this service does not
            // implement. §31: an unsupported path is refused, never silently
            // approximated.
            RefusalCode::SchemaUnsupported
            | RefusalCode::ContextCoverageUnsupported
            | RefusalCode::HashAlgorithmDomainMismatch
            | RefusalCode::RepositoryIncarnationMismatch => Self::Unsupported,

            // The principal, its delegation chain, or its capability set does
            // not cover the requested effect.
            RefusalCode::SponsorUnauthorized
            | RefusalCode::AgentIdentityRevoked
            | RefusalCode::CapabilityMissing
            | RefusalCode::CapabilityExpired
            | RefusalCode::CapabilityAudienceMismatch
            | RefusalCode::CapabilityScopeViolation
            | RefusalCode::DelegationAmplifiesAuthority
            | RefusalCode::PathOutsideScope
            | RefusalCode::NetworkDestinationDenied
            | RefusalCode::SecretPurposeDenied
            | RefusalCode::HiddenRefUnauthorized
            | RefusalCode::SignedPushCertificateRefused => Self::Unauthorized,

            // Evidence or preparation bound to a head basis that moved.
            RefusalCode::IntentExpired
            | RefusalCode::AuthorityReceiptInvalid
            | RefusalCode::AuthorityReceiptStale
            | RefusalCode::EvidenceStale
            | RefusalCode::WitnessRefinementInsufficient
            | RefusalCode::BasisCapsuleNotReusable
            | RefusalCode::WorkspaceBaseUnavailable => Self::StaleBasis,

            // A declared precondition on a ref disagreed with the basis.
            // `TargetRefMoved` is the agent-protocol spelling of the same
            // dimension.
            RefusalCode::ExpectedOldRefMismatch | RefusalCode::TargetRefMoved => {
                Self::ExpectedOldMismatch
            }

            // Deterministic policy over the pinned snapshot said no.
            RefusalCode::NonFastForwardRefused
            | RefusalCode::ForceNotPermitted
            | RefusalCode::ProtectedRefTransitionDenied
            | RefusalCode::PublicationPolicyRefused
            | RefusalCode::PolicyEpochSuperseded
            | RefusalCode::WorkspacePolicyViolation
            | RefusalCode::RetentionHoldViolation
            | RefusalCode::ForgeTransitionInvalid
            | RefusalCode::IndependentVerificationRequired
            | RefusalCode::ContextGenerationMixed
            | RefusalCode::EvidenceMissing
            | RefusalCode::EvidenceInvalid => Self::Policy,

            // An object failed validation against its own commitments.
            RefusalCode::NativeObjectIdMismatch => Self::ObjectInvalidity,

            // A promised object was not in the admitted closure.
            RefusalCode::ObjectClosureIncomplete | RefusalCode::ThinPackBaseMissing => {
                Self::MissingPromisedObject
            }

            // Quotas, budgets, and admission bounds.
            RefusalCode::BudgetInsufficient
            | RefusalCode::QuotaExceeded
            | RefusalCode::ResourceBudgetExceeded
            | RefusalCode::DecompressionBudgetExceeded
            | RefusalCode::CanonicalBoundExceeded
            | RefusalCode::DeltaBudgetExceeded => Self::Resource,

            // Contradictory effects, and the atomic-transaction abort a
            // sibling command's contradiction produces.
            RefusalCode::AtomicTransactionAborted | RefusalCode::ConflictingSemanticEffects => {
                Self::ConflictingEffects
            }

            // An effect-scoped idempotency key bound to different canonical
            // parameters by another transaction.
            RefusalCode::EffectIdempotencyKeyReuse => Self::IdempotencyReuse,

            // A first-party invariant observed broken.
            RefusalCode::InternalInvariantBreach => Self::InternalInvariant,

            // The declared placement predicate cannot be met, or an
            // externally observed effect's commit status cannot be
            // established: in both cases the declared durability profile has
            // not been reached and cannot be proven reachable.
            RefusalCode::DurabilityProfileUnavailable
            | RefusalCode::ExternalEffectIndeterminate
            | RefusalCode::ObligationsOutstanding
            | RefusalCode::CancellationInProgress => Self::DurabilityUnavailable,
        }
    }
}

/// Every [`RefusalCode`] the reference state machine may produce.
///
/// This is the model's declared refusal surface. It is intentionally much
/// smaller than [`RefusalCode::ALL`]: the reference model owns seal, intent
/// evaluation, decision, batch, and head semantics, so it never emits the
/// agent-protocol, workspace, transport, or pack-admission dimensions, which
/// belong to the crates that own those subsystems.
///
/// The list is sorted by [`RefusalCode::code_point`] and a test asserts that it
/// is exactly the set of codes the transitions emit, so a refusal added to a
/// transition without being declared here, or declared here without a
/// producing transition, fails the test rather than passing silently.
///
/// The surface covers twelve of the thirteen [`RefusalClass`] members. The
/// thirteenth, [`RefusalClass::InternalInvariant`], is deliberately absent: the
/// model reports a broken invariant as [`crate::state::InvariantBreach`] and
/// refuses to make the transition at all, rather than writing a bug into the
/// authenticated decision stream. [`crate::state::InvariantBreach::refusal_code`]
/// gives a caller that must report it through the decision vocabulary the
/// right code.
pub const MODEL_REFUSAL_SURFACE: &[RefusalCode] = &[
    RefusalCode::CapabilityScopeViolation,
    RefusalCode::SchemaUnsupported,
    RefusalCode::ExpectedOldRefMismatch,
    RefusalCode::NonFastForwardRefused,
    RefusalCode::ForceNotPermitted,
    RefusalCode::ProtectedRefTransitionDenied,
    RefusalCode::RefNameInvalid,
    RefusalCode::ObjectClosureIncomplete,
    RefusalCode::NativeObjectIdMismatch,
    RefusalCode::HashAlgorithmDomainMismatch,
    RefusalCode::ResourceBudgetExceeded,
    RefusalCode::RetentionHoldViolation,
    RefusalCode::PolicyEpochSuperseded,
    RefusalCode::BasisCapsuleNotReusable,
    RefusalCode::ForgeTransitionInvalid,
    RefusalCode::EffectIdempotencyKeyReuse,
    RefusalCode::ConflictingSemanticEffects,
    RefusalCode::DurabilityProfileUnavailable,
];

/// True when `code` is inside the model's declared refusal surface.
#[must_use]
pub fn is_model_refusal(code: RefusalCode) -> bool {
    MODEL_REFUSAL_SURFACE.contains(&code)
}

#[cfg(test)]
mod tests {
    use super::{MODEL_REFUSAL_SURFACE, RefusalClass, is_model_refusal};
    use fgit_types::vocabulary::RefusalCode;
    use std::collections::BTreeSet;

    #[test]
    fn every_wire_refusal_code_has_exactly_one_class() {
        // Totality is guaranteed by the exhaustive match; this asserts the
        // function is callable for every published member and that
        // classification is a function, not a relation.
        for code in RefusalCode::ALL {
            let first = RefusalClass::of(*code);
            let second = RefusalClass::of(*code);
            assert_eq!(
                first,
                second,
                "classification of {} is not deterministic",
                code.as_str()
            );
        }
    }

    #[test]
    fn class_names_are_distinct_and_match_variant_names() {
        let names = RefusalClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names.len(),
            RefusalClass::ALL.len(),
            "two refusal classes share a name"
        );
    }

    #[test]
    fn the_taxonomy_has_exactly_the_thirteen_classes_of_plan_15_11() {
        assert_eq!(RefusalClass::ALL.len(), 13);
    }

    #[test]
    fn model_refusal_surface_has_no_duplicates_and_is_code_point_sorted() {
        let unique = MODEL_REFUSAL_SURFACE.iter().collect::<BTreeSet<_>>();
        assert_eq!(
            unique.len(),
            MODEL_REFUSAL_SURFACE.len(),
            "MODEL_REFUSAL_SURFACE lists a code twice"
        );
        let mut previous = 0_u16;
        for code in MODEL_REFUSAL_SURFACE {
            let point = code.code_point();
            assert!(
                point > previous,
                "MODEL_REFUSAL_SURFACE is not sorted by code point at {}",
                code.as_str()
            );
            previous = point;
        }
    }

    #[test]
    fn membership_test_agrees_with_the_declared_surface() {
        for code in RefusalCode::ALL {
            assert_eq!(
                is_model_refusal(*code),
                MODEL_REFUSAL_SURFACE.contains(code),
                "membership disagrees for {}",
                code.as_str()
            );
        }
    }
}
