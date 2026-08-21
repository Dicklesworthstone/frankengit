//! Closed protocol vocabularies: rejections, refusals, terminal decisions,
//! intent mismatch policy, and publication epochs.
//!
//! Two rejection vocabularies exist because the normative contract draws a
//! hard line at the transaction seal.
//!
//! * A **request rejection** ([`RequestRejectionCode`]) happens *before* a seal
//!   exists. It is not repository history and must never claim `Committed`,
//!   `Refused`, or non-commit after an ambiguous attempt.
//! * A **transaction refusal** ([`RefusalCode`]) is a canonical terminal
//!   decision *after* sealing. It consumes decision sequence and appears in the
//!   authenticated decision history.
//!
//! Collapsing the two would let a pre-seal throttle masquerade as repository
//! history, so they are separate types with separate code-point spaces and no
//! conversion between them.
//!
//! Every member carries a stable `u16` code point. Decoding an unrecognized
//! code point is a typed [`TypeRefusal`] and never falls back to a default
//! member: a peer that speaks a newer vocabulary is refused, not
//! misinterpreted.

use crate::error::TypeRefusal;
use crate::identity::{RefusalRecordId, RepositoryCommitId};

/// Reason a request was rejected before any transaction seal existed.
///
/// A rejection leaves no canonical trace and proves nothing about commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RequestRejectionCode {
    /// Authentication did not establish a principal.
    AuthenticationFailed,
    /// Transport or request framing could not be parsed within bounds.
    MalformedFraming,
    /// The requested capability is not advertised by this service.
    UnsupportedCapability,
    /// The request exceeded the declared maximum request size.
    RequestSizeExceeded,
    /// The tenant is suspended.
    TenantSuspended,
    /// Coarse ingress throttling shed the request.
    IngressThrottled,
    /// The idempotency key is already bound to a different canonical request
    /// digest. The first request is never aliased.
    IdempotencyKeyReuse,
    /// The request schema identifier is not supported by this service.
    SchemaUnsupported,
    /// The addressed repository does not exist in this tenant, or names a
    /// superseded incarnation.
    RepositoryUnknown,
    /// The request mixed a hash algorithm the repository does not declare.
    HashAlgorithmUnsupported,
}

impl RequestRejectionCode {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationFailed,
        Self::MalformedFraming,
        Self::UnsupportedCapability,
        Self::RequestSizeExceeded,
        Self::TenantSuspended,
        Self::IngressThrottled,
        Self::IdempotencyKeyReuse,
        Self::SchemaUnsupported,
        Self::RepositoryUnknown,
        Self::HashAlgorithmUnsupported,
    ];

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::AuthenticationFailed => 0x0001,
            Self::MalformedFraming => 0x0002,
            Self::UnsupportedCapability => 0x0003,
            Self::RequestSizeExceeded => 0x0004,
            Self::TenantSuspended => 0x0005,
            Self::IngressThrottled => 0x0006,
            Self::IdempotencyKeyReuse => 0x0007,
            Self::SchemaUnsupported => 0x0008,
            Self::RepositoryUnknown => 0x0009,
            Self::HashAlgorithmUnsupported => 0x000a,
        }
    }

    /// Stable wire name, identical to the Rust variant name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AuthenticationFailed",
            Self::MalformedFraming => "MalformedFraming",
            Self::UnsupportedCapability => "UnsupportedCapability",
            Self::RequestSizeExceeded => "RequestSizeExceeded",
            Self::TenantSuspended => "TenantSuspended",
            Self::IngressThrottled => "IngressThrottled",
            Self::IdempotencyKeyReuse => "IdempotencyKeyReuse",
            Self::SchemaUnsupported => "SchemaUnsupported",
            Self::RepositoryUnknown => "RepositoryUnknown",
            Self::HashAlgorithmUnsupported => "HashAlgorithmUnsupported",
        }
    }

    /// Recovers a member from its wire code point.
    ///
    /// An unrecognized code point is refused; it is never mapped onto a
    /// nearby or default member.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "RequestRejectionCode",
                observed: u32::from(code_point),
            })
    }
}

/// Canonical terminal refusal reason for a sealed transaction.
///
/// Members in the `0x01xx` range come from the agent-protocol refusal taxonomy;
/// members in the `0x02xx` range are the ref-transaction and admission
/// dimensions that quarantine validation, expected-old/force semantics,
/// retention, and policy evaluation can refuse on.
///
/// There is deliberately no `Cancelled` member. Client cancellation before
/// publication leaves a sealed transaction undecided and retryable; it never
/// becomes a terminal decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefusalCode {
    // ---- agent-protocol taxonomy (0x01xx) ----
    /// The intent run's validity window elapsed before publication.
    IntentExpired,
    /// The submitted intent bytes disagree with the sealed intent identity.
    IntentBytesConflict,
    /// The sponsoring principal may not authorize this delegation.
    SponsorUnauthorized,
    /// The acting agent identity was revoked.
    AgentIdentityRevoked,
    /// The presented authority read receipt failed verification.
    AuthorityReceiptInvalid,
    /// The presented authority read receipt names a superseded head.
    AuthorityReceiptStale,
    /// No capability covering the requested effect was presented.
    CapabilityMissing,
    /// The presented capability has expired.
    CapabilityExpired,
    /// The presented capability names a different audience.
    CapabilityAudienceMismatch,
    /// The requested effect is outside the capability's declared scope.
    CapabilityScopeViolation,
    /// A delegation attempted to grant more authority than it holds.
    DelegationAmplifiesAuthority,
    /// Context packets mixed immutable generations.
    ContextGenerationMixed,
    /// The requested context coverage class is not supported.
    ContextCoverageUnsupported,
    /// The requested workspace base is unavailable.
    WorkspaceBaseUnavailable,
    /// The workspace operation violates workspace policy.
    WorkspacePolicyViolation,
    /// A path escaped the declared effect scope.
    PathOutsideScope,
    /// A network destination outside the allowed egress set was requested.
    NetworkDestinationDenied,
    /// A secret was requested for a purpose its policy does not allow.
    SecretPurposeDenied,
    /// The reserved budget cannot cover the requested effect.
    BudgetInsufficient,
    /// Required evidence was not supplied.
    EvidenceMissing,
    /// Supplied evidence failed verification.
    EvidenceInvalid,
    /// Supplied evidence names a superseded basis.
    EvidenceStale,
    /// The claim class requires an independent verifier that did not run.
    IndependentVerificationRequired,
    /// A target ref moved away from the expected basis.
    TargetRefMoved,
    /// Declared conflict witnesses were too coarse to prove non-conflict after
    /// a lost compare-and-exchange.
    WitnessRefinementInsufficient,
    /// Publication policy refused the transition.
    PublicationPolicyRefused,
    /// A cancellation drain is in progress for this scope.
    CancellationInProgress,
    /// Obligations from a prior effect remain unresolved.
    ObligationsOutstanding,
    /// An externally observed effect cannot be proven committed or not.
    ExternalEffectIndeterminate,
    /// The body schema identifier is not supported.
    SchemaUnsupported,

    // ---- ref-transaction and admission dimensions (0x02xx) ----
    /// The expected-old value for a ref did not match the basis.
    ExpectedOldRefMismatch,
    /// The update is not a fast-forward and force was not requested.
    NonFastForwardRefused,
    /// Force was requested but the principal or ref policy forbids it.
    ForceNotPermitted,
    /// A protection rule forbids this ref transition.
    ProtectedRefTransitionDenied,
    /// The ref name violates the ref naming rules.
    RefNameInvalid,
    /// The request touched a ref hidden from this principal.
    HiddenRefUnauthorized,
    /// An atomic transaction aborted because a sibling command failed.
    AtomicTransactionAborted,
    /// The advertised object closure is incomplete.
    ObjectClosureIncomplete,
    /// Transport, pack header, trailer, or checksum framing failed validation.
    PackFramingInvalid,
    /// Decompressed size or expansion ratio exceeded the admission bound.
    DecompressionBudgetExceeded,
    /// Delta depth, fan-out, aggregate work, or a delta cycle exceeded the
    /// admission bound.
    DeltaBudgetExceeded,
    /// A thin-pack base object is absent from the repository and the pack.
    ThinPackBaseMissing,
    /// An object header, type, or declared length failed validation.
    ObjectHeaderInvalid,
    /// Tree entry ordering, mode, or name rules were violated.
    TreeEntryOrderingInvalid,
    /// A commit or annotated tag header failed validation or exceeded an
    /// encoding limit.
    CommitOrTagHeaderInvalid,
    /// A recomputed native object identity disagreed with the declared one.
    NativeObjectIdMismatch,
    /// An operation crossed the SHA-1 and SHA-256 identity domains.
    HashAlgorithmDomainMismatch,
    /// A signed-push certificate failed policy evaluation.
    SignedPushCertificateRefused,
    /// A tenant or repository quota would be exceeded.
    QuotaExceeded,
    /// A wall-clock, memory, or work budget for admission was exhausted.
    ResourceBudgetExceeded,
    /// The effect would remove or alter state under retention or legal hold.
    RetentionHoldViolation,
    /// The pinned policy epoch was superseded before publication.
    PolicyEpochSuperseded,
    /// The prepared capsule cannot be reused against the current head basis.
    BasisCapsuleNotReusable,
    /// A requested forge state transition is invalid from the current forge
    /// position.
    ForgeTransitionInvalid,
    /// The request names a superseded repository incarnation.
    RepositoryIncarnationMismatch,
    /// A sealed transaction bound an effect-scoped idempotency key that another
    /// transaction already bound to different canonical parameters.
    ///
    /// Distinct from [`RequestRejectionCode::IdempotencyKeyReuse`], which is a
    /// pre-seal rejection over the *request* key. This one is a terminal
    /// decision about an *effect* key and is repository history. The same key
    /// with identical canonical parameters stays an absorbed no-op and is not
    /// a refusal.
    EffectIdempotencyKeyReuse,
    /// Source intents folded to contradictory duplicate values, an ambiguous
    /// cascade, or an unordered collection, so no single net effect exists.
    ///
    /// Such input is refused rather than normalized into an invented policy.
    ConflictingSemanticEffects,
    /// The declared durability profile cannot be satisfied.
    ///
    /// The placement, repair, and failure-domain predicate cannot be met, so
    /// the batch cannot reach the durability epoch its profile requires. The
    /// bodies may be staged and valid; it is the profile that cannot be met.
    DurabilityProfileUnavailable,
    /// A first-party invariant was observed broken: a second terminal decision
    /// for one sealed transaction, or an accelerator that disagrees with the
    /// authenticated stream.
    ///
    /// This exists so the one condition operators most need to see is reported
    /// as itself instead of failing closed as a nearby class.
    InternalInvariantBreach,
    /// A canonical body's framing, lengths, tags, or collection ordering
    /// failed validation, so the bytes have no single well-defined value.
    CanonicalFramingInvalid,
    /// A canonical body exceeded a declared decode bound: a length, an element
    /// count, or a nesting depth. The bound is checked before allocation.
    CanonicalBoundExceeded,
}

impl RefusalCode {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[
        Self::IntentExpired,
        Self::IntentBytesConflict,
        Self::SponsorUnauthorized,
        Self::AgentIdentityRevoked,
        Self::AuthorityReceiptInvalid,
        Self::AuthorityReceiptStale,
        Self::CapabilityMissing,
        Self::CapabilityExpired,
        Self::CapabilityAudienceMismatch,
        Self::CapabilityScopeViolation,
        Self::DelegationAmplifiesAuthority,
        Self::ContextGenerationMixed,
        Self::ContextCoverageUnsupported,
        Self::WorkspaceBaseUnavailable,
        Self::WorkspacePolicyViolation,
        Self::PathOutsideScope,
        Self::NetworkDestinationDenied,
        Self::SecretPurposeDenied,
        Self::BudgetInsufficient,
        Self::EvidenceMissing,
        Self::EvidenceInvalid,
        Self::EvidenceStale,
        Self::IndependentVerificationRequired,
        Self::TargetRefMoved,
        Self::WitnessRefinementInsufficient,
        Self::PublicationPolicyRefused,
        Self::CancellationInProgress,
        Self::ObligationsOutstanding,
        Self::ExternalEffectIndeterminate,
        Self::SchemaUnsupported,
        Self::ExpectedOldRefMismatch,
        Self::NonFastForwardRefused,
        Self::ForceNotPermitted,
        Self::ProtectedRefTransitionDenied,
        Self::RefNameInvalid,
        Self::HiddenRefUnauthorized,
        Self::AtomicTransactionAborted,
        Self::ObjectClosureIncomplete,
        Self::PackFramingInvalid,
        Self::DecompressionBudgetExceeded,
        Self::DeltaBudgetExceeded,
        Self::ThinPackBaseMissing,
        Self::ObjectHeaderInvalid,
        Self::TreeEntryOrderingInvalid,
        Self::CommitOrTagHeaderInvalid,
        Self::NativeObjectIdMismatch,
        Self::HashAlgorithmDomainMismatch,
        Self::SignedPushCertificateRefused,
        Self::QuotaExceeded,
        Self::ResourceBudgetExceeded,
        Self::RetentionHoldViolation,
        Self::PolicyEpochSuperseded,
        Self::BasisCapsuleNotReusable,
        Self::ForgeTransitionInvalid,
        Self::RepositoryIncarnationMismatch,
        Self::EffectIdempotencyKeyReuse,
        Self::ConflictingSemanticEffects,
        Self::DurabilityProfileUnavailable,
        Self::InternalInvariantBreach,
        Self::CanonicalFramingInvalid,
        Self::CanonicalBoundExceeded,
    ];

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::IntentExpired => 0x0101,
            Self::IntentBytesConflict => 0x0102,
            Self::SponsorUnauthorized => 0x0103,
            Self::AgentIdentityRevoked => 0x0104,
            Self::AuthorityReceiptInvalid => 0x0105,
            Self::AuthorityReceiptStale => 0x0106,
            Self::CapabilityMissing => 0x0107,
            Self::CapabilityExpired => 0x0108,
            Self::CapabilityAudienceMismatch => 0x0109,
            Self::CapabilityScopeViolation => 0x010a,
            Self::DelegationAmplifiesAuthority => 0x010b,
            Self::ContextGenerationMixed => 0x010c,
            Self::ContextCoverageUnsupported => 0x010d,
            Self::WorkspaceBaseUnavailable => 0x010e,
            Self::WorkspacePolicyViolation => 0x010f,
            Self::PathOutsideScope => 0x0110,
            Self::NetworkDestinationDenied => 0x0111,
            Self::SecretPurposeDenied => 0x0112,
            Self::BudgetInsufficient => 0x0113,
            Self::EvidenceMissing => 0x0114,
            Self::EvidenceInvalid => 0x0115,
            Self::EvidenceStale => 0x0116,
            Self::IndependentVerificationRequired => 0x0117,
            Self::TargetRefMoved => 0x0118,
            Self::WitnessRefinementInsufficient => 0x0119,
            Self::PublicationPolicyRefused => 0x011a,
            Self::CancellationInProgress => 0x011b,
            Self::ObligationsOutstanding => 0x011c,
            Self::ExternalEffectIndeterminate => 0x011d,
            Self::SchemaUnsupported => 0x011e,
            Self::ExpectedOldRefMismatch => 0x0201,
            Self::NonFastForwardRefused => 0x0202,
            Self::ForceNotPermitted => 0x0203,
            Self::ProtectedRefTransitionDenied => 0x0204,
            Self::RefNameInvalid => 0x0205,
            Self::HiddenRefUnauthorized => 0x0206,
            Self::AtomicTransactionAborted => 0x0207,
            Self::ObjectClosureIncomplete => 0x0208,
            Self::PackFramingInvalid => 0x0209,
            Self::DecompressionBudgetExceeded => 0x020a,
            Self::DeltaBudgetExceeded => 0x020b,
            Self::ThinPackBaseMissing => 0x020c,
            Self::ObjectHeaderInvalid => 0x020d,
            Self::TreeEntryOrderingInvalid => 0x020e,
            Self::CommitOrTagHeaderInvalid => 0x020f,
            Self::NativeObjectIdMismatch => 0x0210,
            Self::HashAlgorithmDomainMismatch => 0x0211,
            Self::SignedPushCertificateRefused => 0x0212,
            Self::QuotaExceeded => 0x0213,
            Self::ResourceBudgetExceeded => 0x0214,
            Self::RetentionHoldViolation => 0x0215,
            Self::PolicyEpochSuperseded => 0x0216,
            Self::BasisCapsuleNotReusable => 0x0217,
            Self::ForgeTransitionInvalid => 0x0218,
            Self::RepositoryIncarnationMismatch => 0x0219,
            Self::EffectIdempotencyKeyReuse => 0x021a,
            Self::ConflictingSemanticEffects => 0x021b,
            Self::DurabilityProfileUnavailable => 0x021c,
            Self::InternalInvariantBreach => 0x021d,
            Self::CanonicalFramingInvalid => 0x021e,
            Self::CanonicalBoundExceeded => 0x021f,
        }
    }

    /// Stable wire name, identical to the Rust variant name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntentExpired => "IntentExpired",
            Self::IntentBytesConflict => "IntentBytesConflict",
            Self::SponsorUnauthorized => "SponsorUnauthorized",
            Self::AgentIdentityRevoked => "AgentIdentityRevoked",
            Self::AuthorityReceiptInvalid => "AuthorityReceiptInvalid",
            Self::AuthorityReceiptStale => "AuthorityReceiptStale",
            Self::CapabilityMissing => "CapabilityMissing",
            Self::CapabilityExpired => "CapabilityExpired",
            Self::CapabilityAudienceMismatch => "CapabilityAudienceMismatch",
            Self::CapabilityScopeViolation => "CapabilityScopeViolation",
            Self::DelegationAmplifiesAuthority => "DelegationAmplifiesAuthority",
            Self::ContextGenerationMixed => "ContextGenerationMixed",
            Self::ContextCoverageUnsupported => "ContextCoverageUnsupported",
            Self::WorkspaceBaseUnavailable => "WorkspaceBaseUnavailable",
            Self::WorkspacePolicyViolation => "WorkspacePolicyViolation",
            Self::PathOutsideScope => "PathOutsideScope",
            Self::NetworkDestinationDenied => "NetworkDestinationDenied",
            Self::SecretPurposeDenied => "SecretPurposeDenied",
            Self::BudgetInsufficient => "BudgetInsufficient",
            Self::EvidenceMissing => "EvidenceMissing",
            Self::EvidenceInvalid => "EvidenceInvalid",
            Self::EvidenceStale => "EvidenceStale",
            Self::IndependentVerificationRequired => "IndependentVerificationRequired",
            Self::TargetRefMoved => "TargetRefMoved",
            Self::WitnessRefinementInsufficient => "WitnessRefinementInsufficient",
            Self::PublicationPolicyRefused => "PublicationPolicyRefused",
            Self::CancellationInProgress => "CancellationInProgress",
            Self::ObligationsOutstanding => "ObligationsOutstanding",
            Self::ExternalEffectIndeterminate => "ExternalEffectIndeterminate",
            Self::SchemaUnsupported => "SchemaUnsupported",
            Self::ExpectedOldRefMismatch => "ExpectedOldRefMismatch",
            Self::NonFastForwardRefused => "NonFastForwardRefused",
            Self::ForceNotPermitted => "ForceNotPermitted",
            Self::ProtectedRefTransitionDenied => "ProtectedRefTransitionDenied",
            Self::RefNameInvalid => "RefNameInvalid",
            Self::HiddenRefUnauthorized => "HiddenRefUnauthorized",
            Self::AtomicTransactionAborted => "AtomicTransactionAborted",
            Self::ObjectClosureIncomplete => "ObjectClosureIncomplete",
            Self::PackFramingInvalid => "PackFramingInvalid",
            Self::DecompressionBudgetExceeded => "DecompressionBudgetExceeded",
            Self::DeltaBudgetExceeded => "DeltaBudgetExceeded",
            Self::ThinPackBaseMissing => "ThinPackBaseMissing",
            Self::ObjectHeaderInvalid => "ObjectHeaderInvalid",
            Self::TreeEntryOrderingInvalid => "TreeEntryOrderingInvalid",
            Self::CommitOrTagHeaderInvalid => "CommitOrTagHeaderInvalid",
            Self::NativeObjectIdMismatch => "NativeObjectIdMismatch",
            Self::HashAlgorithmDomainMismatch => "HashAlgorithmDomainMismatch",
            Self::SignedPushCertificateRefused => "SignedPushCertificateRefused",
            Self::QuotaExceeded => "QuotaExceeded",
            Self::ResourceBudgetExceeded => "ResourceBudgetExceeded",
            Self::RetentionHoldViolation => "RetentionHoldViolation",
            Self::PolicyEpochSuperseded => "PolicyEpochSuperseded",
            Self::BasisCapsuleNotReusable => "BasisCapsuleNotReusable",
            Self::ForgeTransitionInvalid => "ForgeTransitionInvalid",
            Self::RepositoryIncarnationMismatch => "RepositoryIncarnationMismatch",
            Self::EffectIdempotencyKeyReuse => "EffectIdempotencyKeyReuse",
            Self::ConflictingSemanticEffects => "ConflictingSemanticEffects",
            Self::DurabilityProfileUnavailable => "DurabilityProfileUnavailable",
            Self::InternalInvariantBreach => "InternalInvariantBreach",
            Self::CanonicalFramingInvalid => "CanonicalFramingInvalid",
            Self::CanonicalBoundExceeded => "CanonicalBoundExceeded",
        }
    }

    /// True when this refusal came from the agent-protocol taxonomy rather
    /// than the ref-transaction admission dimensions.
    #[must_use]
    pub const fn is_agent_protocol_dimension(self) -> bool {
        self.code_point() < 0x0200
    }

    /// Recovers a member from its wire code point.
    ///
    /// An unrecognized code point is refused; it is never mapped onto a
    /// nearby or default member.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "RefusalCode",
                observed: u32::from(code_point),
            })
    }
}

/// The one terminal decision a sealed transaction can reach.
///
/// A sealed transaction appears at most once in the authenticated decision
/// history. There is no canonical cancelled outcome: infrastructure
/// interruption before publication leaves the transaction undecided and
/// retryable, and client cancellation can neither erase nor redefine a
/// decision that already linearized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DecisionOutcome {
    /// The transaction committed and produced one Repository Commit Record.
    Committed {
        /// Identity of the committed Repository Commit Record.
        repository_commit_id: RepositoryCommitId,
    },
    /// The transaction was refused and produced one refusal record.
    Refused {
        /// Terminal refusal reason.
        code: RefusalCode,
        /// Identity of the immutable refusal record explaining the decision.
        refusal_record_id: RefusalRecordId,
    },
}

impl DecisionOutcome {
    /// Stable discriminant used by canonical encodings and indexes.
    #[must_use]
    pub const fn discriminant(&self) -> u8 {
        match self {
            Self::Committed { .. } => 1,
            Self::Refused { .. } => 2,
        }
    }

    /// True when this decision advanced repository sequence.
    ///
    /// Refusals consume decision sequence but never advance repository
    /// sequence or the source and forge roots.
    #[must_use]
    pub const fn advances_repository_sequence(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }
}

/// What happens when an intent's precondition does not match the basis.
///
/// Canonical commands are intents, not pre-baked effects; the mismatch policy
/// is part of the transaction schema rather than an implementation detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MismatchPolicy {
    /// The statement is absorbed as a no-op.
    NoOp,
    /// The statement fails locally, where the transaction schema permits
    /// statement-local failure.
    StatementError,
    /// The whole transaction aborts.
    TxnAbort,
}

impl MismatchPolicy {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[Self::NoOp, Self::StatementError, Self::TxnAbort];

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::NoOp => 1,
            Self::StatementError => 2,
            Self::TxnAbort => 3,
        }
    }

    /// Recovers a member from its wire code point.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "MismatchPolicy",
                observed: u32::from(code_point),
            })
    }
}

/// The three distinct publication epochs.
///
/// Object existence, canonical visibility, and satisfaction of the declared
/// durability profile are separate facts and are never conflated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PublicationEpoch {
    /// Immutable candidate bodies exist but no authority root references them.
    Staged,
    /// An authority or generation root references them and clients may observe
    /// them.
    Visible,
    /// The declared placement, repair, and failure-domain predicate holds.
    Durable,
}

impl PublicationEpoch {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[Self::Staged, Self::Visible, Self::Durable];

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Staged => 1,
            Self::Visible => 2,
            Self::Durable => 3,
        }
    }

    /// Recovers a member from its wire code point.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "PublicationEpoch",
                observed: u32::from(code_point),
            })
    }
}
