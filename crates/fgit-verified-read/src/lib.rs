#![forbid(unsafe_code)]

//! Versioned verified-read envelopes and a client-side proof verifier.
//!
//! A serving cell is allowed to supply this envelope, but it is not allowed to
//! choose the authority root it verifies against. The client provides one
//! pinned [`RepositoryAuthorityHeadBody`] and this crate refuses an envelope
//! that names any other head before inspecting its answer.
//!
//! The verifier intentionally depends only on the canonical body/types and
//! the landed Merkle verifier cores. It has no authority-store, node, network,
//! or server dependency. That keeps the client trust boundary reviewable: a
//! valid answer establishes membership under the *pinned* head, not that a
//! server selected the head honestly or that it is current.
//!
//! # Typed non-claim: forge positions
//!
//! The V1 ref layout admits ordered non-membership proofs only after the
//! disclosure boundary has authorized the lookup. The independent Merkle
//! verifier's sorted-tree precondition is discharged by an authenticated V1
//! ref root built through the canonical layout; an arbitrary opaque root is
//! not enough. Likewise,
//! `forge_position_root` has no published canonical Merkle layout yet, so
//! forge-position proof generation is a typed refusal.

use core::fmt;

pub mod freshness;

use fgit_authority::{OutcomeFailure, TerminalOutcome, verify_outcome_index_membership};
use fgit_codec::{
    CryptoBodyIdentity, RepositoryAuthorityHeadBody, RepositoryConfigurationBody,
    RepositoryIncarnationConfigurationBody, body_id,
};
use fgit_crypto::{
    MerkleProof, MerkleRefusal, RefStateNonMembershipProof, verify_ref_state_membership_under,
    verify_ref_state_non_membership_under,
};
use fgit_types::identity::TxId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitOid;
use fgit_types::refs::RefName;

/// The sole proof-envelope wire version this build understands.
pub use freshness::{FreshnessRefusal, FreshnessVerdict, HeadChainFloor};

pub const VERIFIED_READ_ENVELOPE_V1: u16 = 1;

/// A client's offered verified-read capability.
///
/// A client that does not offer [`Self::EnvelopeV1`] receives an ordinary
/// answer. That preserves compatibility for consumers which do not need a
/// proof and prevents a server from assuming that every caller can interpret
/// a proof response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedReadCapability {
    /// The client accepts only an ordinary, unproven response.
    Unproven,
    /// The client accepts the version-one verified-read envelope.
    EnvelopeV1,
}

/// The response representation selected from a client capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedReadResponseMode {
    /// Return the regular response body without a proof envelope.
    Unproven,
    /// Return a [`VerifiedReadEnvelope`] using version one.
    EnvelopeV1,
}

/// Selects the response representation for one offered capability.
#[must_use]
pub const fn negotiate_response_mode(
    capability: VerifiedReadCapability,
) -> VerifiedReadResponseMode {
    match capability {
        VerifiedReadCapability::Unproven => VerifiedReadResponseMode::Unproven,
        VerifiedReadCapability::EnvelopeV1 => VerifiedReadResponseMode::EnvelopeV1,
    }
}

/// A head whose authenticity and desired snapshot semantics the client has
/// already established independently of the serving cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedAuthorityHead {
    body: RepositoryAuthorityHeadBody,
}

impl PinnedAuthorityHead {
    /// Pins the exact authority-head body against which subsequent responses
    /// are checked.
    #[must_use]
    pub const fn new(body: RepositoryAuthorityHeadBody) -> Self {
        Self { body }
    }

    /// The exact pinned head body.
    #[must_use]
    pub const fn body(&self) -> &RepositoryAuthorityHeadBody {
        &self.body
    }
}

/// A regular read answer for a client that did not negotiate proofs.
///
/// This type deliberately carries no statement about inclusion. It remains a
/// valid response mode, but the client retains the ordinary serving-cell trust
/// model for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnprovenReadAnswer {
    /// A ref answer, including an authorization-gated absence when `oid` is
    /// `None`.
    Ref { name: RefName, oid: Option<GitOid> },
    /// A terminal-decision answer, or an ordinary undecided answer.
    Outcome {
        /// Transaction queried by the client.
        tx_id: TxId,
        /// Terminal outcome, when one was found.
        outcome: Option<Box<TerminalOutcome>>,
    },
}

/// The two response representations a server may return after capability
/// negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadResponse {
    /// An ordinary response selected for a client without proof support.
    Unproven(Box<UnprovenReadAnswer>),
    /// A response carrying a versioned proof envelope.
    Verified(Box<VerifiedReadEnvelope>),
}

/// An authorization policy at the read-serving boundary.
///
/// This trait does not grant access by itself. The serving layer supplies its
/// authenticated policy snapshot; this crate makes the order load-bearing by
/// calling it before the lookup closure that could disclose a ref's existence.
pub trait RefDisclosurePolicy {
    /// Whether `name` is within the caller's authorized disclosure scope.
    fn permits_ref_disclosure(&self, name: &RefName) -> bool;
}

/// An absence that was looked up only after authorization allowed disclosure.
///
/// It is intentionally not a Merkle non-membership proof. The wrapper keeps a
/// caller from constructing an absence answer without passing the
/// authorization-first constructor below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRefAbsence {
    name: RefName,
}

impl AuthorizedRefAbsence {
    /// The name whose authorized lookup found no ref.
    #[must_use]
    pub const fn name(&self) -> &RefName {
        &self.name
    }
}

/// Applies authorization before looking up a possible ref absence.
///
/// A denied caller receives exactly [`VerifiedReadRefusal::RefNotFoundOrUnauthorized`]
/// regardless of whether `lookup` would have found a ref. In particular, the
/// closure is not called in that branch, so a hidden ref cannot be probed by
/// observing lookup-specific behavior.
///
/// # Errors
///
/// [`VerifiedReadRefusal::RefNotFoundOrUnauthorized`] when disclosure is not
/// authorized, and [`VerifiedReadRefusal::RefPresent`] when the authorized
/// lookup found the requested ref.
pub fn authorize_ref_absence<P, L>(
    policy: &P,
    name: RefName,
    lookup: L,
) -> Result<AuthorizedRefAbsence, VerifiedReadRefusal>
where
    P: RefDisclosurePolicy + ?Sized,
    L: FnOnce(&RefName) -> bool,
{
    if !policy.permits_ref_disclosure(&name) {
        return Err(VerifiedReadRefusal::RefNotFoundOrUnauthorized);
    }
    if lookup(&name) {
        return Err(VerifiedReadRefusal::RefPresent);
    }
    Ok(AuthorizedRefAbsence { name })
}

/// One answer that a version-one envelope can carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedReadAnswer {
    /// A ref and the membership path under the pinned head's `ref_root`.
    RefMembership {
        /// Ref name claimed by the serving cell.
        name: RefName,
        /// Native object identity claimed for `name`.
        oid: GitOid,
        /// Merkle path generated from the canonical ref-state layout.
        proof: Box<MerkleProof>,
    },
    /// A terminal outcome and the membership path under the pinned head's
    /// `outcome_index_root`.
    OutcomeMembership {
        /// Transaction identity claimed by the serving cell.
        tx_id: TxId,
        /// Terminal outcome claimed for `tx_id`.
        outcome: Box<TerminalOutcome>,
        /// Merkle path generated from the canonical outcome-index layout.
        proof: Box<MerkleProof>,
    },
    /// An authorization-gated absence and its ordered V1 Merkle witness.
    ///
    /// The absence wrapper can only be obtained through
    /// [`authorize_ref_absence`], which runs the disclosure policy before the
    /// lookup. The proof still has to verify under the exact pinned ref root.
    AuthorizedRefAbsence {
        /// The name whose absence was authorized for disclosure.
        absence: AuthorizedRefAbsence,
        /// Ordered neighbour evidence for that absence.
        proof: Box<RefStateNonMembershipProof>,
    },
}

/// The exact repository-configuration body selected by an authority head.
///
/// Envelope V1 describes the proof-envelope grammar, not the configuration
/// schema.  Repository incarnation support selected schema-major 2 while
/// retaining the same authority-head `configuration_root` slot; erasing that
/// distinction and recreating a schema-major 1 body would change the canonical
/// identity.  A verifier therefore keeps the selected body typed and computes
/// its identity from its own canonical schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedReadConfiguration {
    /// The original repository-configuration schema.
    RepositoryV1(RepositoryConfigurationBody),
    /// The incarnation-bound repository-configuration schema.
    RepositoryIncarnationV2(RepositoryIncarnationConfigurationBody),
}

impl VerifiedReadConfiguration {
    /// The root-layout interpretation committed by this exact configuration.
    #[must_use]
    pub const fn root_layout(&self) -> RootLayoutVersion {
        match self {
            Self::RepositoryV1(configuration) => configuration.root_layout,
            Self::RepositoryIncarnationV2(configuration) => configuration.root_layout,
        }
    }
}

/// A versioned proof response tied to the head body the server claims to have
/// used.
///
/// The client still supplies [`PinnedAuthorityHead`] to [`verify_envelope`].
/// Carrying a head in the response helps transports frame one self-contained
/// record, but does not give a serving cell authority to select it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReadEnvelope {
    version: u16,
    head: RepositoryAuthorityHeadBody,
    configuration: Option<VerifiedReadConfiguration>,
    answer: VerifiedReadAnswer,
}

impl VerifiedReadEnvelope {
    /// Constructs a version-one envelope.
    #[must_use]
    pub fn new(
        head: RepositoryAuthorityHeadBody,
        configuration: Option<RepositoryConfigurationBody>,
        answer: VerifiedReadAnswer,
    ) -> Self {
        let configuration = match configuration {
            Some(configuration) => Some(VerifiedReadConfiguration::RepositoryV1(configuration)),
            None => None,
        };
        Self::new_with_exact_configuration(head, configuration, answer)
    }

    /// Constructs a version-one envelope carrying the exact selected
    /// configuration schema.
    ///
    /// This is the serving-side constructor for repositories whose authority
    /// head selects an incarnation-bound configuration.  It deliberately takes
    /// the body rather than a root supplied by the serving cell: verification
    /// re-identifies this canonical body and requires that identity to equal
    /// the pinned head's `configuration_root`.
    #[must_use]
    pub const fn new_with_exact_configuration(
        head: RepositoryAuthorityHeadBody,
        configuration: Option<VerifiedReadConfiguration>,
        answer: VerifiedReadAnswer,
    ) -> Self {
        Self {
            version: VERIFIED_READ_ENVELOPE_V1,
            head,
            configuration,
            answer,
        }
    }

    /// Validates and constructs an envelope from a transport-decoded version.
    ///
    /// # Errors
    ///
    /// [`VerifiedReadRefusal::UnsupportedEnvelopeVersion`] when `version` is
    /// unknown to this verifier.
    pub fn from_versioned_parts(
        version: u16,
        head: RepositoryAuthorityHeadBody,
        configuration: Option<RepositoryConfigurationBody>,
        answer: VerifiedReadAnswer,
    ) -> Result<Self, VerifiedReadRefusal> {
        let configuration = configuration.map(VerifiedReadConfiguration::RepositoryV1);
        Self::from_versioned_parts_with_exact_configuration(version, head, configuration, answer)
    }

    /// Validates and constructs an envelope carrying the exact selected
    /// configuration schema from a transport-decoded version.
    ///
    /// # Errors
    ///
    /// [`VerifiedReadRefusal::UnsupportedEnvelopeVersion`] when `version` is
    /// unknown to this verifier.
    pub fn from_versioned_parts_with_exact_configuration(
        version: u16,
        head: RepositoryAuthorityHeadBody,
        configuration: Option<VerifiedReadConfiguration>,
        answer: VerifiedReadAnswer,
    ) -> Result<Self, VerifiedReadRefusal> {
        if version != VERIFIED_READ_ENVELOPE_V1 {
            return Err(VerifiedReadRefusal::UnsupportedEnvelopeVersion { observed: version });
        }
        Ok(Self {
            version,
            head,
            configuration,
            answer,
        })
    }

    /// The accepted envelope version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The head body carried by the serving cell.
    #[must_use]
    pub const fn head(&self) -> &RepositoryAuthorityHeadBody {
        &self.head
    }

    /// The configuration body used to establish a non-legacy root layout.
    #[must_use]
    pub const fn configuration(&self) -> Option<&RepositoryConfigurationBody> {
        match self.configuration.as_ref() {
            Some(VerifiedReadConfiguration::RepositoryV1(configuration)) => Some(configuration),
            Some(VerifiedReadConfiguration::RepositoryIncarnationV2(_)) | None => None,
        }
    }

    /// The exact configuration body whose identity the verifier binds to the
    /// pinned head when a ref proof needs a non-legacy layout.
    #[must_use]
    pub const fn exact_configuration(&self) -> Option<&VerifiedReadConfiguration> {
        self.configuration.as_ref()
    }

    /// The claimed answer and proof path.
    #[must_use]
    pub const fn answer(&self) -> &VerifiedReadAnswer {
        &self.answer
    }
}

/// Successful membership verification under one exact pinned root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedMembership {
    /// A ref membership proof verified against the pinned head's `ref_root`.
    Ref,
    /// An authorization-gated ref non-membership proof verified against the
    /// pinned head's `ref_root`.
    RefAbsence,
    /// An outcome membership proof verified against the pinned head's
    /// `outcome_index_root`.
    Outcome,
}

/// A failure to form, gate, or verify a verified-read answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedReadRefusal {
    /// The response named an envelope version this verifier does not support.
    UnsupportedEnvelopeVersion {
        /// Version observed in transport data.
        observed: u16,
    },
    /// The serving cell's carried head differs from the client's pin.
    PinnedHeadMismatch,
    /// The configuration body could not be canonically identified.
    ConfigurationIdentityUnavailable,
    /// The configuration body does not identify to the pinned head's
    /// `configuration_root`.
    ConfigurationRootMismatch,
    /// The selected layout does not admit a ref-state membership proof.
    RefLayout(Box<MerkleRefusal>),
    /// The Merkle path did not verify against the pinned root.
    ProofRejected,
    /// Canonical outcome encoding or its verifier refused the answer.
    Outcome(Box<OutcomeFailure>),
    /// Disclosure was denied before consulting the requested ref's existence.
    ///
    /// This same public refusal intentionally covers a hidden ref and an
    /// absent ref from a caller without disclosure authority.
    RefNotFoundOrUnauthorized,
    /// The caller was allowed to disclose the name, but the lookup found it.
    RefPresent,
    /// No canonical forge-position Merkle layout is published yet.
    ForgePositionProofUnavailable,
}

impl fmt::Display for VerifiedReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEnvelopeVersion { observed } => {
                write!(formatter, "unsupported verified-read envelope version {observed}")
            }
            Self::PinnedHeadMismatch => {
                formatter.write_str("the response head does not equal the client-pinned head")
            }
            Self::ConfigurationIdentityUnavailable => {
                formatter.write_str("the carried configuration body has no canonical identity")
            }
            Self::ConfigurationRootMismatch => formatter.write_str(
                "the carried configuration body does not match the pinned head configuration root",
            ),
            Self::RefLayout(refusal) => write!(formatter, "ref proof layout refused: {refusal}"),
            Self::ProofRejected => {
                formatter.write_str("the claimed Merkle path does not verify against the pinned root")
            }
            Self::Outcome(refusal) => write!(formatter, "outcome proof refused: {refusal}"),
            Self::RefNotFoundOrUnauthorized => formatter.write_str("ref not found"),
            Self::RefPresent => formatter.write_str("ref is present after authorized lookup"),
            Self::ForgePositionProofUnavailable => formatter.write_str(
                "forge-position proof generation is unavailable until a canonical forge Merkle layout is published",
            ),
        }
    }
}

impl std::error::Error for VerifiedReadRefusal {}

/// Verifies one claimed membership answer against an exact client-pinned head.
///
/// The result establishes only membership in the selected root of `pinned`.
/// The caller must authenticate and choose that pin through the authority-head
/// chain before calling this function. It must not infer currentness from a
/// successful Merkle path.
///
/// # Errors
///
/// A typed refusal names a version, pin, configuration, layout, encoding, or
/// proof failure. An authorized ref absence verifies only through the V1
/// ordered non-membership shape; no missing-proof fallback is accepted as a
/// verified negative answer.
pub fn verify_envelope(
    pinned: &PinnedAuthorityHead,
    envelope: &VerifiedReadEnvelope,
) -> Result<VerifiedMembership, VerifiedReadRefusal> {
    if envelope.version != VERIFIED_READ_ENVELOPE_V1 {
        return Err(VerifiedReadRefusal::UnsupportedEnvelopeVersion {
            observed: envelope.version,
        });
    }
    if envelope.head != pinned.body {
        return Err(VerifiedReadRefusal::PinnedHeadMismatch);
    }

    match &envelope.answer {
        VerifiedReadAnswer::RefMembership { name, oid, proof } => {
            let layout = selected_ref_layout(pinned.body(), envelope.exact_configuration())?;
            let verified =
                verify_ref_state_membership_under(layout, &pinned.body.ref_root, name, oid, proof)
                    .map_err(|refusal| VerifiedReadRefusal::RefLayout(Box::new(refusal)))?;
            if verified {
                Ok(VerifiedMembership::Ref)
            } else {
                Err(VerifiedReadRefusal::ProofRejected)
            }
        }
        VerifiedReadAnswer::OutcomeMembership {
            tx_id,
            outcome,
            proof,
        } => {
            let verified = verify_outcome_index_membership(
                &pinned.body.outcome_index_root,
                *tx_id,
                outcome.as_ref(),
                proof.as_ref(),
            )
            .map_err(|refusal| VerifiedReadRefusal::Outcome(Box::new(refusal)))?;
            if verified {
                Ok(VerifiedMembership::Outcome)
            } else {
                Err(VerifiedReadRefusal::ProofRejected)
            }
        }
        VerifiedReadAnswer::AuthorizedRefAbsence { absence, proof } => {
            let layout = selected_ref_layout(pinned.body(), envelope.exact_configuration())?;
            let verified = verify_ref_state_non_membership_under(
                layout,
                &pinned.body.ref_root,
                absence.name(),
                proof.as_ref(),
            )
            .map_err(|refusal| VerifiedReadRefusal::RefLayout(Box::new(refusal)))?;
            if verified {
                Ok(VerifiedMembership::RefAbsence)
            } else {
                Err(VerifiedReadRefusal::ProofRejected)
            }
        }
    }
}

/// Refuses forge-position proof generation until a canonical forge Merkle
/// layout and its verifier are published.
///
/// # Errors
///
/// Always [`VerifiedReadRefusal::ForgePositionProofUnavailable`]. This is a
/// typed protocol boundary, not a failed membership answer.
pub const fn refuse_forge_position_proof() -> Result<(), VerifiedReadRefusal> {
    Err(VerifiedReadRefusal::ForgePositionProofUnavailable)
}

fn selected_ref_layout(
    pinned: &RepositoryAuthorityHeadBody,
    configuration: Option<&VerifiedReadConfiguration>,
) -> Result<RootLayoutVersion, VerifiedReadRefusal> {
    let Some(configuration) = configuration else {
        return Ok(RootLayoutVersion::LegacyWholeBody);
    };
    let identity = match configuration {
        VerifiedReadConfiguration::RepositoryV1(configuration) => {
            body_id(&CryptoBodyIdentity, configuration)
        }
        VerifiedReadConfiguration::RepositoryIncarnationV2(configuration) => {
            body_id(&CryptoBodyIdentity, configuration)
        }
    }
    .map_err(|_| VerifiedReadRefusal::ConfigurationIdentityUnavailable)?;
    if identity.algorithm() != pinned.configuration_root.algorithm()
        || identity.digest() != pinned.configuration_root.bytes()
    {
        return Err(VerifiedReadRefusal::ConfigurationRootMismatch);
    }
    Ok(configuration.root_layout())
}
