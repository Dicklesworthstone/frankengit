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
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder,
    RepositoryAuthorityHeadBody, RepositoryConfigurationBody, RepositoryDecision,
    RepositoryIncarnationConfigurationBody, body_id, decode_body, encode_body,
};
use fgit_crypto::{
    MerkleProof, MerkleRefusal, ObjectClosureNeighbour, ObjectClosureNonMembershipProof,
    RefStateNeighbour, RefStateNonMembershipProof, verify_object_closure_membership_under,
    verify_object_closure_non_membership_under, verify_ref_state_membership_under,
    verify_ref_state_non_membership_under,
};
use fgit_types::hash::Digest;
use fgit_types::identity::TxId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitOid;
use fgit_types::refs::RefName;
use fgit_types::{DomainTag, SchemaFamily};

/// The sole proof-envelope wire version this build understands.
pub use freshness::{FreshnessRefusal, FreshnessVerdict, HeadChainFloor};

pub const VERIFIED_READ_ENVELOPE_V1: u16 = 1;

/// A canonical, independently frameable Merkle membership proof.
///
/// `MerkleProof` is owned by `fgit-crypto` while [`CanonicalBody`] is owned by
/// `fgit-codec`; Rust's coherence rules deliberately prevent this crate from
/// implementing the foreign trait for the foreign proof type.  This body is
/// the explicit protocol boundary instead: it owns no new proof semantics and
/// converts losslessly to the native verifier input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofBody {
    proof: MerkleProof,
}

impl MerkleProofBody {
    /// Wraps a native proof for canonical transport encoding.
    #[must_use]
    pub const fn new(proof: MerkleProof) -> Self {
        Self { proof }
    }

    /// Borrows the native proof consumed by the verifier.
    #[must_use]
    pub const fn proof(&self) -> &MerkleProof {
        &self.proof
    }

    /// Returns the native proof after transport decoding.
    #[must_use]
    pub fn into_proof(self) -> MerkleProof {
        self.proof
    }
}

/// A canonical, independently frameable ordered ref-state absence proof.
///
/// Like [`MerkleProofBody`], this is a wire owner rather than a second proof
/// implementation.  Its decoded value is exactly the
/// [`RefStateNonMembershipProof`] consumed by the shared Merkle verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefStateNonMembershipProofBody {
    proof: RefStateNonMembershipProof,
}

impl RefStateNonMembershipProofBody {
    /// Wraps a native absence proof for canonical transport encoding.
    #[must_use]
    pub const fn new(proof: RefStateNonMembershipProof) -> Self {
        Self { proof }
    }

    /// Borrows the native proof consumed by the verifier.
    #[must_use]
    pub const fn proof(&self) -> &RefStateNonMembershipProof {
        &self.proof
    }

    /// Returns the native proof after transport decoding.
    #[must_use]
    pub fn into_proof(self) -> RefStateNonMembershipProof {
        self.proof
    }
}

/// A canonical, independently frameable ordered object-closure absence proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectClosureNonMembershipProofBody {
    proof: ObjectClosureNonMembershipProof,
}

impl ObjectClosureNonMembershipProofBody {
    /// Wraps a native absence proof for canonical transport encoding.
    #[must_use]
    pub const fn new(proof: ObjectClosureNonMembershipProof) -> Self {
        Self { proof }
    }

    /// Borrows the native proof consumed by the verifier.
    #[must_use]
    pub const fn proof(&self) -> &ObjectClosureNonMembershipProof {
        &self.proof
    }

    /// Returns the native proof after transport decoding.
    #[must_use]
    pub fn into_proof(self) -> ObjectClosureNonMembershipProof {
        self.proof
    }
}

impl CanonicalBody for MerkleProofBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/verified-read-merkle-proof/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("verified-read-merkle-proof");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_merkle_proof_payload(out, &self.proof)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        read_merkle_proof_payload(input).map(Self::new)
    }
}

impl CanonicalBody for RefStateNonMembershipProofBody {
    const DOMAIN: DomainTag =
        DomainTag::from_static("frankengit/verified-read-ref-non-membership-proof/v1");
    const SCHEMA_FAMILY: SchemaFamily =
        SchemaFamily::from_static("verified-read-ref-non-membership-proof");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_non_membership_proof_payload(out, &self.proof)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        read_non_membership_proof_payload(input).map(Self::new)
    }
}

impl CanonicalBody for ObjectClosureNonMembershipProofBody {
    const DOMAIN: DomainTag =
        DomainTag::from_static("frankengit/verified-read-object-non-membership-proof/v1");
    const SCHEMA_FAMILY: SchemaFamily =
        SchemaFamily::from_static("verified-read-object-non-membership-proof");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_object_non_membership_proof_payload(out, &self.proof)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        read_object_non_membership_proof_payload(input).map(Self::new)
    }
}

/// Encodes a native Merkle proof as its canonical transport frame.
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] when the proof cannot be
/// represented by the canonical codec on this platform.
pub fn encode_merkle_proof(proof: &MerkleProof) -> Result<Vec<u8>, VerifiedReadRefusal> {
    encode_body(&MerkleProofBody::new(proof.clone()))
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

/// Decodes a canonical Merkle-proof transport frame into the native verifier input.
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] for a malformed, non-canonical,
/// or wrong-body frame.
pub fn decode_merkle_proof(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<MerkleProof, VerifiedReadRefusal> {
    decode_body::<MerkleProofBody>(bytes, limits)
        .map(MerkleProofBody::into_proof)
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

/// Encodes an ordered ref-state absence proof as its canonical transport frame.
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] when the proof cannot be
/// represented by the canonical codec on this platform.
pub fn encode_ref_state_non_membership_proof(
    proof: &RefStateNonMembershipProof,
) -> Result<Vec<u8>, VerifiedReadRefusal> {
    encode_body(&RefStateNonMembershipProofBody::new(proof.clone()))
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

/// Decodes an ordered ref-state absence proof into the native verifier input.
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] for a malformed, non-canonical,
/// or wrong-body frame.
pub fn decode_ref_state_non_membership_proof(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<RefStateNonMembershipProof, VerifiedReadRefusal> {
    decode_body::<RefStateNonMembershipProofBody>(bytes, limits)
        .map(RefStateNonMembershipProofBody::into_proof)
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

/// Encodes an ordered object-closure absence proof as its canonical transport frame.
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] when the proof cannot be
/// represented by the canonical codec on this platform.
pub fn encode_object_closure_non_membership_proof(
    proof: &ObjectClosureNonMembershipProof,
) -> Result<Vec<u8>, VerifiedReadRefusal> {
    encode_body(&ObjectClosureNonMembershipProofBody::new(proof.clone()))
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

/// Decodes an ordered object-closure absence proof into the native verifier input.
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] for a malformed, non-canonical,
/// or wrong-body frame.
pub fn decode_object_closure_non_membership_proof(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<ObjectClosureNonMembershipProof, VerifiedReadRefusal> {
    decode_body::<ObjectClosureNonMembershipProofBody>(bytes, limits)
        .map(ObjectClosureNonMembershipProofBody::into_proof)
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

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
    object_closure_root: Option<Digest>,
}

impl PinnedAuthorityHead {
    /// Pins the exact authority-head body against which subsequent responses
    /// are checked.
    #[must_use]
    pub const fn new(body: RepositoryAuthorityHeadBody) -> Self {
        Self {
            body,
            object_closure_root: None,
        }
    }

    /// Pins the exact authority-head body and object closure root against which
    /// subsequent responses are checked.
    #[must_use]
    pub const fn new_with_object_closure(
        body: RepositoryAuthorityHeadBody,
        object_closure_root: Digest,
    ) -> Self {
        Self {
            body,
            object_closure_root: Some(object_closure_root),
        }
    }

    /// The exact pinned head body.
    #[must_use]
    pub const fn body(&self) -> &RepositoryAuthorityHeadBody {
        &self.body
    }

    /// The pinned object closure root, if configured.
    #[must_use]
    pub const fn object_closure_root(&self) -> Option<&Digest> {
        self.object_closure_root.as_ref()
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
    /// An object answer.
    Object {
        /// Object identity queried by the client.
        oid: GitOid,
        /// Whether the object is present in the closure.
        present: bool,
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

/// An authorization policy for object disclosure at the read-serving boundary.
pub trait ObjectDisclosurePolicy {
    /// Whether `oid` is within the caller's authorized disclosure scope.
    fn permits_object_disclosure(&self, oid: &GitOid) -> bool;
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

/// An object absence that was looked up only after authorization allowed disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedObjectAbsence {
    oid: GitOid,
}

impl AuthorizedObjectAbsence {
    /// The object identity whose authorized lookup found no object.
    #[must_use]
    pub const fn oid(&self) -> &GitOid {
        &self.oid
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

/// Applies authorization before looking up a possible object absence.
///
/// A denied caller receives exactly [`VerifiedReadRefusal::ObjectNotFoundOrUnauthorized`]
/// regardless of whether `lookup` would have found an object. The closure is not called
/// in that branch, preventing existence probing.
///
/// # Errors
///
/// [`VerifiedReadRefusal::ObjectNotFoundOrUnauthorized`] when disclosure is not
/// authorized, and [`VerifiedReadRefusal::ObjectPresent`] when the authorized
/// lookup found the requested object.
pub fn authorize_object_absence<P, L>(
    policy: &P,
    oid: GitOid,
    lookup: L,
) -> Result<AuthorizedObjectAbsence, VerifiedReadRefusal>
where
    P: ObjectDisclosurePolicy + ?Sized,
    L: FnOnce(&GitOid) -> bool,
{
    if !policy.permits_object_disclosure(&oid) {
        return Err(VerifiedReadRefusal::ObjectNotFoundOrUnauthorized);
    }
    if lookup(&oid) {
        return Err(VerifiedReadRefusal::ObjectPresent);
    }
    Ok(AuthorizedObjectAbsence { oid })
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
    /// An object identity and the membership path under the object closure root.
    ObjectMembership {
        /// Object identity claimed by the serving cell.
        oid: GitOid,
        /// Merkle path generated from the canonical object-closure layout.
        proof: Box<MerkleProof>,
    },
    /// An authorization-gated object absence and its ordered V1 Merkle witness.
    AuthorizedObjectAbsence {
        /// The object identity whose absence was authorized for disclosure.
        absence: AuthorizedObjectAbsence,
        /// Ordered neighbour evidence for that absence.
        proof: Box<ObjectClosureNonMembershipProof>,
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
        let configuration = configuration.map(VerifiedReadConfiguration::RepositoryV1);
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

impl CanonicalBody for VerifiedReadEnvelope {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/verified-read-envelope/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("verified-read-envelope");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.version != VERIFIED_READ_ENVELOPE_V1 {
            return Err(CodecRefusal::VariantUnknown {
                field: "VerifiedReadEnvelope.version",
                observed: u32::from(self.version),
                offset: out.len().try_into().unwrap_or(u64::MAX),
            });
        }
        out.write_scalar(self.version);
        self.head.write_payload(out)?;
        write_configuration(out, self.configuration.as_ref())?;
        write_answer(out, &self.answer)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let version = input.read_scalar::<u16>("verified_read_envelope.version")?;
        let head = RepositoryAuthorityHeadBody::read_payload(input)?;
        let configuration = read_configuration(input)?;
        let answer = read_answer(input)?;
        Ok(Self {
            version,
            head,
            configuration,
            answer,
        })
    }
}

/// Encodes one version-one verified-read envelope for an untrusted relay.
///
/// The returned bytes are self-describing canonical codec bytes.  They do not
/// grant the relay authority: a client still verifies the decoded envelope
/// against its independently pinned head with [`verify_envelope`].
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::WireDecode`] if a field cannot be represented
/// by the canonical codec.
pub fn encode_verified_read_envelope(
    envelope: &VerifiedReadEnvelope,
) -> Result<Vec<u8>, VerifiedReadRefusal> {
    encode_body(envelope).map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))
}

/// Decodes one relayed envelope without trusting the relay's chosen head.
///
/// Decoding checks canonical framing and field syntax.  It does not establish
/// membership or currentness; callers must pass the result to
/// [`verify_envelope`] with their independently authenticated
/// [`PinnedAuthorityHead`].
///
/// # Errors
///
/// Returns [`VerifiedReadRefusal::UnsupportedEnvelopeVersion`] for a wire
/// version this verifier does not understand, and
/// [`VerifiedReadRefusal::WireDecode`] for hostile or malformed codec bytes.
pub fn decode_verified_read_envelope(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<VerifiedReadEnvelope, VerifiedReadRefusal> {
    let envelope = decode_body::<VerifiedReadEnvelope>(bytes, limits)
        .map_err(|refusal| VerifiedReadRefusal::WireDecode(Box::new(refusal)))?;
    if envelope.version != VERIFIED_READ_ENVELOPE_V1 {
        return Err(VerifiedReadRefusal::UnsupportedEnvelopeVersion {
            observed: envelope.version,
        });
    }
    Ok(envelope)
}

fn write_merkle_proof_payload(out: &mut Encoder, proof: &MerkleProof) -> Result<(), CodecRefusal> {
    out.write_scalar(usize_to_u64("merkle_proof.index", proof.index())?);
    out.write_scalar(usize_to_u64("merkle_proof.leaf_count", proof.leaf_count())?);
    out.write_sequence("merkle_proof.siblings", proof.siblings(), |out, sibling| {
        out.write_digest_bytes(sibling)
    })
}

fn read_merkle_proof_payload(input: &mut Decoder<'_>) -> Result<MerkleProof, CodecRefusal> {
    let index = u64_to_usize(
        "merkle_proof.index",
        input.read_scalar::<u64>("merkle_proof.index")?,
    )?;
    let leaf_count = u64_to_usize(
        "merkle_proof.leaf_count",
        input.read_scalar::<u64>("merkle_proof.leaf_count")?,
    )?;
    let siblings = input.read_sequence("merkle_proof.siblings", Decoder::read_digest_bytes)?;
    Ok(MerkleProof::new(index, leaf_count, siblings))
}

fn write_ref_state_neighbour(
    out: &mut Encoder,
    neighbour: &RefStateNeighbour,
) -> Result<(), CodecRefusal> {
    out.write_ref_name(neighbour.name())?;
    out.write_git_oid(neighbour.oid());
    write_merkle_proof_payload(out, neighbour.proof())
}

fn read_ref_state_neighbour(input: &mut Decoder<'_>) -> Result<RefStateNeighbour, CodecRefusal> {
    let name = input.read_ref_name()?;
    let oid = input.read_git_oid()?;
    let proof = read_merkle_proof_payload(input)?;
    Ok(RefStateNeighbour::new(name, oid, proof))
}

fn write_non_membership_proof_payload(
    out: &mut Encoder,
    proof: &RefStateNonMembershipProof,
) -> Result<(), CodecRefusal> {
    match proof {
        RefStateNonMembershipProof::EmptyState => out.write_raw_byte(0),
        RefStateNonMembershipProof::BeforeFirst { first } => {
            out.write_raw_byte(1);
            write_ref_state_neighbour(out, first)?;
        }
        RefStateNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            out.write_raw_byte(2);
            write_ref_state_neighbour(out, predecessor)?;
            write_ref_state_neighbour(out, successor)?;
        }
        RefStateNonMembershipProof::AfterLast { last } => {
            out.write_raw_byte(3);
            write_ref_state_neighbour(out, last)?;
        }
    }
    Ok(())
}

fn read_non_membership_proof_payload(
    input: &mut Decoder<'_>,
) -> Result<RefStateNonMembershipProof, CodecRefusal> {
    let offset = input.offset();
    match input.read_raw_byte("ref_state_non_membership_proof.variant")? {
        0 => Ok(RefStateNonMembershipProof::EmptyState),
        1 => Ok(RefStateNonMembershipProof::BeforeFirst {
            first: Box::new(read_ref_state_neighbour(input)?),
        }),
        2 => Ok(RefStateNonMembershipProof::Between {
            predecessor: Box::new(read_ref_state_neighbour(input)?),
            successor: Box::new(read_ref_state_neighbour(input)?),
        }),
        3 => Ok(RefStateNonMembershipProof::AfterLast {
            last: Box::new(read_ref_state_neighbour(input)?),
        }),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "RefStateNonMembershipProof",
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn write_object_closure_neighbour(
    out: &mut Encoder,
    neighbour: &ObjectClosureNeighbour,
) -> Result<(), CodecRefusal> {
    out.write_git_oid(neighbour.oid());
    write_merkle_proof_payload(out, neighbour.proof())
}

fn read_object_closure_neighbour(
    input: &mut Decoder<'_>,
) -> Result<ObjectClosureNeighbour, CodecRefusal> {
    let oid = input.read_git_oid()?;
    let proof = read_merkle_proof_payload(input)?;
    Ok(ObjectClosureNeighbour::new(oid, proof))
}

fn write_object_non_membership_proof_payload(
    out: &mut Encoder,
    proof: &ObjectClosureNonMembershipProof,
) -> Result<(), CodecRefusal> {
    match proof {
        ObjectClosureNonMembershipProof::EmptyClosure => out.write_raw_byte(0),
        ObjectClosureNonMembershipProof::BeforeFirst { first } => {
            out.write_raw_byte(1);
            write_object_closure_neighbour(out, first)?;
        }
        ObjectClosureNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            out.write_raw_byte(2);
            write_object_closure_neighbour(out, predecessor)?;
            write_object_closure_neighbour(out, successor)?;
        }
        ObjectClosureNonMembershipProof::AfterLast { last } => {
            out.write_raw_byte(3);
            write_object_closure_neighbour(out, last)?;
        }
    }
    Ok(())
}

fn read_object_non_membership_proof_payload(
    input: &mut Decoder<'_>,
) -> Result<ObjectClosureNonMembershipProof, CodecRefusal> {
    let offset = input.offset();
    match input.read_raw_byte("object_closure_non_membership_proof.variant")? {
        0 => Ok(ObjectClosureNonMembershipProof::EmptyClosure),
        1 => Ok(ObjectClosureNonMembershipProof::BeforeFirst {
            first: Box::new(read_object_closure_neighbour(input)?),
        }),
        2 => Ok(ObjectClosureNonMembershipProof::Between {
            predecessor: Box::new(read_object_closure_neighbour(input)?),
            successor: Box::new(read_object_closure_neighbour(input)?),
        }),
        3 => Ok(ObjectClosureNonMembershipProof::AfterLast {
            last: Box::new(read_object_closure_neighbour(input)?),
        }),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "ObjectClosureNonMembershipProof",
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn write_configuration(
    out: &mut Encoder,
    configuration: Option<&VerifiedReadConfiguration>,
) -> Result<(), CodecRefusal> {
    out.write_option(configuration, |out, configuration| match configuration {
        VerifiedReadConfiguration::RepositoryV1(configuration) => {
            out.write_raw_byte(1);
            configuration.write_payload(out)
        }
        VerifiedReadConfiguration::RepositoryIncarnationV2(configuration) => {
            out.write_raw_byte(2);
            configuration.write_payload(out)
        }
    })
}

fn read_configuration(
    input: &mut Decoder<'_>,
) -> Result<Option<VerifiedReadConfiguration>, CodecRefusal> {
    input.read_option("verified_read_envelope.configuration", |input| {
        let offset = input.offset();
        match input.read_raw_byte("verified_read_envelope.configuration.variant")? {
            1 => RepositoryConfigurationBody::read_payload(input)
                .map(VerifiedReadConfiguration::RepositoryV1),
            2 => RepositoryIncarnationConfigurationBody::read_payload(input)
                .map(VerifiedReadConfiguration::RepositoryIncarnationV2),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "VerifiedReadConfiguration",
                observed: u32::from(observed),
                offset,
            }),
        }
    })
}

fn write_answer(out: &mut Encoder, answer: &VerifiedReadAnswer) -> Result<(), CodecRefusal> {
    match answer {
        VerifiedReadAnswer::RefMembership { name, oid, proof } => {
            out.write_raw_byte(1);
            out.write_ref_name(name)?;
            out.write_git_oid(oid);
            write_merkle_proof_payload(out, proof)
        }
        VerifiedReadAnswer::OutcomeMembership {
            tx_id,
            outcome,
            proof,
        } => {
            out.write_raw_byte(2);
            RepositoryDecision::write_canonical(
                out,
                &RepositoryDecision {
                    tx_id: *tx_id,
                    decision_sequence: outcome.decision_sequence,
                    outcome: outcome.outcome,
                },
            )?;
            write_merkle_proof_payload(out, proof)
        }
        VerifiedReadAnswer::AuthorizedRefAbsence { absence, proof } => {
            out.write_raw_byte(3);
            out.write_ref_name(absence.name())?;
            write_non_membership_proof_payload(out, proof)
        }
        VerifiedReadAnswer::ObjectMembership { oid, proof } => {
            out.write_raw_byte(4);
            out.write_git_oid(oid);
            write_merkle_proof_payload(out, proof)
        }
        VerifiedReadAnswer::AuthorizedObjectAbsence { absence, proof } => {
            out.write_raw_byte(5);
            out.write_git_oid(absence.oid());
            write_object_non_membership_proof_payload(out, proof)
        }
    }
}

fn read_answer(input: &mut Decoder<'_>) -> Result<VerifiedReadAnswer, CodecRefusal> {
    let offset = input.offset();
    match input.read_raw_byte("verified_read_envelope.answer.variant")? {
        1 => Ok(VerifiedReadAnswer::RefMembership {
            name: input.read_ref_name()?,
            oid: input.read_git_oid()?,
            proof: Box::new(read_merkle_proof_payload(input)?),
        }),
        2 => {
            let decision = RepositoryDecision::read_canonical(input)?;
            Ok(VerifiedReadAnswer::OutcomeMembership {
                tx_id: decision.tx_id,
                outcome: Box::new(TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                }),
                proof: Box::new(read_merkle_proof_payload(input)?),
            })
        }
        3 => Ok(VerifiedReadAnswer::AuthorizedRefAbsence {
            absence: AuthorizedRefAbsence {
                name: input.read_ref_name()?,
            },
            proof: Box::new(read_non_membership_proof_payload(input)?),
        }),
        4 => Ok(VerifiedReadAnswer::ObjectMembership {
            oid: input.read_git_oid()?,
            proof: Box::new(read_merkle_proof_payload(input)?),
        }),
        5 => Ok(VerifiedReadAnswer::AuthorizedObjectAbsence {
            absence: AuthorizedObjectAbsence {
                oid: input.read_git_oid()?,
            },
            proof: Box::new(read_object_non_membership_proof_payload(input)?),
        }),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "VerifiedReadAnswer",
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn usize_to_u64(field: &'static str, value: usize) -> Result<u64, CodecRefusal> {
    u64::try_from(value).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::MAX,
        limit: u64::MAX,
    })
}

fn u64_to_usize(field: &'static str, value: u64) -> Result<usize, CodecRefusal> {
    usize::try_from(value).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: value,
        limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
    })
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
    /// An object membership proof verified against the pinned object closure root.
    Object,
    /// An authorization-gated object non-membership proof verified against the
    /// pinned object closure root.
    ObjectAbsence,
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
    /// The canonical wire body was truncated, non-canonical, or otherwise
    /// refused before a proof could be considered.
    WireDecode(Box<CodecRefusal>),
    /// The selected layout does not admit a ref-state membership proof.
    RefLayout(Box<MerkleRefusal>),
    /// The selected layout does not admit an object closure membership proof.
    ObjectLayout(Box<MerkleRefusal>),
    /// The client pinned head does not carry an object closure root.
    ObjectClosureRootUnavailable,
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
    /// Disclosure was denied before consulting the requested object's existence.
    ObjectNotFoundOrUnauthorized,
    /// The caller was allowed to disclose the object, but the lookup found it.
    ObjectPresent,
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
            Self::WireDecode(refusal) => write!(formatter, "verified-read wire decode refused: {refusal}"),
            Self::RefLayout(refusal) => write!(formatter, "ref proof layout refused: {refusal}"),
            Self::ObjectLayout(refusal) => write!(formatter, "object proof layout refused: {refusal}"),
            Self::ObjectClosureRootUnavailable => formatter.write_str("the pinned head carries no object closure root"),
            Self::ProofRejected => {
                formatter.write_str("the claimed Merkle path does not verify against the pinned root")
            }
            Self::Outcome(refusal) => write!(formatter, "outcome proof refused: {refusal}"),
            Self::RefNotFoundOrUnauthorized => formatter.write_str("ref not found"),
            Self::RefPresent => formatter.write_str("ref is present after authorized lookup"),
            Self::ObjectNotFoundOrUnauthorized => formatter.write_str("object not found"),
            Self::ObjectPresent => formatter.write_str("object is present after authorized lookup"),
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
        VerifiedReadAnswer::ObjectMembership { oid, proof } => {
            let layout = selected_ref_layout(pinned.body(), envelope.exact_configuration())?;
            let root = pinned
                .object_closure_root()
                .ok_or(VerifiedReadRefusal::ObjectClosureRootUnavailable)?;
            let verified = verify_object_closure_membership_under(layout, root, oid, proof)
                .map_err(|refusal| VerifiedReadRefusal::ObjectLayout(Box::new(refusal)))?;
            if verified {
                Ok(VerifiedMembership::Object)
            } else {
                Err(VerifiedReadRefusal::ProofRejected)
            }
        }
        VerifiedReadAnswer::AuthorizedObjectAbsence { absence, proof } => {
            let layout = selected_ref_layout(pinned.body(), envelope.exact_configuration())?;
            let root = pinned
                .object_closure_root()
                .ok_or(VerifiedReadRefusal::ObjectClosureRootUnavailable)?;
            let verified = verify_object_closure_non_membership_under(
                layout,
                root,
                absence.oid(),
                proof.as_ref(),
            )
            .map_err(|refusal| VerifiedReadRefusal::ObjectLayout(Box::new(refusal)))?;
            if verified {
                Ok(VerifiedMembership::ObjectAbsence)
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
