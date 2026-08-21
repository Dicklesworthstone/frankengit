#![forbid(unsafe_code)]
//! Immutable, canonically framed evidence records.
//!
//! An [`EvidenceRecord`] binds a claim and all of the context needed to
//! interpret its evidence: inputs, implementation and toolchain, selection,
//! window, regime, assumptions, verifier, artifacts, fallback, and replay
//! completeness. The record is immutable: changing any field produces a new
//! canonical frame and therefore a new [`EvidenceRecordId`]. A newer record
//! may name the prior record it supersedes, but neither record is edited.
//!
//! The crate deliberately does not own a digest preimage or body framing.
//! [`fgit_codec`] owns the canonical body/frame layout and its bridge calls the
//! registered [`fgit_crypto`] identity authority. This crate calls that bridge
//! to identify frames and the crypto verifier to check an attached identity.

use core::fmt;

use fgit_claim::{ClaimRank, ClaimRefusal, ClaimText};
use fgit_codec::{
    CODEC_VERSION, CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder,
    body_id, body_id_of_frame_as, canonical_body_bytes, decode_body, encode_body,
};
use fgit_crypto::{
    Digest, DomainTag, IdentityDomain, InternalIdentityError, SchemaFamily,
    verify_internal_object_id,
};
use fgit_types::EvidenceRecordId;

/// Largest canonical evidence-text field, in bytes.
pub const MAX_EVIDENCE_TEXT_BYTES: usize = 1024;
/// Largest collection carried by one evidence record.
pub const MAX_EVIDENCE_ITEMS: usize = 1024;

/// Bounded canonical text used by evidence context fields.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceText(String);

impl EvidenceText {
    /// Parses bounded printable-ASCII evidence text.
    pub fn parse(field: &'static str, value: &str) -> Result<Self, EvidenceRefusal> {
        if value.is_empty() {
            return Err(EvidenceRefusal::InvalidText {
                field,
                reason: "must not be empty",
            });
        }
        if value.len() > MAX_EVIDENCE_TEXT_BYTES {
            return Err(EvidenceRefusal::InvalidText {
                field,
                reason: "exceeds the bounded canonical length",
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(EvidenceRefusal::InvalidText {
                field,
                reason: "must contain only printable ASCII without whitespace",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The canonical evidence text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn decoded(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for EvidenceText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Replay completeness declared by an evidence record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReplayCompleteness {
    /// All deterministic inputs, schedule, and toolchain artifacts are present.
    Replayable,
    /// Structure is available but some supplied artifacts are not replayable here.
    Structural,
    /// Verification succeeds only when named external artifacts are supplied.
    VerifiableIfSupplied,
    /// The record supports human audit but not deterministic replay.
    AuditOnly,
}

impl ReplayCompleteness {
    fn code(self) -> u8 {
        match self {
            Self::Replayable => 0,
            Self::Structural => 1,
            Self::VerifiableIfSupplied => 2,
            Self::AuditOnly => 3,
        }
    }

    fn from_code(code: u8, offset: u64) -> Result<Self, CodecRefusal> {
        match code {
            0 => Ok(Self::Replayable),
            1 => Ok(Self::Structural),
            2 => Ok(Self::VerifiableIfSupplied),
            3 => Ok(Self::AuditOnly),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "replay_completeness",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// One artifact commitment needed to interpret an evidence record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceArtifact {
    location: EvidenceText,
    commitment: Digest,
}

impl EvidenceArtifact {
    /// Constructs one named artifact commitment.
    #[must_use]
    pub fn new(location: EvidenceText, commitment: Digest) -> Self {
        Self {
            location,
            commitment,
        }
    }

    /// Canonical artifact location.
    #[must_use]
    pub const fn location(&self) -> &EvidenceText {
        &self.location
    }

    /// Algorithm-tagged commitment over the artifact.
    #[must_use]
    pub const fn commitment(&self) -> &Digest {
        &self.commitment
    }
}

/// The interpretation context permanently bound into an evidence record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceContext {
    source_inputs: Vec<EvidenceText>,
    implementation: EvidenceText,
    toolchain: EvidenceText,
    selection_strata: EvidenceText,
    exact_window: EvidenceText,
    policy_regime: EvidenceText,
    assumptions: Vec<EvidenceText>,
    verifier_class: EvidenceText,
    artifacts: Vec<EvidenceArtifact>,
    deterministic_fallback: EvidenceText,
    replay_completeness: ReplayCompleteness,
    supersedes: Option<EvidenceRecordId>,
}

impl EvidenceContext {
    /// Constructs the complete interpretation context for one observation.
    pub fn new(
        source_inputs: Vec<EvidenceText>,
        implementation: EvidenceText,
        toolchain: EvidenceText,
        selection_strata: EvidenceText,
        exact_window: EvidenceText,
        policy_regime: EvidenceText,
        assumptions: Vec<EvidenceText>,
        verifier_class: EvidenceText,
        artifacts: Vec<EvidenceArtifact>,
        deterministic_fallback: EvidenceText,
        replay_completeness: ReplayCompleteness,
        supersedes: Option<EvidenceRecordId>,
    ) -> Result<Self, EvidenceRefusal> {
        let context = Self {
            source_inputs,
            implementation,
            toolchain,
            selection_strata,
            exact_window,
            policy_regime,
            assumptions,
            verifier_class,
            artifacts,
            deterministic_fallback,
            replay_completeness,
            supersedes,
        };
        context.validate()?;
        Ok(context)
    }

    /// Exact source inputs, canonically encoded as a set.
    #[must_use]
    pub fn source_inputs(&self) -> &[EvidenceText] {
        &self.source_inputs
    }

    /// Implementation fingerprint or revision.
    #[must_use]
    pub const fn implementation(&self) -> &EvidenceText {
        &self.implementation
    }

    /// Toolchain fingerprint.
    #[must_use]
    pub const fn toolchain(&self) -> &EvidenceText {
        &self.toolchain
    }

    /// Selection population or strata identifier.
    #[must_use]
    pub const fn selection_strata(&self) -> &EvidenceText {
        &self.selection_strata
    }

    /// Exact sequence/time window identifier.
    #[must_use]
    pub const fn exact_window(&self) -> &EvidenceText {
        &self.exact_window
    }

    /// Policy or operational regime identifier.
    #[must_use]
    pub const fn policy_regime(&self) -> &EvidenceText {
        &self.policy_regime
    }

    /// Explicit assumptions, canonically encoded as a set.
    #[must_use]
    pub fn assumptions(&self) -> &[EvidenceText] {
        &self.assumptions
    }

    /// Verifier independence/class identifier.
    #[must_use]
    pub const fn verifier_class(&self) -> &EvidenceText {
        &self.verifier_class
    }

    /// Artifact commitments, canonically encoded as a set.
    #[must_use]
    pub fn artifacts(&self) -> &[EvidenceArtifact] {
        &self.artifacts
    }

    /// Deterministic fallback selected outside the observed regime.
    #[must_use]
    pub const fn deterministic_fallback(&self) -> &EvidenceText {
        &self.deterministic_fallback
    }

    /// Declared replay completeness.
    #[must_use]
    pub const fn replay_completeness(&self) -> ReplayCompleteness {
        self.replay_completeness
    }

    /// The older record this record supersedes, when it is a new observation.
    #[must_use]
    pub const fn supersedes(&self) -> Option<EvidenceRecordId> {
        self.supersedes
    }

    fn validate(&self) -> Result<(), EvidenceRefusal> {
        validate_text("implementation", &self.implementation)?;
        validate_text("toolchain", &self.toolchain)?;
        validate_text("selection_strata", &self.selection_strata)?;
        validate_text("exact_window", &self.exact_window)?;
        validate_text("policy_regime", &self.policy_regime)?;
        validate_text("verifier_class", &self.verifier_class)?;
        validate_text("deterministic_fallback", &self.deterministic_fallback)?;
        validate_collection("source_inputs", &self.source_inputs, true)?;
        validate_collection("assumptions", &self.assumptions, true)?;
        validate_collection("artifacts", &self.artifacts, true)
    }
}

/// Canonical evidence body before it is framed and identity-bound.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceRecordBody {
    claim_id: EvidenceText,
    claim_scope: EvidenceText,
    claim_rank: ClaimRank,
    evidence_rank: ClaimRank,
    context: EvidenceContext,
}

impl EvidenceRecordBody {
    /// Constructs a complete evidence body, refusing an inadmissible claim edge.
    pub fn new(
        claim_id: EvidenceText,
        claim_scope: EvidenceText,
        claim_rank: ClaimRank,
        evidence_rank: ClaimRank,
        context: EvidenceContext,
    ) -> Result<Self, EvidenceRefusal> {
        let body = Self {
            claim_id,
            claim_scope,
            claim_rank,
            evidence_rank,
            context,
        };
        body.validate()?;
        Ok(body)
    }

    /// Canonical claim identifier.
    #[must_use]
    pub const fn claim_id(&self) -> &EvidenceText {
        &self.claim_id
    }

    /// Canonical claim scope.
    #[must_use]
    pub const fn claim_scope(&self) -> &EvidenceText {
        &self.claim_scope
    }

    /// Strength of the claim this record supports.
    #[must_use]
    pub const fn claim_rank(&self) -> ClaimRank {
        self.claim_rank
    }

    /// Strength class of the evidence carried by this record.
    #[must_use]
    pub const fn evidence_rank(&self) -> ClaimRank {
        self.evidence_rank
    }

    /// Complete, immutable interpretation context.
    #[must_use]
    pub const fn context(&self) -> &EvidenceContext {
        &self.context
    }

    fn validate(&self) -> Result<(), EvidenceRefusal> {
        ClaimText::parse("claim_id", self.claim_id.as_str())?;
        ClaimText::parse("claim_scope", self.claim_scope.as_str())?;
        validate_text("claim_id", &self.claim_id)?;
        validate_text("claim_scope", &self.claim_scope)?;
        if !self.evidence_rank.justifies(self.claim_rank) {
            return Err(EvidenceRefusal::Claim(ClaimRefusal::EvidenceTooWeak {
                claim: self.claim_rank,
                evidence: self.evidence_rank,
            }));
        }
        self.context.validate()
    }
}

impl CanonicalBody for EvidenceRecordBody {
    const DOMAIN: DomainTag = DomainTag::from_static(EvidenceRecordId::DOMAIN);
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("evidence-record");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_text("claim_id", self.claim_id.as_str())?;
        out.write_text("claim_scope", self.claim_scope.as_str())?;
        out.write_raw_byte(claim_rank_code(self.claim_rank));
        out.write_raw_byte(claim_rank_code(self.evidence_rank));
        out.write_canonical_set(
            "source_inputs",
            &self.context.source_inputs,
            |out, value| out.write_text("source_input", value.as_str()),
        )?;
        for (field, value) in [
            ("implementation", &self.context.implementation),
            ("toolchain", &self.context.toolchain),
            ("selection_strata", &self.context.selection_strata),
            ("exact_window", &self.context.exact_window),
            ("policy_regime", &self.context.policy_regime),
        ] {
            out.write_text(field, value.as_str())?;
        }
        out.write_canonical_set("assumptions", &self.context.assumptions, |out, value| {
            out.write_text("assumption", value.as_str())
        })?;
        out.write_text("verifier_class", self.context.verifier_class.as_str())?;
        out.write_canonical_set("artifacts", &self.context.artifacts, |out, artifact| {
            out.write_text("artifact_location", artifact.location.as_str())?;
            out.write_digest(&artifact.commitment)
        })?;
        out.write_text(
            "deterministic_fallback",
            self.context.deterministic_fallback.as_str(),
        )?;
        out.write_raw_byte(self.context.replay_completeness.code());
        out.write_option(self.context.supersedes.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let claim_id = read_evidence_text(input, "claim_id")?;
        let claim_scope = read_evidence_text(input, "claim_scope")?;
        let claim_rank = read_claim_rank(input, "claim_rank")?;
        let evidence_rank = read_claim_rank(input, "evidence_rank")?;
        let source_inputs = input.read_canonical_set("source_inputs", |input| {
            read_evidence_text(input, "source_input")
        })?;
        let implementation = read_evidence_text(input, "implementation")?;
        let toolchain = read_evidence_text(input, "toolchain")?;
        let selection_strata = read_evidence_text(input, "selection_strata")?;
        let exact_window = read_evidence_text(input, "exact_window")?;
        let policy_regime = read_evidence_text(input, "policy_regime")?;
        let assumptions = input.read_canonical_set("assumptions", |input| {
            read_evidence_text(input, "assumption")
        })?;
        let verifier_class = read_evidence_text(input, "verifier_class")?;
        let artifacts = input.read_canonical_set("artifacts", |input| {
            Ok(EvidenceArtifact {
                location: read_evidence_text(input, "artifact_location")?,
                commitment: input.read_digest()?,
            })
        })?;
        let deterministic_fallback = read_evidence_text(input, "deterministic_fallback")?;
        let replay_offset = input.offset();
        let replay_completeness = ReplayCompleteness::from_code(
            input.read_raw_byte("replay_completeness")?,
            replay_offset,
        )?;
        let supersedes = input.read_option("supersedes", |input| {
            EvidenceRecordId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        Ok(Self {
            claim_id,
            claim_scope,
            claim_rank,
            evidence_rank,
            context: EvidenceContext {
                source_inputs,
                implementation,
                toolchain,
                selection_strata,
                exact_window,
                policy_regime,
                assumptions,
                verifier_class,
                artifacts,
                deterministic_fallback,
                replay_completeness,
                supersedes,
            },
        })
    }
}

/// An immutable, identity-bound canonical evidence envelope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceRecord {
    id: EvidenceRecordId,
    body: EvidenceRecordBody,
    frame: Vec<u8>,
}

impl EvidenceRecord {
    /// Frames and identity-binds a complete evidence body.
    pub fn new(body: EvidenceRecordBody) -> Result<Self, EvidenceRefusal> {
        body.validate()?;
        let frame = encode_body(&body)?;
        let id = identify(&body)?;
        if body.context.supersedes == Some(id) {
            return Err(EvidenceRefusal::SelfSupersession);
        }
        Ok(Self { id, body, frame })
    }

    /// Decodes and verifies a framed record against its attached identity.
    pub fn decode(
        id: EvidenceRecordId,
        frame: &[u8],
        limits: DecodeLimits,
    ) -> Result<Self, EvidenceRefusal> {
        let body = decode_body::<EvidenceRecordBody>(frame, limits)?;
        body.validate()?;
        let canonical_frame = encode_body(&body)?;
        if canonical_frame != frame {
            return Err(EvidenceRefusal::FrameNotCanonical);
        }
        let record = Self {
            id,
            body,
            frame: frame.to_vec(),
        };
        record.verify(limits)?;
        Ok(record)
    }

    /// Registered, domain-pinned identity of this immutable record.
    #[must_use]
    pub const fn id(&self) -> EvidenceRecordId {
        self.id
    }

    /// The complete canonical body.
    #[must_use]
    pub const fn body(&self) -> &EvidenceRecordBody {
        &self.body
    }

    /// Canonical codec frame, suitable for immutable storage or replay.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Rechecks body validity, canonical framing, and crypto identity binding.
    pub fn verify(&self, limits: DecodeLimits) -> Result<(), EvidenceRefusal> {
        self.body.validate()?;
        if encode_body(&self.body)? != self.frame {
            return Err(EvidenceRefusal::FrameNotCanonical);
        }
        let frame_identity =
            body_id_of_frame_as::<EvidenceRecordBody, _>(&CryptoBodyIdentity, &self.frame, limits)?;
        let frame_id =
            EvidenceRecordId::from_internal_object_id(frame_identity).map_err(|error| {
                EvidenceRefusal::TypedIdentity {
                    detail: error.to_string(),
                }
            })?;
        if frame_id != self.id {
            return Err(EvidenceRefusal::IdentityMismatch {
                expected: self.id,
                observed: frame_id,
            });
        }
        let recomputed = identify(&self.body)?;
        if recomputed != self.id {
            return Err(EvidenceRefusal::IdentityMismatch {
                expected: self.id,
                observed: recomputed,
            });
        }
        if self.body.context.supersedes == Some(self.id) {
            return Err(EvidenceRefusal::SelfSupersession);
        }
        Ok(())
    }
}

/// Why an evidence record was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceRefusal {
    /// A field was absent, oversized, or not canonical evidence text.
    InvalidText {
        /// Field that was refused.
        field: &'static str,
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    /// A required collection was empty, too large, or had duplicate values.
    Collection {
        /// Collection field that was refused.
        field: &'static str,
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    /// Claim-lattice admission refused the evidence rank.
    Claim(ClaimRefusal),
    /// Canonical framing or decoding refused the record.
    Codec(CodecRefusal),
    /// The crypto identity authority rejected the body commitment.
    Identity(InternalIdentityError),
    /// An internal identity could not be adopted as an evidence-record identity.
    TypedIdentity {
        /// Domain/type refusal rendered by the typed identity shell.
        detail: String,
    },
    /// The supplied identity commits to different body bytes.
    IdentityMismatch {
        /// Attached identity.
        expected: EvidenceRecordId,
        /// Identity recomputed through the registered authority.
        observed: EvidenceRecordId,
    },
    /// A strict decoder accepted bytes that did not re-encode identically.
    FrameNotCanonical,
    /// A record cannot supersede its own identity.
    SelfSupersession,
}

impl fmt::Display for EvidenceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::Collection { field, reason } => {
                write!(formatter, "invalid {field} collection: {reason}")
            }
            Self::Claim(error) => fmt::Display::fmt(error, formatter),
            Self::Codec(error) => fmt::Display::fmt(error, formatter),
            Self::Identity(error) => fmt::Display::fmt(error, formatter),
            Self::TypedIdentity { detail } => {
                write!(
                    formatter,
                    "evidence record identity has the wrong domain: {detail}"
                )
            }
            Self::IdentityMismatch { expected, observed } => write!(
                formatter,
                "evidence record identity mismatch: expected {expected}, observed {observed}"
            ),
            Self::FrameNotCanonical => formatter.write_str("evidence frame is not canonical"),
            Self::SelfSupersession => {
                formatter.write_str("evidence record cannot supersede itself")
            }
        }
    }
}

impl std::error::Error for EvidenceRefusal {}

impl From<ClaimRefusal> for EvidenceRefusal {
    fn from(error: ClaimRefusal) -> Self {
        Self::Claim(error)
    }
}

impl From<CodecRefusal> for EvidenceRefusal {
    fn from(error: CodecRefusal) -> Self {
        Self::Codec(error)
    }
}

fn validate_text(field: &'static str, value: &EvidenceText) -> Result<(), EvidenceRefusal> {
    EvidenceText::parse(field, value.as_str()).map(|_| ())
}

fn validate_collection<T: Eq>(
    field: &'static str,
    items: &[T],
    required: bool,
) -> Result<(), EvidenceRefusal> {
    if required && items.is_empty() {
        return Err(EvidenceRefusal::Collection {
            field,
            reason: "must not be empty",
        });
    }
    if items.len() > MAX_EVIDENCE_ITEMS {
        return Err(EvidenceRefusal::Collection {
            field,
            reason: "exceeds the bounded item count",
        });
    }
    for (index, item) in items.iter().enumerate() {
        if items[index + 1..].contains(item) {
            return Err(EvidenceRefusal::Collection {
                field,
                reason: "contains a duplicate",
            });
        }
    }
    Ok(())
}

fn claim_rank_code(rank: ClaimRank) -> u8 {
    match rank {
        ClaimRank::Benchmark => 0,
        ClaimRank::Slo => 1,
        ClaimRank::Statistical => 2,
        ClaimRank::BoundedModel => 3,
        ClaimRank::Proof => 4,
        ClaimRank::Invariant => 5,
    }
}

fn read_claim_rank(
    input: &mut Decoder<'_>,
    field: &'static str,
) -> Result<ClaimRank, CodecRefusal> {
    let offset = input.offset();
    match input.read_raw_byte(field)? {
        0 => Ok(ClaimRank::Benchmark),
        1 => Ok(ClaimRank::Slo),
        2 => Ok(ClaimRank::Statistical),
        3 => Ok(ClaimRank::BoundedModel),
        4 => Ok(ClaimRank::Proof),
        5 => Ok(ClaimRank::Invariant),
        observed => Err(CodecRefusal::VariantUnknown {
            field,
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn read_evidence_text(
    input: &mut Decoder<'_>,
    field: &'static str,
) -> Result<EvidenceText, CodecRefusal> {
    Ok(EvidenceText::decoded(input.read_text(field)?.to_owned()))
}

fn identify(body: &EvidenceRecordBody) -> Result<EvidenceRecordId, EvidenceRefusal> {
    let internal = body_id(&CryptoBodyIdentity, body)?;
    let id = EvidenceRecordId::from_internal_object_id(internal).map_err(|error| {
        EvidenceRefusal::TypedIdentity {
            detail: error.to_string(),
        }
    })?;
    let canonical = canonical_body_bytes(body)?;
    verify_internal_object_id(
        id.as_internal_object_id(),
        IdentityDomain::EvidenceRecord,
        EvidenceRecordBody::schema_id(),
        CODEC_VERSION,
        &canonical,
    )
    .map_err(EvidenceRefusal::Identity)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::{
        EvidenceArtifact, EvidenceContext, EvidenceRecord, EvidenceRecordBody, EvidenceRefusal,
        EvidenceText, ReplayCompleteness,
    };
    use fgit_claim::ClaimRank;
    use fgit_codec::DecodeLimits;
    use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes, sha256_digest};

    fn text(value: &str) -> EvidenceText {
        EvidenceText::parse("test", value).expect("valid evidence text")
    }

    fn commitment(bytes: &[u8]) -> Digest {
        Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&sha256_digest(bytes)).expect("SHA-256 digest fits shell"),
        )
    }

    fn body(source_inputs: Vec<EvidenceText>, fallback: &str) -> EvidenceRecordBody {
        let context = EvidenceContext::new(
            source_inputs,
            text("git:deadbeef"),
            text("nightly-2026-08-20"),
            text("corpus:adversarial-v1"),
            text("sequence:100-200"),
            text("policy:deterministic-v1"),
            vec![text("assumption:bounded-input")],
            text("verifier:independent-local"),
            vec![EvidenceArtifact::new(
                text("artifact:golden"),
                commitment(b"golden"),
            )],
            text(fallback),
            ReplayCompleteness::Replayable,
            None,
        )
        .expect("complete context");
        EvidenceRecordBody::new(
            text("CLM-001"),
            text("claim-artifact-identity-binding"),
            ClaimRank::Proof,
            ClaimRank::Invariant,
            context,
        )
        .expect("admissible claim evidence")
    }

    #[test]
    fn canonical_frame_and_registered_identity_ignore_set_input_order() {
        let first = EvidenceRecord::new(body(
            vec![text("input:z"), text("input:a")],
            "fallback:refuse",
        ))
        .expect("record");
        let second = EvidenceRecord::new(body(
            vec![text("input:a"), text("input:z")],
            "fallback:refuse",
        ))
        .expect("record");

        assert_eq!(first.id(), second.id());
        assert_eq!(first.frame(), second.frame());
        let decoded = EvidenceRecord::decode(first.id(), first.frame(), DecodeLimits::DEFAULT)
            .expect("registered identity and canonical frame verify");
        assert_eq!(decoded.id(), first.id());
        assert_eq!(decoded.frame(), first.frame());
    }

    #[test]
    fn changed_context_requires_a_new_identity_and_old_identity_refuses() {
        let original =
            EvidenceRecord::new(body(vec![text("input:a")], "fallback:refuse")).expect("record");
        let changed =
            EvidenceRecord::new(body(vec![text("input:a")], "fallback:hold")).expect("record");

        assert_ne!(original.id(), changed.id());
        assert!(matches!(
            EvidenceRecord::decode(original.id(), changed.frame(), DecodeLimits::DEFAULT),
            Err(EvidenceRefusal::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn weak_evidence_cannot_form_an_envelope_for_a_stronger_claim() {
        let context = EvidenceContext::new(
            vec![text("input:a")],
            text("git:deadbeef"),
            text("nightly-2026-08-20"),
            text("corpus:adversarial-v1"),
            text("sequence:100-200"),
            text("policy:deterministic-v1"),
            vec![text("assumption:bounded-input")],
            text("verifier:independent-local"),
            vec![EvidenceArtifact::new(
                text("artifact:golden"),
                commitment(b"golden"),
            )],
            text("fallback:refuse"),
            ReplayCompleteness::AuditOnly,
            None,
        )
        .expect("complete context");

        assert!(matches!(
            EvidenceRecordBody::new(
                text("CLM-001"),
                text("claim-artifact-identity-binding"),
                ClaimRank::Proof,
                ClaimRank::Benchmark,
                context,
            ),
            Err(EvidenceRefusal::Claim(_))
        ));
    }
}
