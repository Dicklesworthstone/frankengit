#![forbid(unsafe_code)]
//! Canonical, signed exchange of immutable foreign evidence.
//!
//! An exchange bundle never turns foreign evidence into local evidence.  It
//! binds the origin trust domain, signer, key lifecycle history, and the
//! canonical frames of carried [`EvidenceRecord`] values.  Import verifies a
//! locally configured origin history, re-decodes every carried record, and
//! recomputes claim and replay labels before it exposes an
//! [`ImportedEvidence`] wrapper.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use fgit_claim::ClaimRank;
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, decode_body, encode_body,
};
use fgit_crypto::{
    DetachedSignature, Identity, IdentityDomain, KeyEpoch, KeyLifecycle, KeyPurpose, SecretKey,
    SignatureError, TAG_BYTES, VerifyingKey,
};
use fgit_evidence::{EvidenceArtifact, EvidenceRecord, EvidenceRefusal, ReplayCompleteness};
use fgit_types::{DomainTag, EvidenceRecordId, SchemaFamily};

/// Largest accepted trust-domain or signer spelling in bytes.
pub const MAX_EXCHANGE_TEXT_BYTES: usize = 256;
/// Largest number of historical signing keys for one origin.
pub const MAX_ORIGIN_KEYS: usize = 64;
/// Largest number of evidence records carried in one exchange bundle.
pub const MAX_EXCHANGE_RECORDS: usize = 128;
/// Largest canonical evidence frame carried by one exchange record.
pub const MAX_EXCHANGE_RECORD_FRAME_BYTES: usize = 1024 * 1024;

/// Bounded canonical text used for trust domains and signer identities.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ExchangeText(String);

impl ExchangeText {
    fn parse(field: &'static str, value: &str) -> Result<Self, ExchangeRefusal> {
        if value.is_empty() {
            return Err(ExchangeRefusal::InvalidText {
                field,
                reason: "must not be empty",
            });
        }
        if value.len() > MAX_EXCHANGE_TEXT_BYTES {
            return Err(ExchangeRefusal::InvalidText {
                field,
                reason: "exceeds the bounded canonical length",
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ExchangeRefusal::InvalidText {
                field,
                reason: "must contain only printable ASCII without whitespace",
            });
        }
        Ok(Self(value.to_owned()))
    }

    const fn decoded(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self, field: &'static str) -> Result<(), ExchangeRefusal> {
        Self::parse(field, self.as_str()).map(|_| ())
    }
}

/// The foreign policy partition that produced an evidence bundle.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustDomain(ExchangeText);

impl TrustDomain {
    /// Parses one policy-selected origin trust-domain identity.
    pub fn parse(value: &str) -> Result<Self, ExchangeRefusal> {
        Ok(Self(ExchangeText::parse("trust_domain", value)?))
    }

    /// Stable canonical spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The named foreign identity authorized by its trust domain to sign exports.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OriginSigner(ExchangeText);

impl OriginSigner {
    /// Parses one canonical signer identity.
    pub fn parse(value: &str) -> Result<Self, ExchangeRefusal> {
        Ok(Self(ExchangeText::parse("origin_signer", value)?))
    }

    /// Stable canonical spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for OriginSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One epoch in the signed origin key history.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OriginSigningKey {
    epoch: KeyEpoch,
    lifecycle: KeyLifecycle,
    commitment: [u8; TAG_BYTES],
    verifying_key: VerifyingKey,
}

impl OriginSigningKey {
    /// Declares the verification material and lifecycle for one origin epoch.
    #[must_use]
    pub const fn new(
        epoch: KeyEpoch,
        lifecycle: KeyLifecycle,
        commitment: [u8; TAG_BYTES],
        verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            epoch,
            lifecycle,
            commitment,
            verifying_key,
        }
    }

    /// Rotation epoch named by this key.
    #[must_use]
    pub const fn epoch(self) -> KeyEpoch {
        self.epoch
    }

    /// Whether this epoch remains eligible to verify historical exports.
    #[must_use]
    pub const fn lifecycle(self) -> KeyLifecycle {
        self.lifecycle
    }

    /// Commitment to the key material that the detached signature must name.
    #[must_use]
    pub const fn commitment(self) -> [u8; TAG_BYTES] {
        self.commitment
    }

    /// Locally trusted public key for this epoch.
    #[must_use]
    pub const fn verifying_key(self) -> VerifyingKey {
        self.verifying_key
    }
}

/// The complete origin identity and its signed, ordered key history.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OriginDescriptor {
    trust_domain: TrustDomain,
    signer: OriginSigner,
    key_history: Vec<OriginSigningKey>,
}

impl OriginDescriptor {
    /// Builds an origin descriptor with a strictly ordered key history.
    pub fn new(
        trust_domain: TrustDomain,
        signer: OriginSigner,
        key_history: Vec<OriginSigningKey>,
    ) -> Result<Self, ExchangeRefusal> {
        let descriptor = Self {
            trust_domain,
            signer,
            key_history,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Origin trust-domain identity.
    #[must_use]
    pub const fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Origin signer identity.
    #[must_use]
    pub const fn signer(&self) -> &OriginSigner {
        &self.signer
    }

    /// Historical keys in ascending epoch order.
    #[must_use]
    pub const fn key_history(&self) -> &[OriginSigningKey] {
        self.key_history.as_slice()
    }

    fn key_at(&self, epoch: KeyEpoch) -> Option<OriginSigningKey> {
        self.key_history
            .iter()
            .copied()
            .find(|key| key.epoch() == epoch)
    }

    /// Whether this signed descriptor is a historical snapshot of `trusted`.
    ///
    /// Lifecycle states are intentionally taken only from local policy: an
    /// older bundle may have recorded an epoch as active before a later local
    /// rotation retired it. Key epoch, commitment, and verifying material must
    /// still be the exact trusted prefix, so an offered descriptor cannot add,
    /// replace, reorder, or omit a key in the middle of the trusted history.
    fn is_history_snapshot_of(&self, trusted: &Self) -> bool {
        self.trust_domain == trusted.trust_domain
            && self.signer == trusted.signer
            && self.key_history.len() <= trusted.key_history.len()
            && self
                .key_history
                .iter()
                .zip(&trusted.key_history)
                .all(|(offered, configured)| {
                    offered.epoch() == configured.epoch()
                        && offered.commitment() == configured.commitment()
                        && offered.verifying_key() == configured.verifying_key()
                })
    }

    fn validate(&self) -> Result<(), ExchangeRefusal> {
        self.trust_domain.0.validate("trust_domain")?;
        self.signer.0.validate("origin_signer")?;
        if self.key_history.is_empty() {
            return Err(ExchangeRefusal::EmptyCollection {
                field: "origin_key_history",
            });
        }
        if self.key_history.len() > MAX_ORIGIN_KEYS {
            return Err(ExchangeRefusal::CollectionTooLarge {
                field: "origin_key_history",
                limit: MAX_ORIGIN_KEYS,
            });
        }
        if self
            .key_history
            .windows(2)
            .any(|pair| pair[0].epoch() >= pair[1].epoch())
        {
            return Err(ExchangeRefusal::KeyHistoryNotOrdered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExchangeEntry {
    id: EvidenceRecordId,
    frame: Vec<u8>,
    claim_rank: ClaimRank,
    evidence_rank: ClaimRank,
    replay_completeness: ReplayCompleteness,
}

/// Canonical unsigned exchange body. Its frame is signed as an exchange
/// envelope under the registered `SignedEnvelope` identity domain.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExchangeBundleBody {
    origin: OriginDescriptor,
    entries: Vec<ExchangeEntry>,
}

impl ExchangeBundleBody {
    /// Captures immutable evidence records and their independently checkable labels.
    pub fn new(
        origin: OriginDescriptor,
        records: Vec<EvidenceRecord>,
    ) -> Result<Self, ExchangeRefusal> {
        let mut entries: Vec<_> = records
            .into_iter()
            .map(|record| ExchangeEntry {
                id: record.id(),
                frame: record.frame().to_vec(),
                claim_rank: record.body().claim_rank(),
                evidence_rank: record.body().evidence_rank(),
                replay_completeness: record.body().context().replay_completeness(),
            })
            .collect();
        entries.sort_unstable_by_key(|entry| entry.id);
        let body = Self { origin, entries };
        body.validate()?;
        Ok(body)
    }

    /// Origin identity that the detached signature must authenticate.
    #[must_use]
    pub const fn origin(&self) -> &OriginDescriptor {
        &self.origin
    }

    fn validate(&self) -> Result<(), ExchangeRefusal> {
        self.origin.validate()?;
        if self.entries.is_empty() {
            return Err(ExchangeRefusal::EmptyCollection {
                field: "evidence_records",
            });
        }
        if self.entries.len() > MAX_EXCHANGE_RECORDS {
            return Err(ExchangeRefusal::CollectionTooLarge {
                field: "evidence_records",
                limit: MAX_EXCHANGE_RECORDS,
            });
        }
        for entry in &self.entries {
            if entry.frame.is_empty() {
                return Err(ExchangeRefusal::InvalidFrame {
                    reason: "must not be empty",
                });
            }
            if entry.frame.len() > MAX_EXCHANGE_RECORD_FRAME_BYTES {
                return Err(ExchangeRefusal::CollectionTooLarge {
                    field: "evidence_record_frame",
                    limit: MAX_EXCHANGE_RECORD_FRAME_BYTES,
                });
            }
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if self.entries[index + 1..]
                .iter()
                .any(|other| other.id == entry.id)
            {
                return Err(ExchangeRefusal::DuplicateEvidenceRecord {
                    id: Box::new(entry.id),
                });
            }
        }
        if self.entries.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(ExchangeRefusal::EvidenceRecordsNotOrdered);
        }
        Ok(())
    }
}

impl CanonicalBody for ExchangeBundleBody {
    // The frame is signed under `IdentityDomain::SignedEnvelope`; its schema
    // distinguishes this payload from codec's generic signed-envelope body.
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/signed-envelope/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("evidence-exchange");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_origin(out, &self.origin)?;
        write_bounded_sequence(
            out,
            "evidence_records",
            &self.entries,
            MAX_EXCHANGE_RECORDS,
            write_entry,
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            origin: read_origin(input)?,
            entries: read_bounded_sequence(
                input,
                "evidence_records",
                MAX_EXCHANGE_RECORDS,
                read_entry,
            )?,
        })
    }
}

/// One signed portable evidence bundle before local policy acceptance.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceExchangeBundle {
    frame: Vec<u8>,
    signature: DetachedSignature,
}

impl EvidenceExchangeBundle {
    /// Canonically frames and signs a bundle with an identity-purpose origin key.
    pub fn export(
        origin: OriginDescriptor,
        records: Vec<EvidenceRecord>,
        signer: &SecretKey<Identity>,
    ) -> Result<Self, ExchangeRefusal> {
        let body = ExchangeBundleBody::new(origin, records)?;
        let frame = encode_body(&body)?;
        let signature = signer.sign(
            IdentityDomain::SignedEnvelope,
            ExchangeBundleBody::schema_id(),
            &frame,
        );
        verify_issuing_signature(&body.origin, &signature, &frame)?;
        Ok(Self { frame, signature })
    }

    /// Reconstructs a received bundle without treating either field as trusted.
    #[must_use]
    pub const fn from_wire(frame: Vec<u8>, signature: DetachedSignature) -> Self {
        Self { frame, signature }
    }

    /// Canonical bundle frame that the detached signature authenticates.
    #[must_use]
    pub const fn frame(&self) -> &[u8] {
        self.frame.as_slice()
    }

    /// Detached signature presented by the foreign origin.
    #[must_use]
    pub const fn signature(&self) -> &DetachedSignature {
        &self.signature
    }

    /// Independently verifies and imports every carried evidence record.
    pub fn import<R: ArtifactResolver>(
        &self,
        policy: &ImportPolicy,
        resolver: &R,
        limits: DecodeLimits,
    ) -> Result<Vec<ImportedEvidence>, ExchangeRefusal> {
        let body = decode_body::<ExchangeBundleBody>(&self.frame, limits)?;
        body.validate()?;
        if encode_body(&body)? != self.frame {
            return Err(ExchangeRefusal::FrameNotCanonical);
        }
        let trusted = policy
            .origin_for(&body.origin)
            .ok_or(ExchangeRefusal::OriginUntrusted)?;
        if !body.origin.is_history_snapshot_of(trusted) {
            return Err(ExchangeRefusal::OriginHistoryMismatch);
        }
        verify_signature(trusted, &self.signature, &self.frame)?;
        let source_bundle = Arc::new(self.clone());

        body.entries
            .iter()
            .map(|entry| import_entry(entry, &body.origin, &source_bundle, resolver, limits))
            .collect()
    }

    /// Imports every record and passes it through a bounded equivocation detector.
    ///
    /// The detector recognizes the only predecessor relation the immutable
    /// evidence schema defines: two different records from one origin naming
    /// the same `supersedes` record.  A conflict result retains both verified,
    /// signed source bundles; later observations for that origin/predecessor
    /// slot are refused rather than replacing either observation.
    pub fn import_with_equivocation_detector<R: ArtifactResolver>(
        &self,
        policy: &ImportPolicy,
        resolver: &R,
        limits: DecodeLimits,
        detector: &mut EquivocationDetector,
    ) -> Result<Vec<EquivocationDecision>, ExchangeRefusal> {
        self.import(policy, resolver, limits)?
            .into_iter()
            .map(|imported| detector.observe(imported))
            .collect()
    }
}

/// Result of an artifact lookup performed independently by the importer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactAvailability {
    /// The importer found the artifact and recomputed its advertised commitment.
    Verified,
    /// The importer cannot obtain the named artifact locally.
    Missing,
    /// Bytes were present but did not match the advertised commitment.
    CommitmentMismatch,
}

/// The local capability that rechecks evidence artifacts during import.
pub trait ArtifactResolver {
    /// Returns the result of locally resolving and checking one artifact.
    fn resolve(&self, artifact: &EvidenceArtifact) -> ArtifactAvailability;
}

/// Maps re-derived foreign replay grades to locally permitted satisfaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReplayGradePolicy {
    permitted: u8,
}

impl ReplayGradePolicy {
    /// Explicitly configures which foreign replay grades may satisfy a local requirement.
    #[must_use]
    pub const fn accepting(grades: &[ReplayCompleteness]) -> Self {
        let mut permitted = 0;
        let mut index = 0;
        while index < grades.len() {
            permitted |= replay_grade_bit(grades[index]);
            index += 1;
        }
        Self { permitted }
    }

    /// Accepts only fully replayable foreign evidence for requirement satisfaction.
    #[must_use]
    pub const fn replayable_only() -> Self {
        Self::accepting(&[ReplayCompleteness::Replayable])
    }

    const fn permits(self, grade: ReplayCompleteness) -> bool {
        self.permitted & replay_grade_bit(grade) != 0
    }
}

/// Locally configured origins and the local grade-to-requirement mapping.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImportPolicy {
    trusted_origins: Vec<OriginDescriptor>,
    replay_policy: ReplayGradePolicy,
}

impl ImportPolicy {
    /// Builds a policy with exactly named foreign origins; the bundle's own
    /// descriptor never becomes trusted merely because it is signed.
    pub fn new(
        trusted_origins: Vec<OriginDescriptor>,
        replay_policy: ReplayGradePolicy,
    ) -> Result<Self, ExchangeRefusal> {
        for origin in &trusted_origins {
            origin.validate()?;
        }
        for (index, origin) in trusted_origins.iter().enumerate() {
            if trusted_origins[index + 1..].iter().any(|other| {
                other.trust_domain() == origin.trust_domain() && other.signer() == origin.signer()
            }) {
                return Err(ExchangeRefusal::DuplicateTrustedOrigin);
            }
        }
        Ok(Self {
            trusted_origins,
            replay_policy,
        })
    }

    fn origin_for(&self, offered: &OriginDescriptor) -> Option<&OriginDescriptor> {
        self.trusted_origins.iter().find(|origin| {
            origin.trust_domain() == offered.trust_domain() && origin.signer() == offered.signer()
        })
    }
}

/// A local requirement against which foreign evidence may be evaluated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocalEvidenceRequirement {
    claim_rank: ClaimRank,
    replay_completeness: ReplayCompleteness,
    local_evidence_required: bool,
}

impl LocalEvidenceRequirement {
    /// Defines the minimum claim/replay class and whether a local check is mandatory.
    #[must_use]
    pub const fn new(
        claim_rank: ClaimRank,
        replay_completeness: ReplayCompleteness,
        local_evidence_required: bool,
    ) -> Self {
        Self {
            claim_rank,
            replay_completeness,
            local_evidence_required,
        }
    }
}

/// Whether a foreign record may satisfy a named local requirement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ForeignEvidenceUse {
    /// Foreign evidence adds context or tightens review but cannot discharge the requirement.
    SupplementalOnly,
    /// This specific foreign record meets the configured non-local requirement.
    MaySatisfy,
}

/// A verified evidence record that remains visibly foreign in every API.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImportedEvidence {
    origin: OriginDescriptor,
    record: EvidenceRecord,
    replay_completeness: ReplayCompleteness,
    source_bundle: Arc<EvidenceExchangeBundle>,
}

impl ImportedEvidence {
    /// The foreign origin that signed and whose configured history verified this record.
    #[must_use]
    pub const fn origin(&self) -> &OriginDescriptor {
        &self.origin
    }

    /// The immutable record after frame and identity verification.
    #[must_use]
    pub const fn record(&self) -> &EvidenceRecord {
        &self.record
    }

    /// Grade independently re-derived from the record and local artifact resolution.
    #[must_use]
    pub const fn replay_completeness(&self) -> ReplayCompleteness {
        self.replay_completeness
    }

    /// The exact signed foreign bundle that carried this record.
    ///
    /// Retaining this envelope means an equivocation record can preserve both
    /// foreign attestations, rather than reducing a conflict to mutable local
    /// metadata or silently choosing one observation.
    #[must_use]
    pub fn source_bundle(&self) -> &EvidenceExchangeBundle {
        self.source_bundle.as_ref()
    }

    /// Maps this foreign record through explicit local requirements without
    /// upgrading its declared claim class or bypassing a required local check.
    #[must_use]
    pub const fn local_use(
        &self,
        policy: &ImportPolicy,
        requirement: LocalEvidenceRequirement,
    ) -> ForeignEvidenceUse {
        if requirement.local_evidence_required
            || !self
                .record
                .body()
                .claim_rank()
                .justifies(requirement.claim_rank)
            || !replay_at_least(self.replay_completeness, requirement.replay_completeness)
            || !policy.replay_policy.permits(self.replay_completeness)
        {
            ForeignEvidenceUse::SupplementalOnly
        } else {
            ForeignEvidenceUse::MaySatisfy
        }
    }
}

/// Largest number of origin/predecessor slots a detector retains in one run.
///
/// The detector is deliberately bounded working state; callers persist an
/// [`EquivocationConflict`] before treating its outcome as durably recorded.
pub const MAX_EQUIVOCATION_SLOTS: usize = 1024;

/// Largest combined source-frame and decoded-record footprint retained by one detector.
///
/// A conflict must retain the original foreign bundles, but a count-only cap
/// would still permit a hostile peer to fill memory with maximum-size frames.
/// Frames are shared across every record imported from the same bundle; the
/// separately decoded immutable records are also charged. A detector refuses
/// the next conflicting observation past this bound.
pub const MAX_EQUIVOCATION_RETAINED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EquivocationSlot {
    trust_domain: TrustDomain,
    signer: OriginSigner,
    superseded: EvidenceRecordId,
}

impl EquivocationSlot {
    fn from_imported(imported: &ImportedEvidence, superseded: EvidenceRecordId) -> Self {
        Self {
            trust_domain: imported.origin().trust_domain().clone(),
            signer: imported.origin().signer().clone(),
            superseded,
        }
    }
}

/// Immutable conflict evidence for two incompatible signed successors.
///
/// Both records were independently imported and retain their exact signed
/// source bundles. Their order is closed by immutable record identity, so the
/// pair is portable evidence for a durable append-only conflict log; this
/// detector never selects a winner.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EquivocationConflict {
    origin: OriginDescriptor,
    superseded: EvidenceRecordId,
    first: ImportedEvidence,
    second: ImportedEvidence,
}

impl EquivocationConflict {
    fn new(
        first: ImportedEvidence,
        second: ImportedEvidence,
        superseded: EvidenceRecordId,
    ) -> Self {
        debug_assert_eq!(
            first.origin().trust_domain(),
            second.origin().trust_domain()
        );
        debug_assert_eq!(first.origin().signer(), second.origin().signer());
        debug_assert_ne!(first.record().id(), second.record().id());
        let (first, second) = if first.record().id() <= second.record().id() {
            (first, second)
        } else {
            (second, first)
        };
        Self {
            origin: first.origin().clone(),
            superseded,
            first,
            second,
        }
    }

    /// Canonical source-origin snapshot for the remote identity that signed both records.
    ///
    /// The first and second imports retain their own complete signed key
    /// histories, so key rotation does not collapse their provenance. The
    /// common identity is this descriptor's trust domain and signer.
    #[must_use]
    pub const fn origin(&self) -> &OriginDescriptor {
        &self.origin
    }

    /// Immutable predecessor that both records claimed to supersede.
    #[must_use]
    pub const fn superseded(&self) -> EvidenceRecordId {
        self.superseded
    }

    /// Canonically first signed successor evidence, ordered by immutable record identity.
    #[must_use]
    pub const fn first(&self) -> &ImportedEvidence {
        &self.first
    }

    /// Canonically second signed successor evidence, ordered by immutable record identity.
    #[must_use]
    pub const fn second(&self) -> &ImportedEvidence {
        &self.second
    }
}

/// Outcome of observing one independently verified foreign evidence record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EquivocationDecision {
    /// A record with no competing successor was observed.
    Accepted(ImportedEvidence),
    /// The exact immutable record was already observed for this slot.
    Duplicate(ImportedEvidence),
    /// A different successor was observed; both signed observations are retained.
    Conflict(Box<EquivocationConflict>),
}

/// Bounded detector for foreign evidence records that equivocate on a predecessor.
///
/// It is not a durability substitute: callers append each returned
/// [`EquivocationConflict`] to their durable evidence log. Its local state
/// prevents a later import in the same admission run from overwriting or using
/// an already-conflicted origin/predecessor slot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EquivocationDetector {
    observed: BTreeMap<EquivocationSlot, ImportedEvidence>,
    conflicts: BTreeMap<EquivocationSlot, EquivocationConflict>,
}

impl EquivocationDetector {
    /// Starts an empty bounded detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one verified import without selecting between conflicting successors.
    pub fn observe(
        &mut self,
        imported: ImportedEvidence,
    ) -> Result<EquivocationDecision, ExchangeRefusal> {
        let Some(superseded) = imported.record().body().context().supersedes() else {
            return Ok(EquivocationDecision::Accepted(imported));
        };
        let slot = EquivocationSlot::from_imported(&imported, superseded);

        if self.conflicts.contains_key(&slot) {
            return Err(ExchangeRefusal::EquivocationPreviouslyObserved {
                superseded: Box::new(superseded),
            });
        }

        if let Some(first) = self.observed.get(&slot) {
            if first.record().id() == imported.record().id() {
                return Ok(EquivocationDecision::Duplicate(imported));
            }
            if !self.can_retain(&imported) {
                return Err(ExchangeRefusal::EquivocationDetectorByteLimit {
                    limit: MAX_EQUIVOCATION_RETAINED_BYTES,
                });
            }
            let first = self
                .observed
                .remove(&slot)
                .expect("observed equivocation slot remains present");
            let conflict = EquivocationConflict::new(first, imported, superseded);
            self.conflicts.insert(slot, conflict.clone());
            return Ok(EquivocationDecision::Conflict(Box::new(conflict)));
        }

        if self.observed.len() + self.conflicts.len() >= MAX_EQUIVOCATION_SLOTS {
            return Err(ExchangeRefusal::EquivocationDetectorFull {
                limit: MAX_EQUIVOCATION_SLOTS,
            });
        }
        if !self.can_retain(&imported) {
            return Err(ExchangeRefusal::EquivocationDetectorByteLimit {
                limit: MAX_EQUIVOCATION_RETAINED_BYTES,
            });
        }
        self.observed.insert(slot, imported.clone());
        Ok(EquivocationDecision::Accepted(imported))
    }

    fn can_retain(&self, candidate: &ImportedEvidence) -> bool {
        let mut unique_bundles: Vec<&Arc<EvidenceExchangeBundle>> = Vec::new();
        let mut retained_bytes = 0usize;
        for imported in self.observed.values() {
            if !account_imported(&mut unique_bundles, &mut retained_bytes, imported) {
                return false;
            }
        }
        for conflict in self.conflicts.values() {
            if !account_imported(&mut unique_bundles, &mut retained_bytes, &conflict.first)
                || !account_imported(&mut unique_bundles, &mut retained_bytes, &conflict.second)
            {
                return false;
            }
        }
        account_imported(&mut unique_bundles, &mut retained_bytes, candidate)
            && retained_bytes <= MAX_EQUIVOCATION_RETAINED_BYTES
    }

    /// Returns a retained conflict for one origin and immutable predecessor.
    #[must_use]
    pub fn conflict_for(
        &self,
        origin: &OriginDescriptor,
        superseded: EvidenceRecordId,
    ) -> Option<&EquivocationConflict> {
        let slot = EquivocationSlot {
            trust_domain: origin.trust_domain().clone(),
            signer: origin.signer().clone(),
            superseded,
        };
        self.conflicts.get(&slot)
    }
}

fn account_imported<'a>(
    unique_bundles: &mut Vec<&'a Arc<EvidenceExchangeBundle>>,
    retained_bytes: &mut usize,
    imported: &'a ImportedEvidence,
) -> bool {
    let candidate = &imported.source_bundle;
    if unique_bundles
        .iter()
        .any(|known| Arc::ptr_eq(known, candidate))
    {
        return retained_bytes
            .checked_add(imported.record().frame().len())
            .map(|next| {
                *retained_bytes = next;
                true
            })
            .unwrap_or(false);
    }
    let Some(with_source) = retained_bytes.checked_add(candidate.frame().len()) else {
        return false;
    };
    let Some(with_record) = with_source.checked_add(imported.record().frame().len()) else {
        return false;
    };
    *retained_bytes = with_record;
    unique_bundles.push(candidate);
    true
}

/// Why a bundle export or import was refused.
#[derive(Debug)]
pub enum ExchangeRefusal {
    /// A trust-domain or signer field was not canonical exchange text.
    InvalidText {
        /// Field that was refused.
        field: &'static str,
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    /// A required canonical collection was empty.
    EmptyCollection {
        /// Collection field that was refused.
        field: &'static str,
    },
    /// A collection exceeded this slice's fixed resource bound.
    CollectionTooLarge {
        /// Collection field that was refused.
        field: &'static str,
        /// Largest accepted count or byte length.
        limit: usize,
    },
    /// Origin key epochs were not strictly increasing.
    KeyHistoryNotOrdered,
    /// Evidence entries were not in their required stable identity order.
    EvidenceRecordsNotOrdered,
    /// A bundle named the same immutable evidence record twice.
    DuplicateEvidenceRecord {
        /// Duplicated immutable evidence identity.
        id: Box<EvidenceRecordId>,
    },
    /// A carried evidence frame violated a bundle-local bound.
    InvalidFrame {
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    /// Canonical codec framing refused the bundle.
    Codec(Box<CodecRefusal>),
    /// The carried immutable evidence frame or identity was invalid.
    Evidence(Box<EvidenceRefusal>),
    /// The presented origin is absent from local trust policy.
    OriginUntrusted,
    /// A peer's signed key history is not a trusted historical prefix.
    OriginHistoryMismatch,
    /// Local policy configured the same origin domain/signer twice.
    DuplicateTrustedOrigin,
    /// The detached signature named a purpose other than identity attestation.
    SignerPurposeMismatch,
    /// The signature named an epoch absent from the configured origin history.
    SignerEpochUnknown,
    /// The signature named a revoked or erased origin key epoch.
    SignerEpochNotVerifiable,
    /// Export attempted to issue new evidence with a non-active origin key epoch.
    SignerEpochNotIssuable,
    /// The signature's key commitment differs from the configured history.
    SignerKeyCommitmentMismatch,
    /// Cryptographic verification of the detached signature refused.
    Signature(SignatureError),
    /// A signed bundle label disagreed with the carried record's recomputed claim class.
    ClaimRankLabelMismatch {
        /// Label carried by the exchange body.
        declared: ClaimRank,
        /// Label recomputed from the immutable evidence record.
        recomputed: ClaimRank,
    },
    /// A signed bundle label disagreed with the carried record's evidence class.
    EvidenceRankLabelMismatch {
        /// Label carried by the exchange body.
        declared: ClaimRank,
        /// Label recomputed from the immutable evidence record.
        recomputed: ClaimRank,
    },
    /// A signed bundle label disagreed with the carried record's replay grade.
    ReplayGradeLabelMismatch {
        /// Label carried by the exchange body.
        declared: ReplayCompleteness,
        /// Label recomputed from the immutable evidence record.
        recomputed: ReplayCompleteness,
    },
    /// The importer found bytes that failed the carried artifact commitment.
    ArtifactCommitmentMismatch {
        /// Immutable record whose artifact was inconsistent.
        id: Box<EvidenceRecordId>,
    },
    /// The bounded equivocation detector cannot retain another predecessor slot.
    EquivocationDetectorFull {
        /// Largest number of retained origin/predecessor slots.
        limit: usize,
    },
    /// Retaining another distinct signed source bundle would exceed the byte bound.
    EquivocationDetectorByteLimit {
        /// Largest combined retained signed-frame footprint.
        limit: usize,
    },
    /// This origin/predecessor slot already produced an immutable conflict record.
    EquivocationPreviouslyObserved {
        /// Immutable predecessor named by the conflicting successors.
        superseded: Box<EvidenceRecordId>,
    },
    /// Strict decoding accepted a frame that did not re-encode identically.
    FrameNotCanonical,
}

impl fmt::Display for ExchangeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::EmptyCollection { field } => write!(formatter, "{field} must not be empty"),
            Self::CollectionTooLarge { field, limit } => {
                write!(formatter, "{field} exceeds bound {limit}")
            }
            Self::KeyHistoryNotOrdered => {
                formatter.write_str("origin key history must be strictly increasing by epoch")
            }
            Self::EvidenceRecordsNotOrdered => {
                formatter.write_str("evidence records must be strictly increasing by identity")
            }
            Self::DuplicateEvidenceRecord { id } => {
                write!(formatter, "exchange bundle repeats evidence record {id}")
            }
            Self::InvalidFrame { reason } => {
                write!(formatter, "invalid evidence record frame: {reason}")
            }
            Self::Codec(error) => fmt::Display::fmt(error, formatter),
            Self::Evidence(error) => fmt::Display::fmt(error, formatter),
            Self::OriginUntrusted => {
                formatter.write_str("origin is absent from local trust policy")
            }
            Self::OriginHistoryMismatch => {
                formatter.write_str("origin key history is not a trusted historical prefix")
            }
            Self::DuplicateTrustedOrigin => {
                formatter.write_str("local policy names the same origin more than once")
            }
            Self::SignerPurposeMismatch => {
                formatter.write_str("exchange signature must use an identity-purpose key")
            }
            Self::SignerEpochUnknown => {
                formatter.write_str("exchange signature names an unknown origin key epoch")
            }
            Self::SignerEpochNotVerifiable => {
                formatter.write_str("exchange signature names a non-verifiable origin key epoch")
            }
            Self::SignerEpochNotIssuable => {
                formatter.write_str("exchange export names a non-active origin key epoch")
            }
            Self::SignerKeyCommitmentMismatch => {
                formatter.write_str("exchange signature key commitment differs from origin history")
            }
            Self::Signature(error) => fmt::Display::fmt(error, formatter),
            Self::ClaimRankLabelMismatch {
                declared,
                recomputed,
            } => write!(
                formatter,
                "exchange claim label {declared} disagrees with immutable record label {recomputed}"
            ),
            Self::EvidenceRankLabelMismatch {
                declared,
                recomputed,
            } => write!(
                formatter,
                "exchange evidence label {declared} disagrees with immutable record label {recomputed}"
            ),
            Self::ReplayGradeLabelMismatch {
                declared,
                recomputed,
            } => write!(
                formatter,
                "exchange replay grade {declared:?} disagrees with immutable record grade {recomputed:?}"
            ),
            Self::ArtifactCommitmentMismatch { id } => {
                write!(
                    formatter,
                    "artifact commitment mismatch in evidence record {id}"
                )
            }
            Self::EquivocationDetectorFull { limit } => {
                write!(
                    formatter,
                    "equivocation detector exceeds slot bound {limit}"
                )
            }
            Self::EquivocationDetectorByteLimit { limit } => {
                write!(
                    formatter,
                    "equivocation detector exceeds retained-byte bound {limit}"
                )
            }
            Self::EquivocationPreviouslyObserved { superseded } => {
                write!(
                    formatter,
                    "origin/predecessor slot for {superseded} already has immutable equivocation evidence"
                )
            }
            Self::FrameNotCanonical => formatter.write_str("exchange frame is not canonical"),
        }
    }
}

impl std::error::Error for ExchangeRefusal {}

impl From<CodecRefusal> for ExchangeRefusal {
    fn from(error: CodecRefusal) -> Self {
        Self::Codec(Box::new(error))
    }
}

impl From<EvidenceRefusal> for ExchangeRefusal {
    fn from(error: EvidenceRefusal) -> Self {
        Self::Evidence(Box::new(error))
    }
}

fn write_origin(out: &mut Encoder, origin: &OriginDescriptor) -> Result<(), CodecRefusal> {
    out.write_text("origin_trust_domain", origin.trust_domain().as_str())?;
    out.write_text("origin_signer", origin.signer().as_str())?;
    write_bounded_sequence(
        out,
        "origin_key_history",
        origin.key_history(),
        MAX_ORIGIN_KEYS,
        |out, key| {
            out.write_scalar(key.epoch().get());
            out.write_raw_byte(key_lifecycle_code(key.lifecycle()));
            out.write_bytes("origin_key_commitment", &key.commitment())?;
            out.write_bytes("origin_verifying_key", key.verifying_key().as_bytes())
        },
    )
}

fn read_origin(input: &mut Decoder<'_>) -> Result<OriginDescriptor, CodecRefusal> {
    let trust_domain = TrustDomain(ExchangeText::decoded(
        input.read_text("origin_trust_domain")?.to_owned(),
    ));
    let signer = OriginSigner(ExchangeText::decoded(
        input.read_text("origin_signer")?.to_owned(),
    ));
    let key_history =
        read_bounded_sequence(input, "origin_key_history", MAX_ORIGIN_KEYS, |input| {
            let epoch = KeyEpoch::new(input.read_scalar("origin_key_epoch")?).ok_or_else(|| {
                CodecRefusal::VariantUnknown {
                    field: "origin_key_epoch",
                    observed: 0,
                    offset: input.offset(),
                }
            })?;
            let lifecycle_offset = input.offset();
            let lifecycle = key_lifecycle_from_code(
                input.read_raw_byte("origin_key_lifecycle")?,
                lifecycle_offset,
            )?;
            let commitment = read_fixed(input, "origin_key_commitment")?;
            let verifying_key =
                VerifyingKey::from_bytes(read_fixed(input, "origin_verifying_key")?);
            Ok(OriginSigningKey::new(
                epoch,
                lifecycle,
                commitment,
                verifying_key,
            ))
        })?;
    Ok(OriginDescriptor {
        trust_domain,
        signer,
        key_history,
    })
}

fn write_entry(out: &mut Encoder, entry: &ExchangeEntry) -> Result<(), CodecRefusal> {
    out.write_internal_object_id(entry.id.as_internal_object_id())?;
    out.write_bytes("evidence_record_frame", &entry.frame)?;
    out.write_raw_byte(claim_rank_code(entry.claim_rank));
    out.write_raw_byte(claim_rank_code(entry.evidence_rank));
    out.write_raw_byte(replay_completeness_code(entry.replay_completeness));
    Ok(())
}

fn read_entry(input: &mut Decoder<'_>) -> Result<ExchangeEntry, CodecRefusal> {
    let id = EvidenceRecordId::from_internal_object_id(input.read_internal_object_id()?)?;
    let frame = input.read_bytes("evidence_record_frame")?;
    if frame.len() > MAX_EXCHANGE_RECORD_FRAME_BYTES {
        return Err(CodecRefusal::LengthBoundExceeded {
            field: "evidence_record_frame",
            observed: u64::try_from(frame.len()).unwrap_or(u64::MAX),
            limit: u64::try_from(MAX_EXCHANGE_RECORD_FRAME_BYTES).unwrap_or(u64::MAX),
        });
    }
    let claim_offset = input.offset();
    let claim_rank = claim_rank_from_code(input.read_raw_byte("claim_rank")?, claim_offset)?;
    let evidence_offset = input.offset();
    let evidence_rank =
        claim_rank_from_code(input.read_raw_byte("evidence_rank")?, evidence_offset)?;
    let replay_offset = input.offset();
    let replay_completeness =
        replay_completeness_from_code(input.read_raw_byte("replay_completeness")?, replay_offset)?;
    Ok(ExchangeEntry {
        id,
        frame: frame.to_vec(),
        claim_rank,
        evidence_rank,
        replay_completeness,
    })
}

fn import_entry<R: ArtifactResolver>(
    entry: &ExchangeEntry,
    origin: &OriginDescriptor,
    source_bundle: &Arc<EvidenceExchangeBundle>,
    resolver: &R,
    limits: DecodeLimits,
) -> Result<ImportedEvidence, ExchangeRefusal> {
    if entry.frame.len() > MAX_EXCHANGE_RECORD_FRAME_BYTES {
        return Err(ExchangeRefusal::CollectionTooLarge {
            field: "evidence_record_frame",
            limit: MAX_EXCHANGE_RECORD_FRAME_BYTES,
        });
    }
    let record = EvidenceRecord::decode(entry.id, &entry.frame, limits)?;
    let body = record.body();
    if entry.claim_rank != body.claim_rank() {
        return Err(ExchangeRefusal::ClaimRankLabelMismatch {
            declared: entry.claim_rank,
            recomputed: body.claim_rank(),
        });
    }
    if entry.evidence_rank != body.evidence_rank() {
        return Err(ExchangeRefusal::EvidenceRankLabelMismatch {
            declared: entry.evidence_rank,
            recomputed: body.evidence_rank(),
        });
    }
    let declared_grade = body.context().replay_completeness();
    if entry.replay_completeness != declared_grade {
        return Err(ExchangeRefusal::ReplayGradeLabelMismatch {
            declared: entry.replay_completeness,
            recomputed: declared_grade,
        });
    }
    let replay_completeness = rederive_replay_completeness(&record, resolver)?;
    Ok(ImportedEvidence {
        origin: origin.clone(),
        record,
        replay_completeness,
        source_bundle: source_bundle.clone(),
    })
}

fn verify_signature(
    origin: &OriginDescriptor,
    signature: &DetachedSignature,
    frame: &[u8],
) -> Result<(), ExchangeRefusal> {
    if signature.purpose() != KeyPurpose::Identity {
        return Err(ExchangeRefusal::SignerPurposeMismatch);
    }
    let key = origin
        .key_at(signature.epoch())
        .ok_or(ExchangeRefusal::SignerEpochUnknown)?;
    if !key.lifecycle().may_verify() {
        return Err(ExchangeRefusal::SignerEpochNotVerifiable);
    }
    if signature.key_commitment() != &key.commitment() {
        return Err(ExchangeRefusal::SignerKeyCommitmentMismatch);
    }
    signature
        .verify_with(
            &key.verifying_key(),
            IdentityDomain::SignedEnvelope,
            ExchangeBundleBody::schema_id(),
            frame,
        )
        .map_err(ExchangeRefusal::Signature)
}

fn verify_issuing_signature(
    origin: &OriginDescriptor,
    signature: &DetachedSignature,
    frame: &[u8],
) -> Result<(), ExchangeRefusal> {
    let key = origin
        .key_at(signature.epoch())
        .ok_or(ExchangeRefusal::SignerEpochUnknown)?;
    if !key.lifecycle().may_issue() {
        return Err(ExchangeRefusal::SignerEpochNotIssuable);
    }
    verify_signature(origin, signature, frame)
}

fn rederive_replay_completeness<R: ArtifactResolver>(
    record: &EvidenceRecord,
    resolver: &R,
) -> Result<ReplayCompleteness, ExchangeRefusal> {
    let mut missing = false;
    for artifact in record.body().context().artifacts() {
        match resolver.resolve(artifact) {
            ArtifactAvailability::Verified => {}
            ArtifactAvailability::Missing => missing = true,
            ArtifactAvailability::CommitmentMismatch => {
                return Err(ExchangeRefusal::ArtifactCommitmentMismatch {
                    id: Box::new(record.id()),
                });
            }
        }
    }
    let declared = record.body().context().replay_completeness();
    if missing
        && matches!(
            declared,
            ReplayCompleteness::Replayable | ReplayCompleteness::Structural
        )
    {
        Ok(ReplayCompleteness::VerifiableIfSupplied)
    } else {
        Ok(declared)
    }
}

const fn replay_at_least(actual: ReplayCompleteness, required: ReplayCompleteness) -> bool {
    replay_completeness_strength(actual) >= replay_completeness_strength(required)
}

const fn replay_completeness_strength(grade: ReplayCompleteness) -> u8 {
    match grade {
        ReplayCompleteness::Replayable => 3,
        ReplayCompleteness::Structural => 2,
        ReplayCompleteness::VerifiableIfSupplied => 1,
        ReplayCompleteness::AuditOnly => 0,
    }
}

const fn replay_grade_bit(grade: ReplayCompleteness) -> u8 {
    match grade {
        ReplayCompleteness::Replayable => 1,
        ReplayCompleteness::Structural => 2,
        ReplayCompleteness::VerifiableIfSupplied => 4,
        ReplayCompleteness::AuditOnly => 8,
    }
}

const fn claim_rank_code(rank: ClaimRank) -> u8 {
    match rank {
        ClaimRank::Benchmark => 0,
        ClaimRank::Slo => 1,
        ClaimRank::Statistical => 2,
        ClaimRank::BoundedModel => 3,
        ClaimRank::Proof => 4,
        ClaimRank::Invariant => 5,
    }
}

fn claim_rank_from_code(code: u8, offset: u64) -> Result<ClaimRank, CodecRefusal> {
    match code {
        0 => Ok(ClaimRank::Benchmark),
        1 => Ok(ClaimRank::Slo),
        2 => Ok(ClaimRank::Statistical),
        3 => Ok(ClaimRank::BoundedModel),
        4 => Ok(ClaimRank::Proof),
        5 => Ok(ClaimRank::Invariant),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "claim_rank",
            observed: u32::from(observed),
            offset,
        }),
    }
}

const fn replay_completeness_code(grade: ReplayCompleteness) -> u8 {
    match grade {
        ReplayCompleteness::Replayable => 0,
        ReplayCompleteness::Structural => 1,
        ReplayCompleteness::VerifiableIfSupplied => 2,
        ReplayCompleteness::AuditOnly => 3,
    }
}

fn replay_completeness_from_code(
    code: u8,
    offset: u64,
) -> Result<ReplayCompleteness, CodecRefusal> {
    match code {
        0 => Ok(ReplayCompleteness::Replayable),
        1 => Ok(ReplayCompleteness::Structural),
        2 => Ok(ReplayCompleteness::VerifiableIfSupplied),
        3 => Ok(ReplayCompleteness::AuditOnly),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "replay_completeness",
            observed: u32::from(observed),
            offset,
        }),
    }
}

const fn key_lifecycle_code(lifecycle: KeyLifecycle) -> u8 {
    match lifecycle {
        KeyLifecycle::Active => 0,
        KeyLifecycle::Retired => 1,
        KeyLifecycle::Revoked => 2,
        KeyLifecycle::Erased => 3,
    }
}

fn key_lifecycle_from_code(code: u8, offset: u64) -> Result<KeyLifecycle, CodecRefusal> {
    match code {
        0 => Ok(KeyLifecycle::Active),
        1 => Ok(KeyLifecycle::Retired),
        2 => Ok(KeyLifecycle::Revoked),
        3 => Ok(KeyLifecycle::Erased),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "origin_key_lifecycle",
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn read_fixed<const N: usize>(
    input: &mut Decoder<'_>,
    field: &'static str,
) -> Result<[u8; N], CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    if bytes.len() != N {
        return Err(CodecRefusal::LengthBoundExceeded {
            field,
            observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            limit: u64::try_from(N).unwrap_or(u64::MAX),
        });
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn write_bounded_sequence<T, F>(
    out: &mut Encoder,
    field: &'static str,
    items: &[T],
    limit: usize,
    mut write: F,
) -> Result<(), CodecRefusal>
where
    F: FnMut(&mut Encoder, &T) -> Result<(), CodecRefusal>,
{
    if items.len() > limit {
        return Err(CodecRefusal::ValueUnrepresentable {
            field,
            observed: u64::try_from(items.len()).unwrap_or(u64::MAX),
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    out.write_raw_byte(u8::try_from(items.len()).map_err(|_| {
        CodecRefusal::ValueUnrepresentable {
            field,
            observed: u64::try_from(items.len()).unwrap_or(u64::MAX),
            limit: u64::from(u8::MAX),
        }
    })?);
    for item in items {
        write(out, item)?;
    }
    Ok(())
}

fn read_bounded_sequence<T, F>(
    input: &mut Decoder<'_>,
    field: &'static str,
    limit: usize,
    mut read: F,
) -> Result<Vec<T>, CodecRefusal>
where
    F: FnMut(&mut Decoder<'_>) -> Result<T, CodecRefusal>,
{
    let count = usize::from(input.read_raw_byte(field)?);
    if count > limit {
        return Err(CodecRefusal::CountBoundExceeded {
            field,
            observed: u64::try_from(count).unwrap_or(u64::MAX),
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(read(input)?);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactAvailability, ArtifactResolver, EquivocationDecision, EquivocationDetector,
        EvidenceExchangeBundle, ExchangeBundleBody, ExchangeRefusal, ForeignEvidenceUse,
        ImportPolicy, LocalEvidenceRequirement, OriginDescriptor, OriginSigner, OriginSigningKey,
        ReplayGradePolicy, TrustDomain,
    };
    use fgit_claim::ClaimRank;
    use fgit_codec::{CanonicalBody, DecodeLimits, decode_body, encode_body};
    use fgit_crypto::{
        Digest, DigestAlgorithm, DigestBytes, Identity, IdentityDomain, KeyEpoch, KeyLifecycle,
        KeyScope, RootSecret, SecretKey, sha256_digest,
    };
    use fgit_evidence::{
        EvidenceArtifact, EvidenceContext, EvidenceRecord, EvidenceRecordBody, EvidenceText,
        ReplayCompleteness,
    };
    use fgit_types::EvidenceRecordId;

    struct PresentArtifacts;

    impl ArtifactResolver for PresentArtifacts {
        fn resolve(&self, _artifact: &EvidenceArtifact) -> ArtifactAvailability {
            ArtifactAvailability::Verified
        }
    }

    struct MissingArtifacts;

    impl ArtifactResolver for MissingArtifacts {
        fn resolve(&self, _artifact: &EvidenceArtifact) -> ArtifactAvailability {
            ArtifactAvailability::Missing
        }
    }

    struct MismatchedArtifacts;

    impl ArtifactResolver for MismatchedArtifacts {
        fn resolve(&self, _artifact: &EvidenceArtifact) -> ArtifactAvailability {
            ArtifactAvailability::CommitmentMismatch
        }
    }

    fn text(value: &str) -> EvidenceText {
        EvidenceText::parse("test", value).expect("canonical evidence text")
    }

    fn record() -> EvidenceRecord {
        record_with(b"upstream-log", None)
    }

    fn record_with(artifact_bytes: &[u8], supersedes: Option<EvidenceRecordId>) -> EvidenceRecord {
        let artifact = EvidenceArtifact::new(
            text("artifact:upstream-test-log"),
            Digest::new(
                DigestAlgorithm::Sha256.id(),
                DigestBytes::try_new(&sha256_digest(artifact_bytes)).expect("SHA-256 digest fits"),
            ),
        );
        let context = EvidenceContext::new(
            vec![text("git:upstream-deadbeef")],
            text("source:upstream-v1"),
            text("toolchain:nightly-2026-08-23"),
            text("selection:dependency-update"),
            text("window:upstream-rcr-7"),
            text("policy:upstream-v1"),
            vec![text("assumption:isolated-runner")],
            text("verifier:upstream-independent"),
            vec![artifact],
            text("fallback:local-reverify"),
            ReplayCompleteness::Replayable,
            supersedes,
        )
        .expect("complete evidence context");
        EvidenceRecord::new(
            EvidenceRecordBody::new(
                text("claim:dependency-update-tests"),
                text("scope:dependency:example"),
                ClaimRank::Benchmark,
                ClaimRank::Benchmark,
                context,
            )
            .expect("admissible evidence body"),
        )
        .expect("immutable evidence record")
    }

    fn signing_key() -> SecretKey<Identity> {
        SecretKey::derive(
            &RootSecret::from_bytes([0x42; 32]),
            KeyEpoch::FIRST,
            KeyScope::OPERATOR,
        )
    }

    fn origin(key: &SecretKey<Identity>, trust_domain: &str) -> OriginDescriptor {
        origin_with_lifecycle(key, trust_domain, KeyLifecycle::Active)
    }

    fn origin_with_lifecycle(
        key: &SecretKey<Identity>,
        trust_domain: &str,
        lifecycle: KeyLifecycle,
    ) -> OriginDescriptor {
        origin_with_history(
            trust_domain,
            vec![OriginSigningKey::new(
                key.id().epoch(),
                lifecycle,
                *key.id().commitment(),
                key.verifying_key(),
            )],
        )
    }

    fn origin_with_history(
        trust_domain: &str,
        key_history: Vec<OriginSigningKey>,
    ) -> OriginDescriptor {
        OriginDescriptor::new(
            TrustDomain::parse(trust_domain).expect("canonical trust domain"),
            OriginSigner::parse("identity:upstream-release-bot").expect("canonical signer"),
            key_history,
        )
        .expect("origin descriptor")
    }

    fn origin_key(key: &SecretKey<Identity>, lifecycle: KeyLifecycle) -> OriginSigningKey {
        OriginSigningKey::new(
            key.id().epoch(),
            lifecycle,
            *key.id().commitment(),
            key.verifying_key(),
        )
    }

    fn policy(origin: OriginDescriptor) -> ImportPolicy {
        ImportPolicy::new(vec![origin], ReplayGradePolicy::replayable_only())
            .expect("locally configured origin")
    }

    #[test]
    fn verified_import_stays_foreign_and_respects_local_requirement() {
        let key = signing_key();
        let origin = origin(&key, "trust:upstream-a");
        let bundle = EvidenceExchangeBundle::export(origin.clone(), vec![record()], &key)
            .expect("signed exchange bundle");
        let import_policy = policy(origin.clone());

        let imported = bundle
            .import(&import_policy, &PresentArtifacts, DecodeLimits::DEFAULT)
            .expect("locally verified import");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].origin(), &origin);
        assert_eq!(
            imported[0].replay_completeness(),
            ReplayCompleteness::Replayable
        );
        assert_eq!(
            imported[0].local_use(
                &import_policy,
                LocalEvidenceRequirement::new(
                    ClaimRank::Benchmark,
                    ReplayCompleteness::Replayable,
                    false,
                ),
            ),
            ForeignEvidenceUse::MaySatisfy
        );
        assert_eq!(
            imported[0].local_use(
                &import_policy,
                LocalEvidenceRequirement::new(
                    ClaimRank::Benchmark,
                    ReplayCompleteness::Replayable,
                    true,
                ),
            ),
            ForeignEvidenceUse::SupplementalOnly,
            "foreign evidence must never bypass a local-required check"
        );
    }

    #[test]
    fn records_from_one_exchange_bundle_share_the_signed_source_envelope() {
        let key = signing_key();
        let origin = origin(&key, "trust:upstream-a");
        let bundle = EvidenceExchangeBundle::export(
            origin.clone(),
            vec![record(), record_with(b"second-upstream-log", None)],
            &key,
        )
        .expect("signed bundle with two distinct evidence records");
        let imported = bundle
            .import(&policy(origin), &PresentArtifacts, DecodeLimits::DEFAULT)
            .expect("both records independently verify");

        assert_eq!(imported.len(), 2);
        assert!(std::sync::Arc::ptr_eq(
            &imported[0].source_bundle,
            &imported[1].source_bundle,
        ));
    }

    #[test]
    fn missing_artifact_independently_downgrades_replayable_grade() {
        let key = signing_key();
        let origin = origin(&key, "trust:upstream-a");
        let bundle = EvidenceExchangeBundle::export(origin.clone(), vec![record()], &key)
            .expect("signed exchange bundle");
        let import_policy = policy(origin);

        let imported = bundle
            .import(&import_policy, &MissingArtifacts, DecodeLimits::DEFAULT)
            .expect("missing artifacts downgrade rather than reject the record");
        assert_eq!(
            imported[0].replay_completeness(),
            ReplayCompleteness::VerifiableIfSupplied
        );
        assert_eq!(
            imported[0].local_use(
                &import_policy,
                LocalEvidenceRequirement::new(
                    ClaimRank::Benchmark,
                    ReplayCompleteness::Replayable,
                    false,
                ),
            ),
            ForeignEvidenceUse::SupplementalOnly,
            "a missing artifact cannot retain a replayable satisfaction grade"
        );
    }

    #[test]
    fn re_signed_claim_upgrade_label_is_refused_against_the_immutable_record() {
        let key = signing_key();
        let origin = origin(&key, "trust:upstream-a");
        let bundle = EvidenceExchangeBundle::export(origin.clone(), vec![record()], &key)
            .expect("signed exchange bundle");
        let mut body = decode_body::<ExchangeBundleBody>(bundle.frame(), DecodeLimits::DEFAULT)
            .expect("canonical exchange body");
        body.entries[0].claim_rank = ClaimRank::Invariant;
        let altered_frame = encode_body(&body).expect("canonical relabelled frame");
        let altered_signature = key.sign(
            IdentityDomain::SignedEnvelope,
            ExchangeBundleBody::schema_id(),
            &altered_frame,
        );
        let altered = EvidenceExchangeBundle::from_wire(altered_frame, altered_signature);

        assert!(matches!(
            altered.import(&policy(origin), &PresentArtifacts, DecodeLimits::DEFAULT),
            Err(ExchangeRefusal::ClaimRankLabelMismatch {
                declared: ClaimRank::Invariant,
                recomputed: ClaimRank::Benchmark,
            })
        ));
    }

    #[test]
    fn trust_domain_confusion_is_refused_even_for_the_same_signing_key() {
        let key = signing_key();
        let bundle_origin = origin(&key, "trust:upstream-b");
        let bundle = EvidenceExchangeBundle::export(bundle_origin, vec![record()], &key)
            .expect("signed exchange bundle");

        assert!(matches!(
            bundle.import(
                &policy(origin(&key, "trust:upstream-a")),
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
            ),
            Err(ExchangeRefusal::OriginUntrusted)
        ));
    }

    #[test]
    fn forged_provenance_with_an_unregistered_key_is_refused() {
        let key = signing_key();
        let bundle_origin = origin(&key, "trust:upstream-a");
        let bundle = EvidenceExchangeBundle::export(bundle_origin.clone(), vec![record()], &key)
            .expect("signed exchange bundle");
        let forged_key = SecretKey::<Identity>::derive(
            &RootSecret::from_bytes([0x91; 32]),
            KeyEpoch::FIRST,
            KeyScope::OPERATOR,
        );
        let forged = EvidenceExchangeBundle::from_wire(
            bundle.frame().to_vec(),
            forged_key.sign(
                IdentityDomain::SignedEnvelope,
                ExchangeBundleBody::schema_id(),
                bundle.frame(),
            ),
        );

        assert!(matches!(
            forged.import(
                &policy(bundle_origin),
                &PresentArtifacts,
                DecodeLimits::DEFAULT
            ),
            Err(ExchangeRefusal::SignerKeyCommitmentMismatch)
        ));
    }

    #[test]
    fn replay_against_newer_artifacts_is_refused_on_commitment_mismatch() {
        let key = signing_key();
        let bundle_origin = origin(&key, "trust:upstream-a");
        let bundle = EvidenceExchangeBundle::export(bundle_origin.clone(), vec![record()], &key)
            .expect("signed exchange bundle");

        assert!(matches!(
            bundle.import(
                &policy(bundle_origin),
                &MismatchedArtifacts,
                DecodeLimits::DEFAULT,
            ),
            Err(ExchangeRefusal::ArtifactCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn key_rotation_retains_historical_verification_and_refuses_retired_or_revoked_issuance() {
        let old_key = signing_key();
        let new_key = SecretKey::derive(
            &RootSecret::from_bytes([0x42; 32]),
            KeyEpoch::FIRST.next().expect("second key epoch"),
            KeyScope::OPERATOR,
        );
        let historical_origin = origin_with_history(
            "trust:upstream-a",
            vec![origin_key(&old_key, KeyLifecycle::Active)],
        );
        let historical_bundle =
            EvidenceExchangeBundle::export(historical_origin, vec![record()], &old_key)
                .expect("active epoch may issue historical evidence");
        let rotated_origin = origin_with_history(
            "trust:upstream-a",
            vec![
                origin_key(&old_key, KeyLifecycle::Retired),
                origin_key(&new_key, KeyLifecycle::Active),
            ],
        );
        let rotated_policy = policy(rotated_origin.clone());
        assert!(
            historical_bundle
                .import(&rotated_policy, &PresentArtifacts, DecodeLimits::DEFAULT,)
                .is_ok()
        );

        assert!(matches!(
            EvidenceExchangeBundle::export(rotated_origin.clone(), vec![record()], &old_key),
            Err(ExchangeRefusal::SignerEpochNotIssuable)
        ));
        assert!(EvidenceExchangeBundle::export(rotated_origin, vec![record()], &new_key).is_ok());

        let replacement_key = SecretKey::derive(
            &RootSecret::from_bytes([0x93; 32]),
            KeyEpoch::FIRST,
            KeyScope::OPERATOR,
        );
        let replacement_history = origin_with_history(
            "trust:upstream-a",
            vec![origin_key(&replacement_key, KeyLifecycle::Active)],
        );
        let replacement_bundle =
            EvidenceExchangeBundle::export(replacement_history, vec![record()], &replacement_key)
                .expect("the hostile replacement bundle is structurally valid and signed");
        assert!(matches!(
            replacement_bundle.import(&rotated_policy, &PresentArtifacts, DecodeLimits::DEFAULT,),
            Err(ExchangeRefusal::OriginHistoryMismatch)
        ));

        let revoked_origin =
            origin_with_lifecycle(&old_key, "trust:upstream-a", KeyLifecycle::Revoked);
        assert!(matches!(
            EvidenceExchangeBundle::export(revoked_origin.clone(), vec![record()], &old_key),
            Err(ExchangeRefusal::SignerEpochNotIssuable)
        ));
        let revoked_body = ExchangeBundleBody::new(revoked_origin.clone(), vec![record()])
            .expect("revoked origin remains structurally representable as hostile input");
        let revoked_frame = encode_body(&revoked_body).expect("canonical exchange body");
        let revoked_bundle = EvidenceExchangeBundle::from_wire(
            revoked_frame.clone(),
            old_key.sign(
                IdentityDomain::SignedEnvelope,
                ExchangeBundleBody::schema_id(),
                &revoked_frame,
            ),
        );
        assert!(matches!(
            revoked_bundle.import(
                &policy(revoked_origin),
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
            ),
            Err(ExchangeRefusal::SignerEpochNotVerifiable)
        ));
    }

    #[test]
    fn equivocation_retains_both_signed_successors_and_refuses_later_use() {
        let key = signing_key();
        let bundle_origin = origin(&key, "trust:upstream-a");
        let import_policy = policy(bundle_origin.clone());
        let predecessor = record();
        let first_record = record_with(b"first-successor", Some(predecessor.id()));
        let second_record = record_with(b"second-successor", Some(predecessor.id()));
        let first_bundle =
            EvidenceExchangeBundle::export(bundle_origin.clone(), vec![first_record.clone()], &key)
                .expect("first signed successor");
        let second_bundle = EvidenceExchangeBundle::export(
            bundle_origin.clone(),
            vec![second_record.clone()],
            &key,
        )
        .expect("second signed successor");
        let mut detector = EquivocationDetector::new();

        let first = first_bundle
            .import_with_equivocation_detector(
                &import_policy,
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
                &mut detector,
            )
            .expect("first successor is admissible before a conflict exists");
        assert!(matches!(
            first.as_slice(),
            [EquivocationDecision::Accepted(imported)] if imported.record().id() == first_record.id()
        ));

        let duplicate = first_bundle
            .import_with_equivocation_detector(
                &import_policy,
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
                &mut detector,
            )
            .expect("an exact replay is not a conflicting successor");
        assert!(matches!(
            duplicate.as_slice(),
            [EquivocationDecision::Duplicate(imported)] if imported.record().id() == first_record.id()
        ));

        let second = second_bundle
            .import_with_equivocation_detector(
                &import_policy,
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
                &mut detector,
            )
            .expect("a conflict retains immutable evidence instead of silently overwriting it");
        let [EquivocationDecision::Conflict(conflict)] = second.as_slice() else {
            panic!("second successor must produce exactly one conflict record");
        };
        assert_eq!(conflict.origin(), &bundle_origin);
        assert_eq!(conflict.superseded(), predecessor.id());
        let mut conflict_record_ids = [
            conflict.first().record().id(),
            conflict.second().record().id(),
        ];
        let mut expected_record_ids = [first_record.id(), second_record.id()];
        conflict_record_ids.sort_unstable();
        expected_record_ids.sort_unstable();
        assert_eq!(conflict_record_ids, expected_record_ids);
        assert!(
            (conflict.first().record().id() == first_record.id()
                && conflict.first().source_bundle().frame() == first_bundle.frame())
                || (conflict.first().record().id() == second_record.id()
                    && conflict.first().source_bundle().frame() == second_bundle.frame())
        );
        assert!(
            (conflict.second().record().id() == first_record.id()
                && conflict.second().source_bundle().frame() == first_bundle.frame())
                || (conflict.second().record().id() == second_record.id()
                    && conflict.second().source_bundle().frame() == second_bundle.frame())
        );
        assert_eq!(
            detector
                .conflict_for(&bundle_origin, predecessor.id())
                .expect("detector retains conflict evidence pending durable append"),
            conflict.as_ref()
        );

        let mut reverse_detector = EquivocationDetector::new();
        second_bundle
            .import_with_equivocation_detector(
                &import_policy,
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
                &mut reverse_detector,
            )
            .expect("the other successor is also initially admissible");
        let reverse = first_bundle
            .import_with_equivocation_detector(
                &import_policy,
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
                &mut reverse_detector,
            )
            .expect("reverse arrival order still produces the contradiction");
        let [EquivocationDecision::Conflict(reverse_conflict)] = reverse.as_slice() else {
            panic!("reverse successor must produce exactly one conflict record");
        };
        assert_eq!(
            reverse_conflict, conflict,
            "conflict evidence is canonical rather than arrival-order dependent"
        );

        assert!(matches!(
            first_bundle.import_with_equivocation_detector(
                &import_policy,
                &PresentArtifacts,
                DecodeLimits::DEFAULT,
                &mut detector,
            ),
            Err(ExchangeRefusal::EquivocationPreviouslyObserved { superseded })
                if *superseded == predecessor.id()
        ));
    }
}
