#![forbid(unsafe_code)]
//! Federation and local-first collaboration phase.
//!
//! # The iron law (§23.3 & ADR-0009)
//!
//! Ref authority is NEVER CRDT ambiguity — a remote protected-branch head merges
//! by proposal (immutable observation, mirror-namespace ref, proposed RefTxn with
//! expected basis, equivocation witness, or review item), and local authority
//! decides; last-writer-wins on canonical state is unrepresentable.
//!
//! # CALM-friendly social state (§23.4)
//!
//! Append-only comments, signed attestations, reactions, and some membership sets
//! may replicate without coordination when their algebra and retractions are explicit.
//! Moderation, deletion, permissions, branch protection, billing, and legal hold
//! require local ordered decisions.
//!
//! # Offline reconciliation (§23.5)
//!
//! An exported offline work bundle contains basis capsule/RCR, intents/effects/evidence,
//! and capability constraints. Import ALWAYS revalidates current policy and witnesses;
//! it never assumes that an offline success still applies.
//!
//! # Equivocation and trust (§23.6 & ADR-0009)
//!
//! Federated identities sign events/capsules under versioned key history. Conflicting
//! claims become durable equivocation evidence rather than silently overwriting one
//! another. Trust/reputation may prioritize review but cannot bypass cryptographic
//! identity or local authorization.

use core::fmt;
use std::collections::BTreeMap;

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_crypto::{
    DetachedSignature, DigestHasher, Identity, IdentityDomain, KeyEpoch, KeyPurpose,
    PUBLIC_KEY_BYTES, SIGNATURE_BYTES, SchemaFamily, SchemaId, SecretKey, Sha256Hasher,
    VerifyingKey,
};
use fgit_types::{DomainTag, GitOid};

/// Maximum length of a branch or ref name in federation structures.
pub const MAX_FEDERATION_REF_LEN: usize = 256;
/// Maximum length of a rationale or explanation text.
pub const MAX_FEDERATION_TEXT_LEN: usize = 1024;
/// Maximum number of intents in an offline bundle.
pub const MAX_BUNDLE_INTENTS: usize = 128;
/// Maximum number of effects in an offline bundle.
pub const MAX_BUNDLE_EFFECTS: usize = 256;
/// Maximum number of evidence items in an offline bundle.
pub const MAX_BUNDLE_EVIDENCE: usize = 64;

/// Schema family for federated offline work bundles.
pub const OFFLINE_BUNDLE_SCHEMA_FAMILY: &str = "frankengit.federation-bundle";

/// Schema for federated offline work bundles.
pub const OFFLINE_BUNDLE_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static(OFFLINE_BUNDLE_SCHEMA_FAMILY),
    1,
    0,
);

/// Domain tag for signing federated offline work bundles.
pub const OFFLINE_BUNDLE_DOMAIN: DomainTag =
    DomainTag::from_static("frankengit/federation-bundle/v1");

// =========================================================================
// Peer Identity and Key History
// =========================================================================

/// 32-byte cryptographic identifier for a federated peer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Constructs a `PeerId` from 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Formats the peer ID as a lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            use core::fmt::Write as _;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Parses a 64-character lowercase hex string into a `PeerId`.
    pub fn from_hex(hex: &str) -> Result<Self, FederationRefusal> {
        let trimmed = hex.trim();
        if trimmed.len() != 64 {
            return Err(FederationRefusal::InvalidPeerId {
                reason: "peer ID hex string must be exactly 64 characters",
            });
        }
        let mut bytes = [0_u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let chunk = &trimmed[i * 2..i * 2 + 2];
            *byte =
                u8::from_str_radix(chunk, 16).map_err(|_| FederationRefusal::InvalidPeerId {
                    reason: "invalid hex character in peer ID",
                })?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Operational status of a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerStatus {
    /// Active peer authorized to interact within policy limits.
    Active,
    /// Quarantined peer due to detected equivocation.
    Quarantined {
        /// Rationale for the quarantine.
        reason: String,
        /// Evidence record ID documenting the contradiction.
        evidence_id: EquivocationEvidenceId,
    },
    /// Revoked peer whose keys are permanently invalidated.
    Revoked {
        /// Epoch at which revocation occurred.
        revoked_at_epoch: u64,
    },
}

/// Versioned key history for a peer, tracking active and rotated keys.
#[derive(Clone, Debug, Default)]
pub struct PeerKeyHistory {
    /// Mapping of epoch to verifying key bytes.
    keys: BTreeMap<u64, [u8; PUBLIC_KEY_BYTES]>,
    /// Revocation epoch, if any.
    revoked_at: Option<u64>,
}

impl PeerKeyHistory {
    /// Creates an empty key history.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            revoked_at: None,
        }
    }

    /// Registers a verifying key at a specific epoch.
    pub fn register_key(&mut self, epoch: u64, key: [u8; PUBLIC_KEY_BYTES]) {
        self.keys.insert(epoch, key);
    }

    /// Marks the peer key as revoked from a given epoch forward.
    pub fn revoke(&mut self, epoch: u64) {
        self.revoked_at = Some(epoch);
    }

    /// Retrieves the verifying key for an epoch, checking for revocation.
    pub fn key_for_epoch(&self, epoch: u64) -> Result<VerifyingKey, FederationRefusal> {
        if let Some(rev_epoch) = self.revoked_at {
            if epoch >= rev_epoch {
                return Err(FederationRefusal::PeerKeyRevoked {
                    revoked_at_epoch: rev_epoch,
                });
            }
        }
        self.keys
            .get(&epoch)
            .map(|k| VerifyingKey::from_bytes(*k))
            .ok_or(FederationRefusal::UnknownKeyEpoch { epoch })
    }

    /// Current highest epoch registered.
    #[must_use]
    pub fn latest_epoch(&self) -> Option<u64> {
        self.keys.keys().next_back().copied()
    }
}

// =========================================================================
// CALM Coordination & Federated Event Classes (§23.2 & CALM registry)
// =========================================================================

/// Closed enumeration of federated event classes (§23.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FederatedEventClass {
    /// Immutable Git objects and signed capsules.
    /// Merge is monotone: union of verified content-addressed items.
    ImmutableObjectCapsule,
    /// Mirror namespace reference observations (e.g. `refs/federation/<peer>/...`).
    /// Merge is commutative but bounded per peer.
    MirrorObservation,
    /// Proposed ref transaction (`ProposedRefTxn`).
    /// Requires local authority head CAS decision.
    ProposedRefTxn,
    /// Append-only social events (comments, reactions, signed attestations).
    /// Commutative CRDT merge with explicit retractions.
    SocialEvent,
    /// Moderation, branch protection, permissions, deletion, legal holds.
    /// Requires local coordinated authority head decision.
    ModerationAndProtection,
    /// PR, review, and evidence bundles.
    /// Monotone with authentication: content-addressed signed bundles.
    ReviewAndEvidenceBundle,
    /// Release and package attestations.
    /// Monotone with authentication.
    ReleaseAttestation,
    /// Equivocation evidence (conflicting signed claims from same key).
    /// Monotone with authentication: append-only evidence set.
    EquivocationEvidence,
    /// Offline work bundle import.
    /// Requires local authority head CAS to revalidate basis and apply effects.
    OfflineWorkBundleImport,
}

impl FederatedEventClass {
    /// Exhaustive list of all federated event classes.
    pub const ALL: &'static [Self] = &[
        Self::ImmutableObjectCapsule,
        Self::MirrorObservation,
        Self::ProposedRefTxn,
        Self::SocialEvent,
        Self::ModerationAndProtection,
        Self::ReviewAndEvidenceBundle,
        Self::ReleaseAttestation,
        Self::EquivocationEvidence,
        Self::OfflineWorkBundleImport,
    ];

    /// Returns the required CALM coordination class for this federated event class.
    #[must_use]
    pub const fn coordination_class(self) -> fgit_calm::CoordinationClass {
        match self {
            Self::ImmutableObjectCapsule
            | Self::ReviewAndEvidenceBundle
            | Self::ReleaseAttestation
            | Self::EquivocationEvidence => {
                fgit_calm::CoordinationClass::MonotoneWithAuthentication
            }
            Self::MirrorObservation | Self::SocialEvent => {
                fgit_calm::CoordinationClass::CommutativeButBounded
            }
            Self::ProposedRefTxn
            | Self::ModerationAndProtection
            | Self::OfflineWorkBundleImport => fgit_calm::CoordinationClass::HeadCasRequired,
        }
    }

    /// Whether this event class may replicate coordination-free across peers.
    #[must_use]
    pub const fn is_coordination_free(self) -> bool {
        matches!(
            self.coordination_class(),
            fgit_calm::CoordinationClass::MonotoneWithAuthentication
                | fgit_calm::CoordinationClass::CommutativeButBounded
                | fgit_calm::CoordinationClass::MonotoneScoped
                | fgit_calm::CoordinationClass::LocalDeterministic
        )
    }

    /// Whether this event class requires local authority head CAS.
    #[must_use]
    pub const fn requires_local_authority(self) -> bool {
        matches!(
            self.coordination_class(),
            fgit_calm::CoordinationClass::HeadCasRequired
        )
    }

    /// The exact registry-style operation tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ImmutableObjectCapsule => "immutable_object_capsule",
            Self::MirrorObservation => "mirror_observation",
            Self::ProposedRefTxn => "proposed_ref_txn",
            Self::SocialEvent => "social_event",
            Self::ModerationAndProtection => "moderation_and_protection",
            Self::ReviewAndEvidenceBundle => "review_and_evidence_bundle",
            Self::ReleaseAttestation => "release_attestation",
            Self::EquivocationEvidence => "equivocation_evidence",
            Self::OfflineWorkBundleImport => "offline_work_bundle_import",
        }
    }
}

// =========================================================================
// Canonical vs Mirror Refs (§23.3)
// =========================================================================

/// Canonical reference representing a local protected or authoritative ref
/// (e.g. `refs/heads/main`).
///
/// Can ONLY be updated by local authority head CAS or local admission.
/// Direct writes from remote federation peers are strictly unrepresentable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalRef(String);

impl CanonicalRef {
    /// Parses and validates a canonical ref path.
    pub fn parse(s: &str) -> Result<Self, FederationRefusal> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_FEDERATION_REF_LEN {
            return Err(FederationRefusal::InvalidRefName {
                name: s.to_owned(),
                reason: "reference name must be non-empty and within bounded length",
            });
        }
        if !trimmed.starts_with("refs/heads/") && !trimmed.starts_with("refs/tags/") {
            return Err(FederationRefusal::InvalidRefName {
                name: s.to_owned(),
                reason: "canonical ref must start with refs/heads/ or refs/tags/",
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Borrows the string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A reference in the isolated federated mirror namespace (`refs/federation/<peer>/...`).
///
/// A remote peer's head observations are recorded ONLY in this isolated mirror namespace.
/// It NEVER overwrites or enters `refs/heads/` or `refs/tags/`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MirrorRef {
    peer_id: PeerId,
    branch_name: String,
    tip: GitOid,
    observed_at_generation: u64,
}

impl MirrorRef {
    /// Creates a new mirror reference, ensuring proper namespacing.
    pub fn new(
        peer_id: PeerId,
        branch_name: &str,
        tip: GitOid,
        observed_at_generation: u64,
    ) -> Result<Self, FederationRefusal> {
        let trimmed = branch_name.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_FEDERATION_REF_LEN {
            return Err(FederationRefusal::InvalidRefName {
                name: branch_name.to_owned(),
                reason: "branch name must be non-empty and bounded",
            });
        }
        // Direct remote-head merge into canonical refs is unrepresentable.
        // If caller passes a canonical prefix like "refs/heads/main" intending to target
        // canonical state directly without proposal, reject or sanitize to branch name only.
        let sanitized_branch = if let Some(stripped) = trimmed.strip_prefix("refs/heads/") {
            stripped
        } else if trimmed.starts_with("refs/tags/") || trimmed.starts_with("refs/") {
            return Err(FederationRefusal::CanonicalRefDirectWriteForbidden {
                requested_ref: branch_name.to_owned(),
            });
        } else {
            trimmed
        };

        Ok(Self {
            peer_id,
            branch_name: sanitized_branch.to_owned(),
            tip,
            observed_at_generation,
        })
    }

    /// The observing peer.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The remote branch name.
    #[must_use]
    pub fn branch_name(&self) -> &str {
        &self.branch_name
    }

    /// Observed commit tip.
    #[must_use]
    pub const fn tip(&self) -> GitOid {
        self.tip
    }

    /// Authority generation at which this mirror ref was observed.
    #[must_use]
    pub const fn observed_at_generation(&self) -> u64 {
        self.observed_at_generation
    }

    /// Full git ref path in the mirror namespace.
    /// Format: `refs/federation/<peer_hex>/<branch_name>`
    #[must_use]
    pub fn full_ref_path(&self) -> String {
        format!(
            "refs/federation/{}/{}",
            self.peer_id.to_hex(),
            self.branch_name
        )
    }
}

// =========================================================================
// Proposed Ref Transactions (§23.3)
// =========================================================================

/// Unique 32-byte identifier for a proposed reference transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProposedTxnId([u8; 32]);

impl ProposedTxnId {
    /// Constructs a `ProposedTxnId` from 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A proposal from a remote peer to update a canonical reference.
///
/// Ref authority is never CRDT ambiguity: this does NOT modify the canonical ref.
/// It carries expected basis, candidate proposed tip, and cryptographic signature.
/// Local authority evaluates and decides whether to admit or refuse it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedRefTxn {
    /// Unique proposal identifier.
    pub proposal_id: ProposedTxnId,
    /// Proposing peer.
    pub peer_id: PeerId,
    /// Target canonical reference (e.g. `refs/heads/main`).
    pub target_ref: CanonicalRef,
    /// Expected current tip of the reference before this change.
    pub expected_basis: GitOid,
    /// Candidate tip proposed for the reference.
    pub proposed_tip: GitOid,
    /// Intent identifier backing this proposal.
    pub intent_id: [u8; 32],
    /// Detached signature from the proposing peer.
    pub signature: [u8; SIGNATURE_BYTES],
    /// Rationale or pull-request description.
    pub rationale: String,
}

/// An admitted proposal that has been verified against current local authority
/// and is ready to be submitted to the local authority store CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedProposal {
    /// Proposal identifier.
    pub proposal_id: ProposedTxnId,
    /// Proposing peer.
    pub peer_id: PeerId,
    /// Target reference to update.
    pub target_ref: CanonicalRef,
    /// Verified expected basis.
    pub expected_basis: GitOid,
    /// New candidate tip.
    pub proposed_tip: GitOid,
    /// Local generation at which evaluation occurred.
    pub evaluated_at_generation: u64,
}

impl ProposedRefTxn {
    /// Evaluates this proposal against the current canonical tip of the target ref.
    ///
    /// If current tip does not match `expected_basis`, the proposal is refused
    /// with `FederationRefusal::StagedConflict`.
    pub fn evaluate_against_head(
        &self,
        current_tip: GitOid,
        current_generation: u64,
    ) -> Result<AdmittedProposal, FederationRefusal> {
        if current_tip != self.expected_basis {
            return Err(FederationRefusal::StagedConflict {
                target_ref: self.target_ref.as_str().to_owned(),
                expected: self.expected_basis,
                current: current_tip,
            });
        }

        Ok(AdmittedProposal {
            proposal_id: self.proposal_id,
            peer_id: self.peer_id,
            target_ref: self.target_ref.clone(),
            expected_basis: self.expected_basis,
            proposed_tip: self.proposed_tip,
            evaluated_at_generation: current_generation,
        })
    }
}

// =========================================================================
// Equivocation Detection and Durable Evidence (§23.6 & ADR-0009)
// =========================================================================

/// Unique 32-byte identifier for an equivocation evidence record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EquivocationEvidenceId([u8; 32]);

impl EquivocationEvidenceId {
    /// Constructs an `EquivocationEvidenceId` from 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A signed claim made by a peer about a specific scope (ref, aggregate, or state)
/// at a specific generation or epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedClaim {
    /// Unique claim identifier.
    pub claim_id: [u8; 32],
    /// Proposing peer.
    pub peer_id: PeerId,
    /// Reference or aggregate scope.
    pub scope: String,
    /// Declared generation or sequence number.
    pub generation: u64,
    /// Claimed value or commit tip.
    pub claimed_value: GitOid,
    /// Peer signature.
    pub signature: [u8; SIGNATURE_BYTES],
}

/// Durable evidence proving that a single peer signed contradictory claims
/// for the same scope and generation.
///
/// The system retains BOTH claims and does NOT silently pick a winner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EquivocationEvidence {
    /// Unique evidence identifier derived from the contradictory claims.
    pub evidence_id: EquivocationEvidenceId,
    /// Offending peer.
    pub peer_id: PeerId,
    /// Scope of the contradiction.
    pub scope: String,
    /// Generation at which contradiction occurred.
    pub generation: u64,
    /// The first recorded claim.
    pub first_claim: SignedClaim,
    /// The contradictory second claim.
    pub second_claim: SignedClaim,
    /// Timestamp (tick or epoch) when equivocation was detected.
    pub detected_at_timestamp: u64,
}

/// Routing disposition for equivocation events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewRouting {
    /// Routed to the operator review surface for human / policy inspection.
    ReviewQueue {
        /// Unique queue item identifier.
        queue_item_id: [u8; 32],
        /// Offending peer.
        peer_id: PeerId,
        /// Scope of the contradiction.
        scope: String,
        /// Detailed description for reviewer.
        reason: String,
    },
}

/// Outcome of observing a signed claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationOutcome {
    /// First time seeing a claim for this (peer, scope, generation); recorded.
    ClaimRecorded,
    /// Duplicate identical claim; idempotent no-op.
    DuplicateIgnored,
    /// Equivocation detected: peer signed conflicting claims.
    EquivocationDetected {
        /// Retained durable evidence of equivocation.
        evidence: EquivocationEvidence,
        /// Review queue routing for operator surface.
        review_routing: ReviewRouting,
    },
}

/// Tracks observations per peer to detect equivocation.
#[derive(Default, Debug)]
pub struct EquivocationDetector {
    /// Claims mapped by (peer_id, scope, generation).
    claims: BTreeMap<(PeerId, String, u64), SignedClaim>,
    /// Quarantined peers mapped to their equivocation evidence.
    quarantined: BTreeMap<PeerId, EquivocationEvidence>,
    /// Append-only evidence ledger.
    evidence_ledger: Vec<EquivocationEvidence>,
    /// Operator review queue items.
    review_queue: Vec<ReviewRouting>,
}

impl EquivocationDetector {
    /// Creates a new empty equivocation detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the peer is quarantined.
    #[must_use]
    pub fn is_quarantined(&self, peer_id: &PeerId) -> bool {
        self.quarantined.contains_key(peer_id)
    }

    /// Retrieves quarantine evidence for a peer, if any.
    #[must_use]
    pub fn get_quarantine_evidence(&self, peer_id: &PeerId) -> Option<&EquivocationEvidence> {
        self.quarantined.get(peer_id)
    }

    /// Number of durable equivocation evidence records retained.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_ledger.len()
    }

    /// Immutable view of the review queue.
    #[must_use]
    pub fn review_queue(&self) -> &[ReviewRouting] {
        &self.review_queue
    }

    /// Observes a signed claim.
    ///
    /// If the peer was already quarantined, immediately returns
    /// `Err(FederationRefusal::PeerQuarantined)`.
    ///
    /// If an existing claim for `(peer_id, scope, generation)` contradicts this claim,
    /// equivocation is detected: both claims are preserved in `EquivocationEvidence`,
    /// the peer is quarantined, and the contradiction is routed to review.
    pub fn observe_claim(
        &mut self,
        claim: SignedClaim,
        current_timestamp: u64,
    ) -> Result<ObservationOutcome, FederationRefusal> {
        if let Some(evidence) = self.quarantined.get(&claim.peer_id) {
            return Err(FederationRefusal::PeerQuarantined {
                peer_id: claim.peer_id,
                evidence_id: evidence.evidence_id,
            });
        }

        let key = (claim.peer_id, claim.scope.clone(), claim.generation);
        if let Some(existing) = self.claims.get(&key) {
            if existing.claimed_value == claim.claimed_value {
                return Ok(ObservationOutcome::DuplicateIgnored);
            }

            // Contradiction detected!
            let mut hasher = Sha256Hasher::new();
            hasher.update(b"frankengit.federation.equivocation.v1\0");
            hasher.update(claim.peer_id.as_bytes());
            hasher.update(claim.scope.as_bytes());
            hasher.update(&claim.generation.to_le_bytes());
            hasher.update(existing.claimed_value.as_bytes());
            hasher.update(claim.claimed_value.as_bytes());
            let evidence_digest = hasher.finish();

            let evidence_id = EquivocationEvidenceId::from_bytes(evidence_digest);
            let evidence = EquivocationEvidence {
                evidence_id,
                peer_id: claim.peer_id,
                scope: claim.scope.clone(),
                generation: claim.generation,
                first_claim: existing.clone(),
                second_claim: claim.clone(),
                detected_at_timestamp: current_timestamp,
            };

            let mut routing_hasher = Sha256Hasher::new();
            routing_hasher.update(b"frankengit.federation.review_route.v1\0");
            routing_hasher.update(evidence_id.as_bytes());
            let route_id = routing_hasher.finish();

            let review_routing = ReviewRouting::ReviewQueue {
                queue_item_id: route_id,
                peer_id: claim.peer_id,
                scope: claim.scope,
                reason: format!(
                    "Peer {} signed contradictory claims at generation {}: {} vs {}",
                    claim.peer_id.to_hex(),
                    claim.generation,
                    existing.claimed_value,
                    claim.claimed_value
                ),
            };

            self.quarantined.insert(claim.peer_id, evidence.clone());
            self.evidence_ledger.push(evidence.clone());
            self.review_queue.push(review_routing.clone());

            Ok(ObservationOutcome::EquivocationDetected {
                evidence,
                review_routing,
            })
        } else {
            self.claims.insert(key, claim);
            Ok(ObservationOutcome::ClaimRecorded)
        }
    }
}

// =========================================================================
// Offline Work Bundle (§23.1, §23.5)
// =========================================================================

/// Basis capsule against which offline work was performed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasisCapsule {
    /// Capsule identifier.
    pub capsule_id: [u8; 32],
    /// Repository identifier.
    pub repo_id: [u8; 32],
    /// Authority head generation when exported.
    pub head_generation: u64,
    /// Authority head tip commit when exported.
    pub head_tip: GitOid,
    /// Root snapshot commitment.
    pub snapshot_root: [u8; 32],
}

/// Offline intent variants supported in an export bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfflineIntent {
    /// Proposed update to a reference.
    ProposedRefChange {
        /// Target canonical ref name (e.g. `refs/heads/main`).
        target_ref: String,
        /// Expected tip of the target ref in the basis.
        expected_basis: GitOid,
        /// Proposed new tip.
        proposed_tip: GitOid,
    },
    /// An append-only social comment or discussion item.
    AppendSocialComment {
        /// Topic or thread identifier.
        topic: String,
        /// Content digest.
        content_digest: [u8; 32],
        /// Authoring peer.
        author: PeerId,
    },
    /// A pull request review attestation.
    ReviewAttestation {
        /// PR number.
        pull_request_number: u64,
        /// Decision tag (e.g. "approved", "changes_requested").
        decision_tag: String,
        /// Review body digest.
        review_digest: [u8; 32],
    },
}

/// An immutable Git object or blob effect carried in the bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineEffect {
    /// Effect identifier.
    pub effect_id: [u8; 32],
    /// Git object ID.
    pub object_id: GitOid,
    /// Byte length of the object payload.
    pub byte_length: u64,
}

/// An evidence artifact carried in the bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineEvidence {
    /// Evidence identifier.
    pub evidence_id: [u8; 32],
    /// Declared claim class.
    pub claim_class: String,
    /// Evidence payload bytes.
    pub payload: Vec<u8>,
}

/// Signed immutable offline work bundle (§23.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineWorkBundle {
    /// Unique bundle digest.
    pub bundle_id: [u8; 32],
    /// Peer who authored and signed this bundle.
    pub peer_id: PeerId,
    /// Basis capsule this work was computed against.
    pub basis_capsule: BasisCapsule,
    /// Proposed intents.
    pub intents: Vec<OfflineIntent>,
    /// Embedded effect descriptors.
    pub effects: Vec<OfflineEffect>,
    /// Carried evidence records.
    pub evidence: Vec<OfflineEvidence>,
    /// Detached cryptographic signature over canonical payload.
    pub signature: DetachedSignature,
}

impl CanonicalBody for OfflineWorkBundle {
    const DOMAIN: DomainTag = OFFLINE_BUNDLE_DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("frankengit.federation-bundle");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_bytes("bundle_id", &self.bundle_id)?;
        out.write_bytes("peer_id", self.peer_id.as_bytes())?;

        // Basis capsule
        out.write_bytes("basis_capsule.capsule_id", &self.basis_capsule.capsule_id)?;
        out.write_bytes("basis_capsule.repo_id", &self.basis_capsule.repo_id)?;
        out.write_scalar(self.basis_capsule.head_generation);
        out.write_git_oid(&self.basis_capsule.head_tip);
        out.write_bytes(
            "basis_capsule.snapshot_root",
            &self.basis_capsule.snapshot_root,
        )?;

        // Intents
        out.write_scalar(u32::try_from(self.intents.len()).map_err(|_| {
            CodecRefusal::LengthBoundExceeded {
                field: "intents_count",
                observed: self.intents.len() as u64,
                limit: MAX_BUNDLE_INTENTS as u64,
            }
        })?);
        for intent in &self.intents {
            match intent {
                OfflineIntent::ProposedRefChange {
                    target_ref,
                    expected_basis,
                    proposed_tip,
                } => {
                    out.write_scalar(1_u8);
                    out.write_bytes("target_ref", target_ref.as_bytes())?;
                    out.write_git_oid(expected_basis);
                    out.write_git_oid(proposed_tip);
                }
                OfflineIntent::AppendSocialComment {
                    topic,
                    content_digest,
                    author,
                } => {
                    out.write_scalar(2_u8);
                    out.write_bytes("topic", topic.as_bytes())?;
                    out.write_bytes("content_digest", content_digest)?;
                    out.write_bytes("author", author.as_bytes())?;
                }
                OfflineIntent::ReviewAttestation {
                    pull_request_number,
                    decision_tag,
                    review_digest,
                } => {
                    out.write_scalar(3_u8);
                    out.write_scalar(*pull_request_number);
                    out.write_bytes("decision_tag", decision_tag.as_bytes())?;
                    out.write_bytes("review_digest", review_digest)?;
                }
            }
        }

        // Effects
        out.write_scalar(u32::try_from(self.effects.len()).map_err(|_| {
            CodecRefusal::LengthBoundExceeded {
                field: "effects_count",
                observed: self.effects.len() as u64,
                limit: MAX_BUNDLE_EFFECTS as u64,
            }
        })?);
        for effect in &self.effects {
            out.write_bytes("effect_id", &effect.effect_id)?;
            out.write_git_oid(&effect.object_id);
            out.write_scalar(effect.byte_length);
        }

        // Evidence
        out.write_scalar(u32::try_from(self.evidence.len()).map_err(|_| {
            CodecRefusal::LengthBoundExceeded {
                field: "evidence_count",
                observed: self.evidence.len() as u64,
                limit: MAX_BUNDLE_EVIDENCE as u64,
            }
        })?);
        for ev in &self.evidence {
            out.write_bytes("evidence_id", &ev.evidence_id)?;
            out.write_bytes("claim_class", ev.claim_class.as_bytes())?;
            out.write_bytes("payload", &ev.payload)?;
        }

        // Signature
        out.write_scalar(self.signature.scheme());
        out.write_scalar(self.signature.purpose().code_point());
        out.write_scalar(self.signature.epoch().get());
        out.write_bytes("signature.key_commitment", self.signature.key_commitment())?;
        out.write_bytes(
            "signature.verifying_key",
            self.signature.declared_verifying_key().as_bytes(),
        )?;
        out.write_bytes("signature.signature", self.signature.signature())?;
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let bundle_id_bytes = input.read_bytes("bundle_id")?;
        let mut bundle_id = [0_u8; 32];
        bundle_id.copy_from_slice(bundle_id_bytes);

        let peer_bytes = input.read_bytes("peer_id")?;
        let mut peer_arr = [0_u8; 32];
        peer_arr.copy_from_slice(peer_bytes);
        let peer_id = PeerId::from_bytes(peer_arr);

        // Basis capsule
        let cap_bytes = input.read_bytes("basis_capsule.capsule_id")?;
        let mut capsule_id = [0_u8; 32];
        capsule_id.copy_from_slice(cap_bytes);

        let repo_bytes = input.read_bytes("basis_capsule.repo_id")?;
        let mut repo_id = [0_u8; 32];
        repo_id.copy_from_slice(repo_bytes);

        let head_generation = input.read_scalar::<u64>("basis_capsule.head_generation")?;
        let head_tip = input.read_git_oid()?;

        let snap_bytes = input.read_bytes("basis_capsule.snapshot_root")?;
        let mut snapshot_root = [0_u8; 32];
        snapshot_root.copy_from_slice(snap_bytes);

        let basis_capsule = BasisCapsule {
            capsule_id,
            repo_id,
            head_generation,
            head_tip,
            snapshot_root,
        };

        // Intents
        let intents_count = input.read_scalar::<u32>("intents_count")? as usize;
        if intents_count > MAX_BUNDLE_INTENTS {
            return Err(CodecRefusal::LengthBoundExceeded {
                field: "intents_count",
                observed: intents_count as u64,
                limit: MAX_BUNDLE_INTENTS as u64,
            });
        }
        let mut intents = Vec::with_capacity(intents_count);
        for _ in 0..intents_count {
            let tag = input.read_raw_byte("intent_tag")?;
            match tag {
                1 => {
                    let target_ref_bytes = input.read_bytes("target_ref")?;
                    let target_ref =
                        String::from_utf8(target_ref_bytes.to_vec()).map_err(|_| {
                            CodecRefusal::TextNotUtf8 {
                                field: "target_ref",
                                offset: input.offset(),
                            }
                        })?;
                    let expected_basis = input.read_git_oid()?;
                    let proposed_tip = input.read_git_oid()?;
                    intents.push(OfflineIntent::ProposedRefChange {
                        target_ref,
                        expected_basis,
                        proposed_tip,
                    });
                }
                2 => {
                    let topic_bytes = input.read_bytes("topic")?;
                    let topic = String::from_utf8(topic_bytes.to_vec()).map_err(|_| {
                        CodecRefusal::TextNotUtf8 {
                            field: "topic",
                            offset: input.offset(),
                        }
                    })?;
                    let digest_bytes = input.read_bytes("content_digest")?;
                    let mut content_digest = [0_u8; 32];
                    content_digest.copy_from_slice(digest_bytes);

                    let author_bytes = input.read_bytes("author")?;
                    let mut author_arr = [0_u8; 32];
                    author_arr.copy_from_slice(author_bytes);
                    intents.push(OfflineIntent::AppendSocialComment {
                        topic,
                        content_digest,
                        author: PeerId::from_bytes(author_arr),
                    });
                }
                3 => {
                    let pull_request_number = input.read_scalar::<u64>("pull_request_number")?;
                    let tag_bytes = input.read_bytes("decision_tag")?;
                    let decision_tag = String::from_utf8(tag_bytes.to_vec()).map_err(|_| {
                        CodecRefusal::TextNotUtf8 {
                            field: "decision_tag",
                            offset: input.offset(),
                        }
                    })?;
                    let digest_bytes = input.read_bytes("review_digest")?;
                    let mut review_digest = [0_u8; 32];
                    review_digest.copy_from_slice(digest_bytes);
                    intents.push(OfflineIntent::ReviewAttestation {
                        pull_request_number,
                        decision_tag,
                        review_digest,
                    });
                }
                unknown => {
                    return Err(CodecRefusal::VariantUnknown {
                        field: "intent_tag",
                        observed: unknown as u32,
                        offset: input.offset(),
                    });
                }
            }
        }

        // Effects
        let effects_count = input.read_scalar::<u32>("effects_count")? as usize;
        if effects_count > MAX_BUNDLE_EFFECTS {
            return Err(CodecRefusal::LengthBoundExceeded {
                field: "effects_count",
                observed: effects_count as u64,
                limit: MAX_BUNDLE_EFFECTS as u64,
            });
        }
        let mut effects = Vec::with_capacity(effects_count);
        for _ in 0..effects_count {
            let eff_bytes = input.read_bytes("effect_id")?;
            let mut effect_id = [0_u8; 32];
            effect_id.copy_from_slice(eff_bytes);
            let object_id = input.read_git_oid()?;
            let byte_length = input.read_scalar::<u64>("byte_length")?;
            effects.push(OfflineEffect {
                effect_id,
                object_id,
                byte_length,
            });
        }

        // Evidence
        let evidence_count = input.read_scalar::<u32>("evidence_count")? as usize;
        if evidence_count > MAX_BUNDLE_EVIDENCE {
            return Err(CodecRefusal::LengthBoundExceeded {
                field: "evidence_count",
                observed: evidence_count as u64,
                limit: MAX_BUNDLE_EVIDENCE as u64,
            });
        }
        let mut evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            let ev_bytes = input.read_bytes("evidence_id")?;
            let mut evidence_id = [0_u8; 32];
            evidence_id.copy_from_slice(ev_bytes);
            let class_bytes = input.read_bytes("claim_class")?;
            let claim_class =
                String::from_utf8(class_bytes.to_vec()).map_err(|_| CodecRefusal::TextNotUtf8 {
                    field: "claim_class",
                    offset: input.offset(),
                })?;
            let payload = input.read_bytes("payload")?.to_vec();
            evidence.push(OfflineEvidence {
                evidence_id,
                claim_class,
                payload,
            });
        }

        // Signature
        let scheme = input.read_scalar::<u16>("signature.scheme")?;
        let purpose_code = input.read_scalar::<u16>("signature.purpose")?;
        let purpose =
            KeyPurpose::from_code_point(purpose_code).ok_or(CodecRefusal::VariantUnknown {
                field: "signature.purpose",
                observed: purpose_code as u32,
                offset: input.offset(),
            })?;
        let epoch_val = input.read_scalar::<u32>("signature.epoch")?;
        let epoch = KeyEpoch::new(epoch_val).ok_or(CodecRefusal::VariantUnknown {
            field: "signature.epoch",
            observed: epoch_val,
            offset: input.offset(),
        })?;
        let comm_bytes = input.read_bytes("signature.key_commitment")?;
        let mut key_commitment = [0_u8; 32];
        key_commitment.copy_from_slice(comm_bytes);

        let vk_bytes = input.read_bytes("signature.verifying_key")?;
        let mut verifying_key = [0_u8; PUBLIC_KEY_BYTES];
        verifying_key.copy_from_slice(vk_bytes);

        let sig_bytes = input.read_bytes("signature.signature")?;
        let mut sig_arr = [0_u8; SIGNATURE_BYTES];
        sig_arr.copy_from_slice(sig_bytes);

        let signature = DetachedSignature::from_parts(
            scheme,
            purpose,
            epoch,
            key_commitment,
            verifying_key,
            sig_arr,
        );

        Ok(Self {
            bundle_id,
            peer_id,
            basis_capsule,
            intents,
            effects,
            evidence,
            signature,
        })
    }
}

/// Signer interface for producing signed offline bundles.
pub struct OfflineSigner<'a> {
    secret_key: &'a SecretKey<Identity>,
    epoch: KeyEpoch,
}

impl<'a> OfflineSigner<'a> {
    /// Creates a new `OfflineSigner` wrapping a secret key and epoch.
    #[must_use]
    pub const fn new(secret_key: &'a SecretKey<Identity>, epoch: KeyEpoch) -> Self {
        Self { secret_key, epoch }
    }

    /// Verifying key corresponding to this signer.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.secret_key.verifying_key()
    }

    /// Key epoch.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// Signs pre-image bytes under the `IdentityDomain::SignedEnvelope` domain.
    #[must_use]
    pub fn sign_bytes(&self, body: &[u8]) -> DetachedSignature {
        self.secret_key
            .sign(IdentityDomain::SignedEnvelope, OFFLINE_BUNDLE_SCHEMA, body)
    }
}

/// Creates a signed offline work bundle against a basis capsule.
pub fn create_offline_bundle(
    basis_capsule: BasisCapsule,
    peer_id: PeerId,
    signer: &OfflineSigner<'_>,
    intents: Vec<OfflineIntent>,
    effects: Vec<OfflineEffect>,
    evidence: Vec<OfflineEvidence>,
) -> Result<OfflineWorkBundle, FederationRefusal> {
    if intents.is_empty() && effects.is_empty() && evidence.is_empty() {
        return Err(FederationRefusal::EmptyBundle);
    }
    if intents.len() > MAX_BUNDLE_INTENTS {
        return Err(FederationRefusal::PayloadTooLarge {
            limit: MAX_BUNDLE_INTENTS,
            observed: intents.len(),
        });
    }
    if effects.len() > MAX_BUNDLE_EFFECTS {
        return Err(FederationRefusal::PayloadTooLarge {
            limit: MAX_BUNDLE_EFFECTS,
            observed: effects.len(),
        });
    }
    if evidence.len() > MAX_BUNDLE_EVIDENCE {
        return Err(FederationRefusal::PayloadTooLarge {
            limit: MAX_BUNDLE_EVIDENCE,
            observed: evidence.len(),
        });
    }

    // Compute canonical digest of the bundle content before signature
    let mut hasher = Sha256Hasher::new();
    hasher.update(OFFLINE_BUNDLE_DOMAIN.as_bytes());
    hasher.update(peer_id.as_bytes());
    hasher.update(&basis_capsule.capsule_id);
    hasher.update(&basis_capsule.repo_id);
    hasher.update(&basis_capsule.head_generation.to_le_bytes());
    hasher.update(basis_capsule.head_tip.as_bytes());
    hasher.update(&basis_capsule.snapshot_root);

    for intent in &intents {
        match intent {
            OfflineIntent::ProposedRefChange {
                target_ref,
                expected_basis,
                proposed_tip,
            } => {
                hasher.update(&[1]);
                hasher.update(target_ref.as_bytes());
                hasher.update(expected_basis.as_bytes());
                hasher.update(proposed_tip.as_bytes());
            }
            OfflineIntent::AppendSocialComment {
                topic,
                content_digest,
                author,
            } => {
                hasher.update(&[2]);
                hasher.update(topic.as_bytes());
                hasher.update(content_digest);
                hasher.update(author.as_bytes());
            }
            OfflineIntent::ReviewAttestation {
                pull_request_number,
                decision_tag,
                review_digest,
            } => {
                hasher.update(&[3]);
                hasher.update(&pull_request_number.to_le_bytes());
                hasher.update(decision_tag.as_bytes());
                hasher.update(review_digest);
            }
        }
    }

    for effect in &effects {
        hasher.update(&effect.effect_id);
        hasher.update(effect.object_id.as_bytes());
        hasher.update(&effect.byte_length.to_le_bytes());
    }

    for ev in &evidence {
        hasher.update(&ev.evidence_id);
        hasher.update(ev.claim_class.as_bytes());
        hasher.update(&ev.payload);
    }

    let bundle_id = hasher.finish();

    // Sign the bundle digest
    let signature = signer.sign_bytes(&bundle_id);

    Ok(OfflineWorkBundle {
        bundle_id,
        peer_id,
        basis_capsule,
        intents,
        effects,
        evidence,
        signature,
    })
}

/// Represents the current local repository authority state during import revalidation.
#[derive(Clone, Debug)]
pub struct CurrentAuthorityState {
    /// Local authority head generation.
    pub head_generation: u64,
    /// Current head tip commit.
    pub head_tip: GitOid,
    /// Current ref tips mapped by canonical ref name.
    pub refs: BTreeMap<String, GitOid>,
}

/// Receipt returned on successful bundle import and revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportReceipt {
    /// Identifier of the imported bundle.
    pub bundle_id: [u8; 32],
    /// Proposing peer.
    pub peer_id: PeerId,
    /// Admitted proposals evaluated against current authority.
    pub admitted_proposals: Vec<AdmittedProposal>,
    /// Updated mirror namespace references.
    pub admitted_mirror_refs: Vec<MirrorRef>,
    /// Coordination-free social events admitted to local append log.
    pub admitted_social_events: Vec<OfflineIntent>,
    /// Carried evidence records retained.
    pub retained_evidence: Vec<OfflineEvidence>,
    /// Local generation at which import was admitted.
    pub imported_at_generation: u64,
}

/// Imports and revalidates an offline work bundle online (§23.5).
///
/// # Acceptance condition
///
/// "Import revalidates current policy and witnesses; it never assumes that an
/// offline success still applies."
///
/// Revalidation catches staged conflicts: if any ref expected in the basis has
/// moved on the local head, returns `Err(FederationRefusal::StagedConflict)`.
pub fn import_offline_bundle(
    bundle: &OfflineWorkBundle,
    current_head: &CurrentAuthorityState,
    detector: &mut EquivocationDetector,
    key_history: &PeerKeyHistory,
) -> Result<ImportReceipt, FederationRefusal> {
    // 1. Quarantined peer check
    if let Some(evidence) = detector.get_quarantine_evidence(&bundle.peer_id) {
        return Err(FederationRefusal::PeerQuarantined {
            peer_id: bundle.peer_id,
            evidence_id: evidence.evidence_id,
        });
    }

    // 2. Cryptographic signature check
    let verifying_key = key_history.key_for_epoch(0).or_else(|_| {
        // If epoch 0 not found, try latest epoch
        if let Some(epoch) = key_history.latest_epoch() {
            key_history.key_for_epoch(epoch)
        } else {
            Err(FederationRefusal::UnknownPeer {
                peer_id: bundle.peer_id,
            })
        }
    })?;

    bundle
        .signature
        .verify_with(
            &verifying_key,
            IdentityDomain::SignedEnvelope,
            OFFLINE_BUNDLE_SCHEMA,
            &bundle.bundle_id,
        )
        .map_err(|_| FederationRefusal::InvalidSignature)?;

    // 3. Authority revalidation against current head
    let mut admitted_proposals = Vec::new();
    let mut admitted_mirror_refs = Vec::new();
    let mut admitted_social_events = Vec::new();

    for intent in &bundle.intents {
        match intent {
            OfflineIntent::ProposedRefChange {
                target_ref,
                expected_basis,
                proposed_tip,
            } => {
                let canonical_ref = CanonicalRef::parse(target_ref)?;
                let current_tip = current_head
                    .refs
                    .get(target_ref)
                    .copied()
                    .unwrap_or(current_head.head_tip);

                // REVALIDATION: staged conflict check!
                if current_tip != *expected_basis {
                    return Err(FederationRefusal::StagedConflict {
                        target_ref: target_ref.clone(),
                        expected: *expected_basis,
                        current: current_tip,
                    });
                }

                // Proposal is admitted for local authority head CAS
                let mut prop_hasher = Sha256Hasher::new();
                prop_hasher.update(bundle.bundle_id.as_slice());
                prop_hasher.update(target_ref.as_bytes());
                prop_hasher.update(proposed_tip.as_bytes());
                let proposal_id = ProposedTxnId::from_bytes(prop_hasher.finish());

                admitted_proposals.push(AdmittedProposal {
                    proposal_id,
                    peer_id: bundle.peer_id,
                    target_ref: canonical_ref,
                    expected_basis: *expected_basis,
                    proposed_tip: *proposed_tip,
                    evaluated_at_generation: current_head.head_generation,
                });

                // Also update the peer's isolated mirror ref
                let mirror_ref = MirrorRef::new(
                    bundle.peer_id,
                    target_ref,
                    *proposed_tip,
                    current_head.head_generation,
                )?;
                admitted_mirror_refs.push(mirror_ref);
            }
            OfflineIntent::AppendSocialComment { .. } | OfflineIntent::ReviewAttestation { .. } => {
                // Social events are coordination-free / CRDT bounded
                admitted_social_events.push(intent.clone());
            }
        }
    }

    Ok(ImportReceipt {
        bundle_id: bundle.bundle_id,
        peer_id: bundle.peer_id,
        admitted_proposals,
        admitted_mirror_refs,
        admitted_social_events,
        retained_evidence: bundle.evidence.clone(),
        imported_at_generation: current_head.head_generation,
    })
}

// =========================================================================
// Typed Refusals
// =========================================================================

/// Typed refusal reasons for federation operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederationRefusal {
    /// Remote write directly into canonical refs (`refs/heads/*`, `refs/tags/*`) is forbidden.
    CanonicalRefDirectWriteForbidden {
        /// Attempted destination ref.
        requested_ref: String,
    },
    /// Revalidation detected that current authority head tip does not match expected basis.
    StagedConflict {
        /// Conflicting target ref.
        target_ref: String,
        /// Expected basis commit.
        expected: GitOid,
        /// Current live commit on authority head.
        current: GitOid,
    },
    /// Expected generation has been superseded.
    StaleBasis {
        /// Basis generation.
        expected_generation: u64,
        /// Current live generation.
        current_generation: u64,
    },
    /// Detached cryptographic signature is invalid or forged.
    InvalidSignature,
    /// Peer is quarantined due to detected equivocation evidence.
    PeerQuarantined {
        /// Quarantined peer.
        peer_id: PeerId,
        /// Equivocation evidence record ID.
        evidence_id: EquivocationEvidenceId,
    },
    /// Peer's signing key has been revoked.
    PeerKeyRevoked {
        /// Revocation epoch.
        revoked_at_epoch: u64,
    },
    /// Key epoch is unknown in peer history.
    UnknownKeyEpoch {
        /// Missing epoch.
        epoch: u64,
    },
    /// Peer is unknown to local configuration.
    UnknownPeer {
        /// Unknown peer.
        peer_id: PeerId,
    },
    /// Malformed or invalid peer identifier.
    InvalidPeerId {
        /// Explanation.
        reason: &'static str,
    },
    /// Reference name format is invalid.
    InvalidRefName {
        /// Ref name.
        name: String,
        /// Explanation.
        reason: &'static str,
    },
    /// Offline bundle contains zero intents, effects, and evidence.
    EmptyBundle,
    /// Payload exceeds bounded capacity limits.
    PayloadTooLarge {
        /// Allowed ceiling.
        limit: usize,
        /// Observed count.
        observed: usize,
    },
    /// Codec error during encoding or decoding.
    CodecError(CodecRefusal),
}

impl From<CodecRefusal> for FederationRefusal {
    fn from(error: CodecRefusal) -> Self {
        Self::CodecError(error)
    }
}

impl fmt::Display for FederationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalRefDirectWriteForbidden { requested_ref } => write!(
                formatter,
                "direct write to canonical ref `{requested_ref}` is forbidden; remote heads must use mirror refs or proposed RefTxn"
            ),
            Self::StagedConflict {
                target_ref,
                expected,
                current,
            } => write!(
                formatter,
                "staged conflict on `{target_ref}`: expected basis `{expected}`, but current head is `{current}`"
            ),
            Self::StaleBasis {
                expected_generation,
                current_generation,
            } => write!(
                formatter,
                "stale basis generation: expected `{expected_generation}`, current is `{current_generation}`"
            ),
            Self::InvalidSignature => {
                formatter.write_str("cryptographic detached signature failed verification")
            }
            Self::PeerQuarantined {
                peer_id,
                evidence_id: _,
            } => write!(
                formatter,
                "peer `{}` is quarantined due to equivocation",
                peer_id.to_hex()
            ),
            Self::PeerKeyRevoked { revoked_at_epoch } => {
                write!(
                    formatter,
                    "peer key was revoked at epoch {revoked_at_epoch}"
                )
            }
            Self::UnknownKeyEpoch { epoch } => write!(formatter, "unknown key epoch {epoch}"),
            Self::UnknownPeer { peer_id } => {
                write!(formatter, "peer `{}` is not recognized", peer_id.to_hex())
            }
            Self::InvalidPeerId { reason } => write!(formatter, "invalid peer ID: {reason}"),
            Self::InvalidRefName { name, reason } => {
                write!(formatter, "invalid reference name `{name}`: {reason}")
            }
            Self::EmptyBundle => formatter.write_str(
                "offline bundle must contain at least one intent, effect, or evidence item",
            ),
            Self::PayloadTooLarge { limit, observed } => write!(
                formatter,
                "bundle payload exceeds capacity limit: limit={limit}, observed={observed}"
            ),
            Self::CodecError(err) => write!(formatter, "codec error: {err}"),
        }
    }
}
