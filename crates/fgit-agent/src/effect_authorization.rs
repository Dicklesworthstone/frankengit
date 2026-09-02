//! Effect-time capability-chain verification, revocation freshness, and broker gating.
//!
//! Capability attenuation and authenticators prove that a presented leaf was
//! issued through one non-widening ancestry. They do not prove that none of the
//! links has since been revoked. `docs/AGENT_PROTOCOL.md` section 6.3 requires
//! high-value effects to make that second decision at effect time against a
//! named canonical repository position with an explicit freshness bound.
//!
//! This module provides that missing boundary without inventing a second source
//! of repository authority:
//!
//! 1. [`VerifiedCapabilityChain`] authenticates and bounds the complete ancestry;
//! 2. [`CapabilityRevocationReceipt`] binds a bounded revocation read to the
//!    exact authenticated authority event and complete Intent Run;
//! 3. [`CapabilityEffectAuthorization`] commits one fresh, non-revoked chain to
//!    one exact high-value [`crate::EffectRequest`]; and
//! 4. [`RevocationCheckedEffectBroker`] owns the underlying broker and exposes no
//!    raw high-value request path that can skip this proof.
//!
//! Revocation data remains derived policy evidence. It can refuse an effect, but
//! it cannot publish repository state, mint a capability, or move authority.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{
    RegionCloseOutcome, RegionId, ReleaseReceipt, ResourceError, ResourceVector,
    kinds::OutboxDispatch,
};
use fgit_types::{Digest, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::{
    AgentInstanceId, AuthorityReadIdentityRefusal, AuthorityReadReceipt, AuthorityReadReceiptId,
    BrokerRefusal, Capability, CapabilityId, ChainRefused, EffectBroker, EffectGrant, EffectId,
    EffectJournalEntry, EffectRecord, EffectRequest, IntentRun, IntentRunCommitment,
    IntentRunIdentityRefusal, LogicalTime, OperationClass, OutboxReservationRefused,
    ReservedOutboxEffect, RunId, SealedCapability, verify_chain,
};

/// Maximum revocation rows accepted in one authenticated-position read.
pub const MAX_CAPABILITY_REVOCATIONS: usize = 4_096;
/// Maximum authenticated links accepted in one high-value capability chain.
pub const MAX_EFFECT_CAPABILITY_CHAIN: usize = 64;
/// Maximum high-value authorizations retained by one checked broker.
pub const MAX_EFFECT_AUTHORIZATIONS: usize = 4_096;

const REVOCATION_REQUEST_DOMAIN: &[u8] = b"frankengit.agent.capability-revocation-request/v1\0";
const REVOCATION_RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.capability-revocation-receipt/v1\0";
const VERIFIED_CHAIN_DOMAIN: &[u8] = b"frankengit.agent.verified-capability-chain/v1\0";
const EFFECT_AUTHORIZATION_DOMAIN: &[u8] = b"frankengit.agent.capability-effect-authorization/v1\0";

/// Stable identity of one bounded revocation read request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityRevocationReadRequestId([u8; 32]);

impl CapabilityRevocationReadRequestId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CapabilityRevocationReadRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capability-revocation-request:")?;
        write_hex(formatter, &self.0)
    }
}

/// Stable identity of one admitted revocation snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityRevocationReceiptId([u8; 32]);

impl CapabilityRevocationReceiptId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CapabilityRevocationReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capability-revocations:")?;
        write_hex(formatter, &self.0)
    }
}

/// Stable identity of one verified capability ancestry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerifiedCapabilityChainId([u8; 32]);

impl VerifiedCapabilityChainId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for VerifiedCapabilityChainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("verified-capability-chain:")?;
        write_hex(formatter, &self.0)
    }
}

/// Stable identity of one exact effect-time authorization.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityEffectAuthorizationId([u8; 32]);

impl CapabilityEffectAuthorizationId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CapabilityEffectAuthorizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capability-effect-authorization:")?;
        write_hex(formatter, &self.0)
    }
}

/// Bounded request for revocations interpreted at one authenticated position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationReadRequest {
    request_id: CapabilityRevocationReadRequestId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    repository_id: RepositoryId,
    authority_head_id: RepositoryAuthorityHeadId,
    authority_head_generation: HeadGeneration,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: u32,
}

impl CapabilityRevocationReadRequest {
    /// Builds one exact-read, complete-run-bound revocation request.
    ///
    /// # Errors
    ///
    /// Refuses a legacy or substituted run, observation before authority
    /// verification, an expired run, zero/excessive row limits, zero freshness,
    /// and canonical framing failures.
    pub fn build(
        authority: &AuthorityReadReceipt,
        run: &IntentRun,
        requested_at: LogicalTime,
        max_age: u64,
        max_entries: usize,
    ) -> Result<Self, CapabilityRevocationReadRefusal> {
        if max_age == 0 {
            return Err(CapabilityRevocationReadRefusal::ZeroMaxAge);
        }
        if max_entries == 0 || max_entries > MAX_CAPABILITY_REVOCATIONS {
            return Err(CapabilityRevocationReadRefusal::InvalidRowLimit {
                observed: max_entries,
                limit: MAX_CAPABILITY_REVOCATIONS,
            });
        }
        if requested_at < authority.verified_at_logical_time() {
            return Err(
                CapabilityRevocationReadRefusal::RequestBeforeAuthorityVerification {
                    requested_at,
                    verified_at: authority.verified_at_logical_time(),
                },
            );
        }
        let run_authority = run
            .authority_read_receipt()
            .ok_or(CapabilityRevocationReadRefusal::RunAuthorityReceiptRequired)?;
        if run_authority != authority {
            return Err(CapabilityRevocationReadRefusal::RunAuthorityMismatch);
        }
        if !run.is_open_at(requested_at) {
            return Err(CapabilityRevocationReadRefusal::RunExpired {
                expires_at: run.expiry(),
                observed_at: requested_at,
            });
        }
        let authority_read_receipt_id = authority.receipt_id()?;
        let run_commitment = run.commitment()?;
        let max_entries = u32::try_from(max_entries).map_err(|_| {
            CapabilityRevocationReadRefusal::InvalidRowLimit {
                observed: max_entries,
                limit: MAX_CAPABILITY_REVOCATIONS,
            }
        })?;
        let mut request = Self {
            request_id: CapabilityRevocationReadRequestId([0; 32]),
            authority_read_receipt_id,
            repository_id: authority.repository_id(),
            authority_head_id: authority.authority_head_id(),
            authority_head_generation: authority.authority_head_generation(),
            run_id: run.run_id(),
            run_commitment,
            requested_at,
            max_age,
            max_entries,
        };
        request.request_id =
            CapabilityRevocationReadRequestId(revocation_request_commitment(&request)?);
        Ok(request)
    }

    /// Stable request identity.
    #[must_use]
    pub const fn request_id(self) -> CapabilityRevocationReadRequestId {
        self.request_id
    }

    /// Exact authenticated read event used as the basis.
    #[must_use]
    pub const fn authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Repository whose policy state is queried.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Authenticated head identity naming the revocation interpretation point.
    #[must_use]
    pub const fn authority_head_id(self) -> RepositoryAuthorityHeadId {
        self.authority_head_id
    }

    /// Authenticated head generation naming the interpretation point.
    #[must_use]
    pub const fn authority_head_generation(self) -> HeadGeneration {
        self.authority_head_generation
    }

    /// Coordination identity of the requesting run.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Complete machine identity of the requesting run.
    #[must_use]
    pub const fn run_commitment(self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Logical request instant.
    #[must_use]
    pub const fn requested_at(self) -> LogicalTime {
        self.requested_at
    }

    /// Maximum age admitted for the resulting read.
    #[must_use]
    pub const fn max_age(self) -> u64 {
        self.max_age
    }

    /// Maximum number of revoked identities admitted.
    #[must_use]
    pub const fn max_entries(self) -> u32 {
        self.max_entries
    }
}

/// Untrusted adapter result for one revocation read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationReadObservation {
    request_id: CapabilityRevocationReadRequestId,
    revocation_generation: [u8; 32],
    observed_at: LogicalTime,
    revoked_capability_ids: Vec<CapabilityId>,
    evidence_root: Digest,
}

impl CapabilityRevocationReadObservation {
    /// Creates one adapter observation. It remains untrusted until admitted.
    #[must_use]
    pub const fn new(
        request_id: CapabilityRevocationReadRequestId,
        revocation_generation: [u8; 32],
        observed_at: LogicalTime,
        revoked_capability_ids: Vec<CapabilityId>,
        evidence_root: Digest,
    ) -> Self {
        Self {
            request_id,
            revocation_generation,
            observed_at,
            revoked_capability_ids,
            evidence_root,
        }
    }

    /// Request the adapter claims to have answered.
    #[must_use]
    pub const fn request_id(&self) -> CapabilityRevocationReadRequestId {
        self.request_id
    }

    /// Derived revocation-generation commitment.
    #[must_use]
    pub const fn revocation_generation(&self) -> [u8; 32] {
        self.revocation_generation
    }

    /// Logical read instant.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Revoked identities before canonicalization and admission.
    #[must_use]
    pub fn revoked_capability_ids(&self) -> &[CapabilityId] {
        &self.revoked_capability_ids
    }

    /// Evidence supporting the read and decoding result.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }
}

/// Storage-neutral reader for one named-position revocation generation.
pub trait CapabilityRevocationReader {
    /// Stable reader/decoder/verifier implementation profile.
    fn reader_profile(&self) -> [u8; 32];

    /// Reads no more than the request's declared hard ceiling.
    fn read(
        &mut self,
        request: &CapabilityRevocationReadRequest,
    ) -> Result<CapabilityRevocationReadObservation, CapabilityRevocationReadAdapterRefusal>;
}

/// Immutable, bounded revocation evidence for one exact run and authority read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationReceipt {
    receipt_id: CapabilityRevocationReceiptId,
    request_id: CapabilityRevocationReadRequestId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    authority_read_receipt: AuthorityReadReceipt,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    revocation_generation: [u8; 32],
    observed_at: LogicalTime,
    valid_until: LogicalTime,
    revoked_capability_ids: Vec<CapabilityId>,
    reader_profile: [u8; 32],
    evidence_root: Digest,
}

impl CapabilityRevocationReceipt {
    /// Stable receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> CapabilityRevocationReceiptId {
        self.receipt_id
    }

    /// Request answered by this receipt.
    #[must_use]
    pub const fn request_id(&self) -> CapabilityRevocationReadRequestId {
        self.request_id
    }

    /// Exact authenticated read event used as the interpretation basis.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Complete authenticated read event retained as provenance.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// Coordination identity of the run that requested the read.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Complete run identity bound to this revocation read.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Derived generation of the revocation projection.
    #[must_use]
    pub const fn revocation_generation(&self) -> [u8; 32] {
        self.revocation_generation
    }

    /// Logical instant of the revocation read.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Exclusive freshness deadline.
    #[must_use]
    pub const fn valid_until(&self) -> LogicalTime {
        self.valid_until
    }

    /// Canonically sorted revoked capability identities.
    #[must_use]
    pub fn revoked_capability_ids(&self) -> &[CapabilityId] {
        &self.revoked_capability_ids
    }

    /// Reader/decoder/verifier profile.
    #[must_use]
    pub const fn reader_profile(&self) -> [u8; 32] {
        self.reader_profile
    }

    /// Evidence supporting the read and decoding result.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Whether this receipt is usable at the supplied effect instant.
    #[must_use]
    pub const fn is_fresh_at(&self, now: LogicalTime) -> bool {
        self.observed_at.value() <= now.value() && now.value() < self.valid_until.value()
    }

    /// Whether one ancestry identity was revoked at this projection generation.
    #[must_use]
    pub fn is_revoked(&self, capability_id: CapabilityId) -> bool {
        self.revoked_capability_ids
            .binary_search(&capability_id)
            .is_ok()
    }
}

/// Executes one bounded read and admits only a request-matched observation.
///
/// # Errors
///
/// Refuses request construction, zero reader identity, adapter refusal,
/// request/generation/time/row inconsistencies, duplicate revocations, expired
/// runs, freshness overflow, and canonical framing failures.
pub fn read_capability_revocations<R: CapabilityRevocationReader>(
    reader: &mut R,
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
) -> Result<CapabilityRevocationReceipt, CapabilityRevocationReadRefusal> {
    let request =
        CapabilityRevocationReadRequest::build(authority, run, requested_at, max_age, max_entries)?;
    let reader_profile = reader.reader_profile();
    if is_zero(&reader_profile) {
        return Err(CapabilityRevocationReadRefusal::ZeroReaderProfile);
    }
    let mut observation = reader.read(&request)?;
    if observation.request_id != request.request_id {
        return Err(
            CapabilityRevocationReadRefusal::ObservationRequestMismatch {
                expected: request.request_id,
                observed: observation.request_id,
            },
        );
    }
    if is_zero(&observation.revocation_generation) {
        return Err(CapabilityRevocationReadRefusal::ZeroRevocationGeneration);
    }
    if observation.observed_at < request.requested_at {
        return Err(CapabilityRevocationReadRefusal::ObservationTimeRollback {
            requested_at: request.requested_at,
            observed_at: observation.observed_at,
        });
    }
    if !run.is_open_at(observation.observed_at) {
        return Err(CapabilityRevocationReadRefusal::RunExpired {
            expires_at: run.expiry(),
            observed_at: observation.observed_at,
        });
    }
    let observed_rows = observation.revoked_capability_ids.len();
    if observed_rows > request.max_entries as usize || observed_rows > MAX_CAPABILITY_REVOCATIONS {
        return Err(CapabilityRevocationReadRefusal::TooManyRevocations {
            observed: observed_rows,
            request_limit: request.max_entries,
            hard_limit: MAX_CAPABILITY_REVOCATIONS,
        });
    }
    observation.revoked_capability_ids.sort_unstable();
    for adjacent in observation.revoked_capability_ids.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(CapabilityRevocationReadRefusal::DuplicateRevocation {
                capability_id: adjacent[0],
            });
        }
    }
    let freshness_end = observation
        .observed_at
        .value()
        .checked_add(request.max_age)
        .ok_or(CapabilityRevocationReadRefusal::FreshnessOverflow {
            observed_at: observation.observed_at,
            max_age: request.max_age,
        })?;
    let valid_until = LogicalTime::new(freshness_end.min(run.expiry().value()));
    if valid_until <= observation.observed_at {
        return Err(CapabilityRevocationReadRefusal::RunExpired {
            expires_at: run.expiry(),
            observed_at: observation.observed_at,
        });
    }

    let mut receipt = CapabilityRevocationReceipt {
        receipt_id: CapabilityRevocationReceiptId([0; 32]),
        request_id: request.request_id,
        authority_read_receipt_id: request.authority_read_receipt_id,
        authority_read_receipt: authority.clone(),
        run_id: request.run_id,
        run_commitment: request.run_commitment,
        revocation_generation: observation.revocation_generation,
        observed_at: observation.observed_at,
        valid_until,
        revoked_capability_ids: observation.revoked_capability_ids,
        reader_profile,
        evidence_root: observation.evidence_root,
    };
    receipt.receipt_id = CapabilityRevocationReceiptId(revocation_receipt_commitment(&receipt)?);
    Ok(receipt)
}

/// One cryptographically verified, bounded, root-first capability ancestry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCapabilityChain {
    chain_id: VerifiedCapabilityChainId,
    capability_ids: Vec<CapabilityId>,
    leaf: Capability,
}

impl VerifiedCapabilityChain {
    /// Verifies authenticators, ancestry, and attenuation before retaining the
    /// chain identity.
    ///
    /// # Errors
    ///
    /// Refuses an empty issuer key, an excessive chain before cryptographic
    /// work, any ordinary chain-verification failure, duplicate capability IDs,
    /// and canonical framing failures.
    pub fn verify(
        chain: &[SealedCapability],
        issuer_key: &[u8],
    ) -> Result<Self, VerifiedCapabilityChainRefusal> {
        if issuer_key.is_empty() {
            return Err(VerifiedCapabilityChainRefusal::EmptyIssuerKey);
        }
        if chain.len() > MAX_EFFECT_CAPABILITY_CHAIN {
            return Err(VerifiedCapabilityChainRefusal::TooManyLinks {
                observed: chain.len(),
                limit: MAX_EFFECT_CAPABILITY_CHAIN,
            });
        }
        let leaf = verify_chain(chain, issuer_key)?;
        let mut capability_ids = Vec::with_capacity(chain.len());
        for link in chain {
            let capability_id = link.capability().id();
            if capability_ids.contains(&capability_id) {
                return Err(VerifiedCapabilityChainRefusal::DuplicateCapabilityId {
                    capability_id,
                });
            }
            capability_ids.push(capability_id);
        }
        let chain_id = VerifiedCapabilityChainId(verified_chain_commitment(chain)?);
        Ok(Self {
            chain_id,
            capability_ids,
            leaf,
        })
    }

    /// Stable verified-chain identity.
    #[must_use]
    pub const fn chain_id(&self) -> VerifiedCapabilityChainId {
        self.chain_id
    }

    /// Root-first capability identities.
    #[must_use]
    pub fn capability_ids(&self) -> &[CapabilityId] {
        &self.capability_ids
    }

    /// Verified leaf capability presented to the effect broker.
    #[must_use]
    pub const fn leaf(&self) -> &Capability {
        &self.leaf
    }
}

/// Immutable authorization of one exact high-value effect request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityEffectAuthorization {
    authorization_id: CapabilityEffectAuthorizationId,
    revocation_receipt_id: CapabilityRevocationReceiptId,
    verified_chain_id: VerifiedCapabilityChainId,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    capability_id: CapabilityId,
    effect_id: EffectId,
    parent_effect_id: Option<EffectId>,
    operation: OperationClass,
    cost: ResourceVector,
    input_commitment: [u8; 32],
    authorized_at: LogicalTime,
    valid_until: LogicalTime,
}

impl CapabilityEffectAuthorization {
    /// Authorizes one request against a fresh named-position revocation read.
    ///
    /// # Errors
    ///
    /// Refuses low-risk operations, legacy or substituted runs, stale policy
    /// evidence, revoked ancestry, run/capability scope or quota violations,
    /// invalid lifetimes, and canonical framing failures.
    pub fn authorize(
        run: &IntentRun,
        chain: &VerifiedCapabilityChain,
        revocations: &CapabilityRevocationReceipt,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<Self, CapabilityEffectAuthorizationRefusal> {
        if !requires_effect_time_revocation(request.operation) {
            return Err(
                CapabilityEffectAuthorizationRefusal::OperationDoesNotRequireRevocation {
                    operation: request.operation,
                },
            );
        }
        let run_authority = run
            .authority_read_receipt()
            .ok_or(CapabilityEffectAuthorizationRefusal::RunAuthorityReceiptRequired)?;
        let run_commitment = run.commitment()?;
        if run.run_id() != revocations.run_id {
            return Err(CapabilityEffectAuthorizationRefusal::RunIdMismatch {
                expected: revocations.run_id,
                observed: run.run_id(),
            });
        }
        if run_commitment != revocations.run_commitment {
            return Err(
                CapabilityEffectAuthorizationRefusal::RunCommitmentMismatch {
                    expected: revocations.run_commitment,
                    observed: run_commitment,
                },
            );
        }
        if run_authority != &revocations.authority_read_receipt
            || run_authority.receipt_id()? != revocations.authority_read_receipt_id
        {
            return Err(CapabilityEffectAuthorizationRefusal::AuthorityMismatch);
        }
        if now < revocations.observed_at {
            return Err(
                CapabilityEffectAuthorizationRefusal::AuthorizationTimeRollback {
                    revocations_observed_at: revocations.observed_at,
                    authorized_at: now,
                },
            );
        }
        if !revocations.is_fresh_at(now) {
            return Err(CapabilityEffectAuthorizationRefusal::RevocationReadStale {
                observed_at: revocations.observed_at,
                valid_until: revocations.valid_until,
                authorized_at: now,
            });
        }
        if !run.is_open_at(now) {
            return Err(CapabilityEffectAuthorizationRefusal::RunExpired {
                expires_at: run.expiry(),
                authorized_at: now,
            });
        }
        let leaf = chain.leaf();
        if !leaf.is_valid_at(now) {
            return Err(CapabilityEffectAuthorizationRefusal::CapabilityNotValid {
                not_before: leaf.not_before(),
                expires_at: leaf.expires_at(),
                authorized_at: now,
            });
        }
        for (index, capability_id) in chain.capability_ids.iter().copied().enumerate() {
            if revocations.is_revoked(capability_id) {
                return Err(CapabilityEffectAuthorizationRefusal::CapabilityRevoked {
                    capability_id,
                    chain_index: index,
                    revocation_generation: revocations.revocation_generation,
                });
            }
        }
        let run_operations = run.allowed_operation_classes();
        if !run_operations.contains(request.operation) {
            return Err(CapabilityEffectAuthorizationRefusal::OperationOutsideRun {
                operation: request.operation,
            });
        }
        let capability_operations = leaf.operations();
        if !capability_operations.contains(request.operation) {
            return Err(
                CapabilityEffectAuthorizationRefusal::OperationOutsideCapability {
                    operation: request.operation,
                },
            );
        }
        if let Some(deficit) = leaf.quota().first_deficit(&request.cost) {
            return Err(CapabilityEffectAuthorizationRefusal::CapabilityQuotaExceeded { deficit });
        }

        let valid_until = LogicalTime::new(
            revocations
                .valid_until
                .value()
                .min(run.expiry().value())
                .min(leaf.expires_at().value()),
        );
        if valid_until <= now {
            return Err(
                CapabilityEffectAuthorizationRefusal::AuthorizationWindowEmpty {
                    authorized_at: now,
                    valid_until,
                },
            );
        }
        let mut authorization = Self {
            authorization_id: CapabilityEffectAuthorizationId([0; 32]),
            revocation_receipt_id: revocations.receipt_id,
            verified_chain_id: chain.chain_id,
            run_id: run.run_id(),
            run_commitment,
            capability_id: leaf.id(),
            effect_id: request.effect_id,
            parent_effect_id: request.parent_effect_id,
            operation: request.operation,
            cost: request.cost,
            input_commitment: request.input_commitment,
            authorized_at: now,
            valid_until,
        };
        authorization.authorization_id =
            CapabilityEffectAuthorizationId(effect_authorization_commitment(&authorization)?);
        Ok(authorization)
    }

    /// Stable authorization identity.
    #[must_use]
    pub const fn authorization_id(self) -> CapabilityEffectAuthorizationId {
        self.authorization_id
    }

    /// Revocation read used for this effect.
    #[must_use]
    pub const fn revocation_receipt_id(self) -> CapabilityRevocationReceiptId {
        self.revocation_receipt_id
    }

    /// Verified ancestry used for this effect.
    #[must_use]
    pub const fn verified_chain_id(self) -> VerifiedCapabilityChainId {
        self.verified_chain_id
    }

    /// Complete run identity used for authorization.
    #[must_use]
    pub const fn run_commitment(self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Verified leaf capability.
    #[must_use]
    pub const fn capability_id(self) -> CapabilityId {
        self.capability_id
    }

    /// Coordination identity of the authorized run.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Exact effect request authorized.
    #[must_use]
    pub const fn effect_id(self) -> EffectId {
        self.effect_id
    }

    /// Logical authorization instant.
    #[must_use]
    pub const fn authorized_at(self) -> LogicalTime {
        self.authorized_at
    }

    /// Exclusive deadline after which this proof cannot start an effect.
    #[must_use]
    pub const fn valid_until(self) -> LogicalTime {
        self.valid_until
    }
}

/// An accepted effect paired with the proof that made its high-value request
/// admissible.
#[must_use = "an authorized effect still owns a broker budget reservation"]
#[derive(Debug)]
pub struct RevocationAuthorizedEffectGrant {
    authorization: CapabilityEffectAuthorization,
    grant: EffectGrant,
}

impl RevocationAuthorizedEffectGrant {
    /// Effect-time authorization retained with the live grant.
    #[must_use]
    pub const fn authorization(&self) -> CapabilityEffectAuthorization {
        self.authorization
    }

    /// Broker record produced by the same request.
    #[must_use]
    pub const fn record(&self) -> &EffectRecord {
        self.grant.record()
    }
}

/// Broker facade whose high-value request method cannot omit revocation proof.
#[derive(Debug)]
pub struct RevocationCheckedEffectBroker {
    run: IntentRun,
    run_commitment: IntentRunCommitment,
    broker: EffectBroker,
    authorizations: Vec<CapabilityEffectAuthorization>,
}

impl RevocationCheckedEffectBroker {
    /// Opens the facade and binds the exact run used by the owned broker.
    ///
    /// # Errors
    ///
    /// Refuses a run whose complete machine identity cannot be committed.
    pub fn open(
        run: IntentRun,
        region: RegionId,
        agent_instance_id: AgentInstanceId,
    ) -> Result<Self, RevocationCheckedEffectRefusal> {
        let run_commitment = run.commitment()?;
        let broker = EffectBroker::open(run.clone(), region, agent_instance_id);
        Ok(Self {
            run,
            run_commitment,
            broker,
            authorizations: Vec::new(),
        })
    }

    /// Requests an operation outside the high-value set.
    ///
    /// High-value operations fail closed here rather than falling through to
    /// the raw broker path.
    pub fn request_low_risk(
        &mut self,
        capability: &Capability,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<EffectGrant, RevocationCheckedEffectRefusal> {
        if requires_effect_time_revocation(request.operation) {
            return Err(RevocationCheckedEffectRefusal::RevocationEvidenceRequired {
                operation: request.operation,
            });
        }
        self.broker
            .request(capability, now, request)
            .map_err(RevocationCheckedEffectRefusal::Broker)
    }

    /// Verifies and requests one high-value effect in a single facade call.
    ///
    /// The authorization is appended only after the owned broker accepts the
    /// exact request. A refusal therefore retains neither a misleading effect
    /// record nor a misleading authorization record.
    pub fn request_high_value(
        &mut self,
        chain: &VerifiedCapabilityChain,
        revocations: &CapabilityRevocationReceipt,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<RevocationAuthorizedEffectGrant, RevocationCheckedEffectRefusal> {
        if !requires_effect_time_revocation(request.operation) {
            return Err(RevocationCheckedEffectRefusal::HighValueOperationRequired {
                operation: request.operation,
            });
        }
        if self.authorizations.len() >= MAX_EFFECT_AUTHORIZATIONS {
            return Err(RevocationCheckedEffectRefusal::AuthorizationLimitExceeded {
                limit: MAX_EFFECT_AUTHORIZATIONS,
            });
        }
        let authorization =
            CapabilityEffectAuthorization::authorize(&self.run, chain, revocations, now, request)?;
        if authorization.run_commitment != self.run_commitment {
            return Err(
                RevocationCheckedEffectRefusal::BrokerRunCommitmentMismatch {
                    expected: self.run_commitment,
                    observed: authorization.run_commitment,
                },
            );
        }
        let grant = self
            .broker
            .request(chain.leaf(), now, request)
            .map_err(RevocationCheckedEffectRefusal::Broker)?;
        self.authorizations.push(authorization);
        Ok(RevocationAuthorizedEffectGrant {
            authorization,
            grant,
        })
    }

    /// Aborts a low-risk grant before it becomes a typed obligation.
    pub fn abort_low_risk(
        &mut self,
        grant: EffectGrant,
    ) -> Result<ReleaseReceipt, RevocationCheckedEffectRefusal> {
        self.broker
            .abort(grant)
            .map_err(RevocationCheckedEffectRefusal::Journal)
    }

    /// Aborts a high-value grant while preserving its authorization in the
    /// facade's append-only evidence list.
    pub fn abort_high_value(
        &mut self,
        grant: RevocationAuthorizedEffectGrant,
    ) -> Result<ReleaseReceipt, RevocationCheckedEffectRefusal> {
        self.broker
            .abort(grant.grant)
            .map_err(RevocationCheckedEffectRefusal::Journal)
    }

    /// Converts an authorized external effect into the ordinary typed outbox
    /// obligation without exposing the underlying raw broker.
    pub fn reserve_authorized_outbox(
        &mut self,
        grant: RevocationAuthorizedEffectGrant,
        dispatch: OutboxDispatch,
    ) -> Result<ReservedOutboxEffect, AuthorizedOutboxReservationRefused> {
        let authorization = grant.authorization;
        self.broker
            .reserve_outbox(grant.grant, dispatch)
            .map_err(|source| AuthorizedOutboxReservationRefused {
                authorization,
                source,
            })
    }

    /// Accepted broker records in acceptance order.
    #[must_use]
    pub fn records(&self) -> Vec<EffectRecord> {
        self.broker.records()
    }

    /// Successful high-value authorizations in acceptance order.
    #[must_use]
    pub fn authorizations(&self) -> &[CapabilityEffectAuthorization] {
        &self.authorizations
    }

    /// Underlying append-only effect journal, without a mutable broker handle.
    #[must_use]
    pub fn journal(&self) -> Vec<EffectJournalEntry> {
        self.broker.journal()
    }

    /// Closes the owned broker region and reports any leaked responsibility.
    pub fn close(self) -> RegionCloseOutcome {
        self.broker.close()
    }
}

/// Outbox-conversion refusal retaining the exact authorization and, when the
/// broker still owns a grant, a recoverable authorized grant.
#[must_use]
#[derive(Debug)]
pub struct AuthorizedOutboxReservationRefused {
    authorization: CapabilityEffectAuthorization,
    source: OutboxReservationRefused,
}

impl AuthorizedOutboxReservationRefused {
    /// Effect-time authorization that preceded the conversion attempt.
    #[must_use]
    pub const fn authorization(&self) -> CapabilityEffectAuthorization {
        self.authorization
    }

    /// Ordinary broker refusal.
    #[must_use]
    pub const fn source(&self) -> &OutboxReservationRefused {
        &self.source
    }

    /// Recovers a still-live grant when the ordinary refusal retained one.
    #[must_use]
    pub fn into_authorized_grant(self) -> Option<RevocationAuthorizedEffectGrant> {
        self.source
            .into_grant()
            .map(|grant| RevocationAuthorizedEffectGrant {
                authorization: self.authorization,
                grant,
            })
    }
}

impl fmt::Display for AuthorizedOutboxReservationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authorized outbox reservation refused: {}",
            self.source
        )
    }
}

impl core::error::Error for AuthorizedOutboxReservationRefused {}

/// Whether an operation must pass the named-position revocation gate.
#[must_use]
pub const fn requires_effect_time_revocation(operation: OperationClass) -> bool {
    matches!(
        operation,
        OperationClass::ExecuteSandboxedProcess
            | OperationClass::NetworkDestination
            | OperationClass::SecretHandle
            | OperationClass::ExternalIntegration
            | OperationClass::PreparePublication
            | OperationClass::SubmitEvidence
            | OperationClass::MutateForgeEntity
            | OperationClass::DelegateSubIntent
    )
}

/// Backend-specific refusal while reading the derived revocation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRevocationReadAdapterRefusal {
    /// The requested named-position projection is unavailable.
    Unavailable {
        /// Evidence explaining why it could not be produced.
        evidence_root: Digest,
    },
    /// The backend found bytes but could not decode or authenticate them.
    Invalid {
        /// Evidence identifying the failed input and verifier result.
        evidence_root: Digest,
    },
}

impl fmt::Display for CapabilityRevocationReadAdapterRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability revocation adapter refused: {self:?}")
    }
}

impl core::error::Error for CapabilityRevocationReadAdapterRefusal {}

/// Why a revocation read failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRevocationReadRefusal {
    /// Freshness must have a nonzero bound.
    ZeroMaxAge,
    /// Row bound was zero or exceeded the hard limit.
    InvalidRowLimit {
        /// Bound supplied.
        observed: usize,
        /// Hard limit.
        limit: usize,
    },
    /// The request predates authority authentication.
    RequestBeforeAuthorityVerification {
        /// Proposed request instant.
        requested_at: LogicalTime,
        /// Authority verification instant.
        verified_at: LogicalTime,
    },
    /// High-value reads require a complete authenticated run.
    RunAuthorityReceiptRequired,
    /// Run and request carry different exact authority receipts.
    RunAuthorityMismatch,
    /// Run was no longer open for the request or observation.
    RunExpired {
        /// Exclusive run expiry.
        expires_at: LogicalTime,
        /// Instant checked.
        observed_at: LogicalTime,
    },
    /// Reader profile used the reserved all-zero identity.
    ZeroReaderProfile,
    /// Adapter refused the read.
    Adapter(CapabilityRevocationReadAdapterRefusal),
    /// Adapter answered another request.
    ObservationRequestMismatch {
        /// Expected request.
        expected: CapabilityRevocationReadRequestId,
        /// Observed request.
        observed: CapabilityRevocationReadRequestId,
    },
    /// Derived generation used the reserved all-zero identity.
    ZeroRevocationGeneration,
    /// Adapter observation predates the request.
    ObservationTimeRollback {
        /// Request instant.
        requested_at: LogicalTime,
        /// Observation instant.
        observed_at: LogicalTime,
    },
    /// Adapter returned more revocations than admitted.
    TooManyRevocations {
        /// Rows returned.
        observed: usize,
        /// Per-request bound.
        request_limit: u32,
        /// System hard bound.
        hard_limit: usize,
    },
    /// One revoked identity appeared more than once.
    DuplicateRevocation {
        /// Repeated identity.
        capability_id: CapabilityId,
    },
    /// Observation plus maximum age overflowed logical time.
    FreshnessOverflow {
        /// Observation instant.
        observed_at: LogicalTime,
        /// Requested maximum age.
        max_age: u64,
    },
    /// Exact authenticated-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Complete run identity failed.
    RunIdentity(IntentRunIdentityRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for CapabilityRevocationReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability revocation read refused: {self:?}")
    }
}

impl core::error::Error for CapabilityRevocationReadRefusal {}

impl From<CapabilityRevocationReadAdapterRefusal> for CapabilityRevocationReadRefusal {
    fn from(value: CapabilityRevocationReadAdapterRefusal) -> Self {
        Self::Adapter(value)
    }
}

impl From<AuthorityReadIdentityRefusal> for CapabilityRevocationReadRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<IntentRunIdentityRefusal> for CapabilityRevocationReadRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for CapabilityRevocationReadRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Why capability ancestry verification failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedCapabilityChainRefusal {
    /// The verifier was invoked with no issuer key material.
    EmptyIssuerKey,
    /// Chain length exceeded the effect-time hard limit.
    TooManyLinks {
        /// Links supplied.
        observed: usize,
        /// Hard limit.
        limit: usize,
    },
    /// The same capability identity appeared twice in one ancestry.
    DuplicateCapabilityId {
        /// Repeated identity.
        capability_id: CapabilityId,
    },
    /// Ordinary authenticator, ancestry, or attenuation verification failed.
    Chain(ChainRefused),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for VerifiedCapabilityChainRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability-chain verification refused: {self:?}")
    }
}

impl core::error::Error for VerifiedCapabilityChainRefusal {}

impl From<ChainRefused> for VerifiedCapabilityChainRefusal {
    fn from(value: ChainRefused) -> Self {
        Self::Chain(value)
    }
}

impl From<CodecRefusal> for VerifiedCapabilityChainRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Why one exact effect could not receive a fresh non-revoked authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityEffectAuthorizationRefusal {
    /// This low-risk operation belongs on the ordinary broker path.
    OperationDoesNotRequireRevocation {
        /// Operation supplied.
        operation: OperationClass,
    },
    /// High-value authorization requires an authenticated run.
    RunAuthorityReceiptRequired,
    /// Revocation read belongs to another run ID.
    RunIdMismatch {
        /// Receipt run.
        expected: RunId,
        /// Supplied run.
        observed: RunId,
    },
    /// Revocation read belongs to another complete run.
    RunCommitmentMismatch {
        /// Receipt run commitment.
        expected: IntentRunCommitment,
        /// Supplied run commitment.
        observed: IntentRunCommitment,
    },
    /// Run and revocation read use different authenticated positions/events.
    AuthorityMismatch,
    /// Authorization instant predates the revocation read.
    AuthorizationTimeRollback {
        /// Revocation read instant.
        revocations_observed_at: LogicalTime,
        /// Proposed authorization instant.
        authorized_at: LogicalTime,
    },
    /// Revocation read exceeded its explicit maximum age.
    RevocationReadStale {
        /// Read instant.
        observed_at: LogicalTime,
        /// Exclusive freshness deadline.
        valid_until: LogicalTime,
        /// Proposed authorization instant.
        authorized_at: LogicalTime,
    },
    /// Run expired before the effect authorization.
    RunExpired {
        /// Exclusive run expiry.
        expires_at: LogicalTime,
        /// Proposed authorization instant.
        authorized_at: LogicalTime,
    },
    /// Verified leaf is not valid at the effect instant.
    CapabilityNotValid {
        /// Inclusive validity start.
        not_before: LogicalTime,
        /// Exclusive validity end.
        expires_at: LogicalTime,
        /// Proposed authorization instant.
        authorized_at: LogicalTime,
    },
    /// One link in the verified ancestry is revoked.
    CapabilityRevoked {
        /// Revoked identity.
        capability_id: CapabilityId,
        /// Root-first position in the chain.
        chain_index: usize,
        /// Revocation generation that named it.
        revocation_generation: [u8; 32],
    },
    /// Run does not authorize the requested operation.
    OperationOutsideRun {
        /// Requested operation.
        operation: OperationClass,
    },
    /// Verified leaf does not authorize the requested operation.
    OperationOutsideCapability {
        /// Requested operation.
        operation: OperationClass,
    },
    /// Request cost exceeds the verified leaf quota.
    CapabilityQuotaExceeded {
        /// First deficient grade.
        deficit: ResourceError,
    },
    /// Combined freshness/run/capability deadline is not after authorization.
    AuthorizationWindowEmpty {
        /// Authorization instant.
        authorized_at: LogicalTime,
        /// Derived exclusive deadline.
        valid_until: LogicalTime,
    },
    /// Exact authenticated-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Complete run identity failed.
    RunIdentity(IntentRunIdentityRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for CapabilityEffectAuthorizationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capability effect authorization refused: {self:?}"
        )
    }
}

impl core::error::Error for CapabilityEffectAuthorizationRefusal {}

impl From<AuthorityReadIdentityRefusal> for CapabilityEffectAuthorizationRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<IntentRunIdentityRefusal> for CapabilityEffectAuthorizationRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for CapabilityEffectAuthorizationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Why the checked broker facade refused a request or lifecycle operation.
#[derive(Debug)]
pub enum RevocationCheckedEffectRefusal {
    /// High-value operation was sent to the unproved path.
    RevocationEvidenceRequired {
        /// Operation requiring proof.
        operation: OperationClass,
    },
    /// Low-risk operation was sent to the high-value path.
    HighValueOperationRequired {
        /// Operation supplied.
        operation: OperationClass,
    },
    /// Per-broker authorization journal reached its hard bound.
    AuthorizationLimitExceeded {
        /// Hard limit.
        limit: usize,
    },
    /// Facade and authorization disagree about the complete run.
    BrokerRunCommitmentMismatch {
        /// Broker run.
        expected: IntentRunCommitment,
        /// Authorization run.
        observed: IntentRunCommitment,
    },
    /// Complete run identity failed.
    RunIdentity(IntentRunIdentityRefusal),
    /// Effect-time authorization failed.
    Authorization(CapabilityEffectAuthorizationRefusal),
    /// Ordinary broker admission failed.
    Broker(BrokerRefusal),
    /// Ordinary effect journal lifecycle failed.
    Journal(crate::EffectJournalRefusal),
}

impl fmt::Display for RevocationCheckedEffectRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "revocation-checked effect broker refused: {self:?}"
        )
    }
}

impl core::error::Error for RevocationCheckedEffectRefusal {}

impl From<IntentRunIdentityRefusal> for RevocationCheckedEffectRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CapabilityEffectAuthorizationRefusal> for RevocationCheckedEffectRefusal {
    fn from(value: CapabilityEffectAuthorizationRefusal) -> Self {
        Self::Authorization(value)
    }
}

fn revocation_request_commitment(
    request: &CapabilityRevocationReadRequest,
) -> Result<[u8; 32], CapabilityRevocationReadRefusal> {
    let mut encoder = Encoder::with_capacity(320);
    encoder.write_bytes(
        "capability_revocation_request_domain",
        REVOCATION_REQUEST_DOMAIN,
    )?;
    encoder.write_raw(request.authority_read_receipt_id.as_bytes());
    encoder.write_opaque_id(request.repository_id.as_bytes());
    encoder.write_raw(request.run_commitment.as_bytes());
    encoder.write_scalar(request.requested_at.value());
    encoder.write_scalar(request.max_age);
    encoder.write_scalar(request.max_entries);
    Ok(hash(&encoder.into_bytes()))
}

fn revocation_receipt_commitment(
    receipt: &CapabilityRevocationReceipt,
) -> Result<[u8; 32], CapabilityRevocationReadRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes(
        "capability_revocation_receipt_domain",
        REVOCATION_RECEIPT_DOMAIN,
    )?;
    encoder.write_raw(receipt.request_id.as_bytes());
    encoder.write_raw(receipt.authority_read_receipt_id.as_bytes());
    encoder.write_raw(receipt.run_commitment.as_bytes());
    encoder.write_raw(&receipt.revocation_generation);
    encoder.write_scalar(receipt.observed_at.value());
    encoder.write_scalar(receipt.valid_until.value());
    let count = u32::try_from(receipt.revoked_capability_ids.len()).map_err(|_| {
        CodecRefusal::ValueUnrepresentable {
            field: "capability_revocations.revoked_capability_ids",
            observed: u64::try_from(receipt.revoked_capability_ids.len()).unwrap_or(u64::MAX),
            limit: u64::from(u32::MAX),
        }
    })?;
    encoder.write_scalar(count);
    for capability_id in &receipt.revoked_capability_ids {
        encoder.write_raw(&capability_id.value().to_be_bytes());
    }
    encoder.write_raw(&receipt.reader_profile);
    encoder.write_digest(&receipt.evidence_root)?;
    Ok(hash(&encoder.into_bytes()))
}

fn verified_chain_commitment(
    chain: &[SealedCapability],
) -> Result<[u8; 32], VerifiedCapabilityChainRefusal> {
    let mut encoder = Encoder::with_capacity(768);
    encoder.write_bytes("verified_capability_chain_domain", VERIFIED_CHAIN_DOMAIN)?;
    let count = u32::try_from(chain.len()).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field: "verified_capability_chain.links",
        observed: u64::try_from(chain.len()).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    for link in chain {
        let capability = link.capability();
        encoder.write_raw(&capability.id().value().to_be_bytes());
        match capability.parent() {
            Some(parent) => {
                encoder.write_bool(true);
                encoder.write_raw(&parent.value().to_be_bytes());
            }
            None => encoder.write_bool(false),
        }
        encoder.write_scalar(capability.operations().bits());
        for (_grade, amount) in capability.quota().pairs() {
            encoder.write_scalar(amount);
        }
        encoder.write_scalar(capability.not_before().value());
        encoder.write_scalar(capability.expires_at().value());
        encoder.write_scalar(capability.depth());
        match link.parent_tag() {
            Some(parent_tag) => {
                encoder.write_bool(true);
                encoder.write_raw(parent_tag);
            }
            None => encoder.write_bool(false),
        }
        encoder.write_raw(link.tag());
    }
    Ok(hash(&encoder.into_bytes()))
}

fn effect_authorization_commitment(
    authorization: &CapabilityEffectAuthorization,
) -> Result<[u8; 32], CapabilityEffectAuthorizationRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes(
        "capability_effect_authorization_domain",
        EFFECT_AUTHORIZATION_DOMAIN,
    )?;
    encoder.write_raw(authorization.revocation_receipt_id.as_bytes());
    encoder.write_raw(authorization.verified_chain_id.as_bytes());
    encoder.write_raw(&authorization.run_id.value().to_be_bytes());
    encoder.write_raw(authorization.run_commitment.as_bytes());
    encoder.write_raw(&authorization.capability_id.value().to_be_bytes());
    encoder.write_raw(&authorization.effect_id.value().to_be_bytes());
    match authorization.parent_effect_id {
        Some(parent) => {
            encoder.write_bool(true);
            encoder.write_raw(&parent.value().to_be_bytes());
        }
        None => encoder.write_bool(false),
    }
    encoder.write_raw_byte(authorization.operation as u8);
    for (_grade, amount) in authorization.cost.pairs() {
        encoder.write_scalar(amount);
    }
    encoder.write_raw(&authorization.input_commitment);
    encoder.write_scalar(authorization.authorized_at.value());
    encoder.write_scalar(authorization.valid_until.value());
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
