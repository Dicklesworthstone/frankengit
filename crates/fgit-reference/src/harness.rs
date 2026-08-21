//! The documented construction API differential harnesses build scenarios
//! with.
//!
//! The FG-003 epic requires "a documented API by which implementation crates
//! differential-test against this oracle". This module is the part of that API
//! that deals with **identity assignment**, and it exists because of a boundary
//! stated plainly in the crate documentation: this model computes no digests.
//! Identities for seals, capsules, batches, records, and heads are supplied by
//! the caller, because deriving them is a domain-separated digest over
//! canonical bytes and belongs to `fgit-codec` and the crypto registry.
//!
//! A harness therefore needs *some* source of distinct identity values.
//! [`IdentityMint`] is that source, and its contract is narrow and explicit:
//!
//! * it produces **distinct** values — a test asserts the mint never repeats;
//! * it produces **deterministic** values — two mints started at the same seed
//!   produce the same sequence, so a scenario replays byte-for-byte;
//! * it produces values with **no cryptographic meaning whatsoever**.
//!
//! That last point is the important one. A minted identity is a counter in an
//! identity-shaped wrapper. It is not a digest, it says nothing about the body
//! it names, and it must never appear in an implementation path. The model is
//! indifferent to this because the model never interprets an identity — it only
//! compares identities and enforces the laws any real derivation must satisfy
//! (see [`crate::state::IdentityLedger`]). An implementation being
//! differential-tested supplies its own real identities; the mint is for
//! constructing the scenario around them.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{
    OPAQUE_ID_LEN, PreparationProfileId, PreparedTxnCapsuleId, PrincipalId, PrincipalSnapshotId,
    RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, TenantId, TransactionSealId, TxId,
};
use fgit_types::label::{AsciiSlug, SchemaId};
use fgit_types::native::GitOid;
use fgit_types::numeric::CodecVersion;
use fgit_types::vocabulary::{DecisionOutcome, MismatchPolicy, RefusalCode};

use crate::capsule::WitnessGranularity;
use crate::intent::{DurabilityProfile, IdempotencyKey, Intent, Statement, TransactionRequest};
use crate::state::{ModelResult, QuarantinedObject, RepositoryState};
use crate::transition::{
    CasOutcome, CasRequest, DecisionBodyIdentity, PrepareRequest, QuarantineRequest,
    RepreparationReason, SealOutcome, SealRequest, StageRequest, compare_and_swap, prepare, seal,
    stage, stage_objects,
};

/// The digest algorithm slot minted identities are stamped with.
///
/// A real identity carries the algorithm that actually produced its bytes.
/// A minted one carries this reserved-for-harnesses slot so a minted identity
/// is distinguishable from a real one by inspection.
pub const HARNESS_ALGORITHM_CODE_POINT: u16 = 0xff01;

/// The codec version minted identities are stamped with.
pub const HARNESS_CODEC_VERSION: CodecVersion = CodecVersion::new(1, 0);

/// Length of a minted digest body, in bytes.
const MINTED_DIGEST_LEN: usize = 32;

/// A deterministic source of distinct, cryptographically meaningless
/// identities.
///
/// See the module documentation for what this is and is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityMint {
    seed: u64,
    issued: u64,
}

impl IdentityMint {
    /// Opens a mint at a seed.
    ///
    /// Two mints opened at the same seed issue the same sequence, which is what
    /// makes a scenario replayable.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { seed, issued: 0 }
    }

    /// How many identities this mint has issued.
    #[must_use]
    pub const fn issued(&self) -> u64 {
        self.issued
    }

    /// The next distinct value, as raw bytes.
    ///
    /// The encoding is the seed and the issue counter written big-endian, then
    /// zero padding. It is a counter, deliberately and visibly.
    fn next_raw(&mut self) -> [u8; MINTED_DIGEST_LEN] {
        let mut bytes = [0_u8; MINTED_DIGEST_LEN];
        bytes[0..8].copy_from_slice(&self.seed.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.issued.to_be_bytes());
        self.issued = self.issued.wrapping_add(1);
        bytes
    }

    fn next_opaque(&mut self) -> [u8; OPAQUE_ID_LEN] {
        let raw = self.next_raw();
        let mut bytes = [0_u8; OPAQUE_ID_LEN];
        bytes.copy_from_slice(&raw[0..OPAQUE_ID_LEN]);
        bytes
    }

    /// The next distinct digest.
    ///
    /// # Panics
    ///
    /// Never in practice: the algorithm slot is a fixed non-zero constant and
    /// the body is a fixed 32 bytes, both inside `fgit-types`' accepted
    /// windows. The expectations document that, rather than hiding a failure
    /// behind a default value.
    pub fn digest(&mut self) -> Digest {
        let raw = self.next_raw();
        let algorithm = DigestAlgorithmId::try_new(HARNESS_ALGORITHM_CODE_POINT)
            .expect("the harness algorithm slot is a non-zero constant");
        let bytes = DigestBytes::try_new(&raw)
            .expect("a 32-byte body is inside the accepted digest window");
        Digest::new(algorithm, bytes)
    }

    fn next_digest_bytes(&mut self) -> DigestBytes {
        let raw = self.next_raw();
        DigestBytes::try_new(&raw).expect("a 32-byte body is inside the accepted digest window")
    }

    fn algorithm() -> DigestAlgorithmId {
        DigestAlgorithmId::try_new(HARNESS_ALGORITHM_CODE_POINT)
            .expect("the harness algorithm slot is a non-zero constant")
    }

    /// The next distinct tenant identity.
    pub fn tenant(&mut self) -> TenantId {
        TenantId::from_bytes(self.next_opaque())
    }

    /// The next distinct repository identity.
    pub fn repository(&mut self) -> RepositoryId {
        RepositoryId::from_bytes(self.next_opaque())
    }

    /// The next distinct principal identity.
    pub fn principal(&mut self) -> PrincipalId {
        PrincipalId::from_bytes(self.next_opaque())
    }

    /// The next distinct transaction identity.
    pub fn tx(&mut self) -> TxId {
        let digest = self.next_digest_bytes();
        TxId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct seal identity.
    pub fn seal(&mut self) -> TransactionSealId {
        let digest = self.next_digest_bytes();
        TransactionSealId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct prepared-capsule identity.
    pub fn capsule(&mut self) -> PreparedTxnCapsuleId {
        let digest = self.next_digest_bytes();
        PreparedTxnCapsuleId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct commit-record identity.
    pub fn commit(&mut self) -> RepositoryCommitId {
        let digest = self.next_digest_bytes();
        RepositoryCommitId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct decision-batch identity.
    pub fn batch(&mut self) -> RepositoryDecisionBatchId {
        let digest = self.next_digest_bytes();
        RepositoryDecisionBatchId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct authority-head identity.
    pub fn head(&mut self) -> RepositoryAuthorityHeadId {
        let digest = self.next_digest_bytes();
        RepositoryAuthorityHeadId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct refusal-record identity.
    pub fn refusal_record(&mut self) -> RefusalRecordId {
        let digest = self.next_digest_bytes();
        RefusalRecordId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The next distinct principal-snapshot identity.
    pub fn principal_snapshot(&mut self) -> PrincipalSnapshotId {
        let digest = self.next_digest_bytes();
        PrincipalSnapshotId::from_digest(Self::algorithm(), HARNESS_CODEC_VERSION, digest)
    }

    /// The preparation profile a harness-driven preparation declares.
    ///
    /// # Panics
    ///
    /// Never: the label is a compile-time constant inside the accepted
    /// character set.
    #[must_use]
    pub fn preparation_profile() -> PreparationProfileId {
        PreparationProfileId::try_new(b"fgit-reference/harness/v1")
            .expect("the harness profile label is a valid constant")
    }
}

/// Builds a bounded ASCII label.
///
/// # Panics
///
/// Panics when `text` is outside `fgit-types`' label character set or length
/// window. Callers pass literals, so a failure is a authoring mistake to fix,
/// not a runtime condition to handle.
#[must_use]
pub fn label(text: &str) -> AsciiSlug {
    AsciiSlug::try_new("harness-label", text.as_bytes())
        .unwrap_or_else(|error| panic!("{text:?} is not a valid label: {error}"))
}

/// A [`TransactionRequest`] under construction.
///
/// The builder exists so a harness states only the semantics it cares about —
/// which intents, under which mismatch policy, promising which objects — and
/// lets the identities it does not care about be assigned deterministically.
/// Every field it fills is client-visible semantics that §3.3's canonical
/// request digest binds; there is deliberately nowhere to put a pack encoding,
/// a retry count, a receiving node, or a basis head.
#[derive(Clone, Debug)]
pub struct RequestBuilder {
    tenant: TenantId,
    repository: RepositoryId,
    principal: PrincipalId,
    schema: SchemaId,
    idempotency_key: IdempotencyKey,
    statements: Vec<Statement>,
    promised_closure: BTreeSet<GitOid>,
    atomic: bool,
    durability: DurabilityProfile,
}

impl RequestBuilder {
    /// Opens a builder for one principal acting on one repository.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        repository: RepositoryId,
        principal: PrincipalId,
        schema: SchemaId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            tenant,
            repository,
            principal,
            schema,
            idempotency_key,
            statements: Vec::new(),
            promised_closure: BTreeSet::new(),
            atomic: true,
            durability: DurabilityProfile::CanonicalSource,
        }
    }

    /// Appends one statement.
    #[must_use]
    pub fn statement(mut self, mismatch_policy: MismatchPolicy, intents: Vec<Intent>) -> Self {
        self.statements.push(Statement {
            intents,
            mismatch_policy,
        });
        self
    }

    /// Promises that an object is reachable.
    #[must_use]
    pub fn promising(mut self, object: GitOid) -> Self {
        self.promised_closure.insert(object);
        self
    }

    /// Sets whether all commands must publish together.
    #[must_use]
    pub const fn atomic(mut self, atomic: bool) -> Self {
        self.atomic = atomic;
        self
    }

    /// Sets the durability profile publication must satisfy.
    #[must_use]
    pub const fn durability(mut self, durability: DurabilityProfile) -> Self {
        self.durability = durability;
        self
    }

    /// Overrides the request schema.
    #[must_use]
    pub const fn schema(mut self, schema: SchemaId) -> Self {
        self.schema = schema;
        self
    }

    /// Finishes the request, taking its transaction identity and canonical
    /// request digest from `mint`.
    ///
    /// The two are minted independently, which is what lets a test present the
    /// *same* identity with *different* digests, or the same digest under
    /// different identities — the two shapes
    /// [`crate::state::IdentityLedger`] exists to catch.
    pub fn build(self, mint: &mut IdentityMint) -> TransactionRequest {
        let tx_id = mint.tx();
        let canonical_request_digest = mint.digest();
        self.build_with(tx_id, canonical_request_digest)
    }

    /// Finishes the request with a caller-chosen identity and digest.
    #[must_use]
    pub fn build_with(self, tx_id: TxId, canonical_request_digest: Digest) -> TransactionRequest {
        TransactionRequest {
            tx_id,
            tenant: self.tenant,
            repository: self.repository,
            principal: self.principal,
            schema: self.schema,
            idempotency_key: self.idempotency_key,
            canonical_request_digest,
            statements: self.statements,
            promised_closure: self.promised_closure,
            atomic: self.atomic,
            durability: self.durability,
        }
    }
}

/// Everything one end-to-end attempt produced.
///
/// Each field is `None` when the attempt stopped before reaching that stage,
/// so a harness can see *where* an attempt ended rather than only that it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishReport {
    /// What sealing produced.
    pub seal: SealOutcome,
    /// The capsule, when preparation ran.
    pub capsule: Option<PreparedTxnCapsuleId>,
    /// The staged batch, when staging ran.
    pub batch: Option<RepositoryDecisionBatchId>,
    /// Capsules staging deferred for re-preparation, with the reason.
    ///
    /// Non-empty means the attempt lost a race and the sealed request must be
    /// prepared again (§5.2). It is an ordinary retryable outcome, not a
    /// decision.
    pub deferred: Vec<(TxId, RepreparationReason)>,
    /// The compare-and-swap result, when one was attempted.
    pub cas: Option<CasOutcome>,
    /// The terminal outcome, when the transaction has one.
    ///
    /// `None` means undecided and retryable. It is never evidence of
    /// non-commit (§14).
    pub outcome: Option<DecisionOutcome>,
}

impl PublishReport {
    /// True when this attempt ended in a commit.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self.outcome, Some(DecisionOutcome::Committed { .. }))
    }

    /// Why this attempt must be prepared again, when staging deferred it.
    #[must_use]
    pub fn repreparation_reason(&self) -> Option<RepreparationReason> {
        self.deferred.first().map(|(_, reason)| *reason)
    }

    /// The terminal refusal code, when the transaction was refused.
    #[must_use]
    pub const fn refusal_code(&self) -> Option<RefusalCode> {
        match self.outcome {
            Some(DecisionOutcome::Refused { code, .. }) => Some(code),
            Some(DecisionOutcome::Committed { .. }) | None => None,
        }
    }
}

/// Drives one request through seal, quarantine, prepare, stage, and the head
/// compare-and-swap.
///
/// This is the ordinary happy path of §10 with every stage in order and
/// nothing skipped. A harness that needs to interleave attempts, lose a
/// compare-and-swap, or batch several transactions together calls the
/// transitions in [`crate::transition`] directly; this is the single-attempt
/// convenience, not a shortcut around them.
///
/// Sealing is the only stage that can end the attempt without a decision: a
/// pre-seal rejection is not repository history, so there is nothing further
/// to do with it.
pub fn publish(
    state: &RepositoryState,
    mint: &mut IdentityMint,
    request: &TransactionRequest,
    objects: &[QuarantinedObject],
    durability_satisfied: bool,
) -> ModelResult<(RepositoryState, PublishReport)> {
    let seal_request = SealRequest {
        seal_id: mint.seal(),
        request: request.clone(),
    };
    let (state, seal_outcome) = seal(state, &seal_request)?;
    if seal_outcome.is_rejection() {
        return Ok((
            state,
            PublishReport {
                seal: seal_outcome,
                capsule: None,
                batch: None,
                deferred: Vec::new(),
                cas: None,
                outcome: None,
            },
        ));
    }

    let state = if objects.is_empty() {
        state
    } else {
        stage_objects(
            &state,
            &QuarantineRequest {
                tx_id: request.tx_id,
                objects: objects.to_vec(),
            },
        )?
    };

    let prepare_request = PrepareRequest {
        capsule_id: mint.capsule(),
        request: request.clone(),
        principal_snapshot: mint.principal_snapshot(),
        profile: IdentityMint::preparation_profile(),
        granularity: WitnessGranularity::Refined,
    };
    let (state, capsule) = prepare(&state, &prepare_request)?;

    let mut bodies = BTreeMap::new();
    bodies.insert(
        request.tx_id,
        DecisionBodyIdentity {
            commit: mint.commit(),
            refusal_record: mint.refusal_record(),
        },
    );
    let stage_request = StageRequest {
        batch_id: mint.batch(),
        candidate_head_id: mint.head(),
        capsules: vec![capsule],
        bodies,
        durability_satisfied,
    };
    let (state, staged) = stage(&state, &stage_request)?;

    // Staging deferred this capsule: its basis moved, so there is no batch to
    // publish and nothing to compare-and-swap. The seal survives and the caller
    // prepares again — this is §5.2's retry, not a decision.
    let Some(batch) = staged.batch else {
        let outcome = state.outcome_of(request.tx_id);
        return Ok((
            state,
            PublishReport {
                seal: seal_outcome,
                capsule: Some(capsule),
                batch: None,
                deferred: staged.deferred,
                cas: None,
                outcome,
            },
        ));
    };

    let cas_request = CasRequest {
        expected_head: state.head().id,
        expected_generation: state.head().body.generation,
        batch,
    };
    let (state, cas) = compare_and_swap(&state, cas_request)?;
    let outcome = state.outcome_of(request.tx_id);

    Ok((
        state,
        PublishReport {
            seal: seal_outcome,
            capsule: Some(capsule),
            batch: Some(batch),
            deferred: staged.deferred,
            cas: Some(cas),
            outcome,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::IdentityMint;
    use std::collections::BTreeSet;

    #[test]
    fn a_mint_never_repeats_an_identity() {
        let mut mint = IdentityMint::new(7);
        let mut seen = BTreeSet::new();
        for index in 0..512 {
            assert!(
                seen.insert(mint.tx()),
                "transaction identity repeated at issue {index}"
            );
        }
        assert_eq!(seen.len(), 512);
    }

    #[test]
    fn two_mints_at_the_same_seed_issue_the_same_sequence() {
        let mut left = IdentityMint::new(11);
        let mut right = IdentityMint::new(11);
        for _ in 0..64 {
            assert_eq!(left.batch(), right.batch());
            assert_eq!(left.head(), right.head());
            assert_eq!(left.digest(), right.digest());
        }
        assert_eq!(left.issued(), right.issued());
    }

    #[test]
    fn different_seeds_do_not_collide() {
        let mut left = IdentityMint::new(1);
        let mut right = IdentityMint::new(2);
        for _ in 0..64 {
            assert_ne!(left.tx(), right.tx());
        }
    }

    #[test]
    fn identity_families_do_not_alias_each_other() {
        // Domain separation is `fgit-types`' guarantee, not the mint's, but a
        // harness that accidentally used one family's value for another would
        // be a confusing failure to debug. This pins the expectation.
        let mut mint = IdentityMint::new(3);
        let batch = mint.batch();
        let mut same = IdentityMint::new(3);
        let head = same.head();
        assert_ne!(
            batch.as_internal_object_id().domain(),
            head.as_internal_object_id().domain(),
            "two identity families share a domain separation tag"
        );
    }
}
