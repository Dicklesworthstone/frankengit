//! Acceptance coverage for FG-079's decision-log and segment-compaction slice.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots};
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryCommitRecord};
use fgit_codec::{CryptoBodyIdentity, DecodeLimits, decode_body, encode_body};
use fgit_compaction::{
    CompactionAlgorithm, CompactionExecution, CompactionOutputs, CompactionProfile,
    CompactionPublicationRefusal, CompactionRecord, DecisionRange, DurabilityReceipt,
    DurabilityRefusal, DurableCompaction, LogicalEquivalenceProof, OutputDisposition,
    OutputStageReceipt, RetentionRefusal, SourceEntry, SourceOutputTotalityMap, StagedCompaction,
    TotalityEntry, VisibleCompaction,
};
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, PublicationState, RetentionRootProposal, StoreRefusal,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes,
    GenerationId, GitOid, GitOidSha1, HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch,
    PrincipalSnapshotId, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryId,
    RepositorySequence, SegmentManifestId, TenantId, TxId,
};

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("32-byte corpus fixture body"),
        )
    };
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x71; OPAQUE_ID_LEN])
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x72; OPAQUE_ID_LEN])
}

const fn object() -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([0x73; GitOidSha1::LEN]))
}

fn genesis_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn basis() -> PublicationBasis {
    let head = genesis_head();
    let identity = authority_head_identity(&head).expect("genesis head identifies");
    PublicationBasis::new(identity, head)
}

fn record(input: &PublicationBasis) -> CompactionRecord {
    let manifest = derived!(SegmentManifestId, 0x51);
    CompactionRecord {
        input_head: input.id(),
        input_head_generation: input.generation(),
        decision_range: DecisionRange::new(DecisionSequence::FIRST, DecisionSequence::FIRST)
            .expect("one decision is an increasing range"),
        input_segment_root: digest(0x20),
        input_decision_root: digest(0x21),
        algorithm: CompactionAlgorithm::DeterministicReencodeV1,
        profile: CompactionProfile::ConservativeInterimV1,
        toolchain_fingerprint: digest(0x22),
        outputs: CompactionOutputs {
            pack_roots: vec![digest(0x30)],
            segment_manifests: vec![manifest],
            index_roots: vec![digest(0x31)],
        },
        equivalence_proof: LogicalEquivalenceProof::construct(
            digest(0x40),
            digest(0x40),
            digest(0x41),
        )
        .expect("equal reconstructed logical roots prove equivalence"),
        totality: SourceOutputTotalityMap::new(vec![
            TotalityEntry {
                source: SourceEntry::Object(object()),
                disposition: OutputDisposition::Stored {
                    pack_root: digest(0x30),
                    segment_manifest: manifest,
                },
            },
            TotalityEntry {
                source: SourceEntry::Decision(DecisionSequence::FIRST),
                disposition: OutputDisposition::DocumentedDrop {
                    evidence_root: digest(0x42),
                },
            },
        ])
        .expect("each source is accounted for once"),
        resource_receipt_root: digest(0x43),
        rejected_layout_evidence_root: digest(0x44),
    }
}

fn stage(input: &PublicationBasis) -> StagedCompaction {
    StagedCompaction::stage(
        record(input),
        OutputStageReceipt::new(vec![PublicationState::new(true, false, false); 3])
            .expect("all physical outputs are staged"),
    )
    .expect("well-formed staged compaction")
}

fn roots(compaction_generation_link: Option<Digest>) -> ResultingRoots {
    ResultingRoots {
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        policy_epoch: PolicyEpoch::FIRST,
        compaction_generation_link,
    }
}

fn commit_record(compaction_generation_link: Digest) -> RepositoryCommitRecord {
    RepositoryCommitRecord {
        repository_id: repository(),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, 0x61),
        principal_snapshot_id: derived!(PrincipalSnapshotId, 0x62),
        canonical_request_digest: digest(0x63),
        ref_delta_root: digest(0x64),
        resulting_ref_root: digest(0x10),
        object_closure_root: digest(0x65),
        forge_event_batch_root: digest(0x66),
        resulting_forge_position_root: digest(0x11),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(0x67),
        invariant_evidence_root: compaction_generation_link,
        outbox_effect_root: digest(0x68),
        retention_delta_root: digest(0x69),
    }
}

fn publication(
    input: PublicationBasis,
    staged: &StagedCompaction,
) -> fgit_chronicle::VerifiedPublication {
    let mut plan = PublicationPlan::open(input).expect("authenticated basis opens a plan");
    plan.commit(commit_record(staged.compaction_generation_link()));
    plan.seal(
        &CryptoBodyIdentity,
        roots(Some(staged.compaction_generation_link())),
    )
    .expect("ordinary compaction decision is well formed")
}

fn current_token(
    store: &MemoryAuthorityStore,
    head_key: &HeadKey,
) -> fgit_authority::AuthorityVersionToken {
    match store
        .read_head(head_key)
        .expect("reference head read succeeds")
    {
        HeadRead::Present(receipt) => receipt.token(),
        HeadRead::Absent => panic!("genesis head was initialized"),
    }
}

#[derive(Clone, Copy)]
struct RetentionRegistry {
    head: RepositoryAuthorityHeadId,
    permits: bool,
}

impl AuthenticatedRetentionRegistry for RetentionRegistry {
    fn revalidate_root(&self, proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
        if proposal.authority_head() == self.head {
            Ok(())
        } else {
            Err(StoreRefusal::RetentionRevalidationFailed)
        }
    }

    fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
        if self.permits {
            Ok(())
        } else {
            Err(StoreRefusal::DeletionRetained)
        }
    }
}

#[test]
fn record_codec_binds_every_input_output_and_evidence_field() {
    let input = basis();
    let expected = record(&input);
    let bytes = encode_body(&expected).expect("record encodes canonically");
    let actual: CompactionRecord =
        decode_body(&bytes, DecodeLimits::DEFAULT).expect("record decodes canonically");

    assert_eq!(actual, expected);
    assert_eq!(
        actual
            .generation_id(&CryptoBodyIdentity)
            .expect("registered generation domain identifies"),
        expected
            .generation_id(&CryptoBodyIdentity)
            .expect("same canonical record has the same generation"),
        "every compaction input, proof, output, and receipt participates in the generation identity"
    );
}

#[test]
fn interrupted_output_or_unpublished_staging_leaves_the_old_authority_head_complete() {
    let input = basis();
    let head_key = HeadKey::new(b"fg079/crash-head".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x79));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");
    let before = store
        .read_head(&head_key)
        .expect("head read before staging");

    let interrupted = StagedCompaction::stage(
        record(&input),
        OutputStageReceipt::new(vec![PublicationState::new(true, false, false); 2])
            .expect("partial output reports only what was staged"),
    );
    assert!(matches!(
        interrupted,
        Err(CompactionPublicationRefusal::OutputReceiptCardinality)
    ));
    assert_eq!(
        store.read_head(&head_key).expect("head remains readable"),
        before,
        "a crash while producing outputs cannot create a partial authority state"
    );

    let _staged_but_unpublished = stage(&input);
    assert_eq!(
        store.read_head(&head_key).expect("head remains readable"),
        before,
        "outputs staged before the CAS remain noncanonical after a crash"
    );
}

#[test]
fn ordinary_decision_makes_complete_generation_visible_then_durable_retention_controls_deletion() {
    let input = basis();
    let staged = stage(&input);
    let publication = publication(input.clone(), &staged);
    let head_key = HeadKey::new(b"fg079/visible-head".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7a));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");

    let visible = match staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &publication,
        tenant(),
    ) {
        CompactionExecution::Visible(visible) => visible,
        other => panic!("ordinary decision must publish the staged generation: {other:?}"),
    };
    let current = match store.read_head(&head_key).expect("head read after publish") {
        HeadRead::Present(receipt) => {
            decode_body::<RepositoryAuthorityHeadBody>(receipt.body(), DecodeLimits::DEFAULT)
                .expect("published head remains a complete canonical body")
        }
        HeadRead::Absent => panic!("successful CAS cannot remove a head"),
    };
    assert_eq!(current.ref_root, input.body().ref_root);
    assert_eq!(
        current.forge_position_root,
        input.body().forge_position_root
    );
    assert_eq!(current.retention_root, input.body().retention_root);
    assert_eq!(
        publication.batch().compaction_generation_link,
        Some(visible.compaction_generation_link()),
        "the ordinary batch carries the compaction generation in its dedicated link"
    );

    let not_durable = visible.confirm_durability(DurabilityReceipt::new(
        visible.generation(),
        CompactionProfile::ConservativeInterimV1,
        vec![PublicationState::new(true, true, false); 3],
        digest(0x81),
    ));
    assert_eq!(not_durable, Err(DurabilityRefusal::OutputNotDurable));

    let durable = visible
        .confirm_durability(DurabilityReceipt::new(
            visible.generation(),
            CompactionProfile::ConservativeInterimV1,
            vec![PublicationState::new(true, true, true); 3],
            digest(0x82),
        ))
        .expect("only all durable outputs unlock retention evaluation");
    let proposal = RetentionRootProposal::new(
        visible.successor_head(),
        current.retention_root,
        vec![derived!(SegmentManifestId, 0x51)],
    );
    let proposal = match proposal {
        Ok(proposal) => proposal,
        Err(error) => panic!("one manifest is canonical: {error}"),
    };
    let permit = durable
        .authorize_source_deletion(
            &RetentionRegistry {
                head: visible.successor_head(),
                permits: true,
            },
            &proposal,
            object(),
        )
        .expect("only authenticated retention may permit deletion");
    assert_eq!(permit.source(), object());
}

#[test]
fn publication_without_rcr_evidence_link_stays_staged_even_when_batch_link_matches() {
    let input = basis();
    let staged = stage(&input);
    let mut plan = PublicationPlan::open(input.clone()).expect("basis opens a plan");
    plan.commit(commit_record(digest(0x91)));
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            roots(Some(staged.compaction_generation_link())),
        )
        .expect("the generic batch itself is valid");
    let head_key = HeadKey::new(b"fg079/no-rcr-link".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7b));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");
    let before = store
        .read_head(&head_key)
        .expect("head before rejected publish");

    match staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &publication,
        tenant(),
    ) {
        CompactionExecution::Unpublished(unpublished) => assert_eq!(
            unpublished.reason(),
            &CompactionPublicationRefusal::RcrEvidenceLinkMissing
        ),
        other => panic!("unlinked record must never become visible: {other:?}"),
    }
    assert_eq!(
        store
            .read_head(&head_key)
            .expect("head after rejected publish"),
        before,
        "rejecting an unlinked generation happens before the authority CAS"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

// ---------------------------------------------------------------------------
// frankengit-oq73: the publication-refusal chain
//
// Appended to this file rather than opened as a second binary so these probes
// reuse the fixtures above. Duplicating `basis`, `record`, `stage`, `roots`,
// `commit_record` and `publication` into another integration test would be a
// drift hazard: two copies of an intricate fixture drift silently, and the
// copy that drifts is the one that stops testing what it claims to.
//
// Safe by inspection: scripts/e2e/suites/compaction/compaction_protocol.sh
// asserts `fge_assert_exit 0` plus three `fge_assert_contains` checks on
// specific TEST NAMES. There is no probe-COUNT assertion, so adding tests
// cannot break it — unlike the wire suites, where a count is asserted.
//
// `CompactionPublicationRefusal` had 10 constructed variants and exactly two
// named by any test. These are the constitution's publication rules stated as
// types: §5.1 (only exact-predecessor CAS publishes), §5.2 (one sealed
// transaction has at most one terminal decision), §5.4 (staged / visible /
// durable are distinct epochs).
// ---------------------------------------------------------------------------

use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken,
    CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadReadReceipt, ImmutableKey, ImmutableRead,
    PutOutcome,
};
use fgit_types::{RefusalCode, RefusalRecordId};

/// A basis whose identity and body are supplied independently.
///
/// The two `InputBasisMismatch` axes cannot be varied together: the head
/// identity is *derived from* the body, so changing the generation would change
/// the identity too and the `||` would short-circuit on the identity arm. Since
/// `PublicationBasis::new` takes the identity and the body separately, a probe
/// can hold one fixed while moving the other — which is the only way to reach
/// the generation arm at all.
fn basis_with(identity: RepositoryAuthorityHeadId, generation: HeadGeneration) -> PublicationBasis {
    let mut head = genesis_head();
    head.generation = generation;
    PublicationBasis::new(identity, head)
}

/// A publication built on `input` that commits, carrying `link` in both the
/// explicit batch linkage field and the linked RCR's invariant evidence root.
fn publication_with_link(
    input: PublicationBasis,
    link: Digest,
) -> fgit_chronicle::VerifiedPublication {
    let mut plan = PublicationPlan::open(input).expect("authenticated basis opens a plan");
    plan.commit(commit_record(link));
    plan.seal(&CryptoBodyIdentity, roots(Some(link)))
        .expect("an ordinary decision is well formed")
}

/// A publication carrying only a refusal, so no committed RCR exists.
fn refusal_only_publication(input: PublicationBasis) -> fgit_chronicle::VerifiedPublication {
    let mut plan = PublicationPlan::open(input).expect("authenticated basis opens a plan");
    plan.refuse(
        derived!(TxId, 0x71),
        RefusalCode::IntentExpired,
        derived!(RefusalRecordId, 0x72),
    );
    plan.seal(&CryptoBodyIdentity, roots(None))
        .expect("a refusal-only batch is well formed")
}

/// A store that is a **complete** delegate except for one deliberately
/// ambiguous operation.
///
/// Completeness matters here. `AuthorityStore::publish_head_with_outcomes` has
/// a default body that refuses with `OperationUnsupported`, so a double that
/// simply *omitted* it would fail for a reason the test did not choose and
/// would look like evidence while proving nothing. Every method is forwarded;
/// only the publish path is armed, and it returns `Ambiguous(Cancelled)` —
/// whose own documentation says cancellation after transmission never proves
/// non-commit.
struct AmbiguousPublishStore(MemoryAuthorityStore);

impl AuthorityStore for AmbiguousPublishStore {
    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.0.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.0.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.0.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.0.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.0
            .compare_exchange_head(key, expected, new_generation, new_body)
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.0.authenticate_head_receipt(receipt)
    }

    fn publish_head_with_outcomes(
        &self,
        _key: &HeadKey,
        _expected: AuthorityVersionToken,
        _new_generation: HeadGeneration,
        _new_body: &[u8],
        _outcomes: &[(ImmutableKey, Vec<u8>)],
        _witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled))
    }
}

// ---------------------------------------------------------------------------
// OutputStageReceipt — §5.4, staged is not inferred from existence
// ---------------------------------------------------------------------------

/// An output the caller has not recorded as staged cannot receipt.
///
/// The constructor deliberately does not infer staging from object existence,
/// which is §5.4's separation of epochs: object existence is not visibility and
/// is not durability.
#[test]
fn an_output_that_is_not_recorded_as_staged_cannot_receipt() {
    let refusal = OutputStageReceipt::new(vec![
        PublicationState::new(true, false, false),
        PublicationState::new(false, false, false),
    ])
    .expect_err("an unstaged output cannot be receipted as staged");
    assert_eq!(refusal, CompactionPublicationRefusal::OutputNotStaged);
}

/// The permitted twin, and the ordering pair for the cardinality arm.
///
/// A one-element all-staged receipt is admitted; an EMPTY receipt reports
/// cardinality rather than staging, since that check runs first.
#[test]
fn a_staged_receipt_is_admitted_and_an_empty_one_reports_cardinality() {
    OutputStageReceipt::new(vec![PublicationState::new(true, false, false)])
        .expect("a fully staged receipt must be admitted");

    let refusal =
        OutputStageReceipt::new(Vec::new()).expect_err("no outputs at all is a cardinality fault");
    assert_eq!(
        refusal,
        CompactionPublicationRefusal::OutputReceiptCardinality,
        "the cardinality check runs before the staging scan"
    );
}

// ---------------------------------------------------------------------------
// validate_publication — the five-stage chain
// ---------------------------------------------------------------------------

/// The permitted terminus: a matching publication validates and yields the
/// successor head identity.
///
/// Every refusal below is measured against this; without it they could be
/// `validate_publication` rejecting any input at all.
#[test]
fn a_matching_publication_validates_and_returns_a_successor_head() {
    let input = basis();
    let staged = stage(&input);
    let publication = publication(input, &staged);
    staged
        .validate_publication(&publication)
        .expect("a publication carrying this record must validate");
    assert_eq!(
        publication.batch().compaction_generation_link,
        Some(staged.compaction_generation_link()),
        "the permitted compaction publication uses the explicit linkage field"
    );
}

/// **§5.2.** A batch with no committed RCR cannot carry a compaction
/// generation into visibility.
#[test]
fn a_refusal_only_publication_cannot_publish_a_generation() {
    let input = basis();
    let staged = stage(&input);
    let publication = refusal_only_publication(input);
    let refusal = staged
        .validate_publication(&publication)
        .expect_err("a refusal-only batch commits nothing to carry the generation");
    assert_eq!(
        refusal,
        CompactionPublicationRefusal::RefusalOnlyPublication
    );
}

/// Axis 1 of `InputBasisMismatch`: the publication is built on another head.
#[test]
fn a_publication_on_another_head_is_refused() {
    let input = basis();
    let staged = stage(&input);
    let foreign = basis_with(
        derived!(RepositoryAuthorityHeadId, 0x7e),
        input.generation(),
    );
    let publication = publication_with_link(foreign, staged.compaction_generation_link());
    let refusal = staged
        .validate_publication(&publication)
        .expect_err("a compaction record binds the head it was computed against");
    assert_eq!(refusal, CompactionPublicationRefusal::InputBasisMismatch);
}

/// Axis 2 of `InputBasisMismatch`: the same head identity at another
/// generation.
///
/// One arm covers two conditions joined by `||`, so a probe hitting only the
/// identity leaves the generation unexercised — and the generation is the arm
/// that stops a record computed against one generation being replayed onto a
/// later one.
#[test]
fn a_publication_at_another_head_generation_is_refused() {
    let input = basis();
    let staged = stage(&input);
    let later = HeadGeneration::try_new(2).expect("a second generation");
    let shifted = basis_with(input.id(), later);
    let publication = publication_with_link(shifted, staged.compaction_generation_link());
    let refusal = staged
        .validate_publication(&publication)
        .expect_err("a compaction record binds the generation it was computed against");
    assert_eq!(refusal, CompactionPublicationRefusal::InputBasisMismatch);
}

/// The batch must carry exactly this compaction's generation link.
#[test]
fn a_publication_with_another_compaction_generation_link_is_refused() {
    let input = basis();
    let staged = stage(&input);
    let publication = publication_with_link(input, digest(0x7d));
    let refusal = staged
        .validate_publication(&publication)
        .expect_err("an unrelated batch linkage cannot carry this generation");
    assert_eq!(
        refusal,
        CompactionPublicationRefusal::CompactionGenerationLinkMismatch
    );
}

// ---------------------------------------------------------------------------
// Ordering — publications that are wrong twice
// ---------------------------------------------------------------------------

/// Stage 1 outranks stage 2: refusal-only is reported before a basis mismatch.
///
/// Single-fault probes are structurally blind to a stage swap — each violates
/// one rule and still reaches its own stage wherever that stage sits.
#[test]
fn a_refusal_only_publication_outranks_a_basis_mismatch() {
    let input = basis();
    let staged = stage(&input);
    let foreign = basis_with(
        derived!(RepositoryAuthorityHeadId, 0x7e),
        input.generation(),
    );
    let publication = refusal_only_publication(foreign);
    let refusal = staged
        .validate_publication(&publication)
        .expect_err("a publication wrong in two ways must still refuse");
    assert_eq!(
        refusal,
        CompactionPublicationRefusal::RefusalOnlyPublication,
        "the refusal-only check runs before the basis comparison"
    );
}

/// Stage 2 outranks stage 3: a basis mismatch is reported before a linkage
/// mismatch — the opposite end of the chain from the probe above, so the two
/// together pin the order rather than one adjacency of it.
#[test]
fn a_basis_mismatch_outranks_a_compaction_generation_link_mismatch() {
    let input = basis();
    let staged = stage(&input);
    let foreign = basis_with(
        derived!(RepositoryAuthorityHeadId, 0x7e),
        input.generation(),
    );
    let publication = publication_with_link(foreign, digest(0x7d));
    let refusal = staged
        .validate_publication(&publication)
        .expect_err("a publication wrong in two ways must still refuse");
    assert_eq!(
        refusal,
        CompactionPublicationRefusal::InputBasisMismatch,
        "the basis comparison runs before the compaction-link comparison"
    );
}

// ---------------------------------------------------------------------------
// publish — the three outcomes, told apart from each other
// ---------------------------------------------------------------------------

/// **§5.1.** A stale expected token loses the race; nothing it staged becomes
/// canonical, and the staged output survives for a replan.
///
/// **Comment corrected (`frankengit-q77o`).** This test originally asserted
/// "a moved head is a lost race, not an already-decided duplicate". That is
/// **false for this very fixture**, and I wrote it. Driving the same scenario
/// through `fgit_chronicle::publish` directly returns
/// `Lost(Superseded { decided: [(tx, Committed(..))] })` — the transaction IS
/// already decided, and chronicle says so while naming the committed RCR.
///
/// `StagedCompaction::publish` matches `Lost(_)` with a wildcard, so both
/// `LostCandidate` arms become `AuthorityRaceLost` even though their own docs
/// carry opposite instructions: `Replannable` may be replanned, `Superseded`
/// must not be retried. What this test pins is therefore what the compaction
/// layer *reports*, which is not the same as what the authority layer
/// *classified*.
///
/// The assertion is left as-is deliberately: whether that mapping should change
/// is a refusal-vocabulary decision recorded on `frankengit-q77o` and not
/// settled here. Only the misleading claim is removed.
#[test]
fn a_stale_expected_token_reports_a_lost_race() {
    let input = basis();
    let head_key = HeadKey::new(b"oq73/race-head".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7b));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");
    let stale = current_token(&store, &head_key);

    // Move the head first, so `stale` no longer names the current version.
    let winner_staged = stage(&input);
    let winner = publication(input.clone(), &winner_staged);
    match winner_staged.publish(&store, &head_key, stale, &winner, tenant()) {
        CompactionExecution::Visible(_) => {}
        other => panic!("the first publication must land: {other:?}"),
    }

    let loser_staged = stage(&input);
    let loser = publication(input, &loser_staged);
    match loser_staged.publish(&store, &head_key, stale, &loser, tenant()) {
        CompactionExecution::Unpublished(unpublished) => {
            assert_eq!(
                unpublished.reason(),
                &CompactionPublicationRefusal::AuthorityRaceLost,
                "the compaction layer reports a lost race here -- but see the note \
                 above: chronicle classified this same candidate as Superseded"
            );
        }
        other => panic!("a stale predecessor cannot publish: {other:?}"),
    }
}

/// **§5.2, and the arm that must NOT be a refusal.**
///
/// An ambiguous authority failure means the CAS may or may not have occurred.
/// Reporting it as `Unpublished` would assert non-commit, which is exactly what
/// `AmbiguityReason::Cancelled` documents as unprovable. The outcome must be
/// `Indeterminate`.
///
/// This is the distinction between "we know it did not commit" and "we do not
/// know", and getting it backwards is the failure the type exists to prevent.
#[test]
fn an_ambiguous_authority_failure_is_indeterminate_and_never_an_unpublished_refusal() {
    let input = basis();
    let head_key = HeadKey::new(b"oq73/ambiguous-head".to_vec()).expect("bounded head key");
    let inner = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7c));
    initialize_repository(&inner, &head_key, input.body()).expect("genesis initializes");
    let token = current_token(&inner, &head_key);
    let store = AmbiguousPublishStore(inner);

    let staged = stage(&input);
    let publication = publication(input, &staged);
    match staged.publish(&store, &head_key, token, &publication, tenant()) {
        CompactionExecution::Indeterminate(_) => {}
        CompactionExecution::Unpublished(unpublished) => panic!(
            "an ambiguous failure must not manufacture a non-commit conclusion, got {:?}",
            unpublished.reason()
        ),
        other @ CompactionExecution::Visible(_) => {
            panic!("an ambiguous authority failure cannot report a visible generation: {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// frankengit-pkea: the four refusal paths of `authorize_source_deletion`.
//
// That function is documented "Consults the *authenticated* retention basis
// before allowing a source placement deletion", and it returns a
// `SourceDeletionPermit` — the capability that lets a caller delete data. Its
// success path was tested; none of the four guards in front of it was.
//
// ORDERING, which every probe below has to respect:
//   :380 totality  ->  :383 head  ->  :387 `revalidate_root`  ->  :390 permits
// Each case keeps every earlier guard satisfied and says which, or it would
// prove an earlier refusal instead of its own.
// ---------------------------------------------------------------------------

/// An object that is deliberately NOT in the totality map.
///
/// `object()` is the one totality entry the fixture records, so any other
/// identity is absent by construction. Asserted different, because a fixture
/// change that made these equal would silently turn the totality probe into a
/// second happy path.
const fn absent_object() -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([0x74; GitOidSha1::LEN]))
}

/// The durable generation the existing happy-path test reaches, extracted so
/// the refusal probes share one setup rather than duplicating the chain.
///
/// Reproduces stage -> publish -> visible -> `confirm_durability` with all
/// outputs durable, which is the only state in which retention is consulted at
/// all.
fn visible_generation(
    slot: &'static [u8],
    instance: u64,
) -> (VisibleCompaction, Digest, RepositoryAuthorityHeadId) {
    let input = basis();
    let staged = stage(&input);
    let publication = publication(input.clone(), &staged);
    let head_key = HeadKey::new(slot.to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");

    let visible = match staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &publication,
        tenant(),
    ) {
        CompactionExecution::Visible(visible) => visible,
        other => panic!("the staged generation must publish: {other:?}"),
    };
    let retention_root = match store.read_head(&head_key).expect("head read after publish") {
        HeadRead::Present(receipt) => {
            decode_body::<RepositoryAuthorityHeadBody>(receipt.body(), DecodeLimits::DEFAULT)
                .expect("published head is a canonical body")
                .retention_root
        }
        HeadRead::Absent => panic!("a successful CAS cannot remove a head"),
    };
    let successor = visible.successor_head();
    (visible, retention_root, successor)
}

/// The number of physical outputs `stage()` above places in the output stage.
///
/// `a_receipt_matching_the_stage_confirms_durability` pins this empirically, so
/// a fixture change cannot silently turn the cardinality probe below into a
/// second copy of some other refusal.
const STAGED_OUTPUT_COUNT: usize = 3;

/// The durable generation the existing happy-path test reaches, extracted so
/// the refusal probes share one setup rather than duplicating the chain.
fn durable_generation(
    slot: &'static [u8],
    instance: u64,
) -> (DurableCompaction, Digest, RepositoryAuthorityHeadId) {
    let (visible, retention_root, successor) = visible_generation(slot, instance);
    let durable = visible
        .confirm_durability(DurabilityReceipt::new(
            visible.generation(),
            CompactionProfile::ConservativeInterimV1,
            vec![PublicationState::new(true, true, true); STAGED_OUTPUT_COUNT],
            digest(0x82),
        ))
        .expect("all-durable outputs unlock retention evaluation");
    (durable, retention_root, successor)
}

fn proposal_for(head: RepositoryAuthorityHeadId, retention_root: Digest) -> RetentionRootProposal {
    RetentionRootProposal::new(
        head,
        retention_root,
        vec![derived!(SegmentManifestId, 0x51)],
    )
    .expect("one manifest is canonical")
}

/// Deleting an object the generation never accounted for is refused first.
///
/// This is the outermost guard, so nothing earlier can pre-empt it. The
/// registry is fully permissive — matching head, `permits: true` — which is
/// what makes the refusal attributable to the totality check rather than to
/// anything the registry did.
#[test]
fn deleting_a_source_outside_the_totality_map_is_refused() {
    let (durable, retention_root, successor) = durable_generation(b"fg079/pkea-totality", 0x91);
    assert_ne!(
        absent_object(),
        object(),
        "the probe object must differ from the one totality entry",
    );

    let refusal = durable.authorize_source_deletion(
        &RetentionRegistry {
            head: successor,
            permits: true,
        },
        &proposal_for(successor, retention_root),
        absent_object(),
    );
    assert_eq!(refusal, Err(RetentionRefusal::SourceNotInTotality));
}

/// A proposal naming a head other than the compacted successor is refused.
///
/// Earlier guard satisfied: the object IS in the totality map, so
/// `SourceNotInTotality` cannot fire first. The registry again permits
/// everything, so only the proposal's head is wrong.
#[test]
fn a_retention_proposal_for_another_head_is_refused() {
    let (durable, retention_root, successor) = durable_generation(b"fg079/pkea-head", 0x92);
    let foreign = derived!(RepositoryAuthorityHeadId, 0x66);
    assert_ne!(
        foreign, successor,
        "the foreign head must differ or the refusal below is vacuous",
    );

    let refusal = durable.authorize_source_deletion(
        &RetentionRegistry {
            head: successor,
            permits: true,
        },
        &proposal_for(foreign, retention_root),
        object(),
    );
    assert_eq!(refusal, Err(RetentionRefusal::AuthorityHeadMismatch));
}

/// A stale retention basis is refused by the registry, not by this crate.
///
/// Earlier guards satisfied: the object is in the totality map and the
/// PROPOSAL names the compacted successor — that second part is essential,
/// because a proposal for another head would trip `AuthorityHeadMismatch`
/// before the registry is consulted at all. The REGISTRY is the thing that
/// disagrees, so `revalidate_root` refuses.
///
/// The inner `StoreRefusal` is asserted, not just the outer variant, and that
/// is forced rather than stylistic: `Registry(..)` wraps BOTH registry calls
/// (protocol.rs:387 and :390), so the outer variant cannot say which refused.
#[test]
fn a_retention_basis_the_registry_no_longer_recognises_is_refused() {
    let (durable, retention_root, successor) = durable_generation(b"fg079/pkea-basis", 0x93);

    let refusal = durable.authorize_source_deletion(
        &RetentionRegistry {
            head: derived!(RepositoryAuthorityHeadId, 0x67),
            permits: true,
        },
        &proposal_for(successor, retention_root),
        object(),
    );
    assert_eq!(
        refusal,
        Err(RetentionRefusal::Registry(
            StoreRefusal::RetentionRevalidationFailed
        )),
        "a stale basis must be distinguishable from a retained object, and only \
         the inner refusal carries that distinction",
    );
}

/// An object the registry retains is refused even with a current basis.
///
/// Earlier guards satisfied: object in totality, proposal head matches the
/// successor, and the registry's head matches so `revalidate_root` succeeds.
/// The only remaining difference is `permits: false`.
///
/// Together with the test above, this is the pair that shows `Registry(..)`
/// covers two genuinely different operator situations — a stale basis versus a
/// retained object — which the outer variant alone cannot report.
#[test]
fn an_object_the_registry_retains_is_refused_even_on_a_current_basis() {
    let (durable, retention_root, successor) = durable_generation(b"fg079/pkea-retained", 0x94);

    let refusal = durable.authorize_source_deletion(
        &RetentionRegistry {
            head: successor,
            permits: false,
        },
        &proposal_for(successor, retention_root),
        object(),
    );
    assert_eq!(
        refusal,
        Err(RetentionRefusal::Registry(StoreRefusal::DeletionRetained)),
    );
}

/// The permit carries the generation it was authorized against.
///
/// The existing happy-path test asserts the permit's source; this pins the
/// other half. A permit naming a different generation would authorize a
/// deletion against a compaction that did not account for the object, which is
/// the whole property the totality guard exists to establish.
#[test]
fn a_granted_permit_names_the_generation_that_authorized_it() {
    let (durable, retention_root, successor) = durable_generation(b"fg079/pkea-permit", 0x95);

    let permit = durable
        .authorize_source_deletion(
            &RetentionRegistry {
                head: successor,
                permits: true,
            },
            &proposal_for(successor, retention_root),
            object(),
        )
        .expect("an authenticated retention basis permits deletion");

    assert_eq!(permit.source(), object());
    assert_eq!(
        permit.generation(),
        durable.generation(),
        "a permit must name the compaction generation that authorized it",
    );
}

// ---------------------------------------------------------------------------
// frankengit-wpn8: the integrity guards of `confirm_durability`.
//
// `DurableCompaction` is what unlocks retention evaluation -- only a compaction
// that has passed this call can be asked to `authorize_source_deletion`
// (frankengit-pkea). Four guards stand in front of it:
//
//   :296 generation -> :299 profile -> :302 cardinality -> :309 not-durable
//
// One was exercised, on one of its three axes. Each probe below keeps every
// earlier guard satisfied, or it would prove an earlier refusal under its own
// name.
//
// `ProfileMismatch` (:299) has NO probe here and that is deliberate:
// `CompactionProfile` (record.rs:51) has exactly one variant, so
// `receipt.profile != self.staged.record.profile` is unreachable from any
// caller. Adding a variant to make it fire would be changing the code to serve
// the test. It is recorded as unreachable, not as covered.
// ---------------------------------------------------------------------------

/// A receipt naming a different generation cannot confirm this one.
///
/// Every other field is valid -- right profile, right cardinality, every output
/// fully durable -- so the refusal is attributable to the generation alone.
///
/// The foreign id is built directly rather than taken from a second store: the
/// generation derives from the compaction record body, so a second store over
/// the same fixture would mint a byte-identical id and this probe would pass
/// while proving nothing.
#[test]
fn a_durability_receipt_for_another_generation_is_refused() {
    let (visible, _, _) = visible_generation(b"fg079/wpn8-generation", 0xa1);
    let foreign = derived!(GenerationId, 0x69);
    assert_ne!(
        foreign,
        visible.generation(),
        "the foreign generation must differ or the refusal below is vacuous",
    );

    let refusal = visible.confirm_durability(DurabilityReceipt::new(
        foreign,
        CompactionProfile::ConservativeInterimV1,
        vec![PublicationState::new(true, true, true); STAGED_OUTPUT_COUNT],
        digest(0x83),
    ));
    assert_eq!(refusal, Err(DurabilityRefusal::GenerationMismatch));
}

/// A receipt covering the wrong number of outputs is refused in BOTH
/// directions.
///
/// Under-count and over-count are both checked, and that is the point: the
/// guard is `!=`, and a `<` written by mistake would accept the over-count
/// while still passing an under-count-only test. Every state is fully durable
/// in both receipts, so the later not-durable guard cannot be what fires.
#[test]
fn a_durability_receipt_of_the_wrong_cardinality_is_refused() {
    let (visible, _, _) = visible_generation(b"fg079/wpn8-cardinality", 0xa2);

    for count in [STAGED_OUTPUT_COUNT - 1, STAGED_OUTPUT_COUNT + 1] {
        let refusal = visible.confirm_durability(DurabilityReceipt::new(
            visible.generation(),
            CompactionProfile::ConservativeInterimV1,
            vec![PublicationState::new(true, true, true); count],
            digest(0x84),
        ));
        assert_eq!(
            refusal,
            Err(DurabilityRefusal::OutputReceiptCardinality),
            "a receipt covering {count} outputs cannot confirm a \
             {STAGED_OUTPUT_COUNT}-output stage",
        );
    }
}

/// An output that was never staged is not durable, however durable it claims.
///
/// This axis looks redundant -- surely nothing can be durable without having
/// been staged -- and it is not, because `PublicationState::new`
/// (fabric.rs:974) is an unvalidated three-`bool` constructor that enforces no
/// ordering between the epochs. A non-monotone state is constructible, so the
/// guard has to check this term, and dropping it is a change no other test in
/// the suite would notice.
#[test]
fn an_output_that_was_never_staged_is_not_durable() {
    let (visible, _, _) = visible_generation(b"fg079/wpn8-staged-axis", 0xa3);

    let refusal = visible.confirm_durability(DurabilityReceipt::new(
        visible.generation(),
        CompactionProfile::ConservativeInterimV1,
        vec![PublicationState::new(false, true, true); STAGED_OUTPUT_COUNT],
        digest(0x85),
    ));
    assert_eq!(refusal, Err(DurabilityRefusal::OutputNotDurable));
}

/// An output that never became visible is not durable.
///
/// The second unexercised term of the same disjunction. AGENTS.md 5.4 requires
/// staged, visible, and durable to stay distinct; this is the test that makes
/// the middle epoch load-bearing rather than assumed.
#[test]
fn an_output_that_never_became_visible_is_not_durable() {
    let (visible, _, _) = visible_generation(b"fg079/wpn8-visible-axis", 0xa4);

    let refusal = visible.confirm_durability(DurabilityReceipt::new(
        visible.generation(),
        CompactionProfile::ConservativeInterimV1,
        vec![PublicationState::new(true, false, true); STAGED_OUTPUT_COUNT],
        digest(0x86),
    ));
    assert_eq!(refusal, Err(DurabilityRefusal::OutputNotDurable));
}

/// The permitted twin: a receipt matching the stage confirms durability and
/// carries its evidence into the capability.
///
/// This is the half that makes the four refusals above mean something -- four
/// tests that only ever see `Err` would pass against a `confirm_durability`
/// that refused unconditionally. It also pins `STAGED_OUTPUT_COUNT`
/// empirically: change the fixture's output count and this fails loudly rather
/// than letting the cardinality probe drift into agreement.
///
/// The evidence root is asserted, not just `is_ok`: the durability evidence is
/// the whole reason the receipt exists, and a call that dropped it would still
/// return `Ok`.
#[test]
fn a_receipt_matching_the_stage_confirms_durability() {
    let (visible, _, _) = visible_generation(b"fg079/wpn8-permitted", 0xa5);
    let evidence = digest(0x87);

    let durable = visible
        .confirm_durability(DurabilityReceipt::new(
            visible.generation(),
            CompactionProfile::ConservativeInterimV1,
            vec![PublicationState::new(true, true, true); STAGED_OUTPUT_COUNT],
            evidence,
        ))
        .expect("a matching all-durable receipt confirms durability");

    assert_eq!(
        durable.generation(),
        visible.generation(),
        "confirming durability must not change which generation is durable",
    );
    assert_eq!(
        durable.durability_evidence_root(),
        evidence,
        "the receipt's durability evidence must survive into the capability",
    );
}

// ---------------------------------------------------------------------------
// frankengit-6c3r: the FOURTH verdict arm.
//
// `StagedCompaction::publish` matches four arms of `PublicationVerdict` and
// maps each to a different execution outcome:
//
//   Published       -> Visible
//   Lost            -> Unpublished(AuthorityRaceLost)
//   AlreadyDecided  -> Unpublished(AlreadyDecided)
//   Err(failure)    -> Indeterminate
//
// Three were pinned above — the section header two blocks up says "the three
// outcomes", and that undercount is the gap. The fourth is §5.2's arm: one
// sealed transaction has at most one terminal decision, and a batch whose
// transaction is already terminal must not be re-decided.
//
// Note which `AlreadyDecided` this is. Three distinct types carry the name:
// `fgit-authority`'s `PublicationOutcome::AlreadyDecided` (tested in that
// crate), `fgit-chronicle`'s `PublicationVerdict::AlreadyDecided`, and this
// crate's `CompactionPublicationRefusal::AlreadyDecided`. A grep for the bare
// word finds the tested one and reports a false green.
// ---------------------------------------------------------------------------

/// **§5.2.** A transaction that already reached a terminal decision is refused
/// as `AlreadyDecided`, and that is NOT a lost race.
///
/// Driven through the real authority path rather than a store double: the
/// first publication lands, and the second is built on the **successor** head
/// so it passes every `validate_publication` guard, against the **current**
/// token so its CAS predecessor is correct. The only thing wrong with it is
/// that `commit_record` pins one `tx_id`, so both batches carry the same
/// transaction — and that transaction is already terminal.
///
/// A double returning the verdict would prove the match arm compiles. This
/// proves the protocol reaches it.
///
/// The distinction from `AuthorityRaceLost` is the point, and both arms land on
/// `Unpublished` with the staged output intact, so a probe that only checked
/// `Unpublished` could not tell them apart. They mean opposite things to an
/// operator: a lost race says retry against the new head; an already-terminal
/// transaction says do **not** retry, the decision exists. Chronicle's own
/// comment says this arm is deliberately not routed through `classify_loss`,
/// because the head did not move.
#[test]
fn a_transaction_that_is_already_terminal_reports_already_decided_not_a_lost_race() {
    let input = basis();
    let head_key = HeadKey::new(b"6c3r/already-decided".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7d));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");

    let first_staged = stage(&input);
    let first = publication(input.clone(), &first_staged);
    match first_staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &first,
        tenant(),
    ) {
        CompactionExecution::Visible(_) => {}
        other => panic!("the first publication must land: {other:?}"),
    }

    // Re-publish the IDENTICAL batch: same basis, same record, so the same
    // compaction-generation link and therefore the same committed RCR. A
    // duplicate that produced *different* canonical content would not be
    // idempotent -- it would be one transaction with two different terminal
    // outcomes, which is the conflict §5.2 exists to prevent, and a different
    // failure entirely.
    let second_staged = stage(&input);
    let second = publication(input, &second_staged);
    match second_staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &second,
        tenant(),
    ) {
        CompactionExecution::Unpublished(unpublished) => {
            assert_eq!(
                unpublished.reason(),
                &CompactionPublicationRefusal::AlreadyDecided,
                "an already-terminal transaction must not be re-decided"
            );
            assert_ne!(
                unpublished.reason(),
                &CompactionPublicationRefusal::AuthorityRaceLost,
                "the head did not move, so this is not a lost race; reporting one \
                 would tell the caller to discard positions that are still valid"
            );
        }
        CompactionExecution::Indeterminate(_) => panic!(
            "an already-terminal transaction is a DEFINITE non-move, not an unknown: \
             the head did not move and nothing was attempted"
        ),
        other @ CompactionExecution::Visible(_) => {
            panic!("re-deciding a terminal transaction cannot publish a generation: {other:?}")
        }
    }
}

/// The staged output survives an already-decided refusal, exactly as it does a
/// lost race.
///
/// Asserted separately because it is what makes the reason worth reporting: the
/// caller still holds everything it staged, and the reason is the only thing
/// telling it whether replanning is appropriate.
#[test]
fn an_already_decided_refusal_keeps_the_staged_output() {
    let input = basis();
    let head_key = HeadKey::new(b"6c3r/already-decided-staged".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7e));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");

    let first_staged = stage(&input);
    let first = publication(input.clone(), &first_staged);
    match first_staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &first,
        tenant(),
    ) {
        CompactionExecution::Visible(_) => {}
        other => panic!("the first publication must land: {other:?}"),
    }

    let second_staged = stage(&input);
    let handed_in = second_staged.generation();
    let second = publication(input, &second_staged);
    match second_staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &second,
        tenant(),
    ) {
        CompactionExecution::Unpublished(unpublished) => {
            assert_eq!(
                unpublished.reason(),
                &CompactionPublicationRefusal::AlreadyDecided
            );
            let recovered = unpublished.into_staged();
            assert_eq!(
                recovered.generation(),
                handed_in,
                "into_staged must hand back exactly the compaction that was attempted, \
                 so a caller can re-plan it against a fresh authenticated basis"
            );
        }
        other => panic!("expected an already-decided refusal: {other:?}"),
    }
}

/// **Why `Codec` is not reachable through `stage`.**
///
/// `stage` calls `record.validate()` and maps failure to `Record`. The very
/// next statement calls `record.generation_id()`, which calls `self.validate()`
/// **again** and maps failure to `Codec`. The earlier guard subsumes the later
/// one's validation half, so no invalid record can reach the `Codec` arm this
/// way — what remains behind `Codec` is the crypto identity computation for a
/// record that already validated.
///
/// This is recorded as a test rather than a comment because it is the ordering
/// that makes it true: move the two statements and the same input reports the
/// other variant. Measured, not argued — the bead's mutation matrix records
/// that deleting the `Codec` arm changes no test result here.
#[test]
fn an_invalid_record_reports_record_because_that_guard_precedes_the_codec_one() {
    let input = basis();
    let mut invalid = record(&input);
    // A totality entry naming a pack root the outputs never list. The map's own
    // shape check passes; the cross-reference check inside `validate` is what
    // refuses.
    invalid.totality = SourceOutputTotalityMap::new(vec![
        TotalityEntry {
            source: SourceEntry::Object(object()),
            disposition: OutputDisposition::Stored {
                pack_root: digest(0x7f),
                segment_manifest: derived!(SegmentManifestId, 0x51),
            },
        },
        TotalityEntry {
            source: SourceEntry::Decision(DecisionSequence::FIRST),
            disposition: OutputDisposition::DocumentedDrop {
                evidence_root: digest(0x42),
            },
        },
    ])
    .expect("the map's shape is well formed; only the cross-reference is wrong");

    let refusal = StagedCompaction::stage(
        invalid,
        OutputStageReceipt::new(vec![PublicationState::new(true, false, false); 3])
            .expect("all physical outputs are staged"),
    )
    .expect_err("a record whose totality names an unknown output cannot stage");

    assert!(
        matches!(refusal, CompactionPublicationRefusal::Record(_)),
        "the validate() guard owns this refusal, got {refusal:?}"
    );
    assert!(
        !matches!(refusal, CompactionPublicationRefusal::Codec(_)),
        "reaching Codec would mean the identity computation ran on an unvalidated record"
    );
}
