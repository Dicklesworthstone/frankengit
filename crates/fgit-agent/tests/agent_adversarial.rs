#![forbid(unsafe_code)]
//! FG-030c adversarial corpus for the real Agent Protocol boundaries.
//!
//! The corpus rows are malicious *source text*.  Each row is admitted through
//! the production [`ContextPacket`] source channel, then an effect request is
//! sent to the production [`EffectBroker`].  This matters: a test that merely
//! searched strings would not establish that an injection remains separate
//! from control metadata or that it cannot acquire an effect reservation.
//!
//! The evidence case uses the immutable `fgit-evidence` verifier, and the
//! interrupted-outbox case owns the real `fgit-resource` obligation.  Thus no
//! mock claims to be an authority, an evidence verifier, or an external-effect
//! ledger.  The in-process channel is deliberately a bounded model of a
//! downstream provider; it is not a live-provider or durable-journal claim.

use core::num::NonZeroU32;

use fgit_agent::{
    AgentInstanceId, AuthorityBasisRef, AuthorityReadReceipt, BrokerRefusal, Capability,
    CapabilityId, ClassSet, ContextControl, ContextPacket, ContextSource, EffectBroker, EffectId,
    EffectRequest, EffectTerminalOutcome, ExternalEffectOutcome, IntentRun, LogicalTime,
    OperationClass, RetrievalChannel, RunId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_claim::ClaimRank;
use fgit_codec::{DecodeLimits, RepositoryAuthorityHeadBody};
use fgit_evidence::{
    EvidenceArtifact, EvidenceContext, EvidenceRecord, EvidenceRecordBody, EvidenceRefusal,
    EvidenceText, ReplayCompleteness,
};
use fgit_resource::{
    DownstreamChannel, DownstreamIdempotency, IdempotencyKey, OpaqueHandle, ReconcilePlan,
    ReconcilePolicy, RegionId, ResourceVector,
    algebra::Grade,
    kinds::{DownstreamAck, OutboxDispatch},
    settlement::{DeliveryVerdict, ProbeVerdict},
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, EvidenceRecordId,
    HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch, PrincipalId, RegistryEpoch, RepositoryCommitId,
    RepositoryId, RepositorySequence,
};

const CORPUS: &str = include_str!("corpus/agent_adversarial.tsv");
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff2;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

#[derive(Debug)]
struct CorpusCase<'a> {
    id: &'a str,
    operation: OperationClass,
    payload: &'a [u8],
}

fn corpus_cases() -> Vec<CorpusCase<'static>> {
    let mut cases = Vec::new();
    for (line_number, line) in CORPUS.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.splitn(3, '|');
        let id = fields
            .next()
            .unwrap_or_else(|| panic!("corpus line {} lacks an id", line_number + 1));
        let operation = match fields
            .next()
            .unwrap_or_else(|| panic!("corpus line {} lacks an operation", line_number + 1))
        {
            "external_integration" => OperationClass::ExternalIntegration,
            "prepare_publication" => OperationClass::PreparePublication,
            "secret_handle" => OperationClass::SecretHandle,
            "submit_evidence" => OperationClass::SubmitEvidence,
            other => panic!(
                "corpus line {} has an unsupported closed operation label {other:?}",
                line_number + 1
            ),
        };
        let payload = fields
            .next()
            .unwrap_or_else(|| panic!("corpus line {} lacks a payload", line_number + 1));
        assert!(
            !id.is_empty() && !payload.is_empty(),
            "corpus line {} names both an attack and its source bytes",
            line_number + 1
        );
        cases.push(CorpusCase {
            id,
            operation,
            payload: payload.as_bytes(),
        });
    }
    assert!(
        !cases.is_empty(),
        "the adversarial corpus must not be empty"
    );
    let unique_ids: std::collections::BTreeSet<&str> = cases.iter().map(|case| case.id).collect();
    assert_eq!(
        unique_ids.len(),
        cases.len(),
        "a duplicate corpus id would silently run one attack twice and omit another"
    );
    cases
}

const fn time(value: u64) -> LogicalTime {
    LogicalTime::new(value)
}

const fn basis() -> AuthorityBasisRef {
    AuthorityBasisRef {
        repository_id: 0x030c,
        authority_head_generation: 1,
        authority_head_digest: [0x30; 32],
        verified_at: time(1),
    }
}

fn bytes(amount: u64) -> ResourceVector {
    ResourceVector::single(Grade::Bytes, amount)
}

fn egress(amount: u64) -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, amount)
}

fn read_only_run() -> IntentRun {
    IntentRun::new(
        RunId::new(0x030c),
        basis(),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        bytes(1_024),
        time(100),
    )
    .expect("the corpus control run is nonempty and bounded")
}

fn read_only_capability() -> Capability {
    Capability::issue(
        CapabilityId::new(0x030c),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        bytes(1_024),
        time(0),
        time(100),
    )
    .expect("the corpus read capability is valid")
}

fn request(effect_id: u128, operation: OperationClass, cost: ResourceVector) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(effect_id),
        parent_effect_id: None,
        operation,
        cost,
        input_commitment: [effect_id as u8; 32],
    }
}

fn repository_commit(tag: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("reserved corpus fixture algorithm is nonzero"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("repository commit fixture has 32 bytes"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let repository_id = RepositoryId::from_bytes([0x30; 16]);
    let root = outcome_index_root(&[]).expect("the empty outcome root is canonical");
    let head = RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(repository_commit(0x31)),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let expected = authority_head_identity(&head).expect("the authority head identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x030c));
    let key = HeadKey::new(b"agent-adversarial-corpus".to_vec())
        .expect("corpus authority key is bounded and nonempty");
    let read = match initialize_repository(&store, &key, &head)
        .expect("the production in-memory authority store initializes the test head")
    {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("a fresh corpus authority store must create its head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("the authority store authenticates the receipt it issued");
    let receipt =
        AuthorityReadReceipt::from_authenticated_head(&authenticated, time(2), [0x32; 32])
            .expect("the context packet uses a complete authenticated authority receipt");
    assert_eq!(receipt.authority_head_id(), expected);
    receipt
}

fn context_control() -> ContextControl {
    ContextControl::new(
        [0x33; 32],
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        [0x34; 32],
        vec![[0x35; 32]],
        vec![[0x36; 32]],
    )
}

#[test]
fn untrusted_corpus_cannot_widen_effect_capabilities_or_request_secrets() {
    let cases = corpus_cases();
    let sources = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            ContextSource::new(
                [u8::try_from(index).expect("the bounded fixture corpus fits in u8"); 32],
                RetrievalChannel::Exact,
                case.payload.to_vec(),
            )
            .expect("each bounded malicious string remains a visibly untrusted source")
        })
        .collect();
    let packet = ContextPacket::build(authority_receipt(), context_control(), sources)
        .expect("the real context packet binds the corpus to one authority receipt");

    assert_eq!(
        packet.control().authorization_scope(),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        "untrusted text cannot alter authenticated control scope"
    );
    for (case, source) in cases.iter().zip(packet.sources()) {
        assert_eq!(
            source.untrusted_bytes(),
            case.payload,
            "{} stays in the source-data channel",
            case.id
        );
    }

    let capability = read_only_capability();
    let mut broker = EffectBroker::open(
        read_only_run(),
        RegionId::new(0x030c),
        AgentInstanceId::new(0x030c),
    );
    for (index, case) in cases.iter().enumerate() {
        let effect_id = 0x030c_0000 + u128::try_from(index).expect("fixture index fits");
        let refusal = broker
            .request(
                &capability,
                time(10),
                &request(effect_id, case.operation, bytes(1)),
            )
            .expect_err("repository text cannot acquire an operation outside the exact run");
        assert!(
            matches!(
                refusal,
                BrokerRefusal::OperationOutsideRun { requested, .. } if requested == case.operation
            ),
            "{} must be refused as the exact attempted operation, not reinterpreted",
            case.id
        );
    }
    assert!(
        broker.records().is_empty(),
        "refused injected requests cannot create a ledger record or consume a reservation"
    );

    let permitted = broker
        .request(
            &capability,
            time(10),
            &request(0x030c_ffff, OperationClass::ReadCanonicalObject, bytes(1)),
        )
        .expect("the near-identical, authorized canonical read remains permitted");
    let _abort_receipt = broker
        .abort(permitted)
        .expect("the permitted control effect settles explicitly");
    assert!(broker.close().is_quiescent());
}

fn evidence_text(value: &str) -> EvidenceText {
    EvidenceText::parse("agent-adversarial", value)
        .expect("the fixed evidence fixture text is canonical")
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("reserved corpus fixture algorithm is nonzero"),
        DigestBytes::try_new(&[tag; 32]).expect("fixture digest has 32 bytes"),
    )
}

fn verifiable_evidence_record() -> EvidenceRecord {
    let context = EvidenceContext::new(
        vec![evidence_text("agent-adversarial-input")],
        evidence_text("fgit-agent"),
        evidence_text("dated-nightly"),
        evidence_text("adversarial-corpus"),
        evidence_text("single-run"),
        evidence_text("local-exact"),
        vec![evidence_text("no-live-provider-claim")],
        evidence_text("independent-verifier"),
        vec![EvidenceArtifact::new(
            evidence_text("receipt"),
            digest(0x41),
        )],
        evidence_text("typed-refusal"),
        ReplayCompleteness::Replayable,
        None,
    )
    .expect("the real evidence context is complete and bounded");
    EvidenceRecord::new(
        EvidenceRecordBody::new(
            evidence_text("agent-adversarial-corpus"),
            evidence_text("fg030c"),
            ClaimRank::BoundedModel,
            ClaimRank::BoundedModel,
            context,
        )
        .expect("an evidence claim cannot outrank its evidence"),
    )
    .expect("the evidence verifier frames and identity-binds a real receipt")
}

#[test]
fn fabricated_evidence_identity_is_refused_by_the_real_evidence_verifier() {
    let record = verifiable_evidence_record();
    record
        .verify(DecodeLimits::DEFAULT)
        .expect("the permitted twin proves the verifier itself admits a valid receipt");

    let fabricated = EvidenceRecordId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("reserved corpus fixture algorithm is nonzero"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x42; 32]).expect("fabricated identity has 32 bytes"),
    );
    let refusal = EvidenceRecord::decode(fabricated, record.frame(), DecodeLimits::DEFAULT)
        .expect_err("a claimed receipt that commits to different canonical bytes is refused");
    assert!(
        matches!(refusal, EvidenceRefusal::IdentityMismatch { .. }),
        "the refusal must name identity disagreement rather than accepting a fabricated receipt"
    );
}

fn external_run() -> IntentRun {
    IntentRun::new(
        RunId::new(0x030c_e),
        basis(),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_024),
        time(100),
    )
    .expect("external-effect corpus run is bounded")
}

fn external_capability() -> Capability {
    Capability::issue(
        CapabilityId::new(0x030c_e),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_024),
        time(0),
        time(100),
    )
    .expect("external-effect corpus capability is valid")
}

fn dispatch(tag: u8, strength: DownstreamIdempotency) -> OutboxDispatch {
    OutboxDispatch {
        idempotency: IdempotencyKey::new(digest(tag)),
        precondition_rcr: repository_commit(tag.wrapping_add(1)),
        endpoint: OpaqueHandle::new(&[tag.wrapping_add(2); 20])
            .expect("bounded opaque downstream endpoint"),
        idempotency_strength: strength,
    }
}

const fn reconciliation_policy() -> ReconcilePolicy {
    ReconcilePolicy::new(NonZeroU32::MIN)
}

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

struct InterruptedChannel {
    probe: ProbeVerdict,
    deliveries: u32,
    probes: u32,
}

impl DownstreamChannel for InterruptedChannel {
    fn deliver(&mut self, _: &IdempotencyKey, _: u32) -> DeliveryVerdict {
        self.deliveries = self.deliveries.saturating_add(1);
        DeliveryVerdict::AmbiguousTimeout
    }

    fn probe(&mut self, _: &IdempotencyKey) -> ProbeVerdict {
        self.probes = self.probes.saturating_add(1);
        self.probe
    }
}

#[test]
fn interrupted_external_effects_are_reconciled_or_explicitly_escalated_then_quiesced() {
    let mut broker = EffectBroker::open(
        external_run(),
        RegionId::new(0x030d),
        AgentInstanceId::new(0x030d),
    );
    let dispatch = dispatch(0x51, DownstreamIdempotency::Weak);
    let grant = broker
        .request(
            &external_capability(),
            time(10),
            &request(0x030c_e001, OperationClass::ExternalIntegration, egress(64)),
        )
        .expect("the real broker reserves the authorized external effect once");
    let deferred = broker
        .reserve_outbox(grant, dispatch)
        .expect("the external effect becomes the shared outbox obligation")
        .dispatch(1, &egress(64))
        .expect("the dispatch is canonically committed before the crash window");

    let mut channel = InterruptedChannel {
        probe: ProbeVerdict::Unknown,
        deliveries: 0,
        probes: 0,
    };
    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        reconciliation_policy(),
    );
    let outcome = deferred
        .reconcile(
            &mut plan,
            &mut channel,
            principal(0x51),
            |attempt| DownstreamAck {
                receipt: OpaqueHandle::new(&[0x52; 20])
                    .expect("bounded downstream acknowledgement"),
                attempt,
            },
            vec![[0x53; 32]],
        )
        .expect("the crash window becomes a typed external outcome");
    let escalated = match outcome {
        ExternalEffectOutcome::Escalated(effect) => effect,
        ExternalEffectOutcome::Acknowledged(_) | ExternalEffectOutcome::TerminallyFailed(_) => {
            panic!("a weak downstream Unknown probe must not be fabricated as terminal success")
        }
    };
    assert_eq!(channel.deliveries, 1);
    assert_eq!(channel.probes, 1);
    let record = broker
        .records()
        .pop()
        .expect("the interrupted effect remains in the ledger");
    assert!(matches!(
        record.terminal_outcome,
        Some(EffectTerminalOutcome::Escalated { .. })
    ));
    assert_eq!(
        record
            .reconciliation_evidence
            .as_ref()
            .expect("the ledger retains the downstream observations")
            .transitions
            .len(),
        2
    );

    let _late_acknowledgement = escalated
        .resolve_acknowledged(
            DownstreamAck {
                receipt: OpaqueHandle::new(&[0x54; 20]).expect("bounded late acknowledgement"),
                attempt: 1,
            },
            vec![[0x55; 32]],
        )
        .expect("a named owner can settle the unresolved external effect explicitly");
    let resolved = broker
        .records()
        .pop()
        .expect("the resolved outcome remains replayable");
    assert_eq!(
        resolved.terminal_outcome,
        Some(EffectTerminalOutcome::Acknowledged)
    );
    assert!(broker.close().is_quiescent());
}
