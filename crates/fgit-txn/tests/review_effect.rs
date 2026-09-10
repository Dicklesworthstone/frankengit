//! Review effects use the production facade's one reference fold and codec.
//! These tests do not treat the in-memory model as durable authority evidence.
use std::collections::{BTreeMap, BTreeSet};
use fgit_reference::effect::{FoldBasis, FoldOutcome};
use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey, Intent, OutboxDeliveryKey, OutboxIntent};
use fgit_types::{MismatchPolicy, RefName, SchemaFamily, SchemaId};
use fgit_txn::{IntentEvaluator, canonical_fold_bytes, canonical_forge_effect_bytes};

#[test]
fn reviewer_streams_fold_without_moving_refs_or_advancing_the_pr() {
    let mut mint = IdentityMint::new(812);
    let tenant = mint.tenant(); let repository = mint.repository(); let principal = mint.principal();
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let pr = ForgeStreamId::new(label("pull-request/17"));
    let streams = [ForgeStreamId::new(label("review/17/a")), ForgeStreamId::new(label("review/17/b"))];
    let events = streams.map(|stream| ForgeEventKind::PullRequestReviewed {
        review: ForgeEntityId::new(stream.label()), target: target.clone(),
    });
    let delivery = OutboxDeliveryKey::new(label("review-effect"));
    let parameters = mint.digest();
    let request = RequestBuilder::new(tenant, repository, principal,
        SchemaId::new(SchemaFamily::from_static("fgit/review-test"), 1, 0), IdempotencyKey::new(label("reviews")))
        .statement(MismatchPolicy::TxnAbort, vec![
            Intent::Forge(ForgeIntent { stream: streams[0], expected_position: ForgeStreamPosition::GENESIS, event: events[0].clone() }),
            Intent::Forge(ForgeIntent { stream: streams[1], expected_position: ForgeStreamPosition::GENESIS, event: events[1].clone() }),
            Intent::Outbox(OutboxIntent { delivery_key: delivery, parameters }),
        ]).build(&mut mint);
    let refs = BTreeMap::new();
    let positions = BTreeMap::from([(pr, ForgeStreamPosition::new(4))]);
    let retention = BTreeSet::new(); let outbox = BTreeMap::new();
    let basis = FoldBasis { refs: &refs, forge_positions: &positions, retention: &retention, outbox: &outbox };
    let report = IntentEvaluator.evaluate(basis, &request);
    IntentEvaluator.validate_report(&request, &report).unwrap();
    let effects = report.effects().unwrap();
    assert!(effects.refs.is_empty()); assert!(effects.retention.is_empty());
    assert!(!effects.forge.contains_key(&pr));
    assert_eq!(effects.forge, BTreeMap::from([(streams[0], vec![events[0].clone()]), (streams[1], vec![events[1].clone()])]));
    assert_eq!(effects.outbox, BTreeMap::from([(delivery, parameters)]));
    assert!(events.iter().all(|event| event.required_ref_effect().is_none()));
    let encoded = canonical_fold_bytes(&request, &report).unwrap();
    assert_eq!(encoded, canonical_fold_bytes(&request, &IntentEvaluator.evaluate(basis, &request)).unwrap());
    let literal = b"\x05\0\0\0\x0breview/17/a\0\0\0\x0frefs/heads/main";
    let bytes = canonical_forge_effect_bytes(effects).unwrap();
    assert!(bytes.windows(literal.len()).any(|part| part == literal));
    let changed = BTreeMap::from([(streams[0], ForgeStreamPosition::new(1)), (pr, ForgeStreamPosition::new(4))]);
    let stale = IntentEvaluator.evaluate(FoldBasis { forge_positions: &changed, ..basis }, &request);
    assert!(matches!(stale.outcome, FoldOutcome::Aborted { .. }));
    assert!(stale.effects().is_none(), "one stale reviewer precondition cannot publish the other effects");
}

#[test]
fn review_kind_survives_complete_trace_codec_and_replay_without_relabeling_metadata() {
    use fgit_reference::machine::ModelInput;
    use fgit_reference::state::{GenesisConfiguration, PolicySnapshot};
    use fgit_reference::trace::{TraceRecorder, decode, encode, replay};
    use fgit_reference::transition::SealRequest;
    use fgit_types::{GitHashAlgorithm, PolicyEpoch, RegistryEpoch};
    let mut mint = IdentityMint::new(813);
    let genesis = GenesisConfiguration {
        tenant: mint.tenant(), repository: mint.repository(), object_format: GitHashAlgorithm::Sha1,
        genesis_head_id: mint.head(), format_registry_epoch: RegistryEpoch::FIRST,
        policy: PolicySnapshot { epoch: PolicyEpoch::FIRST, protected_scopes: BTreeSet::new(),
            principals: BTreeMap::new(), max_intents_per_transaction: 8,
            supported_schemas: BTreeSet::new(), supported_durability: BTreeSet::new() },
    };
    let request = RequestBuilder::new(genesis.tenant, genesis.repository, mint.principal(),
        SchemaId::new(SchemaFamily::from_static("fgit/review-test"), 1, 0), IdempotencyKey::new(label("review-codec")))
        .statement(MismatchPolicy::TxnAbort, vec![Intent::Forge(ForgeIntent {
            stream: ForgeStreamId::new(label("review/17/a")), expected_position: ForgeStreamPosition::GENESIS,
            event: ForgeEventKind::PullRequestReviewed { review: ForgeEntityId::new(label("review/17/a")),
                target: RefName::try_new(b"refs/heads/main").unwrap() },
        })]).build(&mut mint);
    let mut recorder = TraceRecorder::new(genesis);
    recorder.apply(ModelInput::Seal(Box::new(SealRequest { seal_id: mint.seal(), request }))).unwrap();
    // This codec/replay test uses an empty authorization policy; it must not
    // mistake the recorded pre-seal refusal for an admitted review.
    let trace = recorder.finish();
    assert!(matches!(trace.steps[0].observed, fgit_reference::trace::ObservedOutcome::SealRejected(_)));
    let bytes = encode(&trace).unwrap(); let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded, trace); assert_eq!(encode(&decoded).unwrap(), bytes);
    assert!(replay(&decoded).unwrap().is_faithful());
    for end in 0..bytes.len() { assert!(decode(&bytes[..end]).is_err()); }
}
