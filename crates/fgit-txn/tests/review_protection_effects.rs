#![forbid(unsafe_code)]
use fgit_codec::{DecodeLimits, Decoder};
use fgit_reference::{
    effect::{FoldBasis, FoldOutcome, NetEffects},
    harness::{IdentityMint, RequestBuilder, label},
    intent::{
        ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition,
        IdempotencyKey, Intent, OutboxDeliveryKey, OutboxIntent,
    },
};
use fgit_txn::{IntentEvaluator, canonical_forge_effect_bytes};
use fgit_types::{AsciiSlug, SchemaFamily, SchemaId, vocabulary::MismatchPolicy};
use std::collections::{BTreeMap, BTreeSet};
fn slug(value: &str) -> AsciiSlug {
    AsciiSlug::try_new("protection-test", value.as_bytes()).unwrap()
}
fn kind() -> ForgeEventKind {
    ForgeEventKind::ReviewProtectionChanged {
        policy: ForgeEntityId::new(slug("review-protection")),
    }
}
#[test]
fn policy_effect_has_new_tag_seven_without_reusing_existing_issue_or_annotation_tags() {
    let stream = ForgeStreamId::new(slug("review-protection"));
    let mut effect = NetEffects::default();
    effect.forge.insert(stream, vec![kind()]);
    let bytes = canonical_forge_effect_bytes(&effect).unwrap();
    let mut decoder = Decoder::new(&bytes, DecodeLimits::DEFAULT);
    assert_eq!(
        decoder
            .take("header", b"fgit-txn/forge-effects".len())
            .unwrap(),
        b"fgit-txn/forge-effects"
    );
    assert_eq!(
        decoder.read_scalar::<u16>("version").unwrap(),
        fgit_txn::NORMAL_FORM_FORMAT_VERSION
    );
    let decoded = decoder
        .read_sequence("forge", |input| {
            let stream = input.read_text("stream")?.to_owned();
            let events = input.read_sequence("events", |input| {
                Ok((
                    input.read_raw_byte("kind")?,
                    input.read_text("entity")?.to_owned(),
                ))
            })?;
            Ok((stream, events))
        })
        .unwrap();
    assert_eq!(
        decoded,
        vec![(
            "review-protection".into(),
            vec![(7, "review-protection".into())]
        )]
    );
    decoder.finish().unwrap();
    let entity = ForgeEntityId::new(slug("review-protection"));
    for other in [
        ForgeEventKind::IssueChanged { issue: entity },
        ForgeEventKind::PullRequestClosed {
            pull_request: entity,
        },
    ] {
        effect.forge.insert(stream, vec![other]);
        assert_ne!(canonical_forge_effect_bytes(&effect).unwrap(), bytes);
    }
}
#[test]
fn a_policy_and_its_outbox_fold_together_without_inventing_ref_or_retention_effects() {
    let stream = ForgeStreamId::new(slug("review-protection"));
    let delivery = OutboxDeliveryKey::new(slug("delivery"));
    let mut mint = IdentityMint::new(912);
    let payload = mint.digest();
    let request = RequestBuilder::new(
        mint.tenant(),
        mint.repository(),
        mint.principal(),
        SchemaId::new(SchemaFamily::from_static("policy-fold-test"), 1, 0),
        IdempotencyKey::new(label("policy-fold")),
    )
    .statement(
        MismatchPolicy::TxnAbort,
        vec![
            Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::new(0),
                event: kind(),
            }),
            Intent::Outbox(OutboxIntent {
                delivery_key: delivery,
                parameters: payload,
            }),
        ],
    )
    .build(&mut mint);
    let (refs, positions, retention, outbox) = (
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeMap::new(),
    );
    let evaluator = IntentEvaluator::new();
    let report = evaluator.evaluate(
        FoldBasis {
            refs: &refs,
            forge_positions: &positions,
            retention: &retention,
            outbox: &outbox,
        },
        &request,
    );
    evaluator.validate_report(&request, &report).unwrap();
    let FoldOutcome::Folded(effect) = report.outcome else {
        panic!("valid policy effect must fold");
    };
    assert_eq!(effect.forge.get(&stream), Some(&vec![kind()]));
    assert_eq!(effect.outbox.get(&delivery), Some(&payload));
    assert!(effect.refs.is_empty() && effect.retention.is_empty());
}
