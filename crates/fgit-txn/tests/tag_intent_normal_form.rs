#![forbid(unsafe_code)]
//! Tag-intent lowering through the one canonical ref normal-form evaluator.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::effect::{
    AbsorptionReason, EffectTarget, FoldBasis, FoldOutcome, IntentDisposition, RefEffect,
};
use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{
    IdempotencyKey, Intent, TagIntent, TagReference, TagSignatureEvidence,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_txn::IntentEvaluator;
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::MismatchPolicy;

const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("fgit/ref-txn"), 2, 0)
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn name(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).expect("fixed ref name")
}

#[test]
fn tag_intents_keep_read_your_own_writes_and_one_surviving_ref_effect() {
    let mut mint = IdentityMint::new(0x097);
    let lightweight = oid(0x11);
    let annotated_object = oid(0x22);
    let tag_name = name("refs/tags/release");
    let first = TagIntent::update(
        tag_name.clone(),
        ExpectedRefState::Absent,
        TagReference::Lightweight {
            target: lightweight,
        },
        false,
    )
    .expect("a tag name lowers");
    let second = TagIntent::update(
        tag_name.clone(),
        ExpectedRefState::Exact(lightweight),
        TagReference::Annotated {
            tag_object: annotated_object,
            signature: TagSignatureEvidence::Unsupported,
        },
        true,
    )
    .expect("a tag name lowers");
    let request = RequestBuilder::new(
        mint.tenant(),
        mint.repository(),
        mint.principal(),
        schema(),
        IdempotencyKey::new(label("tag-normal-form")),
    )
    .statement(
        MismatchPolicy::TxnAbort,
        vec![
            Intent::Ref(first.into_ref_intent()),
            Intent::Ref(second.into_ref_intent()),
        ],
    )
    .promising(lightweight)
    .promising(annotated_object)
    .build(&mut mint);

    let refs = BTreeMap::new();
    let forge = BTreeMap::new();
    let retention = BTreeSet::new();
    let outbox = BTreeMap::new();
    let report = IntentEvaluator::new().evaluate(
        FoldBasis {
            refs: &refs,
            forge_positions: &forge,
            retention: &retention,
            outbox: &outbox,
        },
        &request,
    );

    let FoldOutcome::Folded(effects) = report.outcome else {
        panic!("expected a folded tag transaction, got {report:?}");
    };
    assert_eq!(
        effects.refs,
        BTreeMap::from([(tag_name.clone(), RefEffect::Set(annotated_object))]),
        "the later annotated update survives; the lightweight target is not synthesized"
    );
    assert_eq!(
        report.mappings[0].disposition,
        IntentDisposition::Absorbed(AbsorptionReason::OverwrittenBySucceedingIntent),
        "the first tag write is explicitly accounted for rather than disappearing"
    );
    assert_eq!(
        report.mappings[1].disposition,
        IntentDisposition::Surviving(EffectTarget::Ref(tag_name)),
        "the exact succeeding tag update owns the one normal-form ref effect"
    );
}
