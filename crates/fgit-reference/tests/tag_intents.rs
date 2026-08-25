#![forbid(unsafe_code)]
//! Tag lifecycle intent construction and lossless ref-intent lowering.

use fgit_reference::intent::{
    RefIntent, TagIntent, TagIntentRefusal, TagReference, TagSignatureEvidence,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_types::native::{GitOid, GitOidSha1, GitOidSha256};
use fgit_types::refs::RefName;

const fn sha1(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

const fn sha256(seed: u8) -> GitOid {
    GitOid::Sha256(GitOidSha256::from_bytes([seed; GitOidSha256::LEN]))
}

fn name(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).expect("fixed ref name")
}

#[test]
fn lightweight_tags_lower_to_their_direct_target_without_a_synthesized_object() {
    let target = sha1(0x11);
    let intent = TagIntent::update(
        name("refs/tags/v1"),
        ExpectedRefState::Absent,
        TagReference::Lightweight { target },
        false,
    )
    .expect("a tag namespace name is admitted");

    assert_eq!(
        intent.into_ref_intent(),
        RefIntent::Update {
            name: name("refs/tags/v1"),
            expected: ExpectedRefState::Absent,
            new: target,
            force: false,
        },
        "a lightweight tag ref must hold its original target, not a synthetic tag object"
    );
}

#[test]
fn annotated_tags_lower_to_the_actual_tag_object_and_keep_untrusted_evidence_typed() {
    let tag_object = sha256(0x22);
    let reference = TagReference::Annotated {
        tag_object,
        signature: TagSignatureEvidence::OpaqueUnverifiable,
    };
    assert_eq!(
        reference.signature_evidence(),
        Some(TagSignatureEvidence::OpaqueUnverifiable),
        "opaque signature bytes cannot become a trusted state in the intent layer"
    );
    let intent = TagIntent::update(
        name("refs/tags/v2"),
        ExpectedRefState::Exact(sha256(0x21)),
        reference,
        true,
    )
    .expect("a tag namespace name is admitted");

    assert_eq!(
        intent.into_ref_intent(),
        RefIntent::Update {
            name: name("refs/tags/v2"),
            expected: ExpectedRefState::Exact(sha256(0x21)),
            new: tag_object,
            force: true,
        },
        "force and expected-old survive tag lowering for the ordinary policy path"
    );
}

#[test]
fn a_non_tag_refusal_has_a_near_identical_permitted_tag_twin() {
    assert_eq!(
        TagIntent::delete(name("refs/heads/main"), ExpectedRefState::Any),
        Err(TagIntentRefusal::OutsideTagNamespace(name(
            "refs/heads/main"
        ))),
        "a branch cannot be relabelled as a tag lifecycle operation"
    );
    assert!(
        TagIntent::delete(name("refs/tags/main"), ExpectedRefState::Any).is_ok(),
        "the same operation under refs/tags is permitted"
    );
}
