use std::collections::BTreeMap;

use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::{DecodeLimits, Encoder, decode_body, encode_body};
use fgit_types::{
    Digest, GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, InternalObjectId, PrincipalId,
    RefName, RootLayoutVersion, TenantId,
};

use super::*;

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).unwrap()
}

fn fixture() -> (
    AdmissionContext,
    PublicationBasis,
    CanonicalRefState,
    CanonicalRefState,
    CanonicalHeadChange,
) {
    let mut head = fgit_codec::harness::genesis_head();
    let context = AdmissionContext {
        head_key: HeadKey::new(b"head-delta-unit/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: head.repository_id,
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"select-topic".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    };
    let command = DefaultBranchCommand {
        expected_head: Some(name(b"refs/heads/main")),
        target: name(b"refs/heads/topic"),
        expected_target_tip: GitOid::Sha1(GitOidSha1::from_bytes([8; 20])),
    };
    let before = CanonicalRefState::new_with_head_target(
        BTreeMap::from([
            (
                name(b"refs/heads/main"),
                GitOid::Sha1(GitOidSha1::from_bytes([7; 20])),
            ),
            (command.target.clone(), command.expected_target_tip),
        ]),
        command.expected_head.clone().unwrap(),
    )
    .unwrap();
    let after =
        CanonicalRefState::new_with_head_target(before.refs().clone(), command.target.clone())
            .unwrap();
    let layout = RootLayoutVersion::RefStateMerkleV2;
    head.ref_root = ref_state_root(layout, &before).unwrap();
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    );
    let (tx_id, seal) = proposal(&context, &command).unwrap().derive().unwrap();
    let delta = CanonicalHeadChange {
        tenant: context.tenant_id,
        repository: context.repository_id,
        principal: context.principal_id,
        tx_id,
        request_digest: seal.canonical_request_digest,
        basis_head: basis.id(),
        layout,
        previous_ref_root: basis.body().ref_root,
        resulting_ref_root: ref_state_root(layout, &after).unwrap(),
        command,
        protection_witness_root: None,
    };
    (context, basis, before, after, delta)
}

#[test]
fn request_profile_binds_all_semantics_without_a_direct_ref_or_authority_basis() {
    let (context, _, _, _, delta) = fixture();
    let command = delta.command;
    let original = proposal(&context, &command).unwrap();
    assert_eq!(
        original.request.request_schema(),
        DEFAULT_BRANCH_ADMISSION_SCHEMA
    );
    assert!(original.request.ref_commands().is_empty());
    let identity = original.derive().unwrap().0;
    let mut absent = command.clone();
    absent.expected_head = None;
    let mut other_head = command.clone();
    other_head.expected_head = Some(name(b"refs/heads/other"));
    let mut other_target = command.clone();
    other_target.target = name(b"refs/heads/other");
    let mut other_tip = command.clone();
    other_tip.expected_target_tip = GitOid::Sha1(GitOidSha1::from_bytes([9; 20]));
    for changed in [absent, other_head, other_target, other_tip] {
        assert_ne!(
            proposal(&context, &changed).unwrap().derive().unwrap().0,
            identity
        );
    }
    let mut routed = context.clone();
    routed.head_key = HeadKey::new(b"same-repository-new-node/head".to_vec()).unwrap();
    assert_eq!(proposal(&routed, &command).unwrap(), original);
    let mut out = Encoder::new();
    command.write(&mut out).unwrap();
    let mut expected = vec![1];
    bytes(&mut expected, b"refs/heads/main");
    bytes(&mut expected, b"refs/heads/topic");
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(&[8; 20]);
    assert_eq!(
        out.into_bytes(),
        expected,
        "independent semantic-command golden"
    );
}

#[test]
fn malformed_branch_zero_tip_and_foreign_native_hash_refuse_before_sealing() {
    let (context, _, _, _, delta) = fixture();
    for (command, expected) in [
        (
            DefaultBranchCommand {
                target: name(b"refs/tags/release"),
                ..delta.command.clone()
            },
            RefusalCode::RefNameInvalid,
        ),
        (
            DefaultBranchCommand {
                expected_head: Some(name(b"refs/tags/release")),
                ..delta.command.clone()
            },
            RefusalCode::RefNameInvalid,
        ),
        (
            DefaultBranchCommand {
                expected_target_tip: GitOid::Sha1(GitOidSha1::from_bytes([0; 20])),
                ..delta.command.clone()
            },
            RefusalCode::NativeObjectIdMismatch,
        ),
        (
            DefaultBranchCommand {
                expected_target_tip: GitOid::Sha256(GitOidSha256::from_bytes([8; 32])),
                ..delta.command.clone()
            },
            RefusalCode::HashAlgorithmDomainMismatch,
        ),
    ] {
        assert!(
            matches!(proposal(&context, &command), Err(AdmissionError::AsyncProjectionUnavailable(code)) if code == expected)
        );
    }
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
}
fn digest(out: &mut Vec<u8>, value: Digest) {
    out.extend_from_slice(&value.algorithm().code_point().to_be_bytes());
    bytes(out, value.bytes().as_bytes());
}
fn identity(out: &mut Vec<u8>, value: &InternalObjectId) {
    out.extend_from_slice(&value.algorithm().code_point().to_be_bytes());
    bytes(out, value.domain().as_bytes());
    out.extend_from_slice(&value.codec_version().major().to_be_bytes());
    out.extend_from_slice(&value.codec_version().minor().to_be_bytes());
    bytes(out, value.digest().as_bytes());
}

#[test]
fn head_delta_frame_has_independent_field_framing_and_closed_domain_version() {
    let (_, _, _, _, delta) = fixture();
    let mut payload = Vec::new();
    payload.extend_from_slice(delta.tenant.as_bytes());
    payload.extend_from_slice(delta.repository.as_bytes());
    payload.extend_from_slice(delta.principal.as_bytes());
    identity(&mut payload, delta.tx_id.as_internal_object_id());
    digest(&mut payload, delta.request_digest);
    identity(&mut payload, delta.basis_head.as_internal_object_id());
    payload.extend_from_slice(&4_u16.to_be_bytes());
    digest(&mut payload, delta.previous_ref_root);
    digest(&mut payload, delta.resulting_ref_root);
    payload.push(1);
    bytes(&mut payload, b"refs/heads/main");
    bytes(&mut payload, b"refs/heads/topic");
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&[8; 20]);
    payload.push(0);
    let mut expected = b"FGC1\x00\x01\x00\x00".to_vec();
    bytes(&mut expected, b"frankengit/admission-head-delta/v1");
    bytes(&mut expected, b"admission-head-delta");
    let schema_at = expected.len();
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(&0_u16.to_be_bytes());
    bytes(&mut expected, &payload);
    assert_eq!(encode_body(&delta).unwrap(), expected);
    assert_eq!(
        decode_body::<CanonicalHeadChange>(&expected, DecodeLimits::DEFAULT).unwrap(),
        delta
    );
    for truncate in [0, 4, schema_at, expected.len() - 1] {
        assert!(
            decode_body::<CanonicalHeadChange>(&expected[..truncate], DecodeLimits::DEFAULT)
                .is_err()
        );
    }
    let mut wrong_domain = expected.clone();
    wrong_domain[12] = b'x';
    assert!(matches!(
        decode_body::<CanonicalHeadChange>(&wrong_domain, DecodeLimits::DEFAULT),
        Err(fgit_codec::CodecRefusal::DomainUnexpected { .. })
    ));
    let mut future = expected.clone();
    future[schema_at + 1] = 2;
    assert!(matches!(
        decode_body::<CanonicalHeadChange>(&future, DecodeLimits::DEFAULT),
        Err(fgit_codec::CodecRefusal::SchemaMajorUnsupported { .. })
    ));
    let mut minor = expected;
    minor[schema_at + 3] = 1;
    assert!(matches!(
        decode_body::<CanonicalHeadChange>(&minor, DecodeLimits::DEFAULT),
        Err(fgit_codec::CodecRefusal::SchemaMinorUnsupported { .. })
    ));
}

#[test]
fn transition_witness_rejects_relabeling_ref_changes_and_unauthenticated_head_layouts() {
    let (context, basis, before, after, delta) = fixture();
    delta
        .verify_transition(&context, &basis, &before, &after, delta.command(), None)
        .unwrap();
    let mut foreign = delta.clone();
    foreign.principal = PrincipalId::from_bytes([99; 16]);
    let mut wrong_tip = delta.clone();
    wrong_tip.command.expected_target_tip = GitOid::Sha1(GitOidSha1::from_bytes([9; 20]));
    let mut old_layout = delta.clone();
    old_layout.layout = RootLayoutVersion::RefStateMerkleV1;
    let mut altered_root = delta.clone();
    altered_root.resulting_ref_root = delta.previous_ref_root;
    for changed in [foreign, wrong_tip, old_layout.clone(), altered_root] {
        assert_eq!(
            changed.verify_transition(&context, &basis, &before, &after, delta.command(), None),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    assert!(encode_body(&old_layout).is_err());
    let mut altered_refs = after.refs().clone();
    altered_refs.remove(&name(b"refs/heads/main"));
    let altered_after =
        CanonicalRefState::new_with_head_target(altered_refs, delta.command.target.clone())
            .unwrap();
    assert_eq!(
        delta.verify_transition(
            &context,
            &basis,
            &before,
            &altered_after,
            delta.command(),
            None
        ),
        Err(RefusalCode::EvidenceInvalid)
    );
}
