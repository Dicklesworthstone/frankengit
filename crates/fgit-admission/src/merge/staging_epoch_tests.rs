//! Pure preparation/staging boundary tests. Actual file-backed policy
//! installation, enforcement and restart are exercised by the node suite.
use super::*;
use crate::merge::native::{NativeMergeIntent, protection};
use crate::merge::prepare::{NativeMergeBasis, prepare_event};
use crate::{AdmissionContext, CanonicalRefState, PermittedObjectClosure, ValidatedClosure};
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, CryptoBodyIdentity,
    RepositoryAuthorityHeadBody, body_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::{AggregateId, ExpectedVersion, ForgeEventPayload, PullRequestNumber};
use fgit_types::{DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid, HeadGeneration,
    PolicyEpoch, PrincipalId, RefName, RegistryEpoch, RepositoryAuthorityHeadId, RootLayoutVersion,
    TenantId};
use std::collections::{BTreeMap, BTreeSet};

fn epoch(value: u64) -> PolicyEpoch { PolicyEpoch::try_new(value).unwrap() }
fn fixture(format: GitHashAlgorithm, before: u64, policy: bool) -> PreparedNativeMerge {
    let digest = |byte| Digest::new(DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&[byte;32]).unwrap());
    let oid = |byte: u8| GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap();
    let name = |text: &str| RefName::try_new(text.as_bytes()).unwrap();
    let actor = PrincipalId::from_bytes([3;16]);
    let repository = RepositoryId::from_bytes([2;16]);
    let context = AdmissionContext { head_key: HeadKey::new(b"epoch-test".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1;16]), repository_id: repository,
        principal_id: actor, idempotency_key: IdempotencyKey::new(b"epoch".to_vec()).unwrap(),
        object_format: format };
    let refs = CanonicalRefState::new(BTreeMap::from([
        (name("refs/heads/main"),oid(10)), (name("refs/heads/topic"),oid(11))]));
    let forge = CanonicalForgePositionState::try_new(repository,Vec::new()).unwrap();
    let outbox = CanonicalOutboxState::try_new(repository,Vec::new()).unwrap();
    let resolved = NativeMergeBasis { refs, forge, outbox, root_layout: RootLayoutVersion::LegacyWholeBody };
    let head = RepositoryAuthorityHeadBody { repository_id: repository, generation: HeadGeneration::FIRST,
        predecessor_head_id: None, decision_tail_id: None, latest_decision_sequence: None,
        latest_committed_rcr_id: None, latest_repository_sequence: None,
        ref_root: crate::ref_state_root(resolved.root_layout,&resolved.refs).unwrap(),
        forge_position_root: root(&resolved.forge).unwrap(), outbox_root: root(&resolved.outbox).unwrap(),
        outcome_index_root: digest(20), retention_root: digest(21), configuration_root: digest(22),
        policy_epoch: epoch(before), format_registry_epoch: RegistryEpoch::FIRST, last_checkpoint_id: None };
    let id = RepositoryAuthorityHeadId::from_internal_object_id(body_id(&CryptoBodyIdentity,&head).unwrap()).unwrap();
    let basis = PublicationBasis::new(id,head);
    let (event, attempt, objects) = if policy {
        let command = ProtectionCommand { expected_version: ExpectedVersion::NewStream, expected_epoch: epoch(before),
            protection: ReviewProtection { administrators: vec![actor], branches: vec![ProtectedBranch {
                name: name("refs/heads/main"), reviewers: vec![PrincipalId::from_bytes([9;16])] }] } };
        let (event,attempt) = protection::proposal(&context,&command).unwrap();
        (event,attempt,BTreeSet::new())
    } else {
        let intent = NativeMergeIntent::new(PullRequestNumber::FIRST,ExpectedVersion::NewStream,
            NativeMerge { source_ref: name("refs/heads/topic"), target_ref: name("refs/heads/main"),
                source_tip: oid(11), target_tip_before: oid(10), base_tip: oid(12), merge_commit: oid(13) }).unwrap();
        (intent.event().clone(),intent.seal_attempt(&context).unwrap(),BTreeSet::from([oid(10),oid(11),oid(12),oid(13)]))
    };
    let closure = ValidatedClosure { object_closure_root: crate::permitted_object_closure_root(
        &PermittedObjectClosure::new(objects.clone())).unwrap(), objects };
    prepare_event(&context,&event,&closure,attempt.derive().unwrap().0,&attempt,&basis,&resolved).unwrap()
}
fn invalid_preparation(prepared: &PreparedNativeMerge) {
    assert!(matches!(validate_prepared(prepared),
        Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceInvalid))));
}
#[test]
fn protection_stages_old_authorization_with_exact_new_epoch_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        for before in [1,17,u64::MAX-1] {
            let prepared = fixture(format,before,true);
            validate_prepared(&prepared).unwrap();
            assert_eq!(prepared.materialization.record.policy_epoch,epoch(before));
            assert_eq!(prepared.materialization.roots.policy_epoch,epoch(before+1));
            assert!(prepared.fold.effects().unwrap().refs.is_empty());
            assert_eq!(prepared.forge.entries().len(),1);
            assert_eq!(prepared.outbox.entries().len(),1);
            assert_eq!(root(prepared.evidence.policy_decision()).unwrap(),prepared.materialization.record.policy_decision_root);
        }
    }
}
#[test]
fn policy_cannot_repeat_skip_roll_back_or_relabel_its_authorizing_epoch() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let good = fixture(format,7,true);
        validate_prepared(&good).unwrap();
        for after in [1,6,7,9,u64::MAX] {
            let mut bad=good.clone(); bad.materialization.roots.policy_epoch=epoch(after);
            invalid_preparation(&bad);
        }
        let mut bad=good.clone(); bad.materialization.record.policy_epoch=epoch(8);
        invalid_preparation(&bad);
        let mut bad=good;
        let ForgeEventPayload::ReviewProtectionChanged(change)=&mut bad.event.events[0].payload else { panic!() };
        change.expected_epoch=epoch(u64::MAX);
        invalid_preparation(&bad);
    }
}
#[test]
fn ordinary_native_merges_still_require_one_unchanged_epoch() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        for before in [1,7,u64::MAX] {
            let good=fixture(format,before,false); validate_prepared(&good).unwrap();
            let mut bad=good.clone(); bad.materialization.roots.policy_epoch=epoch(if before==1 {2} else {1});
            invalid_preparation(&bad);
        }
    }
}
#[test]
fn singleton_kind_actor_empty_closure_and_effect_bounds_are_not_optional() {
    let good=fixture(GitHashAlgorithm::Sha256,1,true); validate_prepared(&good).unwrap();
    let mut bad=good.clone(); bad.event.events.clear(); invalid_preparation(&bad);
    let mut bad=good.clone(); bad.event.events.push(bad.event.events[0].clone()); invalid_preparation(&bad);
    let mut bad=good.clone(); bad.event.events[0].aggregate=AggregateId::PullRequest(PullRequestNumber::FIRST); invalid_preparation(&bad);
    let mut bad=good.clone();
    let ForgeEventPayload::ReviewProtectionChanged(change)=&mut bad.event.events[0].payload else {panic!()};
    change.actor=PrincipalId::from_bytes([8;16]); invalid_preparation(&bad);
    let mut bad=good.clone();
    let id=GitOid::from_hex(GitHashAlgorithm::Sha256,&"aa".repeat(32)).unwrap();
    bad.closure=PermittedObjectClosure::new(BTreeSet::from([id]));
    bad.materialization.record.object_closure_root=crate::permitted_object_closure_root(&bad.closure).unwrap();
    invalid_preparation(&bad);
    let mut bad=good;
    let fgit_reference::effect::FoldOutcome::Folded(effects)=&mut bad.fold.outcome else {panic!()};
    effects.refs.insert(RefName::try_new(b"refs/heads/main").unwrap(),fgit_reference::effect::RefEffect::Set(id));
    invalid_preparation(&bad);
}
