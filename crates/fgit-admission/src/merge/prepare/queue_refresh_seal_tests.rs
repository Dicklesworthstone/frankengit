//! Exact normal-form and profile separation checks at the shared fold boundary.
use super::*;
use crate::merge::native::queue::{
    QueueHeadRefreshCommand, queue_head_refresh_proposal,
};
use fgit_authority::{HeadKey, IdempotencyKey, ScopedEntry, SemanticRequest};
use fgit_forge::event::pull_request::{PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName, RepositoryId, TenantId};

fn inputs(format: GitHashAlgorithm) -> (AdmissionContext, QueueHeadRefreshCommand) {
    let oid = |digit: &str| GitOid::from_hex(format, &digit.repeat(format.digest_len() * 2)).unwrap();
    let context = AdmissionContext {
        head_key: HeadKey::new(b"queue-refresh/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"queue-refresh".to_vec()).unwrap(),
        object_format: format,
    };
    let command = QueueHeadRefreshCommand {
        number: QueueNumber::FIRST,
        expected_queue_version: AggregateVersion::try_new(2).unwrap(),
        expected_policy_epoch: PolicyEpoch::FIRST,
        expected_recorded_target_tip: oid("a"),
        pull_request: PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: PullRequestAction::Update,
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: oid("b"),
                target_tip: oid("c"),
                title: "Preserve the queued subject".into(),
                body: "Original body é\n".into(),
            },
        },
    };
    (context, command)
}

fn reseal(
    context: &AdmissionContext,
    original: &SealAttempt,
    guards: Vec<ScopedEntry>,
) -> SealAttempt {
    SealAttempt {
        request: SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            Vec::new(),
            Vec::new(),
            guards,
        )
        .unwrap(),
        ..original.clone()
    }
}

#[test]
fn queue_refresh_seal_preserves_ordinary_identity_and_binds_every_observation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command) = inputs(format);
        let (event, sealed) = queue_head_refresh_proposal(&context, &command).unwrap();
        assert!(sealed.request.atomic());
        assert!(sealed.request.ref_commands().is_empty());
        assert_eq!(sealed.request.scoped_entries().len(), 5);
        assert_eq!(
            verify_pull_request_seal(&context, &event, &sealed),
            Ok(Some(command.clone()))
        );
        let (ordinary_event, ordinary) =
            crate::merge::native::pull_request::proposal(&context, &command.pull_request).unwrap();
        assert_eq!(ordinary_event, event);
        assert_eq!(verify_pull_request_seal(&context, &event, &ordinary), Ok(None));
        assert_ne!(sealed.derive().unwrap().0, ordinary.derive().unwrap().0);
        assert_eq!(
            queue_head_refresh_proposal(&context, &command).unwrap(),
            (event.clone(), sealed.clone())
        );

        let mut variants = Vec::new();
        let mut changed = command.clone();
        changed.number = QueueNumber::try_new(2).unwrap();
        variants.push(changed);
        let mut changed = command.clone();
        changed.expected_queue_version = AggregateVersion::try_new(3).unwrap();
        variants.push(changed);
        let mut changed = command.clone();
        changed.expected_policy_epoch = PolicyEpoch::try_new(2).unwrap();
        variants.push(changed);
        let mut changed = command.clone();
        changed.expected_recorded_target_tip =
            GitOid::from_hex(format, &"d".repeat(format.digest_len() * 2)).unwrap();
        variants.push(changed);
        for changed in variants {
            let (same_event, guarded) = queue_head_refresh_proposal(&context, &changed).unwrap();
            assert_eq!(same_event, event);
            assert_ne!(guarded.derive().unwrap().0, sealed.derive().unwrap().0);
            assert_eq!(
                verify_pull_request_seal(&context, &same_event, &guarded),
                Ok(Some(changed))
            );
        }
    }
}

#[test]
fn queue_refresh_rejects_partial_extra_and_substituted_seals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command) = inputs(format);
        let (event, sealed) = queue_head_refresh_proposal(&context, &command).unwrap();
        for index in 0..sealed.request.scoped_entries().len() {
            let mut guards = sealed.request.scoped_entries().to_vec();
            guards.remove(index);
            assert_eq!(
                verify_pull_request_seal(&context, &event, &reseal(&context, &sealed, guards)),
                Err(RefusalCode::EvidenceInvalid)
            );
        }
        let mut guards = sealed.request.scoped_entries().to_vec();
        guards.push(
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("queue-head-refresh.unrecognized"),
                b"extra",
            )
            .unwrap(),
        );
        assert_eq!(
            verify_pull_request_seal(&context, &event, &reseal(&context, &sealed, guards)),
            Err(RefusalCode::EvidenceInvalid)
        );
        let mut substituted = event.clone();
        let ForgeEventPayload::PullRequestChangedNative(change) = &mut substituted.payload else {
            panic!("native PR event");
        };
        change.data.title = "Substituted metadata".into();
        assert_eq!(
            verify_pull_request_seal(&context, &substituted, &sealed),
            Err(RefusalCode::EvidenceInvalid)
        );
        change_actor_and_refuse(&context, event, &sealed);
    }
}

fn change_actor_and_refuse(context: &AdmissionContext, mut event: ForgeEvent, sealed: &SealAttempt) {
    let ForgeEventPayload::PullRequestChangedNative(change) = &mut event.payload else {
        panic!("native PR event");
    };
    change.actor = PrincipalId::from_bytes([9; 16]);
    assert_eq!(
        verify_pull_request_seal(context, &event, sealed),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn queue_refresh_advances_only_the_pr_and_refuses_noop_or_other_lifecycles() {
    let (context, command) = inputs(GitHashAlgorithm::Sha256);
    let mut changed = command.clone();
    changed.expected_queue_version = AggregateVersion::try_new(u64::MAX).unwrap();
    assert!(queue_head_refresh_proposal(&context, &changed).is_ok());
    changed.pull_request.expected_version =
        ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX).unwrap());
    assert!(queue_head_refresh_proposal(&context, &changed).is_err());

    let mut changed = command.clone();
    changed.expected_recorded_target_tip = changed.pull_request.data.target_tip;
    assert!(queue_head_refresh_proposal(&context, &changed).is_err());
    for action in [PullRequestAction::Open, PullRequestAction::Close, PullRequestAction::Reopen] {
        let mut changed = command.clone();
        changed.pull_request.action = action;
        assert!(queue_head_refresh_proposal(&context, &changed).is_err());
    }
    let mut changed = command.clone();
    changed.pull_request.expected_version = ExpectedVersion::NewStream;
    assert!(queue_head_refresh_proposal(&context, &changed).is_err());
    let mut changed = command.clone();
    changed.expected_recorded_target_tip =
        GitOid::from_hex(GitHashAlgorithm::Sha1, &"a".repeat(40)).unwrap();
    assert!(queue_head_refresh_proposal(&context, &changed).is_err());
    let mut changed = command;
    changed.expected_recorded_target_tip =
        GitOid::from_hex(GitHashAlgorithm::Sha256, &"0".repeat(64)).unwrap();
    assert!(queue_head_refresh_proposal(&context, &changed).is_err());
}
