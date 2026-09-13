// Included by review_tests.rs: use its actual file-backed node and native merge.
use fgit_admission::{
    AdmissionContext, SourceImportOrigin, SourceImportReceipt, SourceRefUpdate, ValidatedClosure,
    permitted_object_closure_root, validate_source_import,
};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, TerminalOutcome};
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_types::{PolicyEpoch, RefName, RefusalCode, TxId};
use std::{future::Future, task::Poll};
fn protection_context(f: &Fixture, who: u8, key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: f.node.head_key.clone(),
        tenant_id: f.node.tenant_id,
        repository_id: f.node.repository_id,
        principal_id: actor(who),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        object_format: f.node.object_format,
    }
}

fn protection_policy(names: &[&[u8]], administrators: &[u8], reviewers: &[u8]) -> ReviewProtection {
    let mut policy = ReviewProtection {
        administrators: administrators.iter().copied().map(actor).collect(),
        branches: names
            .iter()
            .map(|name| ProtectedBranch {
                name: RefName::try_new(name).unwrap(),
                reviewers: reviewers.iter().copied().map(actor).collect(),
            })
            .collect(),
    };
    policy.administrators.sort();
    policy.branches.sort_by(|a, b| a.name.cmp(&b.name));
    for branch in &mut policy.branches {
        branch.reviewers.sort();
    }
    policy.validate().unwrap();
    policy
}
fn policy_command(
    version: u64,
    epoch: PolicyEpoch,
    protection: ReviewProtection,
) -> ProtectionCommand {
    ProtectionCommand {
        expected_version: AggregateVersion::try_new(version)
            .map(ExpectedVersion::Exactly)
            .unwrap_or(ExpectedVersion::NewStream),
        expected_epoch: epoch,
        protection,
    }
}
fn change_policy(
    f: &Fixture,
    who: u8,
    key: &[u8],
    command: &ProtectionCommand,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let session = LoopbackReceiveSession::authenticated(
        actor(who),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    let request = f.node.request_context();
    f.node
        .runtime()
        .block_on(f.node.admit_review_protection_durable_in(
            &request,
            &session,
            command,
            AdmissionLimits::default(),
        ))
}
fn current_policy(f: &Fixture) -> fgit_admission::merge::native::protection::ProtectionState {
    let request = f.node.request_context();
    f.node
        .runtime()
        .block_on(f.node.read_review_protection_in(&request))
        .unwrap()
}
fn plain_merge(f: &Fixture, key: &[u8]) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
    let request = f.node.request_context();
    let merge = f.command.candidate.merge(&f.command.review.subject);
    f.node
        .runtime()
        .block_on(f.node.apply_merge_bundle_durable_in(
            &request,
            actor(2),
            key,
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            &merge,
            &f.bundle,
        ))
}
fn denied(terminal: &TerminalOutcome) {
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Refused { .. }),
        "{terminal:?}"
    );
}

#[test]
fn mandatory_policy_blocks_plain_merge_and_caller_selected_weaker_review_sets() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        let old = snapshot(&f.node);
        let command = policy_command(
            0,
            PolicyEpoch::FIRST,
            protection_policy(&[b"refs/heads/main"], &[1], &[3, 4]),
        );
        let installed = committed(change_policy(&f, 1, b"activate", &command).unwrap());
        let policy = current_policy(&f);
        assert_eq!(policy.version(), Some(AggregateVersion::FIRST));
        assert_eq!(policy.policy_epoch, PolicyEpoch::FIRST.next().unwrap());
        let active = snapshot(&f.node);
        assert_eq!(old.snapshot().refs, active.snapshot().refs);
        assert_eq!(
            old.selected_closure().closure(),
            active.selected_closure().closure()
        );
        assert_eq!(
            old.basis().body().retention_root,
            active.basis().body().retention_root
        );
        assert_eq!(
            old.snapshot().outbox.len() + 1,
            active.snapshot().outbox.len()
        );
        let failed = plain_merge(&f, b"missing-review").unwrap();
        denied(&failed.1);
        f.command.review.subject.policy_epoch = policy.policy_epoch;
        committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "approve-three").unwrap());
        let weakened =
            publish(&f.node, &f.command, &f.bundle, &[actor(3)], "weaker-caller").unwrap();
        denied(&weakened.1);
        assert_eq!(
            snapshot(&f.node).snapshot().refs.get(&f.data.target_ref),
            Some(&f.data.target_tip)
        );
        committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "approve-four").unwrap());
        // A canonical missing-review refusal never changes after later votes.
        assert_eq!(plain_merge(&f, b"missing-review").unwrap(), failed);
        let applied = committed(plain_merge(&f, b"permitted-plain-merge").unwrap());
        assert_eq!(
            snapshot(&f.node).snapshot().refs.get(&f.data.target_ref),
            Some(&f.command.candidate.commit)
        );
        assert_eq!(
            change_policy(&f, 1, b"activate", &command).unwrap(),
            installed
        );
        assert_eq!(plain_merge(&f, b"permitted-plain-merge").unwrap(), applied);
        f.node.shutdown().unwrap();
    }
}

#[test]
fn protection_replacement_invalidates_old_votes_and_clear_preserves_administrators() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        let policy = protection_policy(&[b"refs/heads/main"], &[1], &[3]);
        committed(
            change_policy(
                &f,
                1,
                b"set-one",
                &policy_command(0, PolicyEpoch::FIRST, policy.clone()),
            )
            .unwrap(),
        );
        let epoch = current_policy(&f).policy_epoch;
        f.command.review.subject.policy_epoch = epoch;
        committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "old-approval").unwrap());
        // Even byte-identical settings form a new explicit policy epoch.
        committed(
            change_policy(
                &f,
                1,
                b"replace-policy",
                &policy_command(1, epoch, policy.clone()),
            )
            .unwrap(),
        );
        let failed = plain_merge(&f, b"old-vote-refused").unwrap();
        denied(&failed.1);
        let epoch = current_policy(&f).policy_epoch;
        let takeover = policy_command(2, epoch, protection_policy(&[], &[9], &[]));
        let refusal = change_policy(&f, 9, b"takeover", &takeover).unwrap();
        denied(&refusal.1);
        let clear = policy_command(2, epoch, protection_policy(&[], &[1], &[]));
        let cleared = committed(change_policy(&f, 1, b"clear", &clear).unwrap());
        assert!(current_policy(&f).protection().unwrap().branches.is_empty());
        assert_eq!(
            change_policy(&f, 9, b"takeover", &takeover).unwrap(),
            refusal
        );
        let epoch = current_policy(&f).policy_epoch;
        let second_takeover = change_policy(
            &f,
            9,
            b"takeover-disabled",
            &policy_command(3, epoch, policy.clone()),
        )
        .unwrap();
        denied(&second_takeover.1);
        let epoch_before_cancel = snapshot(&f.node);
        let request = f.node.request_context();
        request.authority().cancel();
        let session = LoopbackReceiveSession::authenticated(
            actor(1),
            IdempotencyKey::new(b"cancel-policy".to_vec()).unwrap(),
        );
        assert!(
            f.node
                .runtime()
                .block_on(f.node.admit_review_protection_durable_in(
                    &request,
                    &session,
                    &policy_command(3, epoch, policy),
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert_eq!(snapshot(&f.node).basis(), epoch_before_cancel.basis());
        assert_eq!(change_policy(&f, 1, b"clear", &clear).unwrap(), cleared);
        committed(plain_merge(&f, b"permitted-disabled").unwrap());
        f.node.shutdown().unwrap();
    }
}

fn direct_branch(
    f: &Fixture,
    key: &str,
    name: &RefName,
    old: ExpectedOld,
    new: ProposedNew,
) -> (TxId, TerminalOutcome) {
    let request = f.node.request_context();
    let result = f
        .node
        .runtime()
        .block_on(f.node.admit_branch_updates_durable_in(
            &request,
            &session(2, key),
            &[RefCommand {
                name: name.clone(),
                expected_old: old,
                proposed_new: new,
                force: false,
            }],
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert_eq!(result.commands.len(), 1);
    (result.commands[0].tx_id, result.commands[0].terminal)
}

#[test]
fn protected_branch_creation_updates_deletion_and_import_share_the_same_mandatory_gate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch, format);
        let branch = RefName::try_new(b"refs/heads/protected").unwrap();
        let unborn = RefName::try_new(b"refs/heads/protected-unborn").unwrap();
        committed(direct_branch(
            &f,
            "create-before",
            &branch,
            ExpectedOld::Absent,
            ProposedNew::Update(f.data.target_tip),
        ));
        let command = policy_command(
            0,
            PolicyEpoch::FIRST,
            protection_policy(&[branch.as_bytes(), unborn.as_bytes()], &[1], &[3]),
        );
        committed(change_policy(&f, 1, b"protect-direct-paths", &command).unwrap());
        let before = snapshot(&f.node);
        let create = direct_branch(
            &f,
            "forbidden-create",
            &unborn,
            ExpectedOld::Absent,
            ProposedNew::Update(f.data.source_tip),
        );
        let delete = direct_branch(
            &f,
            "forbidden-delete",
            &branch,
            ExpectedOld::Exactly(f.data.target_tip),
            ProposedNew::Delete,
        );
        for result in [&create, &delete] {
            assert!(matches!(
                result.1.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ProtectedRefTransitionDenied,
                    ..
                }
            ));
        }
        assert_eq!(snapshot(&f.node).snapshot().refs, before.snapshot().refs);
        let closure = before.selected_closure().closure().clone();
        let imported = validate_source_import(
            &[SourceRefUpdate {
                old: f.data.target_tip,
                new: f.data.source_tip,
                ref_name: branch.as_bytes().to_vec(),
            }],
            &SourceImportReceipt {
                object_format: format,
                object_count: closure.objects().len().try_into().unwrap(),
                delete_only: false,
                origin: SourceImportOrigin::LocalGitDirectory,
            },
            ValidatedClosure {
                object_closure_root: permitted_object_closure_root(&closure).unwrap(),
                objects: closure.objects().clone(),
            },
        )
        .unwrap();
        let context = protection_context(&f, 2, b"direct-import");
        let request = f.node.request_context();
        let imported = f
            .node
            .runtime()
            .block_on(f.node.admit_validated_source_import_durable_in(
                &request,
                &context,
                &imported,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(imported.commands.iter().all(|c| matches!(
            c.terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        )));
        let free = RefName::try_new(b"refs/heads/unprotected").unwrap();
        committed(direct_branch(
            &f,
            "permitted-direct-twin",
            &free,
            ExpectedOld::Absent,
            ProposedNew::Update(f.data.source_tip),
        ));
        assert_eq!(
            snapshot(&f.node).snapshot().refs.get(&branch),
            Some(&f.data.target_tip)
        );
        assert_eq!(
            snapshot(&f.node).snapshot().refs.get(&free),
            Some(&f.data.source_tip)
        );
        f.node.shutdown().unwrap();
    }
}

#[test]
fn current_policy_and_historical_results_survive_real_node_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        let command = policy_command(
            0,
            PolicyEpoch::FIRST,
            protection_policy(&[b"refs/heads/main"], &[1], &[3]),
        );
        let receipt = committed(change_policy(&f, 1, b"persist-policy", &command).unwrap());
        let before = current_policy(&f);
        let config = scratch.config(format);
        f.node.shutdown().unwrap();
        f.node = OneNode::open_existing(config).unwrap();
        // Terminal identity recovery is independent of current serving status.
        assert_eq!(
            change_policy(&f, 1, b"persist-policy", &command).unwrap(),
            receipt
        );
        f.node.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(current_policy(&f), before);
        let denied = plain_merge(&f, b"after-reopen-missing-review").unwrap();
        assert!(matches!(denied.1.outcome, DecisionOutcome::Refused { .. }));
        f.node.shutdown().unwrap();
    }
}

#[test]
fn concurrent_activation_and_direct_publication_cannot_commit_a_bypass_after_activation() {
    let scratch = Scratch::new();
    let f = fixture(&scratch, GitHashAlgorithm::Sha1);
    let initial = policy_command(0, PolicyEpoch::FIRST, protection_policy(&[], &[1], &[]));
    committed(change_policy(&f, 1, b"initial-disabled", &initial).unwrap());
    let command = policy_command(
        1,
        current_policy(&f).policy_epoch,
        protection_policy(&[b"refs/heads/raced"], &[1], &[3]),
    );
    let state = snapshot(&f.node);
    let closure = state.selected_closure().closure().clone();
    let imported = validate_source_import(
        &[SourceRefUpdate {
            old: fgit_types::GitOid::from_hex(GitHashAlgorithm::Sha1, &"0".repeat(40)).unwrap(),
            new: f.data.source_tip,
            ref_name: b"refs/heads/raced".to_vec(),
        }],
        &SourceImportReceipt {
            object_format: GitHashAlgorithm::Sha1,
            object_count: closure.objects().len().try_into().unwrap(),
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&closure).unwrap(),
            objects: closure.objects().clone(),
        },
    )
    .unwrap();
    let (pa, pb) = (f.node.request_context(), f.node.request_context());
    let session = LoopbackReceiveSession::authenticated(
        actor(1),
        IdempotencyKey::new(b"racing-activation".to_vec()).unwrap(),
    );
    let import_context = protection_context(&f, 2, b"racing-direct-import");
    let mut activate = Box::pin(f.node.admit_review_protection_durable_in(
        &pa,
        &session,
        &command,
        AdmissionLimits::default(),
    ));
    let mut update = Box::pin(f.node.admit_validated_source_import_durable_in(
        &pb,
        &import_context,
        &imported,
        AdmissionLimits::default(),
    ));
    let (mut left, mut right, mut overlap) = (None, None, false);
    let (activated, updated) = f.node.runtime().block_on(std::future::poll_fn(|cx| {
        if left.is_none()
            && let Poll::Ready(result) = activate.as_mut().poll(cx)
        {
            left = Some(result);
        }
        if right.is_none()
            && let Poll::Ready(result) = update.as_mut().poll(cx)
        {
            right = Some(result);
        }
        overlap |= left.is_none() && right.is_none();
        if left.is_some() && right.is_some() {
            Poll::Ready((
                left.take().unwrap().unwrap(),
                right.take().unwrap().unwrap(),
            ))
        } else {
            Poll::Pending
        }
    }));
    drop(activate);
    drop(update);
    assert!(overlap, "the real authority operations must overlap");
    committed(activated.clone());
    for row in updated.commands {
        if matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }) {
            assert!(
                row.terminal.decision_sequence < activated.1.decision_sequence,
                "a direct update may win before activation, never after it"
            );
        } else {
            assert!(matches!(
                row.terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ProtectedRefTransitionDenied,
                    ..
                }
            ));
        }
    }
    assert_eq!(current_policy(&f).version().unwrap().get(), 2);
    f.node.shutdown().unwrap();
}

fn direct_native_recovery(
    f: &Fixture,
    who: u8,
    key: &[u8],
    intent: &fgit_admission::merge::native::NativeMergeIntent,
    object_limits: fgit_admission::merge::native::objects::MergeObjectLimits,
) -> Result<TerminalOutcome, NodeReceiveTransportRefusal> {
    let request = f.node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        actor(who), IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    f.node.runtime().block_on(f.node.admit_native_merge_durable_in(
        &request, &session, intent, AdmissionLimits::default(), object_limits,
    ))
}

fn recovery_intent(f: &Fixture) -> fgit_admission::merge::native::NativeMergeIntent {
    fgit_admission::merge::native::NativeMergeIntent::new(
        PullRequestNumber::FIRST, ExpectedVersion::Exactly(AggregateVersion::FIRST),
        f.command.candidate.merge(&f.command.review.subject),
    ).unwrap()
}

#[test]
fn direct_native_merge_recovers_committed_bundle_after_policy_activation_and_reopen() {
    use fgit_admission::merge::native::objects::MergeObjectLimits;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        let key = b"direct-recovery-committed";
        let intent = recovery_intent(&f);
        let original = committed(plain_merge(&f, key).unwrap());
        let proposed = intent.seal_attempt(&protection_context(&f, 2, key)).unwrap();
        assert_eq!(proposed.derive().unwrap().0, original.0,
            "bundle and direct APIs must recover the identical semantic seal");
        committed(change_policy(&f, 1, b"protect-after-commit", &policy_command(
            0, PolicyEpoch::FIRST, protection_policy(&[b"refs/heads/main"], &[1], &[3]),
        )).unwrap());
        let before = snapshot(&f.node);
        f.node.shutdown().unwrap();
        f.node = OneNode::open_existing(scratch.config(format)).unwrap();
        // New mutation is not admitted yet; no candidate work budget exists.
        // Neither fact may conceal an already published committed decision.
        let no_object_work = MergeObjectLimits { max_objects: 0, ..MergeObjectLimits::default() };
        assert_eq!(direct_native_recovery(&f, 2, key, &intent, no_object_work).unwrap(), original.1);
        assert_eq!(snapshot(&f.node).basis(), before.basis());
        assert_eq!(snapshot(&f.node).snapshot().refs[&target()], f.command.candidate.commit);
        assert_eq!(snapshot(&f.node).snapshot().outbox, before.snapshot().outbox);
        for (who, other_key) in [(9, key.as_slice()), (2, b"unknown-recovery-key".as_slice())] {
            assert!(direct_native_recovery(&f, who, other_key, &intent, no_object_work).is_err(),
                "an unrelated principal or key must not recover another transaction");
        }
        let changed = fgit_admission::merge::native::NativeMergeIntent::new(
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(AggregateVersion::FIRST.next().unwrap()),
            f.command.candidate.merge(&f.command.review.subject),
        ).unwrap();
        assert!(direct_native_recovery(&f, 2, key, &changed, no_object_work).is_err());
        let request = f.node.request_context();
        let anonymous = LoopbackReceiveSession::anonymous();
        assert!(matches!(f.node.runtime().block_on(f.node.admit_native_merge_durable_in(
            &request, &anonymous, &intent, AdmissionLimits::default(), no_object_work,
        )), Err(NodeReceiveTransportRefusal::Unauthenticated)));
        assert_eq!(snapshot(&f.node).basis(), before.basis());
        f.node.shutdown().unwrap();
    }
}

#[test]
fn direct_native_merge_preserves_refusal_after_policy_clear_but_new_request_can_commit() {
    use fgit_admission::merge::native::objects::MergeObjectLimits;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        committed(change_policy(&f, 1, b"protect-before-refusal", &policy_command(
            0, PolicyEpoch::FIRST, protection_policy(&[b"refs/heads/main"], &[1], &[3]),
        )).unwrap());
        let key = b"direct-recovery-refused";
        let refused = plain_merge(&f, key).unwrap();
        denied(&refused.1);
        let intent = recovery_intent(&f);
        assert_eq!(intent.seal_attempt(&protection_context(&f, 2, key)).unwrap().derive().unwrap().0, refused.0);
        committed(change_policy(&f, 1, b"clear-after-refusal", &policy_command(
            1, current_policy(&f).policy_epoch, protection_policy(&[], &[1], &[]),
        )).unwrap());
        let before = snapshot(&f.node);
        f.node.shutdown().unwrap();
        f.node = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(direct_native_recovery(&f, 2, key, &intent, MergeObjectLimits::default()).unwrap(), refused.1);
        assert_eq!(snapshot(&f.node).basis(), before.basis());
        f.node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fresh = direct_native_recovery(&f, 2, b"direct-new-permitted", &intent, MergeObjectLimits::default()).unwrap();
        assert!(matches!(fresh.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(snapshot(&f.node).snapshot().refs[&target()], f.command.candidate.commit);
        let after = snapshot(&f.node);
        assert_eq!(direct_native_recovery(&f, 2, key, &intent, MergeObjectLimits::default()).unwrap(), refused.1);
        assert_eq!(snapshot(&f.node).basis(), after.basis(), "old refusal never rolls the ref back");
        f.node.shutdown().unwrap();
    }
}

#[test]
fn direct_native_merge_retry_does_not_consume_quota_but_undecided_requests_still_do() {
    use fgit_admission::merge::native::objects::MergeObjectLimits;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        let key = b"quota-recovered-merge";
        let original = committed(plain_merge(&f, key).unwrap());
        let intent = recovery_intent(&f);
        let before = snapshot(&f.node);
        f.node.push_quota = crate::PushQuota::default();
        f.node.push_quota.limit.max_events = 1;
        f.node.push_quota.limit.window = std::time::Duration::from_secs(3600);
        for _ in 0..3 {
            assert_eq!(direct_native_recovery(&f, 2, key, &intent, MergeObjectLimits::default()).unwrap(), original.1);
        }
        assert!(f.node.push_quota.windows.lock().unwrap().is_empty(), "terminal reads never enter mutation rate windows");
        f.node.push_quota.evaluate(&actor(2)).unwrap();
        assert!(f.node.push_quota.evaluate(&actor(2)).is_err());
        assert_eq!(direct_native_recovery(&f, 2, key, &intent, MergeObjectLimits::default()).unwrap(), original.1);
        assert!(direct_native_recovery(&f, 2, b"new-under-exhausted-quota", &intent, MergeObjectLimits::default()).is_err());
        assert_eq!(snapshot(&f.node).basis(), before.basis());
        assert_eq!(snapshot(&f.node).snapshot().outbox, before.snapshot().outbox);
        f.node.shutdown().unwrap();
    }
}

include!("bundle_fetch_protection_tests.rs");
