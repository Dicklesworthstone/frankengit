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
