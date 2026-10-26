use super::*;

fn transact(
    node: &OneNode,
    commands: &[RefCommand],
    key: &str,
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.admit_branch_transaction_durable_in(
            &node.request_context(),
            &session(key),
            commands,
            AdmissionLimits::default(),
        ))
}
fn advance(name: &str, old: GitOid, new: GitOid) -> RefCommand {
    RefCommand {
        name: reference(name),
        expected_old: ExpectedOld::Exactly(old),
        proposed_new: ProposedNew::Update(new),
        force: false,
    }
}

#[test]
fn multi_branch_transaction_is_one_decision_and_survives_reopen_and_reordered_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child, _) = fixture(&scratch, format);
        accepted(transact(
            &node,
            &[create("refs/heads/a", base), create("refs/heads/b", base)],
            "setup-many",
        ));
        let before = snapshot(&node);
        let commands = [
            advance("refs/heads/a", base, child),
            delete("refs/heads/b", base),
            create("refs/heads/c", child),
        ];
        let committed = accepted(transact(&node, &commands, "atomic-many"));
        assert_eq!(committed.commands.len(), 3);
        assert!(
            committed
                .commands
                .iter()
                .all(|command| command == &committed.commands[0])
        );
        let after = snapshot(&node);
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(
            after.snapshot().refs.get(&reference("refs/heads/a")),
            Some(&child)
        );
        assert!(
            !after
                .snapshot()
                .refs
                .contains_key(&reference("refs/heads/b"))
        );
        assert_eq!(
            after.snapshot().refs.get(&reference("refs/heads/c")),
            Some(&child)
        );
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure()
        );
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_eq!(
            after.basis().body().outbox_root,
            before.basis().body().outbox_root
        );
        node.shutdown().unwrap();
        fs::rename(scratch.0.join("source"), scratch.0.join("source-offline")).unwrap();
        let node = OneNode::open_existing(scratch.config(format)).unwrap();
        let reordered = [
            commands[2].clone(),
            commands[0].clone(),
            commands[1].clone(),
        ];
        assert_eq!(
            transact(&node, &reordered, "atomic-many").unwrap(),
            committed
        );
        assert!(
            transact(
                &node,
                &[create("refs/heads/different", base)],
                "atomic-many"
            )
            .is_err()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn one_stale_tip_refuses_every_branch_and_the_refusal_is_recoverable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child, _) = fixture(&scratch, format);
        accepted(transact(
            &node,
            &[create("refs/heads/a", base), create("refs/heads/b", child)],
            "setup-stale",
        ));
        let before = snapshot(&node);
        let commands = [
            advance("refs/heads/a", base, child),
            delete("refs/heads/b", base),
            create("refs/heads/c", child),
        ];
        let rejected = transact(&node, &commands, "stale-many").unwrap();
        assert!(rejected.session.atomic);
        assert!(
            rejected
                .commands
                .iter()
                .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Refused { .. }))
        );
        assert_eq!(snapshot(&node).snapshot().refs, before.snapshot().refs);
        let after = snapshot(&node);
        assert_eq!(transact(&node, &commands, "stale-many").unwrap(), rejected);
        assert_eq!(snapshot(&node).basis(), after.basis());
        accepted(transact(
            &node,
            &[
                commands[0].clone(),
                delete("refs/heads/b", child),
                commands[2].clone(),
            ],
            "valid-many",
        ));
        node.shutdown().unwrap();
    }
}

#[test]
fn transaction_limits_force_duplicates_formats_and_default_branch_remain_guarded() {
    let scratch = Scratch::new();
    let (node, base, child, blob) = fixture(&scratch, GitHashAlgorithm::Sha1);
    let before = snapshot(&node);
    let good = create("refs/heads/a", base);
    let mut forced = good.clone();
    forced.force = true;
    let mut unspecified = good.clone();
    unspecified.expected_old = ExpectedOld::Unspecified;
    for commands in [
        vec![],
        vec![good.clone(), good.clone()],
        vec![forced],
        vec![unspecified],
        vec![create("refs/tags/not-branch", base)],
        vec![good.clone(), delete("refs/heads/main", child)],
        vec![good.clone(), create("refs/heads/blob", blob)],
        vec![good.clone(), advance("refs/heads/main", child, base)],
    ] {
        assert!(transact(&node, &commands, "invalid-many").is_err());
        assert_eq!(snapshot(&node).basis(), before.basis());
    }
    let foreign = GitOid::from_hex(GitHashAlgorithm::Sha256, &"11".repeat(32)).unwrap();
    assert!(transact(&node, &[create("refs/heads/foreign", foreign)], "foreign").is_err());
    let maximum: Vec<_> = (0..OneNode::MAX_BRANCH_TRANSACTION_COMMANDS)
        .map(|i| create(&format!("refs/heads/batch-{i:02}"), base))
        .collect();
    let mut excessive = maximum.clone();
    excessive.push(create("refs/heads/overflow", base));
    assert!(transact(&node, &excessive, "too-many").is_err());
    assert_eq!(snapshot(&node).basis(), before.basis());
    let accepted = accepted(transact(&node, &maximum, "maximum"));
    assert_eq!(
        accepted.commands.len(),
        OneNode::MAX_BRANCH_TRANSACTION_COMMANDS
    );
    assert_eq!(
        snapshot(&node).snapshot().refs.len(),
        OneNode::MAX_BRANCH_TRANSACTION_COMMANDS + 1
    );
    node.shutdown().unwrap();
}

#[test]
fn cancellation_cannot_publish_a_prefix_and_terminal_retry_precedes_quota() {
    let scratch = Scratch::new();
    let (mut node, base, _, _) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let commands = [
        create("refs/heads/one", base),
        create("refs/heads/two", base),
        create("refs/heads/three", base),
    ];
    let before = snapshot(&node);
    let request = node.request_context();
    request.cancel();
    assert!(
        node.runtime()
            .block_on(node.admit_branch_transaction_durable_in(
                &request,
                &session("cancel-many"),
                &commands,
                AdmissionLimits::default(),
            ))
            .is_err()
    );
    assert_eq!(snapshot(&node).basis(), before.basis());
    let committed = accepted(transact(&node, &commands, "many"));
    let after = snapshot(&node);
    node.push_quota.limit.max_events = 0;
    assert_eq!(transact(&node, &commands, "many").unwrap(), committed);
    assert!(transact(&node, &[create("refs/heads/new", base)], "quota").is_err());
    assert_eq!(snapshot(&node).basis(), after.basis());
    node.shutdown().unwrap();
}

#[test]
fn mandatory_review_protection_rejects_whole_transaction_not_just_protected_member() {
    use fgit_forge::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
    use fgit_types::PolicyEpoch;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, _, _) = fixture(&scratch, format);
        let command = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![principal()],
                branches: vec![ProtectedBranch {
                    required_approvals: 1,
                    name: reference("refs/heads/guarded"),
                    reviewers: vec![PrincipalId::from_bytes([9; 16])],
                    required_checks: vec![],
                }],
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_review_protection_durable_in(
                &node.request_context(),
                &session("install-protection"),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let before = snapshot(&node);
        let commands = [
            create("refs/heads/allowed", base),
            create("refs/heads/guarded", base),
            create("refs/heads/also-allowed", base),
        ];
        let result = transact(&node, &commands, "protected-batch");
        assert!(
            result.as_ref().is_err()
                || result
                    .unwrap()
                    .commands
                    .iter()
                    .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Refused { .. }))
        );
        assert_eq!(snapshot(&node).snapshot().refs, before.snapshot().refs);
        accepted(transact(
            &node,
            &[commands[0].clone(), commands[2].clone()],
            "unprotected-batch",
        ));
        node.shutdown().unwrap();
    }
}
