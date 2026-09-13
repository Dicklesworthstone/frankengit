//! Reuse the real imported-objects/review fixture. No mock authority or fake vote.
use super::*;
use fgit_forge::event::protection::{BranchReviewRule, ProtectionCommand, RepositoryProtectionPolicy};
fn policy(node: &OneNode, version: u64, reviewers: &[u8]) -> ProtectionCommand {
    ProtectionCommand {
        expected_version: if version == 0 { ExpectedVersion::NewStream }
            else { ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap()) },
        expected_policy_epoch: snapshot(node).basis().body().policy_epoch,
        policy: RepositoryProtectionPolicy { administrators: vec![actor(9)],
            branches: if reviewers.is_empty() { vec![] } else { vec![BranchReviewRule {
                target: target(), reviewers: reviewers.iter().copied().map(actor).collect(),
            }] },
        },
    }
}
fn activate(node: &OneNode, command: &ProtectionCommand, who: u8, key: &str) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    node.runtime().block_on(node.admit_repository_protection_durable_in(&request,
        &session(who, key), command, AdmissionLimits::default())).unwrap()
}
fn plain(node: &OneNode, command: &CandidateReviewCommand, bundle: &[u8], key: &str) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    node.runtime().block_on(node.apply_merge_bundle_durable_in(&request, actor(2), key.as_bytes(),
        command.review.subject.pull_request, ExpectedVersion::Exactly(command.review.subject.pull_request_version),
        &command.candidate.merge(&command.review.subject), bundle)).unwrap()
}
fn view(node: &OneNode) -> crate::RepositoryProtectionView {
    let request = node.request_context();
    node.runtime().block_on(node.read_repository_protection_in(&request, None)).unwrap()
}
fn refused(result: &(TxId, TerminalOutcome), code: RefusalCode) {
    assert!(matches!(result.1.outcome, DecisionOutcome::Refused { code: actual, .. } if actual == code), "{result:?}");
}

#[test]
fn repository_protection_enforces_ordinary_merge_and_retains_historical_outcomes_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut f = fixture(&scratch, format);
        assert!(view(&f.node).selected.is_none());
        let before = snapshot(&f.node);
        let setting = policy(&f.node, 0, &[3]);
        let enabled = committed(activate(&f.node, &setting, 9, "enable"));
        let active = view(&f.node);
        assert_eq!(active.policy_epoch, setting.expected_policy_epoch.next().unwrap());
        assert_eq!(active.selected.as_ref().unwrap().version, AggregateVersion::FIRST);
        code_unchanged(&before, &snapshot(&f.node));
        let missing = plain(&f.node, &f.command, &f.bundle, "missing-review");
        refused(&missing, RefusalCode::EvidenceMissing);
        f.command.review.subject.policy_epoch = active.policy_epoch;
        committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "approve-active").unwrap());
        let before_retry = snapshot(&f.node);
        assert_eq!(plain(&f.node, &f.command, &[], "missing-review"), missing);
        assert_eq!(snapshot(&f.node).basis(), before_retry.basis());
        f.node.shutdown().unwrap();
        let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(activate(&node, &setting, 9, "enable"), enabled);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(view(&node).selected.unwrap().event.policy, setting.policy);
        let published = committed(plain(&node, &f.command, &f.bundle, "ordinary-reviewed"));
        assert_eq!(snapshot(&node).snapshot().refs[&target()], f.command.candidate.commit);
        let disable = policy(&node, 1, &[]);
        committed(activate(&node, &disable, 9, "disable-after-merge"));
        let final_head = snapshot(&node);
        assert_eq!(plain(&node, &f.command, &[], "ordinary-reviewed"), published);
        assert_eq!(snapshot(&node).basis(), final_head.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn repository_protection_refuses_real_source_import_until_an_authorized_policy_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let f = fixture(&scratch, format);
        committed(activate(&f.node, &policy(&f.node, 0, &[3]), 9, "enable"));
        let root = scratch.0.join("source");
        let object = f.node.read_git_object(f.data.target_tip).unwrap();
        let text = std::str::from_utf8(object.payload()).unwrap();
        let tree = GitOid::from_hex(format, text.lines().next().unwrap().strip_prefix("tree ").unwrap()).unwrap();
        let next = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[f.data.target_tip], "direct import"));
        fs::write(root.join("refs/heads/main"), format!("{next}\n")).unwrap();
        let before = snapshot(&f.node); let request = f.node.request_context();
        let result = f.node.runtime().block_on(f.node.import_loose_git_directory_durable_in(
            &request, &root, actor(9), b"protected-import")).unwrap();
        assert!(result.commands.iter().all(|command| matches!(command.terminal.outcome,
            DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. })), "{result:?}");
        code_unchanged(&before, &snapshot(&f.node));
        // Administrator status is NOT a direct write bypass.
        let disable = policy(&f.node, 1, &[]);
        refused(&activate(&f.node, &disable, 2, "not-admin"), RefusalCode::ProtectedRefTransitionDenied);
        assert!(!view(&f.node).selected.unwrap().event.policy.branches.is_empty());
        committed(activate(&f.node, &disable, 9, "admin-disable"));
        let result = f.node.runtime().block_on(f.node.import_loose_git_directory_durable_in(
            &request, &root, actor(9), b"now-unprotected-import")).unwrap();
        assert!(result.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
        assert_eq!(snapshot(&f.node).snapshot().refs[&target()], next);
        f.node.shutdown().unwrap();
    }
}

#[test]
fn repository_protection_epoch_change_invalidates_old_votes_and_caller_cannot_weaken_reviewers() {
    let scratch = Scratch::new(); let mut f = fixture(&scratch, GitHashAlgorithm::Sha256);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "old-approval").unwrap());
    committed(activate(&f.node, &policy(&f.node, 0, &[3,4]), 9, "enable-two"));
    refused(&plain(&f.node, &f.command, &f.bundle, "old-epoch"), RefusalCode::EvidenceStale);
    f.command.review.subject.policy_epoch = view(&f.node).policy_epoch;
    f.command.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "refresh-three").unwrap());
    // Even the explicit reviewed command cannot replace repository requirements
    // with a smaller caller-selected set.
    refused(&publish(&f.node, &f.command, &f.bundle, &[actor(3)], "omit-four").unwrap(), RefusalCode::EvidenceMissing);
    let mut fourth = f.command.clone(); fourth.review.expected_version = ExpectedVersion::NewStream;
    committed(vote(&f.node, &fourth, Some(&f.bundle), 4, "approve-four").unwrap());
    let mut withdrawn = fourth.clone(); withdrawn.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    withdrawn.review.decision = ReviewDecision::Withdraw;
    committed(vote(&f.node, &withdrawn, None, 4, "withdraw-four").unwrap());
    refused(&plain(&f.node, &f.command, &f.bundle, "withdrawn"), RefusalCode::ProtectedRefTransitionDenied);
    fourth.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
    committed(vote(&f.node, &fourth, Some(&f.bundle), 4, "reapprove-four").unwrap());
    committed(plain(&f.node, &f.command, &f.bundle, "both-current"));
    f.node.shutdown().unwrap();
}

#[test]
fn repository_protection_administration_has_exact_versions_cancellation_and_changed_key_refusal() {
    let scratch = Scratch::new(); let f = fixture(&scratch, GitHashAlgorithm::Sha1);
    let setting = policy(&f.node, 0, &[3]);
    let before = snapshot(&f.node);
    let request = f.node.request_context(); request.authority().cancel();
    assert!(f.node.runtime().block_on(f.node.admit_repository_protection_durable_in(&request,
        &session(9,"cancel"), &setting, AdmissionLimits::default())).is_err());
    assert_eq!(snapshot(&f.node).basis(), before.basis());
    let original = committed(activate(&f.node, &setting, 9, "enable"));
    let current = snapshot(&f.node);
    let mut altered = setting.clone(); altered.policy.branches.clear();
    let request = f.node.request_context();
    assert!(f.node.runtime().block_on(f.node.admit_repository_protection_durable_in(&request,
        &session(9,"enable"), &altered, AdmissionLimits::default())).is_err());
    assert_eq!(snapshot(&f.node).basis(), current.basis());
    let mut replacement = policy(&f.node, 1, &[4]);
    replacement.policy.administrators = vec![actor(8)];
    committed(activate(&f.node, &replacement, 9, "transfer-admin"));
    assert_eq!(activate(&f.node, &setting, 9, "enable"), original);
    let next = policy(&f.node, 2, &[]);
    refused(&activate(&f.node, &next, 9, "removed-admin"), RefusalCode::ProtectedRefTransitionDenied);
    committed(activate(&f.node, &next, 8, "current-admin"));
    assert!(view(&f.node).selected.unwrap().event.policy.branches.is_empty());
    f.node.shutdown().unwrap();
}
