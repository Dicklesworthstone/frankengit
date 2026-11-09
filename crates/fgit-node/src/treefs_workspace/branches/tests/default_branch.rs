//! Native canonical HEAD changes use the real import, authority, object fabric,
//! advertisement, history and reopen paths. No local default cache is seeded.

use super::*;
use crate::AuthenticatedReceiveSession;
use fgit_admission::default_branch::DefaultBranchCommand;
use fgit_admission::evidence::AdmissionAuthentication;
use fgit_authority::TerminalOutcome;
use fgit_types::{RefusalCode, RootLayoutVersion, TxId};
use fgit_wire::{UploadPackRepository, WireLimits};

fn command(expected: Option<&str>, target: &str, tip: GitOid) -> DefaultBranchCommand {
    DefaultBranchCommand {
        expected_head: expected.map(reference),
        target: reference(target),
        expected_target_tip: tip,
    }
}

fn set_default(
    node: &OneNode,
    command: &DefaultBranchCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    node.runtime()
        .block_on(node.admit_default_branch_trusted_local_in(
            &node.request_context(),
            &session(key),
            command,
            AdmissionLimits::default(),
        ))
}

fn committed(
    result: Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>,
) -> (TxId, TerminalOutcome) {
    let result = result.unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
    result
}

fn read_default(node: &OneNode) -> (RepositoryAuthorityHeadId, Option<RefName>, Option<GitOid>) {
    node.runtime()
        .block_on(node.read_default_branch_in(&node.request_context(), &RefVisibility::default()))
        .unwrap()
}

fn unrelated_state_unchanged(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(after.snapshot().refs, before.snapshot().refs);
    assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
    assert_eq!(
        after.selected_closure().closure(),
        before.selected_closure().closure()
    );
    let old = before.basis().body();
    let new = after.basis().body();
    assert_eq!(new.forge_position_root, old.forge_position_root);
    assert_eq!(new.retention_root, old.retention_root);
    assert_eq!(new.outbox_root, old.outbox_root);
    assert_eq!(new.configuration_root, old.configuration_root);
    assert_eq!(new.policy_epoch, old.policy_epoch);
    assert_eq!(new.format_registry_epoch, old.format_registry_epoch);
    assert_eq!(new.last_checkpoint_id, old.last_checkpoint_id);
}

#[test]
fn default_branch_changes_are_authoritative_advertised_historical_and_reopenable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV2,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
        ] {
            let scratch = Scratch::new();
            let (node, base, child, _) = fixture_with_layout(&scratch, format, layout);
            accepted(apply(
                &node,
                &[create("refs/heads/topic", base)],
                "create-topic",
            ));
            let before = snapshot(&node);
            assert_eq!(
                read_default(&node),
                (
                    before.basis().id(),
                    Some(reference("refs/heads/main")),
                    Some(child)
                )
            );
            let change = command(Some("refs/heads/main"), "refs/heads/topic", base);
            let outcome = committed(set_default(&node, &change, "select-topic"));
            let after = snapshot(&node);
            unrelated_state_unchanged(&before, &after);
            assert_ne!(
                after.basis().body().ref_root,
                before.basis().body().ref_root
            );
            assert_eq!(
                after.basis().generation().get(),
                before.basis().generation().get() + 1
            );
            assert_eq!(
                after.basis().body().latest_decision_sequence.unwrap().get(),
                before
                    .basis()
                    .body()
                    .latest_decision_sequence
                    .unwrap()
                    .get()
                    + 1
            );
            assert_eq!(
                after
                    .basis()
                    .body()
                    .latest_repository_sequence
                    .unwrap()
                    .get(),
                before
                    .basis()
                    .body()
                    .latest_repository_sequence
                    .unwrap()
                    .get()
                    + 1
            );
            assert_eq!(
                read_default(&node),
                (
                    after.basis().id(),
                    Some(reference("refs/heads/topic")),
                    Some(base)
                )
            );
            let request = node.request_context();
            let repository =
                node.runtime()
                    .block_on(node.durable_admission_upload_pack_repository_in(
                        &request,
                        &WireLimits::default(),
                    ))
                    .unwrap();
            assert_eq!(
                repository.symref_target(b"HEAD"),
                Some(b"refs/heads/topic".as_slice())
            );
            assert_eq!(
                GitOid::try_from(
                    repository
                        .advertised_refs()
                        .iter()
                        .find(|value| value.name == b"HEAD")
                        .unwrap()
                        .oid
                )
                .unwrap(),
                base
            );
            let history = node
                .runtime()
                .block_on(node.snapshot_history_in(&request))
                .unwrap();
            let row = history
                .iter()
                .find(|row| row.resulting_head_id == after.basis().id())
                .unwrap();
            assert!(
                row.ref_updates.is_empty(),
                "HEAD is not a fake direct Git ref"
            );
            assert!(row.forge_events.is_empty());
            assert_eq!(row.batch.decisions.len(), 1);
            let old_refs = node
                .runtime()
                .block_on(crate::read_historical_ref_state_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id,
                    before.basis().body(),
                ))
                .unwrap();
            let new_refs = node
                .runtime()
                .block_on(crate::read_historical_ref_state_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id,
                    after.basis().body(),
                ))
                .unwrap();
            assert_eq!(old_refs.head_target(), Some(&reference("refs/heads/main")));
            assert_eq!(new_refs.head_target(), Some(&reference("refs/heads/topic")));
            assert_eq!(old_refs.refs(), new_refs.refs());
            assert_eq!(
                set_default(&node, &change, "select-topic").unwrap(),
                outcome
            );
            assert_eq!(snapshot(&node).basis(), after.basis());
            let conflicting = command(Some("refs/heads/topic"), "refs/heads/main", child);
            assert!(set_default(&node, &conflicting, "select-topic").is_err());
            assert_eq!(snapshot(&node).basis(), after.basis());
            node.shutdown().unwrap();
            let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
            // The exact historical outcome resolves even before serving starts.
            assert_eq!(
                set_default(&reopened, &change, "select-topic").unwrap(),
                outcome
            );
            reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
            assert_eq!(
                read_default(&reopened),
                (
                    after.basis().id(),
                    Some(reference("refs/heads/topic")),
                    Some(base)
                )
            );
            assert_eq!(
                reopened
                    .runtime()
                    .block_on(reopened.snapshot_history_in(&reopened.request_context()))
                    .unwrap(),
                history
            );
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn changing_default_moves_deletion_guard_and_retry_never_revalidates_a_deleted_target() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, base, child, _) = fixture(&scratch, format);
        accepted(apply(
            &node,
            &[create("refs/heads/topic", base)],
            "create-topic",
        ));
        let select = command(Some("refs/heads/main"), "refs/heads/topic", base);
        let outcome = committed(set_default(&node, &select, "select-topic"));
        let selected = snapshot(&node);
        assert!(apply(&node, &[delete("refs/heads/topic", base)], "delete-current").is_err());
        assert_eq!(snapshot(&node).basis(), selected.basis());
        // The former default is now an ordinary direct branch.
        accepted(apply(
            &node,
            &[delete("refs/heads/main", child)],
            "delete-former",
        ));
        accepted(apply(
            &node,
            &[create("refs/heads/main", child)],
            "restore-main",
        ));
        committed(set_default(
            &node,
            &command(Some("refs/heads/topic"), "refs/heads/main", child),
            "select-main",
        ));
        accepted(apply(
            &node,
            &[delete("refs/heads/topic", base)],
            "delete-topic",
        ));
        let final_state = snapshot(&node);
        node.push_quota.limit.max_events = 0;
        assert_eq!(
            set_default(&node, &select, "select-topic").unwrap(),
            outcome
        );
        assert_eq!(snapshot(&node).basis(), final_state.basis());
        assert!(
            set_default(
                &node,
                &command(Some("refs/heads/main"), "refs/heads/main", child),
                "new-quota"
            )
            .is_err()
        );
        assert_eq!(snapshot(&node).basis(), final_state.basis());
        node.shutdown().unwrap();
        fs::rename(scratch.0.join("source"), scratch.0.join("source-offline")).unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            set_default(&reopened, &select, "select-topic").unwrap(),
            outcome
        );
        assert_eq!(snapshot(&reopened).basis(), final_state.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn stale_or_absent_targets_refuse_without_mutation_and_same_target_is_a_real_noop() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child, _) = fixture(&scratch, format);
        accepted(apply(
            &node,
            &[create("refs/heads/topic", base)],
            "create-topic",
        ));
        for (key, change) in [
            (
                "wrong-head",
                command(Some("refs/heads/topic"), "refs/heads/topic", base),
            ),
            ("absent-head", command(None, "refs/heads/topic", base)),
            (
                "wrong-tip",
                command(Some("refs/heads/main"), "refs/heads/topic", child),
            ),
            (
                "missing-target",
                command(Some("refs/heads/main"), "refs/heads/missing", base),
            ),
        ] {
            let before = snapshot(&node);
            let refused = set_default(&node, &change, key).unwrap();
            assert!(
                matches!(
                    refused.1.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::ExpectedOldRefMismatch,
                        ..
                    }
                ),
                "{refused:?}"
            );
            let after = snapshot(&node);
            unrelated_state_unchanged(&before, &after);
            assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
            assert_eq!(
                after.basis().body().ref_root,
                before.basis().body().ref_root
            );
            assert_eq!(set_default(&node, &change, key).unwrap(), refused);
            assert_eq!(snapshot(&node).basis(), after.basis());
        }
        let before = snapshot(&node);
        let noop = command(Some("refs/heads/main"), "refs/heads/main", child);
        let outcome = committed(set_default(&node, &noop, "same-target"));
        let after = snapshot(&node);
        unrelated_state_unchanged(&before, &after);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(
            after.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(set_default(&node, &noop, "same-target").unwrap(), outcome);
        node.shutdown().unwrap();
    }
}

#[test]
fn local_operator_scope_and_original_context_are_required_before_any_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, _, _) = fixture(&scratch, format);
        accepted(apply(
            &node,
            &[create("refs/heads/topic", base)],
            "create-topic",
        ));
        let change = command(Some("refs/heads/main"), "refs/heads/topic", base);
        let before = snapshot(&node);
        for authentication in [
            AdmissionAuthentication::HttpToken,
            AdmissionAuthentication::SshDeployKey,
        ] {
            let remote = LoopbackReceiveSession::Authenticated(
                AuthenticatedReceiveSession::new(
                    principal(),
                    IdempotencyKey::new(b"remote-admin".to_vec()).unwrap(),
                )
                .with_authentication(authentication),
            );
            assert!(
                node.runtime()
                    .block_on(node.admit_default_branch_trusted_local_in(
                        &node.request_context(),
                        &remote,
                        &change,
                        AdmissionLimits::default()
                    ))
                    .is_err()
            );
            assert_eq!(snapshot(&node).basis(), before.basis());
        }
        let narrowed = LoopbackReceiveSession::Authenticated(
            AuthenticatedReceiveSession::new(
                principal(),
                IdempotencyKey::new(b"narrowed-admin".to_vec()).unwrap(),
            )
            .with_ref_write_scope(
                fgit_types::RefWriteScope::parse("none")
                    .unwrap()
                    .map(std::sync::Arc::new),
            ),
        );
        assert!(
            node.runtime()
                .block_on(node.admit_default_branch_trusted_local_in(
                    &node.request_context(),
                    &narrowed,
                    &change,
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.admit_default_branch_trusted_local_in(
                    &node.request_context(),
                    &LoopbackReceiveSession::Anonymous,
                    &change,
                    AdmissionLimits::default()
                )),
            Err(NodeReceiveTransportRefusal::Unauthenticated)
        ));
        assert_eq!(snapshot(&node).basis(), before.basis());
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_default_branch_trusted_local_in(
                    &cancelled,
                    &session("cancelled"),
                    &change,
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.read_default_branch_in(&cancelled, &RefVisibility::default()))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        // A cancellation is not a terminal refusal or a poisoned retry key.
        committed(set_default(&node, &change, "cancelled"));
        assert_eq!(read_default(&node).1, Some(reference("refs/heads/topic")));
        node.shutdown().unwrap();
    }
}

#[test]
fn current_administrator_can_select_a_protected_target_without_changing_protection() {
    use fgit_forge::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
    use fgit_types::PolicyEpoch;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, _, _) = fixture(&scratch, format);
        accepted(apply(
            &node,
            &[create("refs/heads/topic", base)],
            "create-topic",
        ));
        let protection = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                ref_policy: None,
                administrators: vec![principal()],
                branches: vec![ProtectedBranch {
                    name: reference("refs/heads/topic"),
                    reviewers: vec![PrincipalId::from_bytes([0xc4; 16])],
                    required_approvals: 1,
                    required_checks: vec![],
                    required_candidate_checks: vec![],
                    path_reviews: vec![],
                    require_merge_queue: true,
                }],
            },
        };
        committed(
            node.runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &node.request_context(),
                    &session("protect-topic"),
                    &protection,
                    AdmissionLimits::default(),
                )),
        );
        let change = command(Some("refs/heads/main"), "refs/heads/topic", base);
        let before = snapshot(&node);
        let unauthorized = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xc5; 16]),
            IdempotencyKey::new(b"not-administrator".to_vec()).unwrap(),
        );
        let refused = node
            .runtime()
            .block_on(node.admit_default_branch_trusted_local_in(
                &node.request_context(),
                &unauthorized,
                &change,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(
            matches!(
                refused.1.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::PublicationPolicyRefused,
                    ..
                }
            ),
            "{refused:?}"
        );
        let refused_state = snapshot(&node);
        unrelated_state_unchanged(&before, &refused_state);
        assert_eq!(
            refused_state.snapshot().head_target,
            before.snapshot().head_target
        );
        committed(set_default(&node, &change, "administrator"));
        let after = snapshot(&node);
        unrelated_state_unchanged(&refused_state, &after);
        assert_eq!(
            after.snapshot().head_target,
            Some(reference("refs/heads/topic"))
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn default_read_preserves_unborn_and_non_utf8_names_and_refuses_hidden_names() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let empty = Scratch::new();
        let (mut node, _) = OneNode::init(empty.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(read_default(&node).1, Some(reference("refs/heads/main")));
        assert_eq!(read_default(&node).2, None);
        node.shutdown().unwrap();

        let scratch = Scratch::new();
        let (node, base, _, _) = fixture(&scratch, format);
        let target = RefName::try_new(b"refs/heads/topic-\xff").unwrap();
        accepted(apply(
            &node,
            &[RefCommand {
                name: target.clone(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(base),
                force: false,
            }],
            "create-byte-target",
        ));
        let change = DefaultBranchCommand {
            expected_head: Some(reference("refs/heads/main")),
            target: target.clone(),
            expected_target_tip: base,
        };
        committed(set_default(&node, &change, "select-byte-target"));
        let before = snapshot(&node);
        for hidden_name in [b"HEAD".as_slice(), target.as_bytes()] {
            let mut hidden = RefVisibility::default();
            hidden
                .push_rule(hidden_name, &WireLimits::default())
                .unwrap();
            assert!(matches!(
                node.runtime()
                    .block_on(node.read_default_branch_in(&node.request_context(), &hidden)),
                Err(NodeWorkspaceRefusal::RefUnavailable)
            ));
            assert_eq!(snapshot(&node).basis(), before.basis());
        }
        assert_eq!(
            read_default(&node),
            (before.basis().id(), Some(target), Some(base))
        );
        node.shutdown().unwrap();
    }
}
