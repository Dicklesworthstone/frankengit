//! Native admission independently checks milestone scope, revocation and expiry.
use super::*;
use fgit_forge::MilestoneNumber;
use fgit_forge::event::milestone::{MilestoneAction, MilestoneCommand};
use fgit_identity::agent::{MILESTONES_READ, MILESTONES_WRITE};

fn milestone(number: u64) -> MilestoneCommand {
    MilestoneCommand {
        number: MilestoneNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: MilestoneAction::Open {
            title: format!("Sponsored milestone {number}"),
            body: "Bounded planning metadata".into(),
            due_at: None,
        },
    }
}

fn publish_milestone(
    node: &OneNode,
    run: &AgentRequest,
    command: &MilestoneCommand,
) -> (TxId, TerminalOutcome) {
    node.runtime()
        .block_on(node.admit_milestone_durable_in(
            &run.context(node),
            &run.authenticated_session(),
            command,
            Default::default(),
        ))
        .unwrap()
}

#[test]
fn native_milestone_admission_rechecks_scope_revocation_and_original_session_deadline() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        for (index, (scope, digit)) in [
            (ISSUES_WRITE, 'a'),
            (MILESTONES_READ, 'b'),
            (MILESTONES_WRITE, 'c'),
        ]
        .into_iter()
        .enumerate()
        {
            let token = bearer(digit);
            let grant = AgentCredentialGrant {
                operations: scope,
                ..grant(&node)
            };
            let issued = issue_command(&token, grant);
            committed(credential(
                &node,
                &issued,
                actor(1),
                &format!("issue-{index}"),
            ));
            let retry = format!("milestone-{index}");
            let run = authentication(&node, &token, &retry, scope);
            let expected_class = if scope == MILESTONES_READ {
                OperationClass::ReadCanonicalObject
            } else {
                OperationClass::MutateForgeEntity
            };
            for class in OperationClass::ALL {
                assert_eq!(
                    run.run.allowed_operation_classes().contains(class),
                    class == expected_class
                );
            }
            let result = publish_milestone(&node, &run, &milestone(index as u64 + 1));
            if scope != MILESTONES_WRITE {
                denied(&result, RefusalCode::CapabilityScopeViolation);
                continue;
            }
            committed(result);
            assert_eq!(
                provenance(&node, actor(2), &retry).agent_provenance(),
                Some(&run.authentication)
            );

            // Even a fresh caller context cannot renew the original session.
            let mut expired = authentication(&node, &token, "expired-milestone", scope);
            expired.constrain_deadline(Instant::now() - std::time::Duration::from_secs(1));
            let error = node
                .runtime()
                .block_on(node.admit_milestone_durable_in(
                    &node.request_context(),
                    &expired.authenticated_session(),
                    &milestone(7),
                    Default::default(),
                ))
                .unwrap_err();
            assert!(matches!(
                error,
                NodeReceiveTransportRefusal::Admission(error)
                    if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::CapabilityExpired))
            ));

            let inflight = authentication(&node, &token, "revoked-milestone", scope);
            committed(credential(
                &node,
                &AgentCredentialCommand {
                    id: issued.id,
                    expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    action: AgentCredentialAction::Revoke(grant),
                },
                actor(1),
                "revoke-milestone-writer",
            ));
            let refused = publish_milestone(&node, &inflight, &milestone(8));
            denied(&refused, RefusalCode::CapabilityScopeViolation);
            assert_eq!(publish_milestone(&node, &inflight, &milestone(8)), refused);
        }
        let page = node
            .runtime()
            .block_on(node.read_milestones_in(&node.request_context(), 0, 10, None))
            .unwrap();
        assert_eq!(page.milestones.len(), 1);
        assert_eq!(page.milestones[0].milestone.number.get(), 3);
        node.shutdown().unwrap();
    }
}
