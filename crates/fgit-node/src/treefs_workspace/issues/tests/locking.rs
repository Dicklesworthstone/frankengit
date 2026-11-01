//! Persisted comment locks, retained historical views and terminal recovery.
use super::*;
use fgit_forge::ForgeEventPayload;

fn append(
    node: &OneNode,
    body: &str,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_issue_comment_durable_in(
        &request,
        &session(key),
        &IssueCommentIntent {
            number: IssueNumber::FIRST,
            body: body.into(),
        },
        AdmissionLimits::default(),
    ))
}
fn blocked(
    result: Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>,
) -> (TxId, TerminalOutcome) {
    let result = result.unwrap();
    assert!(
        matches!(
            result.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ),
        "{result:?}"
    );
    result
}

#[test]
fn durable_locks_survive_restart_and_old_outcomes_are_not_reinterpreted_after_unlock() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "open-lockable-issue"));
        let baseline = snapshot(&node);
        let strict_before = change(
            1,
            1,
            IssueAction::Comment {
                body: "Already admitted strict comment".into(),
            },
        );
        let strict_terminal = accepted(apply(&node, &strict_before, "strict-before-lock"));
        let append_terminal = accepted(append(
            &node,
            "Already admitted append",
            "append-before-lock",
        ));
        let unlocked_page = history(&node, 1, 0, None).unwrap();
        assert!(!unlocked_page.issue.as_ref().unwrap().locked);
        let lock = change(1, 3, IssueAction::Lock);
        let lock_terminal = accepted(apply(&node, &lock, "lock-comments"));
        let locked_page = history(&node, 1, 0, None).unwrap();
        let issue = locked_page.issue.as_ref().unwrap();
        assert!(issue.locked);
        assert_eq!(issue.comments, 2);
        assert_eq!(issue.version.get(), 4);
        let lock_event = history(&node, 1, 3, Some(locked_page.source_head)).unwrap();
        assert_eq!(lock_event.events.len(), 1);
        assert!(matches!(
            &lock_event.events[0].payload,
            ForgeEventPayload::IssueChangedNative(change) if change.action == IssueAction::Lock
        ));
        let strict_blocked = change(
            1,
            4,
            IssueAction::Comment {
                body: "Blocked strict".into(),
            },
        );
        let strict_refusal = blocked(apply(&node, &strict_blocked, "strict-locked"));
        let append_refusal = blocked(append(&node, "Blocked append", "append-locked"));
        let settled = snapshot(&node);
        let settled_page = history(&node, 1, 0, None).unwrap();
        assert_eq!(settled_page.issue, locked_page.issue);
        no_code_changes(&baseline, &settled);
        assert_eq!(
            history(&node, 1, 0, Some(unlocked_page.source_head)).unwrap(),
            unlocked_page
        );
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // The original committed or refused outcome is selected before current
        // service intake and before the present lock state could reinterpret it.
        assert_eq!(
            apply(&reopened, &strict_before, "strict-before-lock").unwrap(),
            strict_terminal
        );
        assert_eq!(
            append(&reopened, "Already admitted append", "append-before-lock").unwrap(),
            append_terminal
        );
        assert_eq!(
            apply(&reopened, &lock, "lock-comments").unwrap(),
            lock_terminal
        );
        assert_eq!(
            apply(&reopened, &strict_blocked, "strict-locked").unwrap(),
            strict_refusal
        );
        assert_eq!(
            append(&reopened, "Blocked append", "append-locked").unwrap(),
            append_refusal
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(), settled.basis());
        assert_eq!(history(&reopened, 1, 0, None).unwrap(), settled_page);
        assert_eq!(
            history(&reopened, 1, 0, Some(locked_page.source_head)).unwrap(),
            locked_page
        );
        assert_eq!(
            history(&reopened, 1, 0, Some(unlocked_page.source_head)).unwrap(),
            unlocked_page
        );

        accepted(apply(
            &reopened,
            &change(1, 4, IssueAction::Unlock),
            "unlock-comments",
        ));
        let after_unlock = snapshot(&reopened);
        assert!(
            !history(&reopened, 1, 0, None)
                .unwrap()
                .issue
                .unwrap()
                .locked
        );
        assert_eq!(
            apply(&reopened, &lock, "lock-comments").unwrap(),
            lock_terminal
        );
        assert_eq!(
            apply(&reopened, &strict_blocked, "strict-locked").unwrap(),
            strict_refusal
        );
        assert_eq!(
            append(&reopened, "Blocked append", "append-locked").unwrap(),
            append_refusal
        );
        assert_eq!(snapshot(&reopened).basis(), after_unlock.basis());
        accepted(apply(
            &reopened,
            &change(
                1,
                5,
                IssueAction::Comment {
                    body: "Resumed strict comment".into(),
                },
            ),
            "strict-unlocked",
        ));
        accepted(append(&reopened, "Resumed append", "append-unlocked"));
        let final_issue = history(&reopened, 1, 0, None).unwrap().issue.unwrap();
        assert!(!final_issue.locked);
        assert_eq!(final_issue.version.get(), 7);
        assert_eq!(final_issue.comments, 4);
        assert_eq!(final_issue.state, IssueState::Open);
        assert_eq!(
            history(&reopened, 1, 0, Some(locked_page.source_head)).unwrap(),
            locked_page
        );
        no_code_changes(&baseline, &snapshot(&reopened));
        reopened.shutdown().unwrap();
    }
}
