//! Whole-batch subscription checks shared by manual and fenced delivery.
use fgit_forge::webhook::WebhookEventFilter;
use fgit_forge::{ForgeEvent, ForgeEventPayload};

/// Filter an entire committed batch or refuse it. Removing individual events
/// while retaining the original batch root would lie about the transmitted
/// payload. Fine-grained fan-out needs its own canonical delivery identities.
pub(super) fn require_subscription(
    filter: &WebhookEventFilter,
    events: &[ForgeEvent],
) -> Result<(), String> {
    if events.is_empty() {
        return Err("no native forge events in selected delivery; no webhook attempted".into());
    }
    for event in events {
        let name = match &event.payload {
            ForgeEventPayload::NotificationPreferenceChangedNative(_) => {
                return Err("private notification preferences cannot be delivered by repository webhooks".into());
            }
            ForgeEventPayload::PullRequestOpened { .. }
            | ForgeEventPayload::PullRequestHeadAdvanced { .. }
            | ForgeEventPayload::MergeCommitted { .. }
            | ForgeEventPayload::PullRequestClosed { .. }
            | ForgeEventPayload::MergeCommittedNative(_)
            | ForgeEventPayload::PullRequestChangedNative(_) => "pull_request",
            ForgeEventPayload::PullRequestReviewedNative(_) => "pull_request_review",
            ForgeEventPayload::PullRequestCommentedNative(_) => "pull_request_commented",
            ForgeEventPayload::IssueChangedNative(_) => "issue",
            ForgeEventPayload::MilestoneChangedNative(_) => "milestone",
            ForgeEventPayload::ReviewProtectionChanged(_) => "review_protection",
            ForgeEventPayload::MergeQueueChangedNative(_) => "merge_queue",
            ForgeEventPayload::WorkflowCheckObservedNative(_) => "workflow_check",
            ForgeEventPayload::CandidateWorkflowCheckObservedNative(_) => {
                "candidate_workflow_check"
            }
        };
        if !filter.matches(name) && !filter.matches(&format!("kind:{}", event.payload.kind())) {
            return Err(format!(
                "subscription does not admit every event in this batch (kind {}); no webhook attempted",
                event.payload.kind()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_forge::event::pull_request_comment::{
        PullRequestCommentCommand, SourceCommentAnchor, SourceCommentComparison, SourceCommentSide,
    };
    use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
    use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName};

    #[test]
    fn private_notification_preferences_refuse_every_subscription_and_complete_mixed_batch() {
        use fgit_forge::IssueNumber;
        use fgit_forge::event::issue::{IssueAction, IssueCommand};
        use fgit_forge::event::notification::{
            NotificationAction, NotificationCommand, NotificationMode,
        };

        let actor = PrincipalId::from_bytes([0x39; 16]);
        let public = IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Public issue".into(),
                body: String::new(),
                labels: Vec::new(),
            },
        }
        .proposed_event(actor)
        .unwrap();
        for filter in [
            WebhookEventFilter::Wildcard,
            WebhookEventFilter::Selected(vec!["issue".into()]),
            WebhookEventFilter::Selected(vec!["kind:8".into()]),
        ] {
            assert!(require_subscription(&filter, std::slice::from_ref(&public)).is_ok());
        }

        let mut filters = vec![
            WebhookEventFilter::Wildcard,
            WebhookEventFilter::Selected(Vec::new()),
        ];
        filters.extend(
            [
                "*",
                "issue",
                "milestone",
                "pull_request",
                "pull_request_review",
                "pull_request_commented",
                "review_protection",
                "merge_queue",
                "workflow_check",
                "candidate_workflow_check",
                "notification",
                "notification_preference",
                "kind:23",
            ]
            .into_iter()
            .map(|name| WebhookEventFilter::Selected(vec![name.into()])),
        );
        filters.push(WebhookEventFilter::Selected(vec![
            "issue".into(),
            "kind:23".into(),
        ]));
        for action in [
            NotificationAction::SetMode(NotificationMode::Participating),
            NotificationAction::SetMode(NotificationMode::Subscribed),
            NotificationAction::SetMode(NotificationMode::Muted),
            NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
            NotificationAction::SetReadThrough(None),
        ] {
            let private = NotificationCommand {
                number: IssueNumber::FIRST,
                expected_version: ExpectedVersion::NewStream,
                action,
            }
            .proposed_event(actor)
            .unwrap();
            assert_eq!(private.payload.kind(), 23);
            assert!(WebhookEventFilter::Wildcard.matches("kind:23"));
            assert!(WebhookEventFilter::Selected(vec!["kind:23".into()]).matches("kind:23"));
            for filter in &filters {
                let refusal =
                    require_subscription(filter, std::slice::from_ref(&private)).unwrap_err();
                assert!(
                    refusal.contains("private notification preferences"),
                    "{refusal}"
                );
                for mixed in [
                    [public.clone(), private.clone()],
                    [private.clone(), public.clone()],
                ] {
                    assert!(
                        require_subscription(filter, &mixed).is_err(),
                        "a batch containing private preferences cannot be delivered or silently truncated"
                    );
                }
            }
        }
    }

    #[test]
    fn milestones_require_their_own_family_or_exact_kind() {
        use fgit_forge::event::milestone::{MilestoneAction, MilestoneCommand};
        let event = MilestoneCommand {
            number: fgit_forge::MilestoneNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: MilestoneAction::Open {
                title: "Release".into(),
                body: String::new(),
                due_at: None,
            },
        }
        .proposed_event(PrincipalId::from_bytes([7; 16]))
        .unwrap();
        for selector in ["milestone", "kind:22"] {
            assert!(
                require_subscription(
                    &WebhookEventFilter::Selected(vec![selector.into()]),
                    std::slice::from_ref(&event)
                )
                .is_ok()
            );
        }
        for selector in ["issue", "pull_request", "kind:8"] {
            assert!(
                require_subscription(
                    &WebhookEventFilter::Selected(vec![selector.into()]),
                    std::slice::from_ref(&event)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn conversation_delivery_requires_its_own_event_family_or_exact_kind() {
        let event = PullRequestCommentCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            body: "A conversation comment".into(),
            anchor: None,
        }
        .proposed_event(PrincipalId::from_bytes([7; 16]))
        .unwrap();
        for selector in ["pull_request_commented", "kind:12"] {
            assert!(
                require_subscription(
                    &WebhookEventFilter::Selected(vec![selector.into()]),
                    std::slice::from_ref(&event)
                )
                .is_ok()
            );
        }
        assert!(
            require_subscription(
                &WebhookEventFilter::Selected(vec!["pull_request_review".into()]),
                &[event]
            )
            .is_err()
        );
    }

    #[test]
    fn source_comments_share_the_comment_family_but_require_kind_15_for_exact_selection() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let oid = |byte: u8| {
                GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len()))
                    .unwrap()
            };
            let mut command = PullRequestCommentCommand {
                number: PullRequestNumber::FIRST,
                expected_version: ExpectedVersion::NewStream,
                body: "Review the original source lines".into(),
                anchor: None,
            };
            let actor = PrincipalId::from_bytes([7; 16]);
            let plain = command.proposed_event(actor).unwrap();
            command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
            command.anchor = Some(SourceCommentAnchor {
                pull_request_version: AggregateVersion::FIRST,
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: oid(0x11),
                target_tip: oid(0x22),
                compared_base: oid(0x22),
                comparison: SourceCommentComparison::Direct,
                path: b"src/\xff.rs".to_vec(),
                side: SourceCommentSide::After,
                blob: oid(0x33),
                mode: 0o100644,
                byte_start: 0,
                byte_end: 9,
                line_start: 0,
                line_count: 1,
            });
            let anchored = command.proposed_event(actor).unwrap();
            assert_eq!(plain.payload.kind(), 12);
            assert_eq!(anchored.payload.kind(), 15);
            assert_eq!(plain.aggregate, anchored.aggregate);

            let family = WebhookEventFilter::Selected(vec!["pull_request_commented".into()]);
            let both_kinds = WebhookEventFilter::Selected(vec!["kind:12".into(), "kind:15".into()]);
            assert!(require_subscription(&family, &[plain.clone(), anchored.clone()]).is_ok());
            assert!(require_subscription(&both_kinds, &[plain.clone(), anchored.clone()]).is_ok());
            assert!(
                require_subscription(
                    &WebhookEventFilter::Selected(vec!["kind:15".into()]),
                    std::slice::from_ref(&anchored),
                )
                .is_ok()
            );

            for selector in ["pull_request", "pull_request_review", "kind:12"] {
                assert!(
                    require_subscription(
                        &WebhookEventFilter::Selected(vec![selector.into()]),
                        std::slice::from_ref(&anchored),
                    )
                    .is_err()
                );
            }
            // A selector cannot strip an unselected event while transmitting
            // the immutable root of the complete mixed conversation batch.
            for selector in ["kind:12", "kind:15"] {
                let filter = WebhookEventFilter::Selected(vec![selector.into()]);
                for batch in [
                    [plain.clone(), anchored.clone()],
                    [anchored.clone(), plain.clone()],
                ] {
                    assert!(require_subscription(&filter, &batch).is_err());
                }
            }
        }
    }
}
