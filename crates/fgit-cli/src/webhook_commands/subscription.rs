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
            ForgeEventPayload::PullRequestOpened { .. }
            | ForgeEventPayload::PullRequestHeadAdvanced { .. }
            | ForgeEventPayload::MergeCommitted { .. }
            | ForgeEventPayload::PullRequestClosed { .. }
            | ForgeEventPayload::MergeCommittedNative(_)
            | ForgeEventPayload::PullRequestChangedNative(_) => "pull_request",
            ForgeEventPayload::PullRequestReviewedNative(_) => "pull_request_review",
            ForgeEventPayload::PullRequestCommentedNative(_) => "pull_request_commented",
            ForgeEventPayload::IssueChangedNative(_) => "issue",
            ForgeEventPayload::ReviewProtectionChanged(_) => "review_protection",
            ForgeEventPayload::MergeQueueChangedNative(_) => "merge_queue",
            ForgeEventPayload::WorkflowCheckObservedNative(_) => "workflow_check",
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
    use fgit_forge::event::pull_request_comment::PullRequestCommentCommand;
    use fgit_forge::{ExpectedVersion, PullRequestNumber};
    use fgit_types::PrincipalId;

    #[test]
    fn conversation_delivery_requires_its_own_event_family_or_exact_kind() {
        let event = PullRequestCommentCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            body: "A conversation comment".into(),
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
}
