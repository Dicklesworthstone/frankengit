//! Whole-batch subscription checks shared by manual and fenced delivery.
use fgit_forge::webhook::WebhookEventFilter;
use fgit_forge::{ForgeEvent, ForgeEventPayload};

/// Filter an entire committed batch or refuse it. Removing individual events
/// while retaining the original batch root would lie about the transmitted
/// payload. Fine-grained fan-out needs its own canonical delivery identities.
pub(super) fn require_subscription(filter: &WebhookEventFilter, events: &[ForgeEvent]) -> Result<(), String> {
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
