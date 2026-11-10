//! V2 disclosure uses the existing canonical readers for metadata that is not
//! carried by an event. Their basis is selected once by the enclosing feed.

use super::{ForgeEventPage, ForgeEventReadGrants, ForgeEventReadRefusal, stopped};
use fgit_admission::merge::native::pull_request::{self, comments};
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::{AggregateId, ForgeEvent, ForgeEventPayload, PullRequestNumber};
use fgit_types::RefName;
use std::collections::{BTreeMap, BTreeSet};

/// Request-local disclosure results, never a cache reused at another head.
#[derive(Default)]
pub(super) struct Visibility {
    pub(super) reviews: BTreeSet<PullRequestNumber>,
    pub(super) conversations: BTreeSet<PullRequestNumber>,
}

/// Resolve only event families whose independent grants have already passed.
/// At most one top-level canonical reader call is made for each distinct
/// selected review subject or conversation; each may perform multiple reads.
/// Each reader retains its own finite event/byte/work bounds and shares the
/// enclosing request's cancellation and deadline rather than starting a timer.
pub(super) async fn read_visibility_at<S, H, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    page: &ForgeEventPage,
    grants: ForgeEventReadGrants,
    hidden: &H,
    cancelled: &C,
) -> Result<Visibility, ForgeEventReadRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    H: Fn(&[u8]) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    stopped(cancelled)?;
    if page.source_head != basis.id() || page.events.len() > 100 {
        return Err(ForgeEventReadRefusal::InvalidPage);
    }
    let mut reviews = BTreeMap::new();
    let mut conversations = BTreeMap::new();
    for envelope in &page.events {
        stopped(cancelled)?;
        match (&envelope.event.payload, envelope.event.aggregate) {
            (
                ForgeEventPayload::PullRequestReviewedNative(review),
                AggregateId::PullRequestReview {
                    pull_request,
                    reviewer,
                },
            ) if grants.reviews
                && pull_request == review.subject.pull_request
                && reviewer == review.reviewer
                && !hidden(review.subject.source_ref.as_bytes())
                && !hidden(review.subject.target_ref.as_bytes()) =>
            {
                let version = review.subject.pull_request_version;
                reviews
                    .entry(pull_request)
                    .and_modify(|previous| *previous = std::cmp::max(*previous, version))
                    .or_insert(version);
            }
            (
                ForgeEventPayload::PullRequestCommentedNative(_),
                AggregateId::PullRequestConversation(number),
            ) if grants.pulls => {
                let version = envelope.event.version;
                conversations
                    .entry(number)
                    .and_modify(|previous| *previous = std::cmp::max(*previous, version))
                    .or_insert(version);
            }
            _ => {}
        }
    }
    let visible = |source: &RefName, target: &RefName| {
        !hidden(source.as_bytes()) && !hidden(target.as_bytes())
    };
    let failure = |error| ForgeEventReadRefusal::Admission(Box::new(error));
    let mut result = Visibility::default();
    for (number, required_version) in reviews {
        stopped(cancelled)?;
        let current =
            pull_request::read_page_at(store, cx, basis, number.get() - 1, 1, &visible, cancelled)
                .await
                .map_err(failure)?;
        stopped(cancelled)?;
        if current.source_head != basis.id() {
            return Err(ForgeEventReadRefusal::InvalidPage);
        }
        if let Some(subject) = current
            .pull_requests
            .iter()
            .find(|subject| subject.number == number && subject.data.is_some())
        {
            if subject.event.version < required_version {
                return Err(ForgeEventReadRefusal::InvalidPage);
            }
            result.reviews.insert(number);
        }
    }
    for (number, required_version) in conversations {
        stopped(cancelled)?;
        // This reader validates every selected historical anchor, including
        // anchors outside its one-row return window. A hidden anchor hides the
        // WHOLE conversation, as required by the ordinary conversation API.
        if let Some(current) =
            comments::read_page_at(store, cx, basis, number, 0, 1, &visible, cancelled)
                .await
                .map_err(failure)?
        {
            if current.source_head != basis.id()
                || current.number != number
                || current
                    .discussion_version
                    .is_none_or(|latest| latest < required_version)
            {
                return Err(ForgeEventReadRefusal::InvalidPage);
            }
            result.conversations.insert(number);
        }
        stopped(cancelled)?;
    }
    Ok(result)
}

pub(super) fn permitted(
    event: &ForgeEvent,
    grants: ForgeEventReadGrants,
    visibility: &Visibility,
    hidden: &dyn Fn(&[u8]) -> bool,
) -> bool {
    if super::permitted(event, grants.issues, grants.pulls, hidden) {
        return true;
    }
    match (&event.payload, event.aggregate) {
        (ForgeEventPayload::MilestoneChangedNative(_), AggregateId::Milestone(_)) => grants.issues,
        (ForgeEventPayload::DiscussionChangedNative(_), AggregateId::Discussion(_)) => {
            grants.discussions
        }
        (
            ForgeEventPayload::PullRequestReviewedNative(review),
            AggregateId::PullRequestReview {
                pull_request,
                reviewer,
            },
        ) => {
            grants.reviews
                && pull_request == review.subject.pull_request
                && reviewer == review.reviewer
                && visibility.reviews.contains(&pull_request)
                && !hidden(review.subject.source_ref.as_bytes())
                && !hidden(review.subject.target_ref.as_bytes())
        }
        (
            ForgeEventPayload::PullRequestCommentedNative(comment),
            AggregateId::PullRequestConversation(number),
        ) => {
            grants.pulls
                && visibility.conversations.contains(&number)
                && comment.anchor.as_ref().is_none_or(|anchor| {
                    !hidden(anchor.source_ref.as_bytes()) && !hidden(anchor.target_ref.as_bytes())
                })
        }
        // Notification preferences belong to a recipient; policy, workflow,
        // queue, credentials, legacy and unknown families remain undisclosed.
        _ => false,
    }
}
