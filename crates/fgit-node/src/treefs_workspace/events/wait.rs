//! Bounded tail waits over the existing authenticated canonical event reader.

use super::{
    ForgeEventDisclosureProfile, ForgeEventReadGrants, ForgeEventReadRefusal,
    scoped::ScopedForgeEventPage, workspace_request_live,
};
use crate::{NodeRequestContext, OneNode};
use fgit_types::RepositoryAuthorityHeadId;
use std::time::Duration;

const HEAD_POLL_INTERVAL: Duration = Duration::from_millis(50);

impl OneNode {
    /// Maximum optional event-feed tail wait, shared by HTTP and MCP.
    pub const MAX_FORGE_EVENT_WAIT_MS: u32 = 30_000;

    /// Read one bounded event page, optionally waiting at an empty tail.
    ///
    /// Zero preserves [`Self::read_profiled_forge_events_in`] exactly. A
    /// positive wait returns as soon as the cursor advances, even when every
    /// examined event is hidden by the caller's grants or disclosure policy.
    /// It never scans extra pages to fill a visible-event quota. At timeout,
    /// the last authenticated empty page retains its current source head.
    /// An `expected_head` pin remains active while waiting: any observed head
    /// movement returns [`ForgeEventReadRefusal::SnapshotMoved`].
    ///
    /// The original request owns every read and timer wait; its deadline,
    /// cancellation, poll quota and cost quota are never renewed. An idle
    /// wait checks cancellation at most every 50 ms. Canonical reads are
    /// awaited to completion rather than dropped on a timer, so completing
    /// an in-flight read can outlast the optional wait. An unchanged head
    /// needs no history replay or repeated canonical event-page read. Grants
    /// must come from the host's independent authentication boundary; hosts
    /// with mutable credentials must revalidate them before disclosure.
    pub async fn read_profiled_forge_events_wait_in(
        &self,
        request: &NodeRequestContext,
        after: Option<(u64, u32)>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
        profile: ForgeEventDisclosureProfile,
        grants: ForgeEventReadGrants,
        wait_ms: u32,
    ) -> Result<ScopedForgeEventPage, ForgeEventReadRefusal> {
        if wait_ms > Self::MAX_FORGE_EVENT_WAIT_MS {
            return Err(ForgeEventReadRefusal::InvalidWait);
        }
        if wait_ms == 0 {
            return self
                .read_profiled_forge_events_in(
                    request,
                    after,
                    limit,
                    expected_head,
                    profile,
                    grants,
                )
                .await;
        }
        let deadline = self.runtime().now() + Duration::from_millis(u64::from(wait_ms));
        let mut page = self
            .read_profiled_forge_events_in(request, after, limit, expected_head, profile, grants)
            .await?;
        loop {
            if !workspace_request_live(request) {
                return Err(ForgeEventReadRefusal::Cancelled);
            }
            if page.resume_after() != after
                || page.next_after().is_some()
                || !page.events().is_empty()
            {
                return Ok(page);
            }
            let now = self.runtime().now();
            let remaining = Duration::from_nanos(deadline.duration_since(now));
            if remaining.is_zero() {
                return Ok(page);
            }
            asupersync::time::sleep(now, remaining.min(HEAD_POLL_INTERVAL)).await;
            if !workspace_request_live(request) {
                return Err(ForgeEventReadRefusal::Cancelled);
            }
            // Authenticate storage's live head, including when a different
            // node instance publishes. A cached tail cannot suppress this
            // check. The optional event index never selects authority.
            let selected = self.event_read_basis_in(request, expected_head).await?;
            if selected.basis.id() != page.source_head() {
                // The shared reader selects events and their policy together
                // at its own authenticated basis, including a second append
                // racing this head probe. Preserve the original cursor and
                // per-page scan/byte budgets; hidden progress ends the wait.
                page = self
                    .read_profiled_forge_events_in(
                        request,
                        after,
                        limit,
                        expected_head,
                        profile,
                        grants,
                    )
                    .await?;
            }
        }
    }
}
