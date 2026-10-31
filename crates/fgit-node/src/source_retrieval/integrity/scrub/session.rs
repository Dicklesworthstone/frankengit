#![forbid(unsafe_code)]
//! Request-owned pagination over one authenticated, immutable selection.
//! Membership and refs are materialized once, not copied or replayed per page.
//! Every page still authenticates current authority before and after native reads.

use super::{
    GraphAuditRefusal, Instant, MaterializedAdmission, NodeRequestContext, OneNode, ReadMode,
    ScrubQuery, ScrubRefusal, SelectedObjectScrub, admits_read, checkpoint, fmt, revalidate_head,
};

/// A bounded, read-only cursor tied to the originating node and request.
///
/// The session owns its authenticated selection and advances only through pages
/// it produced. It does not pin retention, prevent filesystem corruption or
/// grant a whole-sweep certificate. Consumers must retain prior findings.
/// Dropping an in-flight page leaves the session failed; it cannot silently
/// continue with a fresh budget or an uncertain cursor.
pub struct SelectedObjectScrubSession<'a> {
    node: &'a OneNode,
    request: &'a NodeRequestContext,
    selected: MaterializedAdmission,
    query: ScrubQuery,
    started: Instant,
    exhausted: bool,
    failed: bool,
}

impl fmt::Debug for SelectedObjectScrubSession<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SelectedObjectScrubSession")
            .field("head", &self.selected.basis().id())
            .field("cursor", &self.query.cursor)
            .field("exhausted", &self.exhausted)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl SelectedObjectScrubSession<'_> {
    /// Read the next page under the original per-page bounds. None means the
    /// selected suffix is exhausted; it does not certify any previous page.
    pub async fn next_page(&mut self) -> Result<Option<SelectedObjectScrub>, ScrubRefusal> {
        self.next_page_with_max_payload_bytes(self.query.max_payload_bytes)
            .await
    }

    /// Tighten the next page's included-payload budget, for a sweep's remaining
    /// cumulative allowance. This cannot increase the original page ceiling.
    /// The original request and absolute timeout remain in force for all pages.
    pub async fn next_page_with_max_payload_bytes(
        &mut self,
        maximum: u64,
    ) -> Result<Option<SelectedObjectScrub>, ScrubRefusal> {
        if self.failed {
            return Err(ScrubRefusal::SessionFailed);
        }
        if self.exhausted {
            return Ok(None);
        }
        // Set before the first await: cancellation by dropping this future
        // cannot leave a resumable cursor after an incomplete read.
        self.failed = true;
        let page = self.read_next(maximum).await?;
        self.query.cursor = page.next_cursor();
        self.exhausted = self.query.cursor.is_none();
        self.failed = false;
        Ok(Some(page))
    }

    async fn read_next(&self, maximum: u64) -> Result<SelectedObjectScrub, ScrubRefusal> {
        if maximum == 0 || maximum > self.query.max_payload_bytes {
            return Err(ScrubRefusal::InvalidLimit("session page payload bytes"));
        }
        admits_read(self.node.cell_state(), ReadMode::Current).map_err(GraphAuditRefusal::Cell)?;
        checkpoint(self.request, self.started, self.query.timeout)?;
        let current = self.node.authenticate_authority_head_in(self.request).await;
        checkpoint(self.request, self.started, self.query.timeout)?;
        let current = current.map_err(|cause| GraphAuditRefusal::Authority(Box::new(cause)))?;
        revalidate_head(self.selected.authenticated(), &current)?;
        let query = ScrubQuery {
            max_payload_bytes: maximum,
            ..self.query
        };
        self.node
            .scrub_selected_page_in(self.request, &self.selected, &query, self.started)
            .await
    }
}

impl OneNode {
    /// Materialize one authenticated selection for a request-owned scrub.
    ///
    /// Query timeout starts before selection and never resets on continuation.
    /// Authority changes fail closed before the next page's object reads, even
    /// when the new head happens to select identical object identities.
    pub async fn begin_selected_object_scrub_local_in<'a>(
        &'a self,
        request: &'a NodeRequestContext,
        query: ScrubQuery,
    ) -> Result<SelectedObjectScrubSession<'a>, ScrubRefusal> {
        let started = Instant::now();
        let selected = self
            .prepare_scrub_selection_in(request, &query, started)
            .await?;
        checkpoint(request, started, query.timeout)?;
        Ok(SelectedObjectScrubSession {
            node: self,
            request,
            selected,
            query,
            started,
            exhausted: false,
            failed: false,
        })
    }
}

#[cfg(test)]
mod tests;
