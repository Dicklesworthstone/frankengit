//! Disposable exact-head coordinates for canonical event pagination.
//!
//! Construction verifies the complete history once. Only the committed roots
//! and page coordinates survive; every page still reads and verifies its event
//! payloads. This is neither persisted authority nor a disclosure decision.

use super::{
    AdmissionError, ForgeEventCursor, ForgeEventPage, PageRecord, Record, checkpoint, history,
    page_limit, read_records_page, storage, unavailable,
};
use fgit_authority::{AsyncAuthorityStore, StoreInstanceId, authority_head_identity};
use fgit_chronicle::PublicationBasis;
use fgit_forge::ForgeEventBatch;
use fgit_types::{HeadGeneration, RefusalCode, RepositoryAuthorityHeadId, RepositoryId};

mod catch_up;

/// Verified metadata for one complete canonical history at one exact head.
///
/// Private fields prevent a caller from supplying derived rows as history.
/// The host must independently authenticate the selected head and authorize
/// disclosure on EVERY read. It must also bind retained indexes to its tenant,
/// storage root, repository incarnation and object format; equal store instance
/// numbers alone do not establish that two host configurations are equivalent.
///
/// A cold build remains bounded O(history). Warm reads perform a binary search
/// plus O(limit) event-batch reads, independently of empty-event commits. Per-
/// batch byte/element limits, page byte limits and cancellation remain enforced.
/// This object contains no event text and does not survive a process restart.
#[derive(Debug)]
pub struct VerifiedEventIndex {
    source_head: RepositoryAuthorityHeadId,
    source_generation: HeadGeneration,
    repository_sequence: u64,
    repository: RepositoryId,
    store_instance: StoreInstanceId,
    records: Vec<PageRecord>,
}

impl VerifiedEventIndex {
    /// Conservative host preflight before an optional full-history build.
    /// Repository sequence bounds the number of committed rows, including
    /// empty batches. A false result only disables acceleration; callers keep
    /// the canonical reader without spending its I/O budget on a doomed build.
    #[must_use]
    pub fn fits_retention_budget(basis: &PublicationBasis, max_retained_bytes: usize) -> bool {
        let rows = basis
            .body()
            .latest_repository_sequence
            .map_or(0, |sequence| sequence.get());
        usize::try_from(rows)
            .ok()
            .and_then(|rows| retained_bytes(rows).ok())
            .is_some_and(|bytes| bytes <= max_retained_bytes)
    }

    /// Build a complete index from the exact canonical history. No incomplete
    /// index is returned after cancellation, history loss or resource refusal.
    /// `max_retained_bytes` bounds the final descriptor allocation; temporary
    /// history verification retains its existing finite replay limits.
    pub async fn build_at<S, C>(
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        max_retained_bytes: usize,
        cancelled: &C,
    ) -> Result<Self, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        checkpoint(cancelled)?;
        if max_retained_bytes < std::mem::size_of::<Self>() {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        let records =
            history::read_records(store, cx, basis, None, history::Limits::DEFAULT, cancelled)
                .await?;

        Self::retain_at(
            store,
            cx,
            basis,
            &[],
            records,
            max_retained_bytes,
            cancelled,
        )
        .await
    }

    /// Extend this verified prefix across exactly one canonical successor edge.
    ///
    /// A different predecessor returns `Ok(None)` without storage I/O, allowing
    /// the host to use its canonical reader without searching unrelated history.
    /// Even that fast path checks the supplied body identity and repository/store
    /// binding. A matching edge verifies the actual predecessor body and complete
    /// decision batch or checkpoint capsule; a matching ID alone is insufficient.
    ///
    /// Only new empty-event bodies are read here. Page reads still verify every
    /// selected nonempty payload, including rows retained from this prefix.
    /// Copying the immutable descriptor vector is O(retained rows), with explicit
    /// cancellation checks; storage work is bounded to the one new history edge
    /// and at most two empty schemas. The existing complete-history record and
    /// predecessor-edge ceilings are preserved. All failures leave `self` intact.
    pub async fn extend_at<S, C>(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        max_retained_bytes: usize,
        cancelled: &C,
    ) -> Result<Option<Self>, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        checkpoint(cancelled)?;
        self.check_binding(store, basis)?;
        if basis.body().predecessor_head_id != Some(self.source_head) {
            return Ok(None);
        }
        let extended = self
            .catch_up_at(store, cx, basis, max_retained_bytes, cancelled)
            .await?;
        // A caller asserting this exact predecessor must supply a valid edge,
        // not turn a malformed generation into an optional cache miss.
        if extended.is_none() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        Ok(extended)
    }

    /// Retain a verified prefix and independently verified newly committed rows.
    /// This helper never accepts rows from a public caller.
    async fn retain_at<S, C>(
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        prefix: &[PageRecord],
        records: Vec<Record>,
        max_retained_bytes: usize,
        cancelled: &C,
    ) -> Result<Self, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        checkpoint(cancelled)?;
        // Native forge commits and ordinary ref-only commits use distinct
        // canonical empty schemas. Verify each referenced empty body once.
        // All other roots that pass storage::read_events must have an event:
        // that reader recomputes the canonical root of the decoded batch.
        // Therefore empty commits cannot turn a warm page into a history scan,
        // and building the index need not read unrelated nonempty payloads.
        let native_empty = storage::root(&ForgeEventBatch { events: Vec::new() })?;
        let reference_empty = storage::root(
            &crate::evidence::ForgeEventBatch::empty()
                .map_err(|_| unavailable(RefusalCode::CanonicalFramingInvalid))?,
        )?;
        let empty_roots = [native_empty, reference_empty];
        let mut empty_seen = [false; 2];
        let mut nonempty = 0usize;
        for record in &records {
            checkpoint(cancelled)?;
            if let Some(index) = empty_roots
                .iter()
                .position(|root| *root == record.event_root)
            {
                empty_seen[index] = true;
            } else {
                nonempty = nonempty
                    .checked_add(1)
                    .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            }
        }
        let retained = prefix
            .len()
            .checked_add(nonempty)
            .filter(|count| *count <= history::Limits::DEFAULT.records)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        let bytes = retained_bytes(retained)?;
        if bytes > max_retained_bytes {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        for (root, seen) in empty_roots.into_iter().zip(empty_seen) {
            if seen {
                checkpoint(cancelled)?;
                let batch =
                    storage::read_events(store, cx, basis.body().repository_id, root).await?;
                checkpoint(cancelled)?;
                if !batch.events.is_empty() {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
            }
        }
        let mut indexed = Vec::new();
        indexed
            .try_reserve_exact(retained)
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        if retained_bytes(indexed.capacity())? > max_retained_bytes {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        for record in prefix {
            checkpoint(cancelled)?;
            indexed.push(*record);
        }
        for record in records {
            checkpoint(cancelled)?;
            if !empty_roots.contains(&record.event_root) {
                indexed.push(PageRecord::from(record));
            }
        }
        checkpoint(cancelled)?;
        Ok(Self {
            source_head: basis.id(),
            source_generation: basis.body().generation,
            repository_sequence: basis
                .body()
                .latest_repository_sequence
                .map_or(0, |sequence| sequence.get()),
            repository: basis.body().repository_id,
            store_instance: store.instance_id(),
            records: indexed,
        })
    }

    fn check_binding<S>(&self, store: &S, basis: &PublicationBasis) -> Result<(), AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
    {
        if authority_head_identity(basis.body())
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
            != basis.id()
            || basis.body().repository_id != self.repository
            || store.instance_id() != self.store_instance
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        Ok(())
    }

    /// Exact verified authority head selected by this index.
    #[must_use]
    pub const fn source_head(&self) -> RepositoryAuthorityHeadId {
        self.source_head
    }

    /// Generation of the exact authenticated head that supplied these rows.
    #[must_use]
    pub const fn source_generation(&self) -> HeadGeneration {
        self.source_generation
    }

    /// Inline index value plus the allocated descriptor capacity. All nested
    /// identifiers are fixed-capacity inline values, with no retained payloads.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        // The constructor checked this exact arithmetic before publication.
        std::mem::size_of::<Self>() + self.records.capacity() * std::mem::size_of::<PageRecord>()
    }

    /// Read a canonical page using this index only at its exact verified head.
    /// A cursor still has to name an existing event, including at EOF. Actual
    /// payloads are commitment-checked on each call, so disappearance/corruption
    /// cannot be hidden by retained index coordinates.
    pub async fn read_page_at<S, C>(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        after: Option<ForgeEventCursor>,
        limit: u16,
        cancelled: &C,
    ) -> Result<ForgeEventPage, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        let limit = page_limit(limit)?;
        checkpoint(cancelled)?;
        self.check_binding(store, basis)?;
        if basis.id() != self.source_head {
            return Err(unavailable(RefusalCode::EvidenceStale));
        }
        let start = if let Some(cursor) = after {
            if cursor.repository_sequence == 0 {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            self.records
                .binary_search_by_key(&cursor.repository_sequence, |record| record.sequence)
                .map_err(|_| unavailable(RefusalCode::EvidenceStale))?
        } else {
            0
        };
        read_records_page(
            store,
            cx,
            basis,
            self.records[start..].iter().copied(),
            after,
            limit,
            cancelled,
        )
        .await
    }
}

fn retained_bytes(capacity: usize) -> Result<usize, AdmissionError> {
    capacity
        .checked_mul(std::mem::size_of::<PageRecord>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<VerifiedEventIndex>()))
        .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))
}
