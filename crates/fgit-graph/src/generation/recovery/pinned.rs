//! Exact immutable query selection, rather than a minimum freshness floor.
//! A requested historical generation is accepted only on one authenticated
//! selected lineage, at its original generation. No arbitrary staged lookup.

use super::{
    AsyncAuthorityStore, AuthorityStore, GenerationActivation, GenerationAuthority,
    GenerationAuthorityError, GenerationReadLimits, GraphGenerationBody, GraphViewId,
    SelectedGeneration, Walk,
};
use fgit_types::Digest;

/// An exact query generation plus the distinct head that substantiated it.
/// Fields are private: a caller-supplied ID or body cannot construct this result.
/// This proves root selection, not access, retention or graph-content validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedGeneration {
    generation: SelectedGeneration,
    selected_head: GenerationActivation,
}
impl PinnedGeneration {
    /// The requested generation, never an implicit replacement by a newer one.
    #[must_use]
    pub const fn activation(&self) -> &GenerationActivation {
        self.generation.activation()
    }
    /// Exact immutable manifest used by every continuation of this query.
    #[must_use]
    pub const fn body(&self) -> &GraphGenerationBody {
        self.generation.body()
    }
    /// Current head observed once when this membership check started. It is
    /// evidence of lineage, not the generation to use for the query's payloads.
    #[must_use]
    pub const fn selected_head(&self) -> &GenerationActivation {
        &self.selected_head
    }
    #[must_use]
    pub const fn generations_read(&self) -> usize {
        self.generation.generations_read()
    }
    #[must_use]
    pub const fn bytes_read(&self) -> usize {
        self.generation.bytes_read()
    }
}

impl GraphGenerationBody {
    /// Committed vertex payload root. Reading it still requires the owning
    /// store's authorization and exact payload verification.
    #[must_use]
    pub const fn vertices_root(&self) -> &Digest {
        &self.vertices_root
    }
    /// Committed edge payload root, not a caller-selected substitute.
    #[must_use]
    pub const fn edges_root(&self) -> &Digest {
        &self.edges_root
    }
    /// Committed index manifest, shared by all reads of this exact generation.
    #[must_use]
    pub const fn index_manifest_root(&self) -> &Digest {
        &self.index_manifest_root
    }
    /// Evidence committed with this generation, not evidence from a newer head.
    #[must_use]
    pub const fn evidence_root(&self) -> &Digest {
        &self.evidence_root
    }
}

fn pinned(
    walk: Option<Walk>,
    expected: &GenerationActivation,
) -> Result<PinnedGeneration, GenerationAuthorityError> {
    let walk = walk.ok_or(GenerationAuthorityError::CheckpointUnresolved)?;
    let activation = walk
        .found
        .ok_or(GenerationAuthorityError::CheckpointUnresolved)?;
    if &activation != expected || !walk.minimum_seen {
        return Err(GenerationAuthorityError::CheckpointUnresolved);
    }
    let body = walk
        .found_body
        .ok_or(GenerationAuthorityError::HistoryInconsistent)?;
    // These are measured work counters for the complete membership/checkpoint
    // observation, not a claim that only the target body was read.
    Ok(PinnedGeneration {
        generation: SelectedGeneration {
            activation,
            body,
            generations_read: walk.selected.generations_read(),
            bytes_read: walk.selected.bytes_read(),
        },
        selected_head: walk.selected.activation,
    })
}

impl<S: AuthorityStore> GenerationAuthority<'_, S> {
    /// Resolve an EXACT previously selected generation for query continuation.
    /// Unlike `read_active`, `expected` is not a lower bound on freshness.
    ///
    /// The optional minimum head is independently checked even when it is
    /// newer or older than the query generation. This lets a caller retain its
    /// latest anti-rollback checkpoint without upgrading the query's index.
    /// Missing history, a fork or the wrong original position refuses; no
    /// staged-object fallback, head refresh, retry or write is performed.
    pub fn read_at(
        &self,
        view: GraphViewId,
        expected: &GenerationActivation,
        minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<PinnedGeneration, GenerationAuthorityError> {
        // With no independent floor, requiring the query checkpoint avoids
        // confusing a staged identity with a published generation at this slot.
        let walk = self.inspect(
            view,
            Some(expected.generation_id),
            minimum.or(Some(expected)),
            limits,
            live,
        )?;
        pinned(walk, expected)
    }
}

impl<S: AsyncAuthorityStore> GenerationAuthority<'_, S> {
    /// Production counterpart of `read_at`, with the invocation's context on
    /// every awaited read. Both surfaces share the same lineage/checkpoint
    /// walker and final exact-position check; neither calls the other.
    ///
    /// The caller must authorize the scoped head and requested source before
    /// using the returned manifest. Keeping this value alive does not pin data
    /// against retention or replace the runtime's cancellation ownership.
    pub async fn read_at_async(
        &self,
        cx: &S::Context,
        view: GraphViewId,
        expected: &GenerationActivation,
        minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<PinnedGeneration, GenerationAuthorityError> {
        let walk = self
            .inspect_async(
                cx,
                view,
                Some(expected.generation_id),
                minimum.or(Some(expected)),
                limits,
                live,
            )
            .await?;
        pinned(walk, expected)
    }
}

#[cfg(test)]
mod tests;
