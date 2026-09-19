//! Bounded, read-only resolution from one authenticated generation head.
//!
//! A staged object is not an activation receipt. Resolution follows only the
//! exact immutable predecessor keys reachable from the selected head, never a
//! listing, a fresh head halfway through the walk, or a local outcome cache.

mod pinned;
pub use pinned::PinnedGeneration;

use super::{
    GenerationActivation, GenerationAuthority, GenerationAuthorityError, GraphGenerationBody,
    GraphGenerationId, GraphViewId, activation::check_authenticated, immutable_generation_key,
};
use fgit_authority::{AsyncAuthorityStore, AuthorityStore, HeadRead, ImmutableRead};
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_types::HeadGeneration;
use std::collections::BTreeSet;

/// Read/ancestry bounds, independently narrowable from this profile's ceilings.
/// The backend must also bound its own read allocation before returning bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationReadLimits {
    pub max_generations: usize,
    pub max_body_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for GenerationReadLimits {
    fn default() -> Self {
        Self { max_generations: 4096, max_body_bytes: 16 * 1024, max_total_bytes: 16 * 1024 * 1024 }
    }
}
impl GenerationReadLimits {
    pub fn validate(self) -> Result<(), GenerationAuthorityError> {
        let ceiling = Self::default();
        if self.max_generations == 0 || self.max_generations > ceiling.max_generations
            || self.max_body_bytes == 0 || self.max_body_bytes > ceiling.max_body_bytes
            || self.max_total_bytes == 0 || self.max_total_bytes > ceiling.max_total_bytes
        { return Err(GenerationAuthorityError::InvalidReadLimits); }
        Ok(())
    }
}

/// A generation selected by an authenticated head, with its exact immutable
/// body verified. It does not grant repository access or attest graph contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedGeneration {
    activation: GenerationActivation,
    body: GraphGenerationBody,
    generations_read: usize,
    bytes_read: usize,
}
impl SelectedGeneration {
    #[must_use]
    pub const fn activation(&self) -> &GenerationActivation { &self.activation }
    #[must_use]
    pub const fn body(&self) -> &GraphGenerationBody { &self.body }
    /// Immutable generation bodies read, including the active body's backing.
    #[must_use]
    pub const fn generations_read(&self) -> usize { self.generations_read }
    /// Head plus immutable body bytes returned by the store during this read.
    #[must_use]
    pub const fn bytes_read(&self) -> usize { self.bytes_read }
}

/// Evidence from the selected generation history. None of these cases retries
/// an operation or converts immutable object existence into publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationRecovery {
    /// No head exists. This does not erase any caller-retained higher checkpoint.
    Uninitialized,
    /// The candidate is the exact active generation of this observation.
    Active { selected: SelectedGeneration },
    /// The candidate is an identity-verified predecessor of the observed head.
    Superseded { activation: GenerationActivation, selected: SelectedGeneration },
    /// The complete verified chain reached genesis without the candidate.
    /// Concurrent publication after the selected head is outside this result.
    NotInSelectedHistory { selected: SelectedGeneration },
}

fn check(live: &mut impl FnMut() -> bool) -> Result<(), GenerationAuthorityError> {
    if live() { Ok(()) } else { Err(GenerationAuthorityError::ReadCancelled) }
}

fn check_head_size(count: usize, limits: GenerationReadLimits) -> Result<(), GenerationAuthorityError> {
    // Check the raw envelope before authentication/decoding can inspect its
    // fields. Never disclose a decoded view before authenticating the read.
    Budget { limits, generations: 0, bytes: 0 }.bytes(count)
}

struct Budget {
    limits: GenerationReadLimits,
    generations: usize,
    bytes: usize,
}
impl Budget {
    fn bytes(&mut self, count: usize) -> Result<(), GenerationAuthorityError> {
        if count > self.limits.max_body_bytes {
            return Err(GenerationAuthorityError::ReadBudgetExceeded("generation body bytes"));
        }
        self.bytes = self.bytes.checked_add(count)
            .filter(|n| *n <= self.limits.max_total_bytes)
            .ok_or(GenerationAuthorityError::ReadBudgetExceeded("generation read bytes"))?;
        Ok(())
    }
}

struct Walk {
    selected: SelectedGeneration,
    target: Option<GraphGenerationId>,
    minimum: Option<GenerationActivation>,
    minimum_seen: bool,
    found: Option<GenerationActivation>,
    found_body: Option<GraphGenerationBody>,
    next: GraphGenerationId,
    position: HeadGeneration,
    visited: BTreeSet<GraphGenerationId>,
    ended: bool,
    budget: Budget,
}
impl Walk {
    fn start(
        read: &HeadRead,
        view: GraphViewId,
        target: Option<GraphGenerationId>,
        minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits,
    ) -> Result<Option<Self>, GenerationAuthorityError> {
        let HeadRead::Present(receipt) = read else {
            return if minimum.is_some() { Err(GenerationAuthorityError::CheckpointUnresolved) }
                else { Ok(None) };
        };
        let mut budget = Budget { limits, generations: 0, bytes: 0 };
        budget.bytes(receipt.body().len())?;
        let body = decode_body::<GraphGenerationBody>(receipt.body(), DecodeLimits::default())?;
        if encode_body(&body)? != receipt.body() { return Err(GenerationAuthorityError::HistoryInconsistent); }
        if body.graph_view_id() != view {
            return Err(GenerationAuthorityError::ViewMismatch {
                active: Box::new(body.graph_view_id()), proposed: Box::new(view),
            });
        }
        let activation = GenerationActivation {
            generation_id: body.generation_id()?, authority_generation: receipt.generation(),
        };
        if minimum.is_some_and(|floor| floor.authority_generation > activation.authority_generation) {
            return Err(GenerationAuthorityError::CheckpointUnresolved);
        }
        Ok(Some(Self {
            next: activation.generation_id, position: activation.authority_generation,
            selected: SelectedGeneration { activation, body, generations_read: 0, bytes_read: 0 },
            target, minimum: minimum.cloned(), minimum_seen: minimum.is_none(), found: None, found_body: None,
            visited: BTreeSet::new(), ended: false, budget,
        }))
    }

    fn key(&mut self) -> Result<fgit_authority::ImmutableKey, GenerationAuthorityError> {
        if self.budget.bytes >= self.budget.limits.max_total_bytes {
            return Err(GenerationAuthorityError::ReadBudgetExceeded("generation read bytes"));
        }
        if self.budget.generations == self.budget.limits.max_generations {
            return Err(GenerationAuthorityError::ReadBudgetExceeded("generation ancestry"));
        }
        if !self.visited.insert(self.next) { return Err(GenerationAuthorityError::HistoryInconsistent); }
        self.budget.generations += 1;
        immutable_generation_key(self.next)
    }

    /// Verify before observing the target or accepting a checkpoint. Every
    /// positive and negative answer passes the SAME canonical-body checks.
    fn observe(&mut self, read: ImmutableRead) -> Result<bool, GenerationAuthorityError> {
        let ImmutableRead::Present(bytes) = read else {
            return Err(GenerationAuthorityError::MissingGeneration { generation_id: Box::new(self.next) });
        };
        self.budget.bytes(bytes.len())?;
        let body = decode_body::<GraphGenerationBody>(&bytes, DecodeLimits::default())?;
        let observed = body.generation_id()?;
        if observed != self.next {
            return Err(GenerationAuthorityError::GenerationIdentityMismatch {
                expected: Box::new(self.next), observed: Box::new(observed),
            });
        }
        if encode_body(&body)? != bytes || body.graph_view_id() != self.selected.body.graph_view_id()
            || (self.budget.generations == 1 && body != self.selected.body)
            || ((self.position == HeadGeneration::FIRST) != body.predecessor_generation_id().is_none())
        { return Err(GenerationAuthorityError::HistoryInconsistent); }
        if let Some(minimum) = &self.minimum {
            if self.position == minimum.authority_generation {
                if observed != minimum.generation_id { return Err(GenerationAuthorityError::CheckpointUnresolved); }
                self.minimum_seen = true;
            }
        }
        if self.target == Some(observed) {
            self.found = Some(GenerationActivation { generation_id: observed, authority_generation: self.position });
            // Retain at most one bounded body. It remains private until every
            // requested checkpoint has been verified by this same walk.
            self.found_body = Some(body.clone());
        }
        self.ended = body.predecessor_generation_id().is_none();
        if self.minimum_seen && (self.target.is_none() || self.found.is_some() || self.ended) {
            self.selected.generations_read = self.budget.generations;
            self.selected.bytes_read = self.budget.bytes;
            return Ok(true);
        }
        if self.ended { return Err(GenerationAuthorityError::CheckpointUnresolved); }
        self.next = body.predecessor_generation_id().ok_or(GenerationAuthorityError::HistoryInconsistent)?;
        self.position = HeadGeneration::try_new(self.position.get() - 1)?;
        Ok(false)
    }

    fn recovery(self) -> GenerationRecovery {
        match self.found {
            Some(found) if found.generation_id == self.selected.activation.generation_id =>
                GenerationRecovery::Active { selected: self.selected },
            Some(activation) => GenerationRecovery::Superseded { activation, selected: self.selected },
            None => GenerationRecovery::NotInSelectedHistory { selected: self.selected },
        }
    }
}

impl<S: AuthorityStore> GenerationAuthority<'_, S> {
    fn inspect(
        &self, view: GraphViewId, target: Option<GraphGenerationId>,
        minimum: Option<&GenerationActivation>, limits: GenerationReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Option<Walk>, GenerationAuthorityError> {
        limits.validate()?;
        check(live)?;
        let read = self.store.read_head(&self.head_key)?;
        check(live)?;
        if let HeadRead::Present(receipt) = &read {
            check_head_size(receipt.body().len(), limits)?;
            let authenticated = self.store.authenticate_head_receipt(receipt)?;
            check(live)?;
            check_authenticated(self.store.instance_id(), &self.head_key, receipt, &authenticated)?;
        }
        let Some(mut walk) = Walk::start(&read, view, target, minimum, limits)? else { return Ok(None); };
        loop {
            check(live)?;
            let key = walk.key()?;
            let body = self.store.read_immutable(&key)?;
            check(live)?;
            if walk.observe(body)? { check(live)?; return Ok(Some(walk)); }
        }
    }

    /// Select the current exact body, optionally proving extension of a
    /// caller-retained checkpoint. An unresolved higher/forked checkpoint
    /// refuses rather than silently selecting an older valid generation.
    pub fn read_active(
        &self, view: GraphViewId, minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits, live: &mut impl FnMut() -> bool,
    ) -> Result<Option<SelectedGeneration>, GenerationAuthorityError> {
        self.inspect(view, None, minimum, limits, live).map(|walk| walk.map(|walk| walk.selected))
    }

    /// Resolve a candidate only through one authenticated selected lineage.
    /// Missing objects, cancellation and budget exhaustion never mean absence.
    pub fn recover_activation(
        &self, view: GraphViewId, candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>, limits: GenerationReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<GenerationRecovery, GenerationAuthorityError> {
        self.inspect(view, Some(candidate), minimum, limits, live)
            .map(|walk| walk.map_or(GenerationRecovery::Uninitialized, Walk::recovery))
    }
}

impl<S: AsyncAuthorityStore> GenerationAuthority<'_, S> {
    async fn inspect_async(
        &self, cx: &S::Context, view: GraphViewId, target: Option<GraphGenerationId>,
        minimum: Option<&GenerationActivation>, limits: GenerationReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<Option<Walk>, GenerationAuthorityError> {
        limits.validate()?;
        check(live)?;
        let read = self.store.read_head(cx, &self.head_key).await?;
        check(live)?;
        if let HeadRead::Present(receipt) = &read {
            check_head_size(receipt.body().len(), limits)?;
            let authenticated = self.store.authenticate_head_receipt(cx, receipt).await?;
            check(live)?;
            check_authenticated(self.store.instance_id(), &self.head_key, receipt, &authenticated)?;
        }
        let Some(mut walk) = Walk::start(&read, view, target, minimum, limits)? else { return Ok(None); };
        loop {
            check(live)?;
            let key = walk.key()?;
            let body = self.store.read_immutable(cx, &key).await?;
            check(live)?;
            if walk.observe(body)? { check(live)?; return Ok(Some(walk)); }
        }
    }

    /// Production selection with this invocation's store context. The read
    /// shares the reference walk and owns no retry, runtime or stored context.
    pub async fn read_active_async(
        &self, cx: &S::Context, view: GraphViewId, minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits, live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<Option<SelectedGeneration>, GenerationAuthorityError> {
        self.inspect_async(cx, view, None, minimum, limits, live).await
            .map(|walk| walk.map(|walk| walk.selected))
    }

    /// Resolve an interrupted activation without staging, publishing, listing,
    /// refreshing the selected head or automatically retrying the candidate.
    pub async fn recover_activation_async(
        &self, cx: &S::Context, view: GraphViewId, candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>, limits: GenerationReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<GenerationRecovery, GenerationAuthorityError> {
        self.inspect_async(cx, view, Some(candidate), minimum, limits, live).await
            .map(|walk| walk.map_or(GenerationRecovery::Uninitialized, Walk::recovery))
    }
}

#[cfg(test)]
mod tests;
