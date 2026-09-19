//! One decision core for reference and asynchronous generation publication.
//!
//! The body and key formats are unchanged. Callers still own authorization,
//! source validation, staging of referenced graph/index bodies and their
//! durability obligations. This module publishes only the generation root.

use super::{
    GenerationActivation, GenerationAuthority, GenerationAuthorityError, GraphGenerationBody,
    GraphGenerationId, immutable_generation_key,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityStore, AuthorityVersionToken, CasOutcome,
    HeadInit, HeadKey, HeadRead, HeadReadReceipt, PutOutcome, StoreInstanceId,
};
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_types::HeadGeneration;

struct Prepared {
    id: GraphGenerationId,
    bytes: Vec<u8>,
}
impl Prepared {
    fn new(candidate: &GraphGenerationBody) -> Result<Self, GenerationAuthorityError> {
        Ok(Self {
            id: candidate.generation_id()?,
            bytes: encode_body(candidate)?,
        })
    }

    fn staged(&self, outcome: PutOutcome) -> Result<(), GenerationAuthorityError> {
        match outcome {
            PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()),
            PutOutcome::Conflict => Err(GenerationAuthorityError::ImmutableConflict {
                generation_id: Box::new(self.id),
            }),
        }
    }

    fn confirmed(
        &self,
        key: &HeadKey,
        expected: HeadGeneration,
        receipt: &HeadReadReceipt,
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        // Do not await another operation after a successful primitive: later
        // cancellation cannot turn an observed publication into a refusal.
        // A malformed success receipt, however, cannot confirm this candidate.
        if receipt.key() != key || receipt.generation() != expected || receipt.body() != self.bytes {
            return Err(GenerationAuthorityError::InvalidActivationReceipt);
        }
        Ok(GenerationActivation {
            generation_id: self.id,
            authority_generation: expected,
        })
    }

    fn initialized(
        &self,
        key: &HeadKey,
        outcome: HeadInit,
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        match outcome {
            HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => {
                self.confirmed(key, HeadGeneration::FIRST, &receipt)
            }
            HeadInit::Conflict => Err(GenerationAuthorityError::HeadAlreadyInitialized),
        }
    }

    fn exchanged(
        &self,
        key: &HeadKey,
        expected: HeadGeneration,
        outcome: CasOutcome,
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        match outcome {
            CasOutcome::Committed(receipt) => self.confirmed(key, expected, &receipt),
            CasOutcome::PredecessorMismatch => Err(GenerationAuthorityError::ConcurrentActivation),
        }
    }
}

enum Step {
    Initialize,
    Replace {
        token: AuthorityVersionToken,
        generation: HeadGeneration,
    },
}

/// Both drivers use this exact predecessor/view/generation decision. There is
/// no second head read between authentication and the conditional replacement.
fn plan(
    candidate: &GraphGenerationBody,
    id: GraphGenerationId,
    read: &HeadRead,
) -> Result<Step, GenerationAuthorityError> {
    let HeadRead::Present(receipt) = read else {
        if candidate.predecessor_generation_id().is_some() {
            return Err(GenerationAuthorityError::GenesisHasPredecessor {
                generation_id: Box::new(id),
            });
        }
        return Ok(Step::Initialize);
    };
    let active = decode_body::<GraphGenerationBody>(receipt.body(), DecodeLimits::default())?;
    if active.graph_view_id() != candidate.graph_view_id() {
        return Err(GenerationAuthorityError::ViewMismatch {
            active: Box::new(active.graph_view_id()),
            proposed: Box::new(candidate.graph_view_id()),
        });
    }
    let active_id = active.generation_id()?;
    if candidate.predecessor_generation_id() != Some(active_id) {
        // Preserve the existing API: even an exact already-active candidate
        // is not a fresh activation. Use read-only recovery after lost replies.
        return Err(GenerationAuthorityError::PredecessorMismatch {
            expected: Box::new(active_id),
            supplied: candidate.predecessor_generation_id().map(Box::new),
        });
    }
    Ok(Step::Replace {
        token: receipt.token(),
        generation: receipt.generation().next()?,
    })
}

pub(super) fn check_authenticated(
    instance: StoreInstanceId,
    key: &HeadKey,
    receipt: &HeadReadReceipt,
    authenticated: &AuthenticatedHead,
) -> Result<(), GenerationAuthorityError> {
    if receipt.key() != key
        || authenticated.verified_against() != instance
        || authenticated.receipt() != receipt
    {
        return Err(GenerationAuthorityError::InvalidHeadReceipt);
    }
    Ok(())
}

impl<'a, S> GenerationAuthority<'a, S> {
    /// Bind one generation view to an authority head. The caller supplies a
    /// tenant/repository/incarnation-scoped key and authorizes the invocation.
    /// Construction works for async-only production stores without an adapter.
    #[must_use]
    pub const fn new(store: &'a S, head_key: HeadKey) -> Self {
        Self { store, head_key }
    }
}

impl<S: AuthorityStore> GenerationAuthority<'_, S> {
    /// Stage the immutable generation body and conditionally select it at the
    /// exact predecessor. This is the deterministic reference-store surface.
    /// Backend ambiguity remains an error, not evidence of non-publication.
    pub fn stage_and_activate(
        &self,
        candidate: &GraphGenerationBody,
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        let prepared = Prepared::new(candidate)?;
        let key = immutable_generation_key(prepared.id)?;
        prepared.staged(self.store.put_if_absent(&key, &prepared.bytes)?)?;
        let read = self.store.read_head(&self.head_key)?;
        if let HeadRead::Present(receipt) = &read {
            let authenticated = self.store.authenticate_head_receipt(receipt)?;
            check_authenticated(self.store.instance_id(), &self.head_key, receipt, &authenticated)?;
        }
        match plan(candidate, prepared.id, &read)? {
            Step::Initialize => prepared.initialized(
                &self.head_key,
                self.store.initialize_head(&self.head_key, HeadGeneration::FIRST, &prepared.bytes)?,
            ),
            Step::Replace { token, generation } => prepared.exchanged(
                &self.head_key,
                generation,
                self.store.compare_exchange_head(&self.head_key, token, generation, &prepared.bytes)?,
            ),
        }
    }
}

impl<S: AsyncAuthorityStore> GenerationAuthority<'_, S> {
    /// The production counterpart of [`GenerationAuthority::stage_and_activate`]. Every store
    /// operation receives this invocation's context; no context or runtime is
    /// retained on the authority, and no synchronous store adapter is used.
    ///
    /// Referenced graph/index bodies must already satisfy the caller's source
    /// and durability contract. Cancellation or storage ambiguity propagates
    /// without a retry or a fabricated terminal refusal. A successful store
    /// primitive is returned without a subsequent cancellation-prone await.
    pub async fn stage_and_activate_async(
        &self,
        cx: &S::Context,
        candidate: &GraphGenerationBody,
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        let prepared = Prepared::new(candidate)?;
        let key = immutable_generation_key(prepared.id)?;
        prepared.staged(self.store.put_if_absent(cx, &key, &prepared.bytes).await?)?;
        let read = self.store.read_head(cx, &self.head_key).await?;
        if let HeadRead::Present(receipt) = &read {
            let authenticated = self.store.authenticate_head_receipt(cx, receipt).await?;
            check_authenticated(self.store.instance_id(), &self.head_key, receipt, &authenticated)?;
        }
        match plan(candidate, prepared.id, &read)? {
            Step::Initialize => prepared.initialized(
                &self.head_key,
                self.store.initialize_head(cx, &self.head_key, HeadGeneration::FIRST, &prepared.bytes).await?,
            ),
            Step::Replace { token, generation } => prepared.exchanged(
                &self.head_key,
                generation,
                self.store.compare_exchange_head(cx, &self.head_key, token, generation, &prepared.bytes).await?,
            ),
        }
    }
}

#[cfg(test)]
mod tests;
