//! Synchronous native admission over the same preparation/publication driver.
//!
//! Only synchronous authority and projection capabilities enter this adapter.
//! Each private bridge operation completes before returning `Ready`; no caller
//! can supply a suspending future. Polling the shared driver once therefore
//! executes the complete synchronous operation without an executor or wait loop.
//! An asynchronous-only durable store cannot enter this surface.

use std::future::{Future, ready};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId, TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::{HeadGeneration, RefusalCode, TxId};

use super::{NativeMergeIntent, NativeMergeProjection};
use crate::merge::SealedMerge;
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure,
};

/// Synchronous ownership of native validation and immutable materialization.
///
/// Failures retain their terminal-versus-unavailable classification exactly as
/// on the async surface. Implementations must finish every operation before
/// returning; this trait cannot hide an asynchronous staging obligation.
pub trait SyncNativeMergeProjection: Sync {
    /// Check the caller's cancellation and remaining work budget.
    fn merge_checkpoint(&self) -> Result<(), RefusalCode>;
    fn merge_publication_checkpoint(&self) -> Result<(), RefusalCode> {
        self.merge_checkpoint()
    }
    /// Observe the snapshot held by the real workspace owner. Unbound requests
    /// do not call this hook; bound requests require a concrete observation.
    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> {
        Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
    }
    /// Read only the immutable state selected by this authenticated basis.
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure>;
    /// Revalidate the exact candidate, ordered parents, base and full native
    /// object closure at each authority basis, including every CAS replan.
    fn validate_merge(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        intent: &NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure>;
    /// Finish staging the reference partition and its closure before returning.
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure>;
    /// Finish staging the evidence for an evaluated terminal refusal.
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure>;
}

/// Admit a native intent using synchronous storage and native validation.
/// The original async driver owns every seal, replan, fold and publication.
pub fn admit_native_merge<S, P>(
    store: &S,
    context: &AdmissionContext,
    intent: &NativeMergeIntent,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AuthorityStore + Sync + ?Sized,
    P: SyncNativeMergeProjection + ?Sized,
{
    let authority = SyncAuthorityAsAsync(store);
    let projection = SyncProjectionAsAsync(projection);
    complete_immediate(super::admit_native_merge_async(
        &authority,
        &(),
        context,
        intent,
        limits,
        &projection,
    ))
}

/// Admit an original sealed native package without changing its seal identity.
/// This uses the same supplied-evidence and freshness checks as its async twin.
pub fn admit_sealed_native_merge<S, P>(
    store: &S,
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AuthorityStore + Sync + ?Sized,
    P: SyncNativeMergeProjection + ?Sized,
{
    let authority = SyncAuthorityAsAsync(store);
    let projection = SyncProjectionAsAsync(projection);
    complete_immediate(super::admit_sealed_native_merge_async(
        &authority,
        &(),
        context,
        sealed,
        limits,
        &projection,
    ))
}

/// Admit an original native package with an explicit workspace snapshot
/// precondition through the same driver as the asynchronous entrypoint.
pub fn admit_workspace_sealed_native_merge<S, P>(
    store: &S,
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    digest: [u8; 32],
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AuthorityStore + Sync + ?Sized,
    P: SyncNativeMergeProjection + ?Sized,
{
    let authority = SyncAuthorityAsAsync(store);
    let projection = SyncProjectionAsAsync(projection);
    complete_immediate(super::admit_workspace_sealed_native_merge_async(
        &authority,
        &(),
        context,
        sealed,
        digest,
        limits,
        &projection,
    ))
}

// This helper is private and only receives the shared driver instantiated with
// the two private, immediate-only adapters below. It never accepts user futures.
fn complete_immediate(
    future: impl Future<Output = Result<TerminalOutcome, AdmissionError>>,
) -> Result<TerminalOutcome, AdmissionError> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::InternalInvariantBreach,
        )),
    }
}

struct SyncAuthorityAsAsync<'a, S: ?Sized>(&'a S);

impl<S: AuthorityStore + Sync + ?Sized> AsyncAuthorityStore for SyncAuthorityAsAsync<'_, S> {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        ready(self.0.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        ready(self.0.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        ready(self.0.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        ready(self.0.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        ready(
            self.0
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn publish_head_with_outcomes(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        ready(
            self.0
                .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness),
        )
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        ready(self.0.authenticate_head_receipt(receipt))
    }
}

struct SyncProjectionAsAsync<'a, P: ?Sized>(&'a P);

impl<'store, S, P> AsyncAdmissionProjection<SyncAuthorityAsAsync<'store, S>>
    for SyncProjectionAsAsync<'_, P>
where
    S: AuthorityStore + Sync + ?Sized,
    P: SyncNativeMergeProjection + ?Sized,
{
    fn snapshot_async<'a>(
        &'a self,
        _: &'a SyncAuthorityAsAsync<'store, S>,
        _: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        ready(self.0.snapshot(basis, authenticated))
    }
    fn materialize_commit_async<'a>(
        &'a self,
        _: &'a SyncAuthorityAsAsync<'store, S>,
        _: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        ready(self.0.materialize_commit(basis, request, fold, closure))
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        _: &'a SyncAuthorityAsAsync<'store, S>,
        _: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        ready(self.0.materialize_refusal(basis, tx_id, code))
    }
}

impl<'store, S, P> NativeMergeProjection<SyncAuthorityAsAsync<'store, S>>
    for SyncProjectionAsAsync<'_, P>
where
    S: AuthorityStore + Sync + ?Sized,
    P: SyncNativeMergeProjection + ?Sized,
{
    fn merge_checkpoint(&self, _: &()) -> Result<(), RefusalCode> {
        self.0.merge_checkpoint()
    }
    fn merge_publication_checkpoint(&self, _: &()) -> Result<(), RefusalCode> {
        self.0.merge_publication_checkpoint()
    }
    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> {
        self.0.workspace_snapshot_digest()
    }
    fn validate_merge_async<'a>(
        &'a self,
        _: &'a SyncAuthorityAsAsync<'store, S>,
        _: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        ready(self.0.validate_merge(basis, authenticated, intent))
    }
}
