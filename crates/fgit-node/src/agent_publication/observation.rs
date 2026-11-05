//! Checkpoint-aware observation of an original agent submission. The retained
//! witness may replace a history scan, never the original run/seal checks or
//! the authority layer's exact-head and outcome-root authentication.

use core::future::Future;

use fgit_agent::{
    IntentRun,
    ref_publication::{
        ObservedRefTransaction, RefTransactionBinding, RefTransactionObservationRefusal,
        observe_ref_transaction_async, observe_ref_transaction_with_cumulative_async,
    },
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityRefusal,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableBatchFailure, ImmutableKey, ImmutableRead, OutcomeFailure,
    PutOutcome, StoreInstanceId,
};
use fgit_object_fabric::local::LocalFilesystemFabric;
use fgit_types::HeadGeneration;

use crate::{FsqliteCx, NodeRequestContext, OneNode, outcome_collection};

fn outcome(error: OutcomeFailure) -> RefTransactionObservationRefusal {
    RefTransactionObservationRefusal::Outcome(Box::new(error))
}

impl OneNode {
    pub(super) async fn observe_agent_ref_transaction_checkpointed_in(
        &self,
        request: &NodeRequestContext,
        run: &IntentRun,
        binding: &RefTransactionBinding,
    ) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal> {
        if binding.seal().tenant_id != self.tenant_id
            || binding.seal().repository_id != self.repository_id
        {
            return Err(RefTransactionObservationRefusal::Binding);
        }
        observe_checkpointed(
            &self.authority,
            &self.head_key,
            &self.outcome_checkpoint_fabric,
            request,
            run,
            binding,
        )
        .await
    }
}

pub(super) async fn observe_checkpointed<Authority>(
    authority: &Authority,
    head_key: &HeadKey,
    fabric: &LocalFilesystemFabric,
    request: &NodeRequestContext,
    run: &IntentRun,
    binding: &RefTransactionBinding,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal>
where
    Authority: AsyncAuthorityStore<Context = FsqliteCx> + ?Sized,
{
    let cx = request.authority();
    outcome_collection::live(cx).map_err(outcome)?;
    for _ in 0..outcome_collection::MAX_OUTCOME_HEAD_RETRIES {
        outcome_collection::live(cx).map_err(outcome)?;
        let HeadRead::Present(receipt) = AsyncAuthorityStore::read_head(authority, cx, head_key)
            .await
            .map_err(|error| outcome(error.into()))?
        else {
            // The original authenticated run names a repository that already
            // existed. Losing its current head cannot establish no decision.
            return Err(RefTransactionObservationRefusal::StaleOutcomeBasis);
        };
        let authenticated = AsyncAuthorityStore::authenticate_head_receipt(authority, cx, &receipt)
            .await
            .map_err(|error| outcome(error.into()))?;
        // Without a checkpoint the existing terminal-only walk can stop
        // at a recent decision. Do not replace it with an unconditional
        // cumulative walk of the repository's entire history.
        if authenticated
            .body()
            .map_err(|error| outcome(error.into()))?
            .last_checkpoint_id
            .is_none()
        {
            break;
        }
        let expected = authenticated.receipt().token();
        let cumulative = match outcome_collection::collect(
            authority,
            cx,
            head_key,
            &authenticated,
            Some(fabric),
        )
        .await
        {
            Ok(cumulative) => cumulative,
            Err(
                error @ (OutcomeFailure::ReplayBoundExceeded { .. }
                | OutcomeFailure::StreamBodyMissing { .. }),
            ) => {
                // A recent terminal can still be authenticated without a
                // complete cumulative set. Incomplete older evidence never
                // establishes that an unobserved transaction is undecided.
                return match observe_replayed(authority, head_key, request, run, binding).await? {
                    Some(observed) => Ok(Some(observed)),
                    None => Err(outcome(error)),
                };
            }
            Err(error) => return Err(outcome(error)),
        };
        if cumulative.observed() != expected {
            continue;
        }
        let observed = observe_ref_transaction_with_cumulative_async(
            authority,
            cx,
            head_key,
            run,
            binding,
            &cumulative,
        )
        .await;
        outcome_collection::live(cx).map_err(outcome)?;
        match observed {
            Err(RefTransactionObservationRefusal::StaleOutcomeBasis) => continue,
            result => return result,
        }
    }
    observe_replayed(authority, head_key, request, run, binding).await
}

async fn observe_replayed<Authority>(
    authority: &Authority,
    head_key: &HeadKey,
    request: &NodeRequestContext,
    run: &IntentRun,
    binding: &RefTransactionBinding,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal>
where
    Authority: AsyncAuthorityStore<Context = FsqliteCx> + ?Sized,
{
    let cx = request.authority();
    outcome_collection::live(cx).map_err(outcome)?;
    let required = RequiredHead { authority };
    let observed = observe_ref_transaction_async(&required, cx, head_key, run, binding).await;
    outcome_collection::live(cx).map_err(outcome)?;
    observed
}

/// Preserve terminal-only replay while requiring the already-existing
/// repository's head at the replay's own read. A separate before/after check
/// cannot distinguish an absent replay basis from a newer head appearing later.
/// All identity, context, authentication and non-head operations delegate to
/// the original authority; this adapter owns no state or publication decision.
struct RequiredHead<'a, Authority: ?Sized> {
    authority: &'a Authority,
}

impl<Authority> AsyncAuthorityStore for RequiredHead<'_, Authority>
where
    Authority: AsyncAuthorityStore<Context = FsqliteCx> + ?Sized,
{
    type Context = FsqliteCx;

    fn instance_id(&self) -> StoreInstanceId {
        self.authority.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.authority.limits()
    }

    fn put_if_absent(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        self.authority.put_if_absent(cx, key, body)
    }

    fn put_if_absent_batch(
        &self,
        cx: &FsqliteCx,
        entries: &[(ImmutableKey, Vec<u8>)],
    ) -> impl Future<Output = Result<Vec<PutOutcome>, ImmutableBatchFailure>> + Send {
        self.authority.put_if_absent_batch(cx, entries)
    }

    fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.authority.read_immutable(cx, key)
    }

    fn initialize_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        self.authority.initialize_head(cx, key, generation, body)
    }

    async fn read_head(&self, cx: &FsqliteCx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        match self.authority.read_head(cx, key).await? {
            HeadRead::Absent => Err(AuthorityFailure::Refused(AuthorityRefusal::HeadAbsent)),
            present => Ok(present),
        }
    }

    fn compare_exchange_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        self.authority
            .compare_exchange_head(cx, key, expected, generation, body)
    }

    fn publish_head_with_outcomes(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        self.authority
            .publish_head_with_outcomes(cx, key, expected, generation, body, outcomes, witness)
    }

    fn authenticate_head_receipt(
        &self,
        cx: &FsqliteCx,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        self.authority.authenticate_head_receipt(cx, receipt)
    }
}
