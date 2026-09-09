//! Durable native merge admission. Source refs, forge frontier and delivery
//! obligation are one evaluated transaction and one authority-head replacement.

use std::future::Future;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ExpectedOld, OutcomeLookup, ProposedNew, RefCommand,
    ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan};
use fgit_codec::CryptoBodyIdentity;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMerge};
use fgit_types::{AsciiSlug, RefusalCode};

use super::SealedMerge;
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AsyncAdmissionProjection,
    ProjectionFailure, ValidatedClosure,
};
use super::{NativeMergeBasis, prepare::prepare_event, staging::stage_prepared};
use storage::root;

pub mod delivery;
pub mod history;
pub mod objects;
pub mod prepare;
pub mod progress;
pub mod settlement;
mod storage;
pub use storage::{legacy_genesis_root, load_forge_positions};

/// A reviewed native merge. A new stream records a merge receipt, not invented
/// PR opening or approval events. The caller's expected version is immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMergeIntent {
    expected_version: ExpectedVersion,
    event: ForgeEvent,
}

impl NativeMergeIntent {
    pub fn new(
        pull_request: PullRequestNumber,
        expected_version: ExpectedVersion,
        merge: NativeMerge,
    ) -> Result<Self, AdmissionError> {
        merge.validate().map_err(|_| incoherent("native merge coordinates"))?;
        let version = match expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version.next()
                .map_err(|_| incoherent("exhausted aggregate version"))?,
        };
        Ok(Self {
            expected_version,
            event: ForgeEvent {
                aggregate: fgit_forge::aggregate::AggregateId::PullRequest(pull_request),
                version,
                payload: ForgeEventPayload::MergeCommittedNative(merge),
            },
        })
    }

    #[must_use]
    pub const fn expected_version(&self) -> ExpectedVersion { self.expected_version }

    #[must_use]
    pub const fn event(&self) -> &ForgeEvent { &self.event }

    pub fn merge(&self) -> Result<&NativeMerge, AdmissionError> {
        match &self.event.payload {
            ForgeEventPayload::MergeCommittedNative(merge) => Ok(merge),
            _ => Err(incoherent("native event kind")),
        }
    }

    /// The unchanged semantic seal binds every reviewed coordinate. Delivery
    /// IDs are derived from the winning basis, never from mutable retry state.
    /// Earlier terminal outcomes remain earlier outcomes, without retroactive
    /// enqueueing when this implementation is upgraded.
    pub fn seal_attempt(&self, context: &AdmissionContext) -> Result<SealAttempt, AdmissionError> {
        let merge = self.merge()?;
        if merge.merge_commit.algorithm() != context.object_format {
            return Err(AdmissionError::ObjectFormatMismatch);
        }
        let event_root = root(&ForgeEventBatch::of_one(self.event.clone()))?;
        let request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            vec![RefCommand {
                name: merge.target_ref.clone(),
                expected_old: ExpectedOld::Exactly(merge.target_tip_before),
                proposed_new: ProposedNew::Update(merge.merge_commit),
                force: false,
            }],
            Vec::new(),
            vec![ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("merge.event-batch-root"),
                event_root.bytes().as_bytes(),
            )?],
        )?;
        Ok(SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request,
        })
    }
}

/// Additional capabilities required of a real native-merge projection.
/// Resolution must verify bodies against this exact authenticated head and
/// repository configuration, including any explicit legacy genesis sentinels.
/// It must not substitute an empty frontier for a missing advanced root.
pub trait NativeMergeProjection<S>: AsyncAdmissionProjection<S>
where S: AsyncAuthorityStore + ?Sized,
{
    fn merge_checkpoint(&self, _cx: &S::Context) -> Result<(), RefusalCode> {
        Ok(())
    }

    fn resolve_merge_basis_async<'a>(
        &'a self, authority: &'a S, cx: &'a S::Context,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a;

    /// Re-read native objects and validate ordered parents, common ancestry
    /// and full closure on every CAS attempt. Staging is not object authority.
    fn validate_merge_async<'a>(
        &'a self, authority: &'a S, cx: &'a S::Context,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

/// Evaluate and stage the complete Ref + Forge + Outbox fold before one CAS.
/// The ordinary ref-only publisher is neither called nor weakened. Terminal
/// recovery precedes staleness checks; all pre-CAS dependency failures leave
/// the sealed request undecided, never a fabricated permanent refusal.
pub async fn admit_native_merge_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    intent: &NativeMergeIntent, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    let attempt = intent.seal_attempt(context)?;
    admit_native_attempt_async(
        store, cx, context, intent, &attempt, None, limits, projection,
    )
    .await
}

/// Admit a native event through the original sealed-package API and identity.
///
/// The supplied closure and evidence are checked against native validation and
/// the complete fold at each authenticated basis. This profile requires the
/// exact native closure; additional caller-claimed objects are not admitted.
/// The caller's current workspace epoch remains an asserted precondition, not
/// proof of a supervisor-owned session. Terminal retries resolve before these
/// basis-dependent checks, including after the original merge moved its refs.
pub async fn admit_sealed_native_merge_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    // Preserve every original scoped entry, including the ref-intent root and
    // workspace epoch. Constructing NativeMergeIntent's seal here would give
    // the already sealed logical request a different transaction identity.
    let attempt = super::seal_attempt_for(context, sealed)?;
    let ForgeEventPayload::MergeCommittedNative(merge) = &sealed.package.event.payload else {
        return Err(incoherent("native event kind"));
    };
    let expected_version = match sealed.package.event.version.get() - 1 {
        0 => ExpectedVersion::NewStream,
        version => ExpectedVersion::Exactly(
            AggregateVersion::try_new(version).ok_or_else(|| incoherent("aggregate version"))?,
        ),
    };
    let intent =
        NativeMergeIntent::new(sealed.attempt.pull_request, expected_version, merge.clone())?;
    if intent.event() != &sealed.package.event {
        return Err(incoherent("normalized native event"));
    }
    if merge.merge_commit.algorithm() != context.object_format {
        return Err(AdmissionError::ObjectFormatMismatch);
    }
    admit_native_attempt_async(
        store,
        cx,
        context,
        &intent,
        &attempt,
        Some(sealed),
        limits,
        projection,
    )
    .await
}

/// Both public request forms enter this one validation/publication loop with
/// their original seal. The normalized intent is only an evaluation input.
async fn admit_native_attempt_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    intent: &NativeMergeIntent,
    attempt: &SealAttempt,
    sealed: Option<&SealedMerge<'_>>,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let admission = fgit_authority::seal_request_async(store, cx, attempt).await?;
    let tx_id = admission.tx_id();
    let merge = intent.merge()?;
    for _ in 0..limits.max_cas_replans {
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store, cx, &context.head_key, context.tenant_id, context.repository_id, tx_id,
        ).await? { return Ok(terminal); }
        let (basis, receipt, authenticated) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() { continue; }

        let preparation: Result<_, PreparationFailure> = async {
            let snapshot = projection.snapshot_async(store, cx, &basis, &authenticated).await?;
            if snapshot.hidden_refs.hides(merge.source_ref.as_bytes())
                || snapshot.hidden_refs.hides(merge.target_ref.as_bytes())
            { return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into()); }
            if snapshot.refs.get(&merge.source_ref) != Some(&merge.source_tip)
                || snapshot.refs.get(&merge.target_ref) != Some(&merge.target_tip_before)
            { return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into()); }
            let resolved = projection.resolve_merge_basis_async(store, cx, &basis, &authenticated).await?;
            if resolved.refs.refs() != &snapshot.refs
                || resolved.refs.head_target() != snapshot.head_target.as_ref()
            { return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into()); }
            let positions = load_forge_positions(store, cx, &basis).await?;
            if positions != resolved.forge {
                return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into());
            }
            if let Some(sealed) = sealed {
                super::check_against_snapshot(sealed, &snapshot)
                    .map_err(|stale| ProjectionFailure::Refuse(stale.refusal_code()))?;
            }
            if let Some(code) = storage::aggregate_refusal(store, cx, &positions, intent).await? {
                return Err(ProjectionFailure::Refuse(code).into());
            }
            let closure = projection.validate_merge_async(store, cx, &basis, &authenticated, intent).await?;
            if sealed.is_some_and(|sealed| sealed.closure != &closure) {
                return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete).into());
            }
            let prepared = prepare_event(context, &intent.event, &closure, tx_id, attempt, &basis, &resolved)
                .map_err(ProjectionFailure::Refuse)?;
            Ok(prepared)
        }.await;

        let prepared = match preparation {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => return Err(unavailable(code)),
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                if let Some(terminal) = crate::publish_refusal_async(
                    store, cx, context, &basis, receipt.token(), admission.seal_id(), tx_id,
                    code, projection, &cumulative,
                ).await? { return Ok(terminal); }
                continue;
            }
        };
        // The record is constructed from the complete fold, never repaired by
        // substituting roots into a record whose evidence described fewer effects.
        stage_prepared(store, cx, &prepared).await?;
        let mut plan = PublicationPlan::open(basis.clone())?;
        plan.commit(prepared.materialization.record);
        let publication = plan.seal(&CryptoBodyIdentity, prepared.materialization.roots,
            &cumulative, receipt.token())?;
        if let Some(terminal) = crate::outcome_after_publish_async(store, cx, context, receipt.token(), &publication).await? {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded { limit: limits.max_cas_replans })
}

enum PreparationFailure {
    Projection(ProjectionFailure),
    Admission(Box<AdmissionError>),
}
impl From<ProjectionFailure> for PreparationFailure {
    fn from(value: ProjectionFailure) -> Self { Self::Projection(value) }
}
impl From<AdmissionError> for PreparationFailure {
    fn from(value: AdmissionError) -> Self { Self::Admission(Box::new(value)) }
}
fn unavailable(code: RefusalCode) -> AdmissionError { AdmissionError::AsyncProjectionUnavailable(code) }
fn incoherent(field: &'static str) -> AdmissionError { AdmissionError::MergeIncoherent { field } }
