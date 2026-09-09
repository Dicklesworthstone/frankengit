//! Explicit workspace snapshot preconditions for native merge admission.
//!
//! The original request fields remain intact. Only callers of this additive
//! profile bind a snapshot digest; their projection must hold the real session
//! owner throughout the shared driver's preparation and publication.

use fgit_authority::{
    AsyncAuthorityStore, ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome,
};
use fgit_types::AsciiSlug;

use super::{NativeMergeIntent, NativeMergeProjection, admit_merge_attempt_async};
use crate::merge::SealedMerge;
use crate::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion};
use fgit_forge::event::ForgeEventPayload;

/// Add an exact workspace snapshot precondition to the original sealed-package
/// request. Ref intent, event, epoch and every other original field retain their
/// meaning and bytes. This explicit profile has a distinct logical identity.
pub fn workspace_seal_attempt_for(
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    digest: [u8; 32],
) -> Result<SealAttempt, AdmissionError> {
    bind_snapshot(crate::merge::seal_attempt_for(context, sealed)?, digest)
}

pub(super) fn bind_snapshot(
    mut attempt: SealAttempt,
    digest: [u8; 32],
) -> Result<SealAttempt, AdmissionError> {
    let request = &attempt.request;
    let mut entries = request.scoped_entries().to_vec();
    entries.push(ScopedEntry::new(
        AsciiSlug::from_static("treefs"),
        AsciiSlug::from_static("merge.workspace-snapshot-digest"),
        digest,
    )?);
    attempt.request = SemanticRequest::build(
        request.request_schema(),
        request.object_format(),
        request.atomic(),
        request.ref_commands().to_vec(),
        request.push_options().to_vec(),
        entries,
    )?;
    Ok(attempt)
}

/// Admit the original native package with an additional exact snapshot
/// precondition. Terminal retries resolve before observing current workspace
/// state. Fresh work requires the projection's live owner to match the digest.
pub async fn admit_workspace_sealed_native_merge_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    digest: [u8; 32],
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    let attempt = workspace_seal_attempt_for(context, sealed, digest)?;
    let ForgeEventPayload::MergeCommittedNative(merge) = &sealed.package.event.payload else {
        return Err(super::incoherent("native event kind"));
    };
    let fgit_forge::AggregateId::PullRequest(number) = sealed.package.event.aggregate else {
        return Err(super::incoherent("event aggregate"));
    };
    if merge.merge_commit.algorithm() != context.object_format {
        return Err(AdmissionError::ObjectFormatMismatch);
    }
    let predecessor = sealed.package.event.version.get() - 1;
    let expected = match AggregateVersion::try_new(predecessor) {
        Some(version) => ExpectedVersion::Exactly(version),
        None => ExpectedVersion::NewStream,
    };
    let intent = NativeMergeIntent::new(number, expected, merge.clone())?
        .with_workspace_snapshot(digest);
    if intent.event() != &sealed.package.event {
        return Err(super::incoherent("native event adaptation"));
    }
    admit_merge_attempt_async(
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
