//! Forge reads need a head and disclosure policy, not source/outbox projections.
//! All immutable coordinates below descend from ONE authenticated head read.

use super::{ForgeEventReadRefusal, workspace_request_live};
use crate::{NodeRequestContext, OneNode};
use fgit_authority::{
    AsyncAuthorityStore, HeadKey, HeadRead, OutcomeFailure, authority_head_identity,
    read_hidden_ref_policy_async, read_repository_incarnation_configuration_async,
};
use fgit_chronicle::PublicationBasis;
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{
    GitHashAlgorithm, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId,
};
use fgit_wire::{WireLimits, visibility::RefVisibility};

pub(in crate::treefs_workspace) struct EventReadBasis {
    pub(in crate::treefs_workspace) basis: PublicationBasis,
    pub(in crate::treefs_workspace) hidden_refs: RefVisibility,
}

#[derive(Clone, Copy)]
struct Binding {
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    format: GitHashAlgorithm,
}

impl OneNode {
    pub(in crate::treefs_workspace) async fn event_read_basis_in(
        &self,
        request: &NodeRequestContext,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<EventReadBasis, ForgeEventReadRefusal> {
        let cancelled = || !workspace_request_live(request);
        checkpoint(&cancelled)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(ForgeEventReadRefusal::Cell)?;
        read_basis(
            &self.authority,
            request.authority(),
            &self.head_key,
            Binding {
                repository: self.repository_id,
                incarnation: self.repository_incarnation_id(),
                format: self.object_format,
            },
            expected_head,
            &cancelled,
        )
        .await
    }
}

fn boundary(error: impl Into<OutcomeFailure>) -> ForgeEventReadRefusal {
    ForgeEventReadRefusal::Boundary(Box::new(error.into()))
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), ForgeEventReadRefusal> {
    if cancelled() {
        Err(ForgeEventReadRefusal::Cancelled)
    } else {
        Ok(())
    }
}

/// The storage boundary is generic only to run its exact I/O through the
/// reference fault store. Production supplies the existing native Cx/store;
/// no request can supply a head body, configuration, visibility rule or binding.
async fn read_basis<S, C>(
    store: &S,
    cx: &S::Context,
    key: &HeadKey,
    binding: Binding,
    expected_head: Option<RepositoryAuthorityHeadId>,
    cancelled: &C,
) -> Result<EventReadBasis, ForgeEventReadRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let read = store.read_head(cx, key).await.map_err(boundary)?;
    checkpoint(cancelled)?;
    let HeadRead::Present(receipt) = read else {
        return Err(boundary(OutcomeFailure::StreamBodyMissing {
            link: "authority head",
        }));
    };
    let authenticated = store
        .authenticate_head_receipt(cx, &receipt)
        .await
        .map_err(boundary)?;
    checkpoint(cancelled)?;
    if receipt.key() != key
        || authenticated.receipt() != &receipt
        || authenticated.verified_against() != store.instance_id()
    {
        return Err(ForgeEventReadRefusal::RepositoryBindingMismatch);
    }
    let body = authenticated.body().map_err(boundary)?;
    if body.repository_id != binding.repository {
        return Err(ForgeEventReadRefusal::RepositoryBindingMismatch);
    }
    let id = authority_head_identity(&body).map_err(boundary)?;
    if expected_head.is_some_and(|expected| expected != id) {
        return Err(ForgeEventReadRefusal::SnapshotMoved);
    }
    let configuration =
        read_repository_incarnation_configuration_async(store, cx, &body.configuration_root)
            .await
            .map_err(boundary)?;
    checkpoint(cancelled)?;
    if configuration.repository_incarnation_id != binding.incarnation
        || configuration.object_format != binding.format
    {
        return Err(ForgeEventReadRefusal::RepositoryBindingMismatch);
    }
    let mut hidden_refs = RefVisibility::new();
    if let Some(root) = configuration.policy_root {
        // Missing or corrupt policy is not an empty policy. Bind its decoded
        // bytes to the selected root before any rule can affect disclosure.
        let policy = read_hidden_ref_policy_async(store, cx, &root)
            .await
            .map_err(boundary)?;
        checkpoint(cancelled)?;
        let identity = fgit_authority::canonical_body_id(
            fgit_crypto::IdentityDomain::HiddenRefPolicy,
            fgit_types::CANONICAL_CODEC_VERSION,
            &policy,
        )
        .map_err(boundary)?;
        if identity.algorithm() != root.algorithm() || identity.digest() != root.bytes() {
            return Err(ForgeEventReadRefusal::InvalidPage);
        }
        for rule in &policy.rules {
            checkpoint(cancelled)?;
            hidden_refs
                .push_rule(rule, &WireLimits::default())
                .map_err(|_| ForgeEventReadRefusal::InvalidPage)?;
        }
    }
    checkpoint(cancelled)?;
    Ok(EventReadBasis {
        basis: PublicationBasis::new(id, body),
        hidden_refs,
    })
}

#[cfg(test)]
mod tests;
