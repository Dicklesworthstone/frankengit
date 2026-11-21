//! Borrowed authority for the closed, scoped native source publisher.
//! A credential receipt or candidate proof cannot construct this boundary.

use super::{AgentRequest, epoch_seconds};
use crate::{NodeReceiveTransportRefusal, NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_admission::evidence::{AdmissionAuthentication, AgentAuthentication};
use fgit_admission::merge::native::protection::path_reviews::VerifiedSourcePaths;
use fgit_authority::IdempotencyKey;
use fgit_types::{PrincipalId, RefName, RefusalCode};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::Instant;

/// One live sponsored request's authority to apply a single-parent candidate.
/// Identity, retry key, repository and deadline come from authentication, never
/// from publication arguments. Current canonical ref/path scope is checked by
/// ordinary admission at every exact publication basis.
pub struct SourcePublicationRequest<'a>(&'a AgentRequest);

impl AgentRequest {
    pub fn source_publication(
        &self,
        node: &OneNode,
    ) -> Result<SourcePublicationRequest<'_>, NodeReceiveTransportRefusal> {
        self.check_operation(node, fgit_identity::agent::SOURCE_PUBLISH)?;
        Ok(SourcePublicationRequest(self))
    }
}

impl SourcePublicationRequest<'_> {
    /// Await and drain the same operation when its request expires. The timer
    /// wakes even while authority I/O is pending; cancelling this exact context
    /// propagates into that I/O without refreshing its poll/cost ledger. An
    /// already submitted CAS keeps its real result, including uncertainty.
    pub(crate) async fn drive_in<F: Future>(
        &self,
        node: &OneNode,
        context: &NodeRequestContext,
        operation: F,
    ) -> F::Output {
        let remaining = self.0.deadline().saturating_duration_since(Instant::now());
        let mut timer = pin!(asupersync::time::sleep(node.runtime().now(), remaining));
        let mut operation = pin!(operation);
        let mut stopped = false;
        poll_fn(|task| {
            if !stopped && (self.0.check(0, 0).is_err() || timer.as_mut().poll(task).is_ready()) {
                context.cancel();
                stopped = true;
            }
            operation.as_mut().poll(task)
        })
        .await
    }

    /// Keep the adapter's actual context, including already consumed polls and
    /// cancellation. A fresh sibling context would renew those resource bounds.
    pub(crate) fn check_context(
        &self,
        node: &OneNode,
        context: &NodeRequestContext,
    ) -> Result<(), NodeWorkspaceRefusal> {
        if !self.0.matches_namespace(node) {
            return Err(NodeWorkspaceRefusal::RepositoryMismatch);
        }
        match crate::checkpoint_pack_context(context.authority()) {
            crate::PackContextCheckpoint::Live => {}
            crate::PackContextCheckpoint::Stopped { budget_exhaustion } => {
                return Err(NodeWorkspaceRefusal::Cancelled {
                    exhaustion: budget_exhaustion,
                });
            }
        }
        self.0
            .check(0, 0)
            .map_err(|error| NodeWorkspaceRefusal::WorkspacePublication(Box::new(error)))
    }

    pub(crate) fn check_input(&self, input_bytes: usize) -> Result<(), NodeWorkspaceRefusal> {
        let input_bytes =
            u64::try_from(input_bytes).map_err(|_| NodeWorkspaceRefusal::WorkspaceCapacity)?;
        self.0
            .check(input_bytes, 0)
            .map_err(|error| NodeWorkspaceRefusal::WorkspacePublication(Box::new(error)))
    }

    pub(crate) fn principal(&self) -> PrincipalId {
        self.0.authentication.agent()
    }

    pub(crate) fn key(&self) -> &IdempotencyKey {
        &self.0.key
    }

    pub(crate) fn authentication(&self) -> AdmissionAuthentication {
        AdmissionAuthentication::AgentCredential(self.0.authentication)
    }

    pub(crate) fn bind_paths(
        &self,
        reference: &RefName,
        paths: VerifiedSourcePaths,
    ) -> SourcePublicationProof {
        SourcePublicationProof {
            reference: reference.clone(),
            paths,
            authentication: self.0.authentication,
            deadline: self.0.deadline(),
        }
    }
}

/// Native object evidence and the request witness which selected its sole
/// publication exception. Only the borrowed request above can bind this proof.
#[derive(Debug)]
pub(crate) struct SourcePublicationProof {
    reference: RefName,
    paths: VerifiedSourcePaths,
    authentication: AgentAuthentication,
    deadline: Instant,
}

impl SourcePublicationProof {
    pub(crate) fn reference(&self) -> &RefName {
        &self.reference
    }

    pub(crate) fn paths(&self) -> &VerifiedSourcePaths {
        &self.paths
    }

    pub(crate) fn authentication(&self) -> AgentAuthentication {
        self.authentication
    }

    /// Called before staging and again before publication begins. The owner
    /// additionally cancels and drains the original context at this deadline,
    /// including while publication's authority operations are awaiting I/O.
    pub(crate) fn checkpoint(&self) -> Result<u64, RefusalCode> {
        let now = epoch_seconds().ok_or(RefusalCode::CapabilityExpired)?;
        if Instant::now() >= self.deadline
            || now < self.authentication.authenticated_at()
            || now >= self.authentication.expires_at()
        {
            return Err(RefusalCode::CapabilityExpired);
        }
        Ok(now)
    }
}
