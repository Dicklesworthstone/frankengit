//! Explicit, request-owned authority to create an absent scoped task branch.

use super::{AgentRequest, SourcePublicationProof};
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_authority::IdempotencyKey;
use fgit_types::{GitOid, RefName};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::Instant;

/// A borrowed, independently granted task-branch operation. Neither source
/// publication nor candidate authority can construct this proof, and public
/// principal provenance cannot substitute for the live authenticated request.
pub struct SourceBranchCreationRequest<'a>(&'a AgentRequest);

impl AgentRequest {
    pub fn source_branch_creation(
        &self,
        node: &OneNode,
    ) -> Result<SourceBranchCreationRequest<'_>, NodeReceiveTransportRefusal> {
        self.check_operation(node, fgit_identity::agent::SOURCE_BRANCH_CREATE)?;
        Ok(SourceBranchCreationRequest(self))
    }
}

impl SourceBranchCreationRequest<'_> {
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
                return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: budget_exhaustion });
            }
        }
        self.0.check(0, 0).map_err(|error| {
            NodeWorkspaceRefusal::WorkspacePublication(Box::new(error))
        })
    }

    pub(crate) fn check_input(&self, input_bytes: usize) -> Result<(), NodeWorkspaceRefusal> {
        let input_bytes = u64::try_from(input_bytes)
            .map_err(|_| NodeWorkspaceRefusal::WorkspaceCapacity)?;
        self.0.check(input_bytes, 0).map_err(|error| {
            NodeWorkspaceRefusal::WorkspacePublication(Box::new(error))
        })
    }

    pub(crate) fn key(&self) -> &IdempotencyKey {
        &self.0.key
    }

    pub(crate) fn session(&self) -> LoopbackReceiveSession {
        self.0.authenticated_session()
    }

    pub(crate) fn bind_branch(&self, reference: &RefName, target: GitOid) -> SourcePublicationProof {
        SourcePublicationProof::branch_creation(
            reference.clone(), target, self.0.authentication, self.0.deadline(),
        )
    }

    /// Expiry cancels and drains the actual original authority operation. An
    /// already submitted CAS keeps its real result; no detached future or fresh
    /// context converts a timeout into evidence that nothing committed.
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
}
