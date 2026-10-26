//! Native retrieval and hydration for an already authenticated, read-scoped run.
//! No run is minted here and a ContextPacket is never a publication capability.

use super::{AgentContextRefusal, context_packet_for_run, match_run_source, run_receipt};
use crate::source_retrieval::authorization::SourceReadContext;
use crate::source_retrieval::context::{ContextLimits, InitialContext};
use crate::source_retrieval::{Checkpoints, InitialLimits, InitialQuery, RetrievalError, live};
use crate::{NodeRequestContext, OneNode};
use fgit_agent::{ContextControl, ContextPacket, IntentRun, LogicalTime};
use fgit_types::RefName;

/// Explicit inputs to one native agent-context read. The host must supply BOTH
/// its current source-read authorization and the previously authenticated run.
/// A run ID, a search report, or repository text cannot substitute for either.
///
/// Limits bound this invocation, not the cumulative run. The embedding retains
/// responsibility for sponsorship, revocation and whole-run budget reservation.
/// The host also supplies the monotone clock in the run's logical-time domain.
pub struct AgentContextRead<'a> {
    pub run: &'a IntentRun,
    pub authorization: &'a SourceReadContext,
    pub reference: &'a RefName,
    pub query: &'a InitialQuery,
    pub checkpoints: &'a Checkpoints,
    pub retrieval_limits: InitialLimits,
    pub context_limits: ContextLimits,
    pub control: ContextControl,
}

/// Keep exact native paths, spans, authorization lineage, generation positions
/// and omissions next to the Agent Protocol packet. Packet sources are not a
/// replacement for that retrieval evidence and do not claim complete coverage.
#[derive(Clone, Debug)]
pub struct AgentSourceContext {
    context: InitialContext,
    packet: ContextPacket,
}
impl AgentSourceContext {
    #[must_use]
    pub const fn context(&self) -> &InitialContext {
        &self.context
    }

    #[must_use]
    pub const fn packet(&self) -> &ContextPacket {
        &self.packet
    }

    #[must_use]
    pub fn into_parts(self) -> (InitialContext, ContextPacket) {
        (self.context, self.packet)
    }
}

#[derive(Debug)]
pub enum AgentContextReadError {
    Binding(AgentContextRefusal),
    Retrieval(RetrievalError),
    /// Expiry is half-open: a read at the expiry instant is not admitted.
    RunExpired,
    /// Time predates the receipt or an earlier observation in this invocation.
    ClockRegressed,
}
impl core::fmt::Display for AgentContextReadError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "native agent context read refused: {self:?}")
    }
}
impl core::error::Error for AgentContextReadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::Retrieval(error) => Some(error),
            Self::RunExpired | Self::ClockRegressed => None,
        }
    }
}
impl From<AgentContextRefusal> for AgentContextReadError {
    fn from(error: AgentContextRefusal) -> Self {
        Self::Binding(error)
    }
}
impl From<RetrievalError> for AgentContextReadError {
    fn from(error: RetrievalError) -> Self {
        Self::Retrieval(error)
    }
}

struct ReadClock<'a, C: ?Sized> {
    run: &'a IntentRun,
    now: &'a C,
    floor: LogicalTime,
}
impl<C: Fn() -> LogicalTime + ?Sized> ReadClock<'_, C> {
    fn check(&mut self, request: &NodeRequestContext) -> Result<(), AgentContextReadError> {
        live(request)?;
        let now = (self.now)();
        live(request)?;
        if now.value() < self.floor.value() {
            return Err(AgentContextReadError::ClockRegressed);
        }
        if !self.run.is_open_at(now) {
            return Err(AgentContextReadError::RunExpired);
        }
        self.floor = now;
        Ok(())
    }
}

impl OneNode {
    /// Read indexed source, hydrate exact bytes and build the existing Agent
    /// Protocol ContextPacket under the run's ORIGINAL authenticated head.
    ///
    /// The native readers own current disclosure, index checkpoints, object
    /// membership and finite work/byte limits. This method never refreshes the
    /// run, builds an index, retries a changed source, executes source text or
    /// publishes anything. Any phase failure discards the whole result.
    ///
    /// `now` is a trusted host clock in the same domain as run expiry and the
    /// receipt's verification time. It is checked before/after every phase;
    /// backwards time and late expiry cannot release a packet. Interruption
    /// WITHIN a native phase remains owned by `request`, whose cancellation and
    /// finite deadline the host must arrange for the run's lifetime.
    pub async fn retrieve_agent_context_local_in<C>(
        &self,
        request: &NodeRequestContext,
        input: AgentContextRead<'_>,
        now: &C,
    ) -> Result<AgentSourceContext, AgentContextReadError>
    where
        C: Fn() -> LogicalTime + ?Sized,
    {
        live(request)?;
        input.authorization.check_node(self)?;
        let receipt = run_receipt(input.run, &input.control)?;
        if receipt.repository_id() != self.repository_id {
            return Err(AgentContextRefusal::NodeRepositoryMismatch.into());
        }
        if receipt.latest_repository_commit_id().is_none() {
            return Err(AgentContextRefusal::RepositoryCommitMissing.into());
        }
        // Check both phases' input bounds before starting either phase.
        input.retrieval_limits.validate(input.query)?;
        input.context_limits.validate()?;
        let mut clock = ReadClock {
            run: input.run,
            now,
            floor: receipt.verified_at_logical_time(),
        };
        clock.check(request)?;
        let initial = self
            .search_source_initial_local_in(
                request,
                input.authorization,
                input.reference,
                Some(receipt.authority_head_id()),
                None,
                input.checkpoints,
                input.query,
                input.retrieval_limits,
            )
            .await?;
        clock.check(request)?;
        // Do not hydrate a report for another RCR or forge position even if a
        // future retrieval implementation were to return an inconsistent join.
        match_run_source(receipt, &initial)?;
        let context = self
            .hydrate_source_initial_local_in(
                request,
                input.authorization,
                initial,
                input.context_limits,
            )
            .await?;
        clock.check(request)?;
        let packet = context_packet_for_run(input.run, &context, input.control)?;
        clock.check(request)?;
        Ok(AgentSourceContext { context, packet })
    }
}
