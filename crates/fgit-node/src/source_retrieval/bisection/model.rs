//! Pure query and diagnostic values shared by the authenticated node reader and
//! the historical state fold. No value in this module grants disclosure rights.
use fgit_forge::bisection::{BisectionReceipt, BisectionTermination};
use fgit_forge::event::issue::IssueState;
use fgit_forge::event::workflow_check::{MAX_CHECK_JOB_BYTES, WorkflowCheckConclusion};
use fgit_forge::{IssueNumber, PullRequestNumber};
use fgit_types::{
    DecisionSequence, GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName,
    RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fmt;

pub const PROFILE: &str = "forge-state-bisect-local-v1";
pub const MAX_POSITIONS: usize = 4096;
pub const MAX_EVENTS: usize = 65_536;
pub const MAX_PROBES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullState {
    Open,
    Closed,
    Merged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Predicate {
    RefEquals {
        name: RefName,
        target: GitOid,
    },
    RefAbsent {
        name: RefName,
    },
    PolicyAtLeast(PolicyEpoch),
    IssueState {
        number: IssueNumber,
        state: IssueState,
    },
    PullRequestState {
        number: PullRequestNumber,
        state: PullState,
    },
    /// The latest canonical observation for all five exact selector coordinates,
    /// across runs and attempts. Absence never satisfies any conclusion.
    WorkflowCheck {
        source_ref: RefName,
        source_commit: GitOid,
        publisher: PrincipalId,
        graph_root: [u8; 32],
        job: String,
        conclusion: WorkflowCheckConclusion,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    pub start: DecisionSequence,
    /// None means the latest decision in the one authenticated observation.
    pub end: Option<DecisionSequence>,
    pub predicate: Predicate,
    pub max_probes: usize,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}
impl Query {
    #[must_use]
    pub const fn new(start: DecisionSequence, predicate: Predicate) -> Self {
        Self {
            start,
            end: None,
            predicate,
            max_probes: MAX_PROBES,
            expected_head: None,
        }
    }
    pub(super) fn validate(&self, format: GitHashAlgorithm) -> Result<(), Error> {
        if self.max_probes == 0 || self.max_probes > MAX_PROBES {
            return Err(Error::new("probe_limit", "max_probes must be in 1..=4096"));
        }
        if self.end.is_some_and(|end| end < self.start) {
            return Err(Error::new("invalid_range", "start exceeds end"));
        }
        let target = match &self.predicate {
            Predicate::RefEquals { target, .. } => Some(target),
            Predicate::WorkflowCheck { source_commit, .. } => Some(source_commit),
            _ => None,
        };
        if target.is_some_and(|target| target.algorithm() != format || target.is_zero()) {
            return Err(Error::new(
                "object_format",
                "the target must be a nonzero native object ID in this repository's hash domain",
            ));
        }
        if let Predicate::WorkflowCheck {
            source_ref, job, ..
        } = &self.predicate
            && (!source_ref.as_bytes().starts_with(b"refs/heads/")
                || job.is_empty()
                || job.len() > MAX_CHECK_JOB_BYTES
                || job.chars().any(char::is_control))
        {
            return Err(Error::new(
                "workflow_check_selector",
                "workflow checks require a branch ref and a nonempty job of at most 1024 bytes without control characters",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Error {
    pub code: &'static str,
    pub detail: String,
}
impl Error {
    pub(super) fn new(code: &'static str, detail: impl fmt::Display) -> Self {
        Self {
            code,
            detail: detail.to_string(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}: {}", self.code, self.detail)
    }
}
impl std::error::Error for Error {}

/// A revision-bound diagnostic, not a signature, attestation, mutation receipt,
/// retention pin or proof that authority cannot move after the final read.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Report {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub format: GitHashAlgorithm,
    pub source_head: RepositoryAuthorityHeadId,
    pub source_generation: u64,
    pub current_policy_epoch: PolicyEpoch,
    pub query: Query,
    pub history_batches: usize,
    pub history_events: usize,
    pub published_positions: usize,
    pub positions_digest: String,
    pub search: BisectionReceipt,
}
impl Report {
    #[must_use]
    pub const fn complete(&self) -> bool {
        !matches!(
            self.search.termination,
            BisectionTermination::Refused { .. }
        )
    }
    #[must_use]
    pub const fn matched(&self) -> bool {
        self.complete() && self.search.transition_found.is_some()
    }
    #[must_use]
    pub fn to_json(&self) -> String {
        super::receipt::render(self)
    }
}
