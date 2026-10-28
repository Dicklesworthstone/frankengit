#![forbid(unsafe_code)]
//! Read-only FG-038b over the node's authenticated canonical history.
//! This API is for a whole-repository trusted local operator. It authenticates
//! stored history, NOT a caller principal. Remote servers must not expose it as
//! a substitute for current disclosure authorization. No result grants access.
use crate::{NodeRequestContext, OneNode};
use fgit_authority::ImmutableRead;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_forge::bisection::{
    BisectionRange, BisectionReceipt, BisectionTermination, MonotonicityShape, ProbeObservation,
    TransitionDirection, search_published_positions,
};
use fgit_forge::event::issue::IssueState;
use fgit_forge::{IssueNumber, PullRequestNumber};
use fgit_types::{
    DecisionSequence, GitHashAlgorithm, GitOid, PolicyEpoch, RefName, RepositoryAuthorityHeadId,
    RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fmt;

mod fold;
mod receipt;
pub use receipt::head_token;

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
    fn validate(&self, format: GitHashAlgorithm) -> Result<(), Error> {
        if self.max_probes == 0 || self.max_probes > MAX_PROBES {
            return Err(Error::new("probe_limit", "max_probes must be in 1..=4096"));
        }
        if self.end.is_some_and(|end| end < self.start) {
            return Err(Error::new("invalid_range", "start exceeds end"));
        }
        if let Predicate::RefEquals { target, .. } = self.predicate {
            if target.algorithm() != format || target.is_zero() {
                return Err(Error::new(
                    "object_format",
                    "the target must be a nonzero native object ID in this repository's hash domain",
                ));
            }
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
    fn new(code: &'static str, detail: impl fmt::Display) -> Self {
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
    pub fn matched(&self) -> bool {
        self.complete() && self.search.transition_found.is_some()
    }
    #[must_use]
    pub fn to_json(&self) -> String {
        receipt::render(self)
    }
}

fn checkpoint(request: &NodeRequestContext) -> Result<(), Error> {
    request
        .authority()
        .checkpoint()
        .map_err(|error| Error::new("request_stopped", error))
}

impl OneNode {
    /// Search exact published states at one authenticated head. The underlying
    /// history reader retains its 65,536-edge bound and caller's finite runtime
    /// budget; this profile additionally admits at most 4,096 decision batches
    /// and 65,536 events after loading. It does not advertise streaming history
    /// memory bounds. Missing/pruned history refuses; no partial-history fallback.
    /// All state folding is linear. Only policy-threshold *search probes* are
    /// logarithmic, after verifying nondecreasing epochs across the whole history.
    pub async fn bisect_forge_trusted_local_in(
        &self,
        request: &NodeRequestContext,
        query: &Query,
    ) -> Result<Report, Error> {
        query.validate(self.object_format)?;
        checkpoint(request)?;
        let anchor = self
            .authenticate_authority_head_in(request)
            .await
            .map_err(|error| Error::new("authority_read", error))?;
        let body = anchor
            .body()
            .map_err(|error| Error::new("authority_body", error))?;
        let source_head =
            crate::authority_head_id(&body).map_err(|error| Error::new("authority_body", error))?;
        if query
            .expected_head
            .is_some_and(|expected| expected != source_head)
        {
            return Err(Error::new(
                "snapshot_changed",
                "expected head is not current",
            ));
        }
        let latest = body.latest_decision_sequence.ok_or_else(|| {
            Error::new("missing_position", "repository has no published decision")
        })?;
        let end = query.end.unwrap_or(latest);
        if end > latest {
            return Err(Error::new(
                "missing_position",
                "range extends past the current decision",
            ));
        }
        let range = BisectionRange::new(query.start, end)
            .map_err(|error| Error::new("invalid_range", error))?;
        let history = self
            .snapshot_history_in(request)
            .await
            .map_err(|error| Error::new("history_unavailable", error))?;
        checkpoint(request)?;
        if history.is_empty() || history.len() > MAX_POSITIONS {
            return Err(Error::new(
                "history_limit",
                "this profile requires 1..=4096 complete historical decision batches",
            ));
        }
        // Obtain the first published ref value from its actual immutable head,
        // not an assumed empty genesis or a fabricated clone of the current head.
        let initial_ref = match &query.predicate {
            Predicate::RefEquals { name, .. } | Predicate::RefAbsent { name } => {
                let first = &history[0];
                let key = fgit_authority::body_key_for_id(
                    first.resulting_head_id.as_internal_object_id(),
                )
                .map_err(|error| Error::new("history_unavailable", error))?;
                let ImmutableRead::Present(frame) = self
                    .authority
                    .read_immutable(request.authority(), &key)
                    .await
                    .map_err(|error| Error::new("history_unavailable", error))?
                else {
                    return Err(Error::new(
                        "history_unavailable",
                        "first published head body is absent",
                    ));
                };
                let first_head = fgit_codec::decode_body::<RepositoryAuthorityHeadBody>(
                    &frame,
                    fgit_codec::DecodeLimits::DEFAULT,
                )
                .map_err(|error| Error::new("history_unavailable", error))?;
                if crate::authority_head_id(&first_head)
                    .map_err(|error| Error::new("history_unavailable", error))?
                    != first.resulting_head_id
                    || first_head.repository_id != self.repository_id
                {
                    return Err(Error::new(
                        "corrupt_history",
                        "first published head identity disagrees",
                    ));
                }
                crate::read_historical_ref_state_in(
                    &self.authority,
                    request.authority(),
                    self.repository_id,
                    &first_head,
                )
                .await
                .map_err(|error| Error::new("history_unavailable", error))?
                .refs()
                .get(name)
                .copied()
            }
            _ => None,
        };
        let (points, events) =
            fold::points(&history, &body, query, range, initial_ref, &mut || {
                checkpoint(request)
            })?;
        let positions: Vec<_> = points.iter().map(|point| point.sequence).collect();
        if positions.first() != Some(&range.start()) || positions.last() != Some(&range.end()) {
            return Err(Error::new(
                "unpublished_position",
                "range endpoints must be actual publication-batch ends, not an interior decision",
            ));
        }
        let shape = if matches!(query.predicate, Predicate::PolicyAtLeast(_)) {
            MonotonicityShape::GuaranteedMonotone {
                expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
            }
        } else {
            MonotonicityShape::LinearOnly {
                max_steps: query.max_probes,
            }
        };
        let mut inspected = 0;
        let search = search_published_positions(
            self.repository_id,
            range,
            shape,
            &positions,
            |sequence| {
                if inspected == query.max_probes {
                    return Err(fgit_forge::bisection::BisectionRefusal::BudgetExhausted {
                        steps_taken: inspected,
                        max_budget: query.max_probes,
                    });
                }
                inspected += 1;
                let point = &points[positions
                    .binary_search(&sequence)
                    .expect("search selects supplied publication")];
                Ok(ProbeObservation {
                    outcome: Ok(point.evaluate(&query.predicate)),
                    head_id: point.head,
                    policy_epoch: point.epoch,
                    replayed_batches: point.replayed,
                })
            },
            &mut || checkpoint(request).is_ok(),
        );
        checkpoint(request)?;
        let report = Report {
            tenant: self.tenant_id,
            repository: self.repository_id,
            incarnation: self.repository_incarnation_id(),
            format: self.object_format,
            source_head,
            source_generation: body.generation.get(),
            current_policy_epoch: body.policy_epoch,
            query: query.clone(),
            history_batches: history.len(),
            history_events: events,
            published_positions: positions.len(),
            positions_digest: receipt::positions_digest(&points),
            search,
        };
        self.revalidate_bisection_in(request, source_head).await?;
        Ok(report)
    }

    async fn revalidate_bisection_in(
        &self,
        request: &NodeRequestContext,
        source_head: RepositoryAuthorityHeadId,
    ) -> Result<(), Error> {
        checkpoint(request)?;
        let current = self
            .authenticate_authority_head_in(request)
            .await
            .map_err(|error| Error::new("authority_read", error))?;
        let current = current
            .body()
            .map_err(|error| Error::new("authority_body", error))?;
        if crate::authority_head_id(&current)
            .map_err(|error| Error::new("authority_body", error))?
            != source_head
        {
            return Err(Error::new(
                "snapshot_changed",
                "authority moved during historical search; no result is current",
            ));
        }
        checkpoint(request)
    }
}

#[cfg(test)]
mod tests;
