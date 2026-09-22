#![forbid(unsafe_code)]
//! Trusted-local integrity of the complete authority-selected native graph.
//! This is not a remote disclosure or retention API. The embedding application
//! must authorize whole-repository inspection, including hidden and historical
//! objects, before calling it.

use std::fmt;
use std::time::{Duration, Instant};

use crate::{
    AdmissionMaterializationRefusal, NodeRefusal, NodeRequestContext, OneNode,
    PackContextCheckpoint, checkpoint_pack_context,
};
use fgit_object_fabric::ObjectKind as FabricKind;
use fgit_runtime::Exhaustion;
pub use fgit_treefs::integrity::{GraphLimits, GraphRefusal, GraphReport};
use fgit_treefs::integrity::{ObjectGraphAudit, ObjectKind};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{
    Digest, GitOid, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId,
    RepositoryIncarnationId,
};

/// Exact optional source fences and independent finite audit limits.
#[derive(Clone, Copy, Debug)]
pub struct GraphAuditQuery {
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_generation: Option<HeadGeneration>,
    pub limits: GraphLimits,
    /// Cooperative whole-operation timeout; does not interrupt a blocking OS read.
    /// The inherited request/runtime limits may stop the operation earlier.
    pub timeout: Duration,
}
impl Default for GraphAuditQuery {
    fn default() -> Self {
        Self {
            expected_head: None,
            expected_generation: None,
            limits: GraphLimits::default(),
            timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
pub enum GraphAuditRefusal {
    InvalidTimeout,
    Cell(CellRefusal),
    Cancelled {
        exhaustion: Option<Exhaustion>,
    },
    Deadline,
    Materialization(Box<AdmissionMaterializationRefusal>),
    Authority(Box<NodeRefusal>),
    Object {
        oid: GitOid,
        cause: Box<NodeRefusal>,
    },
    NonGitObject(GitOid),
    ExpectedHead,
    ExpectedGeneration {
        expected: u64,
        observed: u64,
    },
    SnapshotChanged,
    Graph(GraphRefusal),
}
impl fmt::Display for GraphAuditRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => {
                out.write_str("graph audit timeout must be in (0, 3600 seconds]")
            }
            Self::Cell(error) => write!(out, "graph audit read refused: {error}"),
            Self::Cancelled { exhaustion } => {
                write!(out, "graph audit request stopped: {exhaustion:?}")
            }
            Self::Deadline => out.write_str("audit_deadline_exceeded"),
            Self::Materialization(error) => {
                write!(out, "authority materialization failed: {error}")
            }
            Self::Authority(error) => write!(out, "authority revalidation failed: {error}"),
            Self::Object { oid, cause } => write!(out, "object_read_failed: {oid}: {cause}"),
            Self::NonGitObject(id) => write!(out, "selected object has no native Git kind: {id}"),
            Self::ExpectedHead => {
                out.write_str("authority_head_mismatch: expected snapshot is not current")
            }
            Self::ExpectedGeneration { expected, observed } => write!(
                out,
                "authority_generation_mismatch: expected {expected}, observed {observed}"
            ),
            Self::SnapshotChanged => out.write_str("authority_snapshot_changed: restart the audit"),
            Self::Graph(error) => fmt::Display::fmt(error, out),
        }
    }
}
impl std::error::Error for GraphAuditRefusal {}

/// Constructed only after graph completion and an exact authenticated head/token
/// reread. This is an observation, not a lock against subsequent publication or
/// physical corruption. Node shutdown remains the lifecycle owner's obligation.
#[derive(Clone, Debug)]
pub struct SelectedGraphAudit {
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    head: RepositoryAuthorityHeadId,
    generation: HeadGeneration,
    closure_root: Digest,
    graph: GraphReport,
}
impl SelectedGraphAudit {
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository
    }
    pub const fn repository_incarnation_id(&self) -> RepositoryIncarnationId {
        self.incarnation
    }
    pub const fn head(&self) -> RepositoryAuthorityHeadId {
        self.head
    }
    pub const fn generation(&self) -> HeadGeneration {
        self.generation
    }
    pub const fn closure_root(&self) -> Digest {
        self.closure_root
    }
    pub const fn graph(&self) -> &GraphReport {
        &self.graph
    }
}

fn checkpoint(
    request: &NodeRequestContext,
    started: Instant,
    timeout: Duration,
) -> Result<(), GraphAuditRefusal> {
    if started.elapsed() >= timeout {
        return Err(GraphAuditRefusal::Deadline);
    }
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped { budget_exhaustion } => Err(GraphAuditRefusal::Cancelled {
            exhaustion: budget_exhaustion,
        }),
    }
}

fn revalidate_head(
    before: &fgit_authority::AuthenticatedHead,
    current: &fgit_authority::AuthenticatedHead,
) -> Result<(), GraphAuditRefusal> {
    if current.receipt().token() != before.receipt().token()
        || current.receipt().body() != before.receipt().body()
    {
        return Err(GraphAuditRefusal::SnapshotChanged);
    }
    Ok(())
}

impl OneNode {
    /// Verify every authority-selected native object and local graph edge,
    /// including admitted history unreachable from today's references.
    ///
    /// The same request owns materialization, object reads, graph work and the
    /// final head reread; no fresh budget or detached cancellation scope is
    /// minted after expensive work. No failed or partial report is returned.
    /// Physical residue is never enumerated, and a missing edge never triggers
    /// an out-of-selection storage read. Gitlinks remain foreign opaque data.
    /// Whole reads retain the node-configured per-object allocation ceiling;
    /// narrower query byte limits fence parsing after that bounded read.
    pub async fn audit_selected_object_graph_local_in(
        &self,
        request: &NodeRequestContext,
        query: GraphAuditQuery,
    ) -> Result<SelectedGraphAudit, GraphAuditRefusal> {
        if query.timeout.is_zero() || query.timeout > Duration::from_secs(3600) {
            return Err(GraphAuditRefusal::InvalidTimeout);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(GraphAuditRefusal::Cell)?;
        let started = Instant::now();
        checkpoint(request, started, query.timeout)?;
        let selected = self.materialize_admission_in(request).await;
        checkpoint(request, started, query.timeout)?;
        let selected =
            selected.map_err(|error| GraphAuditRefusal::Materialization(Box::new(error)))?;
        let head = selected.basis().id();
        let generation = selected.basis().generation();
        if let Some(expected) = query.expected_generation {
            if expected != generation {
                return Err(GraphAuditRefusal::ExpectedGeneration {
                    expected: expected.get(),
                    observed: generation.get(),
                });
            }
        }
        if query.expected_head.is_some_and(|expected| expected != head) {
            return Err(GraphAuditRefusal::ExpectedHead);
        }
        let objects = selected.selected_closure().closure().objects();
        let references = &selected.snapshot().refs;
        if references.len() > query.limits.max_references {
            return Err(GraphAuditRefusal::Graph(GraphRefusal::Limit("references")));
        }
        let mut live = || checkpoint(request, started, query.timeout).is_ok();
        let graph = ObjectGraphAudit::new(objects, self.object_format, query.limits, &mut live);
        checkpoint(request, started, query.timeout)?;
        let mut graph = graph.map_err(GraphAuditRefusal::Graph)?;
        for &oid in objects {
            checkpoint(request, started, query.timeout)?;
            let read = self.read_git_object(oid);
            // Preserve cancellation/deadline precedence even if the OS read
            // itself returned an error. Fabric owns envelope/strong commitment
            // validation, and the graph core independently rechecks native IDs.
            checkpoint(request, started, query.timeout)?;
            let object = read.map_err(|cause| GraphAuditRefusal::Object {
                oid,
                cause: Box::new(cause),
            })?;
            let kind = match object.envelope().object_kind() {
                FabricKind::Commit => ObjectKind::Commit,
                FabricKind::Tree => ObjectKind::Tree,
                FabricKind::Blob => ObjectKind::Blob,
                FabricKind::Tag => ObjectKind::Tag,
                FabricKind::Internal => return Err(GraphAuditRefusal::NonGitObject(oid)),
            };
            let observation = graph.observe(oid, kind, object.payload(), &mut live);
            checkpoint(request, started, query.timeout)?;
            observation.map_err(GraphAuditRefusal::Graph)?;
        }
        let graph = graph.finish(references, &mut live);
        checkpoint(request, started, query.timeout)?;
        let graph = graph.map_err(GraphAuditRefusal::Graph)?;
        // One authenticated head read is sufficient: immutable roots cannot
        // change beneath the same exact head. Do not replay the whole history a
        // second time just to check whether the authority token moved.
        let current = self.authenticate_authority_head_in(request).await;
        checkpoint(request, started, query.timeout)?;
        let current = current.map_err(|error| GraphAuditRefusal::Authority(Box::new(error)))?;
        revalidate_head(selected.authenticated(), &current)?;
        Ok(SelectedGraphAudit {
            repository: self.repository_id(),
            incarnation: self.repository_incarnation_id(),
            head,
            generation,
            closure_root: selected.selected_closure().root(),
            graph,
        })
    }
}

#[cfg(test)]
mod tests;
