#![forbid(unsafe_code)]
//! Trusted-local integrity of the complete authority-selected native graph.
//! This is not a remote disclosure or retention API. The embedding application
//! must authorize whole-repository inspection, including hidden and historical
//! objects, before calling it.

pub mod bundle_verify;
pub mod scrub;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, Instant};

use crate::{
    AdmissionMaterializationRefusal, NodeRefusal, NodeRequestContext, OneNode,
    PackContextCheckpoint, checkpoint_pack_context,
};
use fgit_object_fabric::local::LocalBlobStream;
use fgit_object_fabric::{ObjectKind as FabricKind, StoreRefusal};
use fgit_runtime::Exhaustion;
use fgit_treefs::integrity::{BlobGraphError, ObjectGraphAudit, ObjectKind};
pub use fgit_treefs::integrity::{GraphLimits, GraphRefusal, GraphReport};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{
    Digest, GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId, RepositoryId,
    RepositoryIncarnationId,
};

/// Exact optional source fences and independent finite audit limits.
#[derive(Clone, Copy, Debug)]
pub struct GraphAuditQuery {
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_generation: Option<HeadGeneration>,
    pub limits: GraphLimits,
    /// Optional streaming-only blob allowance. None retains the smaller query
    /// and node metadata ceiling. An explicit allowance is also bounded by the
    /// node's selected-blob policy; metadata and total payload bounds still apply.
    pub max_blob_bytes: Option<u64>,
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
            max_blob_bytes: None,
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
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository
    }
    #[must_use]
    pub const fn repository_incarnation_id(&self) -> RepositoryIncarnationId {
        self.incarnation
    }
    #[must_use]
    pub const fn head(&self) -> RepositoryAuthorityHeadId {
        self.head
    }
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration {
        self.generation
    }
    #[must_use]
    pub const fn closure_root(&self) -> Digest {
        self.closure_root
    }
    #[must_use]
    pub const fn graph(&self) -> &GraphReport {
        &self.graph
    }
}

/// Native and original strong commitments of every authority-selected object,
/// followed by an exact authenticated head/token reread. This receipt does not
/// certify graph syntax, connectivity or future physical health.
#[derive(Clone, Debug)]
pub struct SelectedObjectIntegrityAudit {
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    head: RepositoryAuthorityHeadId,
    generation: HeadGeneration,
    closure_root: Digest,
    references: usize,
    objects: usize,
    payload_bytes: u64,
}
impl SelectedObjectIntegrityAudit {
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository
    }
    #[must_use]
    pub const fn repository_incarnation_id(&self) -> RepositoryIncarnationId {
        self.incarnation
    }
    #[must_use]
    pub const fn head(&self) -> RepositoryAuthorityHeadId {
        self.head
    }
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration {
        self.generation
    }
    #[must_use]
    pub const fn closure_root(&self) -> Digest {
        self.closure_root
    }
    #[must_use]
    pub const fn references(&self) -> usize {
        self.references
    }
    #[must_use]
    pub const fn objects(&self) -> usize {
        self.objects
    }
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
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

/// Keep the first precise request failure when a lower-level reader or graph
/// callback can return only a boolean. Both callbacks share this synchronous
/// scope; it never survives an await or creates another request budget.
struct AuditCheckpoints<'a> {
    request: &'a NodeRequestContext,
    started: Instant,
    timeout: Duration,
    refusal: RefCell<Option<GraphAuditRefusal>>,
}
impl<'a> AuditCheckpoints<'a> {
    const fn new(request: &'a NodeRequestContext, started: Instant, timeout: Duration) -> Self {
        Self {
            request,
            started,
            timeout,
            refusal: RefCell::new(None),
        }
    }

    fn live(&self) -> bool {
        if self.refusal.borrow().is_some() {
            return false;
        }
        match checkpoint(self.request, self.started, self.timeout) {
            Ok(()) => true,
            Err(error) => {
                *self.refusal.borrow_mut() = Some(error);
                false
            }
        }
    }

    fn check(&self) -> Result<(), GraphAuditRefusal> {
        self.live();
        match self.refusal.borrow_mut().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn read_audit_blob(
    stream: &mut LocalBlobStream,
    output: &mut [u8],
    checkpoints: &AuditCheckpoints<'_>,
) -> Result<usize, StoreRefusal> {
    loop {
        if !checkpoints.live() {
            return Err(StoreRefusal::RuntimeCheckpointRejected);
        }
        let read = stream.read_tentative(output);
        if !checkpoints.live() {
            return Err(StoreRefusal::RuntimeCheckpointRejected);
        }
        match read {
            Err(StoreRefusal::StorageIo {
                kind: std::io::ErrorKind::Interrupted,
                ..
            }) => {}
            result => return result,
        }
    }
}

fn object_refusal(
    oid: GitOid,
    cause: NodeRefusal,
    kind_limit: u64,
    kind_limit_name: &'static str,
) -> GraphAuditRefusal {
    if let NodeRefusal::Fabric(error) = &cause
        && let StoreRefusal::StreamingBudgetExceeded { offered, .. } = error.as_ref()
    {
        return GraphAuditRefusal::Graph(GraphRefusal::Limit(if *offered > kind_limit {
            kind_limit_name
        } else {
            "payload bytes"
        }));
    }
    GraphAuditRefusal::Object {
        oid,
        cause: Box::new(cause),
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
    /// Blobs stream through bounded chunks after kind and allowance checks on
    /// the same descriptor. The metadata fallback retains the smaller node and
    /// query allocation ceiling; its verified kind is checked again before any
    /// successful report. Both paths preflight the remaining total byte budget
    /// before reading a body.
    pub async fn audit_selected_object_graph_local_in(
        &self,
        request: &NodeRequestContext,
        query: GraphAuditQuery,
    ) -> Result<SelectedGraphAudit, GraphAuditRefusal> {
        let (integrity, graph) = self.audit_selected_local_in(request, query, true).await?;
        Ok(SelectedGraphAudit {
            repository: integrity.repository,
            incarnation: integrity.incarnation,
            head: integrity.head,
            generation: integrity.generation,
            closure_root: integrity.closure_root,
            graph: graph.ok_or(GraphAuditRefusal::Graph(GraphRefusal::Incomplete))?,
        })
    }

    /// Verify native identity, original strong commitment and exact stored
    /// framing for every authority-selected object, without graph parsing.
    ///
    /// Selection, source fences, bounded reads, cancellation and final head
    /// authentication are identical to the complete graph audit. Blob allowance
    /// never widens metadata policy, even though this mode streams metadata too.
    pub async fn audit_selected_object_integrity_local_in(
        &self,
        request: &NodeRequestContext,
        query: GraphAuditQuery,
    ) -> Result<SelectedObjectIntegrityAudit, GraphAuditRefusal> {
        let (integrity, _) = self.audit_selected_local_in(request, query, false).await?;
        Ok(integrity)
    }

    async fn audit_selected_local_in(
        &self,
        request: &NodeRequestContext,
        query: GraphAuditQuery,
        verify_graph: bool,
    ) -> Result<(SelectedObjectIntegrityAudit, Option<GraphReport>), GraphAuditRefusal> {
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
        if let Some(expected) = query.expected_generation
            && expected != generation
        {
            return Err(GraphAuditRefusal::ExpectedGeneration {
                expected: expected.get(),
                observed: generation.get(),
            });
        }
        if query.expected_head.is_some_and(|expected| expected != head) {
            return Err(GraphAuditRefusal::ExpectedHead);
        }
        let objects = selected.selected_closure().closure().objects();
        let references = &selected.snapshot().refs;
        let (payload_bytes, graph) = self.audit_selected_payloads(
            request,
            objects,
            references,
            query,
            started,
            verify_graph,
        )?;
        // One authenticated head read is sufficient: immutable roots cannot
        // change beneath the same exact head. Do not replay the whole history a
        // second time just to check whether the authority token moved.
        let current = self.authenticate_authority_head_in(request).await;
        checkpoint(request, started, query.timeout)?;
        let current = current.map_err(|error| GraphAuditRefusal::Authority(Box::new(error)))?;
        revalidate_head(selected.authenticated(), &current)?;
        Ok((
            SelectedObjectIntegrityAudit {
                repository: self.repository_id(),
                incarnation: self.repository_incarnation_id(),
                head,
                generation,
                closure_root: selected.selected_closure().root(),
                references: references.len(),
                objects: objects.len(),
                payload_bytes,
            },
            graph,
        ))
    }

    fn audit_selected_payloads(
        &self,
        request: &NodeRequestContext,
        objects: &BTreeSet<GitOid>,
        references: &BTreeMap<RefName, GitOid>,
        query: GraphAuditQuery,
        started: Instant,
        verify_graph: bool,
    ) -> Result<(u64, Option<GraphReport>), GraphAuditRefusal> {
        let checkpoints = AuditCheckpoints::new(request, started, query.timeout);
        checkpoints.check()?;
        if references.len() > query.limits.max_references {
            return Err(GraphAuditRefusal::Graph(GraphRefusal::Limit("references")));
        }
        if objects.len() > query.limits.max_objects {
            return Err(GraphAuditRefusal::Graph(GraphRefusal::Limit("objects")));
        }
        for &target in references.values() {
            checkpoints.check()?;
            if !objects.contains(&target) {
                return Err(GraphAuditRefusal::Graph(GraphRefusal::MissingTarget {
                    source: None,
                    target,
                }));
            }
        }
        let metadata_limit = u64::try_from(query.limits.max_object_bytes)
            .unwrap_or(u64::MAX)
            .min(self.max_object_bytes);
        let blob_limit = query.max_blob_bytes.map_or(metadata_limit, |maximum| {
            maximum.min(
                self.service_config
                    .selected_pack_blob_limit()
                    .map(|limit| u64::try_from(limit).unwrap_or(u64::MAX))
                    .unwrap_or(self.max_object_bytes),
            )
        });
        let blob_limit_name = if query.max_blob_bytes.is_some() {
            "blob bytes"
        } else {
            "object bytes"
        };
        let mut live = || checkpoints.live();
        let mut graph = if verify_graph {
            let graph = ObjectGraphAudit::new(objects, self.object_format, query.limits, &mut live);
            checkpoints.check()?;
            Some(graph.map_err(GraphAuditRefusal::Graph)?)
        } else {
            None
        };
        let mut payload_bytes = 0_u64;
        for &oid in objects {
            checkpoints.check()?;
            if oid.algorithm() != self.object_format || oid.is_zero() {
                return Err(GraphAuditRefusal::Graph(GraphRefusal::ObjectFormat(oid)));
            }
            let remaining = query
                .limits
                .max_payload_bytes
                .checked_sub(payload_bytes)
                .ok_or(GraphAuditRefusal::Graph(GraphRefusal::Limit(
                    "payload bytes",
                )))?;
            // Only the checked blob-only opener receives the wider allowance.
            // A separate kind/length peek would allow a replacement metadata
            // file to inherit that allowance. This descriptor checks kind before
            // reading any body; the metadata fallback has its own smaller cap.
            let opened = self.open_git_blob_stream(oid, blob_limit.min(remaining));
            checkpoints.check()?;
            let length = match opened {
                Ok(mut stream) => {
                    let length = stream.declared_length();
                    let observed = if let Some(graph) = graph.as_mut() {
                        let length = usize::try_from(length).map_err(|_| {
                            GraphAuditRefusal::Graph(GraphRefusal::Limit(blob_limit_name))
                        })?;
                        let mut reader =
                            |output: &mut [u8]| read_audit_blob(&mut stream, output, &checkpoints);
                        graph
                            .observe_blob_stream(
                                oid,
                                length,
                                usize::try_from(blob_limit).unwrap_or(usize::MAX),
                                &mut reader,
                                &mut live,
                            )
                            .map_err(|error| match error {
                                BlobGraphError::Graph(error) => GraphAuditRefusal::Graph(error),
                                BlobGraphError::Reader(error) => object_refusal(
                                    oid,
                                    NodeRefusal::from(error),
                                    blob_limit,
                                    blob_limit_name,
                                ),
                            })
                    } else {
                        let mut buffer = [0; 64 * 1024];
                        loop {
                            match read_audit_blob(&mut stream, &mut buffer, &checkpoints) {
                                Ok(0) => break Ok(()),
                                Ok(_) => {}
                                Err(error) => {
                                    break Err(object_refusal(
                                        oid,
                                        NodeRefusal::from(error),
                                        blob_limit,
                                        blob_limit_name,
                                    ));
                                }
                            }
                        }
                    };
                    // Preserve the original request failure even if another
                    // checkpoint or storage refusal follows it at exact EOF.
                    checkpoints.check()?;
                    observed?;
                    length
                }
                Err(NodeRefusal::Fabric(error))
                    if matches!(error.as_ref(), StoreRefusal::NativeObjectIdentityMismatch) =>
                {
                    if let Some(graph) = graph.as_mut() {
                        let read = self
                            .fabric
                            .read_whole_bounded(oid, metadata_limit.min(remaining));
                        checkpoints.check()?;
                        let object = read
                            .map_err(|error| {
                                object_refusal(
                                    oid,
                                    NodeRefusal::from(error),
                                    metadata_limit,
                                    "object bytes",
                                )
                            })?
                            .object;
                        let kind = match object.envelope().object_kind() {
                            FabricKind::Commit => ObjectKind::Commit,
                            FabricKind::Tree => ObjectKind::Tree,
                            FabricKind::Blob => ObjectKind::Blob,
                            FabricKind::Tag => ObjectKind::Tag,
                            FabricKind::Internal => {
                                return Err(GraphAuditRefusal::NonGitObject(oid));
                            }
                        };
                        let length = object.payload().len() as u64;
                        // A replacement between the two opens still cannot
                        // turn a narrower blob policy into successful evidence.
                        if kind == ObjectKind::Blob && length > blob_limit {
                            return Err(GraphAuditRefusal::Graph(GraphRefusal::Limit(
                                blob_limit_name,
                            )));
                        }
                        let observation = graph.observe(oid, kind, object.payload(), &mut live);
                        checkpoints.check()?;
                        observation.map_err(GraphAuditRefusal::Graph)?;
                        length
                    } else {
                        let verified = self.fabric.verify_object_integrity_bounded(
                            oid,
                            metadata_limit.min(remaining),
                            &mut live,
                        );
                        checkpoints.check()?;
                        let verified = verified.map_err(|error| {
                            object_refusal(
                                oid,
                                NodeRefusal::from(error),
                                metadata_limit,
                                "object bytes",
                            )
                        })?;
                        if verified.object_kind() == FabricKind::Blob
                            && verified.payload_length() > blob_limit
                        {
                            return Err(GraphAuditRefusal::Graph(GraphRefusal::Limit(
                                blob_limit_name,
                            )));
                        }
                        verified.payload_length()
                    }
                }
                Err(cause) => {
                    return Err(object_refusal(oid, cause, blob_limit, blob_limit_name));
                }
            };
            payload_bytes = payload_bytes
                .checked_add(length)
                .filter(|total| *total <= query.limits.max_payload_bytes)
                .ok_or(GraphAuditRefusal::Graph(GraphRefusal::Limit(
                    "payload bytes",
                )))?;
        }
        let report = match graph {
            Some(graph) => {
                let report = graph.finish(references, &mut live);
                checkpoints.check()?;
                Some(report.map_err(GraphAuditRefusal::Graph)?)
            }
            None => {
                checkpoints.check()?;
                None
            }
        };
        Ok((payload_bytes, report))
    }
}

#[cfg(test)]
mod tests;
