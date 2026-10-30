//! Whole-object streaming export from one authenticated, visible source graph.
//! Output remains private caller-owned staging until the caller closes the node
//! and completes its own publication protocol.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use fgit_pack::full_bundle::stream::{
    StreamFullBundleError, StreamFullBundleLimits, StreamFullBundleReceipt,
    write_full_bundle_stream, write_incremental_bundle_stream,
};
use fgit_pack::{BundleReference, PackError, PackWriteError};
use fgit_runtime::Exhaustion;
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use super::NodeWorkspaceRefusal;
use crate::{
    ClosureTraversalLimits, NodeRequestContext, OneNode, PackContextCheckpoint,
    PermittedClosureTraversalSource, UnpermittedRootPolicy, VerifiedFabricPackSource,
    checkpoint_pack_context, reachable_within_permitted_closure_bounded,
};

/// Limits and an optional exact source-head fence for one export. The timeout
/// covers selection and output; inherited request limits still apply.
#[derive(Clone, Debug)]
pub struct StreamBundleExportQuery {
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub limits: StreamFullBundleLimits,
    pub timeout: Duration,
}

impl Default for StreamBundleExportQuery {
    fn default() -> Self {
        let mut limits = StreamFullBundleLimits::default();
        limits.pack.max_entries = 100_000;
        limits.pack.max_input_bytes = 128 * 1024 * 1024;
        Self {
            expected_head: None,
            limits,
            timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
pub enum StreamBundleExportRefusal {
    InvalidTimeout,
    ExpectedHead,
    Deadline,
    Cancelled { exhaustion: Option<Exhaustion> },
    Source(Box<NodeWorkspaceRefusal>),
    Stream(StreamFullBundleError),
}

impl fmt::Display for StreamBundleExportRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => {
                out.write_str("bundle export timeout must be in (0, 3600 seconds]")
            }
            Self::ExpectedHead => out.write_str("bundle_export_source_head_mismatch"),
            Self::Deadline => out.write_str("bundle_export_deadline_exceeded"),
            Self::Cancelled { exhaustion } => {
                write!(out, "bundle export request stopped: {exhaustion:?}")
            }
            Self::Source(error) => write!(out, "bundle export source: {error}"),
            Self::Stream(error) => fmt::Display::fmt(error, out),
        }
    }
}
impl std::error::Error for StreamBundleExportRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error.as_ref()),
            Self::Stream(error) => Some(error),
            Self::InvalidTimeout | Self::ExpectedHead | Self::Deadline | Self::Cancelled { .. } => {
                None
            }
        }
    }
}
impl From<NodeWorkspaceRefusal> for StreamBundleExportRefusal {
    fn from(value: NodeWorkspaceRefusal) -> Self {
        Self::Source(Box::new(value))
    }
}

/// A complete native stream bound to the exact immutable authority snapshot
/// selected at the start. It does not claim that the snapshot is still current,
/// that a file is published, that the node is closed, or that forge state was
/// backed up. The only constructor is a completed export.
#[derive(Debug)]
pub struct SelectedStreamBundleExport {
    head: RepositoryAuthorityHeadId,
    generation: HeadGeneration,
    receipt: StreamFullBundleReceipt,
}
impl SelectedStreamBundleExport {
    #[must_use]
    pub const fn head(&self) -> RepositoryAuthorityHeadId {
        self.head
    }
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration {
        self.generation
    }
    #[must_use]
    pub const fn receipt(&self) -> &StreamFullBundleReceipt {
        &self.receipt
    }
}

#[derive(Clone, Copy)]
enum Stop {
    Deadline,
    Cancelled(Option<Exhaustion>),
}
impl Stop {
    const fn refusal(self) -> StreamBundleExportRefusal {
        match self {
            Self::Deadline => StreamBundleExportRefusal::Deadline,
            Self::Cancelled(exhaustion) => StreamBundleExportRefusal::Cancelled { exhaustion },
        }
    }
}

/// Consume each completed tick once. A replacement may already be ready when
/// first polled, so do not poll it here and discard that completion. Wake the
/// owner to register or consume the replacement on its next bounded poll.
pub(super) fn rearm_stop_tick<T: Future<Output = ()>>(
    mut tick: Pin<&mut T>,
    context: &mut Context<'_>,
    next: impl FnOnce() -> T,
) {
    if tick.as_mut().poll(context).is_ready() {
        tick.set(next());
        context.waker().wake_by_ref();
    }
}

/// Poll the same owned operation through cancellation and completion. The
/// timer also wakes this driver when the authority operation is pending and a
/// caller stop has no waker of its own. No task or authority work is detached.
pub(super) async fn drain_materialization<F: Future>(
    node: &OneNode,
    materialization: F,
    started: Instant,
    timeout: Duration,
    mut observe_stop: impl FnMut(),
) -> F::Output {
    const STOP_POLL_INTERVAL: Duration = Duration::from_millis(25);
    let next_tick = || {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            STOP_POLL_INTERVAL
        } else {
            remaining.min(STOP_POLL_INTERVAL)
        }
    };
    let mut materialization = pin!(materialization);
    let mut tick = pin!(asupersync::time::sleep(node.runtime().now(), next_tick()));
    poll_fn(|context| {
        observe_stop();
        if let Poll::Ready(result) = materialization.as_mut().poll(context) {
            return Poll::Ready(result);
        }
        rearm_stop_tick(tick.as_mut(), context, || {
            asupersync::time::sleep(node.runtime().now(), next_tick())
        });
        Poll::Pending
    })
    .await
}

/// Applies the selected-payload ceiling during graph discovery. The existing
/// traversal requests references once per unique object. A refused read can
/// allocate one body up to the source's per-object ceiling, but its bytes are
/// checked before parsing or allocating that object's reference metadata.
struct BoundedStreamSelectionSource<'source, 'fabric> {
    source: &'source VerifiedFabricPackSource<'fabric>,
    selected_bytes: Cell<usize>,
    maximum_bytes: usize,
}

impl PermittedClosureTraversalSource for BoundedStreamSelectionSource<'_, '_> {
    fn object_format(&self) -> GitHashAlgorithm {
        self.source.object_format
    }

    fn selection_checkpoint(&self) -> Result<(), PackWriteError> {
        self.source.session_checkpoint()
    }

    fn references(&self, id: &GitOid) -> Result<Vec<GitOid>, PackWriteError> {
        let (kind, body) = self.source.read_object(id)?;
        let selected_bytes = self.selected_bytes.get().checked_add(body.len()).ok_or(
            PackError::IntegerOverflow {
                context: "streamed bundle selection source bytes",
            },
        )?;
        if selected_bytes > self.maximum_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: selected_bytes,
                limit: self.maximum_bytes,
            }
            .into());
        }
        self.selected_bytes.set(selected_bytes);
        self.source.references_from_body(kind, &body)
    }
}

mod incremental;

#[derive(Clone, Copy)]
enum StreamProfile<'a> {
    Full,
    Incremental {
        references: &'a [RefName],
        prerequisites: &'a [GitOid],
    },
}

impl OneNode {
    /// Stream the exact closure of current visible direct refs from one
    /// authenticated authority snapshot. Caller visibility only narrows the
    /// canonical hidden-ref policy. Deleted-only or hidden-only history is not
    /// an export root, and the stream codec independently checks native typed
    /// edges, completeness and absence of unrelated objects before success.
    ///
    /// Selection keeps bounded identity/frontier metadata; output retains one
    /// bounded object and compressor state rather than a full `PackPlan` or
    /// bundle. The node's configured fabric read ceiling remains in force.
    /// Selection reads objects to discover edges, and streaming rereads them by
    /// immutable identity. Each phase independently enforces the same aggregate
    /// selected-payload ceiling; that limit does not count physical reads.
    ///
    /// `output` must be a private tentative sink. Errors may leave partial bytes
    /// in it. No file publication, flush, durability, cleanup or node shutdown
    /// is performed here; the lifetime owner must complete those obligations.
    pub async fn export_full_git_bundle_stream_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        query: StreamBundleExportQuery,
        output: &mut (impl Write + ?Sized),
    ) -> Result<SelectedStreamBundleExport, StreamBundleExportRefusal> {
        self.export_full_git_bundle_stream_controlled_in(
            request,
            visibility,
            query,
            output,
            &mut || true,
        )
        .await
    }

    /// The same source/stream contract with an additional caller-owned stop
    /// probe, for example termination signals. A refusal is sticky across
    /// source selection and output. Authority materialization is polled to
    /// completion after cancellation; its future is never dropped to stop work.
    /// The query deadline and inherited request budget cover both phases.
    pub async fn export_full_git_bundle_stream_controlled_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        query: StreamBundleExportQuery,
        output: &mut (impl Write + ?Sized),
        allow_work: &mut impl FnMut() -> bool,
    ) -> Result<SelectedStreamBundleExport, StreamBundleExportRefusal> {
        self.export_git_bundle_stream_profile_controlled_in(
            request,
            visibility,
            query,
            StreamProfile::Full,
            output,
            allow_work,
        )
        .await
    }

    /// Stream exactly the named visible references, omitting the complete typed
    /// closure of explicit currently visible commit prerequisites. The receiver
    /// must already possess that history. Omitted blob payloads are not read or
    /// certified healthy; emitted bytes still pass native and strong verification.
    ///
    /// The whole visible native-metadata proof and both reachability walks obey
    /// finite query object/index/edge bounds. Visible reference roots obey the
    /// reference ceiling too. Metadata discovery and emitted payloads each have
    /// their own application of the expanded-byte ceiling, not one physical-read
    /// counter. The same inherited request and deadline cover every phase.
    ///
    /// Like full streaming export, the result names the authenticated starting
    /// snapshot, not necessarily the current head at completion. Output remains
    /// tentative; its owner must close the node and settle file publication.
    pub async fn export_incremental_git_bundle_stream_in(
        &self,
        request: &NodeRequestContext,
        references: &[RefName],
        prerequisites: &[GitOid],
        visibility: &RefVisibility,
        query: StreamBundleExportQuery,
        output: &mut (impl Write + ?Sized),
    ) -> Result<SelectedStreamBundleExport, StreamBundleExportRefusal> {
        self.export_incremental_git_bundle_stream_controlled_in(
            request,
            references,
            prerequisites,
            visibility,
            query,
            output,
            &mut || true,
        )
        .await
    }

    /// Incremental streaming with the same sticky caller-stop probe and
    /// request-cancel/drain lifecycle as the controlled full export.
    pub async fn export_incremental_git_bundle_stream_controlled_in(
        &self,
        request: &NodeRequestContext,
        references: &[RefName],
        prerequisites: &[GitOid],
        visibility: &RefVisibility,
        query: StreamBundleExportQuery,
        output: &mut (impl Write + ?Sized),
        allow_work: &mut impl FnMut() -> bool,
    ) -> Result<SelectedStreamBundleExport, StreamBundleExportRefusal> {
        self.export_git_bundle_stream_profile_controlled_in(
            request,
            visibility,
            query,
            StreamProfile::Incremental {
                references,
                prerequisites,
            },
            output,
            allow_work,
        )
        .await
    }

    async fn export_git_bundle_stream_profile_controlled_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        query: StreamBundleExportQuery,
        profile: StreamProfile<'_>,
        output: &mut (impl Write + ?Sized),
        allow_work: &mut impl FnMut() -> bool,
    ) -> Result<SelectedStreamBundleExport, StreamBundleExportRefusal> {
        if query.timeout.is_zero() || query.timeout > Duration::from_secs(3600) {
            return Err(StreamBundleExportRefusal::InvalidTimeout);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let started = Instant::now();
        let (authority, cancellation) = request.authority().create_child_with_local_cancel_relay();
        let scoped_request = NodeRequestContext { authority };
        let stopped = Cell::new(None::<Stop>);
        let allow_work = RefCell::new(allow_work);
        let live = || {
            if stopped.get().is_some() {
                return false;
            }
            if started.elapsed() >= query.timeout {
                stopped.set(Some(Stop::Deadline));
                return false;
            }
            if !allow_work.borrow_mut()() {
                stopped.set(Some(Stop::Cancelled(None)));
                return false;
            }
            match checkpoint_pack_context(scoped_request.authority()) {
                PackContextCheckpoint::Live => true,
                PackContextCheckpoint::Stopped { budget_exhaustion } => {
                    stopped.set(Some(Stop::Cancelled(budget_exhaustion)));
                    false
                }
            }
        };
        let checkpoint = || {
            if live() {
                Ok(())
            } else {
                Err(stopped.get().unwrap_or(Stop::Cancelled(None)).refusal())
            }
        };
        checkpoint()?;
        let requested_names = match profile {
            StreamProfile::Full => None,
            StreamProfile::Incremental {
                references,
                prerequisites,
            } => {
                let names = incremental::validate_frontier(
                    references,
                    prerequisites,
                    self.object_format,
                    &query.limits,
                    &mut || live(),
                );
                checkpoint()?;
                Some(names?)
            }
        };
        // The Sync predicate fences materializer work/cache installation at
        // the same deadline. The outer poll adds the caller's mutable probe;
        // stopping cancels only the inherited child and drains that operation.
        let materialization_live = || started.elapsed() < query.timeout;
        let materialization =
            self.materialize_admission_while_in(&scoped_request, &materialization_live);
        let selected = drain_materialization(self, materialization, started, query.timeout, || {
            if !live() {
                let reason = match stopped.get() {
                    Some(Stop::Deadline) => fsqlite_types::cx::CancelReason::Timeout,
                    _ => fsqlite_types::cx::CancelReason::UserInterrupt,
                };
                let _ = cancellation.cancel_local(reason);
            }
        })
        .await;
        checkpoint()?;
        let selected =
            selected.map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if query
            .expected_head
            .is_some_and(|head| head != selected.basis().id())
        {
            return Err(StreamBundleExportRefusal::ExpectedHead);
        }
        let mut references = Vec::new();
        let mut selected_name_bytes = 0usize;
        let mut visible_roots = Vec::new();
        for (name, tip) in &selected.snapshot().refs {
            checkpoint()?;
            if visibility.hides(name.as_bytes())
                || selected.snapshot().hidden_refs.hides(name.as_bytes())
            {
                continue;
            }
            if let Some(names) = &requested_names {
                if visible_roots.len() == query.limits.envelope.max_references {
                    return Err(
                        super::bundle_error(fgit_pack::full_bundle::FullBundleError::Limit(
                            "visible references",
                        ))
                        .into(),
                    );
                }
                visible_roots.try_reserve(1).map_err(|_| {
                    super::bundle_error(PackError::AllocationFailed {
                        requested: visible_roots.len().saturating_add(1),
                    })
                })?;
                visible_roots.push(*tip);
                if !names.contains(&name) {
                    continue;
                }
            }
            if references.len() == query.limits.envelope.max_references {
                return Err(
                    super::bundle_error(fgit_pack::full_bundle::FullBundleError::Limit(
                        "references",
                    ))
                    .into(),
                );
            }
            // Bound name custody before cloning or growing the reference
            // vector. The codec independently checks the exact encoded header,
            // including format capabilities, targets, HEAD and delimiters.
            selected_name_bytes = selected_name_bytes
                .checked_add(name.as_bytes().len())
                .ok_or_else(|| {
                    super::bundle_error(PackError::IntegerOverflow {
                        context: "streamed bundle selected reference names",
                    })
                })?;
            if selected_name_bytes > query.limits.envelope.max_header_bytes {
                return Err(
                    super::bundle_error(fgit_pack::full_bundle::FullBundleError::Limit(
                        "header bytes",
                    ))
                    .into(),
                );
            }
            references.try_reserve(1).map_err(|_| {
                super::bundle_error(PackError::AllocationFailed {
                    requested: references.len().saturating_add(1),
                })
            })?;
            references.push(BundleReference::new(*tip, name.clone()));
        }
        if references.is_empty()
            || requested_names
                .as_ref()
                .is_some_and(|names| names.len() != references.len())
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable.into());
        }
        let head = if matches!(profile, StreamProfile::Full) {
            selected.snapshot().head_target.as_ref().and_then(|name| {
                references
                    .iter()
                    .find(|reference| {
                        reference.name() == name && name.as_bytes().starts_with(b"refs/heads/")
                    })
                    .map(|reference| *reference.target())
            })
        } else {
            None
        };
        let reference_records = references
            .len()
            .checked_add(usize::from(head.is_some()))
            .ok_or_else(|| {
                super::bundle_error(PackError::IntegerOverflow {
                    context: "streamed bundle reference records",
                })
            })?;
        if reference_records > query.limits.envelope.max_references {
            return Err(
                super::bundle_error(fgit_pack::full_bundle::FullBundleError::Limit("references"))
                    .into(),
            );
        }
        let mut limits = query.limits.clone();
        limits.pack.max_object_bytes = limits
            .pack
            .max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: limits.pack.max_object_bytes,
            database_context: scoped_request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: Some(&live),
        };
        let receipt = match profile {
            StreamProfile::Full => {
                let selection_source = BoundedStreamSelectionSource {
                    source: &source,
                    selected_bytes: Cell::new(0),
                    maximum_bytes: limits.pack.max_total_expanded_bytes,
                };
                let mut roots = Vec::new();
                roots.try_reserve_exact(references.len()).map_err(|_| {
                    super::bundle_error(PackError::AllocationFailed {
                        requested: references.len(),
                    })
                })?;
                roots.extend(references.iter().map(|reference| *reference.target()));
                let maximum_objects = usize::try_from(limits.pack.max_entries)
                    .unwrap_or(usize::MAX)
                    .min(limits.pack.max_index_entries);
                let ids = reachable_within_permitted_closure_bounded(
                    &selection_source,
                    selected.selected_closure().closure(),
                    &roots,
                    UnpermittedRootPolicy::RejectWant,
                    &limits.pack,
                    ClosureTraversalLimits {
                        unique_nodes: maximum_objects,
                        inspected_edges: limits.max_graph_edges,
                        frontier: maximum_objects,
                    },
                );
                checkpoint()?;
                let ids = ids.map_err(|error| NodeWorkspaceRefusal::BundleGraph(Box::new(error)))?;
                let mut selected_ids = Vec::new();
                selected_ids.try_reserve_exact(ids.len()).map_err(|_| {
                    super::bundle_error(PackError::AllocationFailed {
                        requested: ids.len(),
                    })
                })?;
                selected_ids.extend(ids);
                write_full_bundle_stream(
                    self.object_format,
                    &references,
                    head,
                    &selected_ids,
                    &source,
                    &limits,
                    &mut || live(),
                    output,
                )
            }
            StreamProfile::Incremental { prerequisites, .. } => {
                let prepared = incremental::prepare(
                    &source,
                    selected.selected_closure().closure(),
                    &visible_roots,
                    &references,
                    prerequisites,
                    &limits,
                );
                checkpoint()?;
                let prepared = prepared?;
                write_incremental_bundle_stream(
                    self.object_format,
                    &references,
                    prerequisites,
                    &prepared.objects,
                    &prepared.external,
                    &source,
                    &limits,
                    &mut || live(),
                    output,
                )
            }
        };
        checkpoint()?;
        let receipt = receipt.map_err(StreamBundleExportRefusal::Stream)?;
        Ok(SelectedStreamBundleExport {
            head: selected.basis().id(),
            generation: selected.basis().generation(),
            receipt,
        })
    }
}
