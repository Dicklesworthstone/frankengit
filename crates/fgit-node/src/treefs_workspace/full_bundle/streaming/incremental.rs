//! Selection for incremental streams reuses one bounded visible typed graph.
use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::{AdmissionLimits, PermittedObjectClosure};
use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::stream::{MAX_INCREMENTAL_EXTERNAL_OBJECTS, StreamFullBundleLimits};
use fgit_pack::full_bundle::{FullBundleError, MAX_BUNDLE_PREREQUISITES};
use fgit_pack::{BundleReference, PackError};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

use super::super::bundle_error;
use super::{NodeWorkspaceRefusal, VerifiedFabricPackSource};
use crate::{
    ClosureTraversalLimits, UnpermittedRootPolicy, reachable_within_permitted_closure_bounded,
};

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), NodeWorkspaceRefusal> {
    if live() {
        Ok(())
    } else {
        Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })
    }
}

/// Borrow bounded names until the source snapshot is selected. Duplicate or
/// foreign-domain frontiers refuse before materialization or object reads.
pub(super) fn validate_frontier<'a>(
    references: &'a [RefName],
    prerequisites: &[GitOid],
    format: GitHashAlgorithm,
    limits: &StreamFullBundleLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<&'a RefName>, NodeWorkspaceRefusal> {
    checkpoint(live)?;
    if references.is_empty()
        || references.len() > AdmissionLimits::default().command_limit(true)
        || prerequisites.is_empty()
        || prerequisites.len() > MAX_BUNDLE_PREREQUISITES
    {
        return Err(bundle_error(FullBundleError::Limit(
            "reference or prerequisite count",
        )));
    }
    if references.len() > limits.envelope.max_references {
        return Err(bundle_error(FullBundleError::Limit("references")));
    }
    let mut names = BTreeSet::new();
    let mut name_bytes = 0usize;
    for name in references {
        checkpoint(live)?;
        if !name.as_bytes().starts_with(b"refs/") || !names.insert(name) {
            return Err(bundle_error(FullBundleError::Invalid(
                "duplicate or invalid export frontier",
            )));
        }
        name_bytes = name_bytes
            .checked_add(name.as_bytes().len())
            .ok_or_else(|| bundle_error(FullBundleError::Limit("header bytes")))?;
        if name_bytes > limits.envelope.max_header_bytes {
            return Err(bundle_error(FullBundleError::Limit("header bytes")));
        }
    }
    let mut ids = BTreeSet::new();
    for &id in prerequisites {
        checkpoint(live)?;
        if id.is_zero() || id.algorithm() != format || !ids.insert(id) {
            return Err(bundle_error(FullBundleError::Invalid(
                "duplicate or invalid export frontier",
            )));
        }
    }
    Ok(names)
}

pub(super) struct Selection {
    pub(super) objects: Vec<GitOid>,
    pub(super) external: BTreeMap<GitOid, ObjectType>,
}

/// One visible native-metadata walk owns all durable discovery reads. Both
/// subsequent reachability walks use its saved edges under finite independent
/// node/frontier/edge bounds. Visible metadata bytes and selected payload bytes
/// each obey the query's expanded-byte ceiling; omitted blob payloads are not
/// read or counted as transferred bytes.
pub(super) fn prepare(
    source: &VerifiedFabricPackSource<'_>,
    admitted: &PermittedObjectClosure,
    visible_roots: &[GitOid],
    references: &[BundleReference],
    prerequisites: &[GitOid],
    limits: &StreamFullBundleLimits,
) -> Result<Selection, NodeWorkspaceRefusal> {
    let graph_error = |error| NodeWorkspaceRefusal::BundleGraph(Box::new(error));
    let graph = crate::upload_visibility::bundle_visible_graph_bounded(
        source,
        admitted,
        visible_roots.iter().copied(),
        &limits.pack,
        limits.max_graph_edges,
    )
    .map_err(graph_error)?;
    // Check ALL requested prerequisites against the authenticated visible
    // projection before inspecting any one prerequisite's kind.
    for id in prerequisites {
        source.session_checkpoint().map_err(bundle_error)?;
        if !graph.closure().objects().contains(id) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
    }
    for id in prerequisites {
        source.session_checkpoint().map_err(bundle_error)?;
        if graph.object_metadata(id).map(|(kind, _)| kind) != Some(ObjectType::Commit) {
            return Err(NodeWorkspaceRefusal::CommitRequired);
        }
    }
    let maximum = usize::try_from(limits.pack.max_entries)
        .unwrap_or(usize::MAX)
        .min(limits.pack.max_index_entries)
        .min(MAX_INCREMENTAL_EXTERNAL_OBJECTS);
    let traversal = ClosureTraversalLimits {
        unique_nodes: maximum,
        inspected_edges: limits.max_graph_edges,
        frontier: maximum,
    };
    let selection_source = graph.selection_source(source);
    let external_ids = reachable_within_permitted_closure_bounded(
        &selection_source,
        graph.closure(),
        prerequisites,
        UnpermittedRootPolicy::RejectWant,
        &limits.pack,
        traversal,
    )
    .map_err(graph_error)?;
    let mut roots = Vec::new();
    roots.try_reserve_exact(references.len()).map_err(|_| {
        bundle_error(PackError::AllocationFailed {
            requested: references.len(),
        })
    })?;
    roots.extend(references.iter().map(|reference| *reference.target()));
    let wanted = reachable_within_permitted_closure_bounded(
        &selection_source,
        graph.closure(),
        &roots,
        UnpermittedRootPolicy::RejectWant,
        &limits.pack,
        traversal,
    )
    .map_err(graph_error)?;
    let mut external = BTreeMap::new();
    for id in external_ids {
        source.session_checkpoint().map_err(bundle_error)?;
        let (kind, _) = graph
            .object_metadata(&id)
            .ok_or_else(|| bundle_error(FullBundleError::MissingObject(id)))?;
        external.insert(id, kind);
    }
    let mut objects = Vec::new();
    objects.try_reserve_exact(wanted.len()).map_err(|_| {
        bundle_error(PackError::AllocationFailed {
            requested: wanted.len(),
        })
    })?;
    let mut selected_bytes = 0usize;
    for id in wanted {
        source.session_checkpoint().map_err(bundle_error)?;
        if external.contains_key(&id) {
            continue;
        }
        let (kind, size) = graph
            .object_metadata(&id)
            .ok_or_else(|| bundle_error(FullBundleError::MissingObject(id)))?;
        let maximum = if kind == ObjectType::Blob {
            limits.max_streamed_blob_bytes
        } else {
            limits.pack.max_object_bytes
        };
        if size > maximum {
            return Err(bundle_error(PackError::ObjectSizeLimit {
                actual: size,
                limit: maximum,
            }));
        }
        selected_bytes = selected_bytes.checked_add(size).ok_or_else(|| {
            bundle_error(PackError::IntegerOverflow {
                context: "incremental streamed selected bytes",
            })
        })?;
        if selected_bytes > limits.pack.max_total_expanded_bytes {
            return Err(bundle_error(PackError::TotalExpandedLimit {
                actual: selected_bytes,
                limit: limits.pack.max_total_expanded_bytes,
            }));
        }
        objects.push(id);
    }
    source.session_checkpoint().map_err(bundle_error)?;
    Ok(Selection { objects, external })
}
