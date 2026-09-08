//! Node-owned, pinned export of ordinary file edits. No publication authority.

use super::{NodeTreeSource, NodeWorkspaceRefusal};
use crate::{NodeRequestContext, OneNode};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity};
use fgit_git_object::{AcceptanceProfile, parse_tree};
use fgit_treefs::{
    BaseEntry, BaseError, BaseView, ExportLimits, ExportPlan, ExportPlanner, IntentLog,
    TreeCapability, TreeEditIntent, TreePath,
};
use fgit_types::{GitOid as AnyOid, RefName, RepositoryCommitId};
use fgit_wire::visibility::RefVisibility;
use std::collections::BTreeSet;

/// A candidate tree and its exact source coordinates. This is not a commit.
#[derive(Debug)]
pub struct WorkspaceEditExport<A: GitHashAlgorithm> {
    /// Authenticated repository commit record selected for the source.
    pub source_rcr: RepositoryCommitId,
    /// Native commit whose tree was edited.
    pub source_commit: GitOid<A>,
    /// Candidate blobs/trees, including reused-subtree accounting.
    pub plan: ExportPlan<A>,
    /// The actual requested file targets in canonical order.
    pub changed_paths: Vec<TreePath>,
}

impl OneNode {
    /// Apply bounded file writes/deletions to one exact current ref tip and
    /// construct native Git objects using the existing TreeFS export engine.
    ///
    /// This interface consumes intents, not a caller-minted overlay or tree.
    /// The source is selected through authenticated authority and verified
    /// object reads. Every edited path must be readable and writable; each
    /// rebuilt directory must be completely disclosable to the exporting
    /// principal. A narrower capability refuses instead of accidentally
    /// deleting the siblings filtered out of a sparse directory listing.
    ///
    /// The returned plan is a preparation artifact. It never moves a ref;
    /// publication must separately recheck its exact source precondition.
    pub async fn export_workspace_edits_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_commit: AnyOid,
        visibility: &RefVisibility,
        capability: &mut TreeCapability,
        log: &IntentLog,
        now: u64,
        limits: ExportLimits,
    ) -> Result<WorkspaceEditExport<A>, NodeWorkspaceRefusal> {
        // Validate shape and byte budgets before evaluating/copying bodies.
        validate_log(log, capability, now, limits)?;
        self.with_workspace_base_in(
            request,
            reference,
            visibility,
            capability,
            now,
            |base, source, capability| {
                export_from_base(base, source, capability, log, expected_commit, now, limits,
                    &|| !super::workspace_request_live(request))
            },
        )
        .await
    }
}

/// Shared by the direct edit API and the trusted host-tool composition. The
/// caller already selected this exact immutable base through authority.
pub(super) fn export_from_base<A: GitHashAlgorithm>(
    base: &BaseView<A>, source: &NodeTreeSource<'_>, capability: &mut TreeCapability,
    log: &IntentLog, expected_commit: AnyOid, now: u64, limits: ExportLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<WorkspaceEditExport<A>, NodeWorkspaceRefusal> {
    validate_log(log, capability, now, limits)?;
    if expected_commit.as_bytes() != base.base_commit_oid().digest_bytes() {
        return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
    }
    let mut existing = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for intent in log.intents() {
        let path = intent.primary_path();
        match base.resolve(source, capability, path, now) {
            Ok(BaseEntry::File { .. }) => {
                existing.insert(path.clone());
            }
            Err(BaseError::NotFound { .. }) => {}
            Ok(_) => return Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit),
            Err(error) => {
                return Err(NodeWorkspaceRefusal::Manifest(
                    fgit_treefs::SparseRefusal::Base(error),
                ));
            }
        }
        paths.insert(path.clone());
    }
    let (overlay, evaluation) = log.evaluate(&|path| existing.contains(path));
    if !evaluation.errors().is_empty() {
        return Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit);
    }
    require_complete_directories(base, source, capability, &paths, now)?;
    let plan = ExportPlanner::new(limits, source.inner.parse_limits())
        .plan(base, source, capability, &overlay, now, cancelled)
        .map_err(NodeWorkspaceRefusal::WorkspaceExport)?;
    Ok(WorkspaceEditExport {
        source_rcr: base.base_rcr_id(),
        source_commit: *base.base_commit_oid(),
        plan,
        changed_paths: paths.into_iter().collect(),
    })
}

fn validate_log(
    log: &IntentLog,
    capability: &TreeCapability,
    now: u64,
    limits: ExportLimits,
) -> Result<(), NodeWorkspaceRefusal> {
    if log.len() > limits.max_objects {
        return Err(NodeWorkspaceRefusal::WorkspaceEditLimit);
    }
    let mut bytes = 0usize;
    for intent in log.intents() {
        match intent {
            TreeEditIntent::Write { content, .. } => {
                bytes = bytes
                    .checked_add(content.len())
                    .filter(|total| *total <= limits.max_total_bytes)
                    .ok_or(NodeWorkspaceRefusal::WorkspaceEditLimit)?;
            }
            TreeEditIntent::Delete { .. } => {}
            _ => return Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit),
        }
        capability
            .authorize_write(intent.primary_path(), now)
            .map_err(|error| {
                NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(error))
            })?;
    }
    Ok(())
}

/// The existing exporter calls disclosure-filtered BaseView::list. Verify
/// completeness against the actual, identity-checked trees before letting it
/// reconstruct anything. The refusal deliberately reveals no hidden name.
fn require_complete_directories<A: GitHashAlgorithm>(
    base: &BaseView<A>,
    source: &NodeTreeSource<'_>,
    capability: &mut TreeCapability,
    paths: &BTreeSet<TreePath>,
    now: u64,
) -> Result<(), NodeWorkspaceRefusal> {
    let mut directories = BTreeSet::from([None]);
    for path in paths {
        directories.extend(path.ancestors().into_iter().map(Some));
    }
    for directory in directories {
        let oid = match directory.as_ref() {
            None => *base.base_tree_oid(),
            Some(path) => match base.resolve(source, capability, path, now) {
                Ok(BaseEntry::Directory { oid }) => oid,
                Err(BaseError::NotFound { .. }) => continue,
                Ok(_) => return Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit),
                Err(error) => {
                    return Err(NodeWorkspaceRefusal::Manifest(
                        fgit_treefs::SparseRefusal::Base(error),
                    ));
                }
            },
        };
        let grant = match directory.as_ref() {
            Some(path) => capability.authorize_read(path, now),
            None => capability.authorize_root(now),
        }
        .map_err(|error| {
            NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(error))
        })?;
        let body = base
            .read_object(source, &oid, GitObjectKind::Tree, &grant)
            .map_err(NodeWorkspaceRefusal::Object)?;
        capability.charge_fetch(body.len() as u64).map_err(|error| {
            NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(error))
        })?;
        let entries = parse_tree(
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &source.inner.parse_limits(),
        )
        .map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)?;
        for entry in entries {
            let child = match directory.as_ref() {
                Some(parent) => parent.join(&entry.name, base.path_policy()),
                None => TreePath::parse(&entry.name, base.path_policy()),
            }
            .map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)?;
            if !capability.admits_disclosure(&child) {
                return Err(NodeWorkspaceRefusal::IncompleteWorkspaceExportScope);
            }
        }
    }
    Ok(())
}
