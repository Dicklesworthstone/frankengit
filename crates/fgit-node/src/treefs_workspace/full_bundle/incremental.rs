//! Incremental offline transfer rooted in the same typed visible graph as fetch.
use super::*;
use fgit_admission::PermittedObjectClosure;
use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::{IncrementalBundle, MAX_BUNDLE_PREREQUISITES};
use fgit_types::{GitOid, RefName};
use std::collections::BTreeSet;

impl OneNode {
    /// Export exactly the named visible references, excluding the complete
    /// history of explicit, currently visible native commit prerequisites.
    /// Neither retained/disconnected history nor a caller-minted have set grants
    /// disclosure. The returned object is transfer data, not canonical state.
    pub async fn export_incremental_git_bundle_in(
        &self,
        request: &NodeRequestContext,
        references: &[RefName],
        prerequisites: &[GitOid],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<(RepositoryAuthorityHeadId, IncrementalBundle), NodeWorkspaceRefusal> {
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if references.is_empty()
            || references.len() > AdmissionLimits::default().max_commands
            || prerequisites.is_empty()
            || prerequisites.len() > MAX_BUNDLE_PREREQUISITES
        {
            return Err(bundle_error(FullBundleError::Limit(
                "reference or prerequisite count",
            )));
        }
        let names: BTreeSet<_> = references.iter().cloned().collect();
        let prerequisite_ids: BTreeSet<_> = prerequisites.iter().copied().collect();
        if names.len() != references.len()
            || prerequisite_ids.len() != prerequisites.len()
            || prerequisites
                .iter()
                .any(|id| id.is_zero() || id.algorithm() != self.object_format)
        {
            return Err(bundle_error(FullBundleError::Invalid(
                "duplicate or invalid export frontier",
            )));
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(bundle_error(FullBundleError::Invalid(
                "export snapshot moved",
            )));
        }
        let mut advertised = Vec::new();
        for name in names {
            if visibility.hides(name.as_bytes())
                || selected.snapshot().hidden_refs.hides(name.as_bytes())
            {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
            let id = selected
                .snapshot()
                .refs
                .get(&name)
                .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
            advertised.push(BundleReference::new(*id, name));
        }
        let mut pack_limits = self.selected_pack_limits.clone();
        pack_limits.max_object_bytes = pack_limits
            .max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: pack_limits.max_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        let graph_error = |e| NodeWorkspaceRefusal::BundleGraph(Box::new(e));
        let visible: PermittedObjectClosure = crate::upload_visibility::bundle_visible_closure(
            &source,
            selected.selected_closure().closure(),
            selected
                .snapshot()
                .refs
                .iter()
                .filter(|(name, _)| {
                    !visibility.hides(name.as_bytes())
                        && !selected.snapshot().hidden_refs.hides(name.as_bytes())
                })
                .map(|(_, id)| *id),
            &pack_limits,
        )
        .map_err(graph_error)?;
        // Validate every requested prerequisite before looking up its body.
        if prerequisites
            .iter()
            .any(|id| !visible.objects().contains(id))
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let mut live = || workspace_request_live(request);
        for &id in prerequisites {
            if !live() {
                return Err(NodeWorkspaceRefusal::Cancelled {
                    exhaustion: exhaustion.get(),
                });
            }
            let read = source.read_object(&id);
            if !live() {
                return Err(NodeWorkspaceRefusal::Cancelled {
                    exhaustion: exhaustion.get(),
                });
            }
            let (kind, _) = read.map_err(|_| {
                bundle_error(FullBundleError::Invalid("prerequisite object unavailable"))
            })?;
            if kind != ObjectType::Commit {
                return Err(NodeWorkspaceRefusal::CommitRequired);
            }
        }
        let external = crate::reachable_within_permitted_closure(
            &source,
            &visible,
            prerequisites,
            crate::UnpermittedRootPolicy::RejectWant,
            &pack_limits,
        )
        .map_err(graph_error)?;
        let roots = advertised.iter().map(|r| *r.target()).collect::<Vec<_>>();
        let ids = selected_pack_ids(&source, &visible, Some(&roots), prerequisites, &pack_limits)
            .map_err(graph_error)?;
        let plan = PackPlanner::new(
            self.object_format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            pack_limits.clone(),
        )
        .plan_selected(&BundleObjectSource(&source), &ids, &mut live)
        .map_err(bundle_error)?;
        let bundle = IncrementalBundle::write(
            &advertised,
            prerequisites,
            &external,
            &plan,
            &PackWriter::new(pack_limits),
            FullBundleLimits::default(),
            &mut live,
        )
        .map_err(bundle_error)?;
        if !live() {
            return Err(NodeWorkspaceRefusal::Cancelled {
                exhaustion: exhaustion.get(),
            });
        }
        Ok((selected.basis().id(), bundle))
    }
}
