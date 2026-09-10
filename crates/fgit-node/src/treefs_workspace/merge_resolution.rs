//! Explicit conflict resolution over the same authenticated source and bundle
//! materializer as automatic merge preparation. No canonical mutation.

use super::{Cell, MergeMetadata, MergeObjectSource, NodeRequestContext, NodeWorkspaceRefusal,
    OneNode, ParseLimits, PreparationLimits, RefName, RefVisibility, RepositoryAuthorityHeadId,
    SelectedSource, VerifiedFabricPackSource, bundle_for_plan};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionError, ResolutionInputs,
    ResolvedMerge, prepare_resolved_merge, validate_resolutions};
use fgit_types::cell::{ReadMode, admits_read};

#[derive(Debug)]
pub struct ResolvedMergeBundle {
    pub source_head: RepositoryAuthorityHeadId,
    pub resolved: ResolvedMerge,
    pub bundle: Vec<u8>,
    pub bundle_sha256: [u8; 32],
}

#[derive(Debug)]
pub enum NodeResolutionRefusal {
    Source(Box<NodeWorkspaceRefusal>),
    Resolution(Box<ResolutionError>),
    SnapshotMoved,
    TipsMoved,
}
impl std::fmt::Display for NodeResolutionRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "native merge resolution refused: {self:?}")
    }
}
impl std::error::Error for NodeResolutionRefusal {}
impl From<NodeWorkspaceRefusal> for NodeResolutionRefusal {
    fn from(error: NodeWorkspaceRefusal) -> Self { Self::Source(Box::new(error)) }
}
impl From<ResolutionError> for NodeResolutionRefusal {
    fn from(error: ResolutionError) -> Self { Self::Resolution(Box::new(error)) }
}

impl OneNode {
    /// Prepare a resolved candidate at independently supplied exact branch tips
    /// and unique merge base. Every resolution must name an actual conflict;
    /// the complete set must resolve, or no candidate bytes are returned.
    ///
    /// This local/ref-authorized interface does not infer authority from paths
    /// or text. Callers supply authorization; visibility only narrows canonical
    /// policy. It neither runs user code nor grants a reviewer approval. The
    /// returned bundle still needs independent inspection and ordinary apply.
    pub async fn prepare_resolved_merge_bundle_in(
        &self, request: &NodeRequestContext, target: &RefName, incoming: &RefName,
        visibility: &RefVisibility, expected_head: Option<RepositoryAuthorityHeadId>,
        inputs: ResolutionInputs, resolutions: &[ConflictResolution],
        metadata: &MergeMetadata, limits: PreparationLimits,
    ) -> Result<ResolvedMergeBundle, NodeResolutionRefusal> {
        inputs.validate(self.object_format)?;
        validate_resolutions(resolutions, limits)?;
        metadata.validate().map_err(ResolutionError::from)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if target == incoming || !target.as_bytes().starts_with(b"refs/heads/")
            || !incoming.as_bytes().starts_with(b"refs/heads/")
        { return Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("resolution requires distinct branches").into()); }
        if visibility.hides(target.as_bytes()) || visibility.hides(incoming.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable.into());
        }
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(NodeResolutionRefusal::SnapshotMoved);
        }
        if selected.snapshot().hidden_refs.hides(target.as_bytes())
            || selected.snapshot().hidden_refs.hides(incoming.as_bytes())
        { return Err(NodeWorkspaceRefusal::RefUnavailable.into()); }
        let actual_target = selected.snapshot().refs.get(target).ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let actual_source = selected.snapshot().refs.get(incoming).ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        if *actual_target != inputs.target || *actual_source != inputs.source {
            return Err(NodeResolutionRefusal::TipsMoved);
        }
        let exhaustion = Cell::new(None);
        let maximum_object_bytes = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX).min(32 * 1024 * 1024);
        let source = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric, object_format: self.object_format, maximum_object_bytes,
                database_context: request.authority(), database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            limits: ParseLimits {
                tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: limits.max_tree_entries,
                // A graph-edge budget must not restrict ordinary commit metadata.
                max_header_lines: PreparationLimits::default().max_edges,
                max_object_bytes: maximum_object_bytes, ..ParseLimits::default()
            },
            read_bytes: Cell::new(0), budget_failed: Cell::new(false),
        };
        let resolved = prepare_resolved_merge(&source, self.object_format, inputs, resolutions, metadata, limits)?;
        // The normal production native verifier and pack writer independently
        // validate the complete constructed closure, including selected subtrees.
        let bundle = bundle_for_plan(&source, target, incoming, &resolved.plan, limits)?;
        source.checkpoint().map_err(ResolutionError::from)?;
        let bundle_sha256 = fgit_crypto::sha256_digest(&bundle);
        source.checkpoint().map_err(ResolutionError::from)?;
        Ok(ResolvedMergeBundle { source_head: selected.basis().id(), resolved, bundle, bundle_sha256 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{fixture, metadata};
    use fgit_forge::{ExpectedVersion, PullRequestNumber};
    use fgit_forge::event::NativeMerge;
    use fgit_forge::preparation::{MergePreparation, ConflictKind};
    use fgit_forge::preparation::resolution::ResolutionChoice;
    use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId};

    fn references() -> (RefName, RefName) {
        (RefName::try_new(b"refs/heads/main").unwrap(), RefName::try_new(b"refs/heads/topic").unwrap())
    }
    fn inputs(node: &OneNode, request: &NodeRequestContext) -> ResolutionInputs {
        let (target_ref, source_ref) = references();
        let source = node.runtime().block_on(node.materialize_admission_in(request)).unwrap();
        let auto = node.runtime().block_on(node.prepare_merge_bundle_in(request, &target_ref, &source_ref,
            &RefVisibility::new(), &metadata(), PreparationLimits::default())).unwrap();
        let MergePreparation::Conflicted { base, conflicts } = auto.outcome else { panic!("fixture must conflict"); };
        assert_eq!(conflicts.len(), 1); assert_eq!(conflicts[0].path, b"text");
        assert_eq!(conflicts[0].kind, ConflictKind::Content);
        assert!(auto.bundle.is_none());
        ResolutionInputs { base, target: source.snapshot().refs[&target_ref], source: source.snapshot().refs[&source_ref] }
    }

    #[test]
    fn resolved_candidates_inspect_and_publish_through_the_existing_path_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let (_scratch, node, _, _) = fixture(format, true);
            let request = node.request_context();
            let coordinates = inputs(&node, &request);
            let (target_ref, source_ref) = references();
            let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            let choices = [ConflictResolution { path: b"text".to_vec(), choice: ResolutionChoice::File {
                mode: 0o100755, bytes: b"resolved\nb\nc\nd\ne\n".to_vec(),
            }}];
            let artifact = node.runtime().block_on(node.prepare_resolved_merge_bundle_in(
                &request, &target_ref, &source_ref, &RefVisibility::new(), Some(before.basis().id()),
                coordinates, &choices, &metadata(), PreparationLimits::default(),
            )).unwrap();
            assert_eq!(artifact.source_head, before.basis().id());
            let plan = &artifact.resolved.plan;
            assert!(node.read_git_object(plan.commit).is_err(), "preparation must not stage candidates");
            let merge = NativeMerge { source_ref: source_ref.clone(), source_tip: coordinates.source,
                base_tip: coordinates.base, target_ref: target_ref.clone(), target_tip_before: coordinates.target,
                merge_commit: plan.commit };
            let inspected = node.runtime().block_on(node.inspect_merge_bundle_in(&request, &merge, &artifact.bundle,
                &RefVisibility::new(), Some(before.basis().id()), &Default::default())).unwrap();
            assert_eq!(inspected.parents, vec![coordinates.target, coordinates.source]);
            assert_eq!(inspected.review.comparison.requested_after, plan.commit);
            assert_eq!(inspected.review.comparison.entries.len(), 1);
            assert_eq!(inspected.review.comparison.entries[0].path, b"text");
            assert_eq!(inspected.review.comparison.entries[0].after.unwrap().mode, 0o100755);
            assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
            let repeat = node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &target_ref, &source_ref,
                &RefVisibility::new(), Some(before.basis().id()), coordinates, &choices, &metadata(), PreparationLimits::default())).unwrap();
            assert_eq!(artifact.bundle, repeat.bundle);
            let terminal = node.runtime().block_on(node.apply_merge_bundle_durable_in(&request,
                PrincipalId::from_bytes([0x73; 16]), b"resolved-candidate", PullRequestNumber::FIRST,
                ExpectedVersion::NewStream, &merge, &artifact.bundle)).unwrap();
            assert!(matches!(terminal.1.outcome, DecisionOutcome::Committed { .. }));
            let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            assert_eq!(after.snapshot().refs[&target_ref], plan.commit);
            assert_eq!(after.snapshot().refs[&source_ref], coordinates.source);
            assert_ne!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
            assert_ne!(after.basis().body().outbox_root, before.basis().body().outbox_root);
            assert_eq!(node.runtime().block_on(node.apply_merge_bundle_durable_in(&request,
                PrincipalId::from_bytes([0x73; 16]), b"resolved-candidate", PullRequestNumber::FIRST,
                ExpectedVersion::NewStream, &merge, &artifact.bundle)).unwrap(), terminal);
            assert!(matches!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request,
                &target_ref, &source_ref, &RefVisibility::new(), None, coordinates, &choices, &metadata(), PreparationLimits::default())),
                Err(NodeResolutionRefusal::TipsMoved)));
            assert!(matches!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request,
                &target_ref, &source_ref, &RefVisibility::new(), Some(before.basis().id()), coordinates,
                &choices, &metadata(), PreparationLimits::default())), Err(NodeResolutionRefusal::SnapshotMoved)));
            node.shutdown().unwrap();
        }
    }

    #[test]
    fn unresolved_extra_hidden_and_stale_inputs_never_change_authority() {
        let (_scratch, node, _, _) = fixture(GitHashAlgorithm::Sha1, true);
        let request = node.request_context(); let coordinates = inputs(&node, &request);
        let (target_ref, source_ref) = references();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        for choices in [vec![], vec![ConflictResolution { path: b"keep".to_vec(), choice: ResolutionChoice::Delete }]] {
            assert!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &target_ref, &source_ref,
                &RefVisibility::new(), None, coordinates, &choices, &metadata(), PreparationLimits::default())).is_err());
        }
        let choices = [ConflictResolution { path: b"text".to_vec(), choice: ResolutionChoice::Theirs }];
        let mut hidden = RefVisibility::new(); hidden.push_rule(source_ref.as_bytes(), &Default::default()).unwrap();
        assert!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &target_ref, &source_ref,
            &hidden, None, coordinates, &choices, &metadata(), PreparationLimits::default())).is_err());
        let wrong = ResolutionInputs { base: coordinates.target, ..coordinates };
        assert!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &target_ref, &source_ref,
            &RefVisibility::new(), None, wrong, &choices, &metadata(), PreparationLimits::default())).is_err());
        let low = PreparationLimits { max_content_merges: 1, ..PreparationLimits::default() };
        assert!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &target_ref, &source_ref,
            &RefVisibility::new(), None, coordinates, &choices, &metadata(), low)).is_err());
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        assert!(node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &target_ref, &source_ref,
            &RefVisibility::new(), None, coordinates, &choices, &metadata(), PreparationLimits::default())).is_ok());
        node.shutdown().unwrap();
    }
}
