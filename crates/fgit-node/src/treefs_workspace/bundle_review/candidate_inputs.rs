//! Verified unpublished candidate inputs for trusted local execution.
//! Single-parent and explicit merge candidates share source selection, bounded
//! unpacking, native closure verification and capability-scoped discovery.

use super::*;
use crate::ClosureSelectionSource;
use fgit_crypto::{GitHashAlgorithm as Hash, NativeObjectIdentity};
use fgit_forge::preparation::MergeCommitStyle;
use fgit_treefs::{
    BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant, SparseCandidateManifest,
    SparseLimits, TreeCapability, WorkspaceId,
};

impl OneNode {
    /// Build single-parent candidate inputs at one authenticated base snapshot.
    /// The existing one-parent/one-prerequisite profile is unchanged. No tools,
    /// object staging, canonical check or repository publication occurs here.
    pub async fn sparse_candidate_manifest_in<A: Hash>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_base: GitOid,
        candidate: GitOid,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        capability: &mut TreeCapability,
        now: u64,
        sparse: SparseLimits,
    ) -> Result<
        (
            RepositoryAuthorityHeadId,
            SparseCandidateManifest<A>,
            [u8; 32],
        ),
        BundleInspectionRefusal,
    > {
        self.sparse_bound_candidate_in(
            request,
            reference,
            expected_base,
            candidate,
            None,
            input,
            visibility,
            expected_head,
            capability,
            now,
            sparse,
        )
        .await
    }

    /// Build inputs from an actual two-parent merge bundle, not its source tip.
    /// Both current branch tips are authenticated together; caller visibility
    /// may only narrow canonical disclosure. Native validation proves ordered
    /// parents and that the explicit common base is an ancestor of both.
    ///
    /// This profile requires precisely the target/source tips as prerequisites.
    /// Only their verified closures can provide original objects, including thin
    /// delta bases. Unrelated admitted objects are unavailable. A conflict-
    /// resolved candidate may differ from automatic merge output: these checks
    /// establish structure and identity, not algorithmic equivalence or approval.
    pub async fn sparse_merge_candidate_manifest_in<A: Hash>(
        &self,
        request: &NodeRequestContext,
        merge: &NativeMerge,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        capability: &mut TreeCapability,
        now: u64,
        sparse: SparseLimits,
    ) -> Result<
        (
            RepositoryAuthorityHeadId,
            SparseCandidateManifest<A>,
            [u8; 32],
        ),
        BundleInspectionRefusal,
    > {
        self.sparse_merge_candidate_manifest_with_style_in::<A>(
            request,
            merge,
            input,
            visibility,
            expected_head,
            capability,
            now,
            sparse,
            MergeCommitStyle::TwoParent,
        )
        .await
    }

    /// Select an explicit native parent shape while retaining BOTH authenticated
    /// source closures and exact prerequisites. Squash has one target parent;
    /// the incoming source still supplies objects and common-base evidence.
    /// This does not stage or publish the candidate, or attest merge correctness.
    pub async fn sparse_merge_candidate_manifest_with_style_in<A: Hash>(
        &self,
        request: &NodeRequestContext,
        merge: &NativeMerge,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        capability: &mut TreeCapability,
        now: u64,
        sparse: SparseLimits,
        style: MergeCommitStyle,
    ) -> Result<
        (
            RepositoryAuthorityHeadId,
            SparseCandidateManifest<A>,
            [u8; 32],
        ),
        BundleInspectionRefusal,
    > {
        merge
            .validate()
            .map_err(|_| invalid("invalid merge input coordinates"))?;
        if merge.source_ref == merge.target_ref
            || [&merge.source_ref, &merge.target_ref].iter().any(|name| {
                !name.as_bytes().starts_with(b"refs/heads/") || name.as_bytes().len() > 4096
            })
        {
            return Err(invalid(
                "merge workflow requires two distinct bounded branches",
            ));
        }
        self.sparse_bound_candidate_in(
            request,
            &merge.target_ref,
            merge.target_tip_before,
            merge.merge_commit,
            Some((merge, style)),
            input,
            visibility,
            expected_head,
            capability,
            now,
            sparse,
        )
        .await
    }

    async fn sparse_bound_candidate_in<A: Hash>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_base: GitOid,
        candidate: GitOid,
        merge: Option<(&NativeMerge, MergeCommitStyle)>,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        capability: &mut TreeCapability,
        now: u64,
        sparse: SparseLimits,
    ) -> Result<
        (
            RepositoryAuthorityHeadId,
            SparseCandidateManifest<A>,
            [u8; 32],
        ),
        BundleInspectionRefusal,
    > {
        if A::DIGEST_LEN != self.object_format.digest_len()
            || capability.repository_id() != self.repository_id
            || sparse.max_entries == 0
            || sparse.max_entries > 10_000
            || sparse.max_entry_bytes == 0
            || sparse.max_entry_bytes > 16 * 1024 * 1024
            || sparse.max_payload_bytes == 0
            || sparse.max_payload_bytes > 64 * 1024 * 1024
            || sparse.max_entry_bytes > sparse.max_payload_bytes
        {
            return Err(invalid("invalid candidate input scope, format or limits"));
        }
        capability
            .authorize_root(now)
            .map_err(|_| invalid("candidate input capability refused"))?;
        let envelope = CandidateEnvelope::parse_bounded(input, if merge.is_some() { 2 } else { 1 })
            .map_err(|e| BundleInspectionRefusal::Envelope(Box::new(e)))?;
        envelope
            .bind(self.object_format, reference, expected_base, candidate)
            .map_err(|e| BundleInspectionRefusal::Envelope(Box::new(e)))?;
        if merge.is_some_and(|(m, _)| {
            envelope.prerequisites.len() != 2 || !envelope.prerequisites.contains(&m.source_tip)
        }) {
            return Err(invalid(
                "merge inputs require exact target and source prerequisites",
            ));
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(BundleInspectionRefusal::Cell)?;
        let mut selections = vec![(reference, expected_base)];
        if let Some((m, _)) = merge {
            selections.push((&m.source_ref, m.source_tip));
        }
        if selections
            .iter()
            .any(|(name, _)| visibility.hides(name.as_bytes()))
        {
            return Err(BundleInspectionRefusal::RefUnavailable);
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| BundleInspectionRefusal::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(BundleInspectionRefusal::SnapshotMoved);
        }
        // Check all disclosure rules before distinguishing either stale tip.
        if selections
            .iter()
            .any(|(name, _)| selected.snapshot().hidden_refs.hides(name.as_bytes()))
        {
            return Err(BundleInspectionRefusal::RefUnavailable);
        }
        for (name, expected) in &selections {
            let actual = selected
                .snapshot()
                .refs
                .get(*name)
                .ok_or(BundleInspectionRefusal::RefUnavailable)?;
            if actual != expected {
                return Err(BundleInspectionRefusal::ParentMoved);
            }
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => {
                return Err(BundleInspectionRefusal::RefUnavailable);
            }
        };
        let exhaustion = Cell::new(None);
        let budget = ReadBudget {
            bytes: Cell::new(0),
            exhausted: Cell::new(false),
        };
        let maximum = usize::try_from(self.max_object_bytes)
            .unwrap_or(usize::MAX)
            .min(sparse.max_entry_bytes.max(MAX_CANDIDATE_BYTES));
        let limits = MergeObjectLimits {
            max_object_bytes: maximum,
            ..Default::default()
        };
        let parents: Vec<_> = selections.iter().map(|(_, parent)| *parent).collect();
        let original = OriginalSource::with_parents(
            VerifiedFabricPackSource {
                fabric: &self.fabric,
                object_format: self.object_format,
                maximum_object_bytes: maximum,
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected.selected_closure().closure().objects(),
            &budget,
            &parents,
            limits,
        )
        .map_err(BundleInspectionRefusal::Source)?;
        let pack_limits = PackLimits {
            max_input_bytes: MAX_BUNDLE_BYTES,
            max_entries: MAX_INSPECTION_OBJECTS,
            max_object_bytes: maximum,
            max_total_expanded_bytes: MAX_EXPANDED_BYTES,
            max_cached_bytes: MAX_EXPANDED_BYTES,
            ..Default::default()
        };
        let unpacked = pack::unpack(envelope.pack, self.object_format, &pack_limits, &original);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let unpacked = unpacked?;
        let offered = unpacked
            .objects
            .get(&candidate)
            .ok_or_else(|| invalid("candidate commit is absent from the pack"))?;
        if offered.kind != ObjectType::Commit || offered.body.len() > MAX_CANDIDATE_BYTES {
            return Err(invalid("candidate is not a bounded uploaded commit"));
        }
        let source = InspectionSource {
            original: &original,
            objects: &unpacked.objects,
            parse_limits: ParseLimits {
                max_object_bytes: maximum,
                tree_reference_bytes: self.object_format.digest_len(),
                ..Default::default()
            },
        };
        let verified = match merge {
            Some((m, MergeCommitStyle::TwoParent)) => validate_merge_objects_above(
                &source,
                m,
                ObjectFrontier::with_headers(
                    selected.selected_closure().closure().objects(),
                    &source,
                ),
                limits,
                &mut || original.live().is_ok(),
            ),
            Some((m, MergeCommitStyle::Squash)) => validate_squash_objects_above(
                &source,
                m,
                ObjectFrontier::with_headers(
                    selected.selected_closure().closure().objects(),
                    &source,
                ),
                limits,
                &mut || original.live().is_ok(),
            ),
            None => validate_workspace_objects_above(
                &source,
                candidate,
                expected_base,
                ObjectFrontier::with_headers(
                    selected.selected_closure().closure().objects(),
                    &source,
                ),
                limits,
                &mut || original.live().is_ok(),
            ),
        };
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let verified = verified.map_err(BundleInspectionRefusal::Validation)?;
        unpacked.check_frontier_coverage(&verified.objects, &original, limits)?;
        let base_commit = source
            .commit(expected_base)
            .map_err(BundleInspectionRefusal::Source)?;
        let typed = |id: GitOid| {
            A::parse_hex(&id.to_string()).map_err(|_| invalid("candidate input identity format"))
        };
        let base_view = BaseView::new(
            self.repository_id,
            rcr,
            typed(expected_base)?,
            typed(base_commit.tree)?,
            source.parse_limits.clone(),
            PathPolicy::default(),
        );
        let tree_source = CandidateTreeSource {
            source: &source,
            workspace: capability.workspace_id(),
        };
        let manifest = match merge {
            Some((m, MergeCommitStyle::TwoParent)) => SparseCandidateManifest::build_merge(
                &base_view,
                &tree_source,
                typed(candidate)?,
                typed(m.source_tip)?,
                capability,
                now,
                source.parse_limits.clone(),
                sparse,
            ),
            None | Some((_, MergeCommitStyle::Squash)) => SparseCandidateManifest::build(
                &base_view,
                &tree_source,
                typed(candidate)?,
                capability,
                now,
                source.parse_limits.clone(),
                sparse,
            ),
        };
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let manifest = manifest.map_err(|_| invalid("candidate sparse input discovery refused"))?;
        let digest = sha256_digest(input);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        Ok((selected.basis().id(), manifest, digest))
    }
}

struct CandidateTreeSource<'a, 'b, 'c> {
    source: &'a InspectionSource<'b, 'c>,
    workspace: WorkspaceId,
}
impl<A: Hash> ObjectSource<A> for CandidateTreeSource<'_, '_, '_> {
    fn read_object(
        &self,
        oid: &fgit_crypto::GitOid<A>,
        kind: fgit_crypto::GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let refused = |reason: &str| ObjectSourceError::Refused {
            reason: reason.to_owned(),
        };
        if grant.workspace_id() != self.workspace {
            return Err(refused("workspace grant mismatch"));
        }
        let hex: String = oid
            .digest_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let id = GitOid::from_hex(self.source.original.inner.object_format, &hex)
            .map_err(|_| refused("candidate hash domain mismatch"))?;
        let expected = match kind {
            fgit_crypto::GitObjectKind::Blob => ObjectType::Blob,
            fgit_crypto::GitObjectKind::Tree => ObjectType::Tree,
            fgit_crypto::GitObjectKind::Commit => ObjectType::Commit,
            fgit_crypto::GitObjectKind::Tag => ObjectType::Tag,
        };
        self.source
            .read(id, Some(expected))
            .map(|(_, bytes)| bytes)
            .map_err(|_| refused("candidate object unavailable within selected parents and upload"))
    }
}
