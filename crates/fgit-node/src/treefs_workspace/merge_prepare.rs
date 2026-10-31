//! Native merge preparation over one authenticated source snapshot. Unlike
//! merge admission, this path performs NO object staging, seal or head write.

#[path = "comment_anchor.rs"]
mod comment_anchor;
#[path = "commit_replay.rs"]
mod commit_replay;
#[path = "merge_resolution.rs"]
mod merge_resolution;
#[path = "rebase.rs"]
mod rebase;
#[path = "source_history.rs"]
mod source_history;
#[path = "source_review.rs"]
mod source_review;
#[path = "sparse_bundle.rs"]
mod sparse_bundle;

mod workflow_paths;
pub(super) use workflow_paths::changed_paths;

use std::cell::Cell;
use std::collections::BTreeMap;

use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierObjectHeaders, MergeObjectLimits, ObjectFrontier,
    validate_merge_objects_above, validate_squash_objects_above,
};
use fgit_crypto::git_object_id;
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::{
    CommitInput, MergeCommitStyle, MergeEntry, MergeMetadata, MergeObjectSource, MergePreparation,
    MergeProfile, MergeSourceError, PlannedMergeObject, PreparationError, PreparationLimits,
    PreparedMerge, prepare_merge_with_options,
};
use fgit_git_object::{
    AcceptanceProfile, ObjectError, ObjectType, ParseLimits, ParsedObject, parse_object_body,
};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackError, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter, verify_native_object,
};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use super::NodeWorkspaceRefusal;
use super::native_merge::read_frontier_header;
use crate::ancestry_metadata::{AncestryMetadataAccess, VerifiedCommitMetadata};
use crate::{
    AuthoritySelectedClosure, NodeRequestContext, OneNode, PackContextCheckpoint,
    VerifiedFabricPackSource, checkpoint_pack_context,
};

const MAX_READ_BYTES: usize = 128 * 1024 * 1024;

/// A pinned preparation receipt. Only `Clean` carries a bundle. Preparation
/// does not mutate the repository and does not authorize eventual publication.
#[derive(Debug)]
pub struct PreparedMergeBundle {
    pub source_head: RepositoryAuthorityHeadId,
    pub outcome: MergePreparation,
    pub bundle: Option<Vec<u8>>,
}

impl OneNode {
    /// Construct a reviewable two-parent candidate using explicit PathMergeV1.
    /// Both branch tips come from the SAME authenticated head. Caller policy
    /// can hide more refs, never expose an authority-hidden one. Every original
    /// object is checked against that head's admitted closure. Commit metadata
    /// may reuse a bounded native-hash-verified parse from this same store and
    /// repository incarnation; current traversal and object budgets still apply.
    ///
    /// New objects exist only in the returned artifact, not in node storage.
    /// The resulting merge is independently checked by the production native
    /// validator before a pack is built. `apply_merge_bundle_durable_in` remains
    /// the separate, explicit mutation boundary, with fresh tip/policy checks.
    ///
    /// This profile does not interpret rename heuristics or execute attributes
    /// and hooks. Attribute-dependent content, ambiguous bases and conflicts
    /// refuse automatic construction instead of guessing at reviewed content.
    pub async fn prepare_merge_bundle_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        incoming: &RefName,
        visibility: &RefVisibility,
        metadata: &MergeMetadata,
        limits: PreparationLimits,
    ) -> Result<PreparedMergeBundle, NodeWorkspaceRefusal> {
        self.prepare_merge_bundle_with_profile_in(
            request,
            target,
            incoming,
            visibility,
            metadata,
            limits,
            MergeProfile::PathMergeV1,
        )
        .await
    }

    /// Select bounded merge semantics explicitly over the same authenticated
    /// source, native-object validation and bundle construction as the default.
    /// ExactRenamesV1 preserves opposite-side edits across unique exact-content
    /// regular-file moves. Ambiguous moves refuse; no fallback candidate is made.
    /// Neither profile stages objects, grants review approval or publishes refs.
    pub async fn prepare_merge_bundle_with_profile_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        incoming: &RefName,
        visibility: &RefVisibility,
        metadata: &MergeMetadata,
        limits: PreparationLimits,
        profile: MergeProfile,
    ) -> Result<PreparedMergeBundle, NodeWorkspaceRefusal> {
        self.prepare_merge_bundle_with_options_in(
            request,
            target,
            incoming,
            visibility,
            metadata,
            limits,
            profile,
            MergeCommitStyle::TwoParent,
        )
        .await
    }

    /// Prepare either a two-parent merge or a one-parent squash over the same
    /// authenticated tips. Squash preserves the merge tree and verifies source
    /// history independently; it never publishes or grants review approval.
    pub async fn prepare_merge_bundle_with_options_in(
        &self,
        request: &NodeRequestContext,
        target: &RefName,
        incoming: &RefName,
        visibility: &RefVisibility,
        metadata: &MergeMetadata,
        limits: PreparationLimits,
        profile: MergeProfile,
        style: MergeCommitStyle,
    ) -> Result<PreparedMergeBundle, NodeWorkspaceRefusal> {
        limits
            .validate()
            .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        metadata
            .validate()
            .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if target == incoming
            || !target.as_bytes().starts_with(b"refs/heads/")
            || !incoming.as_bytes().starts_with(b"refs/heads/")
        {
            return Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                "merge preparation requires two distinct branch names",
            ));
        }
        if visibility.hides(target.as_bytes()) || visibility.hides(incoming.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if selected.snapshot().hidden_refs.hides(target.as_bytes())
            || selected.snapshot().hidden_refs.hides(incoming.as_bytes())
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let our_tip = *selected
            .snapshot()
            .refs
            .get(target)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let their_tip = *selected
            .snapshot()
            .refs
            .get(incoming)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let exhaustion = Cell::new(None);
        let source = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric,
                object_format: self.object_format,
                maximum_object_bytes: usize::try_from(self.max_object_bytes)
                    .unwrap_or(usize::MAX)
                    .min(32 * 1024 * 1024),
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            ancestry: Some(AncestryMetadataAccess::for_node(self)),
            limits: ParseLimits {
                tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: limits.max_tree_entries,
                max_header_lines: limits.max_edges,
                max_object_bytes: usize::try_from(self.max_object_bytes)
                    .unwrap_or(usize::MAX)
                    .min(32 * 1024 * 1024),
                ..ParseLimits::default()
            },
            read_bytes: Cell::new(0),
            budget_failed: Cell::new(false),
        };
        let outcome = prepare_merge_with_options(
            &source,
            self.object_format,
            our_tip,
            their_tip,
            metadata,
            limits,
            profile,
            style,
        )
        .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        let bundle = if let MergePreparation::Clean(plan) = &outcome {
            Some(bundle_for_plan(
                &source,
                target,
                incoming,
                plan,
                limits,
                self.reused_merge_blob_limit(),
            )?)
        } else {
            None
        };
        source.checkpoint().map_err(source_error)?;
        Ok(PreparedMergeBundle {
            source_head: selected.basis().id(),
            outcome,
            bundle,
        })
    }
}

/// Shared strict validation and transport materialization for automatic and
/// explicitly resolved candidates. Neither path stages objects or grants approval.
fn bundle_for_plan(
    original: &SelectedSource<'_>,
    target: &RefName,
    incoming: &RefName,
    plan: &PreparedMerge,
    limits: PreparationLimits,
    maximum_reused_blob_bytes: usize,
) -> Result<Vec<u8>, NodeWorkspaceRefusal> {
    let candidate = CandidateSource {
        original,
        generated: plan
            .objects
            .iter()
            .map(|object| (object.id, object))
            .collect(),
    };
    let headers = CandidateFrontierHeaders {
        source: &candidate,
        maximum_blob_bytes: maximum_reused_blob_bytes,
    };
    let object_limits = MergeObjectLimits {
        max_object_bytes: original.inner.buffered_object_limit(),
        max_reused_blob_bytes: maximum_reused_blob_bytes,
        ..MergeObjectLimits::default()
    };
    for object in &plan.objects {
        original.checkpoint().map_err(source_error)?;
        verify_native_object(
            original.inner.object_format,
            object.kind,
            &object.body,
            &object.id,
            AcceptanceProfile::StrictCreate,
            &original.limits,
        )
        .map_err(|_| {
            NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                "constructed object failed strict native validation",
            )
        })?;
    }
    let coordinates = NativeMerge {
        source_ref: incoming.clone(),
        source_tip: plan.source,
        target_ref: target.clone(),
        target_tip_before: plan.target,
        base_tip: plan.base,
        merge_commit: plan.commit,
    };
    let mut live = || original.checkpoint().is_ok();
    // Only what the plan adds above the selected closure is validated here;
    // publication validates the same frontier again (frankengit-lh8z).
    let verified = match plan.style {
        MergeCommitStyle::TwoParent => validate_merge_objects_above(
            &candidate,
            &coordinates,
            ObjectFrontier::with_headers(original.selected.closure().objects(), &headers),
            object_limits,
            &mut live,
        ),
        MergeCommitStyle::Squash => validate_squash_objects_above(
            &candidate,
            &coordinates,
            ObjectFrontier::with_headers(original.selected.closure().objects(), &headers),
            object_limits,
            &mut live,
        ),
    };
    // Preserve the source's actual cancellation/budget failure instead
    // of disguising it as a missing object in the pack-source adapter.
    original.checkpoint().map_err(source_error)?;
    verified.map_err(NodeWorkspaceRefusal::MergeValidation)?;
    let pack_limits = PackLimits {
        max_total_expanded_bytes: limits.max_output_bytes,
        max_cached_bytes: limits.max_output_bytes,
        ..PackLimits::default()
    };
    let ids: Vec<_> = plan.objects.iter().map(|object| object.id).collect();
    let packed = PackPlanner::new(
        original.inner.object_format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        pack_limits.clone(),
    )
    .plan_selected(&candidate, &ids, &mut live)
    .map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
    let (pack, _) = PackWriter::new(pack_limits)
        .write(&packed, &mut live)
        .map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
    original.checkpoint().map_err(source_error)?;
    let mut bytes = match original.inner.object_format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    // Both original histories remain prerequisites. A squash may reuse source
    // blobs even though source is not a parent of its one-parent candidate.
    bytes.extend_from_slice(
        format!(
            "-{} target\n-{} source\n{} ",
            plan.target, plan.source, plan.commit
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(target.as_bytes());
    bytes.extend_from_slice(b"\n\n");
    bytes
        .try_reserve(pack.len())
        .map_err(|_| NodeWorkspaceRefusal::WorkspaceEditLimit)?;
    bytes.extend_from_slice(&pack);
    Ok(bytes)
}

const fn source_error(error: MergeSourceError) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::MergePreparation(PreparationError::Source(error))
}

struct SelectedSource<'a> {
    inner: VerifiedFabricPackSource<'a>,
    selected: &'a AuthoritySelectedClosure,
    ancestry: Option<AncestryMetadataAccess<'a>>,
    limits: ParseLimits,
    read_bytes: Cell<usize>,
    budget_failed: Cell<bool>,
}

impl SelectedSource<'_> {
    fn check_selected(&self, id: GitOid) -> Result<(), MergeSourceError> {
        self.checkpoint()?;
        if !self.selected.closure().objects().contains(&id) {
            return Err(MergeSourceError::OutsideSelection);
        }
        if id.is_zero() || id.algorithm() != self.inner.object_format {
            return Err(MergeSourceError::InvalidObject(id));
        }
        Ok(())
    }

    fn charge_read(&self, bytes: usize) -> Result<(), MergeSourceError> {
        let Some(total) = self
            .read_bytes
            .get()
            .checked_add(bytes)
            .filter(|n| *n <= MAX_READ_BYTES)
        else {
            self.budget_failed.set(true);
            return Err(MergeSourceError::BudgetExceeded);
        };
        self.read_bytes.set(total);
        Ok(())
    }

    fn retain_failure(&self, error: MergeSourceError) -> MergeSourceError {
        if error == MergeSourceError::BudgetExceeded {
            self.budget_failed.set(true);
        }
        error
    }

    fn read(
        &self,
        id: GitOid,
        expected: Option<ObjectType>,
    ) -> Result<(ObjectType, Vec<u8>), MergeSourceError> {
        self.check_selected(id)?;
        let read = self.inner.read_object(&id);
        self.checkpoint()?;
        let (kind, body) = read.map_err(|error| match error {
            PackWriteError::Pack(
                PackError::ObjectSizeLimit { .. } | PackError::AllocationFailed { .. },
            ) => {
                self.budget_failed.set(true);
                MergeSourceError::BudgetExceeded
            }
            _ => MergeSourceError::Unavailable(id),
        })?;
        self.charge_read(body.len())?;
        if expected.is_some_and(|expected| kind != expected)
            || git_object_id(self.inner.object_format, kind, &body) != id
        {
            return Err(MergeSourceError::InvalidObject(id));
        }
        #[cfg(test)]
        if kind == ObjectType::Commit
            && let Some(cache) = &self.ancestry
        {
            cache.record_body_read();
        }
        self.checkpoint()?;
        Ok((kind, body))
    }

    fn oid(&self, value: &[u8], owner: GitOid) -> Result<GitOid, MergeSourceError> {
        let value =
            std::str::from_utf8(value).map_err(|_| MergeSourceError::InvalidObject(owner))?;
        GitOid::from_hex(self.inner.object_format, &value.to_ascii_lowercase())
            .map_err(|_| MergeSourceError::InvalidObject(owner))
    }

    fn parse_error(&self, owner: GitOid, error: ObjectError) -> MergeSourceError {
        match error {
            ObjectError::ObjectTooLarge { .. }
            | ObjectError::TooManyTreeEntries { .. }
            | ObjectError::HeaderLimitExceeded { .. }
            | ObjectError::AllocationFailure => {
                self.budget_failed.set(true);
                MergeSourceError::BudgetExceeded
            }
            _ => MergeSourceError::InvalidObject(owner),
        }
    }
}

impl MergeObjectSource for SelectedSource<'_> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        if self.budget_failed.get() {
            return Err(MergeSourceError::BudgetExceeded);
        }
        match checkpoint_pack_context(self.inner.database_context) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: Some(_),
            } => Err(MergeSourceError::BudgetExceeded),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: None,
            } => Err(MergeSourceError::Cancelled),
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commit_with_date(id).map(|(commit, _)| commit)
    }
    fn commit_with_date(&self, id: GitOid) -> Result<(CommitInput, Option<i64>), MergeSourceError> {
        // A warm entry never grants membership or extends a current request's
        // byte/parser envelope. The graph algorithms still charge every visited
        // commit and edge, regardless of the source of this verified metadata.
        self.check_selected(id)?;
        if let Some(cache) = &self.ancestry
            && let Some(entry) = cache.lookup(id, &self.limits, self.inner.buffered_object_limit())
        {
            self.checkpoint()?;
            let entry = entry.map_err(|error| self.retain_failure(error))?;
            self.charge_read(entry.body_bytes())?;
            self.checkpoint()?;
            return Ok(entry.into_commit());
        }
        let (_, body) = self.read(id, Some(ObjectType::Commit))?;
        let entry = VerifiedCommitMetadata::parse(id, &body, &self.limits)
            .map_err(|error| self.retain_failure(error))?;
        self.checkpoint()?;
        if let Some(cache) = &self.ancestry {
            cache.insert(&entry);
        }
        self.checkpoint()?;
        Ok(entry.into_commit())
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        let (_, body) = self.read(id, Some(ObjectType::Tree))?;
        let ParsedObject::Tree(entries) = parse_object_body(
            ObjectType::Tree,
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &self.limits,
        )
        .map_err(|error| self.parse_error(id, error))?
        else {
            return Err(MergeSourceError::InvalidObject(id));
        };
        let mut output = Vec::with_capacity(entries.len());
        for entry in entries {
            self.checkpoint()?;
            let mode = std::str::from_utf8(&entry.mode)
                .ok()
                .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                .ok_or(MergeSourceError::InvalidObject(id))?;
            let hex: String = entry
                .object_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            output.push(MergeEntry {
                name: entry.name,
                mode,
                oid: self.oid(hex.as_bytes(), id)?,
            });
        }
        Ok(output)
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.read(id, Some(ObjectType::Blob)).map(|(_, body)| body)
    }
}

struct CandidateSource<'a, 'b> {
    original: &'a SelectedSource<'b>,
    generated: BTreeMap<GitOid, &'a PlannedMergeObject>,
}
impl FrontierObjectHeaders for CandidateSource<'_, '_> {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.header_with_blob_limit(id, self.original.inner.buffered_object_limit())
    }
}
struct CandidateFrontierHeaders<'a, 'b, 'c> {
    source: &'a CandidateSource<'b, 'c>,
    maximum_blob_bytes: usize,
}
impl FrontierObjectHeaders for CandidateFrontierHeaders<'_, '_, '_> {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.source
            .header_with_blob_limit(id, self.maximum_blob_bytes)
    }
}
impl CandidateSource<'_, '_> {
    fn header_with_blob_limit(
        &self,
        id: &GitOid,
        maximum_blob_bytes: usize,
    ) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.original
            .checkpoint()
            .map_err(|_| PackError::DeadlineExceeded)?;
        // Generated bytes keep full validation even if the same identity was
        // already present. Only admitted original objects use envelope metadata.
        if self.generated.contains_key(id) {
            return Ok(None);
        }
        if !self.original.selected.closure().objects().contains(id) {
            return Err(PackWriteError::MissingCanonicalObject(*id));
        }
        let result = read_frontier_header(&self.original.inner, id, maximum_blob_bytes);
        self.original
            .checkpoint()
            .map_err(|_| PackError::DeadlineExceeded)?;
        let header = result.inspect_err(|error| {
            if matches!(
                error,
                PackWriteError::Pack(
                    PackError::ObjectSizeLimit { .. } | PackError::AllocationFailed { .. }
                )
            ) {
                // Preserve the same shared resource classification as a body
                // read. The caller's post-validation checkpoint distinguishes
                // this exhaustion from an unavailable object dependency.
                self.original.budget_failed.set(true);
            }
        })?;
        Ok(Some(header))
    }
}
impl CanonicalObjectSource for CandidateSource<'_, '_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let map_error = |error| match error {
            MergeSourceError::Cancelled | MergeSourceError::BudgetExceeded => {
                PackWriteError::from(PackError::DeadlineExceeded)
            }
            _ => PackWriteError::MissingCanonicalObject(*id),
        };
        self.original.checkpoint().map_err(map_error)?;
        let (kind, body) = match self.generated.get(id) {
            Some(object) => (object.kind, object.body.clone()),
            None => self.original.read(*id, None).map_err(map_error)?,
        };
        Ok(CanonicalPackObject::new(*id, kind, body, Vec::new(), 0, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_admission::{
        AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
        SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
        validate_source_import,
    };
    use fgit_authority::IdempotencyKey;
    use fgit_forge::{ExpectedVersion, PullRequestNumber};
    use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
    use std::collections::BTreeSet;
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    pub(super) struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    pub(super) fn metadata() -> MergeMetadata {
        MergeMetadata {
            author: "Test <test@example.invalid>".into(),
            committer: "Test <test@example.invalid>".into(),
            timestamp: 1,
            message: b"reviewable merge\n".to_vec(),
        }
    }
    fn object(
        node: &OneNode,
        kind: ObjectType,
        bytes: Vec<u8>,
        ids: &mut BTreeSet<GitOid>,
    ) -> GitOid {
        let id = node.put_git_object(kind, bytes).unwrap().identity();
        ids.insert(id);
        id
    }
    fn tree(node: &OneNode, entries: &[(&str, GitOid)], ids: &mut BTreeSet<GitOid>) -> GitOid {
        let mut body = Vec::new();
        for (name, id) in entries {
            body.extend(format!("100644 {name}\0").as_bytes());
            body.extend(id.as_bytes());
        }
        object(node, ObjectType::Tree, body, ids)
    }
    fn commit(
        node: &OneNode,
        tree: GitOid,
        parents: &[GitOid],
        label: &str,
        ids: &mut BTreeSet<GitOid>,
    ) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").expect("writing to a String cannot fail");
        }
        write!(body, "author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}").expect("writing to a String cannot fail");
        object(node, ObjectType::Commit, body.into_bytes(), ids)
    }
    pub(super) fn fixture(
        format: GitHashAlgorithm,
        conflict: bool,
    ) -> (Scratch, OneNode, GitOid, GitOid) {
        fixture_with_rename(format, conflict, false)
    }
    pub(super) fn fixture_with_rename(
        format: GitHashAlgorithm,
        conflict: bool,
        rename: bool,
    ) -> (Scratch, OneNode, GitOid, GitOid) {
        fixture_with_preserved(
            format,
            conflict,
            rename,
            b"unchanged sibling\n".to_vec(),
            32 * 1024 * 1024,
        )
    }
    pub(super) fn fixture_with_preserved(
        format: GitHashAlgorithm,
        conflict: bool,
        rename: bool,
        preserved_body: Vec<u8>,
        maximum_object_bytes: u64,
    ) -> (Scratch, OneNode, GitOid, GitOid) {
        let root = std::env::temp_dir().join(format!(
            "fg-merge-prepare-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let (mut node, _) = OneNode::init(
            crate::NodeConfig::new(
                root.clone(),
                TenantId::from_bytes([0x71; 16]),
                RepositoryId::from_bytes([0x72; 16]),
            )
            .with_object_format(format)
            .with_max_object_bytes(maximum_object_bytes),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let mut ids = BTreeSet::new();
        let original = object(
            &node,
            ObjectType::Blob,
            b"a\nb\nc\nd\ne\n".to_vec(),
            &mut ids,
        );
        let ours = object(
            &node,
            ObjectType::Blob,
            b"A\nb\nc\nd\ne\n".to_vec(),
            &mut ids,
        );
        let theirs = object(
            &node,
            ObjectType::Blob,
            if conflict {
                b"X\nb\nc\nd\ne\n".to_vec()
            } else {
                b"a\nb\nc\nd\nE\n".to_vec()
            },
            &mut ids,
        );
        let preserved = object(&node, ObjectType::Blob, preserved_body, &mut ids);
        let bt = tree(&node, &[("keep", preserved), ("text", original)], &mut ids);
        let base = commit(&node, bt, &[], "base", &mut ids);
        let ot = tree(&node, &[("keep", preserved), ("text", ours)], &mut ids);
        let target = commit(&node, ot, &[base], "ours", &mut ids);
        let tt = if rename {
            tree(&node, &[("keep", preserved), ("moved", original)], &mut ids)
        } else {
            tree(&node, &[("keep", preserved), ("text", theirs)], &mut ids)
        };
        let incoming = commit(&node, tt, &[base], "theirs", &mut ids);
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        let updates = [
            SourceRefUpdate {
                old: zero,
                new: target,
                ref_name: b"refs/heads/main".to_vec(),
            },
            SourceRefUpdate {
                old: zero,
                new: incoming,
                ref_name: b"refs/heads/topic".to_vec(),
            },
        ];
        let receipt = SourceImportReceipt {
            object_format: format,
            object_count: u32::try_from(ids.len()).unwrap(),
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        };
        let closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                ids.clone(),
            ))
            .unwrap(),
            objects: ids,
        };
        let imported = validate_source_import(&updates, &receipt, closure).unwrap();
        let context = AdmissionContext {
            head_key: node.head_key.clone(),
            tenant_id: node.tenant_id,
            repository_id: node.repository_id,
            principal_id: PrincipalId::from_bytes([0x73; 16]),
            idempotency_key: IdempotencyKey::new(b"prepare-fixture".to_vec()).unwrap(),
            object_format: format,
        };
        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.admit_validated_source_import_durable_in(
                &request,
                &context,
                &imported,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(
            result.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        (Scratch(root), node, target, incoming)
    }

    #[test]
    fn selected_frontier_header_size_refusal_preserves_the_source_budget() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let (_scratch, node, target, _) = fixture(format, false);
            let request = node.request_context();
            let selected = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            let exhaustion = Cell::new(None);
            let mut original = SelectedSource {
                inner: VerifiedFabricPackSource {
                    fabric: &node.fabric,
                    object_format: format,
                    maximum_object_bytes: 32 * 1024 * 1024,
                    database_context: request.authority(),
                    database_exhaustion: &exhaustion,
                    session_is_live: None,
                },
                selected: selected.selected_closure(),
                ancestry: None,
                limits: ParseLimits {
                    tree_reference_bytes: format.digest_len(),
                    max_object_bytes: 32 * 1024 * 1024,
                    ..ParseLimits::default()
                },
                read_bytes: Cell::new(0),
                budget_failed: Cell::new(false),
            };
            {
                let source = CandidateSource {
                    original: &original,
                    generated: BTreeMap::new(),
                };
                let header = source.load_header(&target).unwrap().unwrap();
                assert_eq!(header.id, target);
                assert_eq!(header.object_type, ObjectType::Commit);
                assert!(header.body_bytes > 1);
                assert_eq!(original.checkpoint(), Ok(()));

                let missing =
                    git_object_id(format, ObjectType::Blob, b"outside the selected closure");
                assert!(matches!(
                    source.load_header(&missing),
                    Err(PackWriteError::MissingCanonicalObject(id)) if id == missing
                ));
                assert_eq!(original.checkpoint(), Ok(()));
            }
            // Read the same real admitted object's envelope under a smaller
            // source cap. No oversized allocation or synthetic fabric is used.
            original.inner.maximum_object_bytes = 1;
            original.limits.max_object_bytes = 1;
            let source = CandidateSource {
                original: &original,
                generated: BTreeMap::new(),
            };
            assert!(matches!(
                source.load_header(&target),
                Err(PackWriteError::Pack(PackError::ObjectSizeLimit {
                    limit: 1,
                    ..
                }))
            ));
            assert_eq!(original.checkpoint(), Err(MergeSourceError::BudgetExceeded));
        }
    }

    #[test]
    fn prepare_then_apply_uses_the_real_native_publication_path_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let (_scratch, node, target, incoming) = fixture(format, false);
            let request = node.request_context();
            let before = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            let target_ref = RefName::try_new(b"refs/heads/main").unwrap();
            let source_ref = RefName::try_new(b"refs/heads/topic").unwrap();
            let artifact = node
                .runtime()
                .block_on(node.prepare_merge_bundle_in(
                    &request,
                    &target_ref,
                    &source_ref,
                    &RefVisibility::new(),
                    &metadata(),
                    PreparationLimits::default(),
                ))
                .unwrap();
            assert_eq!(artifact.source_head, before.basis().id());
            let MergePreparation::Clean(plan) = artifact.outcome else {
                panic!("clean candidate required");
            };
            let bundle = artifact.bundle.unwrap();
            assert!(
                node.read_git_object(plan.commit).is_err(),
                "preparation must not stage its candidate"
            );
            assert_eq!(
                node.runtime()
                    .block_on(node.materialize_admission_in(&request))
                    .unwrap()
                    .basis(),
                before.basis()
            );
            let offset = bundle
                .windows(4)
                .position(|bytes| bytes == b"PACK")
                .unwrap();
            let pack = fgit_pack::read_verified_pack(
                &bundle[offset..],
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .unwrap();
            assert_eq!(pack.entries().len(), plan.objects.len());
            let merge = NativeMerge {
                source_ref,
                source_tip: incoming,
                base_tip: plan.base,
                target_ref: target_ref.clone(),
                target_tip_before: target,
                merge_commit: plan.commit,
            };
            let applied = node
                .runtime()
                .block_on(node.apply_merge_bundle_durable_in(
                    &request,
                    PrincipalId::from_bytes([0x73; 16]),
                    b"prepared-reviewed",
                    PullRequestNumber::FIRST,
                    ExpectedVersion::NewStream,
                    &merge,
                    &bundle,
                ))
                .unwrap();
            assert!(matches!(
                applied.1.outcome,
                DecisionOutcome::Committed { .. }
            ));
            let after = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            assert_eq!(after.snapshot().refs[&target_ref], plan.commit);
            assert_ne!(
                after.basis().body().forge_position_root,
                before.basis().body().forge_position_root
            );
            assert_ne!(
                after.basis().body().outbox_root,
                before.basis().body().outbox_root
            );
            let merged = plan
                .objects
                .iter()
                .find(|o| o.kind == ObjectType::Blob)
                .unwrap();
            assert_eq!(
                node.read_git_object(merged.id).unwrap().payload(),
                b"A\nb\nc\nd\nE\n"
            );
            assert_eq!(
                node.runtime()
                    .block_on(node.apply_merge_bundle_durable_in(
                        &request,
                        PrincipalId::from_bytes([0x73; 16]),
                        b"prepared-reviewed",
                        PullRequestNumber::FIRST,
                        ExpectedVersion::NewStream,
                        &merge,
                        &bundle
                    ))
                    .unwrap(),
                applied
            );
            node.shutdown().unwrap();
        }
    }

    #[test]
    fn conflicted_and_hidden_preparations_never_emit_a_bundle_or_move_authority() {
        let (_scratch, node, _, _) = fixture(GitHashAlgorithm::Sha1, true);
        let request = node.request_context();
        let target = RefName::try_new(b"refs/heads/main").unwrap();
        let incoming = RefName::try_new(b"refs/heads/topic").unwrap();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let artifact = node
            .runtime()
            .block_on(node.prepare_merge_bundle_in(
                &request,
                &target,
                &incoming,
                &RefVisibility::new(),
                &metadata(),
                PreparationLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            artifact.outcome,
            MergePreparation::Conflicted { .. }
        ));
        assert!(artifact.bundle.is_none());
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(b"refs/heads/topic", &fgit_wire::WireLimits::default())
            .unwrap();
        assert!(matches!(
            node.runtime().block_on(node.prepare_merge_bundle_in(
                &request,
                &target,
                &incoming,
                &hidden,
                &metadata(),
                PreparationLimits::default()
            )),
            Err(NodeWorkspaceRefusal::RefUnavailable)
        ));
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        node.shutdown().unwrap();
    }
}

#[cfg(test)]
#[path = "merge_prepare/rename_tests.rs"]
mod rename_tests;

#[cfg(test)]
#[path = "merge_prepare/ancestry_tests.rs"]
mod ancestry_tests;

#[cfg(test)]
#[path = "merge_prepare/frontier_reuse_tests.rs"]
mod frontier_reuse_tests;
