//! Read-only construction of an exact canonical queue prefix. Original PR
//! subjects remain distinct from the unpublished projected merge parents.

use std::cell::Cell;
use std::collections::BTreeSet;

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, ObjectFrontier, validate_merge_objects_above,
};
use fgit_admission::merge::native::{pull_request, queue};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::queue_prefix::{
    MAX_PREFIX_ENTRIES, PrefixInput, PrefixPreparation, PreparedPrefix, prepare_queue_prefix,
};
use fgit_forge::preparation::{MergeMetadata, MergeObjectSource, MergeProfile, PreparationLimits};
use fgit_forge::{AggregateVersion, ForgeEventPayload, QueueNumber};
use fgit_git_object::{AcceptanceProfile, ParseLimits, ParsedObject, parse_object_body};
use fgit_pack::{PackLimits, PackPlanner, PackWriteProfile, PackWriter, verify_native_object};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, RefName, RefusalCode, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use super::{CandidateFrontierHeaders, CandidateSource, SelectedSource, source_error};
use crate::ancestry_metadata::AncestryMetadataAccess;
use crate::treefs_workspace::workspace_request_live;
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode, VerifiedFabricPackSource};

/// Canonical original PR coordinates and explicit reproducible commit content.
/// A later entry still names the original target, never an unpublished parent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuePrefixEntry {
    pub subject: ReviewSubject,
    pub metadata: MergeMetadata,
}

/// An unpublished native artifact. No batch landing, review, successful check
/// or synthetic-ref publication is implied by this result or its digest.
#[derive(Debug)]
pub struct PreparedQueuePrefixBundle {
    pub number: QueueNumber,
    pub expected_version: AggregateVersion,
    pub source_head: RepositoryAuthorityHeadId,
    pub entries: Vec<QueuePrefixEntry>,
    pub profile: MergeProfile,
    pub preparation_id: Option<[u8; 32]>,
    pub outcome: PrefixPreparation,
    pub bundle: Option<Vec<u8>>,
}

impl OneNode {
    /// Construct every selected prefix member at one authenticated predecessor.
    /// A later conflict or already-integrated source stops the complete request:
    /// no shortened successful prefix, partial bundle or canonical effect returns.
    pub async fn prepare_queue_prefix_bundle_in(
        &self,
        request: &NodeRequestContext,
        number: QueueNumber,
        expected_version: AggregateVersion,
        entries: &[QueuePrefixEntry],
        visibility: &RefVisibility,
        limits: PreparationLimits,
        profile: MergeProfile,
    ) -> Result<PreparedQueuePrefixBundle, NodeWorkspaceRefusal> {
        limits
            .validate()
            .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        if entries.is_empty() || entries.len() > MAX_PREFIX_ENTRIES {
            return Err(invalid(
                "queue prefix requires one to sixteen original PR subjects",
            ));
        }
        let first = &entries[0].subject;
        let mut numbers = BTreeSet::new();
        for entry in entries {
            entry
                .subject
                .validate()
                .map_err(|_| invalid("invalid queue prefix subject"))?;
            entry
                .metadata
                .validate()
                .map_err(NodeWorkspaceRefusal::MergePreparation)?;
            if entry.subject.source_tip.algorithm() != self.object_format {
                return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
            }
            if !numbers.insert(entry.subject.pull_request)
                || entry.subject.target_ref != first.target_ref
                || entry.subject.target_tip != first.target_tip
                || entry.subject.policy_epoch != first.policy_epoch
            {
                return Err(invalid(
                    "queue prefix subjects must be distinct and share one original target and policy",
                ));
            }
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        let visible = |name: &RefName| {
            !visibility.hides(name.as_bytes())
                && !selected.snapshot().hidden_refs.hides(name.as_bytes())
        };
        // Check every requested name before reading a queue/PR or any object.
        if entries
            .iter()
            .any(|entry| !visible(&entry.subject.source_ref) || !visible(&entry.subject.target_ref))
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let queue = queue::read_queue_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            number,
            &visible,
            &|| !workspace_request_live(request),
        )
        .await
        .map_err(|error| {
            NodeWorkspaceRefusal::MergeValidation(
                error.into_projection_unavailable(RefusalCode::EvidenceInvalid),
            )
        })?
        .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        if queue.version != expected_version
            || queue.active_batch.is_some()
            || queue.target_ref != first.target_ref
            || queue.entries.len() < entries.len()
            || selected.basis().body().policy_epoch != first.policy_epoch
            || selected.snapshot().refs.get(&first.target_ref) != Some(&first.target_tip)
        {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        for (queued, entry) in queue.entries.iter().zip(entries) {
            let subject = &entry.subject;
            if queued.pull_request != subject.pull_request
                || queued.source_ref != subject.source_ref
                || queued.head_tip != subject.source_tip
                || selected.snapshot().refs.get(&subject.source_ref) != Some(&subject.source_tip)
            {
                return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
            }
            let mut page = pull_request::read_page_at(
                &self.authority,
                request.authority(),
                selected.basis(),
                subject.pull_request.get() - 1,
                1,
                &|source, target| visible(source) && visible(target),
                &|| !workspace_request_live(request),
            )
            .await
            .map_err(|error| {
                NodeWorkspaceRefusal::MergeValidation(
                    error.into_projection_unavailable(RefusalCode::EvidenceInvalid),
                )
            })?;
            let pr = page
                .pull_requests
                .pop()
                .filter(|pr| pr.number == subject.pull_request)
                .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
            let ForgeEventPayload::PullRequestChangedNative(change) = &pr.event.payload else {
                return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
            };
            if change.action == PullRequestAction::Close
                || pr.event.version != subject.pull_request_version
                || change.data.source_ref != subject.source_ref
                || change.data.target_ref != subject.target_ref
                || change.data.source_tip != subject.source_tip
                || change.data.target_tip != subject.target_tip
            {
                return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
            }
        }
        let exhaustion = Cell::new(None);
        let maximum = usize::try_from(self.max_object_bytes)
            .unwrap_or(usize::MAX)
            .min(32 * 1024 * 1024);
        // One source owns the aggregate read budget through graph construction,
        // strict validation and packing. No per-entry source budget is reset.
        let original = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric,
                object_format: self.object_format,
                maximum_object_bytes: maximum,
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
                max_object_bytes: maximum,
                ..ParseLimits::default()
            },
            read_bytes: Cell::new(0),
            budget_failed: Cell::new(false),
        };
        let inputs: Vec<_> = entries
            .iter()
            .map(|entry| PrefixInput {
                source: entry.subject.source_tip,
                metadata: &entry.metadata,
            })
            .collect();
        let outcome = prepare_queue_prefix(
            &original,
            self.object_format,
            first.target_tip,
            &inputs,
            limits,
            profile,
        )
        .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        let (bundle, preparation_id) = match &outcome {
            PrefixPreparation::Clean(plan) => {
                let bundle = prefix_bundle(
                    &original,
                    entries,
                    plan,
                    limits,
                    self.reused_merge_blob_limit(),
                )?;
                let id = preparation_identity(
                    &original,
                    self,
                    selected.basis().id(),
                    number,
                    expected_version,
                    entries,
                    profile,
                    plan,
                    &bundle,
                )?;
                (Some(bundle), Some(id))
            }
            PrefixPreparation::Stopped { .. } => (None, None),
        };
        original.checkpoint().map_err(source_error)?;
        Ok(PreparedQueuePrefixBundle {
            number,
            expected_version,
            source_head: selected.basis().id(),
            entries: entries.to_vec(),
            profile,
            preparation_id,
            outcome,
            bundle,
        })
    }
}

fn invalid(detail: &'static str) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::InvalidWorkspaceCandidate(detail)
}

fn prefix_bundle(
    original: &SelectedSource<'_>,
    entries: &[QueuePrefixEntry],
    plan: &PreparedPrefix,
    limits: PreparationLimits,
    maximum_reused_blob_bytes: usize,
) -> Result<Vec<u8>, NodeWorkspaceRefusal> {
    let first = &entries[0].subject;
    if plan.initial_target != first.target_tip || plan.steps.len() != entries.len() {
        return Err(invalid(
            "native prefix differs from original queue selection",
        ));
    }
    let candidate = CandidateSource {
        original,
        generated: plan
            .objects
            .iter()
            .map(|object| (object.id, object))
            .collect(),
    };
    if candidate.generated.len() != plan.objects.len() {
        return Err(invalid("duplicate generated prefix object"));
    }
    // Validate every native body exactly once; then compare every commit's real
    // ordered parents/tree against the planner's projected-chain receipt.
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
        .map_err(|_| invalid("constructed prefix object failed strict validation"))?;
    }
    let mut parent = plan.initial_target;
    for (entry, step) in entries.iter().zip(&plan.steps) {
        original.checkpoint().map_err(source_error)?;
        if step.source != entry.subject.source_tip || step.projected_target != parent {
            return Err(invalid(
                "projected prefix coordinates do not form the selected chain",
            ));
        }
        let object = candidate
            .generated
            .get(&step.commit)
            .ok_or_else(|| invalid("projected prefix commit is missing"))?;
        let ParsedObject::Commit(commit) = parse_object_body(
            object.kind,
            &object.body,
            AcceptanceProfile::StrictCreate,
            &original.limits,
        )
        .map_err(|_| invalid("invalid generated prefix commit"))?
        else {
            return Err(invalid("projected prefix object is not a commit"));
        };
        let parents = commit
            .parent_references()
            .map(|p| original.oid(p, object.id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(source_error)?;
        let tree = original
            .oid(
                commit
                    .tree_reference()
                    .ok_or_else(|| invalid("projected prefix commit has no tree"))?,
                object.id,
            )
            .map_err(source_error)?;
        if parents != [parent, step.source] || tree != step.tree {
            return Err(invalid(
                "native prefix parent order or tree differs from receipt",
            ));
        }
        parent = step.commit;
    }
    if parent != plan.final_commit {
        return Err(invalid("native prefix final commit differs from receipt"));
    }
    let last = plan
        .steps
        .last()
        .ok_or_else(|| invalid("empty prepared prefix"))?;
    let last_entry = entries
        .last()
        .ok_or_else(|| invalid("empty queue prefix"))?;
    let coordinates = NativeMerge {
        source_ref: last_entry.subject.source_ref.clone(),
        source_tip: last.source,
        target_ref: first.target_ref.clone(),
        target_tip_before: last.projected_target,
        base_tip: last.base,
        merge_commit: last.commit,
    };
    let headers = CandidateFrontierHeaders {
        source: &candidate,
        maximum_blob_bytes: maximum_reused_blob_bytes,
    };
    let mut live = || original.checkpoint().is_ok();
    // One closure walk includes every earlier candidate through the real first
    // parent chain. It never re-walks an ever-growing prefix for every PR.
    let verified = validate_merge_objects_above(
        &candidate,
        &coordinates,
        ObjectFrontier::with_headers(original.selected.closure().objects(), &headers),
        MergeObjectLimits {
            max_object_bytes: original.inner.buffered_object_limit(),
            max_reused_blob_bytes: maximum_reused_blob_bytes,
            ..MergeObjectLimits::default()
        },
        &mut live,
    );
    original.checkpoint().map_err(source_error)?;
    let verified = verified.map_err(NodeWorkspaceRefusal::MergeValidation)?;
    if plan.objects.iter().any(|object| {
        !verified.objects.contains(&object.id)
            && !original.selected.closure().objects().contains(&object.id)
    }) {
        return Err(invalid(
            "generated prefix object is outside the final candidate closure",
        ));
    }
    let pack_limits = PackLimits {
        max_entries: u32::try_from(limits.max_objects)
            .map_err(|_| NodeWorkspaceRefusal::WorkspaceEditLimit)?,
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
    .plan_selected(&candidate, &ids, &mut live);
    original.checkpoint().map_err(source_error)?;
    let packed = packed.map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
    let pack = PackWriter::new(pack_limits).write(&packed, &mut live);
    original.checkpoint().map_err(source_error)?;
    let (pack, _) = pack.map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
    let mut bundle = match original.inner.object_format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    let mut prerequisites = BTreeSet::from([plan.initial_target]);
    prerequisites.extend(entries.iter().map(|entry| entry.subject.source_tip));
    for prerequisite in prerequisites {
        bundle.extend_from_slice(format!("-{prerequisite} queue-input\n").as_bytes());
    }
    bundle.extend_from_slice(format!("{} ", plan.final_commit).as_bytes());
    bundle.extend_from_slice(first.target_ref.as_bytes());
    bundle.extend_from_slice(b"\n\n");
    if bundle
        .len()
        .checked_add(pack.len())
        .is_none_or(|n| n > limits.max_output_bytes)
    {
        return Err(NodeWorkspaceRefusal::WorkspaceEditLimit);
    }
    bundle
        .try_reserve_exact(pack.len())
        .map_err(|_| NodeWorkspaceRefusal::WorkspaceEditLimit)?;
    bundle.extend_from_slice(&pack);
    Ok(bundle)
}

fn preparation_identity(
    original: &SelectedSource<'_>,
    node: &OneNode,
    head: RepositoryAuthorityHeadId,
    number: QueueNumber,
    version: AggregateVersion,
    entries: &[QueuePrefixEntry],
    profile: MergeProfile,
    plan: &PreparedPrefix,
    bundle: &[u8],
) -> Result<[u8; 32], NodeWorkspaceRefusal> {
    let mut hash = Sha256Hasher::new();
    let part = |hash: &mut Sha256Hasher, bytes: &[u8]| -> Result<(), NodeWorkspaceRefusal> {
        original.checkpoint().map_err(source_error)?;
        hash.update(&(bytes.len() as u64).to_be_bytes());
        for chunk in bytes.chunks(16 * 1024) {
            original.checkpoint().map_err(source_error)?;
            hash.update(chunk);
        }
        Ok(())
    };
    part(&mut hash, b"frankengit/queue-prefix-preparation/v1")?;
    for value in [
        node.tenant_id.to_string(),
        node.repository_id.to_string(),
        node.repository_incarnation_id().to_string(),
        head.to_string(),
        node.object_format.as_str().to_owned(),
    ] {
        part(&mut hash, value.as_bytes())?;
    }
    hash.update(&number.get().to_be_bytes());
    hash.update(&version.get().to_be_bytes());
    hash.update(&[match profile {
        MergeProfile::PathMergeV1 => 1,
        MergeProfile::ExactRenamesV1 => 2,
    }]);
    hash.update(&(entries.len() as u64).to_be_bytes());
    for (entry, step) in entries.iter().zip(&plan.steps) {
        let subject = &entry.subject;
        hash.update(&subject.pull_request.get().to_be_bytes());
        hash.update(&subject.pull_request_version.get().to_be_bytes());
        hash.update(&subject.policy_epoch.get().to_be_bytes());
        part(&mut hash, subject.source_ref.as_bytes())?;
        part(&mut hash, subject.target_ref.as_bytes())?;
        for id in [
            subject.source_tip,
            subject.target_tip,
            step.projected_target,
            step.source,
            step.base,
            step.tree,
            step.commit,
        ] {
            part(&mut hash, id.to_string().as_bytes())?;
        }
        part(&mut hash, entry.metadata.author.as_bytes())?;
        part(&mut hash, entry.metadata.committer.as_bytes())?;
        hash.update(&entry.metadata.timestamp.to_be_bytes());
        part(&mut hash, &entry.metadata.message)?;
    }
    part(&mut hash, plan.initial_target.to_string().as_bytes())?;
    part(&mut hash, plan.final_commit.to_string().as_bytes())?;
    hash.update(&(bundle.len() as u64).to_be_bytes());
    let mut artifact = Sha256Hasher::new();
    for chunk in bundle.chunks(16 * 1024) {
        original.checkpoint().map_err(source_error)?;
        artifact.update(chunk);
    }
    hash.update(&artifact.finish());
    original.checkpoint().map_err(source_error)?;
    Ok(hash.finish())
}
