//! Exact patches become ordinary TreeFS intents, then a native candidate.
//! Preparation has no host workspace, subprocess, mutable repository or CAS.

use super::{NodeTreeSource, NodeWorkspaceRefusal, candidate, workspace_request_live};
use crate::{NodeRequestContext, OneNode, VerifiedFabricPackSource};
use fgit_crypto::{
    GitHashAlgorithm, GitObjectKind, NativeObjectIdentity, Sha1, Sha256, git_object_id,
    sha256_digest,
};
use fgit_forge::patch::{FileChange, IndexExpectation, PatchError, PatchLimits, UnifiedPatch};
use fgit_forge::preparation::MergeMetadata;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, parse_object_body, parse_tree};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_treefs::{
    BaseEntry, BaseError, BaseView, EntryClass, ExportLimits, FileMode, IntentLog, TreeCapability,
    TreeEditIntent, TreePath, WorkspaceId,
};
use fgit_types::{
    ByteCount, GitHashAlgorithm as ObjectFormat, GitOid, RefName, RepositoryCommitId,
};
use fgit_wire::visibility::RefVisibility;
use std::collections::{BTreeMap, BTreeSet};

mod binary;

const FETCH_BYTES: u64 = 256 * 1024 * 1024;
const FETCH_OBJECTS: u64 = 100_000;
const EXPORT_BYTES: usize = 64 * 1024 * 1024;
const EXPORT_OBJECTS: usize = 100_000;

/// Verified before/after file identities. Paths are raw repository bytes.
/// A rename contributes two entries: deletion at the source and creation at
/// the destination. Receipts are sorted by raw path and cover every tree effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchPathReceipt {
    pub path: Vec<u8>,
    pub old_blob: Option<GitOid>,
    pub new_blob: Option<GitOid>,
    pub new_mode: Option<u32>,
    pub hunks: usize,
}

/// An incremental single-parent Git bundle. This is not publication authority.
/// Review the native commit and use the ordinary workspace admission boundary.
#[derive(Debug)]
pub struct WorkspacePatchCandidate {
    pub object_format: ObjectFormat,
    pub source_commit: GitOid,
    pub source_rcr: RepositoryCommitId,
    pub candidate_commit: GitOid,
    pub root_tree: GitOid,
    pub patch_sha256: [u8; 32],
    pub paths: Vec<PatchPathReceipt>,
    pub object_count: usize,
    bundle: Vec<u8>,
}
impl WorkspacePatchCandidate {
    #[must_use]
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle
    }
}

const fn invalid(reason: &'static str) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::InvalidWorkspaceCandidate(reason)
}
const fn patch_error(error: PatchError) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspacePatch(error)
}
fn live(request: &NodeRequestContext) -> Result<(), NodeWorkspaceRefusal> {
    if workspace_request_live(request) {
        Ok(())
    } else {
        Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })
    }
}
const fn capability_error(error: fgit_treefs::CapabilityRefusal) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(error))
}
fn paths(patch: &UnifiedPatch<'_>) -> Result<Vec<TreePath>, NodeWorkspaceRefusal> {
    patch
        .files()
        .iter()
        .map(|file| {
            TreePath::parse_default(file.path()).map_err(|_| patch_error(PatchError::InvalidPath))
        })
        .collect()
}
/// Both sides of every relocation are mutation targets. Keeping this separate
/// from the destination vector avoids silently truncating the file/path zip.
fn touched_paths(patch: &UnifiedPatch<'_>) -> Result<Vec<TreePath>, NodeWorkspaceRefusal> {
    patch
        .files()
        .iter()
        .flat_map(|file| std::iter::once(file.path()).chain(file.renamed_from()))
        .map(|path| TreePath::parse_default(path).map_err(|_| patch_error(PatchError::InvalidPath)))
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|paths| paths.into_iter().collect())
}
fn authorize_patch(
    patch: &UnifiedPatch<'_>,
    capability: &TreeCapability,
    now: u64,
) -> Result<(), NodeWorkspaceRefusal> {
    // Write authorization also requires read scope, preventing hidden-source
    // disclosure and hidden-destination existence probes before any fetch.
    for path in touched_paths(patch)? {
        capability
            .authorize_write(&path, now)
            .map_err(capability_error)?;
    }
    Ok(())
}
fn preflight(
    reference: &RefName,
    expected: GitOid,
    format: ObjectFormat,
    metadata: &MergeMetadata,
) -> Result<(), NodeWorkspaceRefusal> {
    if !reference.as_bytes().starts_with(b"refs/heads/") || reference.as_bytes().len() > 4096 {
        return Err(invalid(
            "patch preparation requires a bounded full branch reference",
        ));
    }
    if expected.is_zero() || expected.algorithm() != format {
        return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
    }
    metadata
        .validate()
        .map_err(|_| invalid("patch commit metadata is invalid"))
}

impl OneNode {
    /// Apply an exact patch to the independently named current commit through
    /// a caller-owned capability. No path, ref, scope or privilege is derived
    /// from executable repository text. All target rights are checked before
    /// reading any file content; capabilities may only narrow disclosure.
    ///
    /// The existing exporter requires complete disclosure of each rebuilt
    /// directory so unselected siblings cannot be silently deleted. A narrow
    /// caller receives a refusal, never an implicitly widened capability.
    /// `index` records, when present, must match both verified blob identities.
    /// Explicit regular-file renames read the original source and produce a
    /// source deletion plus destination write in the same candidate. Occupied
    /// destinations, swaps and chains refuse; no sequential overwrite is inferred.
    /// Compressed literal/delta records use the native decoder with full old/new
    /// identities, verified reverse images, and one shared decode budget.
    /// All files must succeed before any candidate is returned. No fuzzy offsets,
    /// compressed rename, symlink, gitlink or copy is supported.
    pub async fn prepare_workspace_patch_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_commit: GitOid,
        visibility: &RefVisibility,
        capability: &mut TreeCapability,
        patch_bytes: &[u8],
        now: u64,
        metadata: &MergeMetadata,
        limits: PatchLimits,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        preflight(reference, expected_commit, self.object_format, metadata)?;
        let patch = UnifiedPatch::parse_with_binary_and_renames(patch_bytes, limits, &|| {
            !workspace_request_live(request)
        })
        .map_err(patch_error)?;
        let paths = paths(&patch)?;
        authorize_patch(&patch, capability, now)?;
        self.with_workspace_base_in::<A, _>(
            request,
            reference,
            visibility,
            capability,
            now,
            |base, source, capability| {
                prepare_at_base(
                    base,
                    source,
                    capability,
                    request,
                    reference,
                    expected_commit,
                    &patch,
                    &paths,
                    patch_bytes,
                    now,
                    metadata,
                )
            },
        )
        .await
    }

    /// Trusted local-owner adapter for callers authorized to read this entire
    /// repository. This is NOT a remote credential verifier or agent endpoint.
    /// It discovers complete root names solely to preserve unedited siblings;
    /// its write scope is limited to declared patch targets. All access retains
    /// hard shared read-byte/object limits, including root discovery. Agents
    /// must use `prepare_workspace_patch_in` with their existing capability.
    pub async fn prepare_trusted_patch_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_commit: GitOid,
        workspace_id: [u8; 16],
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
        limits: PatchLimits,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        match self.object_format {
            ObjectFormat::Sha1 => {
                self.prepare_trusted_patch_format::<Sha1>(
                    request,
                    reference,
                    expected_commit,
                    workspace_id,
                    patch_bytes,
                    metadata,
                    limits,
                )
                .await
            }
            ObjectFormat::Sha256 => {
                self.prepare_trusted_patch_format::<Sha256>(
                    request,
                    reference,
                    expected_commit,
                    workspace_id,
                    patch_bytes,
                    metadata,
                    limits,
                )
                .await
            }
        }
    }

    async fn prepare_trusted_patch_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_commit: GitOid,
        workspace_id: [u8; 16],
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
        limits: PatchLimits,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        preflight(reference, expected_commit, self.object_format, metadata)?;
        let patch = UnifiedPatch::parse_with_binary_and_renames(patch_bytes, limits, &|| {
            !workspace_request_live(request)
        })
        .map_err(patch_error)?;
        let paths = paths(&patch)?;
        let touched = touched_paths(&patch)?;
        let top = touched
            .iter()
            .map(|path| {
                TreePath::parse_default(
                    path.as_bytes()
                        .split(|byte| *byte == b'/')
                        .next()
                        .unwrap_or_default(),
                )
                .map_err(|_| patch_error(PatchError::InvalidPath))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut seed = budgeted(
            WorkspaceId::from_bytes(workspace_id),
            self.repository_id(),
            top.iter().cloned().collect(),
            touched.clone(),
            FETCH_BYTES,
            FETCH_OBJECTS,
        )?;
        self.with_workspace_base_in::<A, _>(
            request,
            reference,
            &RefVisibility::new(),
            &mut seed,
            0,
            |base, source, seed| {
                if expected_commit.as_bytes() != base.base_commit_oid().digest_bytes() {
                    return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
                }
                live(request)?;
                let grant = seed.authorize_root(0).map_err(capability_error)?;
                let root = base
                    .read_object(source, base.base_tree_oid(), GitObjectKind::Tree, &grant)
                    .map_err(NodeWorkspaceRefusal::Object)?;
                seed.charge_fetch(root.len() as u64)
                    .map_err(capability_error)?;
                let entries = parse_tree(
                    &root,
                    AcceptanceProfile::GitCompatibleImport,
                    &source.inner.parse_limits(),
                )
                .map_err(|_| invalid("source root cannot be exported"))?;
                let mut complete = top;
                for entry in entries {
                    live(request)?;
                    complete.insert(
                        TreePath::parse(&entry.name, base.path_policy())
                            .map_err(|_| invalid("source root has an unsupported path"))?,
                    );
                }
                let mut owner = budgeted(
                    seed.workspace_id(),
                    self.repository_id(),
                    complete.into_iter().collect(),
                    touched.clone(),
                    FETCH_BYTES.saturating_sub(seed.fetched_bytes()),
                    FETCH_OBJECTS.saturating_sub(seed.fetched_files()),
                )?;
                prepare_at_base(
                    base,
                    source,
                    &mut owner,
                    request,
                    reference,
                    expected_commit,
                    &patch,
                    &paths,
                    patch_bytes,
                    0,
                    metadata,
                )
            },
        )
        .await
    }
}

fn budgeted(
    id: WorkspaceId,
    repository: fgit_types::RepositoryId,
    reads: Vec<TreePath>,
    writes: Vec<TreePath>,
    bytes: u64,
    objects: u64,
) -> Result<TreeCapability, NodeWorkspaceRefusal> {
    let bytes = ByteCount::try_new("patch_fetch_bytes", bytes, FETCH_BYTES)
        .map_err(|_| patch_error(PatchError::Budget("read bytes")))?;
    Ok(TreeCapability::new(id, repository, reads, writes)
        .with_fetch_budget(bytes)
        .with_file_budget(objects))
}

fn prepare_at_base<A: GitHashAlgorithm>(
    base: &BaseView<A>,
    source: &NodeTreeSource<'_>,
    capability: &mut TreeCapability,
    request: &NodeRequestContext,
    reference: &RefName,
    expected_commit: GitOid,
    patch: &UnifiedPatch<'_>,
    paths: &[TreePath],
    patch_bytes: &[u8],
    now: u64,
    metadata: &MergeMetadata,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    live(request)?;
    if expected_commit.as_bytes() != base.base_commit_oid().digest_bytes() {
        return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
    }
    authorize_patch(patch, capability, now)?;
    let limits = patch.limits();
    let mut decoder =
        binary::Decoder::new(patch, source.inner.object_format).map_err(patch_error)?;
    let mut log = IntentLog::new();
    let mut receipts = Vec::with_capacity(paths.len());
    let mut total = 0usize;
    for (file, path) in patch.files().iter().zip(paths) {
        live(request)?;
        let source_path = TreePath::parse_default(file.source_path())
            .map_err(|_| patch_error(PatchError::InvalidPath))?;
        if file.renamed_from().is_some() {
            match base.resolve(source, capability, path, now) {
                Err(BaseError::NotFound { .. }) => {}
                Ok(_) => return Err(invalid("rename destination already exists")),
                Err(error) => {
                    return Err(NodeWorkspaceRefusal::Manifest(
                        fgit_treefs::SparseRefusal::Base(error),
                    ));
                }
            }
        }
        let existing = match base.resolve(source, capability, &source_path, now) {
            Ok(BaseEntry::File { oid, mode }) => {
                let mode = match FileMode::from_octal_bytes(&mode) {
                    Some(FileMode::Regular) => 0o100644,
                    Some(FileMode::Executable) => 0o100755,
                    None => return Err(patch_error(PatchError::SourceMode)),
                };
                let id = native_id(source.inner.object_format, oid.digest_bytes())?;
                Some((oid, id, mode))
            }
            Err(BaseError::NotFound { .. }) => None,
            Ok(_) => return Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit),
            Err(error) => {
                return Err(NodeWorkspaceRefusal::Manifest(
                    fgit_treefs::SparseRefusal::Base(error),
                ));
            }
        };
        if (file.change() == FileChange::Create) != existing.is_none() {
            return Err(patch_error(PatchError::SourcePresence));
        }
        let old_blob = existing.as_ref().map(|(_, id, _)| *id);
        if let Some(index) = file.index() {
            let old_hex = old_blob.map(|id| id.to_string());
            if !IndexExpectation::matches(&index.old, old_hex.as_deref().map(str::as_bytes)) {
                return Err(invalid(
                    "patch old index does not match the verified source blob",
                ));
            }
        }
        let input = match existing {
            Some((oid, _, mode)) => {
                let grant = capability
                    .authorize_read(&source_path, now)
                    .map_err(capability_error)?;
                // The first verified fabric read retains its configured
                // storage-envelope ceiling. Enforce the narrower patch limit
                // before copying that verified payload into the patch engine;
                // this does not replace the fabric's allocation policy.
                let bounded = NodeTreeSource {
                    inner: VerifiedFabricPackSource {
                        fabric: source.inner.fabric,
                        object_format: source.inner.object_format,
                        maximum_object_bytes: source
                            .inner
                            .maximum_object_bytes
                            .min(limits.max_file_bytes),
                        database_context: source.inner.database_context,
                        database_exhaustion: source.inner.database_exhaustion,
                        session_is_live: source.inner.session_is_live,
                    },
                    selected: source.selected,
                    workspace: source.workspace,
                };
                let body = base
                    .read_object(&bounded, &oid, GitObjectKind::Blob, &grant)
                    .map_err(NodeWorkspaceRefusal::Object)?;
                capability
                    .charge_fetch(body.len() as u64)
                    .map_err(capability_error)?;
                Some((mode, body))
            }
            None => None,
        };
        live(request)?;
        let output = decoder
            .apply(
                file,
                input
                    .as_ref()
                    .map(|(mode, bytes)| (*mode, bytes.as_slice())),
                limits,
                &|| !workspace_request_live(request),
            )
            .map_err(patch_error)?;
        let new_blob = output.as_ref().map(|file| {
            git_object_id(
                source.inner.object_format,
                GitObjectKind::Blob,
                &file.content,
            )
        });
        if let Some(index) = file.index() {
            let new_hex = new_blob.map(|id| id.to_string());
            if !IndexExpectation::matches(&index.new, new_hex.as_deref().map(str::as_bytes)) {
                return Err(invalid(
                    "patch new index does not match the exact result blob",
                ));
            }
        }
        // These are only in-memory intents. No source deletion becomes visible
        // unless every file validates, export succeeds and ordinary admission
        // later publishes the complete candidate through the existing CAS.
        let destination_old = if file.renamed_from().is_some() {
            receipts.push(PatchPathReceipt {
                path: source_path.as_bytes().to_vec(),
                old_blob,
                new_blob: None,
                new_mode: None,
                hunks: 0,
            });
            log.push(TreeEditIntent::Delete { path: source_path });
            None
        } else {
            old_blob
        };
        receipts.push(PatchPathReceipt {
            path: path.as_bytes().to_vec(),
            old_blob: destination_old,
            new_blob,
            new_mode: output.as_ref().map(|file| file.mode),
            hunks: file.hunk_count(),
        });
        match output {
            Some(file) => {
                total = total
                    .checked_add(file.content.len())
                    .filter(|bytes| *bytes <= limits.max_output_bytes)
                    .ok_or_else(|| patch_error(PatchError::Budget("aggregate result bytes")))?;
                log.push(TreeEditIntent::Write {
                    path: path.clone(),
                    content: file.content,
                    mode: if file.mode == 0o100755 {
                        FileMode::Executable
                    } else {
                        FileMode::Regular
                    },
                    entry_class: EntryClass::Content,
                });
            }
            None => log.push(TreeEditIntent::Delete { path: path.clone() }),
        }
    }
    live(request)?;
    receipts.sort_by(|left, right| left.path.cmp(&right.path));
    let export = candidate::export_from_base(
        base,
        source,
        capability,
        &log,
        expected_commit,
        now,
        ExportLimits {
            max_objects: EXPORT_OBJECTS,
            max_total_bytes: EXPORT_BYTES,
            max_tree_entries: EXPORT_OBJECTS,
        },
        &|| !workspace_request_live(request),
    )?;
    if export.plan.root_tree() == base.base_tree_oid() {
        return Err(invalid(
            "patch has no net tree change; no candidate was created",
        ));
    }
    pack(
        source.inner.object_format,
        reference,
        export,
        receipts,
        sha256_digest(patch_bytes),
        metadata,
        &|| workspace_request_live(request),
    )
}

fn native_id(format: ObjectFormat, bytes: &[u8]) -> Result<GitOid, NodeWorkspaceRefusal> {
    GitOid::from_hex(
        format,
        &bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    )
    .map_err(|_| NodeWorkspaceRefusal::ObjectFormatMismatch)
}
struct CandidateObjects(BTreeMap<GitOid, CanonicalPackObject>);
impl CanonicalObjectSource for CandidateObjects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
fn pack<A: GitHashAlgorithm>(
    format: ObjectFormat,
    reference: &RefName,
    export: candidate::WorkspaceEditExport<A>,
    paths: Vec<PatchPathReceipt>,
    patch_sha256: [u8; 32],
    metadata: &MergeMetadata,
    live: &dyn Fn() -> bool,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    let check = || {
        if live() {
            Ok(())
        } else {
            Err(patch_error(PatchError::Cancelled))
        }
    };
    check()?;
    let source_commit = native_id(format, export.source_commit.digest_bytes())?;
    let root_tree = native_id(format, export.plan.root_tree().digest_bytes())?;
    let mut body = format!(
        "tree {root_tree}\nparent {source_commit}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
        metadata.author, metadata.timestamp, metadata.committer, metadata.timestamp
    )
    .into_bytes();
    body.extend_from_slice(&metadata.message);
    let limits = PackLimits {
        max_input_bytes: 128 * 1024 * 1024,
        max_entries: u32::try_from(EXPORT_OBJECTS + 1)
            .map_err(|_| invalid("patch object count cannot be represented"))?,
        max_object_bytes: EXPORT_BYTES,
        max_total_expanded_bytes: EXPORT_BYTES + 1024 * 1024,
        ..PackLimits::default()
    };
    let parsing = ParseLimits {
        tree_reference_bytes: format.digest_len(),
        max_object_bytes: EXPORT_BYTES,
        ..ParseLimits::default()
    };
    parse_object_body(
        ObjectType::Commit,
        &body,
        AcceptanceProfile::StrictCreate,
        &parsing,
    )
    .map_err(|_| invalid("patch candidate commit is invalid"))?;
    let candidate_commit = git_object_id(format, GitObjectKind::Commit, &body);
    let mut objects = BTreeMap::new();
    for object in export.plan.objects() {
        check()?;
        let id = native_id(format, object.oid().digest_bytes())?;
        let refs = if object.kind() == GitObjectKind::Tree {
            parse_tree(object.body(), AcceptanceProfile::StrictCreate, &parsing)
                .map_err(|_| invalid("patch candidate tree is invalid"))?
                .into_iter()
                .filter(|entry| entry.mode != b"160000")
                .map(|entry| native_id(format, &entry.object_id))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        objects.insert(
            id,
            CanonicalPackObject::new(id, object.kind(), object.body().to_vec(), refs, 0, 0),
        );
    }
    objects.insert(
        candidate_commit,
        CanonicalPackObject::new(
            candidate_commit,
            ObjectType::Commit,
            body,
            vec![root_tree, source_commit],
            0,
            0,
        ),
    );
    let selected = objects.keys().copied().collect::<Vec<_>>();
    let mut running = || live();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&CandidateObjects(objects), &selected, &mut running)
    .map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
    let (pack, _) = PackWriter::new(limits)
        .write(&plan, &mut running)
        .map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
    let mut bundle = match format {
        ObjectFormat::Sha1 => b"# v2 git bundle\n".to_vec(),
        ObjectFormat::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle
        .extend_from_slice(format!("-{source_commit} patch base\n{candidate_commit} ").as_bytes());
    bundle.extend_from_slice(reference.as_bytes());
    bundle.extend_from_slice(b"\n\n");
    bundle.extend_from_slice(&pack);
    check()?;
    Ok(WorkspacePatchCandidate {
        object_format: format,
        source_commit,
        source_rcr: export.source_rcr,
        candidate_commit,
        root_tree,
        patch_sha256,
        paths,
        object_count: selected.len(),
        bundle,
    })
}
