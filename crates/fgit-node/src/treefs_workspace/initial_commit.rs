//! Native absent-branch bootstrap. Preparation is read-only; publication uses
//! the existing full-bundle quarantine and expected-absent receive transaction.

use std::collections::BTreeMap;
use super::{NodeWorkspaceRefusal, workspace_request_live};
use super::publication::receive_error;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::{AdmissionLimits, AdmissionResult, CommandOutcome, SessionMapping};
use fgit_authority::{ExpectedOld, OutcomeLookup, ProposedNew, RefCommand, SealAttempt, SemanticRequest, RECEIVE_ADMISSION_SCHEMA};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::initial_commit::{InitialCommitPlan, MAX_INITIAL_OBJECTS, prepare_initial_commit};
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body, parse_tree};
use fgit_pack::full_bundle::{FullBundle, FullBundleInput, FullBundleLimits};
use fgit_pack::{BundleReference, CanonicalObjectSource, CanonicalPackObject, EntryKind,
    NativeChecksumVerifier, PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter, read_verified_pack};
use fgit_types::{GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_types::cell::{ReadMode, admits_read};

fn invalid(reason: &'static str) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::InvalidWorkspaceCandidate(reason)
}
fn check_reference(reference: &RefName) -> Result<(), NodeWorkspaceRefusal> {
    if reference.as_bytes().len() > 4096 || !reference.as_bytes().starts_with(b"refs/heads/") {
        return Err(invalid("initial commit requires a bounded full branch reference"));
    }
    Ok(())
}
fn pack_error(error: impl Into<fgit_pack::full_bundle::FullBundleError>) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::FullBundle(Box::new(error.into()))
}
struct Objects(BTreeMap<GitOid, CanonicalPackObject>);
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0.get(id).cloned().ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

impl OneNode {
    /// Construct a full, zero-parent commit bundle for an absent branch.
    /// This is an explicit trusted-local-owner boundary, not an agent grant or
    /// remote authentication endpoint. It reads only canonical metadata, never
    /// an existing source object or a host worktree. Other branches may exist;
    /// this creates independent history, never rewrites them or changes HEAD.
    ///
    /// `expected_head` optionally pins preparation's metadata read. Publication
    /// separately requires branch absence, allowing unrelated intervening work.
    /// No objects, refs, forge records, policy or retry seals are staged here.
    pub async fn prepare_trusted_initial_patch_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        patch: &[u8], metadata: &MergeMetadata, limits: PatchLimits,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<(RepositoryAuthorityHeadId, InitialCommitPlan, FullBundle), NodeWorkspaceRefusal> {
        check_reference(reference)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|e| NodeWorkspaceRefusal::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(invalid("initial commit preparation snapshot moved"));
        }
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        if selected.snapshot().refs.contains_key(reference) {
            return Err(invalid("initial commit destination branch already exists"));
        }
        let plan = prepare_initial_commit(self.object_format, patch, metadata, limits,
            &|| !workspace_request_live(request)).map_err(NodeWorkspaceRefusal::InitialCommit)?;
        let pack_limits = self.initial_commit_pack_limits();
        let parse_limits = ParseLimits { tree_reference_bytes: self.object_format.digest_len(),
            max_object_bytes: pack_limits.max_object_bytes, ..ParseLimits::default() };
        let mut objects = BTreeMap::new();
        let mut live = || workspace_request_live(request);
        for object in &plan.objects {
            if !live() { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }); }
            let references = match object.kind {
                GitObjectKind::Blob => Vec::new(),
                GitObjectKind::Tree => parse_tree(&object.body, AcceptanceProfile::StrictCreate, &parse_limits)
                    .map_err(|_| invalid("initial tree failed native validation"))?.into_iter()
                    .map(|entry| GitOid::from_hex(self.object_format,
                        &entry.object_id.iter().map(|b| format!("{b:02x}")).collect::<String>())
                        .map_err(|_| NodeWorkspaceRefusal::ObjectFormatMismatch))
                    .collect::<Result<Vec<_>, _>>()?,
                GitObjectKind::Commit => {
                    let ParsedObject::Commit(parsed) = parse_object_body(ObjectType::Commit, &object.body,
                        AcceptanceProfile::StrictCreate, &parse_limits)
                        .map_err(|_| invalid("initial commit failed native validation"))?
                    else { return Err(invalid("initial object kind mismatch")); };
                    if parsed.parent_references().next().is_some() || object.id != plan.commit {
                        return Err(invalid("initial candidate must contain one root commit"));
                    }
                    vec![plan.tree]
                }
                GitObjectKind::Tag => return Err(invalid("initial candidate cannot contain tags")),
            };
            objects.insert(object.id, CanonicalPackObject::new(object.id, object.kind,
                object.body.clone(), references, 0, 0));
        }
        let ids = objects.keys().copied().collect::<Vec<_>>();
        let pack = PackPlanner::new(self.object_format, PackWriteProfile::COMPRESSED_NO_DELTA_V1, pack_limits.clone())
            .plan_selected(&Objects(objects), &ids, &mut live).map_err(pack_error)?;
        let bundle = FullBundle::write(&[BundleReference::new(plan.commit, reference.clone())], None,
            &pack, &PackWriter::new(pack_limits), FullBundleLimits::default(), &mut live).map_err(pack_error)?;
        if !live() { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }); }
        Ok((selected.basis().id(), plan, bundle))
    }

    /// Publish exactly the independently reviewed zero-parent commit at an
    /// absent branch. The supplied full bundle must advertise only that branch
    /// and contain one commit plus regular-file trees/blobs, with no external
    /// prerequisites, tags, gitlinks, symlinks or delta entries in this profile.
    /// Full closure, native identities and current policy are still checked by
    /// production quarantine and the ordinary atomic receive admission path.
    ///
    /// The caller supplies a trusted authenticated session; repository bytes
    /// cannot select the principal. Exact terminal recovery precedes current
    /// intake and object checks. Recovery reconfirms the original semantic seal;
    /// it does not assert the retry transport bytes were decoded again. New
    /// requests never overwrite an existing branch, including an equal tip.
    pub async fn apply_initial_patch_bundle_durable_in(
        &self, request: &NodeRequestContext, session: &LoopbackReceiveSession,
        reference: &RefName, expected_commit: GitOid, input: &[u8], limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let authenticated = session.authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        check_reference(reference)?;
        if expected_commit.is_zero() || expected_commit.algorithm() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        let mut live = || workspace_request_live(request);
        let envelope = FullBundleInput::parse(input, FullBundleLimits { max_references: 1,
            ..FullBundleLimits::default() }, &mut live).map_err(pack_error)?;
        if envelope.format() != self.object_format { return Err(NodeWorkspaceRefusal::ObjectFormatMismatch); }
        let [advertised] = envelope.references() else { return Err(invalid("one initial branch is required")); };
        if advertised.name() != reference || advertised.target() != &expected_commit {
            return Err(invalid("initial bundle differs from independent branch/commit expectations"));
        }
        let semantic = SemanticRequest::build(RECEIVE_ADMISSION_SCHEMA, self.object_format, true,
            vec![RefCommand { name: reference.clone(), expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(expected_commit), force: false }], vec![], vec![])
            .map_err(|_| invalid("invalid initial ref transaction"))?;
        let attempt = SealAttempt { tenant_id: self.tenant_id, repository_id: self.repository_id,
            authenticated_principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(), request: semantic };
        let admission_error = |e| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(e)));
        let (tx_id, _) = attempt.derive().map_err(|e| admission_error(e.into()))?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id, self.repository_id, tx_id,
        ).await.map_err(|e| admission_error(e.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|e| admission_error(e.into()))?;
            return Ok(AdmissionResult { session: SessionMapping { atomic: true, tx_ids: vec![tx_id] },
                commands: vec![CommandOutcome { tx_id, terminal }] });
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&authenticated.principal_id()).map_err(receive_error)?;
        let pack_limits = self.initial_commit_pack_limits();
        let parsing = ParseLimits { tree_reference_bytes: self.object_format.digest_len(),
            max_object_bytes: pack_limits.max_object_bytes, ..ParseLimits::default() };
        // This complete, bounded read is quarantined local data only. The owning
        // receive validator below independently proves closure before staging.
        {
            let pack = read_verified_pack(envelope.pack_bytes(), self.object_format, &pack_limits,
                &mut live, &NativeChecksumVerifier).map_err(pack_error)?;
            let mut commits = 0usize;
            for entry in pack.entries() {
                if !live() { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }); }
                match entry.header.kind {
                    EntryKind::Commit => {
                        commits += 1;
                        if commits != 1 || git_object_id(self.object_format, GitObjectKind::Commit, &entry.inflated) != expected_commit {
                            return Err(invalid("initial bundle must contain only its reviewed root commit"));
                        }
                        let ParsedObject::Commit(commit) = parse_object_body(ObjectType::Commit, &entry.inflated,
                            AcceptanceProfile::StrictCreate, &parsing).map_err(|_| invalid("invalid initial commit bytes"))?
                        else { return Err(invalid("initial object is not a commit")); };
                        if commit.parent_references().next().is_some() { return Err(invalid("initial commit has a parent")); }
                    }
                    EntryKind::Tree => {
                        for child in parse_tree(&entry.inflated, AcceptanceProfile::StrictCreate, &parsing)
                            .map_err(|_| invalid("invalid initial tree"))? {
                            if !matches!(child.mode.as_slice(), b"40000" | b"100644" | b"100755")
                                || fgit_treefs::TreePath::parse_default(&child.name).is_err() {
                                return Err(invalid("initial tree contains a non-regular file or gitlink"));
                            }
                        }
                    }
                    EntryKind::Blob => {}
                    _ => return Err(invalid("initial profile excludes tags and delta entries")),
                }
            }
            if commits != 1 { return Err(invalid("initial root commit is missing")); }
        }
        self.import_full_git_bundle_durable_in(request, session, input, limits).await
    }

    fn initial_commit_pack_limits(&self) -> PackLimits {
        let mut limits = PackLimits::default();
        limits.max_entries = MAX_INITIAL_OBJECTS as u32;
        limits.max_object_bytes = limits.max_object_bytes.min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        limits.max_total_expanded_bytes = PatchLimits::default().max_output_bytes;
        limits
    }
}

#[cfg(test)]
mod tests;
