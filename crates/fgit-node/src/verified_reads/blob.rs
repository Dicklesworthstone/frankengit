//! A complete file proof from one authenticated, currently selected source
//! basis. Ref authorization precedes any ref lookup or object disclosure.

use super::{DisclosureScope, VerifiedReadServingRefusal};
use crate::{
    AdmissionMaterializationRefusal, NodeRequestContext, OneNode, PackContextCheckpoint,
    VerifiedFabricPackSource, checkpoint_pack_context,
};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body, parse_tree,
};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_verified_read::blob::{
    MAX_VERIFIED_BLOB_BYTES, MAX_VERIFIED_BLOB_METADATA_BYTES, MAX_VERIFIED_BLOB_TREE_ENTRIES,
    VerifiedBlobEnvelope, VerifiedBlobRefusal, blob_edge_oid, validate_blob_path,
    verify_blob_against_head_while,
};
use fgit_verified_read::{ReadResponse, RefDisclosurePolicy, VerifiedReadCapability};
use fgit_wire::visibility::RefVisibility;
use std::cell::Cell;

/// Typed refusal before the verified-blob transport can disclose a body.
#[derive(Debug)]
pub enum VerifiedBlobReadRefusal {
    InvalidRequest(Box<VerifiedBlobRefusal>),
    State(CellRefusal),
    Cancelled,
    RefUnavailable,
    PathUnavailable,
    SnapshotMoved,
    UnsupportedLayout,
    Materialization(Box<AdmissionMaterializationRefusal>),
    RefProof(Box<VerifiedReadServingRefusal>),
    ObjectUnavailable,
    Proof(Box<VerifiedBlobRefusal>),
}
impl std::fmt::Display for VerifiedBlobReadRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verified blob read refused: {self:?}")
    }
}
impl std::error::Error for VerifiedBlobReadRefusal {}

fn live(request: &NodeRequestContext) -> bool {
    !matches!(
        checkpoint_pack_context(request.authority()),
        PackContextCheckpoint::Stopped { .. }
    )
}
fn checkpoint(request: &NodeRequestContext) -> Result<(), VerifiedBlobReadRefusal> {
    if live(request) {
        Ok(())
    } else {
        Err(VerifiedBlobReadRefusal::Cancelled)
    }
}
fn proof_error(error: VerifiedBlobRefusal) -> VerifiedBlobReadRefusal {
    match error {
        VerifiedBlobRefusal::Cancelled => VerifiedBlobReadRefusal::Cancelled,
        other => VerifiedBlobReadRefusal::Proof(Box::new(other)),
    }
}

impl OneNode {
    /// Serves an exact current-head ref/path proof to an already authenticated
    /// repository reader. The caller supplies an additional deny-only visibility
    /// scope and an independently retained head pin; neither can broaden the
    /// canonical policy. A moved head refuses instead of selecting fresh bytes.
    ///
    /// This read-only boundary accepts no object identity, workspace, host path,
    /// approval, or publication key. Symlinks are complete data; gitlinks and
    /// directories are not blobs. Legacy whole-body ref roots refuse without
    /// revealing the ref-state map or fabric contents.
    pub async fn verified_blob_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        reference: &RefName,
        path: &[u8],
        expected_head: RepositoryAuthorityHeadId,
    ) -> Result<VerifiedBlobEnvelope, VerifiedBlobReadRefusal> {
        checkpoint(request)?;
        let components = validate_blob_path(path)
            .map_err(|e| VerifiedBlobReadRefusal::InvalidRequest(Box::new(e)))?;
        if visibility.hides(reference.as_bytes()) {
            return Err(VerifiedBlobReadRefusal::RefUnavailable);
        }
        admits_read(self.cell_state(), ReadMode::Current)
            .map_err(VerifiedBlobReadRefusal::State)?;
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| VerifiedBlobReadRefusal::Materialization(Box::new(e)))?;
        checkpoint(request)?;
        let scope = DisclosureScope {
            snapshot: &materialized.snapshot().hidden_refs,
            current: visibility,
            snapshot_refs: &materialized.snapshot().refs,
        };
        if !scope.permits_ref_disclosure(reference) {
            return Err(VerifiedBlobReadRefusal::RefUnavailable);
        }
        if materialized.basis().id() != expected_head {
            return Err(VerifiedBlobReadRefusal::SnapshotMoved);
        }
        if !materialized
            .root_layout()
            .admits_ref_state_membership_proof()
        {
            return Err(VerifiedBlobReadRefusal::UnsupportedLayout);
        }
        let commit_id = *materialized
            .snapshot()
            .refs
            .get(reference)
            .ok_or(VerifiedBlobReadRefusal::RefUnavailable)?;
        if commit_id.algorithm() != self.object_format {
            return Err(VerifiedBlobReadRefusal::ObjectUnavailable);
        }
        // This helper consumes exactly the selected materialization. Calling a
        // second current-read endpoint here would permit a mixed-head response.
        let response = self
            .serve_ref_verified_read_in(
                request,
                &materialized,
                &scope,
                VerifiedReadCapability::EnvelopeV1,
                reference.clone(),
            )
            .await
            .map_err(|e| VerifiedBlobReadRefusal::RefProof(Box::new(e)))?;
        checkpoint(request)?;
        let ReadResponse::Verified(ref_proof) = response else {
            return Err(VerifiedBlobReadRefusal::UnsupportedLayout);
        };
        let exhaustion = Cell::new(None);
        let is_live = || live(request);
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: MAX_VERIFIED_BLOB_BYTES
                .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: Some(&is_live),
        };
        let read = |id: GitOid, expected: ObjectType, remaining: usize| {
            checkpoint(request)?;
            if !materialized
                .selected_closure()
                .closure()
                .objects()
                .contains(&id)
            {
                return Err(VerifiedBlobReadRefusal::ObjectUnavailable);
            }
            let bounded = VerifiedFabricPackSource {
                maximum_object_bytes: source.maximum_object_bytes.min(remaining),
                ..source
            };
            let result = bounded.read_object(&id);
            checkpoint(request)?;
            let (kind, bytes) = result.map_err(|_| VerifiedBlobReadRefusal::ObjectUnavailable)?;
            if kind != expected {
                return Err(VerifiedBlobReadRefusal::ObjectUnavailable);
            }
            Ok(bytes)
        };
        let commit = read(
            commit_id,
            ObjectType::Commit,
            MAX_VERIFIED_BLOB_METADATA_BYTES,
        )?;
        let parse = |entries| ParseLimits {
            max_object_bytes: MAX_VERIFIED_BLOB_METADATA_BYTES,
            max_tree_entries: entries,
            tree_reference_bytes: self.object_format.digest_len(),
            ..ParseLimits::default()
        };
        let ParsedObject::Commit(parsed) = parse_object_body(
            ObjectType::Commit,
            &commit,
            AcceptanceProfile::GitCompatibleImport,
            &parse(0),
        )
        .map_err(|_| VerifiedBlobReadRefusal::ObjectUnavailable)?
        else {
            return Err(VerifiedBlobReadRefusal::ObjectUnavailable);
        };
        if parsed
            .headers()
            .iter()
            .filter(|header| header.name == b"tree")
            .count()
            != 1
        {
            return Err(VerifiedBlobReadRefusal::ObjectUnavailable);
        }
        let tree_text = parsed
            .tree_reference()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or(VerifiedBlobReadRefusal::ObjectUnavailable)?;
        let mut next = GitOid::from_hex(self.object_format, &tree_text.to_ascii_lowercase())
            .map_err(|_| VerifiedBlobReadRefusal::ObjectUnavailable)?;
        let mut remaining_bytes = MAX_VERIFIED_BLOB_METADATA_BYTES - commit.len();
        let mut remaining_entries = MAX_VERIFIED_BLOB_TREE_ENTRIES;
        let mut trees = Vec::with_capacity(components);
        for (index, component) in path.split(|byte| *byte == b'/').enumerate() {
            checkpoint(request)?;
            let body = read(next, ObjectType::Tree, remaining_bytes)?;
            remaining_bytes = remaining_bytes
                .checked_sub(body.len())
                .ok_or_else(|| proof_error(VerifiedBlobRefusal::BoundExceeded("metadata bytes")))?;
            let entries = parse_tree(
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &parse(remaining_entries),
            )
            .map_err(|_| VerifiedBlobReadRefusal::ObjectUnavailable)?;
            remaining_entries = remaining_entries
                .checked_sub(entries.len())
                .ok_or_else(|| proof_error(VerifiedBlobRefusal::BoundExceeded("tree entries")))?;
            checkpoint(request)?;
            let mut matching = entries.iter().filter(|entry| entry.name == component);
            let entry = matching
                .next()
                .ok_or(VerifiedBlobReadRefusal::PathUnavailable)?;
            if matching.next().is_some() {
                return Err(VerifiedBlobReadRefusal::ObjectUnavailable);
            }
            next = blob_edge_oid(self.object_format, &entry.object_id).map_err(proof_error)?;
            if index + 1 < components {
                if !entry.is_tree() {
                    return Err(VerifiedBlobReadRefusal::PathUnavailable);
                }
            } else if !matches!(entry.mode.as_slice(), b"100644" | b"100755" | b"120000") {
                return Err(VerifiedBlobReadRefusal::PathUnavailable);
            }
            trees.push(body);
        }
        let blob = read(next, ObjectType::Blob, MAX_VERIFIED_BLOB_BYTES)?;
        checkpoint(request)?;
        let envelope =
            VerifiedBlobEnvelope::from_parts(*ref_proof, path.to_vec(), commit, trees, blob)
                .map_err(proof_error)?;
        // The same independently usable verifier checks the final production
        // frame before it can leave the authenticated read boundary.
        verify_blob_against_head_while(expected_head, reference, path, &envelope, &is_live)
            .map_err(proof_error)?;
        checkpoint(request)?;
        Ok(envelope)
    }
}
