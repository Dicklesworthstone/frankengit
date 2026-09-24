//! Native tag lifecycle over ordinary quarantine, exact-basis admission, and
//! verified immutable reads. No tag database or signature-derived authority.
use super::publication::receive_error;
use super::{NodeWorkspaceRefusal, workspace_request_live};
use crate::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode,
    VerifiedFabricPackSource, crypto_object_kind,
};
use fgit_admission::{AdmissionLimits, AdmissionResult, CommandOutcome, SessionMapping};
use fgit_authority::{
    ExpectedOld, OutcomeLookup, ProposedNew, RECEIVE_ADMISSION_SCHEMA, SealAttempt, SemanticRequest,
};
use fgit_crypto::GitObjectKind;
use fgit_forge::tags::{
    TagAnnotation, TagCommand, TagRead, TagReadLimits, TagRefusal, TagSignatureState,
    validate_tag_name,
};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, TagSignature, TagTargetType, parse_annotated_tag,
};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackPlanner, PackWriteError, PackWriteProfile,
    PackWriter,
};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::receive::{ReceiveContext, ReceiveLimits, SignedPushProfile};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::{Capabilities, GitObjectFormat, Packet, encode_packets};
use std::{cell::Cell, collections::BTreeSet};

const fn refused(reason: TagRefusal) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::Tag(reason)
}
fn checkpoint(request: &NodeRequestContext) -> Result<(), NodeWorkspaceRefusal> {
    if workspace_request_live(request) {
        Ok(())
    } else {
        Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })
    }
}

// Only newly constructed bytes are packed. Original targets are not loaded by
// this source: production quarantine independently proves their visibility,
// native kinds and selected authority membership before staging the annotation.
struct NewTagObject(Option<CanonicalPackObject>);
impl CanonicalObjectSource for NewTagObject {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .as_ref()
            .filter(|object| object.id() == *id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

impl OneNode {
    /// Create an annotated/lightweight tag or delete an exact old tag. Names
    /// are always refs/tags/*; replacement/force is not implicitly enabled.
    /// The embedding authenticates the trusted-local session before calling.
    /// Every new original target passes the existing visible-frontier proof.
    /// A declared annotated target kind is data to verify, never trusted proof.
    ///
    /// Exact decided retries recover before quota, cell, visibility or object
    /// checks; a changed command under the same key still fails seal binding.
    /// Objects are staged only by production quarantine; ordinary admission is
    /// the sole publication path. Infrastructure failure never proves abort.
    pub async fn admit_tag_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &TagCommand,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        let prepared = command.prepare(self.object_format).map_err(refused)?;
        let semantic = SemanticRequest::build(
            RECEIVE_ADMISSION_SCHEMA,
            self.object_format,
            true,
            vec![prepared.command.clone()],
            vec![],
            vec![],
        )
        .map_err(|_| refused(TagRefusal::InvalidObject))?;
        let attempt = SealAttempt {
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            authenticated_principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            request: semantic,
        };
        let admission_error =
            |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let (tx_id, _) = attempt.derive().map_err(|e| admission_error(e.into()))?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            self.tenant_id,
            self.repository_id,
            tx_id,
        )
        .await
        .map_err(|e| admission_error(e.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|e| admission_error(e.into()))?;
            return Ok(AdmissionResult {
                session: SessionMapping {
                    atomic: true,
                    tx_ids: vec![tx_id],
                },
                commands: vec![CommandOutcome { tx_id, terminal }],
            });
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| NodeWorkspaceRefusal::Authority(Box::new(e)))?;
        if selected
            .snapshot()
            .hidden_refs
            .hides(command.reference().as_bytes())
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        checkpoint(request)?;
        let mut receive_limits = ReceiveLimits::default();
        receive_limits.max_commands = 1;
        receive_limits.pack.max_object_bytes = receive_limits
            .pack
            .max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let parse_limits = ParseLimits {
            tree_reference_bytes: self.object_format.digest_len(),
            max_object_bytes: receive_limits.pack.max_object_bytes,
            ..ParseLimits::default()
        };
        let capability_bytes = format!(
            "report-status atomic delete-refs object-format={}",
            self.object_format.as_str()
        );
        let capabilities =
            Capabilities::parse_v1(capability_bytes.as_bytes(), &receive_limits.wire)
                .map_err(|_| refused(TagRefusal::InvalidObject))?;
        let zero = "0".repeat(self.object_format.digest_len() * 2);
        let old = match prepared.command.expected_old {
            ExpectedOld::Exactly(oid) => oid.to_string(),
            _ => zero.clone(),
        };
        let new = match prepared.command.proposed_new {
            ProposedNew::Update(oid) => oid.to_string(),
            ProposedNew::Delete => zero,
        };
        let mut line = format!("{old} {new} ").into_bytes();
        line.extend_from_slice(command.reference().as_bytes());
        line.push(0);
        line.extend_from_slice(capability_bytes.as_bytes());
        let mut input = encode_packets(&[Packet::Data(line), Packet::Flush], &receive_limits.wire)
            .map_err(|_| refused(TagRefusal::InvalidObject))?;
        let mut live = || workspace_request_live(request);
        if matches!(prepared.command.proposed_new, ProposedNew::Update(_)) {
            let ids = prepared
                .object
                .as_ref()
                .map(|object| vec![object.id])
                .unwrap_or_default();
            let source = NewTagObject(prepared.object.map(|object| {
                CanonicalPackObject::new(
                    object.id,
                    ObjectType::Tag,
                    object.body,
                    vec![object.target],
                    0,
                    0,
                )
            }));
            let plan = PackPlanner::new(
                self.object_format,
                PackWriteProfile::STORED_V1,
                receive_limits.pack.clone(),
            )
            .plan_selected(&source, &ids, &mut live)
            .map_err(|e| NodeWorkspaceRefusal::MergePack(Box::new(e)))?;
            let (pack, _) = PackWriter::new(receive_limits.pack.clone())
                .write(&plan, &mut live)
                .map_err(|e| NodeWorkspaceRefusal::MergePack(Box::new(e)))?;
            input.extend_from_slice(&pack);
        }
        let format = match self.object_format {
            GitHashAlgorithm::Sha1 => GitObjectFormat::Sha1,
            GitHashAlgorithm::Sha256 => GitObjectFormat::Sha256,
        };
        let context = ReceiveContext::new(
            format,
            capabilities,
            receive_limits,
            SignedPushProfile::Refuse,
        )
        .map_err(receive_error)?;
        self.receive_loopback_pack_durable_in(
            request,
            session,
            &selected,
            context,
            &input,
            parse_limits,
            limits,
            &mut live,
        )
        .await
        .map_err(receive_error)
    }

    /// Read and recursively peel one visible current tag at an exact snapshot.
    /// The caller's disclosure policy may only narrow canonical hidden refs.
    /// No arbitrary OID entrypoint is exposed. Every followed edge is bounded,
    /// identity-verified, and checked against its declared native target kind.
    /// Returned annotation bytes are original bytes; signature presence grants
    /// neither cryptographic verification nor trust. Reads never publish state.
    pub async fn read_tag_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: TagReadLimits,
    ) -> Result<TagRead, NodeWorkspaceRefusal> {
        validate_tag_name(reference).map_err(refused)?;
        limits.validate().map_err(refused)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if visibility.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| NodeWorkspaceRefusal::Authority(Box::new(e)))?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let head = selected.basis().id();
        if expected_head.is_some_and(|expected| expected != head) {
            return Err(refused(TagRefusal::SnapshotMoved));
        }
        let tip = *selected
            .snapshot()
            .refs
            .get(reference)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let (mut id, mut expected_kind, mut remaining) = (tip, None, limits.max_total_bytes);
        let mut seen = BTreeSet::new();
        let mut annotations = Vec::new();
        let exhaustion = Cell::new(None);
        loop {
            checkpoint(request)?;
            if !seen.insert(id) {
                return Err(refused(TagRefusal::Cycle));
            }
            if !selected
                .selected_closure()
                .closure()
                .objects()
                .contains(&id)
            {
                return Err(refused(TagRefusal::InvalidObject));
            }
            // Enforce the remaining total before decoding, including terminal
            // blobs/trees/commits. A legitimate zero-byte terminal is allowed.
            let source = VerifiedFabricPackSource {
                fabric: &self.fabric,
                object_format: self.object_format,
                maximum_object_bytes: limits
                    .max_object_bytes
                    .min(remaining)
                    .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            };
            let read = source.read_object(&id);
            checkpoint(request)?;
            let (kind, body) = read.map_err(|e| NodeWorkspaceRefusal::MergePack(Box::new(e)))?;
            remaining = remaining
                .checked_sub(body.len())
                .ok_or_else(|| refused(TagRefusal::Budget("total bytes")))?;
            let actual = crypto_object_kind(kind);
            if expected_kind.is_some_and(|expected| expected != actual) {
                return Err(refused(TagRefusal::TargetKindMismatch));
            }
            if kind != ObjectType::Tag {
                return Ok(TagRead {
                    head,
                    reference: reference.clone(),
                    tip,
                    peeled: id,
                    peeled_kind: actual,
                    annotations,
                });
            }
            if annotations.len() == limits.max_tags {
                return Err(refused(TagRefusal::Budget("tag depth")));
            }
            let parsed = parse_annotated_tag(
                &body,
                self.object_format,
                AcceptanceProfile::GitCompatibleImport,
                &source.parse_limits(),
            )
            .map_err(|_| refused(TagRefusal::InvalidObject))?;
            let target = parsed.target();
            if target.oid.is_zero() {
                return Err(refused(TagRefusal::InvalidObject));
            }
            let target_kind = match target.object_type {
                TagTargetType::Blob => GitObjectKind::Blob,
                TagTargetType::Tree => GitObjectKind::Tree,
                TagTargetType::Commit => GitObjectKind::Commit,
                TagTargetType::Tag => GitObjectKind::Tag,
            };
            let signature = match parsed.signature() {
                TagSignature::OpaqueUnverifiable(_) => TagSignatureState::OpaqueUnverifiable,
                TagSignature::Absent
                    if parsed
                        .message()
                        .windows(b"-----BEGIN ".len())
                        .any(|part| part == b"-----BEGIN ") =>
                {
                    TagSignatureState::OpaqueUnverifiable
                }
                TagSignature::Absent => TagSignatureState::Absent,
            };
            annotations.push(TagAnnotation {
                id,
                target: target.oid,
                target_kind,
                body,
                signature,
            });
            id = target.oid;
            expected_kind = Some(target_kind);
        }
    }
}

#[cfg(test)]
mod tests;
