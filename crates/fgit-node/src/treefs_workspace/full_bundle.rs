//! Offline Git transfer through selected objects and ordinary atomic admission.
//! Bundles move Git objects and direct refs, never forge state or credentials.

use super::publication::receive_error;
use super::{NodeWorkspaceRefusal, workspace_request_live};
use crate::quarantine_validator::ProductionQuarantineValidator;
use crate::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode,
    VerifiedFabricPackSource, selected_pack_ids,
};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive, CommandOutcome,
    QuarantineValidator, SessionMapping, ValidatedClosure, validate_receive_at_basis,
};
use fgit_authority::{
    ExpectedOld, OutcomeLookup, ProposedNew, RECEIVE_ADMISSION_SCHEMA, RefCommand, SealAttempt,
    SemanticRequest,
};
use fgit_chronicle::PublicationBasis;
use fgit_git_object::ParseLimits;
use fgit_pack::full_bundle::{FullBundle, FullBundleError, FullBundleInput, FullBundleLimits};
use fgit_pack::{
    BundleReference, Deadline, PackPlanner, PackWriteProfile, PackWriter, QuarantinedPack,
};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, RefusalCode, RepositoryAuthorityHeadId};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveError, ReceiveLimits, ReceivePack,
    ReceiveQuarantineHandoff, ReceiveRequest, SignedPushProfile,
};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::{Capabilities, GitObjectFormat, Packet, encode_packets};
use std::cell::Cell;

fn bundle_error(error: impl Into<FullBundleError>) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::FullBundle(Box::new(error.into()))
}

impl OneNode {
    /// Export the closure of all currently visible direct refs at one selected
    /// authority head. Caller visibility only narrows canonical hidden-ref rules.
    /// Retained/deleted-only objects are never used as extra export roots.
    /// No object, ref, forge event, outbox or authority state is changed.
    pub async fn export_full_git_bundle_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<(RepositoryAuthorityHeadId, FullBundle), NodeWorkspaceRefusal> {
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(bundle_error(FullBundleError::Invalid(
                "export snapshot moved",
            )));
        }
        let limits = FullBundleLimits::default();
        let mut references = Vec::new();
        for (name, tip) in &selected.snapshot().refs {
            if !workspace_request_live(request) {
                return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
            }
            if visibility.hides(name.as_bytes())
                || selected.snapshot().hidden_refs.hides(name.as_bytes())
            {
                continue;
            }
            if references.len() == limits.max_references {
                return Err(bundle_error(FullBundleError::Limit("references")));
            }
            references.push(BundleReference::new(*tip, name.clone()));
        }
        if references.is_empty() {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let head = selected.snapshot().head_target.as_ref().and_then(|name| {
            references
                .iter()
                .find(|reference| {
                    reference.name() == name && name.as_bytes().starts_with(b"refs/heads/")
                })
                .map(|reference| *reference.target())
        });
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
        let roots = references
            .iter()
            .map(|reference| *reference.target())
            .collect::<Vec<_>>();
        let ids = selected_pack_ids(
            &source,
            selected.selected_closure().closure(),
            Some(&roots),
            &[],
            &pack_limits,
        )
        .map_err(|error| NodeWorkspaceRefusal::BundleGraph(Box::new(error)))?;
        let mut live = || workspace_request_live(request);
        let plan = PackPlanner::new(
            self.object_format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            pack_limits.clone(),
        )
        .plan_selected(&source, &ids, &mut live)
        .map_err(bundle_error)?;
        let bundle = FullBundle::write(
            &references,
            head,
            &plan,
            &PackWriter::new(pack_limits),
            limits,
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

    /// Atomically establish every direct ref from a self-contained native Git
    /// bundle. Existing destination names are never overwritten, even when they
    /// already name the same object. HEAD is a transport hint, not a command to
    /// rewrite the destination's configuration. No forge metadata is imported.
    ///
    /// Authenticated exact terminal replay precedes current intake gates. Fresh
    /// intake reconstructs only supplied pack bytes, verifies every native edge,
    /// stages the complete closure, and uses ordinary expected-absent admission.
    /// A staging/transport error is not evidence of a terminal non-commit.
    pub async fn import_full_git_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &[u8],
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        let mut live = || workspace_request_live(request);
        let mut receive_limits = ReceiveLimits::default();
        let mut bundle_limits = FullBundleLimits::default();
        bundle_limits.max_references = bundle_limits
            .max_references
            .min(receive_limits.max_commands);
        let bundle =
            FullBundleInput::parse(input, bundle_limits, &mut live).map_err(bundle_error)?;
        if bundle.format() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        let commands: Vec<_> = bundle
            .references()
            .iter()
            .map(|reference| RefCommand {
                name: reference.name().clone(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(*reference.target()),
                force: false,
            })
            .collect();
        let semantic = SemanticRequest::build(
            RECEIVE_ADMISSION_SCHEMA,
            self.object_format,
            true,
            commands.clone(),
            vec![],
            vec![],
        )
        .map_err(|_| bundle_error(FullBundleError::Invalid("reference command set")))?;
        let attempt = SealAttempt {
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            authenticated_principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            request: semantic,
        };
        let admission_error =
            |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let (tx_id, _) = attempt
            .derive()
            .map_err(|error| admission_error(error.into()))?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            self.tenant_id,
            self.repository_id,
            tx_id,
        )
        .await
        .map_err(|error| admission_error(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| admission_error(error.into()))?;
            return Ok(AdmissionResult {
                session: SessionMapping {
                    atomic: true,
                    tx_ids: vec![tx_id],
                },
                commands: vec![CommandOutcome { tx_id, terminal }; commands.len()],
            });
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota
            .evaluate(&authenticated.principal_id())
            .map_err(receive_error)?;
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        receive_limits.pack.max_object_bytes = receive_limits
            .pack
            .max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let parse_limits = ParseLimits {
            tree_reference_bytes: self.object_format.digest_len(),
            max_object_bytes: receive_limits.pack.max_object_bytes,
            ..ParseLimits::default()
        };
        let validator = self
            .production_quarantine_validator(
                &materialized,
                receive_limits.pack.clone(),
                parse_limits,
            )
            .map_err(|code| receive_error(ReceiveError::AuthoritativeRefusal(code)))?;
        let capability_bytes = format!(
            "report-status atomic object-format={}",
            self.object_format.as_str()
        );
        let capabilities =
            Capabilities::parse_v1(capability_bytes.as_bytes(), &receive_limits.wire)
                .map_err(|_| bundle_error(FullBundleError::Invalid("receive capabilities")))?;
        let zero = "0".repeat(self.object_format.digest_len() * 2);
        let mut packets = Vec::with_capacity(commands.len() + 1);
        for (index, reference) in bundle.references().iter().enumerate() {
            let mut data = format!("{zero} {} ", reference.target()).into_bytes();
            data.extend_from_slice(reference.name().as_bytes());
            if index == 0 {
                data.push(0);
                data.extend_from_slice(capability_bytes.as_bytes());
            }
            packets.push(Packet::Data(data));
        }
        packets.push(Packet::Flush);
        let prefix = encode_packets(&packets, &receive_limits.wire)
            .map_err(|_| bundle_error(FullBundleError::Limit("reference wire envelope")))?;
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
        let mut receive = ReceivePack::new(context).map_err(receive_error)?;
        receive.push_bytes(&prefix).map_err(receive_error)?;
        receive
            .push_bytes(bundle.pack_bytes())
            .map_err(receive_error)?;
        let mut handoff = FullHandoff {
            validator: FullValidator(validator),
            basis: materialized.basis().clone(),
            validated: None,
        };
        receive
            .finish_with_handoff(&mut handoff, &mut live)
            .map_err(receive_error)?;
        let validated = handoff
            .validated
            .ok_or_else(|| receive_error(ReceiveError::HandoffProofMissing))?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        self.admit_basis_bound_validated_receive_durable_in(request, &context, &validated, limits)
            .await
            .map_err(admission_error)
    }
}

struct FullValidator<'a>(ProductionQuarantineValidator<'a>);
impl QuarantineValidator for FullValidator<'_> {
    fn validate(
        &self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        self.0
            .validate_full_bundle(request, pack, receipt, deadline)
    }
}
struct FullHandoff<'a> {
    validator: FullValidator<'a>,
    basis: PublicationBasis,
    validated: Option<BasisBoundValidatedReceive>,
}
impl ReceiveQuarantineHandoff for FullHandoff<'_> {
    fn handoff(
        &mut self,
        _: &ReceiveRequest,
        _: Option<&QuarantinedPack>,
        _: &QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        // This production profile requires an explicit cancellation owner.
        Err(ReceiveError::HandoffProofMissing)
    }
    fn handoff_with_deadline(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut dyn Deadline,
    ) -> Result<(), ReceiveError> {
        if self.validated.is_some() {
            return Err(ReceiveError::HandoffProofMissing);
        }
        let mut live = || deadline.checkpoint();
        self.validated = Some(
            validate_receive_at_basis(
                request,
                pack,
                receipt,
                &self.basis,
                &self.validator,
                &mut live,
            )
            .map_err(ReceiveError::AuthoritativeRefusal)?,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
