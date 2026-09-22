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
use fgit_pack::full_bundle::fetch::BundleRefMapping;
use fgit_pack::full_bundle::{FullBundle, FullBundleError, FullBundleInput, FullBundleLimits};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, Deadline, PackPlanner,
    PackWriteError, PackWriteProfile, PackWriter, QuarantinedPack,
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
mod incremental;

fn bundle_error(error: impl Into<FullBundleError>) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::FullBundle(Box::new(error.into()))
}

/// The ordinary selected-pack source intentionally omits closure hints because
/// filtered upload-pack selections must not be expanded. A full bundle needs
/// the real local edges for its independent no-extras/completeness check. Derive
/// them from the same verified bytes being packed, never from a second read or
/// caller-supplied hints. Selection still comes from current visible ref roots.
struct BundleObjectSource<'a, 'b>(&'a VerifiedFabricPackSource<'b>);
impl CanonicalObjectSource for BundleObjectSource<'_, '_> {
    fn load(&self, id: &fgit_types::GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self.0.read_object(id)?;
        let references = self.0.references_from_body(kind, &body)?;
        Ok(CanonicalPackObject::new(*id, kind, body, references, 0, 0))
    }
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
        .plan_selected(&BundleObjectSource(&source), &ids, &mut live)
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
        self.admit_full_git_bundle_in(request, session, input, None, None, limits)
            .await
    }

    /// Fetch explicitly selected bundle refs into exact destinations atomically.
    /// Each mapping requires absence or an exact old tip. Existing branches and
    /// remote-tracking refs must fast-forward through native commit parent edges;
    /// tags can be created or reasserted, never replaced. Unselected refs and
    /// their exclusive objects are not imported. This does not prune refs or
    /// rewrite HEAD, forge metadata, policy, or repository configuration.
    ///
    /// Complete supplied objects pass the same self-contained quarantine as
    /// import. No current object is borrowed to repair an incomplete bundle.
    /// Terminal replay precedes intake gates; new writes retain ordinary policy
    /// and exact-basis admission. An I/O failure does not prove non-commit.
    pub async fn fetch_full_git_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &[u8],
        mappings: &[BundleRefMapping],
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        self.admit_full_git_bundle_in(request, session, input, Some(mappings), None, limits)
            .await
    }

    /// Synchronize every advertised ref under explicit old-tip or absent leases.
    /// No implicit refresh or deletion. Caller authorization is required for
    /// exact-tip updates, including rewrites; mandatory repository policy remains.
    pub async fn import_incremental_git_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &[u8],
        expectations: &[(fgit_types::RefName, Option<fgit_types::GitOid>)],
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        self.admit_full_git_bundle_in(request, session, input, None, Some(expectations), limits)
            .await
    }

    async fn admit_full_git_bundle_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &[u8],
        mappings: Option<&[BundleRefMapping]>,
        expectations: Option<&[(fgit_types::RefName, Option<fgit_types::GitOid>)]>,
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
        // Advertisements and mutation commands have distinct bounds. Mapped
        // full fetch can select one command out of many advertised refs. The
        // incremental profile names every direct ref, plus at most one HEAD.
        if expectations.is_some() {
            bundle_limits.max_references = bundle_limits
                .max_references
                .min(limits.max_commands.saturating_add(1));
        }
        let bundle = if expectations.is_some() {
            FullBundleInput::parse_incremental(input, bundle_limits, &mut live)
        } else {
            FullBundleInput::parse(input, bundle_limits, &mut live)
        }
        .map_err(bundle_error)?;
        if bundle.format() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        let mut expected = std::collections::BTreeMap::new();
        if let Some(expectations) = expectations {
            if expectations.len() != bundle.references().len()
                || expectations.len() > limits.max_commands
            {
                return Err(bundle_error(FullBundleError::Invalid(
                    "one expectation per reference is required",
                )));
            }
            for (name, old) in expectations {
                if old.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format)
                    || expected.insert(name.clone(), *old).is_some()
                {
                    return Err(bundle_error(FullBundleError::Invalid(
                        "invalid or duplicate expected reference",
                    )));
                }
            }
            if bundle
                .references()
                .iter()
                .any(|r| !expected.contains_key(r.name()))
            {
                return Err(bundle_error(FullBundleError::Invalid(
                    "expectations differ from advertised reference set",
                )));
            }
        }
        let commands: Vec<_> = match mappings {
            Some(mappings) => bundle
                .select_updates(mappings, bundle_limits, &mut live)
                .map_err(bundle_error)?
                .into_iter()
                .map(|update| RefCommand {
                    name: update.destination,
                    expected_old: update
                        .expected_old
                        .map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
                    proposed_new: ProposedNew::Update(update.target),
                    force: false,
                })
                .collect(),
            None => bundle
                .references()
                .iter()
                .map(|reference| RefCommand {
                    name: reference.name().clone(),
                    expected_old: expected
                        .get(reference.name())
                        .copied()
                        .flatten()
                        .map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
                    proposed_new: ProposedNew::Update(*reference.target()),
                    force: false,
                })
                .collect(),
        };
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
        if (mappings.is_some() || expectations.is_some())
            && commands.iter().any(|command| {
                materialized
                    .snapshot()
                    .hidden_refs
                    .hides(command.name.as_bytes())
            })
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
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
        for (index, command) in commands.iter().enumerate() {
            let old = match command.expected_old {
                ExpectedOld::Absent => zero.clone(),
                ExpectedOld::Exactly(oid) => oid.to_string(),
                ExpectedOld::Unspecified => {
                    return Err(bundle_error(FullBundleError::Invalid(
                        "unspecified fetch expectation",
                    )));
                }
            };
            let ProposedNew::Update(new) = command.proposed_new else {
                return Err(bundle_error(FullBundleError::Invalid("bundle deletion")));
            };
            let mut data = format!("{old} {new} ").into_bytes();
            data.extend_from_slice(command.name.as_bytes());
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
            validator: FullValidator {
                inner: validator,
                fetch: mappings.is_some(),
                prerequisites: expectations.map(|_| bundle.prerequisites().to_vec()),
            },
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

struct FullValidator<'a> {
    inner: ProductionQuarantineValidator<'a>,
    fetch: bool,
    prerequisites: Option<Vec<fgit_types::GitOid>>,
}
impl QuarantineValidator for FullValidator<'_> {
    fn validate(
        &self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        if let Some(prerequisites) = &self.prerequisites {
            self.inner
                .validate_incremental_bundle(request, pack, receipt, prerequisites, deadline)
        } else if self.fetch {
            self.inner
                .validate_bundle_fetch(request, pack, receipt, deadline)
        } else {
            self.inner
                .validate_full_bundle(request, pack, receipt, deadline)
        }
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
