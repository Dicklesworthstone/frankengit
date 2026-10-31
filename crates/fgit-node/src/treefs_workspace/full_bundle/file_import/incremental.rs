//! Incremental file intake binds every borrowed native byte to its selecting
//! authority basis. Private original spans never masquerade as uploaded entries.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Seek};
use std::time::{Duration, Instant};

use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, BasisBoundValidatedSourceImport,
    CanonicalRefState, CommandOutcome, PermittedObjectClosure, SessionMapping, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, admit_basis_bound_source_import_async,
    permitted_object_closure_root, validate_source_import_at_basis,
};
use fgit_authority::{
    ExpectedOld, OutcomeLookup, ProposedNew, RECEIVE_ADMISSION_SCHEMA, RefCommand, SealAttempt,
    SemanticRequest,
};
use fgit_pack::full_bundle::{FullBundleHeader, StreamBundleHeaderError};
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RefName};

use crate::receive_staging::ReceiveStaging;
use crate::source_retrieval::integrity::bundle_verify::{
    BundleOriginalSource, BundleVerifyError, prepare_incremental_bundle_import_reader,
};
use crate::{LoopbackReceiveSession, NodeRequestContext, OneNode};

use super::originals::SelectedBundleOriginals;
use super::{
    MAX_BYTES, NodeReceiveTransportRefusal, NodeWorkspaceRefusal, StreamBundleImportQuery,
    StreamBundleImportRefusal, bounded_query, checkpoint, io_error, receive_error, rewind,
    stage_selected, workspace_request_live,
};

/// Independent uploaded-bundle and authenticated original-source allowances.
#[derive(Clone, Debug)]
pub struct StreamIncrementalBundleImportQuery {
    pub bundle: StreamBundleImportQuery,
    /// Original body bytes read during visible discovery and complete capture.
    /// This does not enlarge the uploaded pack's input or expansion allowance.
    pub max_original_bytes: usize,
}

impl Default for StreamIncrementalBundleImportQuery {
    fn default() -> Self {
        Self {
            bundle: StreamBundleImportQuery::default(),
            max_original_bytes: 128 * 1024 * 1024,
        }
    }
}

impl OneNode {
    /// Synchronize all advertised refs with exact old-tip or absent leases.
    /// Complete declared prerequisite history is selected from current visible
    /// refs and physically verified into private file custody. Native internal
    /// and prerequisite-scoped external deltas retain their actual provenance.
    /// Only selected uploaded objects are staged for ordinary atomic admission.
    ///
    /// An exact lease permits rewrites subject to current repository policy,
    /// matching buffered sync-import. The mapped full-fetch API has its own
    /// stricter fast-forward/tag profile. HEAD and forge state are not imported.
    pub async fn import_incremental_git_bundle_reader_durable_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        expectations: &[(RefName, Option<GitOid>)],
        query: StreamIncrementalBundleImportQuery,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        self.import_incremental_git_bundle_reader_controlled_in(
            request,
            session,
            input,
            expectations,
            query,
            limits,
            &mut || true,
        )
        .await
    }

    /// The same operation with one sticky stop probe and original request
    /// lifetime. Pending authority work is cancelled and drained; a completed
    /// terminal decision survives cancellation arriving after its publication.
    pub async fn import_incremental_git_bundle_reader_controlled_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        expectations: &[(RefName, Option<GitOid>)],
        query: StreamIncrementalBundleImportQuery,
        limits: AdmissionLimits,
        caller_live: &mut impl FnMut() -> bool,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        let timeout = query.bundle.timeout;
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(StreamBundleImportRefusal::InvalidQuery(
                "timeout must be in (0,3600 seconds]",
            ));
        }
        let started = Instant::now();
        let stopped = Cell::new(false);
        let gate = RefCell::new(|| {
            if stopped.get()
                || !caller_live()
                || started.elapsed() >= timeout
                || !workspace_request_live(request)
            {
                stopped.set(true);
                request.cancel();
                false
            } else {
                true
            }
        });
        let mut worker_live = || (gate.borrow_mut())();
        let operation = Box::pin(self.import_incremental_git_bundle_reader_inner(
            request,
            session,
            input,
            expectations,
            query,
            limits,
            &mut worker_live,
        ));
        super::super::streaming::drain_materialization(self, operation, started, timeout, || {
            let _ = (gate.borrow_mut())();
        })
        .await
    }

    async fn import_incremental_git_bundle_reader_inner<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        expectations: &[(RefName, Option<GitOid>)],
        query: StreamIncrementalBundleImportQuery,
        limits: AdmissionLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        checkpoint(live)?;
        let authenticated = session
            .authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        if query.max_original_bytes == 0 || query.max_original_bytes as u64 > MAX_BYTES {
            return Err(StreamBundleImportRefusal::InvalidQuery(
                "original-byte allowance must be in 1..=16 GiB",
            ));
        }
        let maximum_original_bytes = query.max_original_bytes;
        let query = bounded_query(self, query.bundle, &limits, true)?;
        rewind(input, live)?;
        let parsed = FullBundleHeader::read_incremental(
            &mut BufReader::new(&mut *input),
            query.limits.envelope,
            live,
        );
        checkpoint(live)?;
        let header = parsed.map_err(|error| match error {
            StreamBundleHeaderError::Io(error) => io_error("read incremental bundle header", error),
            StreamBundleHeaderError::Bundle(error) => BundleVerifyError::Envelope(error).into(),
        })?;
        if header.format() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch.into());
        }
        if header.references().is_empty()
            || expectations.len() != header.references().len()
            || expectations.len() > limits.command_limit(true)
        {
            return Err(StreamBundleImportRefusal::InvalidQuery(
                "one exact expectation per advertised reference is required",
            ));
        }
        let mut expected = BTreeMap::new();
        for (name, old) in expectations {
            checkpoint(live)?;
            if old.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format)
                || expected.insert(name.clone(), *old).is_some()
            {
                return Err(StreamBundleImportRefusal::InvalidQuery(
                    "invalid or duplicate expected reference",
                ));
            }
        }
        let mut commands = Vec::with_capacity(header.references().len());
        for reference in header.references() {
            checkpoint(live)?;
            let old =
                expected
                    .get(reference.name())
                    .ok_or(StreamBundleImportRefusal::InvalidQuery(
                        "expectations differ from advertised reference set",
                    ))?;
            commands.push(RefCommand {
                name: reference.name().clone(),
                expected_old: old.map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
                proposed_new: ProposedNew::Update(*reference.target()),
                force: false,
            });
        }
        let semantic = SemanticRequest::build(
            RECEIVE_ADMISSION_SCHEMA,
            self.object_format,
            true,
            commands.clone(),
            vec![],
            vec![],
        )
        .map_err(|_| StreamBundleImportRefusal::InvalidQuery("reference command set"))?;
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
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx_id)
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
        checkpoint(live)?;
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota
            .evaluate(&authenticated.principal_id())
            .map_err(receive_error)?;
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if commands.iter().any(|command| {
            materialized
                .snapshot()
                .hidden_refs
                .hides(command.name.as_bytes())
        }) {
            return Err(NodeWorkspaceRefusal::RefUnavailable.into());
        }
        checkpoint(live)?;
        let mut originals = SelectedBundleOriginals::new(
            self,
            request,
            &materialized,
            header.prerequisites(),
            &query.limits,
            maximum_original_bytes,
            live,
        )?;
        let original_closure =
            PermittedObjectClosure::new(originals.objects().keys().copied().collect());
        let prerequisite_closure_root = permitted_object_closure_root(&original_closure)
            .map_err(|_| StreamBundleImportRefusal::InvalidQuery("original closure"))?;
        rewind(input, live)?;
        let scratch = self.fabric.root().join("staging").join(format!(
            ".fg-bundle-incremental-{:032x}",
            std::random::random::<u128>(..),
        ));
        let mut plan = prepare_incremental_bundle_import_reader(
            input,
            self.object_format,
            &scratch,
            &mut originals,
            maximum_original_bytes,
            &query.limits,
            live,
        )?;
        let staging = ReceiveStaging::default();
        let prepared = (|| {
            checkpoint(live)?;
            if plan.header().raw_bytes() != header.raw_bytes() {
                return Err(BundleVerifyError::SourceChanged.into());
            }
            if plan.total_selected_bytes() > query.limits.pack.max_total_expanded_bytes as u64 {
                return Err(StreamBundleImportRefusal::InvalidQuery(
                    "selected uploaded byte limit",
                ));
            }
            let refs = header
                .references()
                .iter()
                .map(|reference| (reference.name().clone(), *reference.target()))
                .collect();
            crate::loose_import::preflight_import_metadata(
                self.object_format,
                plan.selected_ids().len(),
                &CanonicalRefState::new(refs),
                self.authority.limits().body_bytes,
                live,
            )
            .map_err(|error| StreamBundleImportRefusal::Metadata(Box::new(error)))?;
            let closure = PermittedObjectClosure::new(plan.selected_ids().clone());
            let object_closure_root = permitted_object_closure_root(&closure)
                .map_err(|_| StreamBundleImportRefusal::InvalidQuery("canonical object closure"))?;
            stage_selected(
                self,
                &mut plan,
                &staging,
                query.limits.max_streamed_blob_bytes,
                live,
            )?;
            let absent = match self.object_format {
                GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::ZERO),
                GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::ZERO),
            };
            let updates = header
                .references()
                .iter()
                .map(|reference| SourceRefUpdate {
                    old: expected
                        .get(reference.name())
                        .copied()
                        .flatten()
                        .unwrap_or(absent),
                    new: *reference.target(),
                    ref_name: reference.name().as_bytes().to_vec(),
                })
                .collect::<Vec<_>>();
            let receipt = SourceImportReceipt {
                object_format: self.object_format,
                object_count: u32::try_from(closure.objects().len()).map_err(|_| {
                    StreamBundleImportRefusal::InvalidQuery("selected object count")
                })?,
                delete_only: false,
                origin: SourceImportOrigin::IncrementalGitBundle {
                    pack_checksum: plan.receipt().trailer(),
                    pack_sha256: plan.receipt().pack_sha256(),
                    pack_bytes: plan.receipt().pack_bytes(),
                    prerequisite_closure_root,
                },
            };
            let validated = validate_source_import_at_basis(
                &updates,
                &receipt,
                ValidatedClosure {
                    object_closure_root,
                    objects: closure.objects().clone(),
                },
                materialized.basis(),
            )
            .map_err(|_| StreamBundleImportRefusal::InvalidQuery("basis-bound native closure"))?;
            Ok::<BasisBoundValidatedSourceImport, StreamBundleImportRefusal>(validated)
        })();
        let cleanup = plan.finish();
        let validated = match (prepared, cleanup) {
            (Ok(validated), Ok(())) => validated,
            (Err(cause), Ok(())) => return Err(cause),
            (Ok(_), Err(error)) => return Err(error.into()),
            (Err(cause), Err(cleanup)) => {
                return Err(StreamBundleImportRefusal::Cleanup {
                    cause: Box::new(cause),
                    cleanup,
                });
            }
        };
        checkpoint(live)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let projection = self
            .durable_admission_projection_publishing(&context, Some(&staging))
            .map_err(admission_error)?
            .with_authentication(authenticated.authentication());
        Box::pin(admit_basis_bound_source_import_async(
            &self.authority,
            request.authority(),
            &context,
            &validated,
            limits,
            &projection,
        ))
        .await
        .map_err(admission_error)
        .map_err(Into::into)
    }
}
