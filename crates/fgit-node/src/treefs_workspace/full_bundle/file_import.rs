//! Full native bundle intake through authenticated file custody and the ordinary
//! atomic source-import driver. No destination object can repair the input.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, CanonicalRefState, CommandOutcome,
    PermittedObjectClosure, SessionMapping, SourceImportOrigin, SourceImportReceipt,
    SourceRefUpdate, ValidatedClosure, ValidatedSourceImport, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::{
    ExpectedOld, OutcomeLookup, ProposedNew, RECEIVE_ADMISSION_SCHEMA, RefCommand, SealAttempt,
    SemanticRequest,
};
use fgit_crypto::{DigestHasher, IdentityDomain, Sha256Hasher};
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::VerifiedObject;
use fgit_pack::full_bundle::fetch::BundleRefMapping;
use fgit_pack::full_bundle::{FullBundleHeader, StreamBundleHeaderError};
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256};

use crate::receive_staging::ReceiveStaging;
use crate::source_retrieval::integrity::bundle_verify::{
    BundleVerifyError, BundleVerifyLimits, FullBundleImportPlan, prepare_full_bundle_fetch_reader,
    prepare_full_bundle_import_reader,
};
use crate::{LoopbackReceiveSession, NodeRefusal, NodeRequestContext, OneNode};

use super::{
    NodeReceiveTransportRefusal, NodeWorkspaceRefusal, receive_error, workspace_request_live,
};

mod fetch;

const MAX_BYTES: u64 = 16_384 * 1024 * 1024;
const METADATA_BATCH_BYTES: usize = 4 * 1024 * 1024;
const METADATA_BATCH_OBJECTS: usize = 64;

#[derive(Clone, Debug)]
pub struct StreamBundleImportQuery {
    pub limits: BundleVerifyLimits,
    /// One wall-clock allowance across verification, private staging and admission.
    pub timeout: Duration,
}

impl Default for StreamBundleImportQuery {
    fn default() -> Self {
        Self {
            limits: BundleVerifyLimits::default(),
            timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
pub enum StreamBundleImportRefusal {
    InvalidQuery(&'static str),
    Stopped,
    Verification(BundleVerifyError),
    Node(Box<NodeWorkspaceRefusal>),
    Storage(Box<NodeRefusal>),
    Metadata(Box<crate::LooseGitImportRefusal>),
    Cleanup {
        cause: Box<Self>,
        cleanup: BundleVerifyError,
    },
}

impl fmt::Display for StreamBundleImportRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuery(message) => write!(out, "file-backed bundle import: {message}"),
            Self::Stopped => out.write_str("bundle_import_stopped"),
            Self::Verification(error) => error.fmt(out),
            Self::Node(error) => error.fmt(out),
            Self::Storage(error) => error.fmt(out),
            Self::Metadata(error) => error.fmt(out),
            Self::Cleanup { cause, cleanup } => write!(out, "{cause}; scratch cleanup: {cleanup}"),
        }
    }
}
impl std::error::Error for StreamBundleImportRefusal {}
impl From<BundleVerifyError> for StreamBundleImportRefusal {
    fn from(error: BundleVerifyError) -> Self {
        Self::Verification(error)
    }
}
impl From<NodeWorkspaceRefusal> for StreamBundleImportRefusal {
    fn from(error: NodeWorkspaceRefusal) -> Self {
        Self::Node(Box::new(error))
    }
}
impl From<NodeRefusal> for StreamBundleImportRefusal {
    fn from(error: NodeRefusal) -> Self {
        Self::Storage(Box::new(error))
    }
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), StreamBundleImportRefusal> {
    if live() {
        Ok(())
    } else {
        Err(StreamBundleImportRefusal::Stopped)
    }
}

fn io_error(operation: &'static str, error: std::io::Error) -> StreamBundleImportRefusal {
    BundleVerifyError::Io {
        operation,
        kind: error.kind(),
    }
    .into()
}

fn rewind(
    input: &mut impl Seek,
    live: &mut impl FnMut() -> bool,
) -> Result<(), StreamBundleImportRefusal> {
    checkpoint(live)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind bundle import", error))?;
    checkpoint(live)
}

impl OneNode {
    /// Import a self-contained native full bundle through bounded file custody.
    /// Every advertised direct ref is created atomically with an absent lease.
    /// HEAD is an advertisement and does not change destination configuration.
    /// Internal native deltas are supported; prerequisites and external bases
    /// are refused. Metadata, blob, aggregate, graph and work limits are distinct.
    ///
    /// Historical terminal recovery precedes fresh payload intake and quota
    /// gates. New objects remain private until ordinary admission prepares a
    /// commit. Failure after publication starts does not establish non-commit.
    /// The caller owns any blocking input I/O timeout and source stability.
    pub async fn import_full_git_bundle_reader_durable_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        query: StreamBundleImportQuery,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        self.import_full_git_bundle_reader_controlled_in(
            request,
            session,
            input,
            query,
            limits,
            &mut || true,
        )
        .await
    }

    /// The same import with a caller-owned sticky stop probe. Pending authority
    /// operations are cancelled and drained through their original context.
    pub async fn import_full_git_bundle_reader_controlled_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        query: StreamBundleImportQuery,
        limits: AdmissionLimits,
        caller_live: &mut impl FnMut() -> bool,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        self.intake_full_git_bundle_reader_controlled_in(
            request,
            session,
            input,
            None,
            query,
            limits,
            caller_live,
        )
        .await
    }

    /// Fetch explicit full-bundle mappings through bounded file custody.
    /// Every mapping carries an absent or exact-old lease, and the entire set
    /// publishes atomically. Branches and remote refs require commits and native
    /// parent-edge fast-forwards; tags may only be created or reasserted.
    /// Only mapped closures and their transport bases enter candidate storage.
    /// Historical outcomes share the buffered fetch transaction identity.
    pub async fn fetch_full_git_bundle_reader_durable_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        mappings: &[BundleRefMapping],
        query: StreamBundleImportQuery,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        self.fetch_full_git_bundle_reader_controlled_in(
            request,
            session,
            input,
            mappings,
            query,
            limits,
            &mut || true,
        )
        .await
    }

    /// Mapped fetch with a caller-owned sticky stop probe. Pending admission
    /// keeps its original context and drains before private custody is released.
    /// A terminal decision remains valid when stop arrives after publication.
    pub async fn fetch_full_git_bundle_reader_controlled_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        mappings: &[BundleRefMapping],
        query: StreamBundleImportQuery,
        limits: AdmissionLimits,
        caller_live: &mut impl FnMut() -> bool,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        self.intake_full_git_bundle_reader_controlled_in(
            request,
            session,
            input,
            Some(mappings),
            query,
            limits,
            caller_live,
        )
        .await
    }

    async fn intake_full_git_bundle_reader_controlled_in<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        mappings: Option<&[BundleRefMapping]>,
        query: StreamBundleImportQuery,
        limits: AdmissionLimits,
        caller_live: &mut impl FnMut() -> bool,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        if query.timeout.is_zero() || query.timeout > Duration::from_secs(3600) {
            return Err(StreamBundleImportRefusal::InvalidQuery(
                "timeout must be in (0,3600 seconds]",
            ));
        }
        let started = Instant::now();
        let timeout = query.timeout;
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
        let operation = self.import_full_git_bundle_reader_inner(
            request,
            session,
            input,
            mappings,
            query,
            limits,
            &mut worker_live,
        );
        // Keep a completed terminal outcome even if stop arrives after its CAS.
        super::streaming::drain_materialization(self, operation, started, timeout, || {
            let _ = (gate.borrow_mut())();
        })
        .await
    }

    async fn import_full_git_bundle_reader_inner<R: Read + Seek>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        input: &mut R,
        mappings: Option<&[BundleRefMapping]>,
        mut query: StreamBundleImportQuery,
        limits: AdmissionLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<AdmissionResult, StreamBundleImportRefusal> {
        checkpoint(live)?;
        let authenticated = session
            .authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        for allowance in [
            query.limits.envelope.max_bundle_bytes,
            query.limits.pack.max_input_bytes,
            query.limits.pack.max_total_expanded_bytes,
            query.limits.max_streamed_blob_bytes,
        ] {
            if allowance == 0 || allowance as u64 > MAX_BYTES {
                return Err(StreamBundleImportRefusal::InvalidQuery(
                    "byte allowances must be in 1..=16 GiB",
                ));
            }
        }
        query.limits.pack.max_object_bytes = query
            .limits
            .pack
            .max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX))
            .min(crate::DEFAULT_MAX_OBJECT_BYTES as usize);
        query.limits.graph.max_object_bytes = query
            .limits
            .graph
            .max_object_bytes
            .min(query.limits.pack.max_object_bytes);
        query.limits.max_streamed_blob_bytes = query.limits.max_streamed_blob_bytes.min(
            self.service_config
                .bundle_import_blob_limit
                .unwrap_or_else(|| usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
        );
        query.limits.envelope.max_references = query
            .limits
            .envelope
            .max_references
            .min(fgit_wire::receive::ReceiveLimits::default().max_commands);
        // An explicit fetch can select one destination from a larger header.
        // Advertisement capacity and atomic command capacity are independent.
        if mappings.is_none() {
            query.limits.envelope.max_references = query
                .limits
                .envelope
                .max_references
                .min(limits.command_limit(true).saturating_add(1));
        }
        query.limits.graph.max_references = query
            .limits
            .graph
            .max_references
            .min(query.limits.envelope.max_references);

        rewind(input, live)?;
        let parsed = FullBundleHeader::read(
            &mut BufReader::new(&mut *input),
            query.limits.envelope,
            live,
        );
        checkpoint(live)?;
        let header = parsed.map_err(|error| match error {
            StreamBundleHeaderError::Io(error) => io_error("read bundle import header", error),
            StreamBundleHeaderError::Bundle(error) => BundleVerifyError::Envelope(error).into(),
        })?;
        if header.format() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch.into());
        }
        let commands: Vec<_> = if let Some(mappings) = mappings {
            if mappings.is_empty() || mappings.len() > limits.command_limit(true) {
                return Err(StreamBundleImportRefusal::InvalidQuery(
                    "reference command count",
                ));
            }
            let mapping_limits = fgit_pack::full_bundle::FullBundleLimits {
                max_references: limits
                    .command_limit(true)
                    .min(fgit_wire::receive::ReceiveLimits::default().max_commands),
                ..query.limits.envelope
            };
            header
                .select_updates(mappings, mapping_limits, live)
                .map_err(BundleVerifyError::Envelope)?
                .into_iter()
                .map(|update| RefCommand {
                    name: update.destination,
                    expected_old: update
                        .expected_old
                        .map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
                    proposed_new: ProposedNew::Update(update.target),
                    force: false,
                })
                .collect()
        } else {
            if header.references().is_empty()
                || header.references().len() > limits.command_limit(true)
            {
                return Err(StreamBundleImportRefusal::InvalidQuery(
                    "reference command count",
                ));
            }
            header
                .references()
                .iter()
                .map(|reference| RefCommand {
                    name: reference.name().clone(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(*reference.target()),
                    force: false,
                })
                .collect()
        };
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
        if mappings.is_some() {
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
        }
        checkpoint(live)?;
        rewind(input, live)?;
        // This new name is never inferred from a previous process or reused.
        // It is ordinary private scratch, never a fabric/authority object key.
        let scratch = self.fabric.root().join("staging").join(format!(
            ".fg-bundle-import-{:032x}",
            std::random::random::<u128>(..),
        ));
        let mut plan = if let Some(mappings) = mappings {
            let sources: Vec<_> = mappings
                .iter()
                .map(|mapping| mapping.source.clone())
                .collect();
            prepare_full_bundle_fetch_reader(
                input,
                self.object_format,
                &scratch,
                &sources,
                &query.limits,
                live,
            )?
        } else {
            prepare_full_bundle_import_reader(
                input,
                self.object_format,
                &scratch,
                &query.limits,
                live,
            )?
        };
        let staging = ReceiveStaging::default();
        let prepared = (|| {
            checkpoint(live)?;
            let expected: std::collections::BTreeMap<_, _> = header
                .references()
                .iter()
                .map(|reference| (reference.name().clone(), *reference.target()))
                .collect();
            if plan.verified().references() != &expected
                || plan.verified().advertised_head() != header.head()
            {
                return Err(BundleVerifyError::SourceChanged.into());
            }
            if plan.total_selected_bytes() > query.limits.pack.max_total_expanded_bytes as u64 {
                return Err(StreamBundleImportRefusal::InvalidQuery(
                    "selected payload byte limit",
                ));
            }
            let destinations = commands
                .iter()
                .map(|command| {
                    let ProposedNew::Update(target) = command.proposed_new else {
                        return Err(StreamBundleImportRefusal::InvalidQuery(
                            "full bundle update required",
                        ));
                    };
                    Ok((command.name.clone(), target))
                })
                .collect::<Result<_, StreamBundleImportRefusal>>()?;
            if mappings.is_some() {
                fetch::require_fast_forwards(&commands, &mut plan, &query.limits, live)?;
            }
            crate::loose_import::preflight_import_metadata(
                self.object_format,
                plan.selected_ids().len(),
                &CanonicalRefState::new(destinations),
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
            let updates: Vec<_> = commands
                .iter()
                .map(|command| {
                    let ProposedNew::Update(new) = command.proposed_new else {
                        return Err(StreamBundleImportRefusal::InvalidQuery(
                            "full bundle update required",
                        ));
                    };
                    let old = match command.expected_old {
                        ExpectedOld::Absent => absent,
                        ExpectedOld::Exactly(old) => old,
                        ExpectedOld::Unspecified => {
                            return Err(StreamBundleImportRefusal::InvalidQuery(
                                "exact lease required",
                            ));
                        }
                    };
                    Ok(SourceRefUpdate {
                        old,
                        new,
                        ref_name: command.name.as_bytes().to_vec(),
                    })
                })
                .collect::<Result<_, StreamBundleImportRefusal>>()?;
            let receipt = SourceImportReceipt {
                object_format: self.object_format,
                object_count: u32::try_from(closure.objects().len()).map_err(|_| {
                    StreamBundleImportRefusal::InvalidQuery("selected object count")
                })?,
                delete_only: false,
                origin: SourceImportOrigin::FullGitBundle {
                    pack_checksum: plan.receipt().trailer(),
                    pack_sha256: plan.receipt().pack_sha256(),
                    pack_bytes: plan.receipt().pack_bytes(),
                },
            };
            let validated = validate_source_import(
                &updates,
                &receipt,
                ValidatedClosure {
                    object_closure_root,
                    objects: closure.objects().clone(),
                },
            )
            .map_err(|_| StreamBundleImportRefusal::InvalidQuery("selected native closure"))?;
            Ok::<ValidatedSourceImport, StreamBundleImportRefusal>(validated)
        })();
        // Settle raw scratch before a canonical decision can become visible.
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
        // The full source supplies every candidate and ancestry byte. It borrows
        // no object from the earlier visibility snapshot. Ordinary admission
        // rechecks current hidden refs, exact leases and authenticated policy at
        // each publication attempt, including after an unrelated head change.
        self.admit_validated_source_import_with_authentication_publishing_in(
            request,
            &context,
            &validated,
            limits,
            Some(&staging),
            authenticated.authentication(),
        )
        .await
        .map_err(admission_error)
        .map_err(Into::into)
    }
}

fn stage_selected(
    node: &OneNode,
    plan: &mut FullBundleImportPlan,
    staging: &ReceiveStaging,
    maximum_blob_bytes: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), StreamBundleImportRefusal> {
    let ids = plan.selected_ids().clone();
    let mut pending = Vec::<VerifiedObject>::new();
    let mut pending_bytes = 0_usize;
    for id in ids {
        checkpoint(live)?;
        let object = plan
            .object(id)
            .ok_or(BundleVerifyError::ResolutionIncomplete)?;
        if object.kind == ObjectType::Blob {
            let commitment = blob_commitment(plan, id, object.length, live)?;
            let gate = RefCell::new(&mut *live);
            let mut reader_live = || (gate.borrow_mut())();
            let mut stage_live = || (gate.borrow_mut())();
            let mut reader = plan.open_blob(id, &mut reader_live)?;
            let staged = node.stage_synced_git_blob(
                id,
                object.length as u64,
                commitment,
                maximum_blob_bytes as u64,
                &mut reader,
                &mut stage_live,
            )?;
            drop(reader);
            staging.retain_synced_blob(staged)?;
        } else {
            if !pending.is_empty()
                && (pending.len() == METADATA_BATCH_OBJECTS
                    || pending_bytes.saturating_add(object.length) > METADATA_BATCH_BYTES)
            {
                staging.stage(node, &pending, live)?;
                pending.clear();
                pending_bytes = 0;
            }
            let body = plan.read_metadata(id, live)?;
            let verified = node.verified_git_object(object.kind, body)?;
            if verified.envelope().object_identity() != id {
                return Err(BundleVerifyError::SourceChanged.into());
            }
            pending_bytes = pending_bytes.checked_add(object.length).ok_or(
                StreamBundleImportRefusal::InvalidQuery("metadata batch overflow"),
            )?;
            pending.push(verified);
        }
        checkpoint(live)?;
    }
    staging.stage(node, &pending, live)?;
    checkpoint(live)
}

fn blob_commitment(
    plan: &mut FullBundleImportPlan,
    id: GitOid,
    length: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<[u8; 32], StreamBundleImportRefusal> {
    checkpoint(live)?;
    let header = format!("blob {length}\0");
    let bytes = (length as u64).checked_add(header.len() as u64).ok_or(
        StreamBundleImportRefusal::InvalidQuery("blob commitment length overflow"),
    )?;
    let mut strong = Sha256Hasher::new();
    strong.update(&fgit_crypto::internal_id_preimage_header(
        IdentityDomain::GitPayloadCommitment,
        fgit_crypto::GIT_PAYLOAD_SCHEMA,
        bytes,
    ));
    strong.update(header.as_bytes());
    let mut reader = plan.open_blob(id, live)?;
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(64 * 1024).map_err(|_| {
        io_error(
            "allocate original blob commitment buffer",
            std::io::ErrorKind::OutOfMemory.into(),
        )
    })?;
    buffer.resize(64 * 1024, 0);
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error("read original blob commitment", error)),
        };
        if count == 0 {
            break;
        }
        strong.update(&buffer[..count]);
    }
    drop(reader);
    checkpoint(live)?;
    Ok(strong.finish())
}
