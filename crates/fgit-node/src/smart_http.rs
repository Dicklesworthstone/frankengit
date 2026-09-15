//! Authority-backed Smart HTTP composition for one FrankenGit node.
//!
//! `fgit-wire` owns hostile HTTP/Git framing; an outer gateway owns credentials
//! and route selection. This module rechecks the canonical repository route and
//! then composes wire requests with the exact authority-selected admission and
//! disclosure machinery already used by the raw Git compatibility service.

use std::cell::Cell;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use fgit_wire::receive::{
    ReceiveCancellation, ReceiveContext, ReceiveError, ReceiveLimits, SignedPushProfile,
};
use fgit_wire::smart_http::rpc::{RpcError, UploadRpc, receive_discovery, upload_discovery};
use fgit_wire::smart_http::{
    HttpError, HttpLimits, Operation, ProtocolVersion, RequestHead, ResponseEncoder, Service,
    success_head,
};
use fgit_wire::{Capabilities, Packet, UploadPackRepository, WireError, WireLimits};

use super::{
    AdmissionUploadPackRepository, BudgetClass, GitDaemonSessionDeadline,
    GitDaemonTransportRefusal, LoopbackReceiveSession, NodeAdmissionViewRefusal,
    NodeGitDaemonServeRefusal, NodePackMaterializationRefusal, OneNode, PackContextCheckpoint,
    SELECTED_PACK_BUDGET_CLASS, SELECTED_PACK_MATERIALIZATION_OPERATION, checkpoint_pack_context,
    git_daemon_capabilities, selected_write_profile,
};

/// Complete successful Smart HTTP discovery response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSmartHttpDiscovery {
    head: String,
    body: Vec<u8>,
    version: ProtocolVersion,
}

impl NodeSmartHttpDiscovery {
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
}

/// Receipt for one fully emitted upload-pack RPC response.
///
/// This is transport evidence only. A successful read response is not a
/// repository publication and confers no write authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeSmartHttpUploadReceipt {
    version: ProtocolVersion,
    body_bytes: u64,
    pack_requested: bool,
}

impl NodeSmartHttpUploadReceipt {
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    #[must_use]
    pub const fn body_bytes(self) -> u64 {
        self.body_bytes
    }

    #[must_use]
    pub const fn pack_requested(self) -> bool {
        self.pack_requested
    }
}

/// Typed refusal at the node-owned Smart HTTP composition boundary.
#[derive(Debug)]
pub enum NodeSmartHttpRefusal {
    RepositoryRouteMismatch,
    UnsupportedOperation,
    /// Receive-pack discovery is never available without caller-authenticated identity.
    UnauthenticatedReceive,
    /// The HTTP body ended at its declared boundary while caller-owned bytes remained.
    TrailingRequestBytes {
        count: usize,
    },
    Admission(Box<NodeAdmissionViewRefusal>),
    Serve(Box<NodeGitDaemonServeRefusal>),
    Pack(Box<NodePackMaterializationRefusal>),
    Rpc(Box<RpcError>),
    Receive(Box<ReceiveError>),
    Http(Box<HttpError>),
    Wire(Box<WireError>),
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl Display for NodeSmartHttpRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryRouteMismatch => {
                formatter.write_str("smart HTTP route does not select this node repository")
            }
            Self::UnsupportedOperation => {
                formatter.write_str("smart HTTP operation is not served by this node entry point")
            }
            Self::UnauthenticatedReceive => {
                formatter.write_str("smart HTTP receive-pack requires an authenticated principal")
            }
            Self::TrailingRequestBytes { count } => {
                write!(
                    formatter,
                    "smart HTTP request retained {count} bytes past its body boundary"
                )
            }
            Self::Admission(error) => Display::fmt(error, formatter),
            Self::Serve(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
            Self::Rpc(error) => Display::fmt(error, formatter),
            Self::Receive(error) => Display::fmt(error, formatter),
            Self::Http(error) => Display::fmt(error, formatter),
            Self::Wire(error) => Display::fmt(error, formatter),
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
        }
    }
}

impl Error for NodeSmartHttpRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error.as_ref()),
            Self::Serve(error) => Some(error.as_ref()),
            Self::Pack(error) => Some(error.as_ref()),
            Self::Rpc(error) => Some(error.as_ref()),
            Self::Receive(error) => Some(error.as_ref()),
            Self::Http(error) => Some(error.as_ref()),
            Self::Wire(error) => Some(error.as_ref()),
            Self::Io { source, .. } => Some(source),
            Self::RepositoryRouteMismatch
            | Self::UnsupportedOperation
            | Self::UnauthenticatedReceive
            | Self::TrailingRequestBytes { .. } => None,
        }
    }
}

impl From<NodeAdmissionViewRefusal> for NodeSmartHttpRefusal {
    fn from(value: NodeAdmissionViewRefusal) -> Self {
        Self::Admission(Box::new(value))
    }
}
impl From<NodeGitDaemonServeRefusal> for NodeSmartHttpRefusal {
    fn from(value: NodeGitDaemonServeRefusal) -> Self {
        Self::Serve(Box::new(value))
    }
}
impl From<NodePackMaterializationRefusal> for NodeSmartHttpRefusal {
    fn from(value: NodePackMaterializationRefusal) -> Self {
        Self::Pack(Box::new(value))
    }
}
impl From<RpcError> for NodeSmartHttpRefusal {
    fn from(value: RpcError) -> Self {
        Self::Rpc(Box::new(value))
    }
}
impl From<ReceiveError> for NodeSmartHttpRefusal {
    fn from(value: ReceiveError) -> Self {
        Self::Receive(Box::new(value))
    }
}
impl From<HttpError> for NodeSmartHttpRefusal {
    fn from(value: HttpError) -> Self {
        Self::Http(Box::new(value))
    }
}
impl From<WireError> for NodeSmartHttpRefusal {
    fn from(value: WireError) -> Self {
        Self::Wire(Box::new(value))
    }
}

fn upload_capabilities(
    node: &OneNode,
    repository: &AdmissionUploadPackRepository,
    version: ProtocolVersion,
    limits: &WireLimits,
) -> Result<Capabilities, NodeSmartHttpRefusal> {
    if version != ProtocolVersion::V2 {
        let encoded =
            git_daemon_capabilities(node.object_format, repository.symref_target(b"HEAD"));
        return Capabilities::parse_v1(&encoded, limits).map_err(NodeSmartHttpRefusal::from);
    }
    let object_format = match repository.object_format() {
        fgit_wire::GitObjectFormat::Sha1 => "sha1",
        fgit_wire::GitObjectFormat::Sha256 => "sha256",
    };
    let fetch = match repository.supports_shallow() {
        true => b"fetch=shallow filter\n".as_slice(),
        false => b"fetch=filter\n".as_slice(),
    };
    let packets = vec![
        Packet::Data(b"version 2\n".to_vec()),
        Packet::Data(b"ls-refs\n".to_vec()),
        Packet::Data(fetch.to_vec()),
        Packet::Data(format!("object-format={object_format}\n").into_bytes()),
        Packet::Flush,
    ];
    Capabilities::parse_v2_advertisement(&packets, limits).map_err(NodeSmartHttpRefusal::from)
}

fn write_response_part<W: Write>(
    writer: &mut W,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), NodeSmartHttpRefusal> {
    writer
        .write_all(bytes)
        .map_err(|source| NodeSmartHttpRefusal::Io { operation, source })
}

impl OneNode {
    fn smart_http_route_matches(&self, request: &RequestHead<'_>) -> bool {
        request.repository_route.as_bytes() == self.git_daemon_repository_path.as_bytes()
    }

    /// Build one complete upload-pack discovery response from authenticated
    /// canonical state.
    pub fn smart_http_upload_discovery_in(
        &self,
        request: &RequestHead<'_>,
        limits: WireLimits,
    ) -> Result<NodeSmartHttpDiscovery, NodeSmartHttpRefusal> {
        if !self.smart_http_route_matches(request) {
            return Err(NodeSmartHttpRefusal::RepositoryRouteMismatch);
        }
        if request.operation != Operation::Discover(Service::UploadPack) {
            return Err(NodeSmartHttpRefusal::UnsupportedOperation);
        }
        let node_request = self.request_context();
        let repository = self
            .runtime
            .block_on(self.durable_admission_upload_pack_repository_in(&node_request, &limits))
            .map_err(NodeSmartHttpRefusal::from)?;
        let capabilities =
            upload_capabilities(self, &repository, request.requested_version, &limits)?;
        let body = upload_discovery(
            &repository,
            capabilities,
            request.requested_version,
            &limits,
        )?;
        let length = u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
        Ok(NodeSmartHttpDiscovery {
            head: success_head(request, Some(length)),
            body,
            version: request.requested_version,
        })
    }

    /// Serve one complete stateless upload-pack RPC from the same authenticated
    /// publication basis used for ref disclosure and pack selection.
    ///
    /// `body_wire` starts at the HTTP body boundary and may include chunk
    /// framing. Bytes after the declared body are never consumed as a second
    /// command: their presence is refused before any response is written.
    /// Likewise, a requested pack is fully selected and verified before the
    /// success header is emitted. The HTTP body itself remains pull-driven and
    /// bounded while it is written.
    pub fn smart_http_upload_rpc_in<W, C>(
        &self,
        request: &RequestHead<'_>,
        body_wire: &[u8],
        wire_limits: WireLimits,
        http_limits: HttpLimits,
        maximum_response_bytes: u64,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<NodeSmartHttpUploadReceipt, NodeSmartHttpRefusal>
    where
        W: Write,
        C: ReceiveCancellation,
    {
        if !self.smart_http_route_matches(request) {
            return Err(NodeSmartHttpRefusal::RepositoryRouteMismatch);
        }
        if request.operation != Operation::Rpc(Service::UploadPack) {
            return Err(NodeSmartHttpRefusal::UnsupportedOperation);
        }
        if !cancellation.checkpoint() {
            return Err(RpcError::Cancelled.into());
        }

        let deadline = GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        deadline
            .check("materialize smart HTTP admission")
            .map_err(NodeGitDaemonServeRefusal::from)?;
        let node_request = self.request_context();
        let admission_deadline_expired = AtomicBool::new(false);
        let admission_is_live = || {
            if deadline.expired() {
                admission_deadline_expired.store(true, Ordering::Relaxed);
                return false;
            }
            true
        };
        let materialized = self
            .runtime
            .block_on(self.materialize_admission_while_in(&node_request, &admission_is_live))
            .map_err(|error| NodeAdmissionViewRefusal::from(error))?;
        if admission_deadline_expired.load(Ordering::Relaxed) || deadline.expired() {
            return Err(NodeGitDaemonServeRefusal::from(
                GitDaemonTransportRefusal::SessionDeadlineExceeded {
                    operation: "materialize smart HTTP admission",
                },
            )
            .into());
        }
        let disclosure = self
            .prepare_visible_upload_pack(&node_request, &materialized, &wire_limits, &deadline)
            .map_err(NodeSmartHttpRefusal::from)?;
        let repository = disclosure.repository();
        let capabilities =
            upload_capabilities(self, repository, request.requested_version, &wire_limits)?;
        let mut rpc = UploadRpc::new(
            request,
            request.requested_version,
            capabilities,
            repository,
            wire_limits.clone(),
            http_limits,
        )?;
        let progress = rpc.push(body_wire, cancellation)?;
        if progress.consumed != body_wire.len() {
            return Err(NodeSmartHttpRefusal::TrailingRequestBytes {
                count: body_wire.len() - progress.consumed,
            });
        }
        if !progress.body_complete {
            return Err(RpcError::IncompleteRequest.into());
        }
        let reply = rpc.finish(cancellation)?;
        let pack_requested = reply.pack_request().is_some();

        // Construct the whole selected pack before writing HTTP success. The
        // current pack writer has its own explicit memory envelope; this HTTP
        // adapter does not introduce another pack-sized buffer.
        let mut pack = if let Some(pack_request) = reply.pack_request() {
            let pack_context = self.pack_materialization_context();
            let database_exhaustion = Cell::new(None);
            let mut stopped = false;
            let session_deadline_expired = Cell::new(false);
            let mut transfer_exhaustion = None;
            let pack = {
                let session_is_live = || {
                    if deadline.expired() {
                        session_deadline_expired.set(true);
                        false
                    } else {
                        true
                    }
                };
                let mut is_live = || {
                    if stopped {
                        return false;
                    }
                    if !cancellation.checkpoint() || !session_is_live() {
                        stopped = true;
                        return false;
                    }
                    match checkpoint_pack_context(&pack_context) {
                        PackContextCheckpoint::Live => true,
                        PackContextCheckpoint::Stopped { budget_exhaustion } => {
                            stopped = true;
                            transfer_exhaustion = budget_exhaustion;
                            false
                        }
                    }
                };
                self.materialize_selected_pack_in_scope(
                    &materialized,
                    disclosure.closure_for(&materialized)?,
                    Some((&disclosure, pack_request)),
                    Some(&pack_request.wants),
                    &pack_request.haves,
                    selected_write_profile(pack_request.options.ofs_delta()),
                    node_request.authority(),
                    &database_exhaustion,
                    Some(&session_is_live),
                    &mut is_live,
                )
            };
            if deadline.expired() || session_deadline_expired.get() {
                return Err(NodeGitDaemonServeRefusal::from(
                    GitDaemonTransportRefusal::SessionDeadlineExceeded {
                        operation: SELECTED_PACK_MATERIALIZATION_OPERATION,
                    },
                )
                .into());
            }
            if let Some(dimension) = database_exhaustion.get() {
                return Err(NodePackMaterializationRefusal::BudgetClassExhausted {
                    class: BudgetClass::Database,
                    dimension,
                    operation: SELECTED_PACK_MATERIALIZATION_OPERATION,
                }
                .into());
            }
            if let Some(dimension) = transfer_exhaustion {
                return Err(NodePackMaterializationRefusal::BudgetClassExhausted {
                    class: SELECTED_PACK_BUDGET_CLASS,
                    dimension,
                    operation: SELECTED_PACK_MATERIALIZATION_OPERATION,
                }
                .into());
            }
            Some(pack?)
        } else {
            None
        };

        let head = success_head(request, None);
        let mut response =
            reply.into_response(pack.as_mut(), wire_limits, maximum_response_bytes)?;
        let mut encoder = ResponseEncoder::new(request.http_version, None, maximum_response_bytes)?;
        if let Err(error) = write_response_part(writer, head.as_bytes(), "write smart HTTP head") {
            response.abort();
            return Err(error);
        }
        loop {
            let Some(body) = response.next_chunk(cancellation)? else {
                break;
            };
            let framed = encoder.push(&body)?;
            if let Err(error) =
                write_response_part(writer, framed.prefix.as_bytes(), "write HTTP chunk prefix")
                    .and_then(|()| {
                        write_response_part(writer, framed.data, "write smart HTTP body")
                    })
                    .and_then(|()| {
                        write_response_part(writer, framed.suffix, "write HTTP chunk suffix")
                    })
            {
                response.abort();
                return Err(error);
            }
        }
        let body_bytes = response.emitted_bytes();
        let terminal = encoder.finish()?;
        write_response_part(writer, terminal, "finish smart HTTP response")?;
        Ok(NodeSmartHttpUploadReceipt {
            version: request.requested_version,
            body_bytes,
            pack_requested,
        })
    }

    /// Build authenticated receive-pack discovery from one authority-selected
    /// visible ref snapshot. Caller-owned authentication is required before
    /// any canonical state is read; protocol v2 push remains explicitly
    /// unsupported because Git does not define a v2 receive-pack service.
    pub fn smart_http_receive_discovery_in(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        limits: WireLimits,
    ) -> Result<NodeSmartHttpDiscovery, NodeSmartHttpRefusal> {
        if !self.smart_http_route_matches(request) {
            return Err(NodeSmartHttpRefusal::RepositoryRouteMismatch);
        }
        if request.operation != Operation::Discover(Service::ReceivePack) {
            return Err(NodeSmartHttpRefusal::UnsupportedOperation);
        }
        if !matches!(session, LoopbackReceiveSession::Authenticated(_)) {
            return Err(NodeSmartHttpRefusal::UnauthenticatedReceive);
        }
        if request.requested_version == ProtocolVersion::V2 {
            return Err(HttpError::UnsupportedVersion.into());
        }

        let node_request = self.request_context();
        let repository = self
            .runtime
            .block_on(self.durable_admission_upload_pack_repository_in(&node_request, &limits))
            .map_err(NodeSmartHttpRefusal::from)?;
        let format_name = match self.object_format {
            fgit_types::GitHashAlgorithm::Sha1 => "sha1",
            fgit_types::GitHashAlgorithm::Sha256 => "sha256",
        };
        let capability_text =
            format!("report-status delete-refs ofs-delta object-format={format_name}");
        let server_capabilities = Capabilities::parse_v1(capability_text.as_bytes(), &limits)?;
        let wire_format = match self.object_format {
            fgit_types::GitHashAlgorithm::Sha1 => fgit_wire::GitObjectFormat::Sha1,
            fgit_types::GitHashAlgorithm::Sha256 => fgit_wire::GitObjectFormat::Sha256,
        };
        let receive_limits = ReceiveLimits {
            wire: limits.clone(),
            ..ReceiveLimits::default()
        };
        let context = ReceiveContext::new(
            wire_format,
            server_capabilities,
            receive_limits,
            SignedPushProfile::Refuse,
        )?;
        let body = receive_discovery(
            repository.advertised_refs().to_vec(),
            &context,
            request.requested_version,
        )?;
        let length = u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
        Ok(NodeSmartHttpDiscovery {
            head: success_head(request, Some(length)),
            body,
            version: request.requested_version,
        })
    }
}
