//! Authority-backed Smart HTTP composition for one FrankenGit node.
//!
//! `fgit-wire` owns hostile HTTP/Git framing; an outer gateway owns credentials
//! and route selection. This module rechecks the canonical repository route and
//! then composes wire requests with the exact authority-selected admission and
//! disclosure machinery already used by the raw Git compatibility service.

mod command_limit;
mod ingress;
mod receive_session;
mod server;
pub use server::{source_agent_context_json, source_retrieval_json};
mod upload_refusal;
mod verdict;

#[cfg(test)]
mod writer_permit_tests;

use std::cell::Cell;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_wire::receive::{
    ReceiveCancellation, ReceiveContext, ReceiveError, ReceiveLimits, SignedPushProfile,
};
use fgit_wire::smart_http::rpc::{
    ReceiveRpc, RpcError, UploadRpc, receive_discovery, upload_discovery,
};
use fgit_wire::smart_http::{
    HttpError, HttpLimits, Operation, ProtocolVersion, RequestHead, ResponseEncoder, Service,
    success_head,
};
use fgit_wire::{Capabilities, Packet, UploadPackRepository, WireError, WireLimits};

use super::{
    AdmissionUploadPackRepository, BudgetClass, GitDaemonSessionDeadline,
    GitDaemonTransportRefusal, LoopbackReceiveSession, NodeAdmissionViewRefusal,
    NodeGitDaemonServeRefusal, NodePackMaterializationRefusal, NodeReceiveTransportRefusal,
    OneNode, PackContextCheckpoint, ProductionReceiveQuarantineHandoff, SELECTED_PACK_BUDGET_CLASS,
    SELECTED_PACK_MATERIALIZATION_OPERATION, checkpoint_pack_context, git_daemon_capabilities,
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
    /// Receive-pack is never available without caller-authenticated identity.
    UnauthenticatedReceive,
    /// Authentication denied a destination in the complete original request;
    /// no ref decision or transaction seal has been attempted.
    RefWriteScopeDenied,
    /// The HTTP body ended at its declared boundary while caller-owned bytes remained.
    TrailingRequestBytes {
        count: usize,
    },
    Admission(Box<NodeAdmissionViewRefusal>),
    Serve(Box<NodeGitDaemonServeRefusal>),
    Pack(Box<NodePackMaterializationRefusal>),
    Rpc(Box<RpcError>),
    Receive(Box<ReceiveError>),
    ReceiveTransport(Box<NodeReceiveTransportRefusal>),
    /// An interrupted multi-ref session retains its authenticated outcome prefix.
    /// Commands outside that prefix have unknown outcomes, not inferred refusals.
    ReceiveInterrupted(Box<fgit_admission::policy_bridge::receive_session::InterruptedSession>),
    /// A canonical terminal outcome exists even though its response failed.
    /// Retry recovery must use this outcome, never infer rollback from I/O.
    ReceiveResponse {
        outcome: Box<AdmissionResult>,
        source: Box<Self>,
    },
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
            Self::RefWriteScopeDenied => {
                formatter.write_str("credential does not permit writing every requested reference")
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
            Self::ReceiveTransport(error) => Display::fmt(error, formatter),
            Self::ReceiveInterrupted(error) => Display::fmt(error, formatter),
            Self::ReceiveResponse { source, .. } => write!(
                formatter,
                "smart HTTP receive has a canonical outcome but response delivery failed: {source}"
            ),
            Self::Http(error) => Display::fmt(error, formatter),
            Self::Wire(error) => Display::fmt(error, formatter),
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
        }
    }
}

/// One browser origin, besides the listener's own, whose state-changing
/// requests the HTTP gateway accepts: the public origin of an authenticated
/// external TLS terminator in front of the loopback listener
/// (frankengit-root-doctrine-x2mv.4.31).
///
/// The value is one exact serialized origin, as browsers send it: `http://` or
/// `https://`, a lowercase host name, IPv4 or bracketed IPv6 literal, and a
/// port only when it is not the scheme's default. Nothing is normalized, so a
/// value no browser sends is refused here instead of silently never matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTrustedOrigin(String);

/// A trusted origin that is not one exact serialized browser origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpTrustedOriginRefusal;

impl Display for HttpTrustedOriginRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "a trusted origin is one exact browser origin: http(s)://host[:port], lowercase, \
             with no path, user information or default port",
        )
    }
}

impl Error for HttpTrustedOriginRefusal {}

impl HttpTrustedOrigin {
    /// Accepts `origin` only in the exact form a browser serializes it.
    ///
    /// # Errors
    ///
    /// [`HttpTrustedOriginRefusal`] for anything else.
    pub fn try_new(origin: &str) -> Result<Self, HttpTrustedOriginRefusal> {
        let (authority, default_port) = if let Some(rest) = origin.strip_prefix("https://") {
            (rest, "443")
        } else if let Some(rest) = origin.strip_prefix("http://") {
            (rest, "80")
        } else {
            return Err(HttpTrustedOriginRefusal);
        };
        let (host, port) = match authority.strip_prefix('[') {
            Some(literal) => {
                let (inside, rest) = literal.split_once(']').ok_or(HttpTrustedOriginRefusal)?;
                if inside.is_empty()
                    || !inside
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f' | b':' | b'.'))
                {
                    return Err(HttpTrustedOriginRefusal);
                }
                (&authority[..inside.len() + 2], rest.strip_prefix(':'))
            }
            None => {
                let (host, port) = authority
                    .split_once(':')
                    .map_or((authority, None), |(host, port)| (host, Some(port)));
                if host.is_empty()
                    || host.starts_with(['.', '-'])
                    || host.ends_with(['.', '-'])
                    || !host
                        .bytes()
                        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
                {
                    return Err(HttpTrustedOriginRefusal);
                }
                (host, port)
            }
        };
        let rest = &authority[host.len()..];
        let port_ok = match port {
            None => rest.is_empty(),
            Some(port) => {
                rest.len() == port.len() + 1
                    && port != default_port
                    && !port.starts_with('0')
                    && port.bytes().all(|byte| byte.is_ascii_digit())
                    && port.parse::<u16>().is_ok()
            }
        };
        if !port_ok || authority.len() > 255 {
            return Err(HttpTrustedOriginRefusal);
        }
        Ok(Self(origin.to_owned()))
    }

    /// The serialized origin, exactly as a browser sends it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The origin's host and optional port, as a same-origin `Host` names it.
    pub(crate) fn authority(&self) -> &str {
        self.0
            .split_once("://")
            .map_or(self.0.as_str(), |(_, authority)| authority)
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
            Self::ReceiveTransport(error) => Some(error.as_ref()),
            Self::ReceiveInterrupted(error) => Some(error.as_ref()),
            Self::ReceiveResponse { source, .. } => Some(source.as_ref()),
            Self::Http(error) => Some(error.as_ref()),
            Self::Wire(error) => Some(error.as_ref()),
            Self::Io { source, .. } => Some(source),
            Self::RepositoryRouteMismatch
            | Self::UnsupportedOperation
            | Self::UnauthenticatedReceive
            | Self::RefWriteScopeDenied
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
impl From<NodeReceiveTransportRefusal> for NodeSmartHttpRefusal {
    fn from(value: NodeReceiveTransportRefusal) -> Self {
        Self::ReceiveTransport(Box::new(value))
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
    let fetch = if repository.supports_shallow() {
        b"fetch=shallow filter\n".as_slice()
    } else {
        b"fetch=filter\n".as_slice()
    };
    let packets = vec![
        Packet::Data(b"version 2\n".to_vec()),
        // Upstream advertises `unborn`: without it a v2 client never asks for
        // an empty repository's HEAD, and its clone falls back to its own default.
        Packet::Data(b"ls-refs=unborn\n".to_vec()),
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

/// Git RPC failures are successful HTTP exchanges carrying a single ERR
/// packet. Bound and frame the entire packet before emitting the HTTP head,
/// withholding every negotiation prefix and pack byte.
fn write_upload_rpc_error(
    writer: &mut impl Write,
    request: &RequestHead<'_>,
    line: Vec<u8>,
    wire_limits: &WireLimits,
    maximum_response_bytes: u64,
) -> Result<(), NodeSmartHttpRefusal> {
    let body = fgit_wire::encode_packets(&[Packet::Data(line)], wire_limits)?;
    let head = success_head(request, None);
    let mut encoder = ResponseEncoder::new(request.http_version, None, maximum_response_bytes)?;
    let framed = encoder.push(&body)?;
    write_response_part(writer, head.as_bytes(), "write smart HTTP head")?;
    write_response_part(writer, framed.prefix.as_bytes(), "write HTTP chunk prefix")?;
    write_response_part(writer, framed.data, "write smart HTTP body")?;
    write_response_part(writer, framed.suffix, "write HTTP chunk suffix")?;
    let terminal = encoder.finish()?;
    write_response_part(writer, terminal, "finish smart HTTP response")
}

// Cancellation must reach awaited authority work, not stop at the last parser
// checkpoint. Cancel the owning context before each subsequent poll, but keep
// driving the future to completion. Dropping it or replacing its actual result
// with a local timeout could erase a canonical post-transmission outcome.
fn drive_request_while<F: Future>(
    node: &OneNode,
    request: &super::NodeRequestContext,
    future: F,
    is_live: &mut impl FnMut() -> bool,
) -> F::Output {
    let mut future = std::pin::pin!(future);
    node.runtime.block_on(std::future::poll_fn(|cx| {
        if !is_live() {
            request.cancel();
        }
        future.as_mut().poll(cx)
    }))
}

/// Places a waiting receive's verified objects while another writer holds
/// the node's writer capacity (frankengit-root-doctrine-x2mv.4.9).
///
/// Staging is most of a large push's service time, and it is
/// content-addressed: a placed object carries no canonical visibility, so it
/// needs no writer. This runs the production validator against the basis
/// current now over a borrowed quarantine
/// ([`fgit_wire::receive::ReceiveQuarantine::speculate`]) and discards every
/// result, refusals included. The authoritative handoff under the permit still
/// selects its own basis after admission and decides exactly as before; it
/// finds the objects placed and re-verifies them instead of writing and
/// syncing them. An expired `live` ends this early and changes nothing else.
fn prestage_receive(
    node: &OneNode,
    request: &super::NodeRequestContext,
    quarantine: &fgit_wire::receive::ReceiveQuarantine,
    pack_limits: fgit_pack::PackLimits,
    staging: &super::receive_staging::ReceiveStaging,
    live: &mut impl FnMut() -> bool,
) {
    let Ok(selected) =
        drive_request_while(node, request, node.materialize_admission_in(request), live)
    else {
        return;
    };
    let Ok(validator) = node.production_quarantine_validator(
        &selected,
        pack_limits,
        fgit_git_object::ParseLimits {
            tree_reference_bytes: node.object_format.digest_len(),
            ..fgit_git_object::ParseLimits::default()
        },
    ) else {
        return;
    };
    let validator = validator.with_receive_staging(staging);
    let mut handoff = ProductionReceiveQuarantineHandoff::new(validator, selected.basis().clone());
    let _advisory = quarantine.speculate(&mut handoff, live);
}

impl OneNode {
    fn smart_http_route_matches(&self, request: &RequestHead<'_>) -> bool {
        request.repository_route.as_bytes() == self.git_daemon_repository_path.as_bytes()
    }

    /// Build one complete upload-pack discovery response from authenticated
    /// canonical state, using the same visible graph as RPC negotiation.
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
        let deadline = GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        let is_live = || !deadline.expired();
        let materialized = self
            .runtime
            .block_on(self.materialize_admission_while_in(&node_request, &is_live))
            .map_err(NodeAdmissionViewRefusal::from)?;
        let disclosure =
            self.prepare_visible_upload_pack(&node_request, &materialized, &limits, &deadline)?;
        let repository = disclosure.repository();
        let capabilities =
            upload_capabilities(self, repository, request.requested_version, &limits)?;
        let body = if request.requested_version == ProtocolVersion::V2 {
            upload_discovery(repository, capabilities, request.requested_version, &limits)?
        } else {
            // A legacy annotated-tag advertisement needs its synthetic ^{}
            // records. The wrapper uses only already-verified visible peels.
            let legacy =
                super::upload_visibility::tags::LegacyTagRepository::new(repository, &limits)?;
            upload_discovery(&legacy, capabilities, request.requested_version, &limits)?
        };
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
    /// framing. Every supplied byte must belong to this request. A requested
    /// pack is fully selected and verified before the success header is emitted.
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
        self.smart_http_upload_body_in(
            request,
            ingress::BodyInput::Slice(body_wire),
            wire_limits,
            http_limits,
            maximum_response_bytes,
            cancellation,
            writer,
        )
    }

    /// Pull an upload-pack body directly into its bounded native RPC machine.
    ///
    /// The caller authenticates first and supplies a reader starting at the
    /// HTTP body, with chunk framing intact. Reads use a fixed 16 KiB scratch
    /// buffer. HTTP completion, not socket EOF, ends intake. A suffix in a read
    /// crossing that boundary is refused; unread bytes remain the host's and
    /// must not be reused as another command. The host owns finite read/write
    /// deadlines. Pack construction receives a fresh server-work budget after
    /// ingress and uses the same immutable view selected before negotiation.
    pub fn smart_http_upload_stream_in<R, W, C>(
        &self,
        request: &RequestHead<'_>,
        reader: &mut R,
        wire_limits: WireLimits,
        http_limits: HttpLimits,
        maximum_response_bytes: u64,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<NodeSmartHttpUploadReceipt, NodeSmartHttpRefusal>
    where
        R: Read,
        W: Write,
        C: ReceiveCancellation,
    {
        self.smart_http_upload_body_in(
            request,
            ingress::BodyInput::Reader(reader),
            wire_limits,
            http_limits,
            maximum_response_bytes,
            cancellation,
            writer,
        )
    }

    fn smart_http_upload_body_in<W, C>(
        &self,
        request: &RequestHead<'_>,
        body: ingress::BodyInput<'_>,
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
        let materialized = drive_request_while(
            self,
            &node_request,
            self.materialize_admission_while_in(&node_request, &admission_is_live),
            &mut || cancellation.checkpoint() && !deadline.expired(),
        );
        if admission_deadline_expired.load(Ordering::Relaxed) || deadline.expired() {
            return Err(NodeGitDaemonServeRefusal::from(
                GitDaemonTransportRefusal::SessionDeadlineExceeded {
                    operation: "materialize smart HTTP admission",
                },
            )
            .into());
        }
        let materialized = materialized.map_err(NodeAdmissionViewRefusal::from)?;
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
        let reply = body
            .consume(cancellation, |bytes, live| rpc.push(bytes, live))
            .and_then(|_| rpc.finish(cancellation).map_err(NodeSmartHttpRefusal::from));
        let reply = match reply {
            Ok(reply) => reply,
            Err(refusal) => {
                if let NodeSmartHttpRefusal::Rpc(error) = &refusal
                    && let RpcError::Wire(error) = &**error
                    && let Some(line) = crate::upload_want_error(error)
                {
                    if !cancellation.checkpoint() {
                        return Err(RpcError::Cancelled.into());
                    }
                    deadline
                        .check("report smart HTTP upload-pack refusal")
                        .map_err(NodeGitDaemonServeRefusal::from)?;
                    write_upload_rpc_error(
                        writer,
                        request,
                        line,
                        &wire_limits,
                        maximum_response_bytes,
                    )?;
                }
                return Err(refusal);
            }
        };
        if let Some(filter) = reply
            .pack_request()
            .and_then(|pack_request| pack_request.filter.as_ref())
            .and_then(crate::upload_visibility::unserved_filter_name)
        {
            // Upstream's stateless upload-pack answers a filter it does not
            // serve with one `ERR` packet in a 200 body, which a stock client
            // reports as a remote error. The negotiation prefix is withheld.
            write_upload_rpc_error(
                writer,
                request,
                crate::unserved_filter_error(filter),
                &wire_limits,
                maximum_response_bytes,
            )?;
            return Err(NodeGitDaemonServeRefusal::from(
                GitDaemonTransportRefusal::UnservedFilter { filter },
            )
            .into());
        }
        let pack_requested = reply.pack_request().is_some();

        // The network peer must not spend the budget reserved for selecting
        // and verifying its pack. Only contexts change here: the authenticated
        // materialization and exact-head disclosure proof remain unchanged.
        let deadline = GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        let node_request = self.request_context();

        // Construct the whole selected pack before writing HTTP success. The
        // current pack writer has its own explicit memory envelope; this HTTP
        // adapter does not introduce another pack-sized buffer.
        let pack_result = (|| -> Result<_, NodeSmartHttpRefusal> {
            let pack = if let Some(pack_request) = reply.pack_request() {
                let pack_context = self.session_pack_materialization_context(&deadline);
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
                    self.prepare_upload_pack_selection(
                        &materialized,
                        &disclosure,
                        pack_request,
                        &deadline,
                        &pack_context,
                        &mut is_live,
                    )
                    .and_then(|prepared| {
                        self.materialize_prepared_upload_pack(
                            &materialized,
                            &prepared,
                            node_request.authority(),
                            &database_exhaustion,
                            Some(&session_is_live),
                            &mut is_live,
                        )
                    })
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
            Ok(pack)
        })();
        let mut pack = match pack_result {
            Ok(pack) => pack,
            Err(refusal) => {
                // A Git client discards an ordinary HTTP failure body. Report
                // bounded operator-actionable pack refusals in Git framing,
                // before any negotiation prefix or successful pack response.
                // The host's ResponseWriter starts its independent finite
                // output phase here; an expired work budget cannot suppress
                // this last diagnostic or be revived by attempting it.
                if let Some(line) = upload_refusal::line(&refusal)
                    && cancellation.checkpoint()
                {
                    let _ = write_upload_rpc_error(
                        writer,
                        request,
                        line,
                        &wire_limits,
                        maximum_response_bytes,
                    );
                }
                return Err(refusal);
            }
        };

        let head = success_head(request, None);
        let mut response =
            reply.into_response(pack.as_mut(), wire_limits, maximum_response_bytes)?;
        let mut encoder = ResponseEncoder::new(request.http_version, None, maximum_response_bytes)?;
        if let Err(error) = write_response_part(writer, head.as_bytes(), "write smart HTTP head") {
            response.abort();
            return Err(error);
        }
        while let Some(body) = response.next_chunk(cancellation)? {
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
        let materialized = self
            .runtime
            .block_on(self.materialize_admission_in(&node_request))
            .map_err(NodeAdmissionViewRefusal::from)?;
        let snapshot = materialized.snapshot();
        // Receive discovery advertises only direct writable ref names. In
        // particular, a missing/unborn default HEAD must not block pushing a
        // tag-only repository or repairing that default branch.
        let advertisement = super::AdmissionReceivePackAdvertisement::from_snapshot(
            snapshot,
            &snapshot.hidden_refs,
            self.object_format,
            &limits,
        )
        .map_err(NodeAdmissionViewRefusal::from)?;
        let context = self.smart_http_receive_context(limits)?;
        let body = receive_discovery(
            advertisement.advertised_refs().to_vec(),
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

    /// Admit one authenticated, complete Smart HTTP push and emit report-status.
    ///
    /// The gateway supplies a verified principal and a stable client retry key
    /// in `session`; neither is inferred from headers, PACK bytes or a socket.
    /// `body_wire` starts at the HTTP body boundary, with chunk framing intact
    /// when applicable. Every supplied byte must belong to this one request.
    ///
    /// Admission uses the same per-transaction planner, policy, compare-and-swap,
    /// idempotency and cell-state publication gates as the raw receive service.
    /// Non-atomic HTTP sessions retain exact-basis validation for every command,
    /// advancing only over their own verified committed or refused decisions.
    /// Interrupted sessions retain known outcomes in `ReceiveInterrupted`;
    /// response failures after admission retain the result in `ReceiveResponse`.
    pub fn smart_http_receive_rpc_in<W, C>(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        body_wire: &[u8],
        http_limits: HttpLimits,
        admission_limits: AdmissionLimits,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal>
    where
        W: Write,
        C: ReceiveCancellation,
    {
        self.smart_http_receive_body_in(
            request,
            session,
            ingress::BodyInput::Slice(body_wire),
            http_limits,
            admission_limits,
            None,
            cancellation,
            writer,
        )
    }

    /// Pull an authenticated push directly into native transaction quarantine.
    ///
    /// Authentication, quota and cell-intake gates precede the first body read.
    /// The reader starts at the HTTP body and retains chunk framing when used.
    /// Only a fixed 16 KiB ingress scratch buffer is added to the native bounded
    /// quarantine; no whole-request gateway copy or decoded-body copy is made.
    /// The full HTTP envelope must finish before object validation/staging or
    /// durable admission. Any buffered suffix past the boundary is refused.
    ///
    /// The host must bound blocking read/write time and close the connection
    /// after this request. Completion never waits for socket EOF. Server-work
    /// deadlines start after ingress, so a slow upload cannot spend the budget
    /// reserved for validating and publishing an otherwise admissible pack.
    /// Like the slice adapter, call this only on the runtime's blocking lane.
    pub fn smart_http_receive_stream_in<R, W, C>(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        reader: &mut R,
        http_limits: HttpLimits,
        admission_limits: AdmissionLimits,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal>
    where
        R: Read,
        W: Write,
        C: ReceiveCancellation,
    {
        self.smart_http_receive_stream_gated_in(
            request,
            session,
            reader,
            http_limits,
            admission_limits,
            None,
            cancellation,
            writer,
        )
    }

    /// [`Self::smart_http_receive_stream_in`] for a serving process that
    /// bounds its concurrent writers: upload and structural pack validation
    /// are not gated. Once that bounded work completes, this receive waits on
    /// its server-work clock for one of `writers`' admissions, then selects a
    /// fresh authority basis for native validation, staging and publication.
    pub(crate) fn smart_http_receive_stream_gated_in<R, W, C>(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        reader: &mut R,
        http_limits: HttpLimits,
        admission_limits: AdmissionLimits,
        writers: Option<&crate::WriterGate>,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal>
    where
        R: Read,
        W: Write,
        C: ReceiveCancellation,
    {
        self.smart_http_receive_body_in(
            request,
            session,
            ingress::BodyInput::Reader(reader),
            http_limits,
            admission_limits,
            writers,
            cancellation,
            writer,
        )
    }

    fn smart_http_receive_body_in<W, C>(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        body: ingress::BodyInput<'_>,
        http_limits: HttpLimits,
        admission_limits: AdmissionLimits,
        writers: Option<&crate::WriterGate>,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal>
    where
        W: Write,
        C: ReceiveCancellation,
    {
        let result = self.smart_http_receive_body_checked_in(
            request,
            session,
            body,
            http_limits,
            admission_limits,
            writers,
            cancellation,
            writer,
        );
        // A well-formed request refused by a bound or policy is answered as
        // git-http-backend answers a fatal error: one ERR packet in a 200
        // receive-pack body, which a stock client prints as "fatal: remote
        // error: ...". A 4xx/5xx body is discarded by the client. Only causes
        // raised before any response byte qualify (crate::receive_refusal); the
        // refusal is still returned, and the server's started-response guard
        // keeps it from writing a second response (frankengit-yrff). The
        // command-count refusal was already answered where it was raised
        // (command_limit::report_http, frankengit-p9b5).
        if let Err(error) = &result
            && command_limit::before_admission(error).is_none()
            && let Some(cause) = crate::receive_refusal::request_cause(error)
        {
            let message = format!("ERR {cause}; no ref decision was attempted\n").into_bytes();
            let body = fgit_wire::encode_packets(&[Packet::Data(message)], &WireLimits::default())?;
            let length = u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
            let head = success_head(request, Some(length));
            write_response_part(writer, head.as_bytes(), "write smart HTTP refusal head")?;
            write_response_part(writer, &body, "write smart HTTP receive refusal")?;
            writer.flush().map_err(|source| NodeSmartHttpRefusal::Io {
                operation: "flush smart HTTP receive refusal",
                source,
            })?;
        }
        result
    }

    fn smart_http_receive_body_checked_in<W, C>(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        body: ingress::BodyInput<'_>,
        http_limits: HttpLimits,
        admission_limits: AdmissionLimits,
        writers: Option<&crate::WriterGate>,
        cancellation: &mut C,
        writer: &mut W,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal>
    where
        W: Write,
        C: ReceiveCancellation,
    {
        if !self.smart_http_route_matches(request) {
            return Err(NodeSmartHttpRefusal::RepositoryRouteMismatch);
        }
        if request.operation != Operation::Rpc(Service::ReceivePack) {
            return Err(NodeSmartHttpRefusal::UnsupportedOperation);
        }
        let Some(authenticated) = session.authenticated_session() else {
            return Err(NodeSmartHttpRefusal::UnauthenticatedReceive);
        };
        if request.requested_version == ProtocolVersion::V2 {
            return Err(HttpError::UnsupportedVersion.into());
        }
        if !cancellation.checkpoint() {
            return Err(RpcError::Cancelled.into());
        }
        // Keep the raw receive boundary's ordering: authenticate, rate-limit,
        // then check intake before retaining any untrusted transaction bytes.
        self.push_quota.evaluate(&authenticated.principal_id())?;
        fgit_types::cell::admits_staging_intake(self.cell_state())
            .map_err(NodeReceiveTransportRefusal::CellState)?;

        let receive_limits = self.git_daemon_receive_limits.clone();
        let context = self.smart_http_receive_context(receive_limits.wire.clone())?;
        let mut rpc = ReceiveRpc::new(request, request.requested_version, context, http_limits)?
            .with_pack_retention(self.received_pack_cache().capture_limit());
        let decoded_body_bytes =
            match body.consume(cancellation, |bytes, live| rpc.push(bytes, live)) {
                Ok(bytes) => bytes,
                Err(error) => {
                    command_limit::report_http(request, &error, &receive_limits.wire, writer)?;
                    return Err(error);
                }
            };
        if rpc.is_probe() {
            // git's remote-curl sends a lone flush packet before any request
            // larger than http.postBuffer and sends nothing more unless it is
            // answered 200; git-http-backend's receive-pack reads no command
            // and writes an empty result. Nothing is admitted, bound or
            // recorded (frankengit-wh86).
            let head = success_head(request, Some(0));
            write_response_part(writer, head.as_bytes(), "write smart HTTP probe head")?;
            writer.flush().map_err(|source| NodeSmartHttpRefusal::Io {
                operation: "flush smart HTTP probe answer",
                source,
            })?;
            return Ok(AdmissionResult {
                session: fgit_admission::SessionMapping {
                    atomic: false,
                    tx_ids: Vec::new(),
                },
                commands: Vec::new(),
            });
        }

        // Ingress is complete. These independent, finite server-work clocks
        // cannot be exhausted by time the peer spent uploading its body.
        let deadline = GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        let processing = super::GitDaemonReceiveProcessingDeadline::new(
            self.git_daemon_receive_processing_timeout,
        );
        let mut live = || cancellation.checkpoint() && !deadline.expired() && !processing.expired();
        // Inflating and checking the complete untrusted pack needs no writer
        // capacity. Keep its exclusive quarantine owner while waiting, then
        // select authority after admission so another push cannot stale the
        // validation basis merely by finishing while this request prepared.
        let quarantine = rpc.into_quarantine(&mut live)?;
        if quarantine
            .request()
            .commands
            .iter()
            .any(|command| !authenticated.permits_ref_write_bytes(&command.ref_name))
        {
            return Err(NodeSmartHttpRefusal::RefWriteScopeDenied);
        }
        // Staged objects are published only when admission commits; any other
        // end abandons them (frankengit-tz5z). Declared before every user.
        let staging = super::receive_staging::ReceiveStaging::default();
        let writer_permit = super::admit_writer_prestaging(writers, &deadline, || {
            let prestage = super::NodeRequestContext {
                authority: self.receive_admission_authority_context(decoded_body_bytes, &deadline),
            };
            prestage_receive(
                self,
                &prestage,
                &quarantine,
                receive_limits.pack.clone(),
                &staging,
                &mut live,
            );
        })?;
        let node_request = super::NodeRequestContext {
            authority: self.receive_admission_authority_context(decoded_body_bytes, &deadline),
        };
        let admission_is_live = || !deadline.expired() && !processing.expired();
        let materialized = drive_request_while(
            self,
            &node_request,
            self.materialize_admission_while_in(&node_request, &admission_is_live),
            &mut live,
        )
        .map_err(NodeAdmissionViewRefusal::from)?;
        if !live() {
            return Err(RpcError::Cancelled.into());
        }
        let validator = self
            .production_quarantine_validator(
                &materialized,
                receive_limits.pack.clone(),
                fgit_git_object::ParseLimits {
                    tree_reference_bytes: self.object_format.digest_len(),
                    ..fgit_git_object::ParseLimits::default()
                },
            )
            .map_err(ReceiveError::AuthoritativeRefusal)?
            .with_receive_staging(&staging);
        let mut handoff =
            ProductionReceiveQuarantineHandoff::new(validator, materialized.basis().clone());
        let received = quarantine.request().clone();
        let completion = match quarantine.handoff(&mut handoff, &mut live) {
            Err(ReceiveError::AuthoritativeRefusal(code)) => {
                // Admission is finished; a slow response must not hold the
                // process's writer capacity while this verdict is delivered.
                drop(writer_permit);
                // A verdict on the fully received commands reaches the client
                // per ref in a 200 receive-pack result, as git-receive-pack
                // answers over HTTP. The refusal is still returned: nothing is
                // admitted and the request counts as refused (frankengit-87c7).
                let report = verdict::command_verdict_report(&received, code, &receive_limits);
                if let Some(report) = report {
                    let body = fgit_wire::encode_packets(&report?, &receive_limits.wire)?;
                    let length =
                        u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
                    let head = success_head(request, Some(length));
                    write_response_part(writer, head.as_bytes(), "write smart HTTP verdict head")?;
                    write_response_part(writer, &body, "write smart HTTP receive verdict")?;
                    writer.flush().map_err(|source| NodeSmartHttpRefusal::Io {
                        operation: "flush smart HTTP receive verdict",
                        source,
                    })?;
                }
                return Err(RpcError::Receive(ReceiveError::AuthoritativeRefusal(code)).into());
            }
            completion => completion.map_err(RpcError::from)?,
        };
        drop(received);
        let validated = handoff.into_validated_receive()?;
        if !live() {
            return Err(RpcError::Cancelled.into());
        }
        let outcome = match drive_request_while(
            self,
            &node_request,
            self.admit_continuing_http_receive_in(
                &node_request,
                session,
                &validated,
                admission_limits,
                Some(&staging),
            ),
            &mut live,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                drop(writer_permit);
                command_limit::report_http(request, &error, &receive_limits.wire, writer)?;
                return Err(error);
            }
        };
        // The canonical result is fixed. Release write admission before any
        // response encoding or client I/O, including a failed delivery.
        drop(writer_permit);

        // From here on, cancellation and I/O failure cannot mean non-commit.
        // Preserve the canonical result on every response-encoding/write path.
        let delivered: Result<(), NodeSmartHttpRefusal> = (|| {
            let packets = outcome.report_packets(&completion.request, &receive_limits)?;
            let body = fgit_wire::encode_packets(&packets, &receive_limits.wire)?;
            let length = u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
            let head = success_head(request, Some(length));
            write_response_part(writer, head.as_bytes(), "write smart HTTP receive head")?;
            write_response_part(writer, &body, "write smart HTTP receive report")?;
            writer.flush().map_err(|source| NodeSmartHttpRefusal::Io {
                operation: "flush smart HTTP receive report",
                source,
            })
        })();
        match delivered {
            Ok(()) => Ok(outcome),
            Err(source) => Err(NodeSmartHttpRefusal::ReceiveResponse {
                outcome: Box::new(outcome),
                source: Box::new(source),
            }),
        }
    }

    // Discovery and RPC must advertise/accept the same capability matrix and
    // object-format domain, under the operator's immutable receive envelope.
    fn smart_http_receive_context(
        &self,
        wire: WireLimits,
    ) -> Result<ReceiveContext, NodeSmartHttpRefusal> {
        let (wire_format, format_name) = match self.object_format {
            fgit_types::GitHashAlgorithm::Sha1 => (fgit_wire::GitObjectFormat::Sha1, "sha1"),
            fgit_types::GitHashAlgorithm::Sha256 => (fgit_wire::GitObjectFormat::Sha256, "sha256"),
        };
        // The native admission driver seals an atomic command list as one
        // transaction and publishes its complete fold under one head CAS.
        // Advertise that existing guarantee on HTTP; do not emulate atomicity
        // with a loop over independently published ref updates in the gateway.
        // Push options are sealed into each request's canonical digest
        // (normative contracts section 3), within the bounds the node narrowed
        // its receive envelope to (`sealable_receive_limits`).
        let capability_text = format!(
            "report-status delete-refs ofs-delta atomic push-options object-format={format_name}"
        );
        let capabilities = Capabilities::parse_v1(capability_text.as_bytes(), &wire)?;
        Ok(ReceiveContext::new(
            wire_format,
            capabilities,
            ReceiveLimits {
                wire,
                ..self.git_daemon_receive_limits.clone()
            },
            SignedPushProfile::Refuse,
        )?)
    }
}
