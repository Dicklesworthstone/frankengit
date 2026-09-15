#!/usr/bin/env bash
set -euo pipefail

BASE=9453afa03ec77a07354247618831842c8ff0afe5
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"
work="$RUNNER_TEMP/node-smart-http-upload"
git worktree add --detach "$work" "$BASE"
cd "$work"
git config user.name 'Jeff Emanuel'
git config user.email '35050222+Dicklesworthstone@users.noreply.github.com'

python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/src/lib.rs')
s=p.read_text()
old='pub use smart_http::{NodeSmartHttpDiscovery, NodeSmartHttpRefusal};'
new='pub use smart_http::{NodeSmartHttpDiscovery, NodeSmartHttpRefusal, NodeSmartHttpUploadReceipt};'
if s.count(old)!=1:
    raise SystemExit('smart HTTP export anchor changed')
p.write_text(s.replace(old,new))
PY

cat > crates/fgit-node/src/smart_http.rs <<'RS'
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

use fgit_wire::receive::ReceiveCancellation;
use fgit_wire::smart_http::rpc::{RpcError, UploadRpc, upload_discovery};
use fgit_wire::smart_http::{
    HttpError, HttpLimits, Operation, ProtocolVersion, RequestHead, ResponseEncoder, Service,
    success_head,
};
use fgit_wire::{Capabilities, Packet, UploadPackRepository, WireError, WireLimits};

use super::{
    AdmissionUploadPackRepository, BudgetClass, GitDaemonSessionDeadline,
    GitDaemonTransportRefusal, NodeAdmissionViewRefusal, NodeGitDaemonServeRefusal,
    NodePackMaterializationRefusal, OneNode, PackContextCheckpoint, SELECTED_PACK_BUDGET_CLASS,
    SELECTED_PACK_MATERIALIZATION_OPERATION, checkpoint_pack_context, git_daemon_capabilities,
    selected_write_profile,
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
    /// The HTTP body ended at its declared boundary while caller-owned bytes remained.
    TrailingRequestBytes { count: usize },
    Admission(Box<NodeAdmissionViewRefusal>),
    Serve(Box<NodeGitDaemonServeRefusal>),
    Pack(Box<NodePackMaterializationRefusal>),
    Rpc(Box<RpcError>),
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
            Self::TrailingRequestBytes { count } => {
                write!(formatter, "smart HTTP request retained {count} bytes past its body boundary")
            }
            Self::Admission(error) => Display::fmt(error, formatter),
            Self::Serve(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
            Self::Rpc(error) => Display::fmt(error, formatter),
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
            Self::Http(error) => Some(error.as_ref()),
            Self::Wire(error) => Some(error.as_ref()),
            Self::Io { source, .. } => Some(source),
            Self::RepositoryRouteMismatch
            | Self::UnsupportedOperation
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
        let admission_deadline_expired = Cell::new(false);
        let admission_is_live = || {
            if deadline.expired() {
                admission_deadline_expired.set(true);
                return false;
            }
            true
        };
        let materialized = self
            .runtime
            .block_on(self.materialize_admission_while_in(&node_request, &admission_is_live))
            .map_err(|error| NodeAdmissionViewRefusal::from(error))?;
        if admission_deadline_expired.get() || deadline.expired() {
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
        let mut response = reply.into_response(
            pack.as_mut(),
            wire_limits,
            maximum_response_bytes,
        )?;
        let mut encoder = ResponseEncoder::new(
            request.http_version,
            None,
            maximum_response_bytes,
        )?;
        if let Err(error) = write_response_part(writer, head.as_bytes(), "write smart HTTP head") {
            response.abort();
            return Err(error);
        }
        loop {
            let Some(body) = response.next_chunk(cancellation)? else {
                break;
            };
            let framed = encoder.push(&body)?;
            if write_response_part(writer, framed.prefix.as_bytes(), "write HTTP chunk prefix")
                .and_then(|()| write_response_part(writer, framed.data, "write smart HTTP body"))
                .and_then(|()| write_response_part(writer, framed.suffix, "write HTTP chunk suffix"))
                .is_err()
            {
                response.abort();
                return Err(NodeSmartHttpRefusal::Io {
                    operation: "write smart HTTP response",
                    source: io::Error::new(io::ErrorKind::BrokenPipe, "response writer failed"),
                });
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
}
RS

python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/tests/smart_http_node.rs')
s=p.read_text()
s=s.replace('use fgit_node::{NodeConfig, NodeSmartHttpRefusal, OneNode};', 'use fgit_node::{NodeConfig, NodeSmartHttpRefusal, OneNode};')
s=s.replace('use fgit_wire::WireLimits;\nuse fgit_wire::smart_http::{ProtocolVersion, parse_head};', 'use fgit_wire::{Packet, WireLimits, encode_packets};\nuse fgit_wire::smart_http::{HttpLimits, ProtocolVersion, parse_head};')
s += r'''

fn upload_request(route: &str, body_len: usize) -> Vec<u8> {
    format!(
        "POST {route}/git-upload-pack HTTP/1.1\r\nHost: loopback\r\nGit-Protocol: version=2\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {body_len}\r\n\r\n"
    )
    .into_bytes()
}

fn ls_refs_body() -> Vec<u8> {
    encode_packets(
        &[
            Packet::Data(b"command=ls-refs\n".to_vec()),
            Packet::Delimiter,
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .expect("fixed v2 ls-refs body encodes")
}

#[test]
fn stateless_v2_ls_refs_runs_against_the_same_empty_authority_view() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let body = ls_refs_body();
    let head_bytes = upload_request(route, body.len());
    let head = parse_head(&head_bytes, HttpLimits::default()).unwrap().unwrap();
    let mut live = || true;
    let mut output = Vec::new();
    let receipt = node
        .smart_http_upload_rpc_in(
            &head,
            &body,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut live,
            &mut output,
        )
        .expect("v2 ls-refs serves from authenticated empty state");
    assert_eq!(receipt.version(), ProtocolVersion::V2);
    assert!(!receipt.pack_requested());
    assert!(output.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(output.windows(b"Transfer-Encoding: chunked".len()).any(|w| w == b"Transfer-Encoding: chunked"));
    assert!(output.ends_with(b"4\r\n0000\r\n0\r\n\r\n"));
    node.shutdown().unwrap();
}

#[test]
fn rpc_refuses_pipelined_suffix_before_writing_any_response() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let body = ls_refs_body();
    let head_bytes = upload_request(route, body.len());
    let head = parse_head(&head_bytes, HttpLimits::default()).unwrap().unwrap();
    let mut offered = body.clone();
    offered.extend_from_slice(b"NEXT");
    let mut live = || true;
    let mut output = Vec::new();
    assert!(matches!(
        node.smart_http_upload_rpc_in(
            &head,
            &offered,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut live,
            &mut output,
        ),
        Err(NodeSmartHttpRefusal::TrailingRequestBytes { count: 4 })
    ));
    assert!(output.is_empty());
    node.shutdown().unwrap();
}

#[test]
fn rpc_cancellation_precedes_authority_work_and_response_bytes() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let body = ls_refs_body();
    let head_bytes = upload_request(route, body.len());
    let head = parse_head(&head_bytes, HttpLimits::default()).unwrap().unwrap();
    let mut cancelled = || false;
    let mut output = Vec::new();
    assert!(node
        .smart_http_upload_rpc_in(
            &head,
            &body,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut cancelled,
            &mut output,
        )
        .is_err());
    assert!(output.is_empty());
    node.shutdown().unwrap();
}
'''
p.write_text(s)
PY

rustfmt --edition 2024 --config skip_children=true \
  crates/fgit-node/src/smart_http.rs \
  crates/fgit-node/tests/smart_http_node.rs
git diff --check
git add -- crates/fgit-node/src/lib.rs crates/fgit-node/src/smart_http.rs crates/fgit-node/tests/smart_http_node.rs
git commit -m 'feat(node): serve stateless smart HTTP upload RPCs (FG-105a)'

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$RUNNER_TEMP/frankengit-node-http-upload-target"
cargo test -p fgit-node --test smart_http_node
cargo check -p fgit-node --lib

test -z "$(git status --porcelain)"
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"
git push origin HEAD:refs/heads/main
published="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$published" = "$(git rev-parse HEAD)"
echo "PUBLISHED=$published"
