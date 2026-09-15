#!/usr/bin/env bash
set -euo pipefail

BASE="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test -n "$BASE"
work="$RUNNER_TEMP/node-smart-http-receive-rpc"
git worktree add --detach "$work" "$BASE"
cd "$work"
git config user.name 'Jeff Emanuel'
git config user.email '35050222+Dicklesworthstone@users.noreply.github.com'

python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/src/smart_http.rs')
s=p.read_text()
old='use fgit_wire::receive::{ReceiveCancellation, ReceiveContext, ReceiveError, ReceiveLimits, SignedPushProfile};'
new='use fgit_wire::receive::{\n    ReceiveCancellation, ReceiveContext, ReceiveError, ReceiveEvent, ReceiveLimits, ReceivePack,\n    ReceiveRequest, SignedPushProfile,\n};'
if s.count(old)!=1:
    raise SystemExit('receive import anchor changed')
s=s.replace(old,new)
old='''use fgit_wire::smart_http::{
    HttpError, HttpLimits, Operation, ProtocolVersion, RequestHead, ResponseEncoder, Service,
    success_head,
};'''
new='''use fgit_wire::smart_http::{
    BodyDecoder, HttpError, HttpLimits, Operation, ProtocolVersion, RequestHead, ResponseEncoder,
    Service, success_head,
};'''
if s.count(old)!=1:
    raise SystemExit('smart HTTP import anchor changed')
s=s.replace(old,new)
old='use fgit_wire::{Capabilities, Packet, UploadPackRepository, WireError, WireLimits};'
new='use fgit_wire::{Capabilities, Packet, UploadPackRepository, WireError, WireLimits, encode_packets};'
if s.count(old)!=1:
    raise SystemExit('wire import anchor changed')
s=s.replace(old,new)
old='''    LoopbackReceiveSession, NodePackMaterializationRefusal, OneNode, PackContextCheckpoint,
    SELECTED_PACK_BUDGET_CLASS,'''
new='''    AdmissionLimits, LoopbackReceiveSession, NodePackMaterializationRefusal,
    NodeReceiveTransportRefusal, OneNode, PackContextCheckpoint, SELECTED_PACK_BUDGET_CLASS,'''
if s.count(old)!=1:
    raise SystemExit('parent receive import anchor changed')
s=s.replace(old,new)
old='    Receive(Box<ReceiveError>),\n    Http(Box<HttpError>),'
new='    Receive(Box<ReceiveError>),\n    ReceiveTransport(Box<NodeReceiveTransportRefusal>),\n    Http(Box<HttpError>),'
if s.count(old)!=1:
    raise SystemExit('receive error variant anchor changed')
s=s.replace(old,new)
old='''            Self::Receive(error) => Display::fmt(error, formatter),
            Self::Http(error) => Display::fmt(error, formatter),'''
new='''            Self::Receive(error) => Display::fmt(error, formatter),
            Self::ReceiveTransport(error) => Display::fmt(error, formatter),
            Self::Http(error) => Display::fmt(error, formatter),'''
if s.count(old)!=1:
    raise SystemExit('receive display anchor changed')
s=s.replace(old,new)
old='''            Self::Receive(error) => Some(error.as_ref()),
            Self::Http(error) => Some(error.as_ref()),'''
new='''            Self::Receive(error) => Some(error.as_ref()),
            Self::ReceiveTransport(error) => Some(error.as_ref()),
            Self::Http(error) => Some(error.as_ref()),'''
if s.count(old)!=1:
    raise SystemExit('receive source anchor changed')
s=s.replace(old,new)
old='''impl From<ReceiveError> for NodeSmartHttpRefusal {
    fn from(value: ReceiveError) -> Self {
        Self::Receive(Box::new(value))
    }
}'''
new='''impl From<ReceiveError> for NodeSmartHttpRefusal {
    fn from(value: ReceiveError) -> Self {
        Self::Receive(Box::new(value))
    }
}
impl From<NodeReceiveTransportRefusal> for NodeSmartHttpRefusal {
    fn from(value: NodeReceiveTransportRefusal) -> Self {
        Self::ReceiveTransport(Box::new(value))
    }
}'''
if s.count(old)!=1:
    raise SystemExit('receive From anchor changed')
s=s.replace(old,new)
# Insert response type before the refusal enum.
anchor='/// Typed refusal at the node-owned Smart HTTP composition boundary.\n#[derive(Debug)]\npub enum NodeSmartHttpRefusal {'
response=r'''/// One completed canonical receive decision plus its bounded Git report-status response.
///
/// Construction finishes HTTP framing before admission begins. Returning this
/// value means the canonical receive path reached a terminal authority outcome;
/// failure by an outer socket writer after this point MUST NOT be interpreted
/// as proof of non-commit. Retrying the caller-owned idempotency key is the
/// recovery path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSmartHttpReceiveResponse {
    head: String,
    body: Vec<u8>,
}

impl NodeSmartHttpReceiveResponse {
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Typed refusal at the node-owned Smart HTTP composition boundary.
#[derive(Debug)]
pub enum NodeSmartHttpRefusal {'''
if s.count(anchor)!=1:
    raise SystemExit('response type insertion anchor changed')
s=s.replace(anchor,response)
# Helpers are inserted before impl OneNode.
anchor='impl OneNode {'
helpers=r'''fn decode_http_request_body(
    request: &RequestHead<'_>,
    body_wire: &[u8],
    limits: HttpLimits,
) -> Result<Vec<u8>, NodeSmartHttpRefusal> {
    let mut decoder = BodyDecoder::new(request.body, limits)?;
    let mut remaining = body_wire;
    let mut decoded = Vec::new();
    while !decoder.is_complete() && !remaining.is_empty() {
        let step = decoder.push(remaining)?;
        if !step.data.is_empty() {
            decoded
                .try_reserve(step.data.len())
                .map_err(|_| WireError::AllocationFailure)?;
            decoded.extend_from_slice(step.data);
        }
        if step.consumed == 0 && !step.complete {
            return Err(HttpError::TruncatedBody.into());
        }
        remaining = &remaining[step.consumed..];
    }
    decoder.finish()?;
    if !remaining.is_empty() {
        return Err(NodeSmartHttpRefusal::TrailingRequestBytes {
            count: remaining.len(),
        });
    }
    Ok(decoded)
}

fn receive_request_prefix(
    context: ReceiveContext,
    body: &[u8],
) -> Result<ReceiveRequest, NodeSmartHttpRefusal> {
    let mut receive = ReceivePack::new(context)?;
    for chunk in body.chunks(1024) {
        let transition = receive.push_bytes(chunk)?;
        for event in transition.events {
            if let ReceiveEvent::RequestReady(request) = event {
                return Ok(*request);
            }
        }
    }
    Err(ReceiveError::IncompleteRequest {
        state: receive.phase(),
    }
    .into())
}

impl OneNode {'''
if s.count(anchor)!=1:
    raise SystemExit('impl OneNode anchor changed')
s=s.replace(anchor,helpers)
method=r'''

    /// Execute one authenticated Smart HTTP receive-pack request through the
    /// existing durable receive boundary.
    ///
    /// The complete HTTP body is decoded and its exact boundary is proven
    /// before materialization or admission. The decoded Git request is then
    /// parsed by the same native receive machine and admitted by
    /// `receive_loopback_pack_durable_in`, which owns production quarantine,
    /// closure validation, policy, sealed identity, exact-predecessor CAS, and
    /// retry recovery. This adapter never publishes from HTTP status or local
    /// object placement.
    pub fn smart_http_receive_rpc_in<C>(
        &self,
        request: &RequestHead<'_>,
        session: &LoopbackReceiveSession,
        body_wire: &[u8],
        http_limits: HttpLimits,
        receive_limits: ReceiveLimits,
        parse_limits: fgit_git_object::ParseLimits,
        admission_limits: AdmissionLimits,
        cancellation: &mut C,
    ) -> Result<NodeSmartHttpReceiveResponse, NodeSmartHttpRefusal>
    where
        C: ReceiveCancellation,
    {
        if !self.smart_http_route_matches(request) {
            return Err(NodeSmartHttpRefusal::RepositoryRouteMismatch);
        }
        if request.operation != Operation::Rpc(Service::ReceivePack) {
            return Err(NodeSmartHttpRefusal::UnsupportedOperation);
        }
        if !matches!(session, LoopbackReceiveSession::Authenticated(_)) {
            return Err(NodeSmartHttpRefusal::UnauthenticatedReceive);
        }
        if request.requested_version == ProtocolVersion::V2 {
            return Err(HttpError::UnsupportedVersion.into());
        }
        if !cancellation.checkpoint() {
            return Err(ReceiveError::Cancelled.into());
        }

        // This is deliberately complete before any authority-backed mutation.
        let decoded = decode_http_request_body(request, body_wire, http_limits)?;
        if !cancellation.checkpoint() {
            return Err(ReceiveError::Cancelled.into());
        }

        let format_name = match self.object_format {
            fgit_types::GitHashAlgorithm::Sha1 => "sha1",
            fgit_types::GitHashAlgorithm::Sha256 => "sha256",
        };
        let capability_text =
            format!("report-status delete-refs ofs-delta object-format={format_name}");
        let server_capabilities =
            Capabilities::parse_v1(capability_text.as_bytes(), &receive_limits.wire)?;
        let wire_format = match self.object_format {
            fgit_types::GitHashAlgorithm::Sha1 => fgit_wire::GitObjectFormat::Sha1,
            fgit_types::GitHashAlgorithm::Sha256 => fgit_wire::GitObjectFormat::Sha256,
        };
        let context = ReceiveContext::new(
            wire_format,
            server_capabilities,
            receive_limits.clone(),
            SignedPushProfile::Refuse,
        )?;
        // Retain just the semantic request needed to render canonical outcomes.
        // The authoritative path reparses the same bounded bytes and owns the
        // actual quarantine; this prefix parser stops as soon as RequestReady
        // is emitted and never substitutes for production validation.
        let ready = receive_request_prefix(context.clone(), &decoded)?;

        let deadline = GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
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
            .map_err(NodeAdmissionViewRefusal::from)?;
        if admission_deadline_expired.load(Ordering::Relaxed) || deadline.expired() {
            return Err(NodeGitDaemonServeRefusal::from(
                GitDaemonTransportRefusal::SessionDeadlineExceeded {
                    operation: "materialize smart HTTP receive admission",
                },
            )
            .into());
        }

        let outcome = self
            .runtime
            .block_on(self.receive_loopback_pack_durable_in(
                &node_request,
                session,
                &materialized,
                context,
                &decoded,
                parse_limits,
                admission_limits,
                cancellation,
            ))
            .map_err(NodeSmartHttpRefusal::from)?;
        let report = outcome.report_packets(&ready, &receive_limits)?;
        let body = encode_packets(&report, &receive_limits.wire)?;
        let length = u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
        Ok(NodeSmartHttpReceiveResponse {
            head: success_head(request, Some(length)),
            body,
        })
    }
'''
idx=s.rfind('\n}')
if idx<0:
    raise SystemExit('impl OneNode terminator not found')
s=s[:idx]+method+s[idx:]
p.write_text(s)
PY

# Export the completed receive response surface.
python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/src/lib.rs')
s=p.read_text()
old='pub use smart_http::{NodeSmartHttpDiscovery, NodeSmartHttpRefusal, NodeSmartHttpUploadReceipt};'
new='pub use smart_http::{\n    NodeSmartHttpDiscovery, NodeSmartHttpReceiveResponse, NodeSmartHttpRefusal,\n    NodeSmartHttpUploadReceipt,\n};'
if s.count(old)!=1:
    raise SystemExit('node smart HTTP export anchor changed')
p.write_text(s.replace(old,new))
PY

cat > crates/fgit-node/tests/smart_http_receive.rs <<'RS'
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::AdmissionLimits;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_git_object::ParseLimits;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use fgit_wire::receive::ReceiveLimits;
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::WireLimits;

const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const PUSHED_BLOB: &[u8] = b"smart HTTP receive: canonical pushed blob\n";
const PUSHED_REF: &str = "refs/tags/smart-http-fixture";
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-smart-http-receive-{}-{sequence}",
            std::process::id()
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x91; 16]),
        RepositoryId::from_bytes([0x92; 16]),
    )
}

fn serving_node(scratch: &Scratch, initialize: bool) -> OneNode {
    if initialize {
        let (created, _) = OneNode::init(config(scratch.0.clone())).expect("node initializes");
        created.shutdown().expect("initialized node closes");
    }
    let mut node = OneNode::open_existing(config(scratch.0.clone())).expect("node reopens");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("node enters service");
    node
}

fn session() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x77; 16]),
        IdempotencyKey::new(b"smart-http-receive-rpc".to_vec()).expect("retry key is bounded"),
    )
}

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut frame = format!("{:04x}", payload.len() + 4).into_bytes();
    frame.extend_from_slice(payload);
    frame
}

fn object_header(kind: u8, declared_size: usize) -> Vec<u8> {
    let mut remaining = declared_size;
    let mut first = (kind << 4) | u8::try_from(remaining & 0x0f).expect("masked size");
    remaining >>= 4;
    if remaining == 0 {
        return vec![first];
    }
    first |= 0x80;
    let mut header = vec![first];
    while remaining != 0 {
        let mut next = u8::try_from(remaining & 0x7f).expect("masked size");
        remaining >>= 7;
        if remaining != 0 {
            next |= 0x80;
        }
        header.push(next);
    }
    header
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("fixture fits one stored block");
    let mut member = vec![0x78, 0x01, 0x01];
    member.extend_from_slice(&length.to_le_bytes());
    member.extend_from_slice(&(!length).to_le_bytes());
    member.extend_from_slice(bytes);
    member.extend_from_slice(&adler32(bytes).to_be_bytes());
    member
}

fn blob_pack(body: &[u8]) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&object_header(3, body.len()));
    pack.extend_from_slice(&zlib_stored(body));
    let trailer = sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

fn push_body() -> Vec<u8> {
    let oid = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, PUSHED_BLOB);
    let command = format!("{ZERO_OID} {oid} {PUSHED_REF}\0report-status");
    let mut body = pkt_line(command.as_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&blob_pack(PUSHED_BLOB));
    body
}

fn receive_head(route: &str, body_len: usize) -> Vec<u8> {
    format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {body_len}\r\n\r\n"
    )
    .into_bytes()
}

fn upload_discovery_head(route: &str) -> Vec<u8> {
    format!(
        "GET {route}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: loopback\r\n\r\n"
    )
    .into_bytes()
}

fn receive_once(
    node: &OneNode,
    session: &LoopbackReceiveSession,
    body_wire: &[u8],
    declared_len: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<fgit_node::NodeSmartHttpReceiveResponse, NodeSmartHttpRefusal> {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head_bytes = receive_head(route, declared_len);
    let head = parse_head(&head_bytes, HttpLimits::default()).unwrap().unwrap();
    node.smart_http_receive_rpc_in(
        &head,
        session,
        body_wire,
        HttpLimits::default(),
        ReceiveLimits::default(),
        ParseLimits::default(),
        AdmissionLimits::default(),
        live,
    )
}

fn advertised(node: &OneNode) -> Vec<u8> {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = upload_discovery_head(route);
    let head = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    node.smart_http_upload_discovery_in(&head, WireLimits::default())
        .unwrap()
        .body()
        .to_vec()
}

#[test]
fn authenticated_http_push_publishes_through_canonical_receive_and_survives_reopen() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, true);
    let body = push_body();
    let mut live = || true;
    let response = receive_once(&node, &session(), &body, body.len(), &mut live)
        .expect("authenticated HTTP receive reaches terminal authority outcome");
    assert!(response.head().contains("application/x-git-receive-pack-result"));
    assert!(response.body().windows(b"unpack ok".len()).any(|w| w == b"unpack ok"));
    assert!(response.body().windows(PUSHED_REF.len()).any(|w| w == PUSHED_REF.as_bytes()));
    assert!(advertised(&node).windows(PUSHED_REF.len()).any(|w| w == PUSHED_REF.as_bytes()));
    node.shutdown().unwrap();

    let reopened = serving_node(&scratch, false);
    assert!(advertised(&reopened).windows(PUSHED_REF.len()).any(|w| w == PUSHED_REF.as_bytes()));
    reopened.shutdown().unwrap();
}

#[test]
fn anonymous_receive_and_http_suffix_refuse_before_publication() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, true);
    let body = push_body();
    let mut live = || true;
    assert!(matches!(
        receive_once(
            &node,
            &LoopbackReceiveSession::Anonymous,
            &body,
            body.len(),
            &mut live,
        ),
        Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
    ));
    assert!(!advertised(&node).windows(PUSHED_REF.len()).any(|w| w == PUSHED_REF.as_bytes()));

    let mut with_suffix = body.clone();
    with_suffix.extend_from_slice(b"NEXT");
    assert!(matches!(
        receive_once(&node, &session(), &with_suffix, body.len(), &mut live),
        Err(NodeSmartHttpRefusal::TrailingRequestBytes { count: 4 })
    ));
    assert!(!advertised(&node).windows(PUSHED_REF.len()).any(|w| w == PUSHED_REF.as_bytes()));
    node.shutdown().unwrap();
}

#[test]
fn cancelled_http_receive_publishes_nothing() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, true);
    let body = push_body();
    let mut cancelled = || false;
    assert!(receive_once(&node, &session(), &body, body.len(), &mut cancelled).is_err());
    assert!(!advertised(&node).windows(PUSHED_REF.len()).any(|w| w == PUSHED_REF.as_bytes()));
    node.shutdown().unwrap();
}
RS

rustfmt --edition 2024 --config skip_children=true \
  crates/fgit-node/src/smart_http.rs \
  crates/fgit-node/tests/smart_http_receive.rs
git diff --check
git add -- crates/fgit-node/src/lib.rs crates/fgit-node/src/smart_http.rs crates/fgit-node/tests/smart_http_receive.rs
git commit -m 'feat(node): admit authenticated smart HTTP pushes canonically (FG-105a)'

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$RUNNER_TEMP/frankengit-node-http-receive-rpc-target"
cargo test -p fgit-node --test smart_http_receive --test smart_http_node
cargo check -p fgit-node --lib

test -z "$(git status --porcelain)"
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"
git push origin HEAD:refs/heads/main
published="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$published" = "$(git rev-parse HEAD)"
echo "PUBLISHED=$published"
