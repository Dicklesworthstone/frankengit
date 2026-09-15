#!/usr/bin/env bash
set -euo pipefail

BASE="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test -n "$BASE"
work="$RUNNER_TEMP/node-smart-http-receive-discovery"
git worktree add --detach "$work" "$BASE"
cd "$work"
git config user.name 'Jeff Emanuel'
git config user.email '35050222+Dicklesworthstone@users.noreply.github.com'

python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/src/smart_http.rs')
s=p.read_text()
old='use fgit_wire::receive::ReceiveCancellation;'
new='use fgit_wire::receive::{ReceiveCancellation, ReceiveContext, ReceiveError, ReceiveLimits, SignedPushProfile};'
if s.count(old)!=1:
    raise SystemExit('receive import anchor changed')
s=s.replace(old,new)
old='use fgit_wire::smart_http::rpc::{RpcError, UploadRpc, upload_discovery};'
new='use fgit_wire::smart_http::rpc::{RpcError, UploadRpc, receive_discovery, upload_discovery};'
if s.count(old)!=1:
    raise SystemExit('smart HTTP rpc import anchor changed')
s=s.replace(old,new)
old='    RepositoryRouteMismatch,\n    UnsupportedOperation,'
new='    RepositoryRouteMismatch,\n    UnsupportedOperation,\n    /// Receive-pack discovery is never available without caller-authenticated identity.\n    UnauthenticatedReceive,'
if s.count(old)!=1:
    raise SystemExit('refusal variant anchor changed')
s=s.replace(old,new)
old='    Rpc(Box<RpcError>),\n    Http(Box<HttpError>),'
new='    Rpc(Box<RpcError>),\n    Receive(Box<ReceiveError>),\n    Http(Box<HttpError>),'
if s.count(old)!=1:
    raise SystemExit('wire refusal anchor changed')
s=s.replace(old,new)
old='''            Self::UnsupportedOperation => {
                formatter.write_str("smart HTTP operation is not served by this node entry point")
            }
            Self::TrailingRequestBytes { count } => {'''
new='''            Self::UnsupportedOperation => {
                formatter.write_str("smart HTTP operation is not served by this node entry point")
            }
            Self::UnauthenticatedReceive => {
                formatter.write_str("smart HTTP receive-pack requires an authenticated principal")
            }
            Self::TrailingRequestBytes { count } => {'''
if s.count(old)!=1:
    raise SystemExit('display anchor changed')
s=s.replace(old,new)
old='''            Self::Rpc(error) => Display::fmt(error, formatter),
            Self::Http(error) => Display::fmt(error, formatter),'''
new='''            Self::Rpc(error) => Display::fmt(error, formatter),
            Self::Receive(error) => Display::fmt(error, formatter),
            Self::Http(error) => Display::fmt(error, formatter),'''
if s.count(old)!=1:
    raise SystemExit('display error anchor changed')
s=s.replace(old,new)
old='''            Self::Rpc(error) => Some(error.as_ref()),
            Self::Http(error) => Some(error.as_ref()),'''
new='''            Self::Rpc(error) => Some(error.as_ref()),
            Self::Receive(error) => Some(error.as_ref()),
            Self::Http(error) => Some(error.as_ref()),'''
if s.count(old)!=1:
    raise SystemExit('source error anchor changed')
s=s.replace(old,new)
old='''            Self::RepositoryRouteMismatch
            | Self::UnsupportedOperation
            | Self::TrailingRequestBytes { .. } => None,'''
new='''            Self::RepositoryRouteMismatch
            | Self::UnsupportedOperation
            | Self::UnauthenticatedReceive
            | Self::TrailingRequestBytes { .. } => None,'''
if s.count(old)!=1:
    raise SystemExit('source terminal anchor changed')
s=s.replace(old,new)
old='''impl From<HttpError> for NodeSmartHttpRefusal {
    fn from(value: HttpError) -> Self {
        Self::Http(Box::new(value))
    }
}'''
new='''impl From<ReceiveError> for NodeSmartHttpRefusal {
    fn from(value: ReceiveError) -> Self {
        Self::Receive(Box::new(value))
    }
}
impl From<HttpError> for NodeSmartHttpRefusal {
    fn from(value: HttpError) -> Self {
        Self::Http(Box::new(value))
    }
}'''
if s.count(old)!=1:
    raise SystemExit('From<HttpError> anchor changed')
s=s.replace(old,new)
# Add LoopbackReceiveSession to the parent imports.
old='    NodePackMaterializationRefusal, OneNode, PackContextCheckpoint, SELECTED_PACK_BUDGET_CLASS,'
new='    LoopbackReceiveSession, NodePackMaterializationRefusal, OneNode, PackContextCheckpoint,\n    SELECTED_PACK_BUDGET_CLASS,'
if s.count(old)!=1:
    raise SystemExit('parent import anchor changed')
s=s.replace(old,new)
method=r'''

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
'''
idx=s.rfind('\n}')
if idx < 0:
    raise SystemExit('impl OneNode terminator not found')
s=s[:idx]+method+s[idx:]
p.write_text(s)
PY

python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/tests/smart_http_node.rs')
s=p.read_text()
s=s.replace(
    'use fgit_node::{NodeConfig, NodeSmartHttpRefusal, OneNode};',
    'use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};',
    1,
)
insert='''use fgit_authority::IdempotencyKey;\nuse fgit_types::PrincipalId;\n'''
anchor='use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};\n'
if insert not in s:
    s=s.replace(anchor, anchor+insert, 1)
s += r'''

fn receive_discovery_request(route: &str, protocol: Option<&str>) -> Vec<u8> {
    let protocol = protocol.map_or(String::new(), |value| format!("Git-Protocol: {value}\r\n"));
    format!(
        "GET {route}/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: loopback\r\n{protocol}\r\n"
    )
    .into_bytes()
}

fn authenticated_receive() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x77; 16]),
        IdempotencyKey::new(b"smart-http-receive-discovery".to_vec())
            .expect("fixed retry key is bounded"),
    )
}

#[test]
fn authenticated_receive_discovery_uses_authority_visible_refs() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = receive_discovery_request(route, None);
    let head = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    let response = node
        .smart_http_receive_discovery_in(
            &head,
            &authenticated_receive(),
            WireLimits::default(),
        )
        .expect("authenticated receive discovery serves");
    assert_eq!(response.version(), ProtocolVersion::V0);
    assert!(response.head().contains("application/x-git-receive-pack-advertisement"));
    assert!(response.body().starts_with(b"001f# service=git-receive-pack\n0000"));
    assert!(response.body().windows(b"report-status".len()).any(|w| w == b"report-status"));
    assert!(response.body().windows(b"object-format=sha1".len()).any(|w| w == b"object-format=sha1"));
    node.shutdown().unwrap();
}

#[test]
fn receive_discovery_refuses_anonymous_and_protocol_v2() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let anonymous_bytes = receive_discovery_request(route, None);
    let anonymous_head = parse_head(&anonymous_bytes, HttpLimits::default()).unwrap().unwrap();
    assert!(matches!(
        node.smart_http_receive_discovery_in(
            &anonymous_head,
            &LoopbackReceiveSession::Anonymous,
            WireLimits::default(),
        ),
        Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
    ));
    let v2_bytes = receive_discovery_request(route, Some("version=2"));
    let v2_head = parse_head(&v2_bytes, HttpLimits::default()).unwrap().unwrap();
    assert!(node
        .smart_http_receive_discovery_in(
            &v2_head,
            &authenticated_receive(),
            WireLimits::default(),
        )
        .is_err());
    node.shutdown().unwrap();
}

#[test]
fn receive_discovery_sha256_retains_authenticated_object_domain() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha256);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = receive_discovery_request(route, None);
    let head = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    let response = node
        .smart_http_receive_discovery_in(
            &head,
            &authenticated_receive(),
            WireLimits::default(),
        )
        .unwrap();
    assert!(response.body().windows(b"object-format=sha256".len()).any(|w| w == b"object-format=sha256"));
    node.shutdown().unwrap();
}
'''
p.write_text(s)
PY

rustfmt --edition 2024 --config skip_children=true \
  crates/fgit-node/src/smart_http.rs \
  crates/fgit-node/tests/smart_http_node.rs
git diff --check
git add -- crates/fgit-node/src/smart_http.rs crates/fgit-node/tests/smart_http_node.rs
git commit -m 'feat(node): authenticate smart HTTP receive discovery (FG-105a)'

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$RUNNER_TEMP/frankengit-node-http-receive-discovery-target"
cargo test -p fgit-node --test smart_http_node
cargo check -p fgit-node --lib

test -z "$(git status --porcelain)"
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"
git push origin HEAD:refs/heads/main
published="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$published" = "$(git rev-parse HEAD)"
echo "PUBLISHED=$published"
