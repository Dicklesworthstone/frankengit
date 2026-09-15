#!/usr/bin/env bash
set -euo pipefail

BASE=1d91fcd059c505e35d94d7ab474edda1f7748fbc
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"

work="$RUNNER_TEMP/node-smart-http-discovery"
git worktree add --detach "$work" "$BASE"
cd "$work"
git config user.name 'Jeff Emanuel'
git config user.email '35050222+Dicklesworthstone@users.noreply.github.com'

python3 - <<'PY'
from pathlib import Path
p=Path('crates/fgit-node/src/lib.rs')
s=p.read_text()
old='mod loose_import;\nmod merge_delivery;\n'
new='mod loose_import;\nmod merge_delivery;\nmod smart_http;\npub use smart_http::{NodeSmartHttpDiscovery, NodeSmartHttpRefusal};\n'
if s.count(old)!=1:
    raise SystemExit('node module insertion anchor changed')
p.write_text(s.replace(old,new))
PY

cat > crates/fgit-node/src/smart_http.rs <<'RS'
//! Authority-backed Smart HTTP composition for one FrankenGit node.
//!
//! This module deliberately begins at the post-routing boundary. `fgit-wire`
//! owns hostile HTTP/Git framing; an outer gateway owns credentials and route
//! selection. The node rechecks that the canonical repository route selects
//! this repository before any authority read, then builds advertisements from
//! one authenticated durable admission snapshot. No URL, header, or local ref
//! map can become repository authority.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use fgit_wire::smart_http::rpc::{RpcError, upload_discovery};
use fgit_wire::smart_http::{Operation, ProtocolVersion, RequestHead, Service, success_head};
use fgit_wire::{Capabilities, Packet, UploadPackRepository, WireError, WireLimits};

use super::{
    AdmissionUploadPackRepository, NodeAdmissionViewRefusal, OneNode, git_daemon_capabilities,
};

/// Complete successful Smart HTTP discovery response.
///
/// Discovery bodies are bounded and small relative to packs, so retaining the
/// body here avoids inventing a second streaming abstraction for advertisements.
/// RPC pack bodies use the pull-driven response path instead.
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

/// Typed refusal at the node-owned Smart HTTP composition boundary.
#[derive(Debug)]
pub enum NodeSmartHttpRefusal {
    /// The already parsed route does not select this node's canonical repository.
    RepositoryRouteMismatch,
    /// This entry point serves upload-pack discovery only.
    UnsupportedOperation,
    /// The authenticated durable admission view could not be selected.
    Admission(Box<NodeAdmissionViewRefusal>),
    /// Git/HTTP wire composition refused the request.
    Rpc(Box<RpcError>),
    /// Capability construction itself violated the bounded wire profile.
    Wire(Box<WireError>),
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
            Self::Admission(error) => Display::fmt(error, formatter),
            Self::Rpc(error) => Display::fmt(error, formatter),
            Self::Wire(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeSmartHttpRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error.as_ref()),
            Self::Rpc(error) => Some(error.as_ref()),
            Self::Wire(error) => Some(error.as_ref()),
            Self::RepositoryRouteMismatch | Self::UnsupportedOperation => None,
        }
    }
}

impl From<NodeAdmissionViewRefusal> for NodeSmartHttpRefusal {
    fn from(value: NodeAdmissionViewRefusal) -> Self {
        Self::Admission(Box::new(value))
    }
}

impl From<RpcError> for NodeSmartHttpRefusal {
    fn from(value: RpcError) -> Self {
        Self::Rpc(Box::new(value))
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
        let encoded = git_daemon_capabilities(
            node.object_format,
            repository.symref_target(b"HEAD"),
        );
        return Capabilities::parse_v1(&encoded, limits).map_err(NodeSmartHttpRefusal::from);
    }

    // Keep protocol-v2 feature semantics byte-for-byte aligned with the native
    // daemon lane. V2 advertises command/value features, not the legacy token
    // set; parsing this canonical packet group gives UploadRpc the same server
    // capability object that discovery exposes to the client.
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
    Capabilities::parse_v2_advertisement(&packets, limits)
        .map_err(NodeSmartHttpRefusal::from)
}

impl OneNode {
    fn smart_http_route_matches(&self, request: &RequestHead<'_>) -> bool {
        request.repository_route.as_bytes() == self.git_daemon_repository_path.as_bytes()
    }

    /// Build one complete upload-pack discovery response from authenticated
    /// canonical state.
    ///
    /// Route equality is checked before any authority work. The durable
    /// admission view then applies hidden-ref policy before the wire layer sees
    /// refs, and the selected hash domain comes from authenticated repository
    /// configuration rather than request metadata. V0, V1, and V2 therefore
    /// share one authority path while retaining their distinct wire grammar.
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
        let capabilities = upload_capabilities(self, &repository, request.requested_version, &limits)?;
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
}
RS

cat > crates/fgit-node/tests/smart_http_node.rs <<'RS'
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::cell::CellTransitionCause;
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::smart_http::{ProtocolVersion, parse_head};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let n=NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("frankengit-smart-http-node-{}-{n}", std::process::id())))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.0); }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x81;16]),
        RepositoryId::from_bytes([0x82;16]),
    )
}

fn serving_node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _)=OneNode::init(config(scratch.0.clone()).with_object_format(format))
        .expect("node initializes");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("node enters service");
    node
}

fn request(route: &str, protocol: Option<&str>) -> Vec<u8> {
    let protocol=protocol.map_or(String::new(), |value| format!("Git-Protocol: {value}\r\n"));
    format!(
        "GET {route}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: loopback\r\n{protocol}\r\n"
    ).into_bytes()
}

#[test]
fn discovery_v2_comes_from_the_real_empty_authority_view() {
    let scratch=Scratch::new();
    let node=serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route=std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
        .expect("canonical route is UTF-8");
    let bytes=request(route, Some("version=2"));
    let head=parse_head(&bytes, Default::default()).expect("head parses").expect("head complete");
    let response=node.smart_http_upload_discovery_in(&head, WireLimits::default())
        .expect("authority-backed v2 discovery serves");
    assert_eq!(response.version(), ProtocolVersion::V2);
    assert!(response.head().starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.head().contains("application/x-git-upload-pack-advertisement"));
    assert!(response.body().starts_with(b"000eversion 2\n"));
    assert!(response.body().windows(b"object-format=sha1".len()).any(|w| w==b"object-format=sha1"));
    node.shutdown().expect("node shuts down");
}

#[test]
fn discovery_sha256_retains_the_authenticated_object_domain() {
    let scratch=Scratch::new();
    let node=serving_node(&scratch, GitHashAlgorithm::Sha256);
    let route=std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes=request(route, None);
    let head=parse_head(&bytes, Default::default()).unwrap().unwrap();
    let response=node.smart_http_upload_discovery_in(&head, WireLimits::default()).unwrap();
    assert_eq!(response.version(), ProtocolVersion::V0);
    assert!(response.body().starts_with(b"001e# service=git-upload-pack\n0000"));
    assert!(response.body().windows(b"object-format=sha256".len()).any(|w| w==b"object-format=sha256"));
    node.shutdown().unwrap();
}

#[test]
fn mismatched_route_refuses_before_repository_service() {
    let scratch=Scratch::new();
    let node=serving_node(&scratch, GitHashAlgorithm::Sha1);
    let bytes=request("/not-this-repository.git", None);
    let head=parse_head(&bytes, Default::default()).unwrap().unwrap();
    assert!(matches!(
        node.smart_http_upload_discovery_in(&head, WireLimits::default()),
        Err(NodeSmartHttpRefusal::RepositoryRouteMismatch)
    ));
    node.shutdown().unwrap();
}
RS

# Remove an unused import if the current CellTransition API doesn't require it.
sed -i '/use fgit_types::cell::CellTransitionCause;/d' crates/fgit-node/tests/smart_http_node.rs

rustfmt --edition 2024 --config skip_children=true \
  crates/fgit-node/src/smart_http.rs \
  crates/fgit-node/tests/smart_http_node.rs
# Formatting lib.rs recursively would touch unrelated files; only normalize the inserted lines via cargo fmt later if required.
git diff --check

git add -- crates/fgit-node/src/lib.rs crates/fgit-node/src/smart_http.rs crates/fgit-node/tests/smart_http_node.rs
git commit -m 'feat(node): bind smart HTTP discovery to canonical authority (FG-105a)'

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$RUNNER_TEMP/frankengit-node-http-discovery-target"
cargo test -p fgit-node --test smart_http_node
cargo check -p fgit-node --lib

test -z "$(git status --porcelain)"
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"
git push origin HEAD:refs/heads/main
published="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$published" = "$(git rev-parse HEAD)"
echo "PUBLISHED=$published"
