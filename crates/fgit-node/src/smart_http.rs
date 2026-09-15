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
        let encoded =
            git_daemon_capabilities(node.object_format, repository.symref_target(b"HEAD"));
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
    Capabilities::parse_v2_advertisement(&packets, limits).map_err(NodeSmartHttpRefusal::from)
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
}
