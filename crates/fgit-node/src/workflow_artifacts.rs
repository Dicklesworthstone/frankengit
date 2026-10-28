//! Explicit reads from the repository's trusted-workflow custody namespace.
//!
//! The transport grants access to the entire selected namespace independently
//! of Git/source permissions. An artifact ID is only a selector. Neither its
//! existence nor asserted provenance authorizes a canonical check or cache hit.
//! Every read authenticates the current repository incarnation and verifies the
//! complete immutable payload before returning metadata or any content bytes.

use crate::{NodeRefusal, NodeRequestContext, OneNode, TRUSTED_WORKFLOW_ARTIFACT_TRUST};
use fgit_authority::{OutcomeFailure, read_repository_incarnation_configuration_async};
use fgit_object_fabric::ArtifactIdentity;
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactScope, ArtifactStorageError, LocalArtifactStore,
};
use fgit_schema::json::{self, Value, object, text};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};
use std::time::Duration;

/// The complete payload must fit this finite verification and response profile.
pub const MAX_WORKFLOW_ARTIFACT_READ_BYTES: u64 = 64 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_METADATA_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub enum WorkflowArtifactReadRefusal {
    Disabled,
    InvalidId,
    InvalidMetadata,
    InvalidScope,
    Cell(CellRefusal),
    Authority(Box<NodeRefusal>),
    Configuration(Box<OutcomeFailure>),
    Root(ArtifactStorageError),
    Storage(ArtifactStorageError),
}
impl WorkflowArtifactReadRefusal {
    /// Stable transport-safe cause. Detailed storage paths are never disclosed.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "artifact_storage_disabled",
            Self::InvalidId => "invalid_artifact_id",
            Self::Storage(ArtifactStorageError::NotFound) => "artifact_not_found",
            Self::Storage(ArtifactStorageError::PayloadLimit) => "artifact_payload_limit",
            Self::Storage(ArtifactStorageError::Cancelled | ArtifactStorageError::Deadline) => {
                "artifact_request_expired"
            }
            _ => "artifact_storage_unavailable",
        }
    }
}
impl std::fmt::Display for WorkflowArtifactReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "workflow artifact read refused: {self:?}")
    }
}
impl std::error::Error for WorkflowArtifactReadRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error.as_ref()),
            Self::Configuration(error) => Some(error.as_ref()),
            Self::Root(error) | Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

/// Parse the artifact identity, not its payload digest, path, or trust domain.
pub fn parse_artifact_id(value: &str) -> Result<Digest, WorkflowArtifactReadRefusal> {
    if value.len() != 64 {
        return Err(WorkflowArtifactReadRefusal::InvalidId);
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(WorkflowArtifactReadRefusal::InvalidId),
    };
    let mut bytes = [0u8; 32];
    for (output, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered SHA-256"),
        DigestBytes::try_new(&bytes).expect("SHA-256 width"),
    ))
}
fn valid_id(id: &Digest) -> Result<(), WorkflowArtifactReadRefusal> {
    if id.algorithm() != DigestAlgorithmId::try_new(2).expect("registered SHA-256")
        || id.bytes().as_bytes().len() != 32
    {
        return Err(WorkflowArtifactReadRefusal::InvalidId);
    }
    Ok(())
}
fn hex(id: &Digest) -> String {
    id.bytes()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn optional(id: Option<&Digest>) -> Value {
    id.map_or(Value::Null, |id| text(hex(id)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowArtifactMetadata {
    scope: ArtifactScope,
    identity: ArtifactIdentity,
}
impl WorkflowArtifactMetadata {
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }
    /// Shared HTTP/MCP representation. Provenance fields are retained assertions,
    /// never a substitute for authenticated canonical workflow-check evidence.
    #[must_use]
    pub fn json_value(&self) -> Value {
        object([
            ("type", text("artifact_metadata")),
            ("schema_version", json::number(1)),
            ("tenant_id", text(self.scope.tenant().to_string())),
            ("repository_id", text(self.scope.repository().to_string())),
            (
                "repository_incarnation_id",
                text(self.scope.incarnation().to_string()),
            ),
            ("trust_domain", text(self.scope.trust_domain())),
            ("scope_sha256", text(hex(&self.scope.commitment()))),
            ("artifact_id", text(hex(self.identity.artifact_id()))),
            ("payload_sha256", text(hex(self.identity.payload_digest()))),
            ("payload_bytes", json::number(self.identity.payload_len())),
            ("media_type", text(self.identity.media_type().as_str())),
            ("kind", text(self.identity.payload_kind().label())),
            (
                "build_capsule_sha256",
                optional(self.identity.build_capsule_id()),
            ),
            (
                "check_receipt_sha256",
                optional(self.identity.check_receipt_id()),
            ),
            ("source_rcr_sha256", optional(self.identity.source_rcr())),
            (
                "retention_canonical_hex",
                text(
                    self.identity
                        .retention_profile()
                        .encode_canonical()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                ),
            ),
            ("payload_verified", Value::Bool(true)),
            ("provenance_authenticated", Value::Bool(false)),
            ("canonical_repository_published", Value::Bool(false)),
            ("retention_enforced", Value::Bool(false)),
            ("read_only", Value::Bool(true)),
        ])
    }
    pub fn to_json(&self) -> Result<String, WorkflowArtifactReadRefusal> {
        self.json_value()
            .encode(MAX_METADATA_BYTES)
            .map_err(|_| WorkflowArtifactReadRefusal::InvalidMetadata)
    }
}

#[derive(Debug)]
pub struct WorkflowArtifactPayload {
    metadata: WorkflowArtifactMetadata,
    bytes: Vec<u8>,
}
impl WorkflowArtifactPayload {
    #[must_use]
    pub const fn metadata(&self) -> &WorkflowArtifactMetadata {
        &self.metadata
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn into_parts(self) -> (WorkflowArtifactMetadata, Vec<u8>) {
        (self.metadata, self.bytes)
    }
}

fn checkpoint(request: &NodeRequestContext) -> Result<(), WorkflowArtifactReadRefusal> {
    request
        .authority()
        .checkpoint()
        .map_err(|_| WorkflowArtifactReadRefusal::Storage(ArtifactStorageError::Cancelled))
}

impl OneNode {
    fn workflow_artifact_store(&self) -> Result<LocalArtifactStore, WorkflowArtifactReadRefusal> {
        let root = self
            .service_config
            .workflow_artifact_root()
            .ok_or(WorkflowArtifactReadRefusal::Disabled)?;
        if !root.is_absolute() || root.as_os_str().as_encoded_bytes().len() > 4096 {
            return Err(WorkflowArtifactReadRefusal::InvalidScope);
        }
        let scope = ArtifactScope::new(
            self.tenant_id,
            self.repository_id,
            self.repository_incarnation_id,
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
        )
        .map_err(WorkflowArtifactReadRefusal::Root)?;
        LocalArtifactStore::open(root, scope).map_err(WorkflowArtifactReadRefusal::Root)
    }

    /// Validate the existing operator-owned private root without creating a
    /// namespace or granting any transport permission. Startup uses this before
    /// advertising the explicitly enabled artifact-read profile.
    pub fn validate_workflow_artifact_storage(&self) -> Result<(), WorkflowArtifactReadRefusal> {
        self.workflow_artifact_store().map(|_| ())
    }

    async fn verify_workflow_artifact_scope_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<(), WorkflowArtifactReadRefusal> {
        checkpoint(request)?;
        if self.service_config.workflow_artifact_root().is_none() {
            return Err(WorkflowArtifactReadRefusal::Disabled);
        }
        admits_read(self.cell_state(), ReadMode::Current)
            .map_err(WorkflowArtifactReadRefusal::Cell)?;
        let authenticated = self.authenticate_authority_head_in(request).await;
        checkpoint(request)?;
        let authenticated = authenticated
            .map_err(|error| WorkflowArtifactReadRefusal::Authority(Box::new(error)))?;
        let head = authenticated
            .body()
            .map_err(|_| WorkflowArtifactReadRefusal::InvalidScope)?;
        let configuration = read_repository_incarnation_configuration_async(
            &self.authority,
            request.authority(),
            &head.configuration_root,
        )
        .await;
        checkpoint(request)?;
        let configuration = configuration
            .map_err(|error| WorkflowArtifactReadRefusal::Configuration(Box::new(error)))?;
        if head.repository_id != self.repository_id
            || configuration.repository_incarnation_id != self.repository_incarnation_id
            || configuration.object_format != self.object_format
        {
            return Err(WorkflowArtifactReadRefusal::InvalidScope);
        }
        Ok(())
    }

    /// Fully verify one exact artifact without allocating its payload. The
    /// transport must already have granted repository-wide artifact custody
    /// access; ordinary source/ref visibility is a separate, narrower grant.
    pub async fn inspect_workflow_artifact_in(
        &self,
        request: &NodeRequestContext,
        id: &Digest,
    ) -> Result<WorkflowArtifactMetadata, WorkflowArtifactReadRefusal> {
        valid_id(id)?;
        checkpoint(request)?;
        let live = || request.authority().checkpoint().is_ok();
        let operation =
            ArtifactOperation::new(MAX_WORKFLOW_ARTIFACT_READ_BYTES, READ_TIMEOUT, &live)
                .map_err(WorkflowArtifactReadRefusal::Storage)?;
        self.verify_workflow_artifact_scope_in(request).await?;
        let store = self.workflow_artifact_store()?;
        let identity = store
            .inspect(id, &operation)
            .map_err(WorkflowArtifactReadRefusal::Storage)?;
        checkpoint(request)?;
        Ok(WorkflowArtifactMetadata {
            scope: store.scope().clone(),
            identity,
        })
    }

    /// Return bytes only after the whole scoped container, exact identity,
    /// length and payload digest verify. Corruption never returns a prefix.
    pub async fn read_workflow_artifact_in(
        &self,
        request: &NodeRequestContext,
        id: &Digest,
    ) -> Result<WorkflowArtifactPayload, WorkflowArtifactReadRefusal> {
        valid_id(id)?;
        checkpoint(request)?;
        let live = || request.authority().checkpoint().is_ok();
        let operation =
            ArtifactOperation::new(MAX_WORKFLOW_ARTIFACT_READ_BYTES, READ_TIMEOUT, &live)
                .map_err(WorkflowArtifactReadRefusal::Storage)?;
        self.verify_workflow_artifact_scope_in(request).await?;
        let store = self.workflow_artifact_store()?;
        let (identity, bytes) = store
            .read_payload(id, &operation)
            .map_err(WorkflowArtifactReadRefusal::Storage)?;
        checkpoint(request)?;
        Ok(WorkflowArtifactPayload {
            metadata: WorkflowArtifactMetadata {
                scope: store.scope().clone(),
                identity,
            },
            bytes,
        })
    }
}

#[cfg(test)]
mod tests;
