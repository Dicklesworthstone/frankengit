//! Authentication of canonical, explicitly sponsored agent credentials.
//!
//! The caller supplies a grant read from the exact authenticated repository
//! frontier and fresh revocation evidence. A successful result identifies the
//! agent and its finite read/metadata ceiling; it does not create an IntentRun,
//! authorize code publication, or widen the sponsor's authority.

use fgit_crypto::{sha256_digest, verify_mac};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

use crate::RevocationEvidence;
pub use fgit_forge::event::agent_credential::{
    ALL_OPERATIONS, AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant,
    AgentCredentialId, AgentCredentialSnapshot, DISCUSSIONS_READ, DISCUSSIONS_WRITE, ISSUES_READ,
    ISSUES_WRITE, MAX_LIFETIME_SECONDS, NativeAgentCredentialEvent, OUTCOMES_READ, PULLS_READ,
    PULLS_WRITE, SOURCE_CANDIDATES, SOURCE_HISTORY_READ, SOURCE_READ, SponsorKind,
};

/// Fixed finite input bound before hashing untrusted bearer bytes.
pub const MIN_AGENT_BEARER_BYTES: usize = 32;
pub const MAX_AGENT_BEARER_BYTES: usize = 256;

/// Authentication failures contain no bearer bytes or supplied identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentCredentialRefusal {
    InvalidGrant,
    InvalidBearer,
    BindingMismatch,
    NotYetValid,
    Expired,
    Revoked,
    RevocationEvidenceRequired,
    OperationNotGranted,
}

impl core::fmt::Display for AgentCredentialRefusal {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str(match self {
            Self::InvalidGrant => "invalid sponsored agent grant",
            Self::InvalidBearer => "invalid agent bearer credential",
            Self::BindingMismatch => "agent credential repository binding mismatch",
            Self::NotYetValid => "agent credential is not yet valid",
            Self::Expired => "agent credential expired",
            Self::Revoked => "agent credential revoked",
            Self::RevocationEvidenceRequired => "current agent revocation evidence is required",
            Self::OperationNotGranted => "agent credential does not grant this operation",
        })
    }
}

impl core::error::Error for AgentCredentialRefusal {}

/// Hashes a bounded bearer for issuance or lookup, without retaining the secret.
pub fn agent_credential_id(bearer: &[u8]) -> Result<AgentCredentialId, AgentCredentialRefusal> {
    if !(MIN_AGENT_BEARER_BYTES..=MAX_AGENT_BEARER_BYTES).contains(&bearer.len()) {
        return Err(AgentCredentialRefusal::InvalidBearer);
    }
    AgentCredentialId::try_new(sha256_digest(bearer)).ok_or(AgentCredentialRefusal::InvalidBearer)
}

/// An authenticated identity and its explicit operation ceiling. Fields are
/// private so callers cannot construct this result without authentication.
/// A host must additionally create and enforce its sponsored IntentRun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedAgentCredential {
    id: AgentCredentialId,
    grant: AgentCredentialGrant,
}

impl AuthenticatedAgentCredential {
    #[must_use]
    pub const fn id(&self) -> AgentCredentialId {
        self.id
    }

    #[must_use]
    pub const fn grant(&self) -> &AgentCredentialGrant {
        &self.grant
    }

    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.grant.agent
    }

    #[must_use]
    pub const fn sponsor(&self) -> PrincipalId {
        self.grant.sponsor
    }

    /// Checks the requested explicit flag(s), without interpreting an unknown
    /// flag as a broader permission. This is a ceiling, not publication consent.
    pub fn authorize(&self, operation: u16) -> Result<(), AgentCredentialRefusal> {
        if self.grant.permits(operation) {
            Ok(())
        } else {
            Err(AgentCredentialRefusal::OperationNotGranted)
        }
    }
}

/// Verify bearer, full repository binding, half-open lifetime, and current
/// revocation. Even read operations require a current revocation check.
///
/// `grant` and `revocation` must come from the same authenticated current forge
/// frontier. The caller may retain this result for one bounded in-flight request;
/// every subsequent request authenticates again against its own current read.
pub fn authenticate_agent_credential(
    id: AgentCredentialId,
    grant: &AgentCredentialGrant,
    presented_bearer: &[u8],
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    now: u64,
    revocation: RevocationEvidence,
) -> Result<AuthenticatedAgentCredential, AgentCredentialRefusal> {
    grant
        .validate()
        .map_err(|_| AgentCredentialRefusal::InvalidGrant)?;
    let presented = agent_credential_id(presented_bearer)?;
    if !verify_mac(id.as_bytes(), presented.as_bytes()) {
        return Err(AgentCredentialRefusal::InvalidBearer);
    }
    if grant.tenant != tenant || grant.repository != repository || grant.incarnation != incarnation
    {
        return Err(AgentCredentialRefusal::BindingMismatch);
    }
    if now < grant.issued_at {
        return Err(AgentCredentialRefusal::NotYetValid);
    }
    if now >= grant.expires_at {
        return Err(AgentCredentialRefusal::Expired);
    }
    match revocation {
        RevocationEvidence::Live => Ok(AuthenticatedAgentCredential { id, grant: *grant }),
        RevocationEvidence::Revoked => Err(AgentCredentialRefusal::Revoked),
        RevocationEvidence::NotChecked => Err(AgentCredentialRefusal::RevocationEvidenceRequired),
    }
}

#[cfg(test)]
mod tests;
