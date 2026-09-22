//! SSH public-key authentication wired to FrankenGit identity and deploy keys.
//!
//! Ties an authenticated SSH Ed25519 public key to [`DeployKeyBinding`]s
//! defined in `fgit-identity`, returning the authoritative [`PrincipalId`].

use core::fmt::{self, Display, Formatter};

use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope};
use fgit_identity::revocation::RevocationEvidence;
use fgit_types::{PrincipalId, RepositoryId};

use crate::command::SshGitService;
use crate::crypto::{CryptoError, parse_ed25519_public_key, verify_ed25519};
use crate::wire::WireWriter;

/// Refusals during SSH authentication and deploy key authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthRefusal {
    /// Public key cryptographic verification failed.
    Crypto(CryptoError),
    /// Deploy key policy refused authorization.
    DeployKey(DeployKeyRefusal),
    /// No public key was presented before command execution.
    Unauthenticated,
    /// Requested service not permitted by credential scope.
    ScopeNotGranted { requested: DeployKeyScope },
}

impl Display for AuthRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(err) => write!(formatter, "SSH cryptographic auth refusal: {err}"),
            Self::DeployKey(err) => write!(formatter, "deploy key authorization refusal: {err}"),
            Self::Unauthenticated => {
                formatter.write_str("command execution attempted before SSH key authentication")
            }
            Self::ScopeNotGranted { requested } => {
                write!(
                    formatter,
                    "deploy key does not grant required scope `{requested}`"
                )
            }
        }
    }
}

impl core::error::Error for AuthRefusal {}

impl From<CryptoError> for AuthRefusal {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<DeployKeyRefusal> for AuthRefusal {
    fn from(err: DeployKeyRefusal) -> Self {
        Self::DeployKey(err)
    }
}

/// Builds the RFC 4252 signed preimage for publickey user authentication.
///
/// Preimage format:
/// string    session_id
/// byte      SSH_MSG_USERAUTH_REQUEST (50)
/// string    user_name
/// string    service_name ("ssh-connection")
/// string    method_name ("publickey")
/// boolean   true
/// string    public_key_algorithm ("ssh-ed25519")
/// string    public_key_blob
#[must_use]
pub fn build_userauth_signature_preimage(
    session_id: &[u8; 32],
    user_name: &str,
    service_name: &str,
    public_key_blob: &[u8],
) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_string(session_id);
    writer.write_u8(50); // SSH_MSG_USERAUTH_REQUEST
    writer.write_utf8(user_name);
    writer.write_utf8(service_name);
    writer.write_utf8("publickey");
    writer.write_bool(true);
    writer.write_utf8("ssh-ed25519");
    writer.write_string(public_key_blob);
    writer.into_bytes()
}

/// Verifies client's SSH publickey authentication signature over the RFC 4252 preimage.
pub fn verify_client_signature(
    session_id: &[u8; 32],
    user_name: &str,
    service_name: &str,
    public_key_blob: &[u8],
    sig_blob: &[u8],
) -> Result<[u8; 32], AuthRefusal> {
    let pub_key_bytes = parse_ed25519_public_key(public_key_blob)?;
    let preimage =
        build_userauth_signature_preimage(session_id, user_name, service_name, public_key_blob);
    verify_ed25519(&pub_key_bytes, &preimage, sig_blob)?;
    Ok(pub_key_bytes)
}

/// Authorizes an authenticated public key against a repository and requested service.
///
/// # Errors
///
/// Returns [`AuthRefusal`] if the key is not registered for the repository, does not carry
/// the required scope, is ambiguous, or has been revoked.
pub fn authorize_deploy_key(
    bindings: &[DeployKeyBinding],
    pub_key_bytes: &[u8; 32],
    repository_id: RepositoryId,
    service: SshGitService,
    revocation: RevocationEvidence,
) -> Result<PrincipalId, AuthRefusal> {
    let fgit_key = fgit_crypto::VerifyingKey::from_bytes(*pub_key_bytes);

    let scope = match service {
        SshGitService::UploadPack => DeployKeyScope::Read,
        SshGitService::ReceivePack => DeployKeyScope::Write,
    };

    let binding = DeployKeyBinding::resolve(bindings, &fgit_key, repository_id)?;
    let principal = binding.authorize(&fgit_key, repository_id, scope, revocation)?;

    Ok(principal)
}
