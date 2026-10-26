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
    /// The current authorization source could not be checked completely.
    ///
    /// A missing, malformed, interrupted or unavailable source never permits
    /// reuse of an earlier grant. The diagnostic is fixed so filesystem paths
    /// and untrusted source contents cannot escape through the SSH response.
    AuthorizationSourceUnavailable,
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
            Self::AuthorizationSourceUnavailable => {
                formatter.write_str("SSH command authorization source is unavailable")
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

/// Resolves a verified peer's grant at the Git command boundary.
///
/// [`crate::session::SshServerSession`] calls this only after verifying the
/// peer's signature and parsing the repository and service. No principal,
/// active Git command or successful exec response is installed until it returns
/// `Ok`. The verified key, repository and service must all participate in the
/// authorization decision; the SSH username never selects a principal.
///
/// The session owns no authorization I/O, executor or cache. This synchronous
/// capability is supplied by its transport owner. A source performing bounded
/// blocking I/O must run on the owner's blocking worker, with that owner's
/// cancellation/deadline checks; it must not create a runtime or bridge async
/// work with `block_on`. Failed checks must never fall back to a previous grant.
///
/// One successful call authorizes the session's single Git command. Its
/// principal remains fixed through that command and rekey. Later sessions must
/// consult their source again, so a live source can observe revocation,
/// rotation and scope changes without altering an already admitted command.
pub trait SshCommandAuthorizer: Send + Sync {
    fn authorize_command(
        &self,
        authenticated_key: &[u8; 32],
        repository_id: RepositoryId,
        service: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal>;
}

/// Explicit fixed deploy-key grants for the lifetime of this source.
///
/// The caller declares this complete table to be the current authorization
/// configuration. Replacing or revoking one of these static grants requires
/// replacing the source. Continuously reloadable credentials instead provide
/// their own [`SshCommandAuthorizer`] at the transport boundary.
#[derive(Clone, Debug)]
pub struct StaticDeployKeyAuthorizer {
    bindings: Vec<DeployKeyBinding>,
}

impl StaticDeployKeyAuthorizer {
    #[must_use]
    pub const fn new(bindings: Vec<DeployKeyBinding>) -> Self {
        Self { bindings }
    }
}

impl SshCommandAuthorizer for StaticDeployKeyAuthorizer {
    fn authorize_command(
        &self,
        authenticated_key: &[u8; 32],
        repository_id: RepositoryId,
        service: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal> {
        authorize_deploy_key(
            &self.bindings,
            authenticated_key,
            repository_id,
            service,
            RevocationEvidence::Live,
        )
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
