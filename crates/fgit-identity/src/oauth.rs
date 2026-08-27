#![forbid(unsafe_code)]
//! OAuth 2.0 / OIDC Authorization Code Flow with PKCE and exact redirect URI matching.
//!
//! This module implements normative account security controls:
//!
//! * PKCE (RFC 7636) code challenge verification with SHA-256 (`S256`).
//!   Plain code challenge method is explicitly refused for security.
//! * Strict, exact redirect URI matching: wildcards, path prefixes, fragments,
//!   and plain HTTP for non-localhost domains are strictly rejected.
//! * State and Nonce binding for CSRF and replay prevention.
//! * Single-use authorization codes: attempts to reuse a code fail closed.
//!
//! # No clock, no ambient I/O
//!
//! Expirations take `now: u64` explicitly, ensuring deterministic replay.

use core::fmt::{self, Display, Formatter};
use fgit_crypto::sha256_digest;
use fgit_types::{PrincipalId, RepositoryId};

use crate::session::{AuthenticationStrength, Session, SessionId};

/// `Base64URL` unpadded character encoding table.
const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes binary digest bytes to base64url without padding.
pub(crate) fn base64url_encode_unpadded(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0;
    while i < input.len() {
        let b0 = u32::from(input[i]);
        let b1 = if i + 1 < input.len() {
            u32::from(input[i + 1])
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            u32::from(input[i + 2])
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64URL_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(BASE64URL_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < input.len() {
            out.push(BASE64URL_ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(BASE64URL_ALPHABET[(triple & 0x3F) as usize] as char);
        }

        i += 3;
    }
    out
}

/// Constant-time string slice equality comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Supported PKCE code challenge transformation methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PkceMethod {
    /// SHA-256 hash followed by unpadded base64url encoding (RFC 7636).
    S256,
}

impl PkceMethod {
    /// Wire tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::S256 => 1,
        }
    }
}

/// Validates that a code verifier conforms to RFC 7636 §4.1:
/// Length between 43 and 128 characters, composed of `[A-Za-z0-9-._~]`.
fn validate_code_verifier(verifier: &str) -> Result<(), OAuthRefusal> {
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(OAuthRefusal::InvalidPkceVerifierLength {
            len: verifier.len(),
        });
    }
    for c in verifier.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => {}
            _ => return Err(OAuthRefusal::InvalidPkceVerifierCharacter),
        }
    }
    Ok(())
}

/// Derives the S256 code challenge from a code verifier.
///
/// # Errors
///
/// [`OAuthRefusal`] if the verifier is invalid.
pub fn derive_s256_challenge(verifier: &str) -> Result<String, OAuthRefusal> {
    validate_code_verifier(verifier)?;
    let digest = sha256_digest(verifier.as_bytes());
    Ok(base64url_encode_unpadded(&digest))
}

/// Verifies a code verifier against a code challenge using the specified PKCE method.
///
/// # Errors
///
/// [`OAuthRefusal::PkceVerificationFailed`] on mismatch or invalid verifier.
pub fn verify_pkce(
    verifier: &str,
    challenge: &str,
    method: PkceMethod,
) -> Result<(), OAuthRefusal> {
    match method {
        PkceMethod::S256 => {
            let derived = derive_s256_challenge(verifier)?;
            if !constant_time_eq(&derived, challenge) {
                return Err(OAuthRefusal::PkceVerificationFailed);
            }
            Ok(())
        }
    }
}

/// Validates a redirect URI for exact matching requirements:
/// * Strictly absolute URI (starts with `https://` or `http://localhost`/`http://127.0.0.1`);
/// * No fragment identifier (`#`);
/// * No wildcard patterns (`*`).
///
/// # Errors
///
/// [`OAuthRefusal::InsecureRedirectUri`] or [`OAuthRefusal::MalformedRedirectUri`].
pub fn validate_redirect_uri(uri: &str) -> Result<(), OAuthRefusal> {
    if uri.trim().is_empty() {
        return Err(OAuthRefusal::MalformedRedirectUri);
    }
    if uri.contains('#') {
        return Err(OAuthRefusal::FragmentInRedirectUri);
    }
    if uri.contains('*') {
        return Err(OAuthRefusal::WildcardInRedirectUri);
    }
    if uri.starts_with("https://") {
        return Ok(());
    }
    if http_loopback_authority(uri) {
        return Ok(());
    }
    Err(OAuthRefusal::InsecureRedirectUri)
}

/// Whether the `http://` URI's authority names a loopback host exactly.
///
/// The authority is the component up to the first `/`, `?` or `#`; user
/// information (everything before the last `@`) is discarded before the host
/// is compared, so `http://localhost.evil.com`, `http://localhost@evil.com`
/// and `http://localhost:8080@evil.com` all fail despite sharing their prefix
/// with a legitimate loopback redirect.
fn http_loopback_authority(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = match authority.rsplit_once('@') {
        Some((_, host_port)) => host_port,
        None => authority,
    };
    let host = host_port.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

/// An authorization code issued during an OAuth/OIDC authorization flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationCode {
    code_id: u64,
    client_id: String,
    principal: PrincipalId,
    repository: RepositoryId,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: PkceMethod,
    state: String,
    nonce: Option<String>,
    strength: AuthenticationStrength,
    expires_at: u64,
    used: bool,
}

impl AuthorizationCode {
    /// Issues a new authorization code with PKCE and exact redirect URI binding.
    ///
    /// # Errors
    ///
    /// Various [`OAuthRefusal`] variants.
    pub fn issue(
        code_id: u64,
        client_id: impl Into<String>,
        principal: PrincipalId,
        repository: RepositoryId,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        code_challenge: impl Into<String>,
        code_challenge_method: PkceMethod,
        state: impl Into<String>,
        nonce: Option<String>,
        strength: AuthenticationStrength,
        expires_at: u64,
    ) -> Result<Self, OAuthRefusal> {
        if code_id == 0 {
            return Err(OAuthRefusal::InvalidCodeId);
        }
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(OAuthRefusal::EmptyClientId);
        }
        let redirect_uri = redirect_uri.into();
        validate_redirect_uri(&redirect_uri)?;
        let code_challenge = code_challenge.into();
        if code_challenge.trim().is_empty() {
            return Err(OAuthRefusal::EmptyCodeChallenge);
        }
        let state = state.into();
        if state.trim().is_empty() {
            return Err(OAuthRefusal::EmptyState);
        }

        Ok(Self {
            code_id,
            client_id,
            principal,
            repository,
            redirect_uri,
            scope: scope.into(),
            code_challenge,
            code_challenge_method,
            state,
            nonce,
            strength,
            expires_at,
            used: false,
        })
    }

    /// The code ID.
    #[must_use]
    pub const fn code_id(&self) -> u64 {
        self.code_id
    }

    /// The bound client ID.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The repository context.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// The exact registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The granted scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The state parameter.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The optional nonce.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// The strength established when the user authorized the grant.
    #[must_use]
    pub const fn strength(&self) -> AuthenticationStrength {
        self.strength
    }

    /// The expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the code has been redeemed.
    #[must_use]
    pub const fn is_used(&self) -> bool {
        self.used
    }

    /// Redeems the authorization code for an established session.
    ///
    /// Validates:
    /// 1. Exact client ID matching;
    /// 2. Exact redirect URI matching (no wildcard / prefix matching!);
    /// 3. Expiry deadline (`now < expires_at`);
    /// 4. Single-use: if already used, immediately refuses with [`OAuthRefusal::CodeAlreadyUsed`];
    /// 5. PKCE code verifier validation against the recorded code challenge.
    ///
    /// Marks the code as used and returns a new [`Session`].
    ///
    /// # Errors
    ///
    /// [`OAuthRefusal`] on any validation failure.
    pub fn redeem(
        &mut self,
        session_id: SessionId,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
        session_expires_at: u64,
        now: u64,
    ) -> Result<Session, OAuthRefusal> {
        if self.used {
            return Err(OAuthRefusal::CodeAlreadyUsed {
                code_id: self.code_id,
            });
        }
        if !constant_time_eq(&self.client_id, client_id) {
            return Err(OAuthRefusal::ClientMismatch);
        }
        if !constant_time_eq(&self.redirect_uri, redirect_uri) {
            return Err(OAuthRefusal::RedirectUriMismatch);
        }
        if now >= self.expires_at {
            return Err(OAuthRefusal::CodeExpired {
                expires_at: self.expires_at,
                now,
            });
        }

        // Verify PKCE
        verify_pkce(
            code_verifier,
            &self.code_challenge,
            self.code_challenge_method,
        )?;

        // Mark as redeemed (single use)
        self.used = true;

        Ok(Session::establish(
            session_id,
            self.principal,
            self.repository,
            self.strength,
            session_expires_at,
        ))
    }
}

/// Every way an OAuth / OIDC operation is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OAuthRefusal {
    /// Code ID must be non-zero.
    InvalidCodeId,
    /// Client ID was empty or whitespace.
    EmptyClientId,
    /// Code challenge was empty.
    EmptyCodeChallenge,
    /// State parameter was empty.
    EmptyState,
    /// Code verifier length must be between 43 and 128 characters.
    InvalidPkceVerifierLength {
        /// Observed length.
        len: usize,
    },
    /// Code verifier contained characters outside `[A-Za-z0-9-._~]`.
    InvalidPkceVerifierCharacter,
    /// PKCE verification failed.
    PkceVerificationFailed,
    /// Redirect URI was malformed or empty.
    MalformedRedirectUri,
    /// Redirect URI contained fragment `#`.
    FragmentInRedirectUri,
    /// Redirect URI contained wildcard `*`.
    WildcardInRedirectUri,
    /// Redirect URI must use HTTPS or localhost HTTP.
    InsecureRedirectUri,
    /// Redirect URI presented did not exactly match the bound redirect URI.
    RedirectUriMismatch,
    /// Client ID did not match.
    ClientMismatch,
    /// Authorization code has expired.
    CodeExpired {
        /// Expiry deadline.
        expires_at: u64,
        /// Instant evaluated.
        now: u64,
    },
    /// Authorization code has already been redeemed (replay attack detected).
    CodeAlreadyUsed {
        /// The reused code ID.
        code_id: u64,
    },
}

impl Display for OAuthRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCodeId => f.write_str("code ID must be non-zero"),
            Self::EmptyClientId => f.write_str("client ID cannot be empty"),
            Self::EmptyCodeChallenge => f.write_str("code challenge cannot be empty"),
            Self::EmptyState => f.write_str("state parameter cannot be empty"),
            Self::InvalidPkceVerifierLength { len } => {
                write!(f, "PKCE verifier length {len} is not within 43..128 chars")
            }
            Self::InvalidPkceVerifierCharacter => {
                f.write_str("PKCE verifier contains invalid unreserved characters")
            }
            Self::PkceVerificationFailed => {
                f.write_str("PKCE code verifier did not match challenge")
            }
            Self::MalformedRedirectUri => f.write_str("malformed or empty redirect URI"),
            Self::FragmentInRedirectUri => {
                f.write_str("redirect URI cannot contain a fragment identifier (#)")
            }
            Self::WildcardInRedirectUri => {
                f.write_str("redirect URI cannot contain wildcard patterns (*)")
            }
            Self::InsecureRedirectUri => {
                f.write_str("redirect URI must use https:// or http://localhost")
            }
            Self::RedirectUriMismatch => {
                f.write_str("redirect URI does not exactly match registered authorization code URI")
            }
            Self::ClientMismatch => f.write_str("client ID does not match authorization code"),
            Self::CodeExpired { expires_at, now } => {
                write!(
                    f,
                    "authorization code expired at {expires_at}, asked at {now}"
                )
            }
            Self::CodeAlreadyUsed { code_id } => write!(
                f,
                "authorization code {code_id} has already been used: replay attack detected"
            ),
        }
    }
}

impl core::error::Error for OAuthRefusal {}
