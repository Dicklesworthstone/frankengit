#![forbid(unsafe_code)]
//! Passkey and WebAuthn credential registration and assertion verification.
//!
//! Passkeys provide strong, phishing-resistant multi-factor authentication bound
//! to a specific Relying Party ID. This module implements:
//!
//! * Credential registration with public key binding and relying party confinement;
//! * Assertion verification with challenge-response, origin, and RP ID validation;
//! * Monotonic signature counter verification for authenticator cloning and replay detection;
//! * User presence (UP) and user verification (UV) flag enforcement;
//! * Authentic assertion yielding [`crate::session::AuthenticationStrength::MultiFactor`].
//!
//! # No clock, no ambient I/O
//!
//! All time-based checks take `now: u64` explicitly, ensuring deterministic replay
//! and testability.

use core::fmt::{self, Display, Formatter};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fgit_crypto::sha256_digest;
use fgit_types::PrincipalId;

use crate::oauth::base64url_encode_unpadded;
use crate::revocation::RevocationEvidence;
use crate::session::AuthenticationStrength;

/// Wire tag for [`PasskeyAlgorithm::Ed25519`].
pub const ALGORITHM_ED25519: u32 = 1;

/// Public key algorithm supported by the passkey.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PasskeyAlgorithm {
    /// Ed25519 public key signature algorithm.
    Ed25519,
}

impl PasskeyAlgorithm {
    /// The wire tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Ed25519 => ALGORITHM_ED25519,
        }
    }

    /// Parses from a wire tag.
    ///
    /// # Errors
    ///
    /// [`PasskeyRefusal::UnknownAlgorithm`] if the tag is unknown.
    pub const fn from_tag(tag: u32) -> Result<Self, PasskeyRefusal> {
        match tag {
            ALGORITHM_ED25519 => Ok(Self::Ed25519),
            observed => Err(PasskeyRefusal::UnknownAlgorithm { observed }),
        }
    }
}

/// User verification policy requirement for authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum UserVerificationRequirement {
    /// User verification (e.g. biometric or PIN) is strictly required.
    Required,
    /// User verification is preferred if available.
    Preferred,
    /// User verification is not required (user presence is sufficient).
    Discouraged,
}

/// A unique identifier for a registered passkey credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PasskeyId(u64);

impl PasskeyId {
    /// Constructs a new `PasskeyId`, refusing zero.
    #[must_use]
    pub const fn try_new(val: u64) -> Option<Self> {
        if val == 0 { None } else { Some(Self(val)) }
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for PasskeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "passkey-{}", self.0)
    }
}

/// A registered passkey credential bound to a principal and Relying Party ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyCredential {
    id: PasskeyId,
    principal: PrincipalId,
    rp_id: String,
    algorithm: PasskeyAlgorithm,
    public_key: Vec<u8>,
    sign_count: u32,
    created_at: u64,
}

impl PasskeyCredential {
    /// Registers a new passkey credential with validated public key and RP ID.
    ///
    /// # Errors
    ///
    /// [`PasskeyRefusal::InvalidPublicKey`] if the public key bytes are malformed.
    /// [`PasskeyRefusal::EmptyRpId`] if the relying party ID is empty.
    pub fn register(
        id: PasskeyId,
        principal: PrincipalId,
        rp_id: impl Into<String>,
        algorithm: PasskeyAlgorithm,
        public_key: &[u8],
        sign_count: u32,
        created_at: u64,
    ) -> Result<Self, PasskeyRefusal> {
        let rp_id = rp_id.into();
        if rp_id.trim().is_empty() {
            return Err(PasskeyRefusal::EmptyRpId);
        }
        match algorithm {
            PasskeyAlgorithm::Ed25519 => {
                let key_bytes: &[u8; 32] = public_key
                    .try_into()
                    .map_err(|_| PasskeyRefusal::InvalidPublicKey)?;
                if VerifyingKey::from_bytes(key_bytes).is_err() {
                    return Err(PasskeyRefusal::InvalidPublicKey);
                }
            }
        }
        Ok(Self {
            id,
            principal,
            rp_id,
            algorithm,
            public_key: public_key.to_vec(),
            sign_count,
            created_at,
        })
    }

    /// The credential ID.
    #[must_use]
    pub const fn id(&self) -> PasskeyId {
        self.id
    }

    /// The principal who owns this credential.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The Relying Party identifier this credential is bound to.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The public key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> PasskeyAlgorithm {
        self.algorithm
    }

    /// The public key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The latest recorded monotonic signature counter.
    #[must_use]
    pub const fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// When the credential was registered.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Verifies an assertion from the authenticator.
    ///
    /// Validates:
    /// 1. Challenge matching and freshness (`now < challenge.expires_at`);
    /// 2. RP ID matching;
    /// 3. Revocation status;
    /// 4. User Presence (UP flag);
    /// 5. User Verification (UV flag) per requirement;
    /// 6. Signature counter regression (detects authenticator cloning / replay attacks);
    /// 7. Cryptographic signature over `auth_data || client_data_hash`.
    ///
    /// Upon success, updates the internal signature counter and returns
    /// [`AuthenticationStrength::MultiFactor`].
    ///
    /// # Errors
    ///
    /// Various [`PasskeyRefusal`] variants.
    pub fn verify_assertion(
        &mut self,
        challenge: &PasskeyAssertionChallenge,
        assertion: &PasskeyAssertion,
        uv_req: UserVerificationRequirement,
        now: u64,
        revocation: RevocationEvidence,
    ) -> Result<AuthenticationStrength, PasskeyRefusal> {
        if self.rp_id != challenge.rp_id {
            return Err(PasskeyRefusal::RelyingPartyMismatch);
        }
        if self.id != assertion.credential_id {
            return Err(PasskeyRefusal::CredentialMismatch);
        }
        if now >= challenge.expires_at {
            return Err(PasskeyRefusal::ChallengeExpired {
                expires_at: challenge.expires_at,
                now,
            });
        }
        // Bind the issued challenge into the signed payload. The signature
        // covers `auth_data || client_data_hash`, so without these checks a
        // caller-supplied hash decouples the signed bytes from this
        // challenge entirely: any captured assertion would replay against
        // every later challenge for an authenticator whose counter never
        // advances, which is the modern passkey default. The hash is
        // recomputed here rather than trusted, and the canonical challenge
        // token must appear in the signed client data.
        let computed_hash = sha256_digest(&assertion.client_data_json);
        if computed_hash != assertion.client_data_hash {
            return Err(PasskeyRefusal::ClientDataHashMismatch);
        }
        let token = challenge.challenge_token();
        if !contains_subslice(&assertion.client_data_json, token.as_bytes()) {
            return Err(PasskeyRefusal::ChallengeNotBound);
        }
        // The signed clientDataJSON must also name the web origin the
        // ceremony was issued for. RP ID scoping alone would let an
        // assertion minted inside one relying party's page authenticate on
        // another page sharing the ID.
        let Some(observed_origin) =
            extract_client_data_string(&assertion.client_data_json, b"\"origin\":\"")
        else {
            return Err(PasskeyRefusal::OriginMissingInClientData);
        };
        if !constant_time_eq(observed_origin, challenge.origin.as_bytes()) {
            return Err(PasskeyRefusal::OriginMismatch {
                expected: challenge.origin.clone(),
                observed: String::from_utf8_lossy(observed_origin).into_owned(),
            });
        }
        match revocation {
            RevocationEvidence::Revoked => return Err(PasskeyRefusal::Revoked),
            RevocationEvidence::NotChecked => {
                return Err(PasskeyRefusal::RevocationEvidenceRequired);
            }
            RevocationEvidence::Live => {}
        }
        // WebAuthn §6.1: user presence (bit 0x01) and user verification
        // (bit 0x04) live in the flags byte of the SIGNED authenticator
        // data, after the 32-byte RP ID hash. Deriving them here - rather
        // than trusting caller-supplied booleans - is what makes the policy
        // gates below bind to the signature instead of to its arguments.
        if assertion.auth_data.len() < 37 {
            return Err(PasskeyRefusal::AuthDataTooShort {
                len: assertion.auth_data.len(),
            });
        }
        let flags = assertion.auth_data[32];
        let user_present = flags & 0x01 != 0;
        let user_verified = flags & 0x04 != 0;
        if !user_present {
            return Err(PasskeyRefusal::UserPresenceRequired);
        }
        if uv_req == UserVerificationRequirement::Required && !user_verified {
            return Err(PasskeyRefusal::UserVerificationRequired);
        }

        // Monotonic signature counter verification for clone / replay detection.
        // If either recorded or incoming counter is non-zero, the incoming counter
        // must be strictly greater than the recorded one.
        if (self.sign_count > 0 || assertion.sign_count > 0)
            && assertion.sign_count <= self.sign_count
        {
            return Err(PasskeyRefusal::CounterRegression {
                recorded: self.sign_count,
                received: assertion.sign_count,
            });
        }

        // Cryptographic signature verification over (auth_data || client_data_hash)
        let mut signed_payload = Vec::with_capacity(assertion.auth_data.len() + 32);
        signed_payload.extend_from_slice(&assertion.auth_data);
        signed_payload.extend_from_slice(&assertion.client_data_hash);

        match self.algorithm {
            PasskeyAlgorithm::Ed25519 => {
                let key_bytes: &[u8; 32] = self
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| PasskeyRefusal::InvalidPublicKey)?;
                let vk = VerifyingKey::from_bytes(key_bytes)
                    .map_err(|_| PasskeyRefusal::InvalidPublicKey)?;
                let sig_bytes: &[u8; 64] = assertion
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| PasskeyRefusal::InvalidSignature)?;
                let sig = Signature::from_bytes(sig_bytes);
                if vk.verify(&signed_payload, &sig).is_err() {
                    return Err(PasskeyRefusal::InvalidSignature);
                }
            }
        }

        // Advance the recorded signature counter on successful verification
        self.sign_count = assertion.sign_count;

        Ok(AuthenticationStrength::MultiFactor)
    }
}

/// A cryptographic challenge issued for passkey assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyAssertionChallenge {
    challenge: [u8; 32],
    rp_id: String,
    user_id: PrincipalId,
    /// The web origin (`scheme://host[:port]`) this ceremony was issued for.
    /// Assertions whose signed clientDataJSON names a different origin are
    /// refused: an RP-ID match alone would let one relying party's ceremony
    /// feed another sharing the ID.
    origin: String,
    expires_at: u64,
}

impl PasskeyAssertionChallenge {
    #[must_use]
    pub fn new(
        challenge: [u8; 32],
        rp_id: impl Into<String>,
        user_id: PrincipalId,
        origin: impl Into<String>,
        expires_at: u64,
    ) -> Self {
        Self {
            challenge,
            rp_id: rp_id.into(),
            user_id,
            origin: origin.into(),
            expires_at,
        }
    }

    /// The challenge bytes.
    #[must_use]
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// The Relying Party ID.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The target user ID.
    #[must_use]
    pub const fn user_id(&self) -> PrincipalId {
        self.user_id
    }

    /// The web origin this challenge was issued for.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Deadline when this challenge expires.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Computes the expected client data hash from clientDataJSON bytes.
    #[must_use]
    pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
        sha256_digest(client_data_json)
    }

    /// The canonical token this challenge must contribute to clientDataJSON:
    /// the unpadded base64url encoding of the challenge bytes. An assertion
    /// whose signed client data lacks this token proves nothing about this
    /// challenge, whatever its signature says.
    #[must_use]
    pub fn challenge_token(&self) -> String {
        base64url_encode_unpadded(&self.challenge)
    }
}

/// An assertion payload produced by the authenticator during authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyAssertion {
    /// The credential ID.
    pub credential_id: PasskeyId,
    /// SHA-256 hash of the clientDataJSON.
    pub client_data_hash: [u8; 32],
    /// The exact clientDataJSON bytes the hash and signed payload commit to.
    pub client_data_json: Vec<u8>,
    /// Raw authenticator data bytes.
    pub auth_data: Vec<u8>,
    /// Digital signature over `auth_data || client_data_hash`.
    pub signature: Vec<u8>,
    /// The signature counter reported by the authenticator.
    ///
    /// User-presence and user-verification flags are deliberately NOT fields
    /// here: [`PasskeyCredential::verify_assertion`] derives them from the
    /// signed authenticator data's flags byte, so policy binds to what the
    /// signature covers rather than to caller-supplied booleans.
    pub sign_count: u32,
}

/// Every way a passkey operation is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PasskeyRefusal {
    /// The public key bytes were invalid for the algorithm.
    InvalidPublicKey,
    /// The RP ID was empty or whitespace.
    EmptyRpId,
    /// The wire carried an algorithm tag this build does not recognize.
    UnknownAlgorithm {
        /// The tag observed.
        observed: u32,
    },
    /// The assertion targeted a different Relying Party ID.
    RelyingPartyMismatch,
    /// The assertion credential ID does not match the registered credential.
    CredentialMismatch,
    /// The challenge expired before assertion.
    ChallengeExpired {
        /// The expiration deadline.
        expires_at: u64,
        /// The instant the assertion was evaluated.
        now: u64,
    },
    /// The credential has been revoked.
    Revoked,
    /// Revocation evidence was required but missing.
    RevocationEvidenceRequired,
    /// User presence flag was not asserted.
    UserPresenceRequired,
    /// User verification was required by policy but absent.
    UserVerificationRequired,
    /// Counter regression detected: indicates a cloned authenticator or replayed assertion.
    CounterRegression {
        /// The last recorded counter.
        recorded: u32,
        /// The counter received in this assertion.
        received: u32,
    },
    /// The cryptographic signature was invalid.
    InvalidSignature,
    /// The recomputed clientDataJSON digest did not match the asserted hash.
    ClientDataHashMismatch,
    /// The issued challenge does not appear in the signed client data, so
    /// this assertion proves nothing about this challenge.
    ChallengeNotBound,
    /// The signed authenticator data is too short to carry the WebAuthn
    /// §6.1 flags byte.
    AuthDataTooShort {
        /// The observed byte length.
        len: usize,
    },
    /// The signed clientDataJSON carries no `origin` string.
    OriginMissingInClientData,
    /// The signed clientDataJSON names a different web origin than the
    /// ceremony was issued for.
    OriginMismatch {
        /// The origin the challenge was issued for.
        expected: String,
        /// The origin named by the signed client data.
        observed: String,
    },
}

impl Display for PasskeyRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => f.write_str("invalid public key bytes for algorithm"),
            Self::EmptyRpId => f.write_str("relying party ID cannot be empty"),
            Self::UnknownAlgorithm { observed } => {
                write!(f, "unknown passkey algorithm tag {observed}")
            }
            Self::RelyingPartyMismatch => f.write_str("relying party ID mismatch in assertion"),
            Self::CredentialMismatch => f.write_str("credential ID does not match registered key"),
            Self::ChallengeExpired { expires_at, now } => {
                write!(
                    f,
                    "passkey challenge expired at {expires_at}, asked at {now}"
                )
            }
            Self::Revoked => f.write_str("passkey credential was revoked"),
            Self::RevocationEvidenceRequired => {
                f.write_str("passkey assertion requires fresh revocation evidence")
            }
            Self::UserPresenceRequired => f.write_str("authenticator did not assert user presence"),
            Self::UserVerificationRequired => {
                f.write_str("policy requires user verification but authenticator did not verify")
            }
            Self::CounterRegression { recorded, received } => write!(
                f,
                "signature counter regression (recorded {recorded}, received {received}): potential authenticator clone or replay"
            ),
            Self::InvalidSignature => {
                f.write_str("invalid cryptographic signature in passkey assertion")
            }
            Self::ClientDataHashMismatch => {
                f.write_str("clientDataJSON digest does not match the asserted hash")
            }
            Self::ChallengeNotBound => f.write_str(
                "issued challenge is absent from the signed client data: possible replay",
            ),
            Self::AuthDataTooShort { len } => write!(
                f,
                "authenticator data is {len} bytes; WebAuthn flags need at least 37"
            ),
            Self::OriginMissingInClientData => {
                f.write_str("signed clientDataJSON carries no origin string")
            }
            Self::OriginMismatch { expected, observed } => write!(
                f,
                "clientDataJSON origin `{observed}` does not match ceremony origin `{expected}`"
            ),
        }
    }
}
impl core::error::Error for PasskeyRefusal {}

/// Whether `needle` occurs anywhere in `haystack`, without allocating.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Constant-time byte-slice equality: length differences exit early (length
/// is not secret here - both sides are client-visible shapes), contents never
/// short-circuit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extracts the string value following `key_marker` (e.g. `"origin":"`) from
/// clientDataJSON bytes, up to the next unescaped double quote. This is a
/// bounded byte-level scan, not a JSON parser: it is sufficient for the
/// flat, browser-produced client data this module verifies and keeps the
/// crate dependency-free. A malformed or escaped payload simply fails the
/// origin check it exists to serve.
fn extract_client_data_string<'a>(
    client_data_json: &'a [u8],
    key_marker: &[u8],
) -> Option<&'a [u8]> {
    let start = client_data_json
        .windows(key_marker.len())
        .position(|window| window == key_marker)?
        + key_marker.len();
    let rest = &client_data_json[start..];
    let end = rest.iter().position(|byte| *byte == b'"')?;
    rest.get(..end)
}
