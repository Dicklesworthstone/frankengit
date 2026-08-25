#![forbid(unsafe_code)]
//! Identity: principals, organisations, teams, and the credentials bound to
//! them.
//!
//! # What this crate is
//!
//! The identity model for FG-042. It owns:
//!
//! * [`deploy_key`] — an ed25519 public key bound to exactly one repository,
//!   resolving to the principal it speaks as and the scopes it may exercise
//!   there;
//! * [`token`] — a bounded, revocable, audience-bound grant to act as a
//!   principal, whose high-impact operations cannot be authorised without
//!   revocation evidence;
//! * [`revocation`] — the one [`RevocationEvidence`] vocabulary every credential
//!   here answers to, so a revocation cannot mean two things;
//! * [`session`] — what a transport holds after authentication succeeds: the
//!   principal, the strength it authenticated with, and rotation that may
//!   weaken but never strengthen it.
//!
//! Organisation and team aggregates land here as their modules are completed
//! under bead `frankengit-fg042a-identity-model-cas`.
//! Each is named above when its module is real, never before — and equally,
//! each is added the moment it IS real. The inverse mistake, a list that keeps
//! describing delivered work as pending, is what `frankengit-wirh` had to
//! correct in a sibling crate, so this list is maintained in both directions.
//!
//! # What this crate is not
//!
//! It is not a key authority and holds no SECRET key material. A deploy key is
//! recorded as the peer's public half, which is public by construction; the
//! purpose-marker keys in `fgit-crypto` (`KeyPurposeMarker`) remain the only
//! place a key is minted or verified, and nothing in this crate signs or
//! verifies anything. A credential record that could also mint the credential
//! it describes would be a second authority for the same thing.
//!
//! It does not admit. Identity aggregates are published as forge events on the
//! `fgit-forge` machinery, and admission is L4: this crate computes, records
//! and refuses, then hands the result upward.
//!
//! # Load-bearing invariants
//!
//! * A credential names the repository it is bound to, and authorization checks
//!   the binding as well as the scope. A scope that matches on the wrong
//!   repository is refused.
//! * A credential authenticates a principal; it is not one. Everything above
//!   this crate reasons about `PrincipalId`, so a credential that could not name
//!   one would authenticate a peer into a vocabulary nothing downstream speaks.
//! * Capabilities are never implied. `Write` does not confer `Read`; each is
//!   granted explicitly or not at all.
//! * A grant that permits nothing is refused rather than stored, so
//!   "registered" and "may do nothing" can never be the same state.
//! * Every canonical body defined here has a row in `fgit-crypto`'s
//!   `DOMAIN_REGISTRY`. A body with no row cannot receive an identity, and a
//!   credential nothing can point at is not much of a credential. That held
//!   silently false for two bodies once, because encode/decode never consults
//!   the registry — `tests/canonical_identity.rs` is what makes it observable.

pub mod deploy_key;
pub mod oauth;
pub mod passkey;
pub mod rate_limit;
pub mod reauth;
pub mod recovery;
pub mod revocation;
pub mod session;
pub mod token;

pub use deploy_key::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope};
pub use oauth::{
    AuthorizationCode, OAuthRefusal, PkceMethod, derive_s256_challenge, validate_redirect_uri,
    verify_pkce,
};
pub use passkey::{
    PasskeyAlgorithm, PasskeyAssertion, PasskeyAssertionChallenge, PasskeyCredential, PasskeyId,
    PasskeyRefusal, UserVerificationRequirement,
};
pub use rate_limit::{PrincipalRateLimiter, RateLimitConfig, RateLimitRecord, RateLimitRefusal};
pub use reauth::{ElevationToken, MAX_ELEVATION_WINDOW_SECONDS, PrivilegeAction, ReauthRefusal};
pub use recovery::{
    MIN_RECOVERY_DELAY_SECONDS, RecoveryId, RecoveryRefusal, RecoveryRequest, RecoveryState,
};
pub use revocation::RevocationEvidence;
pub use session::{AuthenticationStrength, Session, SessionId, SessionRefusal};
pub use token::{TokenGrant, TokenHandle, TokenOperation, TokenRefusal};
