#![forbid(unsafe_code)]

//! `fgit-ssh` — Pure-Rust SSH transport service for Git operations.
//!
//! Implements:
//! - Shell-free typed command dispatch (`git-upload-pack` / `git-receive-pack`)
//! - RFC 8731 Curve25519 key exchange
//! - OpenSSH `chacha20-poly1305@openssh.com` packet encryption and authentication
//! - Ed25519 host key and client publickey authentication
//! - Binding of authenticated keys to `fgit-identity` deploy keys and scopes

pub mod auth;
pub mod command;
pub mod crypto;
pub mod session;
pub mod wire;
pub mod x25519;

pub use auth::{AuthRefusal, authorize_deploy_key, verify_client_signature};
pub use command::{CommandParseRefusal, SshGitCommand, SshGitService};
pub use crypto::{
    CIPHER_CHACHA20_POLY1305, CryptoError, Curve25519Kex, KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBSSH, OpenSshChaCha20Poly1305, SSH_ED25519_ALGORITHM,
};
pub use session::{SERVER_IDENTIFICATION, SessionPhase, SshServerSession, SshSessionError};
