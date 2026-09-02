//! Stable identity for one exact authenticated authority read event.
//!
//! [`crate::AuthorityReadReceipt`] retains the authenticated authority-head
//! identity, the backend's opaque conditional-write token, and the verifier
//! context under which the read was accepted. The head identity already commits
//! the complete canonical [`fgit_codec::RepositoryAuthorityHeadBody`], including
//! roots that the agent-facing receipt does not expose individually. This module
//! adds the missing identity for the *read event itself*.
//!
//! Two receipts naming the same head are still distinct when they carry a
//! different backend token, verification instant, or verifier profile. That
//! distinction is load-bearing for idempotency, recovery, and detecting a
//! reconstructed same-head basis that was never the read an Intent Run opened
//! against.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};

use crate::AuthorityReadReceipt;

const RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.authority-read-receipt/v1\0";

/// Stable SHA-256 identity of one exact authenticated read event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityReadReceiptId([u8; 32]);

impl AuthorityReadReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AuthorityReadReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authority-read:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl AuthorityReadReceipt {
    /// Commits the exact authenticated read event.
    ///
    /// The authenticated head ID commits the complete canonical head body. The
    /// remaining fields distinguish reads of that head across backend token
    /// issuances and verifier observations.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityReadIdentityRefusal::Codec`] when canonical framing
    /// cannot represent one of the already-bounded receipt fields.
    pub fn receipt_id(&self) -> Result<AuthorityReadReceiptId, AuthorityReadIdentityRefusal> {
        let mut encoder = Encoder::with_capacity(512);
        write_authority_read_receipt(&mut encoder, self)?;
        let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
        hasher.update(&encoder.into_bytes());
        Ok(AuthorityReadReceiptId(hasher.finish()))
    }
}

/// Why an exact read-event identity could not be framed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityReadIdentityRefusal {
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for AuthorityReadIdentityRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(refusal) => {
                write!(
                    formatter,
                    "authority-read identity framing refused: {refusal}"
                )
            }
        }
    }
}

impl core::error::Error for AuthorityReadIdentityRefusal {}

impl From<CodecRefusal> for AuthorityReadIdentityRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Writes the one canonical agent-facing authority-read frame.
///
/// Other agent-control identities should embed [`AuthorityReadReceiptId`]
/// rather than reimplement this field list. This helper remains crate-private
/// so there is one framing rule without exposing mutable encoder plumbing.
pub(crate) fn write_authority_read_receipt(
    encoder: &mut Encoder,
    receipt: &AuthorityReadReceipt,
) -> Result<(), CodecRefusal> {
    encoder.write_bytes("authority_read_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_opaque_id(receipt.repository_id().as_bytes());
    encoder.write_internal_object_id(receipt.authority_head_id().as_internal_object_id())?;
    encoder.write_scalar(receipt.authority_head_generation().get());
    encoder.write_raw(&receipt.backend_version_token().to_opaque_bytes());

    match receipt.latest_decision_batch_id() {
        Some(identity) => {
            encoder.write_bool(true);
            encoder.write_internal_object_id(identity.as_internal_object_id())?;
        }
        None => encoder.write_bool(false),
    }
    match receipt.latest_repository_sequence() {
        Some(sequence) => {
            encoder.write_bool(true);
            encoder.write_scalar(sequence.get());
        }
        None => encoder.write_bool(false),
    }
    match receipt.latest_repository_commit_id() {
        Some(identity) => {
            encoder.write_bool(true);
            encoder.write_internal_object_id(identity.as_internal_object_id())?;
        }
        None => encoder.write_bool(false),
    }

    encoder.write_digest(&receipt.ref_root())?;
    encoder.write_digest(&receipt.forge_position_root())?;
    encoder.write_digest(&receipt.retention_root())?;
    encoder.write_scalar(receipt.policy_epoch().get());
    encoder.write_scalar(receipt.format_epoch().get());
    encoder.write_scalar(receipt.verified_at_logical_time().value());
    encoder.write_raw(&receipt.verifier_profile());
    Ok(())
}
