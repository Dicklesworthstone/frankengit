//! Stable identity and equivocation detection for complete Intent Runs.
//!
//! [`crate::RunId`] is an assigned coordination identity. It is not, by itself,
//! a commitment to the machine-enforced run fields. The Agent Protocol makes
//! reuse of one run ID with different bytes a terminal protocol violation, so
//! downstream task, execution, handoff, and cancellation paths need one
//! canonical commitment they can compare before accepting the ID.
//!
//! [`IntentRunCommitment`] binds the run ID, exact authenticated-read identity
//! (or the explicitly legacy basis), operation classes, resource budget, and
//! expiry. [`IntentRunBinding`] is storage-agnostic: a durable registry may keep
//! the pair and use [`IntentRunBinding::revalidate`] to admit an identical retry
//! or refuse equivocation. This module does not claim that an in-memory value is
//! durable storage and does not grant any authority.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};

use crate::{AuthorityReadIdentityRefusal, IntentRun, RunId};

const RUN_DOMAIN: &[u8] = b"frankengit.agent.intent-run/v1\0";

/// Stable SHA-256 commitment to every machine-enforced Intent Run field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntentRunCommitment([u8; 32]);

impl IntentRunCommitment {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for IntentRunCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("intent-run:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl IntentRun {
    /// Commits every field that can authorize or bound this run.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the exact authority-read identity or the
    /// canonical run frame cannot be produced.
    pub fn commitment(&self) -> Result<IntentRunCommitment, IntentRunIdentityRefusal> {
        let mut encoder = Encoder::with_capacity(256);
        encoder.write_bytes("intent_run_domain", RUN_DOMAIN)?;
        encoder.write_raw(&self.run_id().value().to_be_bytes());

        if let Some(receipt) = self.authority_read_receipt() {
            encoder.write_raw_byte(1);
            let receipt_id = receipt.receipt_id()?;
            encoder.write_raw(receipt_id.as_bytes());
        } else {
            encoder.write_raw_byte(2);
            let basis = self.base_authority();
            encoder.write_raw(&basis.repository_id.to_be_bytes());
            encoder.write_scalar(basis.authority_head_generation);
            encoder.write_raw(&basis.authority_head_digest);
            encoder.write_scalar(basis.verified_at.value());
        }

        encoder.write_scalar(self.allowed_operation_classes().bits());
        for (_grade, amount) in self.resource_budget().pairs() {
            encoder.write_scalar(amount);
        }
        encoder.write_scalar(self.expiry().value());

        let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
        hasher.update(&encoder.into_bytes());
        Ok(IntentRunCommitment(hasher.finish()))
    }
}

/// Durable-registry value pairing an assigned run ID with its committed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentRunBinding {
    run_id: RunId,
    commitment: IntentRunCommitment,
}

impl IntentRunBinding {
    /// Establishes the first binding for one run ID.
    ///
    /// # Errors
    ///
    /// Returns the same framing refusals as [`IntentRun::commitment`].
    pub fn establish(run: &IntentRun) -> Result<Self, IntentRunIdentityRefusal> {
        Ok(Self {
            run_id: run.run_id(),
            commitment: run.commitment()?,
        })
    }

    /// Admits only an identical retry of the already-bound run.
    ///
    /// # Errors
    ///
    /// Refuses another run ID and refuses reuse of the same ID with a different
    /// machine commitment.
    pub fn revalidate(
        &self,
        run: &IntentRun,
    ) -> Result<IntentRunRetry, IntentRunIdentityRefusal> {
        if run.run_id() != self.run_id {
            return Err(IntentRunIdentityRefusal::RunIdMismatch {
                expected: self.run_id,
                observed: run.run_id(),
            });
        }
        let observed = run.commitment()?;
        if observed != self.commitment {
            return Err(IntentRunIdentityRefusal::RunIdEquivocation {
                run_id: self.run_id,
                expected: self.commitment,
                observed,
            });
        }
        Ok(IntentRunRetry::Identical)
    }

    /// Assigned run ID.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Complete machine commitment bound to that ID.
    #[must_use]
    pub const fn commitment(self) -> IntentRunCommitment {
        self.commitment
    }
}

/// Successful replay classification for a previously bound run ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentRunRetry {
    /// Every machine-enforced field is byte-identical under the v1 commitment.
    Identical,
}

/// Why an Intent Run identity or binding failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentRunIdentityRefusal {
    /// Exact authority-read identity could not be produced.
    Authority(AuthorityReadIdentityRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
    /// A registry binding was queried with another run ID.
    RunIdMismatch {
        /// Bound run ID.
        expected: RunId,
        /// Supplied run ID.
        observed: RunId,
    },
    /// One assigned run ID was reused for different machine fields.
    RunIdEquivocation {
        /// Reused run ID.
        run_id: RunId,
        /// Commitment already bound to that ID.
        expected: IntentRunCommitment,
        /// Commitment supplied by the retry.
        observed: IntentRunCommitment,
    },
}

impl fmt::Display for IntentRunIdentityRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(refusal) => {
                write!(formatter, "run authority identity refused: {refusal}")
            }
            Self::Codec(refusal) => write!(formatter, "Intent Run framing refused: {refusal}"),
            Self::RunIdMismatch { expected, observed } => {
                write!(formatter, "run binding for {expected} cannot admit {observed}")
            }
            Self::RunIdEquivocation {
                run_id,
                expected,
                observed,
            } => write!(
                formatter,
                "{run_id} is already bound to {expected}, not {observed}"
            ),
        }
    }
}

impl core::error::Error for IntentRunIdentityRefusal {}

impl From<AuthorityReadIdentityRefusal> for IntentRunIdentityRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::Authority(value)
    }
}

impl From<CodecRefusal> for IntentRunIdentityRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}
