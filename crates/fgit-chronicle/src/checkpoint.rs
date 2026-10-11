//! Verify a capsule activation while following authenticated head ancestry.
//!
//! Capsule activation advances the authority generation without publishing a
//! decision batch. Its unchanged decision tail must therefore not be replayed
//! against the newly introduced predecessor as if it were a new decision.
//! This verifier admits only the exact transition produced by
//! [`crate::activate_frozen_capsule_async`]. It grants no trust to an archive,
//! retention lease, or claim that the capsule's external artifacts are present.

use core::fmt;

use fgit_authority::authority_head_identity;
use fgit_codec::{CryptoBodyIdentity, RepositoryAuthorityHeadBody, encode_body};

use crate::{
    CapsuleInspectionRefusal, PublicationBasis, RestoreOutcome,
    inspect_capsule_against_authority_head_bytes,
};

mod history;
pub use history::{HistoryStep, HistoryStepRefusal, read_history_step_async};

/// A head edge was not the exact root-last activation of its named capsule.
#[derive(Debug)]
pub enum CheckpointTransitionRefusal {
    /// The caller's predecessor identity does not name its canonical body.
    PredecessorIdentity,
    /// No new checkpoint pointer was published by this edge.
    CheckpointNotAdvanced,
    /// The predecessor cannot advance its authority generation.
    GenerationExhausted,
    /// A field other than the three activation fields changed, or one of those
    /// fields does not have the exact value produced by activation.
    HeadMismatch,
    /// The fixed-size predecessor body could not be encoded for inspection.
    HeadEncoding(fgit_codec::CodecRefusal),
    /// The original capsule bytes could not be canonically inspected.
    CapsuleInspection(Box<CapsuleInspectionRefusal>),
    /// The capsule identity, predecessor pointer, or exact head binding failed.
    CapsuleMismatch,
}

impl fmt::Display for CheckpointTransitionRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PredecessorIdentity => {
                out.write_str("checkpoint predecessor identity disagrees with its body")
            }
            Self::CheckpointNotAdvanced => {
                out.write_str("checkpoint transition did not publish a new capsule pointer")
            }
            Self::GenerationExhausted => {
                out.write_str("checkpoint predecessor generation cannot advance")
            }
            Self::HeadMismatch => {
                out.write_str("checkpoint successor changed fields beyond exact capsule activation")
            }
            Self::HeadEncoding(error) => write!(out, "checkpoint predecessor encoding: {error}"),
            Self::CapsuleInspection(error) => write!(out, "checkpoint capsule inspection: {error}"),
            Self::CapsuleMismatch => {
                out.write_str("checkpoint capsule does not bind its exact predecessor head")
            }
        }
    }
}

impl std::error::Error for CheckpointTransitionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HeadEncoding(error) => Some(error),
            Self::CapsuleInspection(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Verify a checkpoint-only successor and its original immutable capsule bytes.
///
/// The caller must reach `predecessor` through an authenticated current head;
/// finding an otherwise valid immutable head is not evidence it was published.
/// This function re-identifies that predecessor and verifies the capsule using
/// the existing bounded canonical parser. It compares the complete successor
/// with a clone of the predecessor, so outcome/outbox roots, configuration,
/// decision positions, and any future head fields cannot change unnoticed.
pub fn verify_checkpoint_successor(
    predecessor: &PublicationBasis,
    successor: &RepositoryAuthorityHeadBody,
    capsule_bytes: &[u8],
) -> Result<(), CheckpointTransitionRefusal> {
    let identity = authority_head_identity(predecessor.body())
        .map_err(|_| CheckpointTransitionRefusal::PredecessorIdentity)?;
    if identity != predecessor.id() {
        return Err(CheckpointTransitionRefusal::PredecessorIdentity);
    }
    let capsule_id = successor
        .last_checkpoint_id
        .filter(|id| Some(*id) != predecessor.body().last_checkpoint_id)
        .ok_or(CheckpointTransitionRefusal::CheckpointNotAdvanced)?;
    let mut expected = predecessor.body().clone();
    expected.predecessor_head_id = Some(predecessor.id());
    expected.generation = expected
        .generation
        .next()
        .map_err(|_| CheckpointTransitionRefusal::GenerationExhausted)?;
    expected.last_checkpoint_id = Some(capsule_id);
    if successor != &expected {
        return Err(CheckpointTransitionRefusal::HeadMismatch);
    }

    let predecessor_bytes =
        encode_body(predecessor.body()).map_err(CheckpointTransitionRefusal::HeadEncoding)?;
    let inspection = inspect_capsule_against_authority_head_bytes(
        &CryptoBodyIdentity,
        capsule_id,
        capsule_bytes,
        &predecessor_bytes,
        predecessor.body().last_checkpoint_id,
    )
    .map_err(|error| CheckpointTransitionRefusal::CapsuleInspection(Box::new(error)))?;
    if inspection.classification().outcome() != RestoreOutcome::Restorable {
        return Err(CheckpointTransitionRefusal::CapsuleMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
