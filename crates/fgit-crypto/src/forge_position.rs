//! Authenticated forge-position Merkle layout.
//!
//! A forge position is a map entry from one canonical stream label to the
//! exact logical position that stream has reached. The layout mirrors the
//! ref-state tree deliberately: entries are sorted by their semantic key,
//! duplicate keys are refused, leaves are domain-separated from interior
//! nodes, and proofs bind the key, position, index, and total tree shape.
//!
//! This module owns only the deterministic commitment and independent proof
//! verifier. Selecting the resulting root as current authority remains the
//! repository-head transition's responsibility.

use core::cmp::Ordering;

use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::label::{AsciiSlug, SchemaFamily, SchemaId};

use crate::merkle::{MerkleProof, MerkleRefusal, merkle_leaf, merkle_proof, merkle_root, verify_merkle_proof};
use crate::registry::IdentityDomain;

/// Why a forge-position commitment or proof could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgePositionRefusal {
    /// Two entries name the same forge stream.
    DuplicateStream,
    /// The requested stream is absent from the offered state.
    StreamNotPresent,
    /// The shared Merkle construction refused the requested operation.
    Merkle(MerkleRefusal),
}

impl core::fmt::Display for ForgePositionRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateStream => {
                formatter.write_str("two forge-position entries name the same stream")
            }
            Self::StreamNotPresent => {
                formatter.write_str("the requested forge stream is absent from the offered state")
            }
            Self::Merkle(source) => write!(formatter, "forge-position Merkle operation refused: {source}"),
        }
    }
}

impl core::error::Error for ForgePositionRefusal {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Merkle(source) => Some(source),
            Self::DuplicateStream | Self::StreamNotPresent => None,
        }
    }
}

impl From<MerkleRefusal> for ForgePositionRefusal {
    fn from(value: MerkleRefusal) -> Self {
        Self::Merkle(value)
    }
}

/// The schema every forge-position Merkle digest is bound to.
#[must_use]
pub const fn forge_position_schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("forge-position-merkle"), 1, 0)
}

/// The closed ordering rule for forge stream keys.
///
/// A non-membership proof may be added later, so the ordering is published now
/// rather than left as an incidental derived-ordering detail. Builder and
/// verifier extensions must compare these exact canonical bytes.
#[must_use]
pub fn forge_stream_order(left: &AsciiSlug, right: &AsciiSlug) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

/// One forge-position leaf over a length-delimited stream key and position.
///
/// The length prefix is load-bearing. The shared hash helper commits only to
/// the total concatenated body length, so a variable-length key must carry its
/// own boundary before the fixed-width position that follows it.
#[must_use]
pub fn forge_position_leaf(stream: &AsciiSlug, position: u64) -> DigestBytes {
    let stream_bytes = stream.as_bytes();
    let stream_length = u32::try_from(stream_bytes.len())
        .expect("an AsciiSlug is bounded well below u32")
        .to_be_bytes();
    let position = position.to_be_bytes();
    merkle_leaf(
        forge_position_schema(),
        &[&stream_length, stream_bytes, &position],
    )
}

fn sorted_forge_position_entries(
    entries: &[(AsciiSlug, u64)],
) -> Result<Vec<&(AsciiSlug, u64)>, ForgePositionRefusal> {
    let mut ordered: Vec<&(AsciiSlug, u64)> = entries.iter().collect();
    ordered.sort_by(|left, right| forge_stream_order(&left.0, &right.0));
    if ordered
        .windows(2)
        .any(|pair| forge_stream_order(&pair[0].0, &pair[1].0) == Ordering::Equal)
    {
        return Err(ForgePositionRefusal::DuplicateStream);
    }
    Ok(ordered)
}

/// Computes the authenticated root for a forge-position map.
///
/// # Errors
///
/// [`ForgePositionRefusal::DuplicateStream`] when the offered entries are not
/// a map.
pub fn forge_position_merkle_root(
    entries: &[(AsciiSlug, u64)],
) -> Result<Digest, ForgePositionRefusal> {
    let leaves = sorted_forge_position_entries(entries)?
        .into_iter()
        .map(|(stream, position)| forge_position_leaf(stream, *position))
        .collect::<Vec<_>>();
    Ok(Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        merkle_root(forge_position_schema(), &leaves),
    ))
}

/// Builds a membership proof for one forge stream and returns its bound
/// position.
///
/// # Errors
///
/// [`ForgePositionRefusal::DuplicateStream`] when the offered entries are not
/// a map, [`ForgePositionRefusal::StreamNotPresent`] when `stream` is absent,
/// and [`ForgePositionRefusal::Merkle`] when the shared proof builder refuses.
pub fn forge_position_membership_proof(
    entries: &[(AsciiSlug, u64)],
    stream: &AsciiSlug,
) -> Result<(u64, MerkleProof), ForgePositionRefusal> {
    let ordered = sorted_forge_position_entries(entries)?;
    let index = ordered
        .iter()
        .position(|(candidate, _)| forge_stream_order(candidate, stream) == Ordering::Equal)
        .ok_or(ForgePositionRefusal::StreamNotPresent)?;
    let position = ordered[index].1;
    let leaves = ordered
        .into_iter()
        .map(|(candidate, candidate_position)| {
            forge_position_leaf(candidate, *candidate_position)
        })
        .collect::<Vec<_>>();
    Ok((
        position,
        merkle_proof(forge_position_schema(), &leaves, index)?,
    ))
}

/// Verifies that `root` commits to `stream` holding `position`.
///
/// This proves membership in the supplied root. It does not prove that the
/// root is current; callers must obtain it from an authenticated authority
/// head under the matching layout version.
#[must_use]
pub fn verify_forge_position_membership(
    root: &Digest,
    stream: &AsciiSlug,
    position: u64,
    proof: &MerkleProof,
) -> bool {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return false;
    }
    verify_merkle_proof(
        forge_position_schema(),
        root.bytes(),
        &forge_position_leaf(stream, position),
        proof,
    )
}
