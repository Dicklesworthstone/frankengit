//! One Merkle construction, its membership proofs, and a verifier that needs
//! nothing but this crate.
//!
//! Two roots in a repository head are already Merkle-shaped — the
//! outcome index today, the ref state under
//! [`RootLayoutVersion::RefStateMerkleV1`] — and a third will follow. Each one
//! written separately is a tree whose proofs verify against a root nobody
//! publishes, because the prover and the publisher drifted. So the tree lives
//! here, once, and callers supply only their leaves and their ordering.
//!
//! # The shape, stated because a verifier has to reproduce it exactly
//!
//! * A leaf digest is `H(MerkleLeaf, schema, parts)`; the caller decides the
//!   parts and the order of the leaf slice.
//! * An interior node is `H(MerkleNode, schema, [left, right])`.
//! * Each level pairs `(0,1), (2,3), …`. **A final odd element is promoted
//!   unchanged**, not duplicated against itself. Duplicating is the more common
//!   convention and it is not the one already published here, so adopting it
//!   would silently change every existing root.
//! * The empty tree is `H(MerkleNode, schema, [])`, distinct from any leaf.
//! * A single leaf is its own root.
//!
//! # Ordering is the caller's, deliberately
//!
//! [`merkle_root`] preserves the slice order it is given. The outcome index
//! sorts its leaves **by digest**; the ref state sorts **by ref name**. Those
//! are different rules for good reasons, and a core that imposed either would
//! force one caller to sort twice or to hash a lie. What the core does
//! guarantee is that the same ordered leaves always give the same root.
//!
//! # What a proof does and does not establish
//!
//! A verified [`MerkleProof`] says the leaf is in the tree with that root, at
//! that index, among that many leaves. It says nothing about whether the root
//! is the *current* authority root — that is the caller's authenticated read,
//! and conflating the two is how a stale-but-valid proof gets accepted.

use crate::body_identity::internal_digest_over_parts;
use crate::registry::IdentityDomain;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitOid;
use fgit_types::refs::RefName;

/// Why a Merkle operation could not be completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleRefusal {
    /// A proof was requested for a leaf index the tree does not contain.
    LeafIndexOutOfRange {
        /// The index asked for.
        index: usize,
        /// How many leaves the tree has.
        leaf_count: usize,
    },
    /// A proof was requested from an empty tree, which has no leaves to prove.
    EmptyTree,
    /// Two entries carry the same ref name.
    ///
    /// A ref state is a map, so this is an invariant breach in the caller
    /// rather than a client-visible condition — but hashing it would silently
    /// commit to whichever copy sorted first.
    DuplicateRefName,
    /// The named ref is not present in the entries offered.
    RefNotPresent,
    /// This layout version admits no membership proof for the ref state.
    ///
    /// [`RootLayoutVersion::LegacyWholeBody`] commits to the whole canonical
    /// body, so there is no tree to walk and no proof to check. Refusing is the
    /// only honest answer: returning `false` would read as "the proof failed"
    /// when the truth is that no proof of this kind can exist, and returning
    /// `true` would be a verification nobody performed.
    LayoutAdmitsNoProof {
        /// The version that was asked to verify.
        version: RootLayoutVersion,
    },
}

impl core::fmt::Display for MerkleRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LeafIndexOutOfRange { index, leaf_count } => write!(
                f,
                "leaf index {index} is outside a tree of {leaf_count} leaves"
            ),
            Self::EmptyTree => f.write_str("an empty tree has no leaf to prove"),
            Self::DuplicateRefName => {
                f.write_str("two entries carry the same ref name; a ref state is a map")
            }
            Self::RefNotPresent => f.write_str("the named ref is not in the offered entries"),
            Self::LayoutAdmitsNoProof { version } => write!(
                f,
                "root layout version {} commits to the whole body, so no ref-state membership \
                 proof exists under it",
                version.code_point()
            ),
        }
    }
}

impl core::error::Error for MerkleRefusal {}

/// A leaf's position in the tree and the sibling path that proves it.
///
/// `leaf_count` is carried because the promotion rule depends on it: whether a
/// level pairs or promotes is a function of that level's length, which the
/// verifier derives from the leaf count rather than being told per level. A
/// proof that carried only siblings would leave the verifier guessing the
/// shape, and a guessed shape is a second implementation of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    index: usize,
    leaf_count: usize,
    siblings: Vec<DigestBytes>,
}

impl MerkleProof {
    /// Position of the proven leaf in the ordered leaf slice.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// How many leaves the tree holds.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// The sibling digests, bottom level first.
    #[must_use]
    pub fn siblings(&self) -> &[DigestBytes] {
        &self.siblings
    }
}

/// One interior node over two children.
fn node(schema: SchemaId, left: &DigestBytes, right: &DigestBytes) -> DigestBytes {
    internal_digest_over_parts(
        IdentityDomain::MerkleNode,
        schema,
        &[left.as_bytes(), right.as_bytes()],
    )
}

/// The digest of a tree with no leaves.
#[must_use]
pub fn empty_merkle_root(schema: SchemaId) -> DigestBytes {
    internal_digest_over_parts(IdentityDomain::MerkleNode, schema, &[])
}

/// Hash one leaf from its caller-chosen parts.
///
/// # Preimage ambiguity is the caller's problem to avoid
///
/// [`internal_digest_over_parts`] commits the **total** length in its header
/// and then concatenates the parts, so `[a, b]` and `[ab, ""]` hash
/// identically. A leaf built from a variable-length field followed by anything
/// else must length-delimit that field itself. [`ref_state_leaf`] does; see it
/// for the worked case.
#[must_use]
pub fn merkle_leaf(schema: SchemaId, parts: &[&[u8]]) -> DigestBytes {
    internal_digest_over_parts(IdentityDomain::MerkleLeaf, schema, parts)
}

/// Fold ordered leaves into a root, preserving the order given.
#[must_use]
pub fn merkle_root(schema: SchemaId, leaves: &[DigestBytes]) -> DigestBytes {
    let Some(&first) = leaves.first() else {
        return empty_merkle_root(schema);
    };
    let mut level: Vec<DigestBytes> = leaves.to_vec();
    let mut root = first;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let (pairs, remainder) = level.as_chunks::<2>();
        for [left, right] in pairs {
            next.push(node(schema, left, right));
        }
        if let Some(odd) = remainder.first() {
            next.push(*odd);
        }
        level = next;
        root = level.first().copied().unwrap_or(root);
    }
    root
}

/// The sibling path proving the leaf at `index`.
///
/// # Errors
///
/// [`MerkleRefusal::EmptyTree`] when there are no leaves, and
/// [`MerkleRefusal::LeafIndexOutOfRange`] when the index is past the last one.
pub fn merkle_proof(
    schema: SchemaId,
    leaves: &[DigestBytes],
    index: usize,
) -> Result<MerkleProof, MerkleRefusal> {
    if leaves.is_empty() {
        return Err(MerkleRefusal::EmptyTree);
    }
    if index >= leaves.len() {
        return Err(MerkleRefusal::LeafIndexOutOfRange {
            index,
            leaf_count: leaves.len(),
        });
    }

    let leaf_count = leaves.len();
    let mut level: Vec<DigestBytes> = leaves.to_vec();
    let mut position = index;
    let mut siblings = Vec::new();

    while level.len() > 1 {
        let promoted = position == level.len() - 1 && level.len() % 2 == 1;
        if !promoted {
            siblings.push(level[position ^ 1]);
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let (pairs, remainder) = level.as_chunks::<2>();
        for [left, right] in pairs {
            next.push(node(schema, left, right));
        }
        if let Some(odd) = remainder.first() {
            next.push(*odd);
        }
        position /= 2;
        level = next;
    }

    Ok(MerkleProof {
        index,
        leaf_count,
        siblings,
    })
}

/// Recompute the root a proof implies, so a caller can compare it to one it
/// authenticated.
///
/// Returns `None` when the proof's shape disagrees with its own `leaf_count` —
/// too few or too many siblings for the tree it claims to describe. That is a
/// malformed proof rather than a failed one, and the distinction matters: a
/// verifier that folded whatever siblings it was handed would accept a proof
/// from a differently-shaped tree.
#[must_use]
pub fn merkle_root_from_proof(
    schema: SchemaId,
    leaf: &DigestBytes,
    proof: &MerkleProof,
) -> Option<DigestBytes> {
    if proof.leaf_count == 0 || proof.index >= proof.leaf_count {
        return None;
    }

    let mut computed = *leaf;
    let mut position = proof.index;
    let mut width = proof.leaf_count;
    let mut offered = proof.siblings.iter();

    while width > 1 {
        let promoted = position == width - 1 && width % 2 == 1;
        if !promoted {
            let sibling = offered.next()?;
            computed = if position.is_multiple_of(2) {
                node(schema, &computed, sibling)
            } else {
                node(schema, sibling, &computed)
            };
        }
        position /= 2;
        width = width.div_ceil(2);
    }

    // Every sibling must be consumed: a proof carrying extra ones describes a
    // different tree and must not verify by accident.
    if offered.next().is_some() {
        return None;
    }
    Some(computed)
}

/// Whether `proof` shows `leaf` is in the tree rooted at `root`.
#[must_use]
pub fn verify_merkle_proof(
    schema: SchemaId,
    root: &DigestBytes,
    leaf: &DigestBytes,
    proof: &MerkleProof,
) -> bool {
    merkle_root_from_proof(schema, leaf, proof).is_some_and(|computed| computed == *root)
}

// --- the ref-state layout ---------------------------------------------------

/// The schema every ref-state Merkle digest is bound to.
#[must_use]
pub const fn ref_state_schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("ref-state-merkle"), 1, 0)
}

/// One ref-state leaf, over a length-delimited name and its object identity.
///
/// # Why the length prefix is load-bearing
///
/// [`internal_digest_over_parts`] commits the total preimage length and then
/// concatenates, so without a delimiter the name could borrow bytes from what
/// follows it. A four-byte big-endian length makes the boundary explicit, and
/// the two-byte algorithm selector that follows fixes the width of the
/// remaining identity bytes. Two distinct ref states therefore cannot share a
/// leaf.
///
/// This is not a hypothetical: it is the one place in this module where a
/// variable-length field is followed by anything at all.
#[must_use]
pub fn ref_state_leaf(name: &RefName, oid: &GitOid) -> DigestBytes {
    let bytes = name.as_bytes();
    let length = u32::try_from(bytes.len())
        .expect("a ref name is bounded well below u32 by MAX_REF_NAME_LEN")
        .to_be_bytes();
    let algorithm = oid.algorithm().code_point().to_be_bytes();
    merkle_leaf(
        ref_state_schema(),
        &[&length, bytes, &algorithm, oid.as_bytes()],
    )
}

/// Ordered leaves for a ref state, sorted by ref name.
///
/// Sorting is by the name's canonical bytes, which is a total order over a set
/// with no duplicates — so the tie-break is closed by there being no ties. A
/// duplicate name is refused rather than resolved, because resolving it would
/// silently commit to whichever copy sorted first.
fn ordered_ref_state_leaves(
    entries: &[(RefName, GitOid)],
) -> Result<Vec<DigestBytes>, MerkleRefusal> {
    let mut ordered: Vec<&(RefName, GitOid)> = entries.iter().collect();
    ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if ordered
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(MerkleRefusal::DuplicateRefName);
    }
    Ok(ordered
        .into_iter()
        .map(|(name, oid)| ref_state_leaf(name, oid))
        .collect())
}

/// The `ref_root` a head publishes under
/// [`RootLayoutVersion::RefStateMerkleV1`](fgit_types::layout::RootLayoutVersion::RefStateMerkleV1).
///
/// # Errors
///
/// [`MerkleRefusal::DuplicateRefName`] when two entries name the same ref.
pub fn ref_state_merkle_root(entries: &[(RefName, GitOid)]) -> Result<Digest, MerkleRefusal> {
    let leaves = ordered_ref_state_leaves(entries)?;
    Ok(Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        merkle_root(ref_state_schema(), &leaves),
    ))
}

/// A membership proof for one ref, with the identity it is bound to.
///
/// # Errors
///
/// [`MerkleRefusal::DuplicateRefName`] when the entries are not a map, and
/// [`MerkleRefusal::RefNotPresent`] when the name is absent — absence is a
/// refusal rather than an empty proof, because an empty proof verifies
/// vacuously and would let a caller conclude membership from nothing.
pub fn ref_state_membership_proof(
    entries: &[(RefName, GitOid)],
    name: &RefName,
) -> Result<(GitOid, MerkleProof), MerkleRefusal> {
    let mut ordered: Vec<&(RefName, GitOid)> = entries.iter().collect();
    ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if ordered
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(MerkleRefusal::DuplicateRefName);
    }
    let index = ordered
        .iter()
        .position(|(candidate, _)| candidate.as_bytes() == name.as_bytes())
        .ok_or(MerkleRefusal::RefNotPresent)?;
    let oid = ordered[index].1;
    let leaves: Vec<DigestBytes> = ordered
        .into_iter()
        .map(|(each, each_oid)| ref_state_leaf(each, each_oid))
        .collect();
    let proof = merkle_proof(ref_state_schema(), &leaves, index)?;
    Ok((oid, proof))
}

/// The independent verifier: does `root` commit to `name` holding `oid`?
///
/// This is the function a verified-read path wraps. It reaches nothing outside
/// `fgit-types` and this crate — no store, no codec, no authority — so a client
/// can run it against a root it obtained by any means. What it does **not**
/// establish is that `root` is current; that is an authenticated read the
/// caller must already hold, and treating this as a substitute would accept a
/// stale-but-internally-valid proof.
#[must_use]
pub fn verify_ref_state_membership(
    root: &Digest,
    name: &RefName,
    oid: &GitOid,
    proof: &MerkleProof,
) -> bool {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return false;
    }
    verify_merkle_proof(
        ref_state_schema(),
        root.bytes(),
        &ref_state_leaf(name, oid),
        proof,
    )
}

/// Verify a ref-state membership proof under an explicitly named layout.
///
/// This is the entry point a verified read should use, and the reason
/// [`RootLayoutVersion`] exists: the version is a fact about the head, so the
/// verifier must be *told* it rather than inferring it from a digest that
/// cannot describe itself.
///
/// # Why the legacy layout is refused rather than answered
///
/// Under [`RootLayoutVersion::LegacyWholeBody`] there is no tree, so there is
/// no proof to check. Returning `Ok(false)` would read as "this proof failed",
/// which is a different and misleading claim — the truth is that no proof of
/// this kind can exist for that layout, and a caller that saw `false` might
/// retry with a different proof forever. Refusing names the actual situation
/// and points at the migration that fixes it.
///
/// # Errors
///
/// [`MerkleRefusal::LayoutAdmitsNoProof`] when the version admits no ref-state
/// membership proof.
pub fn verify_ref_state_membership_under(
    version: RootLayoutVersion,
    root: &Digest,
    name: &RefName,
    oid: &GitOid,
    proof: &MerkleProof,
) -> Result<bool, MerkleRefusal> {
    if !version.admits_ref_state_membership_proof() {
        return Err(MerkleRefusal::LayoutAdmitsNoProof { version });
    }
    Ok(verify_ref_state_membership(root, name, oid, proof))
}
