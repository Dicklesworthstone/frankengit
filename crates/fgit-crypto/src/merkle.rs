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

use core::cmp::Ordering;

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
    /// Two entries carry the same object identity.
    DuplicateObjectOid,
    /// The named ref is not present in the entries offered.
    RefNotPresent,
    /// The requested object identity is not present in the closure offered.
    ObjectNotPresent,
    /// A non-membership proof was requested for a ref the state contains.
    ///
    /// Absence and presence are different questions with different proofs, and
    /// answering this one with a membership proof would let a caller that asked
    /// "is it absent?" receive something that verifies, just not as an answer to
    /// what was asked.
    RefIsPresent,
    /// A non-membership proof was requested for an object the closure contains.
    ObjectIsPresent,
    /// This layout version admits no membership proof for the ref state or object closure.
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
            Self::DuplicateObjectOid => {
                f.write_str("two entries carry the same object identity; a closure is a set")
            }
            Self::RefNotPresent => f.write_str("the named ref is not in the offered entries"),
            Self::ObjectNotPresent => {
                f.write_str("the requested object identity is not in the offered closure")
            }
            Self::RefIsPresent => {
                f.write_str("the named ref is present, so it has no non-membership proof")
            }
            Self::ObjectIsPresent => {
                f.write_str("the requested object is present, so it has no non-membership proof")
            }
            Self::LayoutAdmitsNoProof { version } => write!(
                f,
                "root layout version {} commits to the whole body, so no membership \
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
    /// Rebuild a proof from parts, as a decoder must.
    ///
    /// A proof arrives over the wire as numbers and digests, so a verifier that
    /// could only consume proofs built in-process by [`merkle_proof`] would not
    /// be an independent verifier at all — it would be one half of a single
    /// process checking its own work. Nothing here is trusted: `index`,
    /// `leaf_count` and `siblings` are claims, and verification is what decides
    /// whether they reproduce the root.
    #[must_use]
    pub const fn new(index: usize, leaf_count: usize, siblings: Vec<DigestBytes>) -> Self {
        Self {
            index,
            leaf_count,
            siblings,
        }
    }

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
    let ordered = sorted_ref_state_entries(entries)?;
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
    let ordered = sorted_ref_state_entries(entries)?;
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

// --- ordered non-membership (frankengit-56i4) ---------------------------------

/// The one closed sort order for ref-state leaves.
///
/// # Why this is a function and not `RefName`'s derived `Ord`
///
/// They agree today, and only by accident: `RefName` holds a single `Vec<u8>`,
/// so its derived ordering is the byte ordering the tree is built with. Add a
/// second field to `RefName` and the derived ordering silently becomes
/// something else while the tree keeps sorting by bytes. A non-membership proof
/// is a claim that *nothing sorts between* two leaves, so builder and verifier
/// disagreeing about "sorts" is not a cosmetic bug: it is a proof of absence
/// for a ref that is present. One function, used by both, makes that
/// unrepresentable.
#[must_use]
pub fn ref_name_order(left: &RefName, right: &RefName) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

/// Sort entries into the closed order and reject a non-map.
fn sorted_ref_state_entries(
    entries: &[(RefName, GitOid)],
) -> Result<Vec<&(RefName, GitOid)>, MerkleRefusal> {
    let mut ordered: Vec<&(RefName, GitOid)> = entries.iter().collect();
    ordered.sort_by(|left, right| ref_name_order(&left.0, &right.0));
    if ordered
        .windows(2)
        .any(|pair| ref_name_order(&pair[0].0, &pair[1].0) == Ordering::Equal)
    {
        return Err(MerkleRefusal::DuplicateRefName);
    }
    Ok(ordered)
}

/// One existing leaf, named, with the path that proves it is in the tree.
///
/// The name is carried because that is the whole gap this type closes: a bare
/// [`MerkleProof`] commits to a position and a digest, and a verifier holding
/// only that cannot tell which *name* sits at the position, so it cannot decide
/// whether the queried name would have sorted before or after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefStateNeighbour {
    name: RefName,
    oid: GitOid,
    proof: MerkleProof,
}

impl RefStateNeighbour {
    /// Rebuild a neighbour from parts, as a decoder must.
    ///
    /// Same reason as [`MerkleProof::new`]: the consumer of a non-membership
    /// proof receives one, it does not generate one.
    #[must_use]
    pub const fn new(name: RefName, oid: GitOid, proof: MerkleProof) -> Self {
        Self { name, oid, proof }
    }

    /// The neighbour's ref name.
    #[must_use]
    pub const fn name(&self) -> &RefName {
        &self.name
    }

    /// The identity that name holds.
    #[must_use]
    pub const fn oid(&self) -> &GitOid {
        &self.oid
    }

    /// The membership path proving this neighbour is in the tree.
    #[must_use]
    pub const fn proof(&self) -> &MerkleProof {
        &self.proof
    }
}

/// Evidence that a ref name is **absent** from a v1 ref state.
///
/// Absence is proved by exhibiting the leaves that would have surrounded the
/// name, so the four variants are the four places a name can fail to be: in an
/// empty state, before everything, between two adjacent leaves, or after
/// everything. The edges are separate variants rather than an `Option` pair
/// because "there is no predecessor" is a structural fact the verifier must
/// check differently — at the edges it checks a position against the tree's
/// bounds, and in the middle it checks two positions against each other.
///
/// # Typed non-claim: this is sound only for a tree whose leaves are sorted
///
/// A membership proof needs no assumption about how the tree was built: the
/// path either reproduces the root or it does not. Non-membership is different.
/// It concludes "nothing sorts between these two adjacent leaves", and that
/// follows **only** if the leaves were placed in sorted order. A root alone
/// cannot testify to its own sortedness, and this verifier does not attempt to
/// establish it.
///
/// In this system that assumption is discharged upstream rather than ignored:
/// every ref-state root is produced by [`ref_state_merkle_root`], which sorts
/// through [`ref_name_order`] and refuses duplicates, and the root is named by
/// an authenticated head. So the trust already required for the root to mean
/// anything is the same trust this relies on. What a caller must **not** do is
/// hand this verifier a root of unknown provenance and read a `true` as proof
/// of absence — against an adversarially built tree it is not one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefStateNonMembershipProof {
    /// The ref state holds no refs at all.
    EmptyState,
    /// The queried name sorts before the first leaf.
    BeforeFirst {
        /// The leaf at index 0.
        first: Box<RefStateNeighbour>,
    },
    /// The queried name sorts strictly between two adjacent leaves.
    Between {
        /// The leaf at index `i`.
        predecessor: Box<RefStateNeighbour>,
        /// The leaf at index `i + 1`.
        successor: Box<RefStateNeighbour>,
    },
    /// The queried name sorts after the last leaf.
    AfterLast {
        /// The leaf at index `leaf_count - 1`.
        last: Box<RefStateNeighbour>,
    },
}

/// Build the proof that `name` is absent from `entries`.
///
/// # Errors
///
/// [`MerkleRefusal::DuplicateRefName`] when the entries are not a map, and
/// [`MerkleRefusal::RefIsPresent`] when the name is there — presence is a real
/// answer to a different question, not a failure to build this one.
pub fn ref_state_non_membership_proof(
    entries: &[(RefName, GitOid)],
    name: &RefName,
) -> Result<RefStateNonMembershipProof, MerkleRefusal> {
    let ordered = sorted_ref_state_entries(entries)?;
    if ordered.is_empty() {
        return Ok(RefStateNonMembershipProof::EmptyState);
    }

    // `partition_point` gives the number of leaves that sort strictly before
    // the query, which is the insertion index. Deriving both the edge cases and
    // the neighbour pair from that one number keeps them from disagreeing.
    let insertion =
        ordered.partition_point(|(candidate, _)| ref_name_order(candidate, name) == Ordering::Less);
    if let Some((candidate, _)) = ordered.get(insertion)
        && ref_name_order(candidate, name) == Ordering::Equal
    {
        return Err(MerkleRefusal::RefIsPresent);
    }

    let leaves: Vec<DigestBytes> = ordered
        .iter()
        .map(|(candidate, oid)| ref_state_leaf(candidate, oid))
        .collect();
    let neighbour = |index: usize| -> Result<Box<RefStateNeighbour>, MerkleRefusal> {
        let (candidate, oid) = ordered[index];
        Ok(Box::new(RefStateNeighbour {
            name: candidate.clone(),
            oid: *oid,
            proof: merkle_proof(ref_state_schema(), &leaves, index)?,
        }))
    };

    if insertion == 0 {
        return Ok(RefStateNonMembershipProof::BeforeFirst {
            first: neighbour(0)?,
        });
    }
    if insertion == ordered.len() {
        return Ok(RefStateNonMembershipProof::AfterLast {
            last: neighbour(ordered.len() - 1)?,
        });
    }
    Ok(RefStateNonMembershipProof::Between {
        predecessor: neighbour(insertion - 1)?,
        successor: neighbour(insertion)?,
    })
}

/// The independent verifier: does `root` commit to a state **without** `name`?
///
/// Like [`verify_ref_state_membership`], this reaches nothing outside
/// `fgit-types` and this crate, and it establishes nothing about whether `root`
/// is current. Read the non-claim on [`RefStateNonMembershipProof`] before
/// relying on a `true` from this function: it is sound for a sorted tree, which
/// is a property of how the root was built and not something the root proves.
#[must_use]
pub fn verify_ref_state_non_membership(
    root: &Digest,
    name: &RefName,
    proof: &RefStateNonMembershipProof,
) -> bool {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return false;
    }
    let holds = |neighbour: &RefStateNeighbour| {
        verify_ref_state_membership(root, &neighbour.name, &neighbour.oid, &neighbour.proof)
    };
    match proof {
        RefStateNonMembershipProof::EmptyState => {
            *root.bytes() == empty_merkle_root(ref_state_schema())
        }
        RefStateNonMembershipProof::BeforeFirst { first } => {
            // Index 0 *is* the first position, so nothing can sort before it
            // without displacing this leaf — and the path binds this leaf to
            // that position under this root.
            first.proof.index() == 0
                && ref_name_order(name, &first.name) == Ordering::Less
                && holds(first)
        }
        RefStateNonMembershipProof::AfterLast { last } => {
            // `leaf_count` is bound into the fold shape, so claiming the last
            // position cannot be done by inventing a larger tree.
            // The index is decoded, untrusted input. Checked arithmetic turns
            // a saturated claim into a plain refusal instead of a debug-build
            // panic or a release-build wraparound.
            last.proof.index().checked_add(1) == Some(last.proof.leaf_count())
                && ref_name_order(&last.name, name) == Ordering::Less
                && holds(last)
        }
        RefStateNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            predecessor.proof.leaf_count() == successor.proof.leaf_count()
                // As above, adjacency is checked against a decoded index, not
                // a value computed by this verifier.
                && predecessor.proof.index().checked_add(1) == Some(successor.proof.index())
                && ref_name_order(&predecessor.name, name) == Ordering::Less
                && ref_name_order(name, &successor.name) == Ordering::Less
                && holds(predecessor)
                && holds(successor)
        }
    }
}

/// Verify a ref-state non-membership proof under an explicitly named layout.
///
/// # Errors
///
/// [`MerkleRefusal::LayoutAdmitsNoProof`] when the version admits no ref-state
/// proof. Under [`RootLayoutVersion::LegacyWholeBody`] there is no tree, so
/// there is no ordering to appeal to and absence cannot be shown this way.
pub fn verify_ref_state_non_membership_under(
    version: RootLayoutVersion,
    root: &Digest,
    name: &RefName,
    proof: &RefStateNonMembershipProof,
) -> Result<bool, MerkleRefusal> {
    if !version.admits_ref_state_membership_proof() {
        return Err(MerkleRefusal::LayoutAdmitsNoProof { version });
    }
    Ok(verify_ref_state_non_membership(root, name, proof))
}

// --- object closure Merkle layout and membership (frankengit-c7tb) -------------

/// Schema ID for the object-closure Merkle tree domain.
#[must_use]
pub const fn object_closure_schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("object-closure-merkle"), 1, 0)
}

/// Computes the domain-separated Merkle leaf digest for one object identity.
#[must_use]
pub fn object_closure_leaf(oid: &GitOid) -> DigestBytes {
    let algorithm = oid.algorithm().code_point().to_be_bytes();
    merkle_leaf(object_closure_schema(), &[&algorithm, oid.as_bytes()])
}

/// The closed sort order for Git object identities.
#[must_use]
pub fn git_oid_order(left: &GitOid, right: &GitOid) -> Ordering {
    left.cmp(right)
}

/// Sort entries into the closed order and reject duplicates.
pub fn sorted_object_closure_entries(objects: &[GitOid]) -> Result<Vec<&GitOid>, MerkleRefusal> {
    let mut ordered: Vec<&GitOid> = objects.iter().collect();
    ordered.sort_by(|left, right| git_oid_order(left, right));
    if ordered
        .windows(2)
        .any(|pair| git_oid_order(pair[0], pair[1]) == Ordering::Equal)
    {
        return Err(MerkleRefusal::DuplicateObjectOid);
    }
    Ok(ordered)
}

/// Computes the root digest of the domain-separated Merkle tree over an object closure.
pub fn object_closure_merkle_root(objects: &[GitOid]) -> Result<Digest, MerkleRefusal> {
    let ordered = sorted_object_closure_entries(objects)?;
    let leaves: Vec<DigestBytes> = ordered.into_iter().map(object_closure_leaf).collect();
    Ok(Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        merkle_root(object_closure_schema(), &leaves),
    ))
}

/// Computes a membership proof for one object identity in an object closure.
pub fn object_closure_membership_proof(
    objects: &[GitOid],
    oid: &GitOid,
) -> Result<MerkleProof, MerkleRefusal> {
    let ordered = sorted_object_closure_entries(objects)?;
    let index = ordered
        .iter()
        .position(|candidate| *candidate == oid)
        .ok_or(MerkleRefusal::ObjectNotPresent)?;
    let leaves: Vec<DigestBytes> = ordered.into_iter().map(object_closure_leaf).collect();
    merkle_proof(object_closure_schema(), &leaves, index)
}

/// Verifies that `root` commits to `oid` via `proof`.
#[must_use]
pub fn verify_object_closure_membership(root: &Digest, oid: &GitOid, proof: &MerkleProof) -> bool {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return false;
    }
    verify_merkle_proof(
        object_closure_schema(),
        root.bytes(),
        &object_closure_leaf(oid),
        proof,
    )
}

/// Verifies an object-closure membership proof under an explicitly named layout.
pub fn verify_object_closure_membership_under(
    version: RootLayoutVersion,
    root: &Digest,
    oid: &GitOid,
    proof: &MerkleProof,
) -> Result<bool, MerkleRefusal> {
    if !version.admits_object_closure_membership_proof() {
        return Err(MerkleRefusal::LayoutAdmitsNoProof { version });
    }
    Ok(verify_object_closure_membership(root, oid, proof))
}

/// One existing object leaf, with the path that proves it is in the closure tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectClosureNeighbour {
    oid: GitOid,
    proof: MerkleProof,
}

impl ObjectClosureNeighbour {
    /// Rebuild a neighbour from parts, as a decoder must.
    #[must_use]
    pub const fn new(oid: GitOid, proof: MerkleProof) -> Self {
        Self { oid, proof }
    }

    /// The neighbour's object identity.
    #[must_use]
    pub const fn oid(&self) -> &GitOid {
        &self.oid
    }

    /// The membership path proving this neighbour is in the tree.
    #[must_use]
    pub const fn proof(&self) -> &MerkleProof {
        &self.proof
    }
}

/// Evidence that an object identity is **absent** from a closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectClosureNonMembershipProof {
    /// The closure holds no objects at all.
    EmptyClosure,
    /// The queried object sorts before the first leaf.
    BeforeFirst {
        /// The leaf at index 0.
        first: Box<ObjectClosureNeighbour>,
    },
    /// The queried object sorts strictly between two adjacent leaves.
    Between {
        /// The leaf at index `i`.
        predecessor: Box<ObjectClosureNeighbour>,
        /// The leaf at index `i + 1`.
        successor: Box<ObjectClosureNeighbour>,
    },
    /// The queried object sorts after the last leaf.
    AfterLast {
        /// The leaf at index `leaf_count - 1`.
        last: Box<ObjectClosureNeighbour>,
    },
}

/// Build the proof that `oid` is absent from `objects`.
pub fn object_closure_non_membership_proof(
    objects: &[GitOid],
    oid: &GitOid,
) -> Result<ObjectClosureNonMembershipProof, MerkleRefusal> {
    let ordered = sorted_object_closure_entries(objects)?;
    if ordered.is_empty() {
        return Ok(ObjectClosureNonMembershipProof::EmptyClosure);
    }

    let insertion =
        ordered.partition_point(|candidate| git_oid_order(candidate, oid) == Ordering::Less);
    if let Some(candidate) = ordered.get(insertion)
        && git_oid_order(candidate, oid) == Ordering::Equal
    {
        return Err(MerkleRefusal::ObjectIsPresent);
    }

    let leaves: Vec<DigestBytes> = ordered
        .iter()
        .map(|candidate| object_closure_leaf(candidate))
        .collect();
    let neighbour = |index: usize| -> Result<Box<ObjectClosureNeighbour>, MerkleRefusal> {
        let candidate = ordered[index];
        Ok(Box::new(ObjectClosureNeighbour {
            oid: *candidate,
            proof: merkle_proof(object_closure_schema(), &leaves, index)?,
        }))
    };

    if insertion == 0 {
        return Ok(ObjectClosureNonMembershipProof::BeforeFirst {
            first: neighbour(0)?,
        });
    }
    if insertion == ordered.len() {
        return Ok(ObjectClosureNonMembershipProof::AfterLast {
            last: neighbour(ordered.len() - 1)?,
        });
    }
    Ok(ObjectClosureNonMembershipProof::Between {
        predecessor: neighbour(insertion - 1)?,
        successor: neighbour(insertion)?,
    })
}

/// The independent verifier: does `root` commit to a closure **without** `oid`?
#[must_use]
pub fn verify_object_closure_non_membership(
    root: &Digest,
    oid: &GitOid,
    proof: &ObjectClosureNonMembershipProof,
) -> bool {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return false;
    }
    let holds = |neighbour: &ObjectClosureNeighbour| {
        verify_object_closure_membership(root, &neighbour.oid, &neighbour.proof)
    };
    match proof {
        ObjectClosureNonMembershipProof::EmptyClosure => {
            *root.bytes() == empty_merkle_root(object_closure_schema())
        }
        ObjectClosureNonMembershipProof::BeforeFirst { first } => {
            first.proof.index() == 0
                && git_oid_order(oid, &first.oid) == Ordering::Less
                && holds(first)
        }
        ObjectClosureNonMembershipProof::AfterLast { last } => {
            // `checked_add` because `index` is a decoded claim, not a computed
            // value: `MerkleProof::new` states outright that nothing it carries
            // is trusted. A hostile `usize::MAX` panics here under the overflow
            // checks that debug and test builds enable by default, and wraps to
            // zero under the release profile, which has none. Neither is a
            // typed refusal, and a verifier that aborts on input it was built to
            // reject is the input deciding the outcome.
            last.proof.index().checked_add(1) == Some(last.proof.leaf_count())
                && git_oid_order(&last.oid, oid) == Ordering::Less
                && holds(last)
        }
        ObjectClosureNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            predecessor.proof.leaf_count() == successor.proof.leaf_count()
                // Same reason as `AfterLast`: adjacency is checked against a
                // decoded index, so the addition is the attacker's arithmetic.
                && predecessor.proof.index().checked_add(1) == Some(successor.proof.index())
                && git_oid_order(&predecessor.oid, oid) == Ordering::Less
                && git_oid_order(oid, &successor.oid) == Ordering::Less
                && holds(predecessor)
                && holds(successor)
        }
    }
}

/// Verify an object-closure non-membership proof under an explicitly named layout.
pub fn verify_object_closure_non_membership_under(
    version: RootLayoutVersion,
    root: &Digest,
    oid: &GitOid,
    proof: &ObjectClosureNonMembershipProof,
) -> Result<bool, MerkleRefusal> {
    if !version.admits_object_closure_membership_proof() {
        return Err(MerkleRefusal::LayoutAdmitsNoProof { version });
    }
    Ok(verify_object_closure_non_membership(root, oid, proof))
}
