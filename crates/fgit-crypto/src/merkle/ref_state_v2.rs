//! Version-two ref commitments bind symbolic HEAD without inventing an OID.
//!
//! Index zero is always the typed HEAD leaf. Direct-ref leaves start at index
//! one, use a different discriminator, and retain the canonical name order.
//! V1 roots and proofs are deliberately computed by the untouched v1 helpers.

use super::{
    Digest, DigestBytes, GitOid, IdentityDomain, MerkleProof, MerkleRefusal, Ordering, RefName,
    RefStateNeighbour, RefStateNonMembershipProof, RootLayoutVersion, SchemaFamily, SchemaId,
    internal_digest_over_parts, merkle_leaf, merkle_proof, merkle_root, merkle_root_from_proof,
    ref_name_order, sorted_ref_state_entries,
};

/// A separate schema prevents any v1 leaf, interior or empty root from acquiring
/// v2 meaning. The existing registered Merkle identity domains remain unchanged.
#[must_use]
pub const fn ref_state_schema_v2() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("ref-state-merkle"), 2, 0)
}

/// Commit to exact symbolic HEAD bytes, with an explicit absent/present tag.
/// `HEAD` does not borrow a native Git object-ID domain or a fake ref entry.
pub fn ref_state_head_leaf_v2(head_target: Option<&RefName>) -> Result<DigestBytes, MerkleRefusal> {
    let Some(target) = head_target else {
        return Ok(merkle_leaf(ref_state_schema_v2(), &[&[0, 0]]));
    };
    let bytes = target.as_bytes();
    if !bytes.starts_with(b"refs/heads/") || bytes.len() == b"refs/heads/".len() {
        return Err(MerkleRefusal::InvalidHeadTarget);
    }
    let length = u32::try_from(bytes.len())
        .expect("a ref name is bounded well below u32 by MAX_REF_NAME_LEN")
        .to_be_bytes();
    Ok(merkle_leaf(
        ref_state_schema_v2(),
        &[&[0, 1], &length, bytes],
    ))
}

/// The v2 direct-ref leaf: discriminator one, length-delimited exact name,
/// native hash selector and native identity. All bytes remain unnormalized.
#[must_use]
pub fn ref_state_leaf_v2(name: &RefName, oid: &GitOid) -> DigestBytes {
    let bytes = name.as_bytes();
    let length = u32::try_from(bytes.len())
        .expect("a ref name is bounded well below u32 by MAX_REF_NAME_LEN")
        .to_be_bytes();
    let algorithm = oid.algorithm().code_point().to_be_bytes();
    merkle_leaf(
        ref_state_schema_v2(),
        &[&[1], &length, bytes, &algorithm, oid.as_bytes()],
    )
}

fn leaves(
    ordered: &[&(RefName, GitOid)],
    head_target: Option<&RefName>,
) -> Result<Vec<DigestBytes>, MerkleRefusal> {
    let mut result = Vec::with_capacity(ordered.len().saturating_add(1));
    result.push(ref_state_head_leaf_v2(head_target)?);
    result.extend(
        ordered
            .iter()
            .map(|(name, oid)| ref_state_leaf_v2(name, oid)),
    );
    Ok(result)
}

/// Bind cardinality as well as the raw apex. Promotion of an unpaired subtree
/// otherwise lets a proof relabel its position in a smaller tree: in [HEAD,A,B],
/// B can claim index 1 of 2 with subtree (HEAD,A) as its sibling. That is a false
/// BeforeFirst witness for A. The root envelope makes leaf_count authoritative.
fn root_envelope(apex: &DigestBytes, leaf_count: usize) -> DigestBytes {
    let count = u64::try_from(leaf_count)
        .expect("a slice length always fits in u64 on supported targets")
        .to_be_bytes();
    internal_digest_over_parts(
        IdentityDomain::MerkleNode,
        ref_state_schema_v2(),
        &[&[2], &count, apex.as_bytes()],
    )
}

fn verify_leaf(root: &Digest, leaf: &DigestBytes, proof: &MerkleProof) -> bool {
    root.algorithm() == IdentityDomain::MerkleNode.algorithm().id()
        && merkle_root_from_proof(ref_state_schema_v2(), leaf, proof)
            .is_some_and(|apex| root_envelope(&apex, proof.leaf_count()) == *root.bytes())
}

/// Root for layouts `RefStateMerkleV2` and
/// `RefStateAndObjectClosureMerkleV2`. Even an empty direct-ref map commits to
/// one HEAD leaf. The typed root envelope binds the exact leaf count. Names
/// must be unique and a present HEAD must name a branch.
pub fn ref_state_merkle_root_v2(
    entries: &[(RefName, GitOid)],
    head_target: Option<&RefName>,
) -> Result<Digest, MerkleRefusal> {
    let ordered = sorted_ref_state_entries(entries)?;
    let leaves = leaves(&ordered, head_target)?;
    Ok(Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        root_envelope(&merkle_root(ref_state_schema_v2(), &leaves), leaves.len()),
    ))
}

/// Prove a direct ref at its v2 index, with the mandatory HEAD leaf included
/// in the tree. The sibling digest binds HEAD without disclosing its target.
pub fn ref_state_membership_proof_v2(
    entries: &[(RefName, GitOid)],
    head_target: Option<&RefName>,
    name: &RefName,
) -> Result<(GitOid, MerkleProof), MerkleRefusal> {
    let ordered = sorted_ref_state_entries(entries)?;
    let leaves = leaves(&ordered, head_target)?;
    let index = ordered
        .iter()
        .position(|(candidate, _)| ref_name_order(candidate, name) == Ordering::Equal)
        .ok_or(MerkleRefusal::RefNotPresent)?;
    Ok((
        ordered[index].1,
        merkle_proof(ref_state_schema_v2(), &leaves, index + 1)?,
    ))
}

/// Prove the exact optional HEAD target at its mandatory index zero. The proof
/// does not establish target existence: unborn symbolic HEAD is representable.
pub fn ref_state_head_membership_proof_v2(
    entries: &[(RefName, GitOid)],
    head_target: Option<&RefName>,
) -> Result<MerkleProof, MerkleRefusal> {
    let ordered = sorted_ref_state_entries(entries)?;
    merkle_proof(ref_state_schema_v2(), &leaves(&ordered, head_target)?, 0)
}

/// Independently verify a HEAD claim under an authenticated layout and root.
/// Old layouts admit no HEAD Merkle proof, including legacy whole-body roots.
pub fn verify_ref_state_head_membership_under(
    version: RootLayoutVersion,
    root: &Digest,
    head_target: Option<&RefName>,
    proof: &MerkleProof,
) -> Result<bool, MerkleRefusal> {
    if !version.uses_head_aware_ref_merkle() {
        return Err(MerkleRefusal::LayoutAdmitsNoProof { version });
    }
    let leaf = ref_state_head_leaf_v2(head_target)?;
    Ok(proof.index() == 0 && verify_leaf(root, &leaf, proof))
}

pub(super) fn verify_membership(
    root: &Digest,
    name: &RefName,
    oid: &GitOid,
    proof: &MerkleProof,
) -> bool {
    proof.index() > 0 && verify_leaf(root, &ref_state_leaf_v2(name, oid), proof)
}

/// Build an ordered direct-ref absence proof under the v2 layout. Empty ref
/// maps use `HeadOnly`; populated maps prove the relevant direct neighbours.
pub fn ref_state_non_membership_proof_v2(
    entries: &[(RefName, GitOid)],
    head_target: Option<&RefName>,
    name: &RefName,
) -> Result<RefStateNonMembershipProof, MerkleRefusal> {
    let ordered = sorted_ref_state_entries(entries)?;
    let leaves = leaves(&ordered, head_target)?;
    if ordered.is_empty() {
        return Ok(RefStateNonMembershipProof::HeadOnly {
            head_target: head_target.cloned(),
        });
    }
    let insertion =
        ordered.partition_point(|(candidate, _)| ref_name_order(candidate, name) == Ordering::Less);
    if ordered
        .get(insertion)
        .is_some_and(|(candidate, _)| ref_name_order(candidate, name) == Ordering::Equal)
    {
        return Err(MerkleRefusal::RefIsPresent);
    }
    let neighbour = |index: usize| -> Result<Box<RefStateNeighbour>, MerkleRefusal> {
        let (candidate, oid) = ordered[index];
        Ok(Box::new(RefStateNeighbour::new(
            candidate.clone(),
            *oid,
            merkle_proof(ref_state_schema_v2(), &leaves, index + 1)?,
        )))
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

pub(super) fn verify_non_membership(
    root: &Digest,
    name: &RefName,
    proof: &RefStateNonMembershipProof,
) -> bool {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return false;
    }
    let holds = |neighbour: &RefStateNeighbour| {
        verify_membership(root, neighbour.name(), neighbour.oid(), neighbour.proof())
    };
    match proof {
        RefStateNonMembershipProof::EmptyState => false,
        RefStateNonMembershipProof::HeadOnly { head_target } => {
            ref_state_head_leaf_v2(head_target.as_ref())
                .is_ok_and(|leaf| root_envelope(&leaf, 1) == *root.bytes())
        }
        RefStateNonMembershipProof::BeforeFirst { first } => {
            first.proof().index() == 1
                && ref_name_order(name, first.name()) == Ordering::Less
                && holds(first)
        }
        RefStateNonMembershipProof::AfterLast { last } => {
            last.proof().index().checked_add(1) == Some(last.proof().leaf_count())
                && ref_name_order(last.name(), name) == Ordering::Less
                && holds(last)
        }
        RefStateNonMembershipProof::Between {
            predecessor,
            successor,
        } => {
            predecessor.proof().leaf_count() == successor.proof().leaf_count()
                && predecessor.proof().index().checked_add(1) == Some(successor.proof().index())
                && ref_name_order(predecessor.name(), name) == Ordering::Less
                && ref_name_order(name, successor.name()) == Ordering::Less
                && holds(predecessor)
                && holds(successor)
        }
    }
}
