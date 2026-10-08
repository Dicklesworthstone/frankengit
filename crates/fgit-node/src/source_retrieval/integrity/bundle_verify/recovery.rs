//! Native, read-only preparation of a disposable bare Git recovery layout.
//! The complete bundle is validated once. Original pack bytes are preserved;
//! index locations come from that same resolver, never from an imported index.
use std::collections::BTreeSet;
use std::fmt;

use fgit_pack::build_pack_index_v2;
use fgit_types::{GitHashAlgorithm, RefName};

use super::{
    BundleExpectations, BundleVerifyError, BundleVerifyLimits, VerifiedGitBundle, checkpoint,
    verify_git_bundle_with_locations,
};

#[derive(Debug)]
pub enum BundleRecoveryError {
    Verification(BundleVerifyError),
    Index(fgit_pack::PackError),
    HeadNotBranch,
    HeadNotAdvertised,
    OverlappingRefs,
    MetadataLimit,
}
impl fmt::Display for BundleRecoveryError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(error) => fmt::Display::fmt(error, out),
            Self::Index(error) => write!(out, "bundle_recovery_index: {error}"),
            Self::HeadNotBranch => out.write_str("recovery_head_not_branch"),
            Self::HeadNotAdvertised => out.write_str("recovery_head_not_advertised"),
            Self::OverlappingRefs => out.write_str("overlapping_recovery_refs"),
            Self::MetadataLimit => out.write_str("recovery_metadata_limit"),
        }
    }
}
impl std::error::Error for BundleRecoveryError {}
impl From<BundleVerifyError> for BundleRecoveryError {
    fn from(error: BundleVerifyError) -> Self { Self::Verification(error) }
}

/// Only native verification can construct this plan. It performs no I/O and
/// grants no authority. The owner must stage/sync/read back every body and
/// publish HEAD last into a new or exactly identified recovery directory.
/// Ref names are contents of packed-refs/HEAD, never host filesystem paths.
#[derive(Debug)]
pub struct GitBundleRecovery<'a> {
    verified: VerifiedGitBundle,
    pack: &'a [u8],
    pack_offset: usize,
    head_ref: RefName,
    index: Vec<u8>,
    packed_refs: Vec<u8>,
    config: Vec<u8>,
    head: Vec<u8>,
}
impl GitBundleRecovery<'_> {
    #[must_use]
    pub const fn verified(&self) -> &VerifiedGitBundle { &self.verified }
    #[must_use]
    pub const fn pack_offset(&self) -> usize { self.pack_offset }
    #[must_use]
    pub const fn pack(&self) -> &[u8] { self.pack }
    #[must_use]
    pub const fn head_ref(&self) -> &RefName { &self.head_ref }
    #[must_use]
    pub fn index(&self) -> &[u8] { &self.index }
    #[must_use]
    pub fn packed_refs(&self) -> &[u8] { &self.packed_refs }
    #[must_use]
    pub fn config(&self) -> &[u8] { &self.config }
    #[must_use]
    pub fn head(&self) -> &[u8] { &self.head }
}

/// Validate all included objects and graph edges, check any independent pins,
/// and build an idx-v2 plus safe bare-repository metadata. The caller explicitly
/// selects an advertised branch. Prefix-overlapping ref namespaces refuse.
/// Source signatures, currentness, gitlink targets, forge and authority state
/// remain outside this content-only recovery boundary.
pub fn prepare_git_bundle_recovery<'a>(
    input: &'a [u8],
    limits: &BundleVerifyLimits,
    expected: Option<&BundleExpectations>,
    head_ref: &RefName,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<GitBundleRecovery<'a>, BundleRecoveryError> {
    let mut stopped = false;
    let mut live = || {
        if !stopped && !allow_work() { stopped = true; }
        !stopped
    };
    checkpoint(&mut live)?;
    if !head_ref.as_bytes().starts_with(b"refs/heads/") {
        return Err(BundleRecoveryError::HeadNotBranch);
    }
    let mut locations = Vec::new();
    let verified = verify_git_bundle_with_locations(input, limits, expected, Some(&mut locations), &mut live)?;
    if !verified.references().contains_key(head_ref) {
        return Err(BundleRecoveryError::HeadNotAdvertised);
    }
    let names: BTreeSet<&[u8]> = verified.references().keys().map(RefName::as_bytes).collect();
    for name in &names {
        checkpoint(&mut live)?;
        for (at, byte) in name.iter().enumerate() {
            if *byte == b'/' && names.contains(&name[..at]) {
                return Err(BundleRecoveryError::OverlappingRefs);
            }
        }
    }
    let pack_offset = input.len().checked_sub(verified.pack_bytes())
        .ok_or(BundleRecoveryError::MetadataLimit)?;
    let pack = &input[pack_offset..];
    let index = build_pack_index_v2(pack, verified.format(), &locations, &limits.pack, &mut live)
        .map_err(BundleRecoveryError::Index)?;
    let maximum = limits.envelope.max_header_bytes.checked_add(64)
        .ok_or(BundleRecoveryError::MetadataLimit)?;
    let mut packed_refs = Vec::new();
    append(&mut packed_refs, b"# pack-refs with: sorted\n", maximum)?;
    // Explicit byte ordering is the packed-refs sorted contract, independent of
    // any future change to the typed RefName's internal ordering.
    for name in names {
        checkpoint(&mut live)?;
        let reference = RefName::try_new(name).map_err(|_| BundleRecoveryError::MetadataLimit)?;
        let id = verified.references().get(&reference).ok_or(BundleRecoveryError::MetadataLimit)?;
        append(&mut packed_refs, fgit_crypto::lowercase_hex(id.as_bytes()).as_bytes(), maximum)?;
        append(&mut packed_refs, b" ", maximum)?;
        append(&mut packed_refs, name, maximum)?;
        append(&mut packed_refs, b"\n", maximum)?;
    }
    let config = match verified.format() {
        GitHashAlgorithm::Sha1 => b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n".as_slice(),
        GitHashAlgorithm::Sha256 => b"[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectformat = sha256\n".as_slice(),
    };
    let mut head = Vec::new();
    append(&mut head, b"ref: ", maximum)?;
    append(&mut head, head_ref.as_bytes(), maximum)?;
    append(&mut head, b"\n", maximum)?;
    let mut owned_config = Vec::new();
    append(&mut owned_config, config, maximum)?;
    checkpoint(&mut live)?;
    Ok(GitBundleRecovery { verified, pack, pack_offset, head_ref: head_ref.clone(), index,
        packed_refs, config: owned_config, head })
}

fn append(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), BundleRecoveryError> {
    if output.len().checked_add(bytes.len()).is_none_or(|n| n > maximum) {
        return Err(BundleRecoveryError::MetadataLimit);
    }
    output.try_reserve(bytes.len()).map_err(|_| BundleRecoveryError::MetadataLimit)?;
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests;
