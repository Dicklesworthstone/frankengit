//! Bind a donor's exact canonical head to this export's authenticated capture.
//! Generation ordering alone, or a second read of a newer current head, cannot
//! authorize mixing an older donor with the captured authority image.

use fgit_authority::{
    AsyncAuthorityStore, AuthorityHeadAncestryReceipt, HeadReadReceipt, authority_head_identity,
    read_current_authority_head_descendant_async,
};
use fgit_codec::{DecodeLimits, RepositoryAuthorityHeadBody, decode_body};
use fgit_types::RepositoryId;

#[derive(Clone, Copy)]
pub(super) struct DonorHead<'a> {
    pub key: &'a [u8],
    pub generation: u64,
    pub body: &'a [u8],
}

/// The donor body comes from a fully verified, independently pinned archive.
/// This establishes only exact ancestry/currentness, never payload authenticity
/// by native OID alone. The archive's original strong commitments remain needed.
pub(super) async fn authenticate<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    captured: &HeadReadReceipt,
    repository: RepositoryId,
    donor: DonorHead<'_>,
    max_hops: usize,
    mut live: impl FnMut() -> Result<(), String>,
) -> Result<AuthorityHeadAncestryReceipt, String> {
    live()?;
    if donor.key != captured.key().as_bytes() {
        return Err("donor backup authority head slot differs from current source".into());
    }
    let body: RepositoryAuthorityHeadBody =
        decode_body(donor.body, DecodeLimits::DEFAULT).map_err(|error| error.to_string())?;
    if body.repository_id != repository || body.generation.get() != donor.generation {
        return Err("donor backup head repository or generation mismatch".into());
    }
    let ancestor = authority_head_identity(&body).map_err(|error| error.to_string())?;
    live()?;
    let descendant = read_current_authority_head_descendant_async(
        store,
        cx,
        captured.key(),
        repository,
        ancestor,
        body.generation,
        max_hops,
    )
    .await
    .map_err(|error| format!("donor backup ancestry refused: {error}"))?;
    live()?;
    if descendant.authenticated().receipt() != captured {
        return Err("source head moved during donor ancestry verification".into());
    }
    Ok(descendant.ancestry())
}

#[cfg(test)]
#[path = "ancestry/tests.rs"]
mod tests;
