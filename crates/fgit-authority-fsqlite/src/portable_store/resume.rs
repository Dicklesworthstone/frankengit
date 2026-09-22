//! Reconcile an interrupted portable import against its complete intended image.
//! A matching head alone is insufficient: bodies and the entire reminted ledger
//! must match in one SQL snapshot. Nothing is appended to a nonempty image.

use super::{
    EngineError, ExportBundle, FsqliteAuthorityStore, HeadGeneration, HeadKey,
    HeadReadReceipt, IssuanceSequence, PortableStoreError, PortableStoreLimits,
    StoreInstanceId, cap, Cx, live, mint_token, validate_bundle,
};
use fgit_authority::AuthorityVersionToken;

impl FsqliteAuthorityStore {
    /// Finish an import that either rolled back completely or committed exactly
    /// the supplied snapshot. An exact retry returns the original destination
    /// receipt without minting a token or writing a row. Any other occupied
    /// destination, including a later head or an extra immutable body, refuses.
    ///
    /// Source provenance and the intended destination instance are caller-owned.
    /// This is not permission to merge, repair, or rewind existing authority.
    /// All comparisons and any fresh import share the existing operation lease
    /// and a SQL transaction. A failed COMMIT remains an unknown publication;
    /// retry this method with the same source and destination, not a new identity.
    pub async fn resume_portable_import<Caps>(
        &self, cx: &Cx<Caps>, source: &ExportBundle, limits: PortableStoreLimits,
    ) -> Result<Option<HeadReadReceipt>, PortableStoreError>
    where Caps: cap::SubsetOf<cap::All>, cap::None: cap::SubsetOf<Caps>,
    {
        self.reconcile_portable_import(cx, source, limits, true).await
    }

    /// Read-only counterpart for an already published restored image. An empty
    /// or changed store is NOT initialized. The receipt authenticates only the
    /// exact observed image; callers still revalidate it before publication.
    pub async fn verify_portable_import<Caps>(
        &self, cx: &Cx<Caps>, source: &ExportBundle, limits: PortableStoreLimits,
    ) -> Result<Option<HeadReadReceipt>, PortableStoreError>
    where Caps: cap::SubsetOf<cap::All>, cap::None: cap::SubsetOf<Caps>,
    {
        self.reconcile_portable_import(cx, source, limits, false).await
    }

    async fn reconcile_portable_import<Caps>(
        &self, cx: &Cx<Caps>, source: &ExportBundle, limits: PortableStoreLimits,
        admit_empty: bool,
    ) -> Result<Option<HeadReadReceipt>, PortableStoreError>
    where Caps: cap::SubsetOf<cap::All>, cap::None: cap::SubsetOf<Caps>,
    {
        validate_bundle(source, limits, self.limits, || live(cx))?;
        if source.instance == self.instance.raw() {
            return Err(PortableStoreError::SameStoreInstance);
        }
        let mut lease = self.operation(cx).await?;
        self.begin(cx, &mut lease).await?;
        let inspected = async {
            let observed = self.export_portable_snapshot(cx, limits).await?;
            live(cx)?;
            let empty = observed.bodies.is_empty() && observed.issuance.is_empty()
                && observed.head.is_none();
            if empty && admit_empty {
                let receipt = self.import_portable_snapshot(cx, source).await?;
                return Ok((receipt, true));
            }
            let receipt = match_image(source, &observed, self.instance, || live(cx))?;
            Ok((receipt, false))
        }.await;
        match inspected {
            Ok((receipt, true)) => {
                self.commit(cx, &mut lease).await.map_err(PortableStoreError::Publication)?;
                // A confirmed commit survives cancellation arriving afterward.
                Ok(receipt)
            }
            Ok((receipt, false)) => {
                self.connection.rollback_transaction(cx).await
                    .map_err(|error| PortableStoreError::Engine(EngineError::from(&error)))?;
                lease.finalized();
                live(cx)?;
                Ok(receipt)
            }
            Err(cause) => Err(self.rollback_portable(cx, &mut lease, cause).await),
        }
    }
}

/// Both images have passed the live portable validator. Compare without cloning
/// another metadata-sized bundle; each bounded row comparison checkpoints.
fn match_image(
    source: &ExportBundle, observed: &ExportBundle, instance: StoreInstanceId,
    mut checkpoint: impl FnMut() -> Result<(), PortableStoreError>,
) -> Result<Option<HeadReadReceipt>, PortableStoreError> {
    let mismatch = || PortableStoreError::DestinationSnapshotMismatch;
    checkpoint()?;
    if observed.instance != instance.raw() || observed.schema_version != source.schema_version
        || observed.bodies.len() != source.bodies.len()
        || observed.issuance.len() != source.issuance.len()
    { return Err(mismatch()); }
    for (expected, actual) in source.bodies.iter().zip(&observed.bodies) {
        checkpoint()?;
        if expected != actual { return Err(mismatch()); }
    }
    for (expected, actual) in source.issuance.iter().zip(&observed.issuance) {
        checkpoint()?;
        let sequence = IssuanceSequence::new(expected.sequence).map_err(EngineError::from)?;
        if actual.sequence != expected.sequence || actual.head_key != expected.head_key
            || actual.generation != expected.generation || actual.body != expected.body
            || actual.token.as_slice() != mint_token(instance, sequence).to_opaque_bytes().as_slice()
        { return Err(mismatch()); }
    }
    checkpoint()?;
    match (&source.head, &observed.head) {
        (None, None) => Ok(None),
        (Some(expected), Some(actual)) => {
            let tail = source.issuance.last().ok_or_else(mismatch)?;
            let sequence = IssuanceSequence::new(tail.sequence).map_err(EngineError::from)?;
            if actual.key != expected.key || actual.body != expected.body
                || actual.generation != expected.generation
                || actual.token.as_slice() != mint_token(instance, sequence).to_opaque_bytes().as_slice()
            { return Err(mismatch()); }
            let token = AuthorityVersionToken::from_opaque_bytes(
                actual.token.as_slice().try_into().map_err(|_| mismatch())?);
            let key = HeadKey::new(actual.key.clone()).map_err(|_| mismatch())?;
            let generation = HeadGeneration::try_new(actual.generation).map_err(|_| mismatch())?;
            Ok(Some(HeadReadReceipt::new(key, token, generation, actual.body.clone())))
        }
        _ => Err(mismatch()),
    }
}

#[cfg(test)]
mod tests;
