//! Whole-image SQL operations. No new SQL or public enumeration capability is
//! added to AuthorityStore: this is explicitly an embedded operator boundary.
use super::super::{
    Cx, EngineError, ExportedBody, ExportedHead, ExportedIssuance, FsqliteAuthorityStore,
    HeadGeneration, HeadKey, HeadReadReceipt, IssuanceSequence, PortableStoreError, SCHEMA_VERSION,
    StoreInstanceId, add_bytes, blob, cap, live, mint_token, read_blob, read_unsigned, unsigned,
};
use super::{MultiHeadLimits, MultiHeadSnapshot};

#[derive(Clone, Copy)]
enum ImportMode {
    Fresh,
    Resume,
    Verify,
}

impl FsqliteAuthorityStore {
    /// Read all bodies, all heads and the full issuance ledger in ONE SQL
    /// snapshot under the existing cancellable operation lease. The ordinary
    /// single-head API remains unchanged and still refuses multiple heads.
    pub async fn export_multi_head_portable<Caps>(
        &self,
        cx: &Cx<Caps>,
        limits: MultiHeadLimits,
    ) -> Result<MultiHeadSnapshot, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        limits.validate()?;
        live(cx)?;
        let mut lease = self.operation(cx).await?;
        self.begin(cx, &mut lease).await?;
        match self.export_multi_head_snapshot(cx, limits).await {
            Ok(snapshot) => {
                self.connection
                    .rollback_transaction(cx)
                    .await
                    .map_err(|error| EngineError::from(&error))?;
                lease.finalized();
                live(cx)?;
                Ok(snapshot)
            }
            Err(cause) => Err(self.rollback_portable(cx, &mut lease, cause).await),
        }
    }

    async fn export_multi_head_snapshot<Caps>(
        &self,
        cx: &Cx<Caps>,
        limits: MultiHeadLimits,
    ) -> Result<MultiHeadSnapshot, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let mut total = 0;
        for (statement, maximum) in [
            (
                "portable.body_sizes",
                limits.portable.max_bodies.min(self.limits.immutable_slots),
            ),
            (
                "portable.issuance_sizes",
                limits.portable.max_issuance.min(self.limits.version_tokens),
            ),
            (
                "portable.head_sizes",
                limits.max_heads.min(self.limits.head_slots),
            ),
        ] {
            live(cx)?;
            let rows = self.query(cx, statement, &[]).await?;
            let row = rows.first().ok_or(EngineError::RowMissing { statement })?;
            if read_unsigned(row, 0).map_err(EngineError::from)? > maximum as u64 {
                return Err(PortableStoreError::Limit(statement));
            }
            add_bytes(
                &mut total,
                read_unsigned(row, 1).map_err(EngineError::from)?,
                limits.portable.max_field_bytes,
            )?;
            if read_unsigned(row, 2).map_err(EngineError::from)? > self.limits.body_bytes as u64 {
                return Err(PortableStoreError::Limit("authority body bytes"));
            }
        }
        // Preflight and all payload SELECTs are inside the caller's transaction.
        let mut snapshot = MultiHeadSnapshot {
            schema_version: SCHEMA_VERSION,
            instance: self.instance.raw(),
            bodies: Vec::new(),
            heads: Vec::new(),
            issuance: Vec::new(),
        };
        let rows = self.query(cx, "portable.bodies", &[]).await?;
        live(cx)?;
        snapshot
            .bodies
            .try_reserve_exact(rows.len())
            .map_err(|_| PortableStoreError::Allocation)?;
        for row in rows {
            live(cx)?;
            snapshot.bodies.push(ExportedBody {
                key: read_blob(&row, 0).map_err(EngineError::from)?.to_vec(),
                body: read_blob(&row, 1).map_err(EngineError::from)?.to_vec(),
            });
        }
        let rows = self.query(cx, "portable.issuance", &[]).await?;
        live(cx)?;
        snapshot
            .issuance
            .try_reserve_exact(rows.len())
            .map_err(|_| PortableStoreError::Allocation)?;
        for row in rows {
            live(cx)?;
            snapshot.issuance.push(ExportedIssuance {
                token: read_blob(&row, 0).map_err(EngineError::from)?.to_vec(),
                sequence: read_unsigned(&row, 1).map_err(EngineError::from)?,
                head_key: read_blob(&row, 2).map_err(EngineError::from)?.to_vec(),
                generation: read_unsigned(&row, 3).map_err(EngineError::from)?,
                body: read_blob(&row, 4).map_err(EngineError::from)?.to_vec(),
            });
        }
        let rows = self.query(cx, "portable.heads", &[]).await?;
        live(cx)?;
        snapshot
            .heads
            .try_reserve_exact(rows.len())
            .map_err(|_| PortableStoreError::Allocation)?;
        for row in rows {
            live(cx)?;
            snapshot.heads.push(ExportedHead {
                key: read_blob(&row, 0).map_err(EngineError::from)?.to_vec(),
                token: read_blob(&row, 1).map_err(EngineError::from)?.to_vec(),
                generation: read_unsigned(&row, 2).map_err(EngineError::from)?,
                body: read_blob(&row, 3).map_err(EngineError::from)?.to_vec(),
            });
        }
        snapshot.validate_with(limits, self.limits, || live(cx))?;
        Ok(snapshot)
    }

    /// Restore every head atomically into an empty destination with a distinct
    /// instance. Source tokens are reminted, never transplanted. Canonical body
    /// bytes and per-head generations survive. Provenance is caller-owned.
    pub async fn import_multi_head_portable<Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &MultiHeadSnapshot,
        limits: MultiHeadLimits,
    ) -> Result<Vec<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.reconcile_multi_head_import(cx, source, limits, ImportMode::Fresh)
            .await
    }

    /// An empty image can be imported; an exact committed retry returns the
    /// original receipts without another write. Any other occupied image refuses.
    pub async fn resume_multi_head_import<Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &MultiHeadSnapshot,
        limits: MultiHeadLimits,
    ) -> Result<Vec<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.reconcile_multi_head_import(cx, source, limits, ImportMode::Resume)
            .await
    }

    /// Verify the entire intended imported image in one read-only transaction.
    /// This never initializes an absent head or repairs an incomplete image.
    pub async fn verify_multi_head_import<Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &MultiHeadSnapshot,
        limits: MultiHeadLimits,
    ) -> Result<Vec<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.reconcile_multi_head_import(cx, source, limits, ImportMode::Verify)
            .await
    }

    async fn reconcile_multi_head_import<Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &MultiHeadSnapshot,
        limits: MultiHeadLimits,
        mode: ImportMode,
    ) -> Result<Vec<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        source.validate_with(limits, self.limits, || live(cx))?;
        if source.instance == self.instance.raw() {
            return Err(PortableStoreError::SameStoreInstance);
        }
        let mut lease = self.operation(cx).await?;
        self.begin(cx, &mut lease).await?;
        let prepared = async {
            let mut empty = true;
            for statement in ["body.count", "head.count", "issuance.count"] {
                live(cx)?;
                empty &= self.occupancy(cx, statement).await? == 0;
            }
            if matches!(mode, ImportMode::Fresh) && !empty {
                return Err(PortableStoreError::DestinationNotEmpty);
            }
            if empty && !matches!(mode, ImportMode::Verify) {
                return self
                    .import_multi_head_snapshot(cx, source)
                    .await
                    .map(|receipts| (receipts, true));
            }
            let actual = self.export_multi_head_snapshot(cx, limits).await?;
            match_image(source, &actual, self.instance, || live(cx))?;
            let receipts = receipts_for(source, self.instance, || live(cx))?;
            Ok((receipts, false))
        }
        .await;
        match prepared {
            Ok((receipts, true)) => {
                self.commit(cx, &mut lease)
                    .await
                    .map_err(PortableStoreError::Publication)?;
                // COMMIT is terminal. A subsequent cancellation cannot erase it.
                Ok(receipts)
            }
            Ok((receipts, false)) => {
                self.connection
                    .rollback_transaction(cx)
                    .await
                    .map_err(|error| EngineError::from(&error))?;
                lease.finalized();
                live(cx)?;
                Ok(receipts)
            }
            Err(cause) => Err(self.rollback_portable(cx, &mut lease, cause).await),
        }
    }

    /// Only the transaction/empty-destination gate above calls this staging
    /// function in production. All receipts are allocated before the first write.
    async fn import_multi_head_snapshot<Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &MultiHeadSnapshot,
    ) -> Result<Vec<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let receipts = receipts_for(source, self.instance, || live(cx))?;
        for row in &source.bodies {
            live(cx)?;
            if self
                .execute(cx, "body.put_if_absent", &[blob(&row.key), blob(&row.body)])
                .await?
                != 1
            {
                return Err(PortableStoreError::UnexpectedWriteCount("immutable body"));
            }
        }
        for row in &source.issuance {
            live(cx)?;
            let sequence = IssuanceSequence::new(row.sequence).map_err(EngineError::from)?;
            let key =
                HeadKey::new(row.head_key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
            let generation = HeadGeneration::try_new(row.generation)
                .map_err(|_| PortableStoreError::InvalidLineage)?;
            self.record_issuance(
                cx,
                mint_token(self.instance, sequence),
                sequence,
                &key,
                generation,
                &row.body,
            )
            .await?;
        }
        for receipt in &receipts {
            live(cx)?;
            let count = self
                .execute(
                    cx,
                    "head.create_if_absent",
                    &[
                        blob(receipt.key().as_bytes()),
                        blob(&receipt.token().to_opaque_bytes()),
                        unsigned(receipt.generation().get()).map_err(EngineError::from)?,
                        blob(receipt.body()),
                    ],
                )
                .await?;
            if count != 1 {
                return Err(PortableStoreError::UnexpectedWriteCount("head"));
            }
        }
        live(cx)?;
        Ok(receipts)
    }
}

fn receipts_for(
    source: &MultiHeadSnapshot,
    instance: StoreInstanceId,
    mut checkpoint: impl FnMut() -> Result<(), PortableStoreError>,
) -> Result<Vec<HeadReadReceipt>, PortableStoreError> {
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(source.heads.len())
        .map_err(|_| PortableStoreError::Allocation)?;
    for head in &source.heads {
        checkpoint()?;
        // Validated tokens encode the global sequence in their final 8 bytes.
        // That coordinate must be retained, not the head's ordinal or generation.
        let sequence: [u8; 8] = head
            .token
            .get(8..)
            .ok_or(PortableStoreError::InvalidSourceToken)?
            .try_into()
            .map_err(|_| PortableStoreError::InvalidSourceToken)?;
        let sequence =
            IssuanceSequence::new(u64::from_be_bytes(sequence)).map_err(EngineError::from)?;
        receipts.push(HeadReadReceipt::new(
            HeadKey::new(head.key.clone()).map_err(|_| PortableStoreError::InvalidKey)?,
            mint_token(instance, sequence),
            HeadGeneration::try_new(head.generation)
                .map_err(|_| PortableStoreError::InvalidLineage)?,
            head.body.clone(),
        ));
    }
    Ok(receipts)
}

fn match_image(
    source: &MultiHeadSnapshot,
    actual: &MultiHeadSnapshot,
    instance: StoreInstanceId,
    mut checkpoint: impl FnMut() -> Result<(), PortableStoreError>,
) -> Result<(), PortableStoreError> {
    let mismatch = || PortableStoreError::DestinationSnapshotMismatch;
    checkpoint()?;
    if actual.instance != instance.raw()
        || actual.schema_version != source.schema_version
        || actual.bodies.len() != source.bodies.len()
        || actual.heads.len() != source.heads.len()
        || actual.issuance.len() != source.issuance.len()
    {
        return Err(mismatch());
    }
    for (expected, observed) in source.bodies.iter().zip(&actual.bodies) {
        checkpoint()?;
        if expected != observed {
            return Err(mismatch());
        }
    }
    for (expected, observed) in source.issuance.iter().zip(&actual.issuance) {
        checkpoint()?;
        let sequence = IssuanceSequence::new(expected.sequence).map_err(EngineError::from)?;
        if expected.sequence != observed.sequence
            || expected.head_key != observed.head_key
            || expected.generation != observed.generation
            || expected.body != observed.body
            || observed.token.as_slice()
                != mint_token(instance, sequence).to_opaque_bytes().as_slice()
        {
            return Err(mismatch());
        }
    }
    // Both images validate, so their heads are already proven to equal each
    // slot's latest issuance. Comparing keys and the full ledger binds all heads.
    for (expected, observed) in source.heads.iter().zip(&actual.heads) {
        checkpoint()?;
        if expected.key != observed.key {
            return Err(mismatch());
        }
    }
    checkpoint()
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
