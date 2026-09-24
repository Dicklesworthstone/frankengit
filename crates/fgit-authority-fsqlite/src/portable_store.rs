//! Live single-head authority export and fresh-destination import.
//!
//! This is an embedded-store operation, not a repository backup profile:
//! Git object fabric, signing policy and routing are deliberately not claimed.
//! SQL snapshots and the existing operation lease bind every copied row to one
//! observation. Import remints the complete ledger under the destination's
//! own instance, so portable bytes do not transplant source CAS capabilities.

use super::operation::{OperationGate, OperationLease};
use super::{EngineError, FsqliteAuthorityStore};
use crate::marshal::{blob, read_blob, read_unsigned, unsigned};
use crate::schema::SCHEMA_VERSION;
use crate::{
    BundleRefusal, ExportBundle, ExportedBody, ExportedHead, ExportedIssuance, IssuanceSequence,
    MAX_EXPORT_BODIES, MAX_EXPORT_ISSUANCE, mint_token,
};
use fgit_authority::{
    AuthorityLimits, HeadGeneration, HeadKey, HeadReadReceipt, ImmutableKey, StoreInstanceId,
};
use fsqlite_types::cx::{Cx, cap};

/// Limits apply to variable-length field bytes, not compressed or physical I/O.
/// Row counts independently bound Vec/SQL-row overhead. The complete result is
/// refused rather than truncated. The caller's context also bounds all work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableStoreLimits {
    pub max_bodies: usize,
    pub max_issuance: usize,
    pub max_field_bytes: u64,
}
impl Default for PortableStoreLimits {
    fn default() -> Self {
        Self {
            max_bodies: 100_000,
            max_issuance: 100_000,
            max_field_bytes: 64 * 1024 * 1024,
        }
    }
}
impl PortableStoreLimits {
    const fn validate(self) -> Result<(), PortableStoreError> {
        if self.max_bodies > MAX_EXPORT_BODIES
            || self.max_issuance > MAX_EXPORT_ISSUANCE
            || self.max_field_bytes == 0
            || self.max_field_bytes > 1024 * 1024 * 1024
        {
            return Err(PortableStoreError::InvalidLimits);
        }
        Ok(())
    }
}

/// No error after a publication attempt proves that the commit did not occur.
/// A failed rollback keeps the existing operation gate quarantined until a
/// later live caller drains/finalizes the same connection.
#[derive(Debug)]
pub enum PortableStoreError {
    InvalidLimits,
    Limit(&'static str),
    Bundle(Box<BundleRefusal>),
    InvalidKey,
    InvalidSourceToken,
    InvalidLineage,
    MultipleHeads,
    SameStoreInstance,
    DestinationNotEmpty,
    /// An occupied resume target is not the exact intended imported image.
    DestinationSnapshotMismatch,
    Allocation,
    Engine(EngineError),
    Publication(EngineError),
    UnexpectedWriteCount(&'static str),
    Cleanup {
        cause: Box<Self>,
        cleanup: EngineError,
    },
}
impl std::fmt::Display for PortableStoreError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => out.write_str("invalid portable-store limits"),
            Self::Limit(name) => write!(out, "portable-store limit exceeded: {name}"),
            Self::Bundle(error) => write!(out, "invalid portable bundle: {error}"),
            Self::InvalidKey => out.write_str("portable bundle contains an invalid authority key"),
            Self::InvalidSourceToken => {
                out.write_str("portable token disagrees with its source instance and sequence")
            }
            Self::InvalidLineage => out.write_str(
                "portable head history is not the latest monotonically issued state for each slot",
            ),
            Self::MultipleHeads => out.write_str(
                "the portable format represents one head; multi-head export is unsupported",
            ),
            Self::SameStoreInstance => {
                out.write_str("portable import requires a distinct destination store instance")
            }
            Self::DestinationNotEmpty => {
                out.write_str("portable import requires an empty destination authority store")
            }
            Self::DestinationSnapshotMismatch => out.write_str(
                "portable resume destination does not match the complete imported snapshot",
            ),
            Self::Allocation => out.write_str("bounded portable-store allocation failed"),
            Self::Engine(error) => write!(out, "portable-store engine operation failed: {error}"),
            Self::Publication(error) => write!(
                out,
                "portable import commit was not confirmed; outcome unknown: {error}"
            ),
            Self::UnexpectedWriteCount(name) => {
                write!(out, "portable import did not exclusively insert {name}")
            }
            Self::Cleanup { cause, cleanup } => {
                write!(out, "{cause}; snapshot rollback also failed: {cleanup}")
            }
        }
    }
}
impl std::error::Error for PortableStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bundle(error) => Some(error.as_ref()),
            Self::Engine(error) | Self::Publication(error) => Some(error),
            Self::Cleanup { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}
impl From<EngineError> for PortableStoreError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

fn live<Caps>(cx: &Cx<Caps>) -> Result<(), PortableStoreError>
where
    Caps: cap::SubsetOf<cap::All>,
    cap::None: cap::SubsetOf<Caps>,
{
    cx.checkpoint().map_err(|_| {
        PortableStoreError::Engine(EngineError::Engine(crate::TransientClass::Cancelled))
    })
}
fn add_bytes(total: &mut u64, amount: u64, maximum: u64) -> Result<(), PortableStoreError> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or(PortableStoreError::Limit("retained field bytes"))?;
    Ok(())
}
const fn check_body(body: &[u8], limits: AuthorityLimits) -> Result<(), PortableStoreError> {
    if body.len() > limits.body_bytes {
        return Err(PortableStoreError::Limit("authority body bytes"));
    }
    Ok(())
}

/// The existing wire format's validation is necessary, but a live store has
/// stronger invariants: its tokens must actually be mintable here and its one
/// head cannot silently roll back to an older otherwise valid issuance row.
fn validate_bundle(
    bundle: &ExportBundle,
    limits: PortableStoreLimits,
    store: AuthorityLimits,
    mut checkpoint: impl FnMut() -> Result<(), PortableStoreError>,
) -> Result<(), PortableStoreError> {
    limits.validate()?;
    checkpoint()?;
    if bundle.instance > i64::MAX as u64 {
        return Err(PortableStoreError::InvalidSourceToken);
    }
    if bundle.bodies.len() > limits.max_bodies || bundle.bodies.len() > store.immutable_slots {
        return Err(PortableStoreError::Limit("immutable bodies"));
    }
    if bundle.issuance.len() > limits.max_issuance || bundle.issuance.len() > store.version_tokens {
        return Err(PortableStoreError::Limit("issuance rows"));
    }
    if usize::from(bundle.head.is_some()) > store.head_slots {
        return Err(PortableStoreError::Limit("head slots"));
    }
    // Enforce byte limits before the portable validator's comparisons. Every
    // collection walk checkpoints; a huge repeated payload cannot evade work
    // accounting by being a byte-identical retry.
    let mut total = 0;
    for item in &bundle.bodies {
        checkpoint()?;
        add_bytes(&mut total, item.key.len() as u64, limits.max_field_bytes)?;
        add_bytes(&mut total, item.body.len() as u64, limits.max_field_bytes)?;
        ImmutableKey::new(item.key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
        check_body(&item.body, store)?;
    }
    let mut previous_generation = 0;
    for (ordinal, row) in bundle.issuance.iter().enumerate() {
        checkpoint()?;
        if row.sequence != ordinal as u64 + 1 {
            return Err(PortableStoreError::InvalidLineage);
        }
        for bytes in [&row.token, &row.head_key, &row.body] {
            add_bytes(&mut total, bytes.len() as u64, limits.max_field_bytes)?;
        }
        if row.generation > i64::MAX as u64 {
            return Err(PortableStoreError::InvalidLineage);
        }
        let sequence = IssuanceSequence::new(row.sequence)
            .map_err(|_| PortableStoreError::InvalidSourceToken)?;
        let expected = mint_token(StoreInstanceId::from_raw(bundle.instance), sequence);
        if row.token.as_slice() != expected.to_opaque_bytes().as_slice() {
            return Err(PortableStoreError::InvalidSourceToken);
        }
        let head = bundle
            .head
            .as_ref()
            .ok_or(PortableStoreError::InvalidLineage)?;
        if row.head_key != head.key || row.generation <= previous_generation {
            return Err(PortableStoreError::InvalidLineage);
        }
        previous_generation = row.generation;
        check_body(&row.body, store)?;
    }
    if let Some(head) = &bundle.head {
        checkpoint()?;
        for bytes in [&head.key, &head.token, &head.body] {
            add_bytes(&mut total, bytes.len() as u64, limits.max_field_bytes)?;
        }
        HeadKey::new(head.key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
        check_body(&head.body, store)?;
        let tail = bundle
            .issuance
            .last()
            .ok_or(PortableStoreError::InvalidLineage)?;
        if tail.token != head.token || tail.generation != head.generation || tail.body != head.body
        {
            return Err(PortableStoreError::InvalidLineage);
        }
    }
    bundle
        .validate()
        .map_err(|error| PortableStoreError::Bundle(Box::new(error)))?;
    checkpoint()
}

impl FsqliteAuthorityStore {
    /// Open a pre-existing portable source without executing DDL or creating
    /// an identity row. The local operator supplies a stable existing database
    /// path; this does not turn arbitrary SQLite data into an authority store.
    /// Source provenance and filesystem-path authorization remain caller-owned.
    pub async fn open_portable_source<Caps>(
        cx: &Cx<Caps>,
        path: impl Into<String>,
        limits: AuthorityLimits,
    ) -> Result<Self, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        live(cx)?;
        let connection = fsqlite::AsyncConnection::open(cx, path)
            .await
            .map_err(|error| EngineError::from(&error))?;
        let mut store = Self {
            connection,
            operations: OperationGate::new(),
            instance: StoreInstanceId::from_raw(0),
            limits,
        };
        let identity = async {
            live(cx)?;
            let rows = store.query(cx, "identity.read", &[]).await?;
            if rows.len() != 1 {
                return Err(PortableStoreError::InvalidLineage);
            }
            let recorded = read_unsigned(&rows[0], 0).map_err(EngineError::from)?;
            let version = read_unsigned(&rows[0], 1).map_err(EngineError::from)?;
            let found = i64::try_from(version).unwrap_or(i64::MAX);
            if found != SCHEMA_VERSION {
                return Err(EngineError::SchemaVersionMismatch {
                    found,
                    expected: SCHEMA_VERSION,
                }
                .into());
            }
            live(cx)?;
            Ok(StoreInstanceId::from_raw(recorded))
        }
        .await;
        match identity {
            Ok(instance) => {
                store.instance = instance;
                Ok(store)
            }
            Err(cause) => match store.close(cx).await {
                Ok(()) => Err(cause),
                Err(cleanup) => Err(PortableStoreError::Cleanup {
                    cause: Box::new(cause),
                    cleanup,
                }),
            },
        }
    }

    /// Capture every immutable body, the one published head and its full
    /// issuance ledger in one SQL snapshot. Multi-head stores fail explicitly;
    /// this method does not silently select one head from an unordered set.
    ///
    /// This is the existing ExportBundle format, not a complete repository
    /// backup: it does not contain Git fabric bytes, signatures or routing.
    /// Concurrent writers cannot split its head, outcome bodies and ledger.
    pub async fn export_portable<Caps>(
        &self,
        cx: &Cx<Caps>,
        limits: PortableStoreLimits,
    ) -> Result<ExportBundle, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        limits.validate()?;
        live(cx)?;
        let mut lease = self.operation(cx).await?;
        self.begin(cx, &mut lease).await?;
        let result = self.export_portable_snapshot(cx, limits).await;
        // Read-only transactions are closed by rollback; no canonical mutation
        // or token issuance is needed to obtain a backup observation.
        match result {
            Ok(bundle) => {
                self.connection
                    .rollback_transaction(cx)
                    .await
                    .map_err(|error| PortableStoreError::Engine(EngineError::from(&error)))?;
                lease.finalized();
                live(cx)?;
                Ok(bundle)
            }
            Err(cause) => Err(self.rollback_portable(cx, &mut lease, cause).await),
        }
    }

    async fn export_portable_snapshot<Caps>(
        &self,
        cx: &Cx<Caps>,
        limits: PortableStoreLimits,
    ) -> Result<ExportBundle, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // COUNT and byte-length sums do not materialize all payload columns.
        // They run inside the SAME snapshot as the following SELECTs, fencing
        // allocations even if another connection publishes concurrently.
        let mut total = 0;
        for (name, maximum) in [
            (
                "portable.body_sizes",
                limits.max_bodies.min(self.limits.immutable_slots),
            ),
            (
                "portable.issuance_sizes",
                limits.max_issuance.min(self.limits.version_tokens),
            ),
            ("portable.head_sizes", self.limits.head_slots.min(1)),
        ] {
            live(cx)?;
            let rows = self.query(cx, name, &[]).await?;
            let row = rows
                .first()
                .ok_or(EngineError::RowMissing { statement: name })?;
            let count = read_unsigned(row, 0).map_err(EngineError::from)?;
            if name == "portable.head_sizes" && count > 1 {
                return Err(PortableStoreError::MultipleHeads);
            }
            if count > maximum as u64 {
                return Err(PortableStoreError::Limit(name));
            }
            add_bytes(
                &mut total,
                read_unsigned(row, 1).map_err(EngineError::from)?,
                limits.max_field_bytes,
            )?;
            if read_unsigned(row, 2).map_err(EngineError::from)? > self.limits.body_bytes as u64 {
                return Err(PortableStoreError::Limit("authority body bytes"));
            }
        }
        let mut bundle = ExportBundle {
            schema_version: SCHEMA_VERSION,
            instance: self.instance.raw(),
            bodies: Vec::new(),
            head: None,
            issuance: Vec::new(),
        };
        let rows = self.query(cx, "portable.bodies", &[]).await?;
        live(cx)?;
        bundle
            .bodies
            .try_reserve_exact(rows.len())
            .map_err(|_| PortableStoreError::Allocation)?;
        for row in rows {
            live(cx)?;
            bundle.bodies.push(ExportedBody {
                key: read_blob(&row, 0).map_err(EngineError::from)?.to_vec(),
                body: read_blob(&row, 1).map_err(EngineError::from)?.to_vec(),
            });
        }
        let rows = self.query(cx, "portable.issuance", &[]).await?;
        live(cx)?;
        bundle
            .issuance
            .try_reserve_exact(rows.len())
            .map_err(|_| PortableStoreError::Allocation)?;
        for row in rows {
            live(cx)?;
            bundle.issuance.push(ExportedIssuance {
                token: read_blob(&row, 0).map_err(EngineError::from)?.to_vec(),
                sequence: read_unsigned(&row, 1).map_err(EngineError::from)?,
                head_key: read_blob(&row, 2).map_err(EngineError::from)?.to_vec(),
                generation: read_unsigned(&row, 3).map_err(EngineError::from)?,
                body: read_blob(&row, 4).map_err(EngineError::from)?.to_vec(),
            });
        }
        let rows = self.query(cx, "portable.heads", &[]).await?;
        live(cx)?;
        if rows.len() > 1 {
            return Err(PortableStoreError::MultipleHeads);
        }
        if let Some(row) = rows.first() {
            bundle.head = Some(ExportedHead {
                key: read_blob(row, 0).map_err(EngineError::from)?.to_vec(),
                token: read_blob(row, 1).map_err(EngineError::from)?.to_vec(),
                generation: read_unsigned(row, 2).map_err(EngineError::from)?,
                body: read_blob(row, 3).map_err(EngineError::from)?.to_vec(),
            });
        }
        validate_bundle(&bundle, limits, self.limits, || live(cx))?;
        Ok(bundle)
    }

    /// Import a validated snapshot into an EMPTY store with a distinct instance.
    /// Bodies, reminted issuance ledger and head commit in one SQL transaction.
    /// This cannot overwrite, repair or roll back an existing authority store.
    ///
    /// Canonical keys/body bytes and head generations are preserved. Backend
    /// capabilities are not: every token is reminted under this destination's
    /// identity. An uncertain commit must be inspected using read_head and
    /// export_portable; blindly retrying is not evidence that nothing committed.
    /// Caller authenticates the backup's provenance before invoking this method;
    /// internal consistency alone is neither a signature nor source trust.
    pub async fn import_portable<Caps>(
        &self,
        cx: &Cx<Caps>,
        bundle: &ExportBundle,
        limits: PortableStoreLimits,
    ) -> Result<Option<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        validate_bundle(bundle, limits, self.limits, || live(cx))?;
        if bundle.instance == self.instance.raw() {
            return Err(PortableStoreError::SameStoreInstance);
        }
        let mut lease = self.operation(cx).await?;
        self.begin(cx, &mut lease).await?;
        match self.import_portable_snapshot(cx, bundle).await {
            Ok(receipt) => {
                // Do not poll cancellation after confirmed COMMIT and erase an
                // already established terminal result. The receipt must survive.
                self.commit(cx, &mut lease)
                    .await
                    .map_err(PortableStoreError::Publication)?;
                Ok(receipt)
            }
            Err(cause) => Err(self.rollback_portable(cx, &mut lease, cause).await),
        }
    }

    async fn import_portable_snapshot<Caps>(
        &self,
        cx: &Cx<Caps>,
        bundle: &ExportBundle,
    ) -> Result<Option<HeadReadReceipt>, PortableStoreError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        for name in ["body.count", "head.count", "issuance.count"] {
            live(cx)?;
            if self.occupancy(cx, name).await? != 0 {
                return Err(PortableStoreError::DestinationNotEmpty);
            }
        }
        for item in &bundle.bodies {
            live(cx)?;
            let count = self
                .execute(
                    cx,
                    "body.put_if_absent",
                    &[blob(&item.key), blob(&item.body)],
                )
                .await?;
            if count != 1 {
                return Err(PortableStoreError::UnexpectedWriteCount("immutable body"));
            }
        }
        for row in &bundle.issuance {
            live(cx)?;
            let sequence = IssuanceSequence::new(row.sequence).map_err(EngineError::from)?;
            let token = mint_token(self.instance, sequence);
            let key =
                HeadKey::new(row.head_key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
            let generation = HeadGeneration::try_new(row.generation)
                .map_err(|_| PortableStoreError::InvalidLineage)?;
            self.record_issuance(cx, token, sequence, &key, generation, &row.body)
                .await?;
        }
        live(cx)?;
        let Some(head) = &bundle.head else {
            return Ok(None);
        };
        let tail = bundle
            .issuance
            .last()
            .ok_or(PortableStoreError::InvalidLineage)?;
        let token = mint_token(
            self.instance,
            IssuanceSequence::new(tail.sequence).map_err(EngineError::from)?,
        );
        let generation = HeadGeneration::try_new(head.generation)
            .map_err(|_| PortableStoreError::InvalidLineage)?;
        let key = HeadKey::new(head.key.clone()).map_err(|_| PortableStoreError::InvalidKey)?;
        let count = self
            .execute(
                cx,
                "head.create_if_absent",
                &[
                    blob(&head.key),
                    blob(&token.to_opaque_bytes()),
                    unsigned(head.generation).map_err(EngineError::from)?,
                    blob(&head.body),
                ],
            )
            .await?;
        if count != 1 {
            return Err(PortableStoreError::UnexpectedWriteCount("head"));
        }
        live(cx)?;
        Ok(Some(HeadReadReceipt::new(
            key,
            token,
            generation,
            head.body.clone(),
        )))
    }

    async fn rollback_portable<Caps>(
        &self,
        cx: &Cx<Caps>,
        lease: &mut OperationLease,
        cause: PortableStoreError,
    ) -> PortableStoreError
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        match self.connection.rollback_transaction(cx).await {
            Ok(()) => {
                lease.finalized();
                cause
            }
            Err(error) => PortableStoreError::Cleanup {
                cause: Box::new(cause),
                cleanup: EngineError::from(&error),
            },
        }
    }
}

#[path = "portable_store/resume.rs"]
mod resume;

#[path = "portable_store/multihead.rs"]
pub mod multihead;

#[cfg(test)]
// Explicit path: rustfmt resolves out-of-line children of `#[path]`-attributed
// modules against the parent directory, not the derived `portable_store/` dir,
// and aborts workspace formatting hunting for `src/tests.rs`.
#[path = "portable_store/tests.rs"]
mod tests;
