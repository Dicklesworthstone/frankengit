//! The `AsyncConnection`-owning binding that executes the statement set.
//!
//! This is the half of the profile that touches the engine. Everything it does
//! is expressed in terms of the closed statement set in [`crate::schema`]: an
//! operation looks its SQL up by name and binds parameters, so a statement that
//! is not in the set cannot be executed at all. That is a stronger guarantee
//! than "we intended to parameterize everything", because it is checked on
//! every call rather than reviewed once.
//!
//! # Why the operations are async and the contract is not
//!
//! [`fgit_authority::AuthorityStore`] is synchronous: it is the semantic
//! contract, and a linearizability checker needs to call it without a runtime.
//! The engine is asynchronous: `Connection` is `!Send`, so `fsqlite` owns it on
//! a dedicated worker thread and every operation is a round trip through a
//! command channel.
//!
//! The two are bridged by a blocking adapter that lives in this crate's *test*
//! tree, not here. That placement is deliberate and it bounds a claim: a
//! `block_on`-per-operation bridge cannot model cancellation arriving during an
//! operation, so passing the FG-004 conformance suite through it shows that the
//! binding implements the contract's semantics under a synchronous harness —
//! not that the binding is conformant under cancellation. Keeping the bridge
//! out of `src` keeps that distinction structural instead of a footnote. The
//! methods here are the real binding; they take a `&Cx` and they await.
//!
//! # Where the runtime enters, verified rather than assumed
//!
//! `fsqlite`'s async entry points resolve a native asupersync context via
//! `cx.attached_native_cx().or_else(NativeCx::current)` and fail with a
//! "requires runtime" error when neither exists. So these operations do not
//! merely *prefer* the sanctioned runtime, they cannot run without it, which is
//! what §3.3 asks for and is worth stating because it is checkable rather than
//! promised.
//!
//! # The clock this module does not own
//!
//! The retry driver takes its wait as a parameter, exactly as the synchronous
//! [`crate::retry_whole_transaction`] does. This crate has no clock: §3.3 gives
//! time to the runtime, and a backoff that reached for a global clock would
//! both bypass the runtime's time source and make the law untestable. The
//! deterministic harness passes a waiter that returns immediately, because its
//! ticks are virtual.

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityRefusal,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadGeneration, HeadInit, HeadKey,
    HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
};
use fsqlite::{AsyncConnection, FrankenError, Row, SqliteValue};
use fsqlite_types::cx::{Cx, cap};

use crate::classify::classify_franken_error;
use crate::interpret::{
    CasStep, DisambiguationRefusal, HeadInitStep, ObservedHead, PutStep, compare_stored_body,
    disambiguate_compare_exchange, interpret_compare_exchange, interpret_head_create,
    interpret_put_if_absent,
};
use crate::marshal::{
    MarshalError, blob, read_blob, read_optional_unsigned, read_unsigned, unsigned,
};
use crate::retry::{
    BackoffPlan, RetryBudget, RetryOutcome, RetryVerdict, TransientClass, decide_after_failure,
};
use crate::schema::{SCHEMA_VERSION, ddl_statements, operation_statement};
use crate::token::{TokenMintError, mint_token, next_issuance_after};

/// The number of bytes an opaque version token occupies in storage.
const TOKEN_BYTES: usize = 16;

/// Why one engine operation could not produce a contract answer.
///
/// This is the internal error of the binding. It is mapped to
/// [`AuthorityFailure`] at the public boundary, and the mapping is the whole
/// point: the contract distinguishes *refused* from *ambiguous*, and only the
/// engine knows which engine failures leave the outcome unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineError {
    /// The engine failed, classified into the closed transient family.
    Engine(TransientClass),
    /// A value could not cross the SQL boundary intact.
    Marshal(MarshalError),
    /// The issuance ledger could not mint another token.
    Token(TokenMintError),
    /// The contract itself refuses this operation.
    Contract(AuthorityRefusal),
    /// A zero-row result disagreed with the state that explains it.
    Disambiguation(DisambiguationRefusal),
    /// An operation asked for SQL that is not in the closed statement set.
    ///
    /// This is a programming error in this crate, surfaced rather than
    /// papered over: the set is closed, so the alternative is improvising SQL.
    UnknownStatement(&'static str),
    /// The store on disk carries a schema generation this build does not write.
    SchemaVersionMismatch {
        /// What the store carries.
        found: i64,
        /// What this build writes.
        expected: i64,
    },
    /// A stored token was not the expected width.
    TokenWidth {
        /// The width found in storage.
        found: usize,
    },
    /// A row that must exist did not.
    RowMissing {
        /// Which statement expected it.
        statement: &'static str,
    },
}

// The contract's errors travel in `Result`s that clippy holds to 128 bytes.
const _: () = assert!(size_of::<EngineError>() <= 128);

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Engine(class) => write!(f, "engine failure classified {}", class.as_str()),
            Self::Marshal(error) => write!(f, "{error}"),
            Self::Token(error) => write!(f, "{error}"),
            Self::Contract(refusal) => write!(f, "the contract refuses: {refusal:?}"),
            Self::Disambiguation(refusal) => write!(f, "{refusal:?}"),
            Self::UnknownStatement(name) => {
                write!(f, "`{name}` is not in the closed statement set")
            }
            Self::SchemaVersionMismatch { found, expected } => write!(
                f,
                "the store carries schema generation {found}, this build writes {expected}; \
                 migrating in place would rewrite canonical bytes"
            ),
            Self::TokenWidth { found } => {
                write!(f, "a stored token is {found} bytes, not {TOKEN_BYTES}")
            }
            Self::RowMissing { statement } => {
                write!(f, "`{statement}` returned no row where one must exist")
            }
        }
    }
}

impl std::error::Error for EngineError {}

impl From<MarshalError> for EngineError {
    fn from(error: MarshalError) -> Self {
        Self::Marshal(error)
    }
}

impl From<TokenMintError> for EngineError {
    fn from(error: TokenMintError) -> Self {
        Self::Token(error)
    }
}

impl From<&FrankenError> for EngineError {
    fn from(error: &FrankenError) -> Self {
        Self::Engine(classify_franken_error(error))
    }
}

impl EngineError {
    /// The transient class this error should be retried under, if any.
    #[must_use]
    pub const fn transient_class(&self) -> TransientClass {
        match self {
            Self::Engine(class) => *class,
            // Nothing else is a property of contention: replaying the whole
            // transaction would produce the identical answer.
            _ => TransientClass::Permanent,
        }
    }

    /// Map to the contract's failure vocabulary.
    ///
    /// The distinction that matters: an indeterminate publication outcome is
    /// [`AuthorityFailure::Ambiguous`], which by construction cannot prove no
    /// effect occurred. Everything else here is a refusal, and a refusal is a
    /// promise that the store applied nothing.
    #[must_use]
    pub const fn into_failure(self) -> AuthorityFailure {
        match self {
            Self::Contract(refusal) => AuthorityFailure::Refused(refusal),
            Self::Disambiguation(DisambiguationRefusal::Contract(refusal)) => {
                AuthorityFailure::Refused(refusal)
            }
            Self::Engine(TransientClass::OutcomeIndeterminate) => {
                AuthorityFailure::Ambiguous(fgit_authority::AmbiguityReason::NoResponse)
            }
            // §5.2: client cancellation never proves non-commit, so a cancelled
            // operation must not come back as a refusal. `frankengit-w1ik`.
            Self::Engine(TransientClass::Cancelled) => {
                AuthorityFailure::Ambiguous(fgit_authority::AmbiguityReason::Cancelled)
            }
            Self::Engine(class) if class.is_retryable() => {
                AuthorityFailure::Refused(AuthorityRefusal::Throttled)
            }
            _ => AuthorityFailure::Refused(AuthorityRefusal::Unavailable),
        }
    }
}

/// The embedded `FrankenSQLite` authority store.
///
/// One instance owns one `AsyncConnection`, which owns one worker thread, which
/// owns the `!Send` `Connection`. Nothing here is shared between processes: the
/// admitted concurrency envelope in [`crate::envelope`] bounds what may open
/// the same file.
#[derive(Debug)]
pub struct FsqliteAuthorityStore {
    connection: AsyncConnection,
    instance: StoreInstanceId,
    limits: AuthorityLimits,
}

impl FsqliteAuthorityStore {
    /// Open a store, applying the schema and establishing identity.
    ///
    /// `instance` is supplied rather than generated: this crate has no
    /// randomness capability, and an identity that differed between runs would
    /// make tokens irreproducible. On an existing store the recorded identity
    /// wins, because tokens already in the ledger were minted under it.
    ///
    /// # Errors
    ///
    /// Returns the classified engine failure, or
    /// [`EngineError::SchemaVersionMismatch`] if the store was written by a
    /// build with a different schema generation.
    pub async fn open<Caps>(
        cx: &Cx<Caps>,
        path: impl Into<String>,
        instance: StoreInstanceId,
        limits: AuthorityLimits,
    ) -> Result<Self, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let connection = AsyncConnection::open(cx, path)
            .await
            .map_err(|error| EngineError::from(&error))?;

        let store = Self {
            connection,
            instance,
            limits,
        };
        let instance = store.establish(cx, instance).await?;
        Ok(Self { instance, ..store })
    }

    /// Apply the DDL and read or create the identity row.
    async fn establish<Caps>(
        &self,
        cx: &Cx<Caps>,
        proposed: StoreInstanceId,
    ) -> Result<StoreInstanceId, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        for statement in ddl_statements() {
            self.connection
                .execute(cx, statement.sql)
                .await
                .map_err(|error| EngineError::from(&error))?;
        }

        let rows = self.query(cx, "identity.read", &[]).await?;
        if let Some(row) = rows.first() {
            let recorded = read_unsigned(row, 0)?;
            let version = read_unsigned(row, 1)?;
            let found = i64::try_from(version).unwrap_or(i64::MAX);
            if found != SCHEMA_VERSION {
                return Err(EngineError::SchemaVersionMismatch {
                    found,
                    expected: SCHEMA_VERSION,
                });
            }
            return Ok(StoreInstanceId::from_raw(recorded));
        }

        let version = u64::try_from(SCHEMA_VERSION).unwrap_or(0);
        self.execute(
            cx,
            "identity.create",
            &[unsigned(proposed.raw())?, unsigned(version)?],
        )
        .await?;
        Ok(proposed)
    }

    /// Close the connection, awaiting quiescence.
    ///
    /// The engine's `close_sync` is a `Drop` backstop and cannot prove the
    /// worker drained; this is the only shutdown path this crate uses.
    ///
    /// # Errors
    ///
    /// Returns the classified engine failure if the worker did not close
    /// cleanly.
    pub async fn close<Caps>(&mut self, cx: &Cx<Caps>) -> Result<(), EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.connection
            .close(cx)
            .await
            .map_err(|error| EngineError::from(&*error))
    }

    /// This store's identity.
    #[must_use]
    pub const fn instance_id(&self) -> StoreInstanceId {
        self.instance
    }

    /// The declared bounds this instance enforces.
    #[must_use]
    pub const fn limits(&self) -> AuthorityLimits {
        self.limits
    }

    /// Execute one named statement from the closed set.
    async fn execute<Caps>(
        &self,
        cx: &Cx<Caps>,
        name: &'static str,
        params: &[SqliteValue],
    ) -> Result<u64, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let statement = operation_statement(name).ok_or(EngineError::UnknownStatement(name))?;
        let changed = self
            .connection
            .execute_with_params(cx, statement.sql, params)
            .await
            .map_err(|error| EngineError::from(&error))?;
        Ok(u64::try_from(changed).unwrap_or(u64::MAX))
    }

    /// Run one named query from the closed set.
    async fn query<Caps>(
        &self,
        cx: &Cx<Caps>,
        name: &'static str,
        params: &[SqliteValue],
    ) -> Result<Vec<Row>, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let statement = operation_statement(name).ok_or(EngineError::UnknownStatement(name))?;
        self.connection
            .query_with_params(cx, statement.sql, params)
            .await
            .map_err(|error| EngineError::from(&error))
    }

    async fn begin<Caps>(&self, cx: &Cx<Caps>) -> Result<(), EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.connection
            .begin_transaction(cx)
            .await
            .map_err(|error| EngineError::from(&error))
    }

    async fn commit<Caps>(&self, cx: &Cx<Caps>) -> Result<(), EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.connection
            .commit_transaction(cx)
            .await
            .map_err(|error| EngineError::from(&error))
    }

    /// Roll back, preserving the error that caused it.
    ///
    /// A rollback failure never replaces the original cause: the caller needs
    /// to know why the transaction failed, not why the cleanup did.
    async fn rollback_after<Caps>(&self, cx: &Cx<Caps>, cause: EngineError) -> EngineError
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let _ = self.connection.rollback_transaction(cx).await;
        cause
    }

    /// The next issuance sequence, derived from the committed ledger.
    async fn next_sequence<Caps>(
        &self,
        cx: &Cx<Caps>,
    ) -> Result<crate::token::IssuanceSequence, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let rows = self.query(cx, "issuance.max_sequence", &[]).await?;
        let row = rows.first().ok_or(EngineError::RowMissing {
            statement: "issuance.max_sequence",
        })?;
        let committed_maximum = read_optional_unsigned(row, 0)?;
        Ok(next_issuance_after(committed_maximum)?)
    }

    /// Occupancy of one bounded table, read from committed rows.
    ///
    /// A declared ceiling has to be measured against what the database holds,
    /// not against process memory: a reopened store must enforce the same
    /// ceiling it enforced before the kill, and a counter in memory would
    /// forget. Same reasoning as `issuance.max_sequence`.
    ///
    /// COST, stated rather than hidden: `COUNT(*)` is a scan, and this runs on
    /// the write paths that can occupy a slot. It is correct and it is not
    /// optimised. The optimisation, if it is ever wanted, is a transactionally
    /// maintained counter row -- which is a schema change with its own
    /// generation bump and its own crash-equivalence argument, not something to
    /// smuggle in beside a correctness fix. No performance claim is made here.
    async fn occupancy<Caps>(
        &self,
        cx: &Cx<Caps>,
        statement: &'static str,
    ) -> Result<usize, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let rows = self.query(cx, statement, &[]).await?;
        let row = rows.first().ok_or(EngineError::RowMissing { statement })?;
        let counted = read_unsigned(row, 0)?;
        // Saturating rather than wrapping, and toward "full" rather than
        // "empty": a count that cannot be represented is not a reason to admit
        // one more row. Unreachable on any target whose usize is 64 bits.
        Ok(usize::try_from(counted).unwrap_or(usize::MAX))
    }

    /// Record one minted token in the append-only ledger.
    async fn record_issuance<Caps>(
        &self,
        cx: &Cx<Caps>,
        token: AuthorityVersionToken,
        sequence: crate::token::IssuanceSequence,
        head_key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<(), EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.execute(
            cx,
            "issuance.record",
            &[
                blob(&token.to_opaque_bytes()),
                unsigned(sequence.get())?,
                blob(head_key.as_bytes()),
                unsigned(generation.get())?,
                blob(body),
            ],
        )
        .await
        .map(|_| ())
    }

    /// Read the head slot, if it exists.
    async fn head_row<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
    ) -> Result<Option<(AuthorityVersionToken, HeadGeneration, Vec<u8>)>, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let rows = self.query(cx, "head.read", &[blob(key.as_bytes())]).await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let token = token_from_row(row, 0)?;
        let generation = generation_from_row(row, 1)?;
        let body = read_blob(row, 2)?.to_vec();
        Ok(Some((token, generation, body)))
    }

    /// Reject a body the declared limits do not admit.
    const fn admit_body(&self, body: &[u8]) -> Result<(), EngineError> {
        if body.len() > self.limits.body_bytes {
            return Err(EngineError::Contract(AuthorityRefusal::BodyTooLarge {
                len: body.len(),
                limit: self.limits.body_bytes,
            }));
        }
        Ok(())
    }

    /// Write an immutable body if and only if the slot is empty.
    ///
    /// # Errors
    ///
    /// Returns a classified engine failure, or the contract's refusal if the
    /// body exceeds the declared bound.
    pub async fn put_if_absent<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.admit_body(body)?;
        self.begin(cx).await?;
        match self.put_body(cx, key, body).await {
            Ok(outcome) => {
                self.commit(cx).await?;
                Ok(outcome)
            }
            Err(cause) => Err(self.rollback_after(cx, cause).await),
        }
    }

    async fn put_body<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // `immutable_slots` applies to a body that actually occupies a new
        // slot. A retry of one already present occupies nothing, and the
        // reference admits it at capacity (reference.rs: the check sits in the
        // `None` arm, after the identical-retry and conflict arms), so the
        // existence read is taken only once the ceiling is reached.
        let limit = self.limits.immutable_slots;
        let occupancy = self.occupancy(cx, "body.count").await?;
        if occupancy >= limit
            && self
                .query(cx, "body.read", &[blob(key.as_bytes())])
                .await?
                .is_empty()
        {
            return Err(EngineError::Contract(AuthorityRefusal::CapacityExhausted {
                occupancy,
                limit,
            }));
        }

        let changed = self
            .execute(
                cx,
                "body.put_if_absent",
                &[blob(key.as_bytes()), blob(body)],
            )
            .await?;

        match interpret_put_if_absent(changed) {
            PutStep::Created => Ok(PutOutcome::Created),
            PutStep::OccupiedNeedsComparison => {
                let rows = self.query(cx, "body.read", &[blob(key.as_bytes())]).await?;
                let row = rows.first().ok_or(EngineError::RowMissing {
                    statement: "body.read",
                })?;
                let stored = read_blob(row, 0)?;
                Ok(compare_stored_body(stored, body))
            }
        }
    }

    /// Read one immutable body by exact key.
    ///
    /// # Errors
    ///
    /// Returns the classified engine failure.
    pub async fn read_immutable<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let rows = self.query(cx, "body.read", &[blob(key.as_bytes())]).await?;
        match rows.first() {
            None => Ok(ImmutableRead::Absent),
            Some(row) => Ok(ImmutableRead::Present(read_blob(row, 0)?.to_vec())),
        }
    }

    /// Read the current head, its token, and its generation.
    ///
    /// # Errors
    ///
    /// Returns the classified engine failure.
    pub async fn read_head<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
    ) -> Result<HeadRead, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        match self.head_row(cx, key).await? {
            None => Ok(HeadRead::Absent),
            Some((token, generation, body)) => Ok(HeadRead::Present(HeadReadReceipt::new(
                key.clone(),
                token,
                generation,
                body,
            ))),
        }
    }

    /// Create the repository head slot if and only if it is empty.
    ///
    /// # Errors
    ///
    /// Returns a classified engine failure, or the contract's refusal if the
    /// body exceeds the declared bound or the ledger cannot mint.
    pub async fn initialize_head<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.admit_body(body)?;
        self.begin(cx).await?;
        match self.create_head(cx, key, generation, body).await {
            Ok(outcome) => {
                self.commit(cx).await?;
                Ok(outcome)
            }
            Err(cause) => Err(self.rollback_after(cx, cause).await),
        }
    }

    async fn create_head<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // `head_slots` and `version_tokens` both apply to a head that is
        // actually created. An identical retry or a conflict on an existing
        // slot creates nothing and mints nothing, and the reference admits both
        // at capacity, so the ceilings are consulted only once the slot is
        // known absent. Checked before minting, and in the reference's order:
        // head slots, then version tokens.
        if self.head_row(cx, key).await?.is_none() {
            let head_limit = self.limits.head_slots;
            let heads = self.occupancy(cx, "head.count").await?;
            if heads >= head_limit {
                return Err(EngineError::Contract(AuthorityRefusal::CapacityExhausted {
                    occupancy: heads,
                    limit: head_limit,
                }));
            }

            let token_limit = self.limits.version_tokens;
            let issued = self.occupancy(cx, "issuance.count").await?;
            if issued >= token_limit {
                return Err(EngineError::Contract(AuthorityRefusal::CapacityExhausted {
                    occupancy: issued,
                    limit: token_limit,
                }));
            }
        }

        let sequence = self.next_sequence(cx).await?;
        let token = mint_token(self.instance, sequence);

        let changed = self
            .execute(
                cx,
                "head.create_if_absent",
                &[
                    blob(key.as_bytes()),
                    blob(&token.to_opaque_bytes()),
                    unsigned(generation.get())?,
                    blob(body),
                ],
            )
            .await?;

        match interpret_head_create(changed) {
            HeadInitStep::Created => {
                // The token is recorded only because it was actually used. A
                // ledger entry for a token no head carries would make a forged
                // receipt authenticate.
                self.record_issuance(cx, token, sequence, key, generation, body)
                    .await?;
                Ok(HeadInit::Created(HeadReadReceipt::new(
                    key.clone(),
                    token,
                    generation,
                    body.to_vec(),
                )))
            }
            HeadInitStep::OccupiedNeedsComparison => {
                let (existing_token, existing_generation, existing_body) = self
                    .head_row(cx, key)
                    .await?
                    .ok_or(EngineError::Disambiguation(
                        DisambiguationRefusal::RowCountContradictsState,
                    ))?;

                if existing_generation == generation && existing_body == body {
                    Ok(HeadInit::IdenticalRetry(HeadReadReceipt::new(
                        key.clone(),
                        existing_token,
                        existing_generation,
                        existing_body,
                    )))
                } else {
                    Ok(HeadInit::Conflict)
                }
            }
        }
    }

    /// Replace the head if and only if it still carries `expected`.
    ///
    /// A successful call is the linearization point of the repository mutation
    /// whose decision batch the new body commits to. The exact predecessor
    /// token and the strictly increasing generation are both conditions of the
    /// `UPDATE`, so a losing candidate changes zero rows rather than racing a
    /// check performed in this process.
    ///
    /// # Errors
    ///
    /// Returns a classified engine failure, or the contract's refusal when the
    /// token was never issued, names another head, or does not advance the
    /// generation.
    pub async fn compare_exchange_head<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        self.admit_body(new_body)?;
        self.begin(cx).await?;
        match self
            .exchange_head(cx, key, expected, new_generation, new_body)
            .await
        {
            Ok(outcome) => {
                self.commit(cx).await?;
                Ok(outcome)
            }
            Err(cause) => Err(self.rollback_after(cx, cause).await),
        }
    }

    async fn exchange_head<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // A published exchange mints a token, so `version_tokens` applies to
        // it -- but a losing candidate mints nothing and must not be refused
        // for capacity. The reference reaches its capacity check only after the
        // predecessor token matches and the generation is strictly increasing,
        // so those same two conditions gate it here; anything else falls
        // through to the ordinary CAS disambiguation below.
        let token_limit = self.limits.version_tokens;
        let issued = self.occupancy(cx, "issuance.count").await?;
        if issued >= token_limit
            && let Some((current, current_generation, _)) = self.head_row(cx, key).await?
            && current == expected
            && new_generation > current_generation
        {
            return Err(EngineError::Contract(AuthorityRefusal::CapacityExhausted {
                occupancy: issued,
                limit: token_limit,
            }));
        }

        let sequence = self.next_sequence(cx).await?;
        let token = mint_token(self.instance, sequence);
        let generation = unsigned(new_generation.get())?;

        let changed = self
            .execute(
                cx,
                "head.compare_exchange",
                &[
                    blob(&token.to_opaque_bytes()),
                    generation.clone(),
                    blob(new_body),
                    blob(key.as_bytes()),
                    blob(&expected.to_opaque_bytes()),
                    generation,
                ],
            )
            .await?;

        match interpret_compare_exchange(changed) {
            CasStep::Published => {
                self.record_issuance(cx, token, sequence, key, new_generation, new_body)
                    .await?;
                Ok(CasOutcome::Committed(HeadReadReceipt::new(
                    key.clone(),
                    token,
                    new_generation,
                    new_body.to_vec(),
                )))
            }
            CasStep::UnchangedNeedsDisambiguation => {
                // Zero rows has four possible causes and they are not
                // interchangeable: a token this store never issued is a
                // refusal, while a token it issued and superseded is an
                // ordinary lost race. Provenance is checked before staleness.
                let issued = self.issued_head_key(cx, expected).await?;
                let observed = self
                    .head_row(cx, key)
                    .await?
                    .map(|(token, generation, _)| ObservedHead { token, generation });

                disambiguate_compare_exchange(
                    expected,
                    new_generation,
                    issued.as_deref(),
                    key.as_bytes(),
                    observed,
                )
                .map_err(EngineError::Disambiguation)
            }
        }
    }

    /// The head key a token was issued for, if this store issued it.
    async fn issued_head_key<Caps>(
        &self,
        cx: &Cx<Caps>,
        token: AuthorityVersionToken,
    ) -> Result<Option<Vec<u8>>, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let rows = self
            .query(cx, "issuance.read", &[blob(&token.to_opaque_bytes())])
            .await?;
        match rows.first() {
            None => Ok(None),
            Some(row) => Ok(Some(read_blob(row, 0)?.to_vec())),
        }
    }

    /// Publish terminal outcome entries and replace the head atomically.
    ///
    /// The atomicity is the engine's, not this crate's discipline: everything
    /// below runs inside a single `BEGIN`/`COMMIT`, so a crash or a lost
    /// response cannot leave the head advanced with outcome records missing.
    /// That window is exactly the §5.2 defect this operation exists to close.
    ///
    /// # Errors
    ///
    /// Returns a classified engine failure, or the contract's refusal when an
    /// outcome key already holds different bytes — in which case nothing is
    /// written and the head does not move.
    pub async fn publish_head_with_outcomes<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // The witness must be bound to the token this CAS conditions on. One
        // minted against a different head proves nothing about this one, and
        // accepting it would restore exactly the window the witness exists to
        // close: a duplicate check performed against state the CAS does not
        // cover. Refused before anything is written.
        if witness.bound_to() != expected {
            return Err(EngineError::Contract(AuthorityRefusal::TokenKeyMismatch));
        }
        self.admit_body(new_body)?;
        for (_, bytes) in outcomes {
            self.admit_body(bytes)?;
        }

        self.begin(cx).await?;
        match self
            .publish_atomically(cx, key, expected, new_generation, new_body, outcomes)
            .await
        {
            Ok(outcome @ CasOutcome::Committed(_)) => {
                self.commit(cx).await?;
                Ok(outcome)
            }
            Ok(CasOutcome::PredecessorMismatch) => {
                // `publish_atomically` stages outcome rows before attempting
                // the exact-predecessor exchange. A publisher can lose after
                // its duplicate scan but before that exchange, so committing
                // this ordinary CAS outcome would make the losing rows visible
                // without their head. An awaited rollback is part of proving
                // the contract's "nothing written" result; if cleanup fails,
                // propagate that failure instead of claiming a no-effect loss.
                self.connection
                    .rollback_transaction(cx)
                    .await
                    .map_err(|error| EngineError::from(&error))?;
                Ok(CasOutcome::PredecessorMismatch)
            }
            Err(cause) => Err(self.rollback_after(cx, cause).await),
        }
    }

    /// The body of the atomic publication, inside the caller's transaction.
    ///
    /// Outcome entries are staged **before** the conditional head replacement,
    /// mirroring body-first/head-last — but the ordering is belt-and-braces
    /// here rather than load-bearing, because the whole sequence commits or
    /// aborts as one. The head CAS remains the linearization point; what
    /// changes is that the outcome records are part of what it makes durable.
    async fn publish_atomically<Caps>(
        &self,
        cx: &Cx<Caps>,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
    ) -> Result<CasOutcome, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        for (outcome_key, bytes) in outcomes {
            match self.put_body(cx, outcome_key, bytes).await? {
                PutOutcome::Created | PutOutcome::IdenticalRetry => {}
                // A different terminal decision already recorded for this key.
                // Fail closed and write nothing: a partially applied
                // publication is the state this operation exists to prevent.
                PutOutcome::Conflict => {
                    return Err(EngineError::Contract(AuthorityRefusal::TokenBodyMismatch));
                }
            }
        }
        self.exchange_head(cx, key, expected, new_generation, new_body)
            .await
    }

    /// Confirm that this store issued `receipt` exactly as presented.
    ///
    /// Success proves authenticity, never currency: a genuine receipt for a
    /// superseded head still authenticates, and still loses the exchange.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityRefusal::UnknownVersionToken`] for a token this store
    /// never minted, and the corresponding mismatch refusal when the presented
    /// bytes, key, or generation differ from what was issued.
    pub async fn authenticate_head_receipt<Caps>(
        &self,
        cx: &Cx<Caps>,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        let rows = self
            .query(
                cx,
                "issuance.read",
                &[blob(&receipt.token().to_opaque_bytes())],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Err(EngineError::Contract(AuthorityRefusal::UnknownVersionToken));
        };

        let issued_key = read_blob(row, 0)?;
        if issued_key != receipt.key().as_bytes() {
            return Err(EngineError::Contract(AuthorityRefusal::TokenKeyMismatch));
        }
        let issued_generation = generation_from_row(row, 1)?;
        if issued_generation != receipt.generation() {
            return Err(EngineError::Contract(
                AuthorityRefusal::TokenGenerationMismatch,
            ));
        }
        let issued_body = read_blob(row, 2)?;
        if issued_body != receipt.body() {
            return Err(EngineError::Contract(AuthorityRefusal::TokenBodyMismatch));
        }

        Ok(AuthenticatedHead::new(receipt.clone(), self.instance))
    }
}

/// Read a version token from a `BLOB` column.
fn token_from_row(row: &Row, column: usize) -> Result<AuthorityVersionToken, EngineError> {
    let bytes = read_blob(row, column)?;
    let exact: [u8; TOKEN_BYTES] = bytes
        .try_into()
        .map_err(|_| EngineError::TokenWidth { found: bytes.len() })?;
    Ok(AuthorityVersionToken::from_opaque_bytes(exact))
}

/// Read a head generation from an `INTEGER` column.
fn generation_from_row(row: &Row, column: usize) -> Result<HeadGeneration, EngineError> {
    let raw = read_unsigned(row, column)?;
    head_generation_from_unsigned(raw, column)
}

/// Validate the unsigned SQL value as a live head generation.
///
/// [`read_unsigned`] already refuses negative SQL integers.  This second
/// conversion is deliberately separate: zero is non-negative at the SQL
/// boundary but reserved by [`HeadGeneration`], so describing it as a
/// fabricated negative would hide the actual damaged-row condition.
const fn head_generation_from_unsigned(
    raw: u64,
    column: usize,
) -> Result<HeadGeneration, EngineError> {
    match HeadGeneration::try_new(raw) {
        Ok(generation) => Ok(generation),
        Err(_) => Err(EngineError::Marshal(MarshalError::HeadGenerationZero {
            column,
        })),
    }
}

/// Run one whole logical transaction under the retry law, awaiting the wait.
///
/// This is the asynchronous driver of the law in [`crate::retry`]. It shares
/// the decision with the synchronous driver via
/// [`decide_after_failure`] rather than restating it, because a retry policy
/// that disagreed with itself across two call paths is exactly how a
/// transaction gets replayed after an indeterminate outcome.
///
/// `attempt` runs the **entire** transaction from the beginning every time.
pub async fn run_with_retry<T, A, W>(
    budget: RetryBudget,
    backoff: BackoffPlan,
    mut attempt: A,
    mut wait: W,
) -> RetryOutcome<T>
where
    A: AsyncFnMut(u32) -> Result<T, EngineError>,
    W: AsyncFnMut(u64),
{
    let mut budget = budget;
    let mut elapsed = 0_u64;

    for attempt_number in 1..=budget.max_attempts() {
        let class = match attempt(attempt_number).await {
            Ok(value) => return RetryOutcome::Completed(value),
            Err(error) => error.transient_class(),
        };
        match decide_after_failure(budget, backoff, attempt_number, elapsed, class) {
            RetryVerdict::FreshSnapshotRequired => {
                return RetryOutcome::FreshSnapshotRequired {
                    attempts: attempt_number,
                };
            }
            RetryVerdict::OutcomeIndeterminate => {
                return RetryOutcome::OutcomeIndeterminate {
                    attempts: attempt_number,
                };
            }
            RetryVerdict::Permanent => {
                return RetryOutcome::Permanent {
                    attempts: attempt_number,
                };
            }
            RetryVerdict::Exhausted(exhausted) => return RetryOutcome::Exhausted(exhausted),
            RetryVerdict::Retry {
                delay_ticks,
                budget: next,
            } => {
                wait(delay_ticks).await;
                elapsed = elapsed.saturating_add(delay_ticks);
                budget = next;
            }
        }
    }

    RetryOutcome::Permanent {
        attempts: budget.max_attempts(),
    }
}

// ---------------------------------------------------------------------------
// The production trait impl (t7ip condition 2).
//
// The inherent methods above ARE the implementation; this impl is the published
// surface over them, so there is exactly one body per operation and no place for
// the two to drift. Every method here is a delegation plus the error mapping to
// the contract vocabulary.
// ---------------------------------------------------------------------------

impl AsyncAuthorityStore for FsqliteAuthorityStore {
    /// `FrankenSQLite`'s own capability context at full capability.
    ///
    /// Not asupersync's `Cx` — the two are distinct types bridged by
    /// `set_native_cx`. Threaded per call, never stored on the store, so
    /// per-request budget and cancellation reach the operation.
    type Context = Cx;

    fn instance_id(&self) -> StoreInstanceId {
        Self::instance_id(self)
    }

    fn limits(&self) -> AuthorityLimits {
        Self::limits(self)
    }

    async fn put_if_absent(
        &self,
        cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        Self::put_if_absent(self, cx, key, body)
            .await
            .map_err(EngineError::into_failure)
    }

    async fn read_immutable(
        &self,
        cx: &Self::Context,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        Self::read_immutable(self, cx, key)
            .await
            .map_err(EngineError::into_failure)
    }

    async fn initialize_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        Self::initialize_head(self, cx, key, generation, body)
            .await
            .map_err(EngineError::into_failure)
    }

    async fn read_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
    ) -> Result<HeadRead, AuthorityFailure> {
        Self::read_head(self, cx, key)
            .await
            .map_err(EngineError::into_failure)
    }

    async fn compare_exchange_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        Self::compare_exchange_head(self, cx, key, expected, new_generation, new_body)
            .await
            .map_err(EngineError::into_failure)
    }

    async fn publish_head_with_outcomes(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        Self::publish_head_with_outcomes(
            self,
            cx,
            key,
            expected,
            new_generation,
            new_body,
            outcomes,
            witness,
        )
        .await
        .map_err(EngineError::into_failure)
    }

    async fn authenticate_head_receipt(
        &self,
        cx: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        Self::authenticate_head_receipt(self, cx, receipt)
            .await
            .map_err(EngineError::into_failure)
    }
}

#[cfg(test)]
mod tests {
    use super::{EngineError, HeadGeneration, MarshalError, head_generation_from_unsigned};

    #[test]
    fn head_generation_conversion_accepts_live_values_and_truthfully_refuses_zero() {
        assert_eq!(
            head_generation_from_unsigned(HeadGeneration::FIRST.get(), 4),
            Ok(HeadGeneration::FIRST),
            "the first live generation must survive the SQL boundary"
        );
        assert_eq!(
            head_generation_from_unsigned(0, 4),
            Err(EngineError::Marshal(MarshalError::HeadGenerationZero {
                column: 4,
            })),
            "zero is reserved, not a fabricated negative integer"
        );
    }
}
