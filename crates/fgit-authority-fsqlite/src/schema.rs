//! The exact schema and statement set of the embedded authority profile.
//!
//! Two properties matter more than the SQL itself.
//!
//! **Every statement is parameterized.** Not one of them interpolates a value,
//! because the values here are attacker-influenced canonical bytes and opaque
//! keys. A statement set held as constants can be checked for that property by
//! a test, which is why they are constants rather than strings built at the
//! call site.
//!
//! **The issuance table is append-only and is the token authority.** A version
//! token is `(instance, issuance sequence)`, and the sequence advances inside
//! the *same* transaction that publishes the head it belongs to. That is what
//! makes tokens survive a kill: there is no counter to lose, because the next
//! sequence is a function of the committed ledger rather than of process
//! memory. It is also what makes an authenticated head read possible, exactly
//! as in the in-memory reference profile — a token absent from the ledger was
//! never issued here, whoever presents it.
//!
//! # Why `STRICT`
//!
//! Every table is `STRICT`, so a column declared `BLOB` cannot silently hold
//! text and a column declared `INTEGER` cannot silently hold a float. Canonical
//! bytes that changed type in storage would change identity on the way out;
//! type affinity is not a stylistic preference here.

/// The schema generation this build writes and expects.
///
/// A store carrying a different generation is refused rather than migrated in
/// place: the authority tables hold canonical bytes, and a migration that
/// rewrote them would rewrite history.
pub const SCHEMA_VERSION: i64 = 1;

/// Immutable bodies, addressed by an opaque caller-derived key.
pub const IMMUTABLE_BODY_TABLE: &str = "fgit_immutable_body";
/// The one head slot per repository.
pub const HEAD_SLOT_TABLE: &str = "fgit_head_slot";
/// The append-only record of every version token this store has ever minted.
pub const VERSION_ISSUANCE_TABLE: &str = "fgit_version_issuance";
/// The singleton row carrying store identity and schema generation.
pub const STORE_IDENTITY_TABLE: &str = "fgit_store_identity";

/// One named statement in the profile's fixed statement set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaStatement {
    /// Stable name, referenced by tests and by operation code.
    pub name: &'static str,
    /// The SQL text.
    pub sql: &'static str,
    /// How many bound parameters the statement takes.
    pub parameters: usize,
}

/// The data-definition statements, in the order they must be applied.
///
/// Applying them is idempotent, so an existing store re-runs them harmlessly
/// while a fresh one is created.
#[must_use]
pub const fn ddl_statements() -> &'static [SchemaStatement] {
    &[
        SchemaStatement {
            name: "ddl.immutable_body",
            sql: "CREATE TABLE IF NOT EXISTS fgit_immutable_body (\n\
                  \x20   body_key   BLOB NOT NULL PRIMARY KEY,\n\
                  \x20   body_bytes BLOB NOT NULL\n\
                  ) STRICT",
            parameters: 0,
        },
        SchemaStatement {
            name: "ddl.head_slot",
            sql: "CREATE TABLE IF NOT EXISTS fgit_head_slot (\n\
                  \x20   head_key   BLOB    NOT NULL PRIMARY KEY,\n\
                  \x20   token      BLOB    NOT NULL,\n\
                  \x20   generation INTEGER NOT NULL,\n\
                  \x20   body_bytes BLOB    NOT NULL\n\
                  ) STRICT",
            parameters: 0,
        },
        SchemaStatement {
            name: "ddl.version_issuance",
            sql: "CREATE TABLE IF NOT EXISTS fgit_version_issuance (\n\
                  \x20   token      BLOB    NOT NULL PRIMARY KEY,\n\
                  \x20   issued_seq INTEGER NOT NULL UNIQUE,\n\
                  \x20   head_key   BLOB    NOT NULL,\n\
                  \x20   generation INTEGER NOT NULL,\n\
                  \x20   body_bytes BLOB    NOT NULL\n\
                  ) STRICT",
            parameters: 0,
        },
        SchemaStatement {
            name: "ddl.store_identity",
            sql: "CREATE TABLE IF NOT EXISTS fgit_store_identity (\n\
                  \x20   singleton      INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 0),\n\
                  \x20   instance_id    INTEGER NOT NULL,\n\
                  \x20   schema_version INTEGER NOT NULL\n\
                  ) STRICT",
            parameters: 0,
        },
    ]
}

/// The fixed set of operation statements.
///
/// The set is closed: an operation that needs SQL not named here is a schema
/// change, not a local improvisation.
#[must_use]
pub const fn operation_statements() -> &'static [SchemaStatement] {
    &[
        SchemaStatement {
            name: "identity.read",
            sql: "SELECT instance_id, schema_version FROM fgit_store_identity WHERE singleton = 0",
            parameters: 0,
        },
        SchemaStatement {
            name: "identity.create",
            sql: "INSERT INTO fgit_store_identity (singleton, instance_id, schema_version) \
                  VALUES (0, ?, ?)",
            parameters: 2,
        },
        SchemaStatement {
            name: "body.read",
            sql: "SELECT body_bytes FROM fgit_immutable_body WHERE body_key = ?",
            parameters: 1,
        },
        // Put-if-absent is expressed as a conditional insert rather than a
        // read-then-write: the read-then-write shape has a race whose only
        // remedy is a lock the engine's commit guard already owns.
        SchemaStatement {
            name: "body.put_if_absent",
            sql: "INSERT INTO fgit_immutable_body (body_key, body_bytes) VALUES (?, ?) \
                  ON CONFLICT (body_key) DO NOTHING",
            parameters: 2,
        },
        SchemaStatement {
            name: "body.count",
            sql: "SELECT COUNT(*) FROM fgit_immutable_body",
            parameters: 0,
        },
        SchemaStatement {
            name: "head.read",
            sql: "SELECT token, generation, body_bytes FROM fgit_head_slot WHERE head_key = ?",
            parameters: 1,
        },
        SchemaStatement {
            name: "head.create_if_absent",
            sql: "INSERT INTO fgit_head_slot (head_key, token, generation, body_bytes) \
                  VALUES (?, ?, ?, ?) ON CONFLICT (head_key) DO NOTHING",
            parameters: 4,
        },
        // The conditional replacement, expressed as the WHERE clause rather
        // than as application logic: the exact predecessor token and the
        // strictly increasing generation are both conditions of the UPDATE, so
        // a losing candidate changes zero rows instead of racing a check.
        SchemaStatement {
            name: "head.compare_exchange",
            sql: "UPDATE fgit_head_slot \
                  SET token = ?, generation = ?, body_bytes = ? \
                  WHERE head_key = ? AND token = ? AND generation < ?",
            parameters: 6,
        },
        SchemaStatement {
            name: "issuance.read",
            sql: "SELECT head_key, generation, body_bytes FROM fgit_version_issuance \
                  WHERE token = ?",
            parameters: 1,
        },
        // The next sequence is a function of the committed ledger, never of
        // process memory, so a kill cannot lose it and a reopen cannot reuse
        // one. NULL for an empty ledger is resolved by the caller.
        SchemaStatement {
            name: "issuance.max_sequence",
            sql: "SELECT MAX(issued_seq) FROM fgit_version_issuance",
            parameters: 0,
        },
        SchemaStatement {
            name: "issuance.record",
            sql: "INSERT INTO fgit_version_issuance \
                  (token, issued_seq, head_key, generation, body_bytes) VALUES (?, ?, ?, ?, ?)",
            parameters: 5,
        },
        SchemaStatement {
            name: "issuance.count",
            sql: "SELECT COUNT(*) FROM fgit_version_issuance",
            parameters: 0,
        },
    ]
}

/// Look one operation statement up by name.
#[must_use]
pub fn operation_statement(name: &str) -> Option<&'static SchemaStatement> {
    operation_statements()
        .iter()
        .find(|statement| statement.name == name)
}
