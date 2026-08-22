//! The schema and statement set are a contract, not an implementation detail.

use fgit_authority_fsqlite::{
    HEAD_SLOT_TABLE, IMMUTABLE_BODY_TABLE, SCHEMA_VERSION, STORE_IDENTITY_TABLE,
    VERSION_ISSUANCE_TABLE, ddl_statements, operation_statement, operation_statements,
};

#[test]
fn every_statement_binds_its_values_rather_than_interpolating_them() {
    for statement in ddl_statements().iter().chain(operation_statements()) {
        let placeholders = statement.sql.matches('?').count();
        assert_eq!(
            placeholders, statement.parameters,
            "{} declares {} parameters but has {placeholders} placeholders",
            statement.name, statement.parameters
        );
        assert!(
            !statement.sql.contains('\''),
            "{} contains a SQL string literal; every value in this profile is \
             attacker-influenced canonical bytes and must be bound, not written into the text",
            statement.name
        );
    }
}

#[test]
fn statement_names_are_unique() {
    let mut names: Vec<&str> = ddl_statements()
        .iter()
        .chain(operation_statements())
        .map(|statement| statement.name)
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "two statements share a name");
}

#[test]
fn the_operation_set_is_closed_and_complete() {
    // The set is fixed on purpose: an operation needing SQL not named here is a
    // schema change a reviewer should see, not a local improvisation.
    let expected = [
        "identity.read",
        "identity.create",
        "body.read",
        "body.put_if_absent",
        "body.count",
        "head.read",
        "head.create_if_absent",
        "head.compare_exchange",
        "head.count",
        "issuance.read",
        "issuance.max_sequence",
        "issuance.record",
        "issuance.count",
    ];
    let mut observed: Vec<&str> = operation_statements()
        .iter()
        .map(|statement| statement.name)
        .collect();
    observed.sort_unstable();
    let mut expected_sorted = expected;
    expected_sorted.sort_unstable();
    assert_eq!(
        observed,
        expected_sorted.to_vec(),
        "the operation statement set drifted"
    );

    for name in expected {
        assert!(
            operation_statement(name).is_some(),
            "{name} is not resolvable by lookup"
        );
    }
    assert!(
        operation_statement("body.delete").is_none(),
        "there is no delete"
    );
}

#[test]
fn the_conditional_replacement_carries_both_of_its_guards() {
    let cas = operation_statement("head.compare_exchange").expect("the statement exists");
    // Both guards live in the WHERE clause rather than in application logic, so
    // a losing candidate updates zero rows instead of racing a read.
    assert!(
        cas.sql.contains("token = ?"),
        "the exact-predecessor-token guard is missing; without it any writer wins"
    );
    assert!(
        cas.sql.contains("generation < ?"),
        "the strictly-increasing generation guard is missing; without it the head can roll back"
    );
    assert!(
        cas.sql.starts_with("UPDATE"),
        "the replacement must be an UPDATE so a lost race changes no rows"
    );
}

#[test]
fn put_if_absent_never_replaces_an_existing_body() {
    let put = operation_statement("body.put_if_absent").expect("the statement exists");
    assert!(
        put.sql.contains("DO NOTHING"),
        "put-if-absent must leave an occupied slot alone"
    );
    assert!(
        !put.sql.contains("DO UPDATE") && !put.sql.contains("REPLACE"),
        "an immutable body may never be overwritten"
    );

    let head = operation_statement("head.create_if_absent").expect("the statement exists");
    assert!(head.sql.contains("DO NOTHING"));
    assert!(!head.sql.contains("DO UPDATE") && !head.sql.contains("REPLACE"));
}

#[test]
fn no_statement_deletes_or_truncates_authority_state() {
    // The authority tables are append-only or conditionally replaced. Nothing
    // in the profile removes an immutable body or an issuance record, and the
    // absence of the capability is stronger than a rule against using it.
    for statement in ddl_statements().iter().chain(operation_statements()) {
        let sql = statement.sql.to_ascii_uppercase();
        for forbidden in ["DELETE FROM", "DROP TABLE", "TRUNCATE"] {
            assert!(
                !sql.contains(forbidden),
                "{} contains {forbidden}; authority state is never removed by this profile",
                statement.name
            );
        }
    }
}

#[test]
fn every_table_is_strict_and_named_consistently() {
    for statement in ddl_statements() {
        assert!(
            statement.sql.contains("STRICT"),
            "{} is not STRICT; canonical bytes that changed type in storage would change \
             identity on the way out",
            statement.name
        );
        assert!(
            statement.sql.contains("IF NOT EXISTS"),
            "{} is not idempotent, so reopening an existing store would fail",
            statement.name
        );
    }

    let all: String = ddl_statements()
        .iter()
        .map(|statement| statement.sql)
        .collect();
    for table in [
        IMMUTABLE_BODY_TABLE,
        HEAD_SLOT_TABLE,
        VERSION_ISSUANCE_TABLE,
        STORE_IDENTITY_TABLE,
    ] {
        assert!(all.contains(table), "{table} has no DDL");
    }
}

/// Collapse whitespace runs so a column constraint can be asserted without
/// pinning the DDL's indentation.
fn squeezed(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_issuance_ledger_is_unique_on_both_of_its_identifying_columns() {
    let ddl = ddl_statements()
        .iter()
        .find(|statement| statement.name == "ddl.version_issuance")
        .expect("the ledger DDL exists");
    let sql = squeezed(ddl.sql);
    assert!(
        sql.contains("token BLOB NOT NULL PRIMARY KEY"),
        "a token must be unique, or the ABA defence has a hole: {sql}"
    );
    assert!(
        sql.contains("issued_seq INTEGER NOT NULL UNIQUE"),
        "a sequence must be unique, or two tokens could share a position: {sql}"
    );
}

#[test]
fn the_head_slot_holds_exactly_one_row_per_repository() {
    let ddl = ddl_statements()
        .iter()
        .find(|statement| statement.name == "ddl.head_slot")
        .expect("the head DDL exists");
    let sql = squeezed(ddl.sql);
    assert!(
        sql.contains("head_key BLOB NOT NULL PRIMARY KEY"),
        "one head slot per repository is a primary-key property, not a convention: {sql}"
    );
    assert!(
        sql.contains("generation INTEGER NOT NULL"),
        "the anti-rollback counter must be stored, not derived: {sql}"
    );
}

#[test]
fn the_schema_generation_is_pinned() {
    assert_eq!(
        SCHEMA_VERSION, 1,
        "changing the schema generation is a deliberate act; the authority tables hold \
         canonical bytes and an in-place migration would rewrite history"
    );
}
