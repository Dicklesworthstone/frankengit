//! SQLite statements emitted from the concrete SQLModel metadata. Consumer
//! code sees only typed rows and queries, never a raw-SQL projection API.

use sqlmodel_core::{Dialect, Model, Value};

use super::{
    InboxQuery,
    model::{StoredInbox, StoredThread},
};

fn quoted(name: &str) -> String {
    Dialect::Sqlite.quote_identifier(name)
}

pub(super) fn create<M: Model>() -> String {
    let mut fields = M::fields()
        .iter()
        .map(|field| {
            let mut definition = format!(
                "{} {}",
                quoted(field.column_name),
                field.effective_sql_type_for(Dialect::Sqlite)
            );
            if !field.nullable {
                definition.push_str(" NOT NULL");
            }
            for constraint in field.column_constraints {
                definition.push(' ');
                definition.push_str(constraint);
            }
            definition
        })
        .collect::<Vec<_>>();
    fields.push(format!(
        "PRIMARY KEY ({})",
        M::PRIMARY_KEY
            .iter()
            .map(|name| quoted(name))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    format!(
        "CREATE TABLE IF NOT EXISTS {} ({})",
        quoted(M::TABLE_NAME),
        fields.join(", ")
    )
}

pub(super) fn insert<M: Model>(model: &M) -> (String, Vec<Value>) {
    let row = model.to_row();
    let columns = row
        .iter()
        .map(|(name, _)| quoted(name))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (1..=row.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    (
        format!(
            "INSERT INTO {} ({columns}) VALUES ({placeholders})",
            quoted(M::TABLE_NAME)
        ),
        row.into_iter().map(|(_, value)| value).collect(),
    )
}

pub(super) fn delete<M: Model>() -> String {
    format!("DELETE FROM {}", quoted(M::TABLE_NAME))
}

fn select<M: Model>() -> String {
    let columns = M::fields()
        .iter()
        .map(|field| quoted(field.column_name))
        .collect::<Vec<_>>()
        .join(", ");
    format!("SELECT {columns} FROM {}", quoted(M::TABLE_NAME))
}

pub(super) fn select_marker() -> String {
    format!(
        "{} WHERE {} = 1",
        select::<StoredInbox>(),
        quoted(StoredInbox::PRIMARY_KEY[0])
    )
}

pub(super) fn count<M: Model>() -> String {
    format!(
        "SELECT COUNT(*) AS {} FROM {}",
        quoted("row_count"),
        quoted(M::TABLE_NAME)
    )
}

pub(super) fn all_threads() -> String {
    format!(
        "{} ORDER BY {} ASC LIMIT {}",
        select::<StoredThread>(),
        quoted(StoredThread::PRIMARY_KEY[0]),
        super::MAX_INBOX_ROWS + 1
    )
}

/// Column selectors are indexes into the one SQLModel schema, not accepted
/// names or expressions supplied by a request.
fn thread_column(index: usize) -> String {
    quoted(StoredThread::fields()[index].column_name)
}

pub(super) fn page(query: InboxQuery) -> (String, Vec<Value>) {
    let issue = thread_column(0);
    let muted = thread_column(6);
    let unread = thread_column(7);
    (
        format!(
            "{} WHERE {issue} > ?1 AND (?2 = 1 OR {muted} = 0) AND (?3 = 0 OR {unread} = 1) ORDER BY {issue} ASC LIMIT ?4",
            select::<StoredThread>()
        ),
        vec![
            // The caller checked this conversion before opening a transaction.
            Value::BigInt(
                i64::try_from(query.after_thread.unwrap_or(0)).expect("checked inbox cursor"),
            ),
            Value::BigInt(i64::from(query.include_muted)),
            Value::BigInt(i64::from(query.unread_only)),
            Value::BigInt(i64::from(query.limit.get()) + 1),
        ],
    )
}
