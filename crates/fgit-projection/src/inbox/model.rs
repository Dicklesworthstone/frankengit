//! Actual SQLModel models for the complete-generation marker and thread rows.
//! Manual implementations keep the admitted sqlmodel-core/driver closure;
//! schema and statements consume this metadata rather than a parallel schema.

use fgit_crypto::{DigestHasher, Sha256Hasher, lowercase_hex};
use sqlmodel_core::field::FieldInfo;
use sqlmodel_core::{Model, Row, SqlType, Value};

use super::{
    InboxError, InboxReason, InboxRefusal, InboxRow, InboxSnapshot, InboxSnapshotBinding,
    checked_counter,
};

const PROFILE: &str = "frankengit/thread-notification-inbox/v3";
const SCHEMA_GENERATION: i64 = 3;
const CONTENT_DIGEST_DOMAIN: &[u8] = b"frankengit/thread-notification-inbox/content-digest/v3\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredInbox {
    singleton: i64,
    profile: String,
    schema_generation: i64,
    tenant: String,
    repository: String,
    incarnation: String,
    authority_head: String,
    authority_head_generation: i64,
    forge_position_root: String,
    outbox_root: String,
    principal: String,
    target_kind: String,
    pub complete: i64,
    pub row_count: i64,
    pub content_digest: String,
}

impl StoredInbox {
    #[cfg(test)]
    pub fn from_snapshot(snapshot: &InboxSnapshot) -> Result<Self, InboxError> {
        let threads = snapshot
            .rows
            .iter()
            .map(StoredThread::from_input)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_snapshot_with_threads(snapshot, &threads)
    }

    pub fn from_snapshot_with_threads(
        snapshot: &InboxSnapshot,
        threads: &[StoredThread],
    ) -> Result<Self, InboxError> {
        let binding = &snapshot.binding;
        Ok(Self {
            singleton: 1,
            profile: PROFILE.to_owned(),
            schema_generation: SCHEMA_GENERATION,
            tenant: binding.tenant.to_string(),
            repository: binding.repository.to_string(),
            incarnation: binding.incarnation.to_string(),
            authority_head: binding.authority_head.to_string(),
            authority_head_generation: checked_counter(
                "authority_head_generation",
                binding.authority_head_generation,
            )?,
            forge_position_root: binding.forge_position_root.to_string(),
            outbox_root: binding.outbox_root.to_string(),
            principal: binding.principal.to_string(),
            target_kind: binding.kind.name().to_owned(),
            complete: 1,
            row_count: i64::try_from(threads.len())
                .map_err(|_| InboxRefusal::IncompleteSnapshot)?,
            content_digest: snapshot_content_digest(binding, threads),
        })
    }

    pub fn matches(&self, binding: &InboxSnapshotBinding) -> bool {
        self.singleton == 1
            && self.profile == PROFILE
            && self.schema_generation == SCHEMA_GENERATION
            && self.tenant == binding.tenant.to_string()
            && self.repository == binding.repository.to_string()
            && self.incarnation == binding.incarnation.to_string()
            && self.authority_head == binding.authority_head.to_string()
            && u64::try_from(self.authority_head_generation).ok()
                == Some(binding.authority_head_generation)
            && self.forge_position_root == binding.forge_position_root.to_string()
            && self.outbox_root == binding.outbox_root.to_string()
            && self.principal == binding.principal.to_string()
            && self.target_kind == binding.kind.name()
            && self.content_digest.len() == 64
    }
}

fn feed_framed(hasher: &mut Sha256Hasher, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("in-memory slice fits in u64");
    hasher.update(&len.to_be_bytes());
    hasher.update(bytes);
}

fn feed_optional_i64(hasher: &mut Sha256Hasher, value: Option<i64>) {
    match value {
        None => hasher.update(&[0]),
        Some(number) => {
            hasher.update(&[1]);
            hasher.update(&number.to_be_bytes());
        }
    }
}

fn snapshot_content_digest(binding: &InboxSnapshotBinding, threads: &[StoredThread]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(CONTENT_DIGEST_DOMAIN);
    feed_framed(&mut hasher, binding.tenant.as_bytes());
    feed_framed(&mut hasher, binding.repository.as_bytes());
    feed_framed(&mut hasher, binding.incarnation.as_bytes());
    feed_framed(&mut hasher, binding.authority_head.to_string().as_bytes());
    hasher.update(&binding.authority_head_generation.to_be_bytes());
    feed_framed(
        &mut hasher,
        binding.forge_position_root.to_string().as_bytes(),
    );
    feed_framed(&mut hasher, binding.outbox_root.to_string().as_bytes());
    feed_framed(&mut hasher, binding.principal.as_bytes());
    feed_framed(&mut hasher, binding.kind.name().as_bytes());
    let count = u64::try_from(threads.len()).expect("thread count fits in u64");
    hasher.update(&count.to_be_bytes());
    for thread in threads {
        hasher.update(&thread.thread_number.to_be_bytes());
        hasher.update(&thread.thread_version.to_be_bytes());
        feed_optional_i64(&mut hasher, thread.preference_version);
        feed_optional_i64(&mut hasher, thread.read_through);
        feed_optional_i64(&mut hasher, thread.latest_other_version);
        hasher.update(&thread.reason_mask.to_be_bytes());
        hasher.update(&thread.muted.to_be_bytes());
        hasher.update(&thread.unread.to_be_bytes());
    }
    lowercase_hex(&hasher.finish())
}

const fn singleton_field() -> FieldInfo {
    let mut field = FieldInfo::new("singleton", "singleton", SqlType::BigInt).primary_key(true);
    field.column_constraints = &["CHECK (singleton = 1)"];
    field
}

impl Model for StoredInbox {
    const TABLE_NAME: &'static str = "fgit_thread_inbox_complete";
    const PRIMARY_KEY: &'static [&'static str] = &["singleton"];

    fn fields() -> &'static [FieldInfo] {
        const FIELDS: &[FieldInfo] = &[
            singleton_field(),
            FieldInfo::new("profile", "profile", SqlType::Text),
            FieldInfo::new("schema_generation", "schema_generation", SqlType::BigInt),
            FieldInfo::new("tenant", "tenant", SqlType::Text),
            FieldInfo::new("repository", "repository", SqlType::Text),
            FieldInfo::new("incarnation", "incarnation", SqlType::Text),
            FieldInfo::new("authority_head", "authority_head", SqlType::Text),
            FieldInfo::new(
                "authority_head_generation",
                "authority_head_generation",
                SqlType::BigInt,
            ),
            FieldInfo::new("forge_position_root", "forge_position_root", SqlType::Text),
            FieldInfo::new("outbox_root", "outbox_root", SqlType::Text),
            FieldInfo::new("principal", "principal", SqlType::Text),
            FieldInfo::new("target_kind", "target_kind", SqlType::Text),
            FieldInfo::new("complete", "complete", SqlType::BigInt),
            FieldInfo::new("row_count", "row_count", SqlType::BigInt),
            FieldInfo::new("content_digest", "content_digest", SqlType::Text),
        ];
        FIELDS
    }

    fn to_row(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("singleton", Value::BigInt(self.singleton)),
            ("profile", Value::Text(self.profile.clone())),
            ("schema_generation", Value::BigInt(self.schema_generation)),
            ("tenant", Value::Text(self.tenant.clone())),
            ("repository", Value::Text(self.repository.clone())),
            ("incarnation", Value::Text(self.incarnation.clone())),
            ("authority_head", Value::Text(self.authority_head.clone())),
            (
                "authority_head_generation",
                Value::BigInt(self.authority_head_generation),
            ),
            (
                "forge_position_root",
                Value::Text(self.forge_position_root.clone()),
            ),
            ("outbox_root", Value::Text(self.outbox_root.clone())),
            ("principal", Value::Text(self.principal.clone())),
            ("target_kind", Value::Text(self.target_kind.clone())),
            ("complete", Value::BigInt(self.complete)),
            ("row_count", Value::BigInt(self.row_count)),
            ("content_digest", Value::Text(self.content_digest.clone())),
        ]
    }

    fn from_row(row: &Row) -> sqlmodel_core::Result<Self> {
        Ok(Self {
            singleton: row.get_named("singleton")?,
            profile: row.get_named("profile")?,
            schema_generation: row.get_named("schema_generation")?,
            tenant: row.get_named("tenant")?,
            repository: row.get_named("repository")?,
            incarnation: row.get_named("incarnation")?,
            authority_head: row.get_named("authority_head")?,
            authority_head_generation: row.get_named("authority_head_generation")?,
            forge_position_root: row.get_named("forge_position_root")?,
            outbox_root: row.get_named("outbox_root")?,
            principal: row.get_named("principal")?,
            target_kind: row.get_named("target_kind")?,
            complete: row.get_named("complete")?,
            row_count: row.get_named("row_count")?,
            content_digest: row.get_named("content_digest")?,
        })
    }

    fn primary_key_value(&self) -> Vec<Value> {
        vec![Value::BigInt(self.singleton)]
    }
    fn is_new(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredThread {
    thread_number: i64,
    thread_version: i64,
    preference_version: Option<i64>,
    read_through: Option<i64>,
    latest_other_version: Option<i64>,
    reason_mask: i64,
    muted: i64,
    unread: i64,
}

impl StoredThread {
    pub fn from_input(row: &InboxRow) -> Result<Self, InboxError> {
        Ok(Self {
            thread_number: checked_counter("thread_number", row.thread_number)?,
            thread_version: checked_counter("thread_version", row.thread_version)?,
            preference_version: row
                .preference_version
                .map(|value| checked_counter("preference_version", value))
                .transpose()?,
            read_through: row
                .read_through
                .map(|value| checked_counter("read_through", value))
                .transpose()?,
            latest_other_version: row
                .latest_other_version
                .map(|value| checked_counter("latest_other_version", value))
                .transpose()?,
            reason_mask: row
                .reasons
                .iter()
                .fold(0, |mask, reason| mask | reason.bit()),
            muted: i64::from(row.muted),
            unread: i64::from(row.unread()),
        })
    }

    pub fn into_output(self) -> Result<InboxRow, InboxError> {
        let unsigned = |value| u64::try_from(value).map_err(|_| InboxRefusal::CorruptRow);
        if !(0..=15).contains(&self.reason_mask)
            || !(0..=1).contains(&self.muted)
            || !(0..=1).contains(&self.unread)
        {
            return Err(InboxRefusal::CorruptRow.into());
        }
        let mut row = InboxRow {
            thread_number: unsigned(self.thread_number)?,
            thread_version: unsigned(self.thread_version)?,
            preference_version: self.preference_version.map(unsigned).transpose()?,
            read_through: self.read_through.map(unsigned).transpose()?,
            latest_other_version: self.latest_other_version.map(unsigned).transpose()?,
            reasons: [
                InboxReason::Author,
                InboxReason::Participant,
                InboxReason::Assignee,
                InboxReason::Subscribed,
            ]
            .into_iter()
            .filter(|reason| self.reason_mask & reason.bit() != 0)
            .collect(),
            muted: self.muted == 1,
        };
        row.normalize().map_err(|_| InboxRefusal::CorruptRow)?;
        if row.unread() != (self.unread == 1) {
            return Err(InboxRefusal::CorruptRow.into());
        }
        Ok(row)
    }
}

impl Model for StoredThread {
    const TABLE_NAME: &'static str = "fgit_thread_inbox_thread";
    const PRIMARY_KEY: &'static [&'static str] = &["thread_number"];

    fn fields() -> &'static [FieldInfo] {
        const FIELDS: &[FieldInfo] = &[
            FieldInfo::new("thread_number", "thread_number", SqlType::BigInt).primary_key(true),
            FieldInfo::new("thread_version", "thread_version", SqlType::BigInt),
            FieldInfo::new("preference_version", "preference_version", SqlType::BigInt)
                .nullable(true),
            FieldInfo::new("read_through", "read_through", SqlType::BigInt).nullable(true),
            FieldInfo::new(
                "latest_other_version",
                "latest_other_version",
                SqlType::BigInt,
            )
            .nullable(true),
            FieldInfo::new("reason_mask", "reason_mask", SqlType::BigInt),
            FieldInfo::new("muted", "muted", SqlType::BigInt),
            FieldInfo::new("unread", "unread", SqlType::BigInt),
        ];
        FIELDS
    }

    fn to_row(&self) -> Vec<(&'static str, Value)> {
        let optional = |value: Option<i64>| value.map_or(Value::Null, Value::BigInt);
        vec![
            ("thread_number", Value::BigInt(self.thread_number)),
            ("thread_version", Value::BigInt(self.thread_version)),
            ("preference_version", optional(self.preference_version)),
            ("read_through", optional(self.read_through)),
            ("latest_other_version", optional(self.latest_other_version)),
            ("reason_mask", Value::BigInt(self.reason_mask)),
            ("muted", Value::BigInt(self.muted)),
            ("unread", Value::BigInt(self.unread)),
        ]
    }

    fn from_row(row: &Row) -> sqlmodel_core::Result<Self> {
        Ok(Self {
            thread_number: row.get_named("thread_number")?,
            thread_version: row.get_named("thread_version")?,
            preference_version: row.get_named("preference_version")?,
            read_through: row.get_named("read_through")?,
            latest_other_version: row.get_named("latest_other_version")?,
            reason_mask: row.get_named("reason_mask")?,
            muted: row.get_named("muted")?,
            unread: row.get_named("unread")?,
        })
    }

    fn primary_key_value(&self) -> Vec<Value> {
        vec![Value::BigInt(self.thread_number)]
    }
    fn is_new(&self) -> bool {
        false
    }
}

pub(super) fn read_count(row: Option<&Row>) -> Result<i64, InboxError> {
    row.and_then(|row| row.get_by_name("row_count"))
        .and_then(Value::as_i64)
        .ok_or_else(|| InboxRefusal::IncompleteSnapshot.into())
}
