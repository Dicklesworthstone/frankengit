//! Subscriber-scoped diagnostics: real files, stale handles, and refusal twins.
use super::*;
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-webhook-subscribers-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self) -> PathBuf {
        self.0.join("dead_letters.jsonl")
    }
    fn open(&self) -> DeadLetterQueue {
        DeadLetterQueue::try_with_persist_path(self.path()).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn letter(subscriber: u64) -> DeadLetterEntry {
    DeadLetterEntry {
        delivery_id: AsciiSlug::from_static("shared-canonical-delivery"),
        webhook_id: WebhookId(subscriber),
        target_url: format!("http://subscriber-{subscriber}.example/hook"),
        payload_root: Digest::new(
            DigestAlgorithmId::try_new(2).unwrap(),
            DigestBytes::try_new(&[0x17; 32]).unwrap(),
        ),
        event_name: "issue".into(),
        attempts: 3,
        terminal_reason: "receiver unavailable".into(),
        failed_at_unix_secs: 7,
    }
}

#[test]
fn both_subscribers_retain_one_canonical_delivery_after_restart() {
    let dir = Directory::new();
    let first = dir.open();
    let second = dir.open();
    first.try_push(letter(1)).unwrap();
    // The old single-subscriber representation remains byte-identical.
    assert_eq!(
        std::fs::read_to_string(dir.path()).unwrap(),
        format!("{}\n", serialize_dead_letter(&letter(1)))
    );
    second.try_push(letter(2)).unwrap();
    let reopened = dir.open();
    assert_eq!(reopened.list(), vec![letter(1), letter(2)]);
    for id in [1, 2] {
        assert_eq!(
            reopened.get_for(WebhookId(id), letter(id).delivery_id),
            Some(letter(id))
        );
    }
    assert_eq!(
        reopened.get(letter(1).delivery_id),
        None,
        "unscoped reads cannot select a subscriber"
    );
}

#[test]
fn stale_handles_update_only_their_subscribers_attempts() {
    let dir = Directory::new();
    let first = dir.open();
    let second = dir.open();
    first.try_push(letter(1)).unwrap();
    second.try_push(letter(2)).unwrap();
    let mut latest = letter(1);
    latest.attempts = 4;
    latest.failed_at_unix_secs = 9;
    latest.terminal_reason = "still unavailable".into();
    first.try_push(latest.clone()).unwrap();
    let reopened = dir.open();
    assert_eq!(reopened.list().len(), 2);
    assert_eq!(
        reopened.get_for(WebhookId(1), latest.delivery_id),
        Some(latest)
    );
    assert_eq!(
        reopened.get_for(WebhookId(2), letter(2).delivery_id),
        Some(letter(2))
    );
}

#[test]
fn ambiguous_legacy_removal_checks_reloaded_state_and_changes_nothing() {
    let dir = Directory::new();
    let old = dir.open();
    old.try_push(letter(1)).unwrap();
    dir.open().try_push(letter(2)).unwrap();
    let bytes = std::fs::read(dir.path()).unwrap();
    assert_eq!(
        old.get(letter(1).delivery_id),
        Some(letter(1)),
        "a deliberately stale snapshot"
    );
    let error = old.try_remove(letter(1).delivery_id).unwrap_err();
    assert!(error.starts_with("AmbiguousDelivery:"), "{error}");
    assert_eq!(std::fs::read(dir.path()).unwrap(), bytes);
    assert_eq!(old.get(letter(1).delivery_id), Some(letter(1)));
    assert_eq!(old.remove(letter(1).delivery_id), None);
    assert_eq!(std::fs::read(dir.path()).unwrap(), bytes);
    assert_eq!(
        old.try_remove_for(WebhookId(1), letter(1).delivery_id)
            .unwrap(),
        Some(letter(1))
    );
    assert_eq!(dir.open().list(), vec![letter(2)]);
    assert!(old.persistence_error().is_none());
}

#[test]
fn scoped_removal_never_consumes_another_subscribers_evidence() {
    let dir = Directory::new();
    let store = WebhookStore::open(dir.0.clone()).unwrap();
    store.dead_letters().try_push(letter(1)).unwrap();
    store.dead_letters().try_push(letter(2)).unwrap();
    assert_eq!(
        store.get_dead_letter_for(WebhookId(3), letter(1).delivery_id),
        None
    );
    assert_eq!(
        store
            .try_remove_dead_letter_for(WebhookId(3), letter(1).delivery_id)
            .unwrap(),
        None
    );
    assert_eq!(store.list_dead_letters().len(), 2);
    assert_eq!(
        store
            .try_remove_dead_letter_for(WebhookId(2), letter(2).delivery_id)
            .unwrap(),
        Some(letter(2))
    );
    assert_eq!(
        store.get_dead_letter_for(WebhookId(1), letter(1).delivery_id),
        Some(letter(1))
    );
    assert_eq!(dir.open().list(), vec![letter(1)]);
}

#[test]
fn payload_binding_is_shared_but_endpoint_binding_is_per_subscriber() {
    let dir = Directory::new();
    let queue = dir.open();
    queue.try_push(letter(1)).unwrap();
    queue.try_push(letter(2)).unwrap();
    let before = std::fs::read(dir.path()).unwrap();
    for subscriber in [1, 2, 3] {
        let mut changed = letter(subscriber);
        changed.payload_root = Digest::new(
            changed.payload_root.algorithm(),
            DigestBytes::try_new(&[0x18; 32]).unwrap(),
        );
        assert!(queue.try_push(changed).is_err());
        let mut changed = letter(subscriber);
        changed.event_name = "pull_request".into();
        assert!(queue.try_push(changed).is_err());
        assert_eq!(std::fs::read(dir.path()).unwrap(), before);
    }
    for subscriber in [1, 2] {
        let mut changed = letter(subscriber);
        changed.target_url.push_str("/other");
        assert!(queue.try_push(changed).is_err());
        assert_eq!(std::fs::read(dir.path()).unwrap(), before);
    }
    queue.try_push(letter(3)).unwrap();
    assert_eq!(dir.open().list().len(), 3);
}

#[test]
fn composite_duplicate_and_inconsistent_payload_rows_fail_closed() {
    let dir = Directory::new();
    let first = serialize_dead_letter(&letter(1));
    let mut changed = letter(2);
    changed.event_name = "different".into();
    for second in [first.clone(), serialize_dead_letter(&changed)] {
        let bytes = format!("{first}\n{second}\n");
        std::fs::write(dir.path(), &bytes).unwrap();
        assert!(DeadLetterQueue::try_with_persist_path(dir.path()).is_err());
        assert_eq!(std::fs::read_to_string(dir.path()).unwrap(), bytes);
    }
    let bytes = format!("{first}\n{}\n", serialize_dead_letter(&letter(2)));
    std::fs::write(dir.path(), bytes).unwrap();
    assert_eq!(
        dir.open().list().len(),
        2,
        "same payload, two distinct subscribers is permitted"
    );
}

#[test]
fn scoped_removal_preserves_evidence_when_writer_fence_is_busy() {
    let dir = Directory::new();
    let queue = dir.open();
    queue.try_push(letter(1)).unwrap();
    queue.try_push(letter(2)).unwrap();
    let before = std::fs::read(dir.path()).unwrap();
    let lock = lock_writer(&dir.path()).unwrap();
    assert!(
        queue
            .try_remove_for(WebhookId(1), letter(1).delivery_id)
            .is_err()
    );
    assert_eq!(std::fs::read(dir.path()).unwrap(), before);
    assert_eq!(queue.list().len(), 2);
    drop(lock);
    assert_eq!(
        queue
            .try_remove_for(WebhookId(1), letter(1).delivery_id)
            .unwrap(),
        Some(letter(1))
    );
    assert_eq!(dir.open().list(), vec![letter(2)]);
}

#[test]
fn legacy_single_subscriber_and_memory_only_queues_keep_their_contract() {
    let queue = DeadLetterQueue::new();
    queue.try_push(letter(1)).unwrap();
    assert_eq!(queue.get(letter(1).delivery_id), Some(letter(1)));
    assert_eq!(
        queue.try_remove(letter(1).delivery_id).unwrap(),
        Some(letter(1))
    );
    queue.try_push(letter(1)).unwrap();
    queue.try_push(letter(2)).unwrap();
    assert_eq!(queue.get(letter(1).delivery_id), None);
    assert!(queue.try_remove(letter(1).delivery_id).is_err());
    assert_eq!(
        queue
            .try_remove_for(WebhookId(2), letter(2).delivery_id)
            .unwrap(),
        Some(letter(2))
    );
    assert_eq!(
        queue.try_remove(letter(1).delivery_id).unwrap(),
        Some(letter(1))
    );
}

#[test]
fn every_subscriber_counts_toward_the_existing_store_budget() {
    let dir = Directory::new();
    let bytes = (0..MAX_RECORDS as u64)
        .map(|id| format!("{}\n", serialize_dead_letter(&letter(id))))
        .collect::<String>();
    std::fs::write(dir.path(), &bytes).unwrap();
    let queue = dir.open();
    assert_eq!(queue.list().len(), MAX_RECORDS);
    assert!(queue.try_push(letter(MAX_RECORDS as u64)).is_err());
    assert_eq!(std::fs::read_to_string(dir.path()).unwrap(), bytes);
    assert_eq!(queue.list().len(), MAX_RECORDS);
}
