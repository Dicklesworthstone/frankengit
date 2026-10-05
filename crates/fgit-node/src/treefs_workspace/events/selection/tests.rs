//! Exact I/O and failure boundaries through the production selection helper.
//! MemoryAuthorityStore cases are reference tests, not durable-node evidence.
mod support;
use super::*;
use support::{Fixture, ready};
use fgit_authority::{AuthorityStore, HeadReadReceipt};
use fgit_codec::{HiddenRefPolicyBody, encode_body};
use fgit_types::HeadGeneration;

#[test]
fn selection_reads_only_head_configuration_and_optional_hidden_policy() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for with_policy in [false, true] {
            let f = Fixture::new(format, with_policy);
            let selected = f.select(f.binding, None).unwrap();
            assert_eq!(selected.basis.id(), f.head_id());
            assert_eq!(selected.basis.body(), &f.head);
            assert_eq!(f.store.head_reads(), 1);
            let keys = f.store.keys();
            assert_eq!(keys.len(), if with_policy { 2 } else { 1 });
            assert_eq!(keys[0], f.configuration_key());
            if with_policy { assert_eq!(keys[1], f.policy_key()); }
            // The fixture has no ref, closure, outcome, outbox or retention
            // bodies. Reading any of them would turn this success into failure.
            assert_eq!(selected.hidden_refs.hides(b"refs/heads/private/topic"), with_policy);
            assert!(!selected.hidden_refs.hides(b"refs/heads/public"));
            assert!(!selected.hidden_refs.hides(b"refs/heads/private/open"));
        }
    }
}

#[test]
fn unknown_head_and_stale_pin_refuse_before_any_configuration_read() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, true);
    let other = Fixture::new(GitHashAlgorithm::Sha256, false);
    let error = f.select(f.binding, Some(other.head_id())).err().unwrap();
    assert!(matches!(error, ForgeEventReadRefusal::SnapshotMoved));
    assert!(f.store.keys().is_empty());
    let key = HeadKey::new(b"never-initialized".to_vec()).unwrap();
    assert!(ready(read_basis(&f.store, &(), &key, f.binding, None, &|| false)).is_err());
    assert!(f.store.keys().is_empty());
    assert!(f.select(f.binding, Some(f.head_id())).is_ok());
}

#[test]
fn repository_incarnation_and_object_format_are_independent_binding_checks() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, true);
    for wrong in [
        Binding { repository: RepositoryId::from_bytes([4; 16]), ..f.binding },
        Binding { incarnation: RepositoryIncarnationId::from_bytes([4; 16]), ..f.binding },
        Binding { format: GitHashAlgorithm::Sha256, ..f.binding },
    ] {
        let error = f.select(wrong, None).err().unwrap();
        assert!(matches!(error, ForgeEventReadRefusal::RepositoryBindingMismatch));
        assert_eq!(error.public_code(), "event_read_unavailable");
        assert!(f.select(f.binding, None).is_ok());
    }
}

#[test]
fn missing_corrupt_or_valid_but_different_configuration_never_becomes_defaults() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, true);
    let mut other = f.configuration;
    other.object_format = GitHashAlgorithm::Sha256;
    for replacement in [None, Some(vec![0]), Some(encode_body(&other).unwrap())] {
        f.store.replace(f.configuration_key(), replacement);
        assert!(f.select(f.binding, None).is_err());
        f.store.clear_fault();
        assert!(f.select(f.binding, None).is_ok());
    }
}

#[test]
fn missing_corrupt_or_replayed_empty_policy_never_unhides_a_ref() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, true);
    let empty = encode_body(&HiddenRefPolicyBody { rules: Vec::new() }).unwrap();
    for replacement in [None, Some(vec![0]), Some(empty)] {
        f.store.replace(f.policy_key(), replacement);
        assert!(f.select(f.binding, None).is_err());
        f.store.clear_fault();
        let selected = f.select(f.binding, None).unwrap();
        assert!(selected.hidden_refs.hides(b"refs/heads/private/topic"));
    }
}

#[test]
fn no_cached_policy_survives_a_new_failed_read() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, true);
    assert!(f.select(f.binding, None).is_ok());
    f.store.replace(f.policy_key(), None);
    assert!(f.select(f.binding, None).is_err());
    f.store.clear_fault();
    let first = f.select(f.binding, None).unwrap();
    let second = f.select(f.binding, None).unwrap();
    assert_eq!(first.basis.id(), second.basis.id());
    for name in [b"refs/heads/private/topic".as_slice(), b"refs/heads/private/open", b"refs/heads/public"] {
        assert_eq!(first.hidden_refs.hides(name), second.hidden_refs.hides(name));
    }
}

#[test]
fn cancellation_at_each_io_checkpoint_returns_no_selection_and_retry_succeeds() {
    for stop_after in 0..=4 {
        let f = Fixture::new(GitHashAlgorithm::Sha1, true);
        let error = ready(read_basis(&f.store, &(), &f.key, f.binding, None,
            &|| f.store.calls() >= stop_after)).err().unwrap();
        assert!(matches!(error, ForgeEventReadRefusal::Cancelled));
        assert_eq!(f.store.calls(), stop_after);
        assert!(f.select(f.binding, None).is_ok());
    }
}

#[test]
fn a_forged_receipt_is_rejected_by_the_actual_store_authenticator() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, true);
    let fgit_authority::HeadRead::Present(original) = f.store.backend.read_head(&f.key).unwrap() else {
        panic!("fixture has a head")
    };
    let mut changed = f.head.clone();
    changed.repository_id = RepositoryId::from_bytes([9; 16]);
    let forged = HeadReadReceipt::new(
        f.key.clone(), original.token(), HeadGeneration::FIRST, encode_body(&changed).unwrap(),
    );
    *f.store.head_override.lock().unwrap() = Some(forged);
    assert!(f.select(f.binding, None).is_err());
    assert!(f.store.keys().is_empty());
    *f.store.head_override.lock().unwrap() = None;
    assert!(f.select(f.binding, None).is_ok());
}

#[test]
fn historical_configuration_minor_remains_supported_without_inventing_policy() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, false);
    f.use_historical_configuration();
    let selected = f.select(f.binding, None).unwrap();
    assert_eq!(selected.basis.id(), f.head_id());
    assert!(!selected.hidden_refs.hides(b"refs/heads/private/topic"));
    assert_eq!(f.store.keys().len(), 1);
}

#[test]
fn reopened_native_nodes_share_raw_and_scoped_event_bytes_without_publication() {
    use fgit_authority::IdempotencyKey;
    use fgit_forge::{ExpectedVersion, IssueNumber, event::issue::{IssueAction, IssueCommand}};
    use crate::{LoopbackReceiveSession, NodeConfig};
    use fgit_types::{DecisionOutcome, PrincipalId, TenantId};
    use std::{fs, sync::atomic::{AtomicU64, Ordering}};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch(std::env::temp_dir().join(format!("fg-event-basis-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
        fs::create_dir(&scratch.0).unwrap();
        let config = NodeConfig::new(scratch.0.join("node"), TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16])).with_object_format(format).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let command = IssueCommand {
            number: IssueNumber::try_new(1).unwrap(), expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open { title: "Event basis".into(), body: "Exact history".into(), labels: Vec::new() },
        };
        let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xc3; 16]),
            IdempotencyKey::new(b"event-basis-seed".to_vec()).unwrap());
        let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(
            &request, &session, &command, Default::default(),
        )).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let raw = node.runtime().block_on(node.read_forge_events_in(&request, None, 5, None)).unwrap();
        let scoped = node.runtime().block_on(node.read_scoped_forge_events_in(
            &request, None, 5, Some(raw.source_head), true, false,
        )).unwrap();
        assert_eq!(raw.events.len(), 1);
        assert_eq!(scoped.events().len(), 1);
        assert_eq!(scoped.source_head(), raw.source_head);
        let expected: String = encode_body(&raw.events[0].event).unwrap().iter()
            .map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(scoped.events()[0].frame_hex(), expected);
        let end = node.runtime().block_on(node.read_scoped_forge_events_in(
            &request, scoped.resume_after(), 5, Some(raw.source_head), true, false,
        )).unwrap();
        assert!(end.events().is_empty());
        assert_eq!(end.resume_after(), scoped.resume_after());
        let ungranted = node.runtime().block_on(node.read_scoped_forge_events_in(
            &request, None, 5, None, false, false,
        ));
        assert!(matches!(ungranted, Err(ForgeEventReadRefusal::NoReadScope)));
        let final_page = node.runtime().block_on(node.read_forge_events_in(
            &request, None, 5, Some(raw.source_head),
        )).unwrap();
        assert_eq!(raw, final_page, "reads, EOF and refusals must not publish");
        node.shutdown().unwrap();
    }
}
