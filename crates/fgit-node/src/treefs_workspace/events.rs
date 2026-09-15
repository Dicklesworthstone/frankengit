//! Repository-wide canonical forge event feed for local integrations.
use super::workspace_request_live;
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::feed::{self, ForgeEventCursor, ForgeEventPage};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};

#[derive(Debug)]
pub enum ForgeEventReadRefusal {
    InvalidLimit,
    SnapshotMoved,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<fgit_admission::AdmissionError>),
}
impl std::fmt::Display for ForgeEventReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "forge event feed refused: {self:?}")
    }
}
impl std::error::Error for ForgeEventReadRefusal {}

impl OneNode {
    /// Read committed forge events in repository order from canonical authority
    /// history. A cursor remains valid when the repository advances; supplying
    /// `expected_head` instead freezes pagination to one exact authority head.
    /// This trusted-local read grants no mutation authority and maintains no
    /// second event database or process-local cursor state.
    pub async fn read_forge_events_in(
        &self,
        request: &NodeRequestContext,
        after: Option<ForgeEventCursor>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<ForgeEventPage, ForgeEventReadRefusal> {
        if limit == 0 || limit > 100 {
            return Err(ForgeEventReadRefusal::InvalidLimit);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(ForgeEventReadRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| ForgeEventReadRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(ForgeEventReadRefusal::SnapshotMoved);
        }
        feed::read_page_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            after,
            limit,
            &|| !workspace_request_live(request),
        )
        .await
        .map_err(|error| ForgeEventReadRefusal::Admission(Box::new(error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoopbackReceiveSession, NodeConfig};
    use fgit_admission::AdmissionLimits;
    use fgit_authority::{IdempotencyKey, TerminalOutcome};
    use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber};
    use fgit_forge::event::{ForgeEventPayload, issue::{IssueAction, IssueCommand}};
    use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId, TxId};
    use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fg-forge-feed-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
            NodeConfig::new(
                self.0.join("node"),
                TenantId::from_bytes([0xa1; 16]),
                RepositoryId::from_bytes([0xa2; 16]),
            )
            .with_object_format(format)
            .with_worker_threads(2)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn actor() -> PrincipalId {
        PrincipalId::from_bytes([0xa3; 16])
    }
    fn session(key: &str) -> LoopbackReceiveSession {
        LoopbackReceiveSession::authenticated(
            actor(),
            IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
        )
    }
    fn open() -> IssueCommand {
        IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Feed fixture".into(),
                body: "canonical history".into(),
                labels: vec!["integration".into()],
            },
        }
    }
    fn change(version: u64, action: IssueAction) -> IssueCommand {
        IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap()),
            action,
        }
    }
    fn publish(node: &OneNode, command: &IssueCommand, key: &str) -> (TxId, TerminalOutcome) {
        let request = node.request_context();
        let result = node.runtime().block_on(node.admit_issue_durable_in(
            &request,
            &session(key),
            command,
            AdmissionLimits::default(),
        )).unwrap();
        assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }), "{result:?}");
        result
    }
    fn page(
        node: &OneNode,
        after: Option<ForgeEventCursor>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<ForgeEventPage, ForgeEventReadRefusal> {
        let request = node.request_context();
        node.runtime().block_on(node.read_forge_events_in(
            &request,
            after,
            limit,
            expected_head,
        ))
    }

    #[test]
    fn refusal_vocabulary_distinguishes_input_and_snapshot_movement() {
        assert!(
            ForgeEventReadRefusal::InvalidLimit
                .to_string()
                .contains("InvalidLimit")
        );
        assert!(
            ForgeEventReadRefusal::SnapshotMoved
                .to_string()
                .contains("SnapshotMoved")
        );
    }

    #[test]
    fn forge_event_feed_is_paginated_append_stable_snapshot_pinnable_and_durable() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let scratch = Scratch::new();
            let config = scratch.config(format);
            let (mut node, _) = OneNode::init(config.clone()).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();

            let opened = publish(&node, &open(), "open");
            let comment = change(1, IssueAction::Comment { body: "first comment".into() });
            let commented = publish(&node, &comment, "comment");

            let first = page(&node, None, 1, None).unwrap();
            assert_eq!(first.events.len(), 1);
            assert_eq!(first.events[0].tx_id, opened.0);
            assert!(matches!(
                first.events[0].event.payload,
                ForgeEventPayload::IssueChangedNative(ref change)
                    if matches!(change.action, IssueAction::Open { .. })
            ));
            let first_cursor = first.events[0].cursor;
            assert_eq!(first.next_after, Some(first_cursor));

            let second = page(&node, Some(first_cursor), 1, Some(first.source_head)).unwrap();
            assert_eq!(second.events.len(), 1);
            assert_eq!(second.events[0].tx_id, commented.0);
            assert!(matches!(
                second.events[0].event.payload,
                ForgeEventPayload::IssueChangedNative(ref change)
                    if matches!(change.action, IssueAction::Comment { .. })
            ));
            assert!(second.next_after.is_none());
            let second_cursor = second.events[0].cursor;

            // Exact retries never manufacture a duplicate event.
            assert_eq!(publish(&node, &comment, "comment"), commented);
            assert!(page(&node, Some(second_cursor), 10, None).unwrap().events.is_empty());

            let closed = publish(&node, &change(2, IssueAction::Close), "close");
            assert!(matches!(
                page(&node, Some(second_cursor), 10, Some(first.source_head)),
                Err(ForgeEventReadRefusal::SnapshotMoved)
            ));
            let advanced = page(&node, Some(second_cursor), 10, None).unwrap();
            assert_eq!(advanced.events.len(), 1);
            assert_eq!(advanced.events[0].tx_id, closed.0);
            assert!(matches!(
                advanced.events[0].event.payload,
                ForgeEventPayload::IssueChangedNative(ref change)
                    if matches!(change.action, IssueAction::Close)
            ));
            assert!(advanced.events[0].cursor > second_cursor);
            assert!(advanced.next_after.is_none());

            // A syntactically valid cursor must still name a real event.
            assert!(matches!(
                page(
                    &node,
                    Some(ForgeEventCursor {
                        repository_sequence: first_cursor.repository_sequence,
                        event_index: u32::MAX,
                    }),
                    10,
                    None,
                ),
                Err(ForgeEventReadRefusal::Admission(_))
            ));

            let last_cursor = advanced.events[0].cursor;
            node.shutdown().unwrap();
            let mut reopened = OneNode::open_existing(config).unwrap();
            reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
            let replay = page(&reopened, Some(first_cursor), 10, None).unwrap();
            assert_eq!(replay.events.len(), 2);
            assert_eq!(replay.events[0].cursor, second_cursor);
            assert_eq!(replay.events[1].cursor, last_cursor);
            assert_eq!(replay.events[0].tx_id, commented.0);
            assert_eq!(replay.events[1].tx_id, closed.0);
            assert!(page(&reopened, Some(last_cursor), 10, None).unwrap().events.is_empty());
            reopened.shutdown().unwrap();
        }
    }
}
