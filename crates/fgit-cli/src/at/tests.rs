//! Real authority movement and cancellation at the production read fences.
use super::*;
#[path = "../../../fgit-node/tests/fast_forward_command/fixture.rs"]
mod fixture;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_types::GitHashAlgorithm;
use fixture::*;

fn close(node: &OneNode) {
    let request = node.request_context();
    let page = node
        .runtime()
        .block_on(node.read_pull_requests_in(&request, &Default::default(), 0, 1, None))
        .unwrap();
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: PullRequestAction::Close,
        data: page.pull_requests[0].data.clone().unwrap(),
    };
    committed(
        node.runtime()
            .block_on(node.admit_pull_request_durable_in(
                &request,
                &session(b"snapshot-fence-close"),
                &command,
                Default::default(),
            ))
            .unwrap()
            .1,
    );
}

#[test]
fn actual_head_movement_refuses_initial_materialization_and_final_disclosure() {
    let scratch = Scratch::new();
    let fixture = fixture(&scratch.0, GitHashAlgorithm::Sha256, false);
    assert_ne!(fixture.source, fixture.target);
    let node = fixture.node;
    let request = node.request_context();
    let initial = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    let original = node
        .runtime()
        .block_on(read_in(
            &node,
            &request,
            &initial,
            PositionTarget::Latest,
            None,
            Some("prs"),
            None,
            false,
        ))
        .unwrap();
    assert!(
        matches!(original,CliOutcome::At(AtReport::PullRequests {pull_requests,..}) if pull_requests.len()==1 && pull_requests[0].2=="open")
    );
    close(&node);
    assert!(matches!(
        node.runtime()
            .block_on(ensure_current(&node, &request, &initial)),
        Err(CliRefusal::Snapshot(
            SnapshotRefusal::ConsistencyMismatch { .. }
        ))
    ));
    assert!(matches!(
        node.runtime().block_on(read_in(
            &node,
            &request,
            &initial,
            PositionTarget::Latest,
            None,
            Some("prs"),
            None,
            false
        )),
        Err(CliRefusal::Snapshot(
            SnapshotRefusal::ConsistencyMismatch { .. }
        ))
    ));
    let current = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    let closed = node
        .runtime()
        .block_on(read_in(
            &node,
            &request,
            &current,
            PositionTarget::Latest,
            None,
            Some("prs"),
            None,
            false,
        ))
        .unwrap();
    assert!(
        matches!(closed,CliOutcome::At(AtReport::PullRequests {pull_requests,..}) if pull_requests.len()==1 && pull_requests[0].2=="closed")
    );
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(
        node.runtime()
            .block_on(read_in(
                &node,
                &cancelled,
                &current,
                PositionTarget::Latest,
                None,
                Some("prs"),
                None,
                false
            ))
            .is_err()
    );
    assert_eq!(
        node.runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt(),
        current.receipt()
    );
    node.shutdown().unwrap();
}

#[test]
fn legacy_replay_orders_real_event_versions_and_refuses_conflicting_inventory() {
    let scratch = Scratch::new();
    let fixture = fixture(&scratch.0, GitHashAlgorithm::Sha1, false);
    assert_ne!(fixture.source, fixture.target);
    let node = fixture.node;
    close(&node);
    let request = node.request_context();
    let mut history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    // Exercise the projection's ordering function with authenticated event
    // bodies in inventory order. This rearranged vector is never published or
    // accepted as a substitute for the authority history walk.
    let mut events = history
        .iter()
        .flat_map(|batch| batch.forge_events.iter().cloned())
        .collect::<Vec<_>>();
    events.reverse();
    let last = history.last_mut().unwrap();
    last.forge_events = events;
    order_history(std::slice::from_mut(last), &request).unwrap();
    assert_eq!(last.forge_events.len(), 2);
    assert_eq!(last.forge_events[0].version, AggregateVersion::FIRST);
    assert_eq!(last.forge_events[1].version.get(), 2);
    let mut conflict = last.forge_events[1].clone();
    let ForgeEventPayload::PullRequestChangedNative(change) = &mut conflict.payload else {
        panic!("actual native lifecycle fixture")
    };
    change.data.title.push_str(" conflicting");
    last.forge_events.push(conflict);
    assert!(matches!(
        order_history(std::slice::from_mut(last), &request),
        Err(CliRefusal::Snapshot(
            SnapshotRefusal::ConsistencyMismatch { .. }
        ))
    ));
    node.shutdown().unwrap();
}
