use super::super::tests::{body_path, publish, publish_ref, run, setup};
use super::*;
use fgit_types::GitHashAlgorithm;
use std::fs;

fn pages() -> ScrubQuery {
    ScrubQuery {
        max_page_objects: 2,
        max_findings: 1,
        ..Default::default()
    }
}

#[test]
fn session_pages_match_stateless_oracle_with_damage_in_both_git_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for damaged in [false, true] {
            let (scratch, node) = setup(format);
            let (objects, extra) = publish(&node);
            if damaged {
                fs::remove_file(body_path(&scratch.0, extra[0])).unwrap();
                fs::write(body_path(&scratch.0, extra[1]), b"damaged session object").unwrap();
            }
            let before = node.runtime().block_on(node.read_authority_head()).unwrap();
            let request = node.request_context();
            let mut session = node
                .runtime()
                .block_on(node.begin_selected_object_scrub_local_in(&request, pages()))
                .unwrap();
            let mut query = pages();
            let mut checked = 0;
            let mut findings = 0;
            while let Some(page) = node.runtime().block_on(session.next_page()).unwrap() {
                let oracle = run(&node, &query).unwrap();
                assert_eq!(format!("{page:?}"), format!("{oracle:?}"));
                checked += page.checked_objects();
                findings += page.findings().len();
                query.cursor = page.next_cursor();
            }
            assert_eq!(checked, objects.len());
            assert_eq!(findings, if damaged { 2 } else { 0 });
            assert!(
                node.runtime()
                    .block_on(session.next_page())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                node.runtime().block_on(node.read_authority_head()).unwrap(),
                before
            );
            drop(session);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn current_authority_movement_is_terminal_even_with_identical_membership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node) = setup(format);
        let (objects, _) = publish(&node);
        let request = node.request_context();
        let mut session = node
            .runtime()
            .block_on(node.begin_selected_object_scrub_local_in(&request, pages()))
            .unwrap();
        assert!(
            node.runtime()
                .block_on(session.next_page())
                .unwrap()
                .unwrap()
                .next_cursor()
                .is_some()
        );
        let (same, _) = publish_ref(
            &node,
            b"refs/heads/session-successor",
            b"scrub-session-successor",
        );
        assert_eq!(same, objects);
        assert!(matches!(
            node.runtime().block_on(session.next_page()),
            Err(ScrubRefusal::Audit(GraphAuditRefusal::SnapshotChanged))
        ));
        assert!(matches!(
            node.runtime().block_on(session.next_page()),
            Err(ScrubRefusal::SessionFailed)
        ));
        drop(session);
        assert!(
            run(&node, &ScrubQuery::default())
                .unwrap()
                .entire_selection_verified()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn request_cancellation_after_a_page_does_not_mint_a_new_budget() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha1);
    publish(&node);
    let request = node.request_context();
    let mut session = node
        .runtime()
        .block_on(node.begin_selected_object_scrub_local_in(&request, pages()))
        .unwrap();
    node.runtime()
        .block_on(session.next_page())
        .unwrap()
        .unwrap();
    request.cancel();
    assert!(matches!(
        node.runtime().block_on(session.next_page()),
        Err(ScrubRefusal::Audit(GraphAuditRefusal::Cancelled { .. }))
    ));
    assert!(matches!(
        node.runtime().block_on(session.next_page()),
        Err(ScrubRefusal::SessionFailed)
    ));
    drop(session);
    node.shutdown().unwrap();
}

#[test]
fn session_deadline_is_absolute_across_pages() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha256);
    publish(&node);
    let request = node.request_context();
    let mut session = node
        .runtime()
        .block_on(node.begin_selected_object_scrub_local_in(&request, pages()))
        .unwrap();
    node.runtime()
        .block_on(session.next_page())
        .unwrap()
        .unwrap();
    // Move only the session's clock origin, not any oracle or production bound.
    session.started = Instant::now().checked_sub(session.query.timeout).unwrap();
    assert!(matches!(
        node.runtime().block_on(session.next_page()),
        Err(ScrubRefusal::Audit(GraphAuditRefusal::Deadline))
    ));
    assert!(matches!(
        node.runtime().block_on(session.next_page()),
        Err(ScrubRefusal::SessionFailed)
    ));
    drop(session);
    node.shutdown().unwrap();
}

#[test]
fn page_byte_allowance_may_shrink_but_never_widen() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha256);
    let (objects, _) = publish(&node);
    let first_size = node
        .read_git_object(*objects.first().unwrap())
        .unwrap()
        .payload()
        .len() as u64;
    assert!(first_size > 0);
    let request = node.request_context();
    let mut session = node
        .runtime()
        .block_on(node.begin_selected_object_scrub_local_in(&request, pages()))
        .unwrap();
    let page = node
        .runtime()
        .block_on(session.next_page_with_max_payload_bytes(first_size))
        .unwrap()
        .unwrap();
    let oracle = run(
        &node,
        &ScrubQuery {
            max_payload_bytes: first_size,
            ..pages()
        },
    )
    .unwrap();
    assert_eq!(format!("{page:?}"), format!("{oracle:?}"));
    assert_eq!(page.checked_objects(), 1);
    let too_large = pages().max_payload_bytes + 1;
    assert!(matches!(
        node.runtime()
            .block_on(session.next_page_with_max_payload_bytes(too_large)),
        Err(ScrubRefusal::InvalidLimit("session page payload bytes"))
    ));
    assert!(matches!(
        node.runtime().block_on(session.next_page()),
        Err(ScrubRefusal::SessionFailed)
    ));
    drop(session);
    node.shutdown().unwrap();
}

#[test]
fn retained_membership_does_not_cache_object_health() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node) = setup(format);
        let (objects, _) = publish(&node);
        let request = node.request_context();
        let query = ScrubQuery {
            max_page_objects: 1,
            max_findings: 1,
            ..Default::default()
        };
        let mut session = node
            .runtime()
            .block_on(node.begin_selected_object_scrub_local_in(&request, query))
            .unwrap();
        node.runtime()
            .block_on(session.next_page())
            .unwrap()
            .unwrap();
        let next = *objects.iter().nth(1).unwrap();
        fs::remove_file(body_path(&scratch.0, next)).unwrap();
        let page = node
            .runtime()
            .block_on(session.next_page())
            .unwrap()
            .unwrap();
        assert_eq!(page.findings().len(), 1);
        assert_eq!(page.findings()[0].oid, next);
        assert_eq!(page.verified_objects(), 0);
        drop(session);
        node.shutdown().unwrap();
    }
}

#[test]
fn resumed_session_cannot_claim_unobserved_prefix_coverage() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha1);
    let (objects, _) = publish(&node);
    let first = run(&node, &pages()).unwrap();
    let request = node.request_context();
    let mut session = node
        .runtime()
        .block_on(node.begin_selected_object_scrub_local_in(
            &request,
            ScrubQuery {
                cursor: first.next_cursor(),
                ..pages()
            },
        ))
        .unwrap();
    let mut checked = 0;
    while let Some(page) = node.runtime().block_on(session.next_page()).unwrap() {
        assert!(!page.entire_selection_checked());
        assert!(!page.entire_selection_verified());
        checked += page.checked_objects();
    }
    assert_eq!(checked + first.checked_objects(), objects.len());
    drop(session);
    node.shutdown().unwrap();
}
