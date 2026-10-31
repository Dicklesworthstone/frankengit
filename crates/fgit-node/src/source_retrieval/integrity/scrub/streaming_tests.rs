//! Streaming scrub preserves authority pagination while refusing payload work
//! beyond the caller's page or object envelope.
use super::tests::{body_path, publish, publish_ref_with_payloads, run, setup};
use super::*;
use fgit_types::GitHashAlgorithm;
use std::fs;

#[test]
fn a_corrupt_boundary_payload_is_not_read_or_counted_until_its_next_page() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node) = setup(format);
        let (objects, _) = publish(&node);
        let ordered = objects.iter().copied().collect::<Vec<_>>();
        let first = ordered[0];
        let boundary = ordered[1];
        let first_size = node.read_git_object(first).unwrap().payload().len() as u64;
        let path = body_path(&scratch.0, boundary);
        let original = fs::read(&path).unwrap();
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&path, damaged).unwrap();
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();

        // The first object consumes the whole page. The boundary envelope is
        // inspected, but its corrupt payload must not become a finding here.
        let page = run(
            &node,
            &ScrubQuery {
                max_payload_bytes: first_size,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(page.stop(), ScrubStop::PayloadLimit);
        assert_eq!(page.checked_objects(), 1);
        assert_eq!(page.verified_objects(), 1);
        assert_eq!(page.read_attempts(), 2);
        assert_eq!(page.payload_bytes(), first_size);
        assert!(page.findings().is_empty());
        assert_eq!(page.next_cursor().unwrap().after(), first);
        assert!(!page.entire_selection_verified());

        let next = run(
            &node,
            &ScrubQuery {
                cursor: page.next_cursor(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(next.checked_objects(), objects.len() - 1);
        assert_eq!(next.findings().len(), 1);
        assert_eq!(next.findings()[0].oid, boundary);
        assert!(matches!(
            &next.findings()[0].cause,
            ScrubFindingCause::ObjectRead(_)
        ));
        assert!(!next.entire_selection_verified());
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );

        fs::write(path, original).unwrap();
        assert!(
            run(&node, &ScrubQuery::default())
                .unwrap()
                .entire_selection_verified()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn an_oversized_first_payload_refuses_before_integrity_work_and_a_sufficient_page_checks_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node) = setup(format);
        let (objects, _) = publish(&node);
        let first = *objects.first().unwrap();
        let size = node.read_git_object(first).unwrap().payload().len() as u64;
        assert!(size > 1);
        let path = body_path(&scratch.0, first);
        let original = fs::read(&path).unwrap();
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&path, damaged).unwrap();

        assert!(matches!(
            run(
                &node,
                &ScrubQuery {
                    max_payload_bytes: 1,
                    ..Default::default()
                },
            ),
            Err(ScrubRefusal::ObjectExceedsPage { oid, payload_bytes, maximum: 1 })
                if oid == first && payload_bytes == size
        ));
        let checked = run(&node, &ScrubQuery::default()).unwrap();
        assert!(checked.entire_selection_checked());
        assert_eq!(checked.findings().len(), 1);
        assert_eq!(checked.findings()[0].oid, first);
        assert!(!checked.entire_selection_verified());

        fs::write(path, original).unwrap();
        assert!(
            run(&node, &ScrubQuery::default())
                .unwrap()
                .entire_selection_verified()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn multi_chunk_objects_keep_exact_accounting_and_the_independent_node_ceiling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node) = setup(format);
        let payload = (0..(5 * 64 * 1024 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let large_bytes = payload.len() as u64;
        let (objects, extra) =
            publish_ref_with_payloads(&node, b"refs/heads/streamed", b"streamed-scrub", [payload]);
        let large = extra[0];
        let total = objects
            .iter()
            .map(|oid| node.read_git_object(*oid).unwrap().payload().len() as u64)
            .sum::<u64>();
        let query = ScrubQuery {
            max_payload_bytes: total,
            ..Default::default()
        };
        let complete = run(&node, &query).unwrap();
        assert!(complete.entire_selection_verified());
        assert_eq!(complete.payload_bytes(), total);
        assert_eq!(complete.read_attempts(), objects.len());

        // Seek to the large object through the real exact-head cursor contract.
        let previous = objects.range(..large).next_back().copied();
        assert!(matches!(
            run(
                &node,
                &ScrubQuery {
                    expected_head: Some(complete.head()),
                    cursor: previous.map(|after| ScrubCursor::new(complete.head(), after)),
                    max_payload_bytes: large_bytes - 1,
                    ..Default::default()
                },
            ),
            Err(ScrubRefusal::ObjectExceedsPage { oid, payload_bytes, .. })
                if oid == large && payload_bytes == large_bytes
        ));

        let config = node.service_config.clone();
        node.shutdown().unwrap();
        let mut narrow =
            OneNode::open_existing(config.clone().with_max_object_bytes(64 * 1024)).unwrap();
        narrow.bring_into_service(HeadGeneration::FIRST).unwrap();
        let limited = run(&narrow, &query).unwrap();
        assert!(limited.entire_selection_checked());
        assert!(!limited.entire_selection_verified());
        assert_eq!(limited.findings().len(), 1);
        assert_eq!(limited.findings()[0].oid, large);
        assert!(matches!(
            &limited.findings()[0].cause,
            ScrubFindingCause::ObjectRead(_)
        ));
        assert_eq!(limited.verified_objects(), objects.len() - 1);
        assert_eq!(limited.payload_bytes(), total - large_bytes);
        narrow.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(config).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let recovered = run(&reopened, &query).unwrap();
        assert!(recovered.entire_selection_verified());
        assert_eq!(recovered.payload_bytes(), total);
        reopened.shutdown().unwrap();
    }
}
