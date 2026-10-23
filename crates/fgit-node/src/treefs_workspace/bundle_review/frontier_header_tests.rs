//! Real fabric envelope checks, distinct from reads that disclose verified bytes.
use super::*;
use std::path::{Path, PathBuf};

fn stored(root: &Path, id: GitOid) -> PathBuf {
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    let name = id.to_string();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name() == name.as_str() {
                found.push(entry.path());
            }
        }
    }
    assert_eq!(found.len(), 1, "one isolated fixture object");
    found.pop().unwrap()
}

#[test]
fn reused_edge_checks_read_graph_evidence_but_never_charge_undisclosed_blob_payloads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let exhaustion = Cell::new(None);
        let budget = ReadBudget {
            bytes: Cell::new(0),
            exhausted: Cell::new(false),
        };
        let original = OriginalSource::with_parents(
            VerifiedFabricPackSource {
                fabric: &node.fabric,
                object_format: format,
                maximum_object_bytes: 4096,
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected.selected_closure().closure().objects(),
            &budget,
            &[f.target],
            MergeObjectLimits::default(),
        )
        .unwrap();
        assert!(original.permits(f.keep).unwrap());
        let graph_bytes = budget.bytes.get();
        assert!(graph_bytes > 0);
        for _ in 0..4 {
            original.verify_reused(f.keep, ObjectType::Blob).unwrap();
        }
        assert_eq!(budget.bytes.get(), graph_bytes);
        assert!(
            matches!(original.verify_reused(f.keep, ObjectType::Tree), Err(MergeSourceError::InvalidObject(id)) if id == f.keep)
        );
        assert_eq!(budget.bytes.get(), graph_bytes);
        assert_eq!(
            original.read(f.keep).unwrap(),
            (ObjectType::Blob, b"preserved sibling\n".to_vec())
        );
        assert_eq!(
            budget.bytes.get(),
            graph_bytes + b"preserved sibling\n".len()
        );
        budget.exhausted.set(true);
        assert_eq!(
            original.verify_reused(f.keep, ObjectType::Blob),
            Err(MergeSourceError::BudgetExceeded)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn cumulative_membership_never_substitutes_for_parent_disclosure_or_expected_kind() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let exhaustion = Cell::new(None);
        let budget = ReadBudget {
            bytes: Cell::new(0),
            exhausted: Cell::new(false),
        };
        let original = OriginalSource::with_parents(
            VerifiedFabricPackSource {
                fabric: &node.fabric,
                object_format: format,
                maximum_object_bytes: 4096,
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected.selected_closure().closure().objects(),
            &budget,
            &[f.target],
            MergeObjectLimits::default(),
        )
        .unwrap();
        assert!(original.allowed.contains(&f.secret));
        assert_eq!(
            original.verify_reused(f.secret, ObjectType::Blob),
            Err(MergeSourceError::OutsideSelection)
        );
        original
            .verify_reused(f.original, ObjectType::Blob)
            .unwrap();
        let outside = git_object_id(format, ObjectType::Blob, b"absent");
        let before = budget.bytes.get();
        assert_eq!(
            original.verify_reused(outside, ObjectType::Blob),
            Err(MergeSourceError::OutsideSelection)
        );
        assert_eq!(budget.bytes.get(), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn envelope_failures_refuse_beside_a_permitted_twin_without_claiming_a_payload_scrub() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node, f) = fixture(format);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let exhaustion = Cell::new(None);
        let budget = ReadBudget {
            bytes: Cell::new(0),
            exhausted: Cell::new(false),
        };
        let original = OriginalSource::with_parents(
            VerifiedFabricPackSource {
                fabric: &node.fabric,
                object_format: format,
                maximum_object_bytes: 4096,
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected.selected_closure().closure().objects(),
            &budget,
            &[f.target],
            MergeObjectLimits::default(),
        )
        .unwrap();
        let path = stored(&scratch.0, f.keep);
        let exact = std::fs::read(&path).unwrap();
        original.verify_reused(f.keep, ObjectType::Blob).unwrap();
        let before = budget.bytes.get();
        let mut malformed = exact.clone();
        malformed[0] ^= 1;
        std::fs::write(&path, &malformed).unwrap();
        assert!(
            matches!(original.verify_reused(f.keep, ObjectType::Blob), Err(MergeSourceError::Unavailable(id)) if id == f.keep)
        );
        std::fs::write(&path, &exact).unwrap();
        original.verify_reused(f.keep, ObjectType::Blob).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(
            matches!(original.verify_reused(f.keep, ObjectType::Blob), Err(MergeSourceError::Unavailable(id)) if id == f.keep)
        );
        std::fs::write(&path, &exact).unwrap();
        original.verify_reused(f.keep, ObjectType::Blob).unwrap();
        let mut payload = exact.clone();
        *payload.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &payload).unwrap();
        // Reused metadata is not a scrub certificate. Any actual disclosure
        // still detects changed bytes using the original verified read path.
        original.verify_reused(f.keep, ObjectType::Blob).unwrap();
        assert_eq!(budget.bytes.get(), before);
        assert!(original.read(f.keep).is_err());
        std::fs::write(&path, &exact).unwrap();
        assert_eq!(original.read(f.keep).unwrap().1, b"preserved sibling\n");
        node.shutdown().unwrap();
    }
}
