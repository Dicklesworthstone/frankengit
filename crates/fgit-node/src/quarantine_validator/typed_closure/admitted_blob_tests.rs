//! Real immutable fabric; explicit unit selection, not authenticated admission.
//! Raw receive stays full-body. The reviewed profile reuses only typed leaves
//! reached through original visible graph bytes, never uploaded proof edges.
use super::*;
use crate::quarantine_validator::reused_targets::OriginalFrontier;

struct Case {
    original: Vec<Raw>,
    upload: Vec<Raw>,
    base: GitOid,
    blob: GitOid,
    hidden: GitOid,
    candidate: GitOid,
    graph_bytes: usize,
}
fn case(node: &OneNode, format: GitHashAlgorithm) -> Case {
    let blob = raw(format, ObjectType::Blob, vec![b'a'; 4096]);
    let sibling = raw(format, ObjectType::Blob, vec![b'b'; 4096]);
    let hidden = raw(
        format,
        ObjectType::Blob,
        b"unrelated private content".to_vec(),
    );
    let old_tree = tree(
        format,
        &[("100644", "asset", blob.id), ("100644", "keep", sibling.id)],
    );
    let base = commit(format, old_tree.id, &[], "visible base");
    let graph_bytes = base.body.len() + old_tree.body.len();
    let fresh = raw(format, ObjectType::Blob, b"new file\n".to_vec());
    let next_tree = tree(
        format,
        &[
            ("100644", "asset", blob.id),
            ("100644", "file", fresh.id),
            ("100644", "keep", sibling.id),
        ],
    );
    let next = commit(format, next_tree.id, &[base.id], "candidate");
    let out = Case {
        base: base.id,
        blob: blob.id,
        hidden: hidden.id,
        candidate: next.id,
        graph_bytes,
        original: vec![blob, sibling, hidden, old_tree, base],
        upload: vec![fresh, next_tree, next],
    };
    for object in &out.original {
        assert_eq!(
            node.put_git_object(object.kind, object.body.clone())
                .unwrap()
                .identity(),
            object.id
        );
    }
    out
}
fn scoped<'a>(
    node: &'a OneNode,
    format: GitHashAlgorithm,
    f: &Case,
    bytes: usize,
    reuse: bool,
) -> ProductionQuarantineValidator<'a> {
    let originals: Vec<_> = f.original.iter().map(|o| o.id).collect();
    let mut v = selected_validator(
        node,
        format,
        &originals,
        PackLimits {
            max_cached_bytes: bytes,
            ..Default::default()
        },
    );
    v.visible_roots = BTreeSet::from([f.base]);
    if reuse { v.for_reviewed_candidate() } else { v }
}
fn stored(root: &Path, id: GitOid) -> PathBuf {
    let mut pending = vec![root.to_owned()];
    let mut found = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.file_name() == id.to_string().as_str() {
                found.push(entry.path());
            }
        }
    }
    assert_eq!(found.len(), 1);
    found.pop().unwrap()
}
#[test]
fn reviewed_frontier_permits_small_candidates_but_raw_receive_keeps_its_original_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let strict = scoped(&node, format, &f, 2048, false);
        assert_eq!(
            check(&strict, &f.upload, &[f.candidate]),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        assert!(node.read_git_object(f.candidate).is_err());
        let admitted = scoped(&node, format, &f, 2048, true);
        let new = check(&admitted, &f.upload, &[f.candidate]).unwrap();
        let legacy = check(
            &scoped(&node, format, &f, 16384, false),
            &f.upload,
            &[f.candidate],
        )
        .unwrap();
        assert_eq!(new, legacy);
        assert_eq!(new.objects, f.upload.iter().map(|o| o.id).collect());
        node.shutdown().unwrap();
    }
}
#[test]
fn proof_bytes_still_have_an_exact_inclusive_shared_limit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        for allowance in [f.graph_bytes - 1, f.graph_bytes] {
            let v = scoped(&node, format, &f, allowance, true);
            let bases = ExternalBases {
                bases: BTreeMap::new(),
                read_bytes: 0,
            };
            let mut originals = OriginalFrontier::new(&v, &bases).unwrap();
            let result = originals.authorize(&BTreeSet::from([f.blob]), &mut 1000, &mut || true);
            if allowance == f.graph_bytes {
                assert_eq!(result, Ok(()));
                assert_eq!(originals.read_bytes(), allowance);
            } else {
                assert_eq!(result, Err(RefusalCode::ResourceBudgetExceeded));
            }
        }
        node.shutdown().unwrap();
    }
}
#[test]
fn unrelated_admitted_bytes_cannot_be_borrowed_from_uploaded_proof_edges() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let t = tree(format, &[("100644", "file", f.hidden)]);
        let c = commit(format, t.id, &[f.base], "omitted hidden content");
        let mut upload = vec![t, c.clone()];
        let v = scoped(&node, format, &f, 16384, true);
        assert_eq!(
            check(&v, &upload, &[c.id]),
            Err(RefusalCode::ObjectClosureIncomplete)
        );
        assert!(node.read_git_object(c.id).is_err());
        upload.push(
            f.original
                .iter()
                .find(|o| o.id == f.hidden)
                .unwrap()
                .clone(),
        );
        assert!(check(&v, &upload, &[c.id]).is_ok());
        node.shutdown().unwrap();
    }
}
#[test]
fn missing_malformed_and_oversized_reused_envelopes_fail_before_upload_staging() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let path = stored(scratch.path(), f.blob);
        let original = std::fs::read(&path).unwrap();
        let v = scoped(&node, format, &f, 2048, true);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            check(&v, &f.upload, &[f.candidate]),
            Err(RefusalCode::EvidenceMissing)
        );
        assert!(node.read_git_object(f.candidate).is_err());
        let mut corrupt = original.clone();
        corrupt[0] ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert_eq!(
            check(&v, &f.upload, &[f.candidate]),
            Err(RefusalCode::EvidenceInvalid)
        );
        assert!(node.read_git_object(f.candidate).is_err());
        std::fs::write(&path, &original).unwrap();
        let mut bounded = scoped(&node, format, &f, 2048, true);
        bounded.pack_limits.max_object_bytes = 4095;
        assert_eq!(
            check(&bounded, &f.upload, &[f.candidate]),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        assert!(node.read_git_object(f.candidate).is_err());
        bounded.pack_limits.max_object_bytes = 4096;
        assert!(check(&bounded, &f.upload, &[f.candidate]).is_ok());
        node.shutdown().unwrap();
    }
}
#[test]
fn explicit_reused_blob_policy_is_separate_from_buffered_candidate_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for maximum in [4095, 4096] {
            let scratch = ScratchDirectory::new();
            let (node, _) = OneNode::init(
                NodeConfig::new(
                    scratch.path().to_path_buf(),
                    TenantId::from_bytes([0x71; 16]),
                    RepositoryId::from_bytes([0x72; 16]),
                )
                .with_object_format(format)
                .with_selected_pack_blob_limit(maximum)
                .with_worker_threads(2),
            )
            .unwrap();
            let f = case(&node, format);
            let mut bounded = scoped(&node, format, &f, 2048, true);
            bounded.pack_limits.max_object_bytes = 1024;
            bounded.parse_limits.max_object_bytes = 1024;
            let result = check(&bounded, &f.upload, &[f.candidate]);
            if maximum == 4095 {
                assert_eq!(result, Err(RefusalCode::ResourceBudgetExceeded));
                assert!(node.read_git_object(f.candidate).is_err());
            } else {
                assert!(result.is_ok());
            }
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn reused_blob_cannot_satisfy_an_uploaded_tree_edge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let t = tree(format, &[("40000", "not-a-directory", f.blob)]);
        let c = commit(format, t.id, &[f.base], "wrong edge kind");
        let v = scoped(&node, format, &f, 2048, true);
        assert_eq!(
            check(&v, &[t, c.clone()], &[c.id]),
            Err(RefusalCode::EvidenceInvalid)
        );
        assert!(node.read_git_object(c.id).is_err());
        assert!(check(&v, &f.upload, &[f.candidate]).is_ok());
        node.shutdown().unwrap();
    }
}
#[test]
fn actual_delta_inputs_remain_fully_verified_and_charged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let base = f.original.iter().find(|o| o.id == f.blob).unwrap();
        let result = raw(format, ObjectType::Blob, b"delta result".to_vec());
        let t = tree(format, &[("100644", "file", result.id)]);
        let c = commit(format, t.id, &[f.base], "real external delta");
        let (pack, receipt) = packed(format, &[delta(base, &result), full(&t), full(&c)]);
        let run = |v: &ProductionQuarantineValidator<'_>| {
            v.validate(
                &request(format, &[c.id]),
                Some(&pack),
                &receipt,
                &mut || true,
            )
        };
        assert_eq!(
            run(&scoped(&node, format, &f, 2048, true)),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        assert!(node.read_git_object(c.id).is_err());
        let path = stored(scratch.path(), f.blob);
        let exact = std::fs::read(&path).unwrap();
        let mut corrupt = exact.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert_eq!(
            run(&scoped(&node, format, &f, 16384, true)),
            Err(RefusalCode::EvidenceInvalid)
        );
        assert!(node.read_git_object(c.id).is_err());
        std::fs::write(&path, &exact).unwrap();
        assert!(run(&scoped(&node, format, &f, 16384, true)).is_ok());
        node.shutdown().unwrap();
    }
}
#[test]
fn reuse_is_not_a_scrub_or_a_complete_prerequisite_proof() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let v = scoped(&node, format, &f, 2048, true);
        let bases = ExternalBases {
            bases: BTreeMap::new(),
            read_bytes: 0,
        };
        let mut originals = OriginalFrontier::new(&v, &bases).unwrap();
        assert_eq!(
            originals.prerequisite_closure(&BTreeSet::from([f.base]), &mut 1000, &mut || true),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        let path = stored(scratch.path(), f.blob);
        let exact = std::fs::read(&path).unwrap();
        let mut corrupt = exact.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(check(&v, &f.upload, &[f.candidate]).is_ok());
        assert!(node.read_git_object(f.blob).is_err());
        assert_eq!(
            check(
                &scoped(&node, format, &f, 16384, false),
                &f.upload,
                &[f.candidate]
            ),
            Err(RefusalCode::EvidenceInvalid)
        );
        std::fs::write(&path, &exact).unwrap();
        assert!(node.read_git_object(f.blob).is_ok());
        node.shutdown().unwrap();
    }
}
#[test]
fn cancellation_during_native_proof_never_returns_a_partial_authorized_set() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let f = case(&node, format);
        let v = scoped(&node, format, &f, 2048, true);
        let bases = ExternalBases {
            bases: BTreeMap::new(),
            read_bytes: 0,
        };
        let wanted = BTreeSet::from([f.blob]);
        let mut reached = false;
        for allowance in 0..300 {
            let mut calls = 0;
            let mut originals = OriginalFrontier::new(&v, &bases).unwrap();
            let result = originals.authorize(&wanted, &mut 1000, &mut || {
                calls += 1;
                calls <= allowance
            });
            if result.is_ok() {
                reached = true;
                break;
            }
            assert_eq!(result, Err(RefusalCode::CancellationInProgress));
            assert_eq!(
                originals.kind(f.blob, &mut || true),
                Err(RefusalCode::ObjectClosureIncomplete)
            );
        }
        assert!(reached);
        node.shutdown().unwrap();
    }
}
