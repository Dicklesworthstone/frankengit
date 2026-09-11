//! External-base admission uses the real pack reader and immutable fabric.
//! Small literal deltas deliberately need large bases but reconstruct tiny
//! outputs: output-size limits alone cannot bound this input materialization.
use super::*;
use std::cell::Cell;

fn literal_delta_pack(bases: &[GitOid], results: &[u8]) -> Vec<u8> {
    assert_eq!(bases.len(), results.len());
    let mut bytes = b"PACK\0\0\0\x02".to_vec();
    bytes.extend_from_slice(&(bases.len() as u32).to_be_bytes());
    for (base, result) in bases.iter().zip(results) {
        bytes.push(0x74);
        bytes.extend_from_slice(base.as_bytes());
        bytes.extend_from_slice(&zlib_stored(&[64, 1, 1, *result]));
    }
    bytes.extend_from_slice(&fgit_crypto::sha1_digest(&bytes));
    bytes
}

fn parsed(bytes: &[u8]) -> QuarantinedPack {
    read_verified_pack(bytes, GitHashAlgorithm::Sha1, &PackLimits::default(),
        &mut || true, &NativeChecksumVerifier).unwrap()
}

fn validator<'a>(node: &'a OneNode, selected: &[GitOid], bytes: usize) -> ProductionQuarantineValidator<'a> {
    ProductionQuarantineValidator::new(node, selected_closure(selected.iter().copied().collect()),
        PackLimits { max_cached_bytes: bytes, max_total_expanded_bytes: bytes,
            ..PackLimits::default() }, ParseLimits::default())
}

#[test]
fn tiny_thin_pack_cannot_materialize_more_external_bytes_than_its_envelope() {
    let scratch = ScratchDirectory::new();
    let node = test_node(scratch.path().to_path_buf());
    let a = node.put_git_object(ObjectType::Blob, vec![b'a'; 64]).unwrap().identity();
    let b = node.put_git_object(ObjectType::Blob, vec![b'b'; 64]).unwrap().identity();
    let bytes = literal_delta_pack(&[a, b], b"xy");
    let pack = parsed(&bytes);
    let x = fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"x");
    let y = fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"y");
    let mut request = create_request(x);
    request.commands.extend(create_request(y).commands.into_iter().map(|mut command| {
        command.ref_name = b"refs/tags/second".to_vec(); command
    }));
    let receipt = QuarantineReceipt { object_format: GitObjectFormat::Sha1,
        object_count: 2, pack_bytes: bytes.len(), delete_only: false };
    assert_eq!(validator(&node, &[a, b], 127).validate(&request, Some(&pack), &receipt, &mut || true),
        Err(RefusalCode::ResourceBudgetExceeded));
    assert!(node.read_git_object(x).is_err() && node.read_git_object(y).is_err(),
        "no uploaded object may be staged after an input-budget refusal");

    let mut selected = validator(&node, &[a, b], 128);
    let originals = selected.external_bases(&pack, &mut || true).unwrap();
    assert_eq!(originals.read_bytes, 128, "the original-input bound is inclusive");
    assert_eq!(originals.bases.len(), 2);
    // The resolver independently charges both bases AND the two reconstructed
    // one-byte outputs. Original-input admission at 128 is not permission to
    // ignore the existing aggregate reconstruction ceiling of 130 bytes.
    for expanded in [128, 129] {
        selected.pack_limits.max_total_expanded_bytes = expanded;
        assert_eq!(selected.external_read_limit(), 128);
        assert_eq!(selected.validate(&request, Some(&pack), &receipt, &mut || true),
            Err(RefusalCode::ResourceBudgetExceeded));
        assert!(node.read_git_object(x).is_err() && node.read_git_object(y).is_err(),
            "aggregate refusal must not stage either reconstructed output");
    }
    selected.pack_limits.max_total_expanded_bytes = 130;
    assert_eq!(selected.external_read_limit(), 128, "the original-input cap is not widened");
    let admitted = selected.validate(&request, Some(&pack), &receipt, &mut || true).unwrap();
    assert_eq!(admitted.objects, BTreeSet::from([x, y]));
    node.shutdown().unwrap();
}

#[test]
fn repeated_ref_delta_bases_are_materialized_and_charged_once() {
    let scratch = ScratchDirectory::new();
    let node = test_node(scratch.path().to_path_buf());
    let base = node.put_git_object(ObjectType::Blob, vec![b'a'; 64]).unwrap().identity();
    let pack = parsed(&literal_delta_pack(&[base, base], b"xy"));
    let selected = validator(&node, &[base], 64);
    let found = selected.external_bases(&pack, &mut || true).unwrap();
    assert_eq!(found.read_bytes, 64);
    assert_eq!(found.bases.len(), 1);
    assert_eq!(found.lookup(&base), Some(vec![b'a'; 64].as_slice()));
    node.shutdown().unwrap();
}

#[test]
fn original_object_limits_apply_before_a_quarantine_copy() {
    let scratch = ScratchDirectory::new();
    let node = test_node(scratch.path().to_path_buf());
    let base = node.put_git_object(ObjectType::Blob, vec![b'a'; 64]).unwrap().identity();
    let pack = parsed(&literal_delta_pack(&[base], b"x"));
    let mut bounded = validator(&node, &[base], 128);
    bounded.pack_limits.max_object_bytes = 63;
    assert!(matches!(bounded.external_bases(&pack, &mut || true),
        Err(RefusalCode::ResourceBudgetExceeded)));
    bounded.pack_limits.max_object_bytes = 64;
    bounded.parse_limits.max_object_bytes = 63;
    assert!(matches!(bounded.external_bases(&pack, &mut || true),
        Err(RefusalCode::ResourceBudgetExceeded)));
    bounded.parse_limits.max_object_bytes = 64;
    assert_eq!(bounded.external_bases(&pack, &mut || true).unwrap().read_bytes, 64);
    node.shutdown().unwrap();
}

#[test]
fn cancellation_observed_after_external_read_is_not_a_missing_base_verdict() {
    let scratch = ScratchDirectory::new();
    let node = test_node(scratch.path().to_path_buf());
    let missing = fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &[b'a'; 64]);
    let pack = parsed(&literal_delta_pack(&[missing], b"x"));
    let selected = validator(&node, &[missing], 128);
    let calls = Cell::new(0usize);
    let mut cancelled_at_read = || { calls.set(calls.get() + 1); calls.get() < 3 };
    assert!(matches!(selected.external_bases(&pack, &mut cancelled_at_read),
        Err(RefusalCode::CancellationInProgress)));
    assert!(matches!(selected.external_bases(&pack, &mut || true),
        Err(RefusalCode::EvidenceMissing)));
    node.shutdown().unwrap();
}
