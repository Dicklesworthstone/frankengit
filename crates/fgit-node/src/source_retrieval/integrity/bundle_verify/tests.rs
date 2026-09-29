//! Independent test encoders for full bundles and stored-zlib pack records.
//! No external Git process or alternate production parser is used.
use super::*;
use fgit_crypto::{lowercase_hex, sha1_digest};
use fgit_pack::{DeltaBase, EntryKind};

fn zlib(body: &[u8]) -> Vec<u8> {
    assert!(body.len() <= u16::MAX as usize);
    let length = body.len() as u16;
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&(!length).to_le_bytes());
    bytes.extend_from_slice(body);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in body {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    bytes.extend_from_slice(&((b << 16) | a).to_be_bytes());
    bytes
}
fn record(kind: u8, body: &[u8], base: &[u8]) -> Vec<u8> {
    let mut size = body.len();
    let mut first = (kind << 4) | (size & 15) as u8;
    size >>= 4;
    let mut bytes = Vec::new();
    while size != 0 {
        bytes.push(first | 128);
        first = (size & 127) as u8;
        size >>= 7;
    }
    bytes.push(first);
    bytes.extend_from_slice(base);
    bytes.extend_from_slice(&zlib(body));
    bytes
}
fn pack(format: GitHashAlgorithm, records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"PACK\0\0\0\x02".to_vec();
    bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        bytes.extend_from_slice(record);
    }
    let checksum = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&bytes).to_vec(),
    };
    bytes.extend_from_slice(&checksum);
    bytes
}
fn bundle(format: GitHashAlgorithm, records: &[Vec<u8>], refs: &[(Vec<u8>, GitOid)]) -> Vec<u8> {
    let mut bytes = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    for (name, id) in refs {
        bytes.extend_from_slice(lowercase_hex(id.as_bytes()).as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(name);
        bytes.push(b'\n');
    }
    bytes.push(b'\n');
    bytes.extend_from_slice(&pack(format, records));
    bytes
}
fn commit(tree: GitOid, parents: &[GitOid]) -> Vec<u8> {
    let mut value = format!("tree {}\n", lowercase_hex(tree.as_bytes()));
    for parent in parents {
        value.push_str(&format!("parent {}\n", lowercase_hex(parent.as_bytes())));
    }
    value.push_str("author A <a@example.invalid> 1700000000 +0000\ncommitter A <a@example.invalid> 1700000000 +0000\n\nmessage\n");
    value.into_bytes()
}
fn tree_entry(mode: &[u8], name: &[u8], id: GitOid) -> Vec<u8> {
    let mut bytes = mode.to_vec();
    bytes.push(b' ');
    bytes.extend_from_slice(name);
    bytes.push(0);
    bytes.extend_from_slice(id.as_bytes());
    bytes
}
struct Fixture {
    records: Vec<Vec<u8>>,
    refs: Vec<(Vec<u8>, GitOid)>,
    ids: Vec<GitOid>,
}
fn fixture(format: GitHashAlgorithm) -> Fixture {
    let blob = b"file\0\xff\r\n";
    let blob_id = git_object_id(format, ObjectKind::Blob, blob);
    let tree = tree_entry(b"100755", b"raw-\xff", blob_id);
    let tree_id = git_object_id(format, ObjectKind::Tree, &tree);
    let commit = commit(tree_id, &[]);
    let commit_id = git_object_id(format, ObjectKind::Commit, &commit);
    let tag = format!(
        "object {}\ntype commit\ntag release\ntagger A <a@example.invalid> 1700000000 +0000\n\ntag message\n",
        lowercase_hex(commit_id.as_bytes())
    );
    let tag_id = git_object_id(format, ObjectKind::Tag, tag.as_bytes());
    Fixture {
        records: vec![
            record(3, blob, &[]),
            record(2, &tree, &[]),
            record(1, &commit, &[]),
            record(4, tag.as_bytes(), &[]),
        ],
        refs: vec![
            (b"refs/tags/release".to_vec(), tag_id),
            (b"refs/heads/main".to_vec(), commit_id),
            (b"HEAD".to_vec(), commit_id),
        ],
        ids: vec![blob_id, tree_id, commit_id, tag_id],
    }
}
fn verify(input: &[u8]) -> Result<VerifiedGitBundle, BundleVerifyError> {
    verify_git_bundle(input, &BundleVerifyLimits::default(), &mut || true)
}

#[test]
fn both_native_formats_verify_complete_graphs_and_preserve_raw_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let input = bundle(format, &f.records, &f.refs);
        let result = verify(&input).unwrap();
        assert_eq!(result.format(), format);
        assert_eq!(result.graph().objects, 4);
        assert_eq!(result.graph().references, 2);
        assert_eq!(result.graph().local_edges, 3);
        assert_eq!(result.graph().external_gitlinks, 0);
        assert_eq!(result.advertised_head(), Some(f.ids[2]));
        assert_eq!(result.sha256(), &sha256_digest(&input));
        assert_eq!(
            result.references().keys().next().unwrap().as_bytes(),
            b"refs/heads/main"
        );
        assert_eq!(result.delta_objects(), 0);
    }
}
#[test]
fn valid_native_checksums_do_not_hide_missing_files_trees_or_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        for missing in 0..f.records.len() {
            let records: Vec<_> = f
                .records
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .map(|(_, r)| r.clone())
                .collect();
            assert!(matches!(
                verify(&bundle(format, &records, &f.refs)),
                Err(BundleVerifyError::Graph(GraphRefusal::MissingTarget { .. }))
            ));
        }
        assert!(verify(&bundle(format, &f.records, &f.refs)).is_ok());
    }
}
#[test]
fn missing_parent_history_refuses_even_with_the_current_tree_present() {
    let format = GitHashAlgorithm::Sha1;
    let f = fixture(format);
    let absent = git_object_id(format, ObjectKind::Commit, b"not included");
    let body = commit(f.ids[1], &[absent]);
    let id = git_object_id(format, ObjectKind::Commit, &body);
    let records = vec![
        f.records[0].clone(),
        f.records[1].clone(),
        record(1, &body, &[]),
    ];
    assert!(
        matches!(verify(&bundle(format, &records, &[(b"refs/heads/main".to_vec(), id)])), Err(BundleVerifyError::Graph(GraphRefusal::MissingTarget { target, .. })) if target == absent)
    );
}
#[test]
fn advertised_branches_and_internal_edges_must_name_the_correct_native_kind() {
    let format = GitHashAlgorithm::Sha1;
    let f = fixture(format);
    assert!(matches!(
        verify(&bundle(
            format,
            &f.records,
            &[(b"refs/heads/wrong".to_vec(), f.ids[0])]
        )),
        Err(BundleVerifyError::Graph(GraphRefusal::TargetKind { .. }))
    ));
    let wrong_tree = tree_entry(b"40000", b"folder", f.ids[0]);
    let id = git_object_id(format, ObjectKind::Tree, &wrong_tree);
    let records = vec![f.records[0].clone(), record(2, &wrong_tree, &[])];
    assert!(matches!(
        verify(&bundle(
            format,
            &records,
            &[(b"refs/tags/tree".to_vec(), id)]
        )),
        Err(BundleVerifyError::Graph(GraphRefusal::TargetKind { .. }))
    ));
}
#[test]
fn gitlinks_are_explicit_external_dependencies_not_ambient_repository_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let foreign = git_object_id(format, ObjectKind::Commit, b"foreign");
        let body = tree_entry(b"160000", b"module", foreign);
        let id = git_object_id(format, ObjectKind::Tree, &body);
        let result = verify(&bundle(
            format,
            &[record(2, &body, &[])],
            &[(b"refs/tags/tree".to_vec(), id)],
        ))
        .unwrap();
        assert_eq!(result.graph().objects, 1);
        assert_eq!(result.graph().external_gitlinks, 1);
        assert_eq!(result.graph().local_edges, 0);
    }
}
#[test]
fn duplicate_native_objects_and_malformed_object_headers_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let mut f = fixture(format);
    f.records.push(f.records[0].clone());
    assert!(matches!(
        verify(&bundle(format, &f.records, &f.refs)),
        Err(BundleVerifyError::DuplicateObject(_))
    ));
    let body = b"not a commit";
    let id = git_object_id(format, ObjectKind::Commit, body);
    assert!(matches!(
        verify(&bundle(
            format,
            &[record(1, body, &[])],
            &[(b"refs/heads/main".to_vec(), id)]
        )),
        Err(BundleVerifyError::Graph(GraphRefusal::Malformed { .. }))
    ));
}
#[test]
fn empty_packs_cannot_satisfy_advertised_objects() {
    let f = fixture(GitHashAlgorithm::Sha1);
    assert!(matches!(
        verify(&bundle(GitHashAlgorithm::Sha1, &[], &f.refs)),
        Err(BundleVerifyError::Graph(GraphRefusal::MissingTarget { .. }))
    ));
}
#[test]
fn every_truncation_and_changed_pack_trailer_is_rejected() {
    let format = GitHashAlgorithm::Sha1;
    let f = fixture(format);
    let mut input = bundle(format, &f.records, &f.refs);
    for end in 0..input.len() {
        assert!(verify(&input[..end]).is_err(), "accepted prefix {end}");
    }
    *input.last_mut().unwrap() ^= 1;
    assert!(matches!(verify(&input), Err(BundleVerifyError::Pack(_))));
}
#[test]
fn checksum_valid_trailing_data_and_bad_deflate_are_not_object_success() {
    let format = GitHashAlgorithm::Sha1;
    let mut f = fixture(format);
    f.records[0].push(0); // extra byte between zlib members, included in recomputed trailer
    assert!(matches!(
        verify(&bundle(format, &f.records, &f.refs)),
        Err(BundleVerifyError::Pack(_))
    ));
    let mut f = fixture(format);
    f.records[0][1] = 0; // invalid zlib CMF, with a valid pack hash
    assert!(matches!(
        verify(&bundle(format, &f.records, &f.refs)),
        Err(BundleVerifyError::Pack(_))
    ));
}
fn literal_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    assert!(base.len() < 128 && result.len() < 128);
    let mut bytes = vec![base.len() as u8, result.len() as u8, result.len() as u8];
    bytes.extend_from_slice(result);
    bytes
}
fn ofs(mut distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 127) as u8];
    loop {
        distance >>= 7;
        if distance == 0 {
            break;
        }
        distance -= 1;
        bytes.push(128 | (distance & 127) as u8);
    }
    bytes.reverse();
    bytes
}
#[test]
fn offset_and_forward_reference_deltas_reconstruct_actual_native_ids() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = b"base";
        let result = b"second\0\xff";
        let base_id = git_object_id(format, ObjectKind::Blob, base);
        let result_id = git_object_id(format, ObjectKind::Blob, result);
        let direct = record(3, base, &[]);
        let program = literal_delta(base, result);
        let refs = [(b"refs/tags/result".to_vec(), result_id)];
        let records = vec![
            direct.clone(),
            record(6, &program, &ofs(direct.len() as u64)),
        ];
        let report = verify(&bundle(format, &records, &refs)).unwrap();
        assert_eq!(report.delta_objects(), 1);
        let records = vec![record(7, &program, base_id.as_bytes()), direct];
        let report = verify(&bundle(format, &records, &refs)).unwrap();
        assert_eq!(report.delta_objects(), 1);
        assert_eq!(report.resolution_passes(), 2);
    }
}
#[test]
fn chained_forward_reference_discovery_does_not_depend_on_entry_order() {
    let format = GitHashAlgorithm::Sha256;
    let bodies: Vec<_> = (0..5).map(|i| vec![b'a' + i]).collect();
    let ids: Vec<_> = bodies
        .iter()
        .map(|b| git_object_id(format, ObjectKind::Blob, b))
        .collect();
    let mut records = Vec::new();
    for i in (1..bodies.len()).rev() {
        records.push(record(
            7,
            &literal_delta(&bodies[i - 1], &bodies[i]),
            ids[i - 1].as_bytes(),
        ));
    }
    records.push(record(3, &bodies[0], &[]));
    let input = bundle(
        format,
        &records,
        &[(b"refs/tags/end".to_vec(), *ids.last().unwrap())],
    );
    let report = verify(&input).unwrap();
    assert_eq!(report.delta_objects(), 4);
    assert_eq!(report.resolution_passes(), 5);
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_delta_depth = 2;
    assert!(verify_git_bundle(&input, &limits, &mut || true).is_err());
}
#[test]
fn unknown_delta_bases_never_use_ambient_objects() {
    let format = GitHashAlgorithm::Sha1;
    let base = b"absent";
    let next = b"result";
    let id = git_object_id(format, ObjectKind::Blob, base);
    let target = git_object_id(format, ObjectKind::Blob, next);
    let input = bundle(
        format,
        &[record(7, &literal_delta(base, next), id.as_bytes())],
        &[(b"refs/tags/result".to_vec(), target)],
    );
    assert!(matches!(
        verify(&input),
        Err(BundleVerifyError::ResolutionIncomplete)
    ));
}
#[test]
fn one_shared_resolution_budget_covers_later_identity_discovery_passes() {
    let format = GitHashAlgorithm::Sha1;
    let base = vec![b'x'; 512];
    let base_id = git_object_id(format, ObjectKind::Blob, &base);
    let mut result = base.clone();
    result.push(b'!');
    let target = git_object_id(format, ObjectKind::Blob, &result);
    let program = [128, 4, 129, 4, 0xa0, 2, 1, b'!'];
    let input = bundle(
        format,
        &[
            record(7, &program, base_id.as_bytes()),
            record(3, &base, &[]),
        ],
        &[(b"refs/tags/result".to_vec(), target)],
    );
    assert!(verify(&input).is_ok());
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_total_expanded_bytes = 1024;
    assert!(matches!(
        verify_git_bundle(&input, &limits, &mut || true),
        Err(BundleVerifyError::Pack(
            PackError::TotalExpandedLimit { .. }
        ))
    ));
}
#[test]
fn independent_input_object_ref_edge_and_payload_limits_fail_closed() {
    let format = GitHashAlgorithm::Sha1;
    let f = fixture(format);
    let input = bundle(format, &f.records, &f.refs);
    for mode in 0..7 {
        let mut limits = BundleVerifyLimits::default();
        match mode {
            0 => limits.envelope.max_bundle_bytes = input.len() - 1,
            1 => limits.pack.max_entries = 3,
            2 => limits.graph.max_objects = 3,
            3 => limits.graph.max_references = 1,
            4 => limits.graph.max_edges = 2,
            5 => limits.graph.max_payload_bytes = 1,
            _ => limits.pack.max_delta_work = 1,
        }
        assert!(
            verify_git_bundle(&input, &limits, &mut || true).is_err(),
            "limit mode {mode}"
        );
    }
    let result = verify(&input).unwrap();
    let mut limits = BundleVerifyLimits::default();
    limits.envelope.max_bundle_bytes = input.len();
    limits.pack.max_entries = 4;
    limits.graph.max_objects = 4;
    limits.graph.max_references = 2;
    limits.graph.max_edges = 3;
    limits.graph.max_payload_bytes = result.graph().payload_bytes;
    assert!(verify_git_bundle(&input, &limits, &mut || true).is_ok());
}
#[test]
fn a_stopped_callback_is_latched_including_during_the_final_report_checks() {
    let format = GitHashAlgorithm::Sha1;
    let f = fixture(format);
    let input = bundle(format, &f.records, &f.refs);
    let mut count = 0;
    verify_git_bundle(&input, &BundleVerifyLimits::default(), &mut || {
        count += 1;
        true
    })
    .unwrap();
    for stop_at in [1, 5, count / 2, count - 1, count] {
        let mut polls = 0;
        let result = verify_git_bundle(&input, &BundleVerifyLimits::default(), &mut || {
            polls += 1;
            polls != stop_at
        });
        assert!(
            matches!(result, Err(BundleVerifyError::Stopped)),
            "stop at {stop_at}: {result:?}"
        );
        assert_eq!(polls, stop_at);
    }
}
#[test]
fn unknown_partial_bundle_capabilities_never_select_another_validation_engine() {
    let format = GitHashAlgorithm::Sha1;
    let f = fixture(format);
    let input = bundle(format, &f.records, &f.refs);
    let newline = input.iter().position(|b| *b == b'\n').unwrap() + 1;
    for header in [
        b"# v3 git bundle\n@filter=blob:none\n".to_vec(),
        format!(
            "# v2 git bundle\n-{} prerequisite\n",
            lowercase_hex(f.ids[2].as_bytes())
        )
        .into_bytes(),
    ] {
        let mut changed = header;
        changed.extend_from_slice(&input[newline..]);
        assert!(matches!(
            verify(&changed),
            Err(BundleVerifyError::Envelope(_))
        ));
    }
}
#[test]
fn unchanged_bytes_give_identical_counts_roots_and_digests_without_a_store() {
    let f = fixture(GitHashAlgorithm::Sha256);
    let input = bundle(GitHashAlgorithm::Sha256, &f.records, &f.refs);
    let a = verify(&input).unwrap();
    let b = verify(&input).unwrap();
    assert_eq!(a.graph(), b.graph());
    assert_eq!(a.sha256(), b.sha256());
    assert_eq!(a.references(), b.references());
    assert_eq!(a.pack_checksum(), b.pack_checksum());
}
#[test]
fn native_resolver_input_types_retain_original_entry_provenance() {
    let typed = PackObject::TypedBase {
        offset: 12,
        id: None,
        kind: EntryKind::Blob,
        data: b"x".to_vec(),
    };
    let delta = PackObject::Delta(DeltaObject {
        offset: 30,
        id: None,
        base: DeltaBase::Ofs(12),
        program: vec![1, 1, 1, b'y'],
    });
    assert_eq!(offset(&typed), 12);
    assert_eq!(offset(&delta), 30);
}
