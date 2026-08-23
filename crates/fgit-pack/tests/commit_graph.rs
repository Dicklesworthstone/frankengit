#![forbid(unsafe_code)]

//! FG-052 commit-graph V1 materialization tests.
//!
//! Each fixture uses a real strict Git commit body and is named by the native
//! SHA-1 object identity of that exact body.  The emitted bytes are decoded at
//! the standard chunk boundary; these tests do not claim a pinned-Git
//! differential run.

use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_pack::{
    CommitGraphInput, CommitGraphLimits, CommitGraphRefusal, CommitGraphSource, CommitGraphV1,
    ObjectFormat, ObjectId, PackError,
};
use fgit_types::{
    CodecVersion, DigestAlgorithmId, DigestBytes, GitOidSha1, RepositoryCommitId, RepositoryId,
};
use std::collections::BTreeMap;

const SHA1_BYTES: usize = 20;
const HEADER_BYTES: usize = 8;
const TOC_ENTRY_BYTES: usize = 12;

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x53; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(0x8053).expect("fixture algorithm code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x53; 32]).expect("fixture digest is long enough"),
    )
}

fn oid(byte: u8) -> ObjectId {
    ObjectId::from(GitOidSha1::from_bytes([byte; SHA1_BYTES]))
}

fn source(commit: ObjectId) -> CommitGraphSource {
    CommitGraphSource::new(repository_id(), rcr_id(), commit)
        .expect("fixture source commit is a nonzero native identity")
}

fn commit(tree: ObjectId, parents: &[ObjectId], time: u64) -> CommitGraphInput {
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in parents {
        body.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    body.extend_from_slice(
        format!(
            "author Example <example@invalid> {time} +0000\ncommitter Example <example@invalid> {time} +0000\n\nfixture\n"
        )
        .as_bytes(),
    );
    let native = git_object_id(ObjectFormat::Sha1, GitObjectKind::Commit, &body);
    CommitGraphInput::new(native, body).expect("a native fixture commit has a nonzero ID")
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixture graph contains a complete u32"),
    )
}

fn chunk_offsets(input: &[u8]) -> BTreeMap<[u8; 4], usize> {
    assert_eq!(&input[..4], b"CGPH");
    assert_eq!(input[4], 1);
    assert_eq!(input[5], 1);
    assert_eq!(input[7], 0, "fixtures use no base graph chain");
    let chunks = usize::from(input[6]);
    let mut offsets = BTreeMap::new();
    for index in 0..=chunks {
        let start = HEADER_BYTES + index * TOC_ENTRY_BYTES;
        let id: [u8; 4] = input[start..start + 4]
            .try_into()
            .expect("chunk table entry has a four-byte name");
        let offset = usize::try_from(u64::from_be_bytes(
            input[start + 4..start + TOC_ENTRY_BYTES]
                .try_into()
                .expect("chunk table entry has a u64 offset"),
        ))
        .expect("fixture graph offset fits usize");
        if id == [0; 4] {
            assert_eq!(index, chunks, "only the final TOC entry terminates");
            assert_eq!(offset, input.len() - SHA1_BYTES);
        } else {
            offsets.insert(id, offset);
        }
    }
    offsets
}

fn oid_position(oid_lookup: &[u8], id: ObjectId) -> usize {
    oid_lookup
        .chunks_exact(SHA1_BYTES)
        .position(|candidate| candidate == id.as_bytes())
        .expect("fixture commit identity occurs in its OID lookup chunk")
}

#[test]
fn commit_graph_v1_encodes_closed_native_commit_history_and_extra_edges() {
    let tree = oid(0x11);
    let root = commit(tree, &[], 10);
    let first = commit(tree, &[*root.commit_oid()], 20);
    let side = commit(tree, &[*root.commit_oid()], 25);
    let tip = commit(tree, &[*first.commit_oid()], 30);
    let octopus = commit(
        tree,
        &[*first.commit_oid(), *side.commit_oid(), *tip.commit_oid()],
        40,
    );
    let inputs = vec![
        octopus.clone(),
        side.clone(),
        root.clone(),
        tip.clone(),
        first.clone(),
    ];
    let mut live = || true;
    let graph = CommitGraphV1::write(
        source(*octopus.commit_oid()),
        &inputs,
        &CommitGraphLimits::default(),
        &mut live,
    )
    .expect("all named parents are present and every body has its native identity");

    let receipt = graph.receipt();
    assert_eq!(receipt.commit_count(), 5);
    assert_eq!(receipt.edge_count(), 2, "only the octopus tail uses EDGE");
    assert_eq!(receipt.output_bytes(), graph.bytes().len());
    assert_eq!(
        receipt.checksum().as_bytes(),
        sha1_digest(&graph.bytes()[..graph.bytes().len() - SHA1_BYTES])
    );

    let chunks = chunk_offsets(graph.bytes());
    let fanout = chunks[&*b"OIDF"];
    let oidl = chunks[&*b"OIDL"];
    let cdat = chunks[&*b"CDAT"];
    let edge = chunks[&*b"EDGE"];
    assert_eq!(read_u32(graph.bytes(), fanout + 255 * 4), 5);
    let oid_lookup = &graph.bytes()[oidl..cdat];
    assert!(
        oid_lookup
            .chunks_exact(SHA1_BYTES)
            .collect::<Vec<_>>()
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "OIDL is the standard ascending native-OID order"
    );

    let root_position = oid_position(oid_lookup, *root.commit_oid());
    let first_position = oid_position(oid_lookup, *first.commit_oid());
    let side_position = oid_position(oid_lookup, *side.commit_oid());
    let tip_position = oid_position(oid_lookup, *tip.commit_oid());
    let octopus_position = oid_position(oid_lookup, *octopus.commit_oid());
    let record_width = SHA1_BYTES + 16;
    let record = cdat + octopus_position * record_width;
    assert_eq!(&graph.bytes()[record..record + SHA1_BYTES], tree.as_bytes());
    assert_eq!(
        read_u32(graph.bytes(), record + SHA1_BYTES),
        u32::try_from(first_position).expect("fixture position fits u32")
    );
    assert_eq!(
        read_u32(graph.bytes(), record + SHA1_BYTES + 4),
        0x8000_0000,
        "second-parent field points at the start of EDGE"
    );
    assert_eq!(
        read_u32(graph.bytes(), record + SHA1_BYTES + 8) >> 2,
        4,
        "generation is one more than the maximum parent generation"
    );
    assert_eq!(read_u32(graph.bytes(), record + SHA1_BYTES + 12), 40);
    assert_eq!(
        read_u32(graph.bytes(), edge),
        u32::try_from(side_position).expect("fixture position fits u32")
    );
    assert_eq!(
        read_u32(graph.bytes(), edge + 4),
        0x8000_0000 | u32::try_from(tip_position).expect("fixture position fits u32")
    );
    assert_ne!(root_position, octopus_position, "history is non-vacuous");
    let exact_parents = BTreeMap::from([
        (*root.commit_oid(), Vec::new()),
        (*first.commit_oid(), vec![*root.commit_oid()]),
        (*side.commit_oid(), vec![*root.commit_oid()]),
        (*tip.commit_oid(), vec![*first.commit_oid()]),
        (
            *octopus.commit_oid(),
            vec![*first.commit_oid(), *side.commit_oid(), *tip.commit_oid()],
        ),
    ]);
    for (commit, exact) in &exact_parents {
        let mut query_live = || true;
        assert_eq!(
            graph
                .parents(commit, &mut query_live)
                .expect("receipt-bound graph accepts its emitted chunks"),
            Some(exact.clone()),
            "accelerated parent walk equals the strict source-commit parent order"
        );
    }
    let mut absent_live = || true;
    assert_eq!(
        graph
            .parents(&oid(0xee), &mut absent_live)
            .expect("an absent graph identity is an ordinary non-answer"),
        None
    );
    let mut cancelled = || false;
    assert_eq!(
        graph.parents(octopus.commit_oid(), &mut cancelled),
        Err(CommitGraphRefusal::Pack(PackError::DeadlineExceeded)),
        "query cancellation refuses before a parent result is exposed"
    );
}

#[test]
fn commit_graph_order_is_deterministic_and_receipt_is_source_bound() {
    let tree = oid(0x22);
    let root = commit(tree, &[], 10);
    let tip = commit(tree, &[*root.commit_oid()], 20);
    let inputs = [root.clone(), tip.clone()];
    let reversed = [tip.clone(), root.clone()];
    let mut first_live = || true;
    let first = CommitGraphV1::write(
        source(*tip.commit_oid()),
        &inputs,
        &CommitGraphLimits::default(),
        &mut first_live,
    )
    .expect("closed graph materializes");
    let mut second_live = || true;
    let second = CommitGraphV1::write(
        source(*tip.commit_oid()),
        &reversed,
        &CommitGraphLimits::default(),
        &mut second_live,
    )
    .expect("input order cannot affect derived bytes");
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(
        first.receipt().source().source_commit_oid(),
        tip.commit_oid()
    );
}

#[test]
fn commit_graph_refuses_body_identity_tampering_and_open_parent_closure() {
    let tree = oid(0x33);
    let root = commit(tree, &[], 10);
    let mut changed_body = root.body().to_vec();
    changed_body.push(b'!');
    let tampered = CommitGraphInput::new(*root.commit_oid(), changed_body)
        .expect("the claimed identity itself remains nonzero");
    let mut live = || true;
    assert!(matches!(
        CommitGraphV1::write(
            source(*root.commit_oid()),
            &[tampered],
            &CommitGraphLimits::default(),
            &mut live,
        ),
        Err(CommitGraphRefusal::CommitIdentityMismatch { .. })
    ));

    let absent_parent = oid(0x44);
    let orphan = commit(tree, &[absent_parent], 20);
    let mut second_live = || true;
    assert!(matches!(
        CommitGraphV1::write(
            source(*orphan.commit_oid()),
            &[orphan],
            &CommitGraphLimits::default(),
            &mut second_live,
        ),
        Err(CommitGraphRefusal::ParentOutsideInput { .. })
    ));
}

#[test]
fn commit_graph_enforces_output_bound_before_emitting_bytes() {
    let tree = oid(0x55);
    let root = commit(tree, &[], 10);
    let mut live = || true;
    let complete = CommitGraphV1::write(
        source(*root.commit_oid()),
        &[root.clone()],
        &CommitGraphLimits::default(),
        &mut live,
    )
    .expect("one strict root commit materializes");
    let mut limits = CommitGraphLimits::default();
    limits.max_output_bytes = complete.bytes().len() - 1;
    let mut bounded_live = || true;
    assert!(matches!(
        CommitGraphV1::write(
            source(*root.commit_oid()),
            &[root],
            &limits,
            &mut bounded_live
        ),
        Err(CommitGraphRefusal::OutputBytesExceeded { .. })
    ));
}
