//! Native prerequisite custody: visibility, independent original-byte accounting,
//! authenticated blob EOF and sticky refusal. Shared fixtures enter through the
//! real native directory importer.

use super::super::file_import::originals::SelectedBundleOriginals;
use super::*;
use crate::StreamBundleImportRefusal;
use crate::source_retrieval::integrity::bundle_verify::{
    BundleOriginalSource, BundleVerifyError, BundleVerifyLimits,
};
use fgit_git_object::ObjectType;
use fgit_treefs::integrity::GraphRefusal;
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};

fn selected<'a>(
    node: &'a OneNode,
    request: &'a crate::NodeRequestContext,
    materialized: &MaterializedAdmission,
    roots: &[GitOid],
    budget: usize,
) -> Result<SelectedBundleOriginals<'a>, StreamBundleImportRefusal> {
    SelectedBundleOriginals::new(
        node,
        request,
        materialized,
        roots,
        &BundleVerifyLimits::default(),
        budget,
        &mut || true,
    )
}

fn placed_path(node: &OneNode, identity: GitOid) -> PathBuf {
    let name = identity.to_string();
    let mut pending = vec![node.storage_root().join("objects")];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.file_name().to_str() == Some(name.as_str()) {
                return entry.path();
            }
        }
    }
    panic!("fixture object is not placed: {identity}");
}

fn corrupt_last(path: &Path) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn original_selection_freezes_exact_prerequisite_closure_and_charges_discovery_against_capture() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child, blob) = fixture(&scratch, format);
        let request = node.import_request_context(None);
        let materialized = snapshot(&node);
        let mut originals = selected(&node, &request, &materialized, &[base], usize::MAX).unwrap();
        let ids: BTreeSet<_> = originals.objects().keys().copied().collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&base));
        assert!(ids.contains(&blob));
        assert!(
            !ids.contains(&child),
            "a visible descendant is not a prerequisite ancestor"
        );
        assert_eq!(originals.prerequisites(), &[base]);
        let discovery = originals.discovery_read_bytes();
        let expected_discovery: usize = materialized
            .selected_closure()
            .closure()
            .objects()
            .iter()
            .map(|id| node.read_git_object(*id).unwrap())
            .filter(|object| {
                object.envelope().object_kind() != fgit_object_fabric::ObjectKind::Blob
            })
            .map(|object| object.payload().len())
            .sum();
        assert_eq!(discovery, expected_discovery);
        let captured: usize = originals
            .objects()
            .values()
            .map(|object| object.length)
            .sum();
        for identity in ids.iter().copied() {
            let mut bytes = Vec::new();
            originals
                .read_into(
                    identity,
                    &mut |part| {
                        bytes.extend_from_slice(part);
                        Ok(())
                    },
                    &mut || true,
                )
                .unwrap();
            assert_eq!(bytes, node.read_git_object(identity).unwrap().payload());
        }
        let total = discovery + captured;
        let mut exact = selected(&node, &request, &materialized, &[base], total).unwrap();
        for identity in ids {
            exact
                .read_into(identity, &mut |_| Ok(()), &mut || true)
                .unwrap();
        }
        assert!(matches!(
            exact.read_into(
                base,
                &mut |_| panic!("capture reset the original-byte ledger"),
                &mut || true
            ),
            Err(BundleVerifyError::Graph(GraphRefusal::Limit(
                "original read bytes"
            )))
        ));
        assert!(matches!(
            selected(&node, &request, &materialized, &[base], total - 1),
            Err(StreamBundleImportRefusal::Verification(
                BundleVerifyError::Graph(GraphRefusal::Limit("original read bytes"))
            ))
        ));
        let mut unselected = selected(&node, &request, &materialized, &[base], usize::MAX).unwrap();
        assert!(matches!(
            unselected.read_into(child, &mut |_| panic!("unselected bytes reached sink"), &mut || true),
            Err(BundleVerifyError::Graph(GraphRefusal::MissingTarget { target, .. })) if target == child
        ));
        assert_eq!(snapshot(&node).basis(), materialized.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn stored_hidden_deleted_and_wrong_kind_objects_do_not_become_original_prerequisites() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child, blob) = fixture(&scratch, format);
        let request = node.import_request_context(None);
        let materialized = snapshot(&node);
        let tree = node
            .put_git_object(ObjectType::Tree, Vec::new())
            .unwrap()
            .identity();
        let stored = node
            .put_git_object(
                ObjectType::Commit,
                format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nmerely stored\n").into_bytes(),
            )
            .unwrap()
            .identity();
        assert!(matches!(
            selected(&node, &request, &materialized, &[stored], usize::MAX),
            Err(StreamBundleImportRefusal::Node(error)) if matches!(*error, NodeWorkspaceRefusal::RefUnavailable)
        ));
        assert!(matches!(
            selected(&node, &request, &materialized, &[blob], usize::MAX),
            Err(StreamBundleImportRefusal::Node(error)) if matches!(*error, NodeWorkspaceRefusal::CommitRequired)
        ));
        // This projection-level unit case exercises the exact hidden policy
        // field consumed by the source; the native bytes remain unchanged.
        let mut hidden = materialized.clone();
        hidden
            .snapshot
            .hidden_refs
            .push_rule(b"refs/heads/main", &Default::default())
            .unwrap();
        assert!(matches!(
            selected(&node, &request, &hidden, &[base], usize::MAX),
            Err(StreamBundleImportRefusal::Node(error)) if matches!(*error, NodeWorkspaceRefusal::RefUnavailable)
        ));
        accepted(apply(
            &node,
            &[RefCommand {
                name: reference("refs/heads/main"),
                expected_old: ExpectedOld::Exactly(child),
                proposed_new: ProposedNew::Delete,
                force: false,
            }],
            "remove-original-visibility",
        ));
        let deleted = snapshot(&node);
        assert!(
            deleted
                .selected_closure()
                .closure()
                .objects()
                .contains(&base)
        );
        assert!(node.read_git_object(base).is_ok());
        assert!(matches!(
            selected(&node, &request, &deleted, &[base], usize::MAX),
            Err(StreamBundleImportRefusal::Node(error)) if matches!(*error, NodeWorkspaceRefusal::RefUnavailable)
        ));
        node.shutdown().unwrap();
    }
}

#[test]
fn blob_headers_select_but_corrupt_payloads_never_establish_complete_original_custody() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, _, blob) = fixture(&scratch, format);
        let request = node.import_request_context(None);
        let materialized = snapshot(&node);
        let length = node.read_git_object(blob).unwrap().payload().len();
        corrupt_last(&placed_path(&node, blob));
        let mut originals = selected(&node, &request, &materialized, &[base], usize::MAX).unwrap();
        let mut delivered = 0;
        assert!(matches!(
            originals.read_into(
                blob,
                &mut |part| {
                    delivered += part.len();
                    Ok(())
                },
                &mut || true,
            ),
            Err(BundleVerifyError::Graph(GraphRefusal::IdentityMismatch(id))) if id == blob
        ));
        assert_eq!(
            delivered, length,
            "only authenticated EOF can accept the complete stream"
        );
        assert!(matches!(
            originals.read_into(base, &mut |_| panic!("failed source resumed"), &mut || true),
            Err(BundleVerifyError::Graph(GraphRefusal::Failed))
        ));
        let empty = selected(&node, &request, &materialized, &[], 0).unwrap();
        assert!(empty.objects().is_empty());
        assert_eq!(empty.discovery_read_bytes(), 0);
        assert_eq!(snapshot(&node).basis(), materialized.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn original_sink_failure_cancellation_and_independent_graph_limits_are_sticky() {
    let scratch = Scratch::new();
    let (node, base, _, blob) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let request = node.import_request_context(None);
    let materialized = snapshot(&node);
    let mut originals = selected(&node, &request, &materialized, &[base], usize::MAX).unwrap();
    assert!(matches!(
        originals.read_into(
            blob,
            &mut |_| Err(BundleVerifyError::ScratchChanged),
            &mut || true
        ),
        Err(BundleVerifyError::ScratchChanged)
    ));
    assert!(matches!(
        originals.read_into(
            blob,
            &mut |_| panic!("sink failure became health proof"),
            &mut || true
        ),
        Err(BundleVerifyError::Graph(GraphRefusal::Failed))
    ));
    let mut cancelled = selected(&node, &request, &materialized, &[base], usize::MAX).unwrap();
    assert!(matches!(
        cancelled.read_into(blob, &mut |_| panic!("stopped source read"), &mut || false),
        Err(BundleVerifyError::Stopped)
    ));
    assert!(matches!(
        cancelled.read_into(blob, &mut |_| panic!("later live erased stop"), &mut || {
            true
        }),
        Err(BundleVerifyError::Stopped)
    ));
    let mut limited = BundleVerifyLimits::default();
    limited.graph.max_objects = 2;
    assert!(matches!(
        SelectedBundleOriginals::new(
            &node,
            &request,
            &materialized,
            &[base],
            &limited,
            usize::MAX,
            &mut || true
        ),
        Err(StreamBundleImportRefusal::Verification(
            BundleVerifyError::Graph(GraphRefusal::Limit("original objects"))
        ))
    ));
    limited.graph.max_objects = 100;
    limited.graph.max_edges = 0;
    assert!(matches!(
        SelectedBundleOriginals::new(
            &node,
            &request,
            &materialized,
            &[base],
            &limited,
            usize::MAX,
            &mut || true
        ),
        Err(StreamBundleImportRefusal::Verification(
            BundleVerifyError::Graph(GraphRefusal::Limit("original discovery edges"))
        ))
    ));
    let mut scoped = selected(&node, &request, &materialized, &[base], usize::MAX).unwrap();
    request.cancel();
    assert!(matches!(
        scoped.read_into(
            blob,
            &mut |_| panic!("cancelled request replaced"),
            &mut || true
        ),
        Err(BundleVerifyError::Stopped)
    ));
    node.shutdown().unwrap();
}

fn large_loose_blob(root: &Path, format: GitHashAlgorithm, body: &[u8]) -> GitOid {
    let id = git_object_id(format, GitObjectKind::Blob, body);
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    let mut output = fs::File::create(directory.join(&text[2..])).unwrap();
    output.write_all(&[0x78, 0x01]).unwrap();
    let header = format!("blob {}\0", body.len());
    let mut pieces = std::iter::once(header.as_bytes())
        .chain(body.chunks(65_535))
        .peekable();
    let (mut a, mut b) = (1u32, 0u32);
    while let Some(piece) = pieces.next() {
        let length = u16::try_from(piece.len()).unwrap();
        output
            .write_all(&[u8::from(pieces.peek().is_none())])
            .unwrap();
        output.write_all(&length.to_le_bytes()).unwrap();
        output.write_all(&(!length).to_le_bytes()).unwrap();
        output.write_all(piece).unwrap();
        for byte in piece {
            a = (a + u32::from(*byte)) % 65_521;
            b = (b + a) % 65_521;
        }
    }
    output.write_all(&((b << 16) | a).to_be_bytes()).unwrap();
    id
}

#[test]
fn original_blobs_above_metadata_limit_flow_in_bounded_authenticated_chunks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, _, _, _) = fixture(&scratch, format);
        let root = scratch.0.join("large-original");
        fs::create_dir_all(root.join("refs/heads")).unwrap();
        fs::write(root.join("HEAD"), b"ref: refs/heads/large\n").unwrap();
        fs::write(root.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let body = vec![0x37; 3 * 64 * 1024 + 19];
        let blob = large_loose_blob(&root, format, &body);
        let tree = loose(
            &root,
            format,
            GitObjectKind::Tree,
            "tree",
            &[b"100644 large\0".as_slice(), blob.as_bytes()].concat(),
        );
        let commit = loose(
            &root,
            format,
            GitObjectKind::Commit,
            "commit",
            format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 3 +0000\ncommitter Fixture <fixture@example.invalid> 3 +0000\n\nlarge original\n").as_bytes(),
        );
        fs::write(root.join("refs/heads/large"), format!("{commit}\n")).unwrap();
        let request = node.import_request_context(None);
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &root,
                principal(),
                b"large-original-fixture",
            ))
            .unwrap();
        assert!(
            imported.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let materialized = snapshot(&node);
        let mut limits = BundleVerifyLimits::default();
        limits.pack.max_object_bytes = 1024;
        limits.graph.max_object_bytes = 1024;
        limits.max_streamed_blob_bytes = body.len();
        let mut originals = SelectedBundleOriginals::new(
            &node,
            &request,
            &materialized,
            &[commit],
            &limits,
            usize::MAX,
            &mut || true,
        )
        .unwrap();
        assert_eq!(originals.objects().len(), 3);
        assert!(originals.discovery_read_bytes() < body.len());
        let (mut length, mut chunks) = (0, 0);
        originals
            .read_into(
                blob,
                &mut |part| {
                    assert!(part.len() <= 64 * 1024);
                    assert!(part.iter().all(|byte| *byte == 0x37));
                    length += part.len();
                    chunks += 1;
                    Ok(())
                },
                &mut || true,
            )
            .unwrap();
        assert_eq!(length, body.len());
        assert!(chunks >= 4);
        node.shutdown().unwrap();
    }
}

#[test]
fn original_discovery_roots_do_not_borrow_the_incoming_reference_command_ceiling() {
    let scratch = Scratch::new();
    let (node, base, child, _) = fixture(&scratch, GitHashAlgorithm::Sha256);
    accepted(apply(
        &node,
        &[create("refs/heads/alias", base)],
        "original-visible-alias",
    ));
    let request = node.import_request_context(None);
    let materialized = snapshot(&node);
    assert_eq!(materialized.snapshot().refs.len(), 2);
    let mut limits = BundleVerifyLimits::default();
    limits.envelope.max_references = 1;
    limits.graph.max_references = 1;
    let originals = SelectedBundleOriginals::new(
        &node,
        &request,
        &materialized,
        &[child, base],
        &limits,
        usize::MAX,
        &mut || true,
    )
    .unwrap();
    assert_eq!(originals.prerequisites().len(), 2);
    assert_eq!(originals.objects().len(), 4);
    node.shutdown().unwrap();
}
