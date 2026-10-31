//! Native filesystem and authority regressions for incremental stream selection.
use super::*;
use fgit_pack::full_bundle::stream::{STREAM_INCREMENTAL_BUNDLE_PROFILE, StreamFullBundleError};
use fgit_pack::read_streamed_pack;
use fgit_runtime::{ClassLimits, Exhaustion};
use std::collections::BTreeSet;
use std::io::{self, Cursor, Write};
use std::time::Duration;

fn stream(
    node: &OneNode,
    names: &[&str],
    prerequisites: &[GitOid],
    visibility: &RefVisibility,
    query: StreamBundleExportQuery,
) -> (
    Result<SelectedStreamBundleExport, StreamBundleExportRefusal>,
    Vec<u8>,
) {
    let request = node.request_context();
    let names = names.iter().map(|name| reference(name)).collect::<Vec<_>>();
    let mut bytes = Vec::new();
    let result = node
        .runtime()
        .block_on(node.export_incremental_git_bundle_stream_in(
            &request,
            &names,
            prerequisites,
            visibility,
            query,
            &mut bytes,
        ));
    (result, bytes)
}

fn seed(source: &OneNode, destination: &OneNode, base: GitOid) {
    accepted(apply(
        source,
        &[create("refs/heads/seed", base)],
        "stream-seed-ref",
    ));
    let mut visibility = RefVisibility::new();
    visibility
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    accepted(import(
        destination,
        export(source, &visibility).bytes(),
        "stream-seed",
    ));
    accepted(apply(
        destination,
        &[create("refs/heads/main", base)],
        "stream-seed-main",
    ));
}

fn sync_import(
    node: &OneNode,
    bytes: &[u8],
    expectations: &[(&str, Option<GitOid>)],
    key: &str,
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request = node.request_context();
    let expectations = expectations
        .iter()
        .map(|(name, old)| (reference(name), *old))
        .collect::<Vec<_>>();
    node.runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &request,
            &session(key),
            bytes,
            &expectations,
            AdmissionLimits::default(),
        ))
}

fn recovered_ids(bytes: &[u8]) -> BTreeSet<GitOid> {
    let parsed =
        FullBundleInput::parse_incremental(bytes, FullBundleLimits::default(), &mut || true)
            .unwrap();
    let mut input = Cursor::new(parsed.pack_bytes());
    let mut ids = BTreeSet::new();
    read_streamed_pack(
        &mut input,
        parsed.format(),
        &Default::default(),
        &mut || true,
        |entry| -> Result<(), io::Error> {
            let kind = fgit_pack::object_type_from_base_entry(entry.entry.header.kind).unwrap();
            assert!(ids.insert(git_object_id(parsed.format(), kind, &entry.entry.inflated)));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        usize::try_from(input.position()).unwrap(),
        parsed.pack_bytes().len()
    );
    ids
}

#[test]
fn streamed_file_transfers_only_new_native_bytes_and_recovers_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, base, child, _) = fixture(&source_root, format);
        let target_root = Scratch::new();
        let mut destination = empty_node(&target_root, format);
        seed(&source, &destination, base);
        let before_source = snapshot(&source);
        let request = source.request_context();
        let path = source_root.0.join("private-incremental.bundle");
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let query = StreamBundleExportQuery {
            expected_head: Some(before_source.basis().id()),
            ..Default::default()
        };
        let selected = source
            .runtime()
            .block_on(source.export_incremental_git_bundle_stream_in(
                &request,
                &[reference("refs/heads/main")],
                &[base],
                &RefVisibility::new(),
                query.clone(),
                &mut output,
            ))
            .unwrap();
        drop(output);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(selected.head(), before_source.basis().id());
        assert_eq!(selected.generation(), before_source.basis().generation());
        assert_eq!(
            selected.receipt().profile_id(),
            STREAM_INCREMENTAL_BUNDLE_PROFILE
        );
        assert_eq!(selected.receipt().format(), format);
        assert_eq!(selected.receipt().object_count(), 1);
        assert_eq!(selected.receipt().prerequisite_count(), 1);
        assert_eq!(selected.receipt().external_object_count(), 3);
        assert_eq!(selected.receipt().bundle_bytes(), bytes.len());
        assert_eq!(
            selected.receipt().bundle_sha256(),
            fgit_crypto::sha256_digest(&bytes)
        );
        assert_eq!(
            selected.receipt().total_object_bytes(),
            source.read_git_object(child).unwrap().payload().len()
        );
        assert_eq!(recovered_ids(&bytes), BTreeSet::from([child]));
        let parsed =
            FullBundleInput::parse_incremental(&bytes, FullBundleLimits::default(), &mut || true)
                .unwrap();
        assert_eq!(parsed.prerequisites(), &[base]);
        assert_eq!(parsed.references().len(), 1);
        assert_eq!(parsed.references()[0].name(), &reference("refs/heads/main"));
        assert!(parsed.head().is_none());
        let (again, repeated) = stream(
            &source,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            query,
        );
        assert_eq!(again.unwrap().receipt(), selected.receipt());
        assert_eq!(repeated, bytes);
        assert_eq!(snapshot(&source).basis(), before_source.basis());

        let before = snapshot(&destination);
        let refused = sync_import(
            &destination,
            &bytes,
            &[("refs/heads/main", None)],
            "stream-wrong-old",
        )
        .unwrap();
        assert!(
            refused
                .commands
                .iter()
                .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Refused { .. }))
        );
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            before.snapshot().refs
        );
        assert_missing(&destination, child);
        assert_staging_empty(&destination);
        let committed = accepted(sync_import(
            &destination,
            &bytes,
            &[("refs/heads/main", Some(base))],
            "stream-correct-old",
        ));
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs[&reference("refs/heads/main")], child);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_native_transfer(&source, &destination, child);
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        destination = OneNode::open_existing(target_root.config(format)).unwrap();
        assert_eq!(
            sync_import(
                &destination,
                &bytes,
                &[("refs/heads/main", Some(base))],
                "stream-correct-old"
            )
            .unwrap(),
            committed
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn zero_object_packs_and_overlapping_frontiers_keep_canonical_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (source, base, child, _) = fixture(&root, format);
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        seed(&source, &destination, base);
        accepted(apply(
            &source,
            &[create("refs/heads/copy", base)],
            "stream-copy",
        ));
        accepted(apply(
            &source,
            &[create("refs/heads/alias", child)],
            "stream-alias",
        ));
        let before = snapshot(&source);
        let (zero, bytes) = stream(
            &source,
            &["refs/heads/copy"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        let zero = zero.unwrap();
        assert_eq!(zero.receipt().object_count(), 0);
        assert_eq!(zero.receipt().total_object_bytes(), 0);
        assert_eq!(zero.receipt().external_object_count(), 3);
        assert!(recovered_ids(&bytes).is_empty());
        accepted(sync_import(
            &destination,
            &bytes,
            &[("refs/heads/copy", None)],
            "stream-empty",
        ));
        assert_eq!(
            snapshot(&destination).snapshot().refs[&reference("refs/heads/copy")],
            base
        );
        assert_missing(&destination, child);
        let (first, a) = stream(
            &source,
            &["refs/heads/main", "refs/heads/alias"],
            &[base, child],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        let (second, b) = stream(
            &source,
            &["refs/heads/alias", "refs/heads/main"],
            &[child, base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        let first = first.unwrap();
        assert_eq!(first.receipt(), second.unwrap().receipt());
        assert_eq!(a, b);
        assert!(recovered_ids(&a).is_empty());
        assert_eq!(first.receipt().prerequisite_count(), 2);
        assert_eq!(first.receipt().external_object_count(), 4);
        assert_eq!(snapshot(&source).basis(), before.basis());
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn empty_output_selection_still_bounds_the_complete_visible_proof() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _, child, blob) = fixture(&root, format);
        let before = snapshot(&node);
        let metadata_bytes = before
            .selected_closure()
            .closure()
            .objects()
            .iter()
            .filter(|id| **id != blob)
            .map(|id| node.read_git_object(*id).unwrap().payload().len())
            .sum::<usize>();
        let mut exact = StreamBundleExportQuery::default();
        exact.limits.pack.max_entries = 4;
        exact.limits.pack.max_index_entries = 4;
        exact.limits.pack.max_total_expanded_bytes = metadata_bytes;
        exact.limits.max_graph_edges = 4;
        exact.limits.envelope.max_references = 1;
        let (selected, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[child],
            &RefVisibility::new(),
            exact.clone(),
        );
        assert_eq!(selected.unwrap().receipt().object_count(), 0);
        assert!(recovered_ids(&bytes).is_empty());

        let mut refused = Vec::new();
        let mut limited = exact.clone();
        limited.limits.pack.max_entries = 3;
        refused.push(limited);
        let mut limited = exact.clone();
        limited.limits.pack.max_index_entries = 3;
        refused.push(limited);
        let mut limited = exact.clone();
        limited.limits.max_graph_edges = 3;
        refused.push(limited);
        let mut limited = exact.clone();
        limited.limits.pack.max_total_expanded_bytes = metadata_bytes - 1;
        refused.push(limited);
        let mut limited = exact.clone();
        limited.limits.pack.max_object_bytes = 1;
        refused.push(limited);
        for query in refused {
            let (result, bytes) = stream(
                &node,
                &["refs/heads/main"],
                &[child],
                &RefVisibility::new(),
                query,
            );
            assert!(result.is_err());
            assert!(
                bytes.is_empty(),
                "discovery refusal must precede bundle framing"
            );
        }
        assert_eq!(snapshot(&node).basis(), before.basis());
        accepted(apply(
            &node,
            &[create("refs/heads/other", child)],
            "stream-visible-count",
        ));
        let after = snapshot(&node);
        let (result, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[child],
            &RefVisibility::new(),
            exact,
        );
        assert!(
            result.is_err(),
            "visible roots share the finite reference ceiling"
        );
        assert!(bytes.is_empty());
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn every_prerequisite_membership_is_checked_before_any_prerequisite_kind() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base, _, blob) = fixture(&root, format);
        let mut unadmitted_body = node.read_git_object(base).unwrap().payload().to_vec();
        unadmitted_body.extend_from_slice(b"physically present, never admitted\n");
        let unadmitted = node
            .put_git_object(fgit_git_object::ObjectType::Commit, unadmitted_body)
            .unwrap()
            .identity();
        assert!(node.read_git_object(unadmitted).is_ok());
        let before = snapshot(&node);
        assert!(
            !before
                .selected_closure()
                .closure()
                .objects()
                .contains(&unadmitted)
        );
        let (result, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[blob, unadmitted],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert!(
            matches!(result, Err(StreamBundleExportRefusal::Source(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::RefUnavailable))
        );
        assert!(bytes.is_empty());
        let (result, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[blob],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert!(
            matches!(result, Err(StreamBundleExportRefusal::Source(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::CommitRequired))
        );
        assert!(bytes.is_empty());
        let foreign = git_object_id(
            match format {
                GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
                GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
            },
            GitObjectKind::Blob,
            b"foreign frontier",
        );
        for prerequisites in [Vec::new(), vec![base, base], vec![foreign]] {
            let (result, bytes) = stream(
                &node,
                &["refs/heads/main"],
                &prerequisites,
                &RefVisibility::new(),
                StreamBundleExportQuery::default(),
            );
            assert!(result.is_err());
            assert!(bytes.is_empty());
        }
        for names in [
            vec!["refs/heads/main", "refs/heads/main"],
            vec!["refs/heads/missing"],
        ] {
            let (result, bytes) = stream(
                &node,
                &names,
                &[base],
                &RefVisibility::new(),
                StreamBundleExportQuery::default(),
            );
            assert!(result.is_err());
            assert!(bytes.is_empty());
        }
        let (allowed, _) = stream(
            &node,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert!(allowed.is_ok());
        assert_eq!(snapshot(&node).basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn hidden_and_deleted_only_prerequisites_cannot_grant_disclosure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (seed_node, base, child, _) = fixture(&source_root, format);
        seed_node.shutdown().unwrap();
        let loose_root = source_root.0.join("source");
        fs::write(loose_root.join("refs/heads/main"), format!("{base}\n")).unwrap();
        fs::write(loose_root.join("refs/heads/topic"), format!("{child}\n")).unwrap();
        let target = Scratch::new();
        let node = empty_node(&target, format);
        let request = node.request_context();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &loose_root,
                principal(),
                b"stream-prerequisite-visibility",
            ))
            .unwrap();
        assert!(
            imported.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let mut visibility = RefVisibility::new();
        visibility
            .push_rule(b"refs/heads/topic", &Default::default())
            .unwrap();
        let before = snapshot(&node);
        let (hidden, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[child],
            &visibility,
            StreamBundleExportQuery::default(),
        );
        assert!(
            matches!(hidden, Err(StreamBundleExportRefusal::Source(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::RefUnavailable))
        );
        assert!(bytes.is_empty());
        let (allowed, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[child],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert_eq!(allowed.unwrap().receipt().object_count(), 0);
        assert!(recovered_ids(&bytes).is_empty());
        assert_eq!(snapshot(&node).basis(), before.basis());
        accepted(apply(
            &node,
            &[RefCommand {
                name: reference("refs/heads/topic"),
                expected_old: ExpectedOld::Exactly(child),
                proposed_new: ProposedNew::Delete,
                force: false,
            }],
            "stream-delete-only-prerequisite",
        ));
        let after = snapshot(&node);
        assert!(node.read_git_object(child).is_ok());
        let (deleted, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[child],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert!(
            matches!(deleted, Err(StreamBundleExportRefusal::Source(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::RefUnavailable))
        );
        assert!(bytes.is_empty());
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

// Test-only fault injection finds an already placed object by its exact native
// filename. Production selection never enumerates storage to establish authority.
fn stored_path(node: &OneNode, id: GitOid) -> PathBuf {
    let mut directories = vec![node.storage_root().join("objects")];
    let mut matches = Vec::new();
    let name = id.to_string();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
            } else if entry.file_name().to_str() == Some(name.as_str()) {
                matches.push(entry.path());
            }
        }
    }
    assert_eq!(matches.len(), 1);
    matches.pop().unwrap()
}

#[test]
fn omitted_blob_payload_health_is_not_certified_but_selected_corruption_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base, child, blob) = fixture(&root, format);
        let before = snapshot(&node);
        let (baseline, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        let baseline = baseline.unwrap();
        let blob_path = stored_path(&node, blob);
        let original_blob = fs::read(&blob_path).unwrap();
        let mut corrupt_blob = original_blob.clone();
        *corrupt_blob.last_mut().unwrap() ^= 1;
        fs::write(&blob_path, &corrupt_blob).unwrap();
        assert!(node.read_git_object(blob).is_err());
        let (omitted, repeated) = stream(
            &node,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert_eq!(omitted.unwrap().receipt(), baseline.receipt());
        assert_eq!(repeated, bytes);
        let request = node.request_context();
        let mut full = Vec::new();
        assert!(
            node.runtime()
                .block_on(node.export_full_git_bundle_stream_in(
                    &request,
                    &RefVisibility::new(),
                    StreamBundleExportQuery::default(),
                    &mut full,
                ))
                .is_err()
        );
        fs::write(&blob_path, original_blob).unwrap();
        let child_path = stored_path(&node, child);
        let original_child = fs::read(&child_path).unwrap();
        let mut corrupt_child = original_child.clone();
        *corrupt_child.last_mut().unwrap() ^= 1;
        fs::write(&child_path, corrupt_child).unwrap();
        let (refused, partial) = stream(
            &node,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert!(refused.is_err());
        assert!(
            partial.is_empty(),
            "selected metadata is verified during the visible proof"
        );
        fs::write(&child_path, original_child).unwrap();
        let (retry, repeated) = stream(
            &node,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
        );
        assert_eq!(retry.unwrap().receipt(), baseline.receipt());
        assert_eq!(repeated, bytes);
        assert_eq!(snapshot(&node).basis(), before.basis());
        node.shutdown().unwrap();
    }
}

struct PrivateFile<'a> {
    file: fs::File,
    remaining: usize,
    pulse: Option<&'a Cell<bool>>,
}
impl Write for PrivateFile<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("test private-file write refusal"));
        }
        let count = self
            .file
            .write(&bytes[..bytes.len().min(self.remaining).min(7)])?;
        self.remaining -= count;
        if let Some(pulse) = self.pulse {
            pulse.set(true);
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("the node does not flush or publish caller-owned output");
    }
}

#[test]
fn interrupted_private_files_leave_no_authority_change_and_the_request_can_retry() {
    let root = Scratch::new();
    let (node, base, _, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let before = snapshot(&node);
    let request = node.request_context();
    let names = [reference("refs/heads/main")];
    let failure_path = root.0.join("private-failed.bundle");
    let mut failure = PrivateFile {
        file: fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&failure_path)
            .unwrap(),
        remaining: 19,
        pulse: None,
    };
    let failed = node
        .runtime()
        .block_on(node.export_incremental_git_bundle_stream_in(
            &request,
            &names,
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
            &mut failure,
        ));
    assert!(matches!(
        failed,
        Err(StreamBundleExportRefusal::Stream(
            StreamFullBundleError::Io(_)
        ))
    ));
    drop(failure);
    assert_eq!(fs::metadata(&failure_path).unwrap().len(), 19);
    let pulse = Cell::new(false);
    let stops = Cell::new(0);
    let stopped_path = root.0.join("private-stopped.bundle");
    let mut stopped = PrivateFile {
        file: fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&stopped_path)
            .unwrap(),
        remaining: usize::MAX,
        pulse: Some(&pulse),
    };
    let result = node
        .runtime()
        .block_on(node.export_incremental_git_bundle_stream_controlled_in(
            &request,
            &names,
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
            &mut stopped,
            &mut || {
                if pulse.replace(false) {
                    stops.set(stops.get() + 1);
                    false
                } else {
                    true
                }
            },
        ));
    assert!(matches!(
        result,
        Err(StreamBundleExportRefusal::Cancelled { exhaustion: None })
    ));
    assert_eq!(
        stops.get(),
        1,
        "the first stop remains latched even when the probe returns live later"
    );
    drop(stopped);
    assert_eq!(fs::metadata(&stopped_path).unwrap().len(), 7);
    assert!(matches!(
        crate::checkpoint_pack_context(request.authority()),
        crate::PackContextCheckpoint::Live
    ));
    let retry_path = root.0.join("private-retry.bundle");
    let mut retry = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&retry_path)
        .unwrap();
    let selected = node
        .runtime()
        .block_on(node.export_incremental_git_bundle_stream_in(
            &request,
            &names,
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery::default(),
            &mut retry,
        ))
        .unwrap();
    drop(retry);
    assert_eq!(
        selected.receipt().bundle_bytes(),
        fs::read(&retry_path).unwrap().len()
    );
    assert_eq!(selected.head(), before.basis().id());
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert_staging_empty(&node);
    node.shutdown().unwrap();
}

#[test]
fn inherited_stop_causes_and_the_exact_start_head_fence_are_preserved() {
    let root = Scratch::new();
    let (node, base, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let old_head = snapshot(&node).basis().id();
    accepted(apply(
        &node,
        &[create("refs/heads/later", base)],
        "stream-head-successor",
    ));
    let before = snapshot(&node);
    let (stale, bytes) = stream(
        &node,
        &["refs/heads/main"],
        &[base],
        &RefVisibility::new(),
        StreamBundleExportQuery {
            expected_head: Some(old_head),
            ..Default::default()
        },
    );
    assert!(matches!(
        stale,
        Err(StreamBundleExportRefusal::ExpectedHead)
    ));
    assert!(bytes.is_empty());
    for (limits, expected) in [
        (
            ClassLimits::finite(Duration::ZERO, 1000, 1000),
            Exhaustion::Deadline,
        ),
        (
            ClassLimits::finite(Duration::from_secs(30), 0, 1000),
            Exhaustion::PollQuota,
        ),
        (
            ClassLimits::finite(Duration::from_secs(30), 1000, 0),
            Exhaustion::CostQuota,
        ),
    ] {
        let request = node.request_context();
        request.authority().set_native_cx(
            node.runtime()
                .request_cx_with_budget(limits.at(node.runtime().now())),
        );
        let mut output = Vec::new();
        let result = node
            .runtime()
            .block_on(node.export_incremental_git_bundle_stream_in(
                &request,
                &[reference("refs/heads/main")],
                &[base],
                &RefVisibility::new(),
                StreamBundleExportQuery::default(),
                &mut output,
            ));
        assert!(
            matches!(result, Err(StreamBundleExportRefusal::Cancelled { exhaustion: Some(cause) })
            if cause == expected),
            "{expected:?}: {result:?}"
        );
        assert!(output.is_empty());
    }
    for timeout in [
        Duration::ZERO,
        Duration::from_secs(3601),
        Duration::from_nanos(1),
    ] {
        let (result, bytes) = stream(
            &node,
            &["refs/heads/main"],
            &[base],
            &RefVisibility::new(),
            StreamBundleExportQuery {
                timeout,
                ..Default::default()
            },
        );
        if timeout == Duration::from_nanos(1) {
            assert!(matches!(result, Err(StreamBundleExportRefusal::Deadline)));
        } else {
            assert!(matches!(
                result,
                Err(StreamBundleExportRefusal::InvalidTimeout)
            ));
        }
        assert!(bytes.is_empty());
    }
    let (allowed, _) = stream(
        &node,
        &["refs/heads/main"],
        &[base],
        &RefVisibility::new(),
        StreamBundleExportQuery {
            expected_head: Some(before.basis().id()),
            ..Default::default()
        },
    );
    assert!(allowed.is_ok());
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}
