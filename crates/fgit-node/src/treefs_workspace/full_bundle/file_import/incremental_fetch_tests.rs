//! Mapped incremental intake uses the same real native graph, destination
//! authority and full-fetch recovery oracle as the enclosing fetch campaign.

use super::*;
use crate::StreamIncrementalBundleImportQuery;

fn write_incremental(
    source: &OneNode,
    path: &Path,
    names: &[&str],
    prerequisites: &[GitOid],
) -> Vec<u8> {
    let request = source.request_context();
    let bytes = source
        .runtime()
        .block_on(source.export_incremental_git_bundle_in(
            &request,
            &names.iter().map(|name| reference(name)).collect::<Vec<_>>(),
            prerequisites,
            &RefVisibility::new(),
            None,
        ))
        .unwrap()
        .1
        .bytes()
        .to_vec();
    fs::write(path, &bytes).unwrap();
    bytes
}

fn incremental_fetch(
    node: &OneNode,
    path: &Path,
    mappings: &[BundleRefMapping],
    key: &str,
    query: StreamIncrementalBundleImportQuery,
    limits: AdmissionLimits,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let mut input = fs::File::open(path).unwrap();
    node.runtime()
        .block_on(node.fetch_incremental_git_bundle_reader_durable_in(
            &request,
            &session(key),
            &mut input,
            mappings,
            query,
            limits,
        ))
}

#[test]
fn mapped_incremental_subset_fanout_and_second_parent_history_share_full_fetch_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        let full = write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[mapping(
                "refs/heads/base",
                "refs/remotes/upstream/main",
                None,
            )],
            "incremental-fetch-seed",
            Default::default(),
        ));
        let before = snapshot(&destination);
        let path = root.0.join("incremental-subset.bundle");
        write_incremental(
            &source.node,
            &path,
            &["refs/heads/main", "refs/heads/topic", "refs/heads/private"],
            &[source.base],
        );
        let subset = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            Some(source.base),
        )];
        let first = committed(incremental_fetch(
            &destination,
            &path,
            &subset,
            "incremental-fetch-subset",
            Default::default(),
            AdmissionLimits {
                max_commands: 1,
                ..Default::default()
            },
        ));
        assert_eq!(
            buffered_fetch(&destination, &full, &subset, "incremental-fetch-subset").unwrap(),
            first,
        );
        assert_eq!(
            snapshot(&destination)
                .selected_closure()
                .closure()
                .objects(),
            &BTreeSet::from([source.base, source.child, source.tree, source.blob]),
        );
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_not_placed(
            &destination,
            &[
                source.merge,
                source.other,
                source.private_tip,
                source.private_blob,
            ],
        );

        // One advertised source fans out to two destinations. Its first parent
        // is unrelated to the old tip; the accepted ancestry is the second.
        let path = root.0.join("incremental-second-parent.bundle");
        let bytes = write_incremental(&source.node, &path, &["refs/heads/main"], &[source.child]);
        let parsed =
            FullBundleInput::parse_incremental(&bytes, FullBundleLimits::default(), &mut || true)
                .unwrap();
        // Keep the existing pack and exact prerequisite; remove optional HEAD
        // so a single header-ref allowance is independent of two commands.
        let signature = match format {
            GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
            GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
        };
        let header = format!(
            "{signature}-{} prerequisite\n{} refs/heads/main\n\n",
            source.child, source.merge,
        );
        fs::write(&path, [header.as_bytes(), parsed.pack_bytes()].concat()).unwrap();
        let byte_destination = RefName::try_new(b"refs/heads/review-\xff").unwrap();
        let fanout = [
            mapping(
                "refs/heads/main",
                "refs/remotes/upstream/main",
                Some(source.child),
            ),
            BundleRefMapping {
                source: reference("refs/heads/main"),
                destination: byte_destination.clone(),
                expected_old: None,
            },
        ];
        let mut query = StreamIncrementalBundleImportQuery::default();
        query.bundle.limits.envelope.max_references = 1;
        let result = committed(incremental_fetch(
            &destination,
            &path,
            &fanout,
            "incremental-fetch-fanout",
            query,
            AdmissionLimits {
                max_commands: 2,
                ..Default::default()
            },
        ));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(
            buffered_fetch(&destination, &full, &fanout, "incremental-fetch-fanout").unwrap(),
            result,
        );
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs[&byte_destination], source.merge);
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.merge)
        );
        assert!(tip(&destination, "refs/heads/main").is_none());
        assert!(tip(&destination, "refs/heads/private").is_none());
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root,
        );
        assert_native_transfer(&source.node, &destination, source.merge);
        assert_not_placed(&destination, &[source.private_tip, source.private_blob]);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn empty_incremental_pack_proves_original_ancestry_without_spending_uploaded_expansion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[
                mapping("refs/heads/base", "refs/remotes/upstream/main", None),
                mapping("refs/heads/topic", "refs/heads/original", None),
            ],
            "incremental-empty-seed",
            Default::default(),
        ));
        let path = root.0.join("empty-incremental.bundle");
        let bytes = write_incremental(&source.node, &path, &["refs/heads/topic"], &[source.child]);
        let parsed =
            FullBundleInput::parse_incremental(&bytes, FullBundleLimits::default(), &mut || true)
                .unwrap();
        let pack = fgit_pack::read_verified_pack(
            parsed.pack_bytes(),
            format,
            &Default::default(),
            &mut || true,
            &fgit_pack::NativeChecksumVerifier,
        )
        .unwrap();
        assert!(pack.entries().is_empty());
        let before = snapshot(&destination);
        let mut query = StreamIncrementalBundleImportQuery::default();
        query.bundle.limits.pack.max_total_expanded_bytes = 1;
        query.bundle.limits.graph.max_payload_bytes = 1;
        let updates = [
            mapping(
                "refs/heads/topic",
                "refs/remotes/upstream/main",
                Some(source.base),
            ),
            mapping("refs/heads/topic", "refs/tags/selected", None),
        ];
        committed(incremental_fetch(
            &destination,
            &path,
            &updates,
            "incremental-empty-advance",
            query.clone(),
            Default::default(),
        ));
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_eq!(tip(&destination, "refs/tags/selected"), Some(source.child));
        assert_eq!(
            snapshot(&destination).selected_closure().closure(),
            before.selected_closure().closure(),
        );
        // A healthy prerequisite is still read and authenticated independently
        // of the empty upload, and a narrow original budget is not reset.
        let after = snapshot(&destination);
        query.max_original_bytes = 1;
        assert!(
            incremental_fetch(
                &destination,
                &path,
                &[mapping("refs/heads/topic", "refs/heads/budget", None)],
                "incremental-original-budget",
                query,
                Default::default(),
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());
        assert_native_transfer(&source.node, &destination, source.child);
        assert_not_placed(
            &destination,
            &[source.merge, source.private_tip, source.private_blob],
        );
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}
