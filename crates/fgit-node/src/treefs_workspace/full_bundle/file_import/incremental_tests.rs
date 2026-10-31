//! File-backed incremental intake through real native exports, file readers,
//! prerequisite custody and ordinary durable admission.

use super::*;
use crate::{StreamBundleImportRefusal, StreamIncrementalBundleImportQuery};
use std::cell::Cell;

fn incremental_bytes(node: &OneNode, names: &[&str], prerequisites: &[GitOid]) -> Vec<u8> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.export_incremental_git_bundle_in(
            &request,
            &names.iter().map(|name| reference(name)).collect::<Vec<_>>(),
            prerequisites,
            &RefVisibility::new(),
            None,
        ))
        .unwrap()
        .1
        .bytes()
        .to_vec()
}

fn seed_originals(source: &OneNode, destination: &OneNode, base: GitOid) {
    accepted(apply(
        source,
        &[create("refs/heads/seed", base)],
        "file-sync-seed-ref",
    ));
    let mut visibility = RefVisibility::new();
    visibility
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    accepted(import(
        destination,
        export(source, &visibility).bytes(),
        "file-sync-seed-objects",
    ));
    accepted(apply(
        destination,
        &[create("refs/heads/main", base)],
        "file-sync-seed-main",
    ));
}

fn sync_file(
    node: &OneNode,
    path: &Path,
    expectations: &[(&str, Option<GitOid>)],
    key: &str,
    query: StreamIncrementalBundleImportQuery,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let mut input = fs::File::open(path).unwrap();
    let expectations = expectations
        .iter()
        .map(|(name, old)| (reference(name), *old))
        .collect::<Vec<_>>();
    node.runtime()
        .block_on(node.import_incremental_git_bundle_reader_durable_in(
            &request,
            &session(key),
            &mut input,
            &expectations,
            query,
            AdmissionLimits::default(),
        ))
}

fn committed_sync(result: Result<AdmissionResult, StreamBundleImportRefusal>) -> AdmissionResult {
    let result = result.unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.session.tx_ids.len(), 1);
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })),
        "{result:?}"
    );
    result
}

#[test]
fn file_incremental_exact_old_updates_are_atomic_and_replay_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, base, child, blob) = fixture(&source_root, format);
        let destination_root = Scratch::new();
        let mut destination = empty_node(&destination_root, format);
        seed_originals(&source, &destination, base);
        accepted(apply(
            &source,
            &[create("refs/heads/release", child)],
            "file-sync-release",
        ));
        let bytes = incremental_bytes(&source, &["refs/heads/main", "refs/heads/release"], &[base]);
        let path = source_root.0.join("incremental.bundle");
        fs::write(&path, &bytes).unwrap();
        let before = snapshot(&destination);
        let expectations = [
            ("refs/heads/main", Some(base)),
            ("refs/heads/release", None),
        ];
        let result = committed_sync(sync_file(
            &destination,
            &path,
            &expectations,
            "file-sync-atomic",
            Default::default(),
        ));
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs[&reference("refs/heads/main")], child);
        assert_eq!(
            after.snapshot().refs[&reference("refs/heads/release")],
            child
        );
        assert_eq!(after.snapshot().refs[&reference("refs/heads/seed")], base);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_native_transfer(&source, &destination, base);
        assert_native_transfer(&source, &destination, blob);
        assert_native_transfer(&source, &destination, child);
        assert_staging_empty(&destination);
        assert!(
            sync_file(
                &destination,
                &path,
                &[("refs/heads/main", None), ("refs/heads/release", None)],
                "file-sync-atomic",
                Default::default(),
            )
            .is_err(),
            "changed expected-old is not the sealed retry"
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());

        destination.shutdown().unwrap();
        destination = OneNode::open_existing(destination_root.config(format)).unwrap();
        destination.push_quota.limit.max_events = 0;
        let mut corrupt_replay = bytes;
        *corrupt_replay.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupt_replay).unwrap();
        assert_eq!(
            sync_file(
                &destination,
                &path,
                &expectations,
                "file-sync-atomic",
                Default::default()
            )
            .unwrap(),
            result,
            "a terminal retry precedes fresh pack verification and mutation quota",
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn file_incremental_stale_lease_refuses_every_ref_and_keeps_uploaded_objects_private() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, base, child, blob) = fixture(&source_root, format);
        let destination_root = Scratch::new();
        let destination = empty_node(&destination_root, format);
        seed_originals(&source, &destination, base);
        accepted(apply(
            &source,
            &[create("refs/heads/release", child)],
            "file-sync-stale-release",
        ));
        let path = source_root.0.join("stale.bundle");
        fs::write(
            &path,
            incremental_bytes(&source, &["refs/heads/main", "refs/heads/release"], &[base]),
        )
        .unwrap();
        let before = snapshot(&destination);
        let expectations = [
            ("refs/heads/main", Some(blob)),
            ("refs/heads/release", None),
        ];
        let result = sync_file(
            &destination,
            &path,
            &expectations,
            "file-sync-stale",
            Default::default(),
        )
        .unwrap();
        assert!(result.session.atomic);
        assert!(
            result
                .commands
                .iter()
                .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Refused { .. }))
        );
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            before.snapshot().refs
        );
        assert_missing(&destination, child);
        assert_native_transfer(&source, &destination, base);
        assert_native_transfer(&source, &destination, blob);
        assert_staging_empty(&destination);
        assert_eq!(
            sync_file(
                &destination,
                &path,
                &expectations,
                "file-sync-stale",
                Default::default()
            )
            .unwrap(),
            result
        );
        assert_missing(&destination, child);
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn file_incremental_missing_wrong_kind_and_undeclared_history_never_repairs_the_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, base, child, blob) = fixture(&source_root, format);
        let incremental = incremental_bytes(&source, &["refs/heads/main"], &[base]);
        let complete = export(&source, &RefVisibility::new()).bytes().to_vec();
        let path = source_root.0.join("prerequisites.bundle");
        fs::write(&path, &incremental).unwrap();
        let destination_root = Scratch::new();
        let destination = empty_node(&destination_root, format);
        let empty = snapshot(&destination);
        assert!(
            sync_file(
                &destination,
                &path,
                &[("refs/heads/main", None)],
                "file-sync-missing",
                Default::default()
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), empty.basis());
        assert_missing(&destination, child);
        assert_staging_empty(&destination);

        seed_originals(&source, &destination, base);
        let before = snapshot(&destination);
        let parsed = FullBundleInput::parse_incremental(
            &incremental,
            FullBundleLimits::default(),
            &mut || true,
        )
        .unwrap();
        let header_bytes = incremental.len() - parsed.pack_bytes().len();
        let header = std::str::from_utf8(&incremental[..header_bytes]).unwrap();
        let undeclared = [
            header
                .split_inclusive('\n')
                .filter(|line| !line.starts_with('-'))
                .collect::<String>()
                .into_bytes(),
            parsed.pack_bytes().to_vec(),
        ]
        .concat();
        let wrong_kind = [
            header
                .replace(&format!("-{base} "), &format!("-{blob} "))
                .into_bytes(),
            parsed.pack_bytes().to_vec(),
        ]
        .concat();
        let mut checksum = incremental.clone();
        *checksum.last_mut().unwrap() ^= 1;
        for (index, bytes) in [undeclared, wrong_kind, checksum].into_iter().enumerate() {
            fs::write(&path, bytes).unwrap();
            assert!(
                sync_file(
                    &destination,
                    &path,
                    &[("refs/heads/main", Some(base))],
                    &format!("file-sync-bad-{index}"),
                    Default::default(),
                )
                .is_err()
            );
            assert_eq!(snapshot(&destination).basis(), before.basis());
            assert_missing(&destination, child);
            assert_staging_empty(&destination);
        }

        // Full bundles passed to sync-import must be self-contained. An original
        // budget smaller than any metadata object proves there was no local
        // discovery or borrowing in this successful operation.
        fs::write(&path, complete).unwrap();
        let mut no_borrowing = StreamIncrementalBundleImportQuery::default();
        no_borrowing.max_original_bytes = 1;
        committed_sync(sync_file(
            &destination,
            &path,
            &[("refs/heads/main", Some(base))],
            "file-sync-complete",
            no_borrowing,
        ));
        assert_eq!(
            snapshot(&destination).snapshot().refs[&reference("refs/heads/main")],
            child
        );
        assert_native_transfer(&source, &destination, child);
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn file_incremental_deleted_prerequisites_are_unavailable_despite_retained_native_objects() {
    let format = GitHashAlgorithm::Sha256;
    let source_root = Scratch::new();
    let (source, base, child, _) = fixture(&source_root, format);
    let destination_root = Scratch::new();
    let (mut destination, _) = OneNode::init(
        destination_root
            .config(format)
            .with_initial_branch(reference("refs/heads/retained-default")),
    )
    .unwrap();
    destination
        .bring_into_service(HeadGeneration::FIRST)
        .unwrap();
    seed_originals(&source, &destination, base);
    let path = source_root.0.join("deleted.bundle");
    fs::write(
        &path,
        incremental_bytes(&source, &["refs/heads/main"], &[base]),
    )
    .unwrap();
    // Each branch edit uses its real single-target contract; a pair of
    // deletions is not a rename. The independent unborn default is untouched.
    for (index, name) in ["refs/heads/main", "refs/heads/seed"]
        .into_iter()
        .enumerate()
    {
        accepted(apply(
            &destination,
            &[RefCommand {
                name: reference(name),
                expected_old: ExpectedOld::Exactly(base),
                proposed_new: ProposedNew::Delete,
                force: false,
            }],
            &format!("file-sync-delete-original-root-{index}"),
        ));
    }
    let before = snapshot(&destination);
    assert!(
        before
            .selected_closure()
            .closure()
            .objects()
            .contains(&base)
    );
    assert!(destination.read_git_object(base).is_ok());
    assert!(
        sync_file(
            &destination,
            &path,
            &[("refs/heads/main", None)],
            "file-sync-disconnected",
            Default::default()
        )
        .is_err()
    );
    assert_eq!(snapshot(&destination).basis(), before.basis());
    assert_missing(&destination, child);
    assert_staging_empty(&destination);
    destination.shutdown().unwrap();
    source.shutdown().unwrap();
}

#[test]
fn file_incremental_cancellation_settles_private_custody_and_fresh_same_key_retry_commits() {
    let format = GitHashAlgorithm::Sha256;
    let source_root = Scratch::new();
    let (source, base, child, _) = fixture(&source_root, format);
    let destination_root = Scratch::new();
    let destination = empty_node(&destination_root, format);
    seed_originals(&source, &destination, base);
    let path = source_root.0.join("cancel.bundle");
    fs::write(
        &path,
        incremental_bytes(&source, &["refs/heads/main"], &[base]),
    )
    .unwrap();
    let before = snapshot(&destination);
    let saw_private_scratch = Cell::new(false);
    let staging = destination.storage_root().join("staging");
    let mut live = || {
        if fs::read_dir(&staging).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fg-bundle-incremental-")
        }) {
            saw_private_scratch.set(true);
        }
        !saw_private_scratch.get()
    };
    let request = destination.import_request_context(None);
    let mut input = fs::File::open(&path).unwrap();
    let result = destination.runtime().block_on(
        destination.import_incremental_git_bundle_reader_controlled_in(
            &request,
            &session("file-sync-cancel-retry"),
            &mut input,
            &[(reference("refs/heads/main"), Some(base))],
            Default::default(),
            Default::default(),
            &mut live,
        ),
    );
    assert!(
        saw_private_scratch.get(),
        "stop must reach real private file custody"
    );
    assert!(result.is_err());
    assert_eq!(snapshot(&destination).basis(), before.basis());
    assert_missing(&destination, child);
    assert_staging_empty(&destination);
    committed_sync(sync_file(
        &destination,
        &path,
        &[("refs/heads/main", Some(base))],
        "file-sync-cancel-retry",
        Default::default(),
    ));
    assert_eq!(
        snapshot(&destination).snapshot().refs[&reference("refs/heads/main")],
        child
    );
    assert_native_transfer(&source, &destination, child);
    assert_staging_empty(&destination);
    destination.shutdown().unwrap();
    source.shutdown().unwrap();
}

#[test]
fn file_incremental_empty_pack_publishes_declared_history_under_independent_original_budget() {
    let format = GitHashAlgorithm::Sha256;
    let source_root = Scratch::new();
    let (source, base, _, _) = fixture(&source_root, format);
    let destination_root = Scratch::new();
    let destination = empty_node(&destination_root, format);
    seed_originals(&source, &destination, base);
    accepted(apply(
        &source,
        &[create("refs/heads/copy", base)],
        "file-sync-copy-source",
    ));
    let bytes = incremental_bytes(&source, &["refs/heads/copy"], &[base]);
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
    let path = source_root.0.join("empty-incremental.bundle");
    fs::write(&path, bytes).unwrap();
    let mut query = StreamIncrementalBundleImportQuery::default();
    query.bundle.limits.pack.max_total_expanded_bytes = 1;
    committed_sync(sync_file(
        &destination,
        &path,
        &[("refs/heads/copy", None)],
        "file-sync-empty-pack",
        query,
    ));
    assert_eq!(
        snapshot(&destination).snapshot().refs[&reference("refs/heads/copy")],
        base
    );
    assert_native_transfer(&source, &destination, base);
    assert_staging_empty(&destination);
    destination.shutdown().unwrap();
    source.shutdown().unwrap();
}
