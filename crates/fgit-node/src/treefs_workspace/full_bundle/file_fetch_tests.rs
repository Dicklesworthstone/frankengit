//! Mapped file custody against the buffered oracle and real native authority.
//! Source graphs enter through native directory import; no foreign Git is used.
#![cfg(unix)]

#[path = "file_import/incremental_fetch_tests.rs"]
mod incremental_fetch_tests;

use super::*;
use crate::source_retrieval::integrity::bundle_verify::BundleVerifyError;
use crate::{StreamBundleImportQuery, StreamBundleImportRefusal};
use fgit_admission::evidence::AdmissionAuthentication;
use fgit_pack::full_bundle::fetch::BundleRefMapping;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, Read, Seek, SeekFrom};

struct GraphFixture {
    node: OneNode,
    base: GitOid,
    child: GitOid,
    other: GitOid,
    merge: GitOid,
    blob: GitOid,
    tree: GitOid,
    private_blob: GitOid,
    private_tip: GitOid,
    ids: BTreeSet<GitOid>,
}

fn graph_fixture(scratch: &Scratch, format: GitHashAlgorithm) -> GraphFixture {
    let root = scratch.0.join("mapped-source.git");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::create_dir_all(root.join("refs/tags")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let mut ids = BTreeSet::new();
    let mut put = |kind: GitObjectKind, body: &[u8]| {
        let id = loose(&root, format, kind, kind.label(), body);
        ids.insert(id);
        id
    };
    let blob = put(GitObjectKind::Blob, b"selected history\n");
    let tree = put(
        GitObjectKind::Tree,
        &[b"100644 selected\0".as_slice(), blob.as_bytes()].concat(),
    );
    let commit = |tree, parents: &[GitOid], label| {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").expect("writing to a String cannot fail");
        }
        writeln!(body, "author Native <native@example.test> 1 +0000\ncommitter Native <native@example.test> 1 +0000\n\n{label}").expect("writing to a String cannot fail");
        body.into_bytes()
    };
    let base = put(GitObjectKind::Commit, &commit(tree, &[], "base"));
    let child = put(GitObjectKind::Commit, &commit(tree, &[base], "child"));
    let other_blob = put(GitObjectKind::Blob, b"first parent history\n");
    let other_tree = put(
        GitObjectKind::Tree,
        &[b"100644 other\0".as_slice(), other_blob.as_bytes()].concat(),
    );
    let other = put(
        GitObjectKind::Commit,
        &commit(other_tree, &[], "other root"),
    );
    // The accepted update from child must traverse the second parent.
    let merge = put(
        GitObjectKind::Commit,
        &commit(tree, &[other, child], "merge"),
    );
    let private_blob = put(GitObjectKind::Blob, b"unselected exclusive history\n");
    let private_tree = put(
        GitObjectKind::Tree,
        &[b"100644 private\0".as_slice(), private_blob.as_bytes()].concat(),
    );
    let private_tip = put(
        GitObjectKind::Commit,
        &commit(private_tree, &[], "private root"),
    );
    for (name, tip) in [
        ("main", merge),
        ("topic", child),
        ("base", base),
        ("private", private_tip),
    ] {
        fs::write(root.join("refs/heads").join(name), format!("{tip}\n")).unwrap();
    }
    fs::write(root.join("refs/tags/blob"), format!("{private_blob}\n")).unwrap();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.import_request_context(None);
    committed(
        node.runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &root,
                principal(),
                b"mapped-file-source",
            )),
    );
    GraphFixture {
        node,
        base,
        child,
        other,
        merge,
        blob,
        tree,
        private_blob,
        private_tip,
        ids,
    }
}

fn mapping(source: &str, destination: &str, expected_old: Option<GitOid>) -> BundleRefMapping {
    BundleRefMapping {
        source: reference(source),
        destination: reference(destination),
        expected_old,
    }
}

fn write_export(source: &OneNode, path: &Path, visibility: &RefVisibility) -> Vec<u8> {
    let bytes = export(source, visibility).into_bytes();
    fs::write(path, &bytes).unwrap();
    bytes
}

fn buffered_fetch(
    node: &OneNode,
    bytes: &[u8],
    mappings: &[BundleRefMapping],
    key: &str,
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request = node.import_request_context(None);
    node.runtime()
        .block_on(node.fetch_full_git_bundle_durable_in(
            &request,
            &session(key),
            bytes,
            mappings,
            AdmissionLimits::default(),
        ))
}

fn file_fetch(
    node: &OneNode,
    path: &Path,
    mappings: &[BundleRefMapping],
    key: &str,
    query: StreamBundleImportQuery,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    fetch_as(
        node,
        path,
        mappings,
        session(key),
        query,
        AdmissionLimits::default(),
    )
}

fn fetch_as(
    node: &OneNode,
    path: &Path,
    mappings: &[BundleRefMapping],
    session: LoopbackReceiveSession,
    query: StreamBundleImportQuery,
    limits: AdmissionLimits,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let mut input = fs::File::open(path).unwrap();
    node.runtime()
        .block_on(node.fetch_full_git_bundle_reader_durable_in(
            &request, &session, &mut input, mappings, query, limits,
        ))
}

fn committed<E: std::fmt::Debug>(result: Result<AdmissionResult, E>) -> AdmissionResult {
    let result = result.unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.session.tx_ids.len(), 1);
    assert!(!result.commands.is_empty());
    assert!(
        result.commands.iter().all(|command| {
            command == &result.commands[0]
                && matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })
        }),
        "{result:?}"
    );
    result
}

fn tip(node: &OneNode, name: &str) -> Option<GitOid> {
    snapshot(node)
        .snapshot()
        .refs
        .get(&reference(name))
        .copied()
}

fn assert_not_placed(node: &OneNode, ids: &[GitOid]) {
    for id in ids {
        assert_missing(node, *id);
    }
    assert_staging_empty(node);
}

#[test]
fn subset_fanout_and_second_parent_fast_forward_match_the_buffered_oracle() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("all-refs.bundle");
        let bytes = write_export(&source.node, &path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let oracle_root = Scratch::new();
        let oracle = empty_node(&oracle_root, format);
        let empty = snapshot(&destination);
        let initial = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            None,
        )];
        // The advertised inventory contains five refs and HEAD. Only the one
        // selected command consumes this narrower atomic-command allowance.
        let first = committed(fetch_as(
            &destination,
            &path,
            &initial,
            session("subset"),
            Default::default(),
            AdmissionLimits {
                max_commands: 1,
                ..Default::default()
            },
        ));
        let buffered = committed(buffered_fetch(&oracle, &bytes, &initial, "subset"));
        assert_eq!(first.session.tx_ids, buffered.session.tx_ids);
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            snapshot(&oracle).snapshot().refs
        );
        assert_eq!(
            snapshot(&destination).selected_closure().closure(),
            snapshot(&oracle).selected_closure().closure()
        );
        assert_eq!(
            snapshot(&destination)
                .selected_closure()
                .closure()
                .objects(),
            &BTreeSet::from([source.base, source.child, source.tree, source.blob])
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

        let fanout = [
            mapping(
                "refs/heads/main",
                "refs/remotes/upstream/main",
                Some(source.child),
            ),
            mapping("refs/heads/main", "refs/heads/review", None),
        ];
        // Inverse allowance: this header advertises one source (no HEAD),
        // while two mapped destinations fit the independent command budget.
        let header_end = bytes.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let signature = match format {
            GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
            GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
        };
        let header = format!("{signature}{} refs/heads/main\n\n", source.merge);
        let one_ref_bytes = [header.as_bytes(), &bytes[header_end..]].concat();
        let one_ref_path = root.0.join("one-source.bundle");
        fs::write(&one_ref_path, &one_ref_bytes).unwrap();
        let mut one_ref = StreamBundleImportQuery::default();
        one_ref.limits.envelope.max_references = 1;
        let fetched = committed(fetch_as(
            &destination,
            &one_ref_path,
            &fanout,
            session("advance"),
            one_ref,
            AdmissionLimits {
                max_commands: 2,
                ..Default::default()
            },
        ));
        let buffered = committed(buffered_fetch(&oracle, &one_ref_bytes, &fanout, "advance"));
        assert_eq!(fetched.session.tx_ids, buffered.session.tx_ids);
        assert_eq!(fetched.commands.len(), 2);
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.merge)
        );
        assert_eq!(tip(&destination, "refs/heads/review"), Some(source.merge));
        assert!(tip(&destination, "refs/heads/main").is_none());
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs, snapshot(&oracle).snapshot().refs);
        assert_eq!(
            after.selected_closure().closure(),
            snapshot(&oracle).selected_closure().closure()
        );
        assert_eq!(after.snapshot().head_target, empty.snapshot().head_target);
        assert_eq!(after.snapshot().outbox, empty.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            empty.basis().body().forge_position_root
        );
        assert_native_transfer(&source.node, &destination, source.merge);
        assert_not_placed(&destination, &[source.private_tip, source.private_blob]);
        oracle.shutdown().unwrap();
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn exact_old_refusal_is_atomic_and_replays_across_profiles_after_limits_and_quota_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("candidate.bundle");
        let bytes = write_export(&source.node, &path, &RefVisibility::new());
        let target = Scratch::new();
        let mut destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &path,
            &[mapping(
                "refs/heads/base",
                "refs/remotes/upstream/main",
                None,
            )],
            "seed",
            Default::default(),
        ));
        let before = snapshot(&destination);
        let stale = [
            mapping(
                "refs/heads/main",
                "refs/remotes/upstream/main",
                Some(source.child),
            ),
            mapping("refs/heads/main", "refs/heads/partial", None),
        ];
        let refusal = file_fetch(&destination, &path, &stale, "stale", Default::default()).unwrap();
        assert_eq!(refusal.commands.len(), 2);
        assert!(refusal.commands.iter().all(|command| matches!(
            command.terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        )));
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            before.snapshot().refs
        );
        assert_not_placed(
            &destination,
            &[source.child, source.merge, source.other, source.private_tip],
        );
        let refused_head = snapshot(&destination);
        assert_eq!(
            buffered_fetch(&destination, &bytes, &stale, "stale").unwrap(),
            refusal
        );
        let reversed = [stale[1].clone(), stale[0].clone()];
        assert_eq!(
            file_fetch(&destination, &path, &reversed, "stale", Default::default()).unwrap(),
            refusal
        );
        assert_eq!(snapshot(&destination).basis(), refused_head.basis());

        let allowed = [
            mapping(
                "refs/heads/main",
                "refs/remotes/upstream/main",
                Some(source.base),
            ),
            stale[1].clone(),
        ];
        let terminal = committed(buffered_fetch(&destination, &bytes, &allowed, "permitted"));
        let committed_head = snapshot(&destination);
        destination.push_quota.limit.max_events = 0;
        let end = bytes.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let header = root.0.join("header-only.bundle");
        fs::write(&header, &bytes[..end]).unwrap();
        let mut limited = StreamBundleImportQuery::default();
        limited.limits.pack.max_object_bytes = 1;
        limited.limits.graph.max_object_bytes = 1;
        limited.limits.max_streamed_blob_bytes = 1;
        assert_eq!(
            file_fetch(
                &destination,
                &header,
                &allowed,
                "permitted",
                limited.clone()
            )
            .unwrap(),
            terminal
        );
        assert_eq!(
            file_fetch(&destination, &header, &stale, "stale", limited.clone()).unwrap(),
            refusal
        );
        assert_eq!(snapshot(&destination).basis(), committed_head.basis());
        assert!(
            file_fetch(
                &destination,
                &header,
                &[mapping("refs/heads/main", "refs/heads/different", None)],
                "permitted",
                limited.clone()
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), committed_head.basis());
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        let reopened = OneNode::open_existing(target.config(format)).unwrap();
        assert_eq!(
            file_fetch(&reopened, &header, &allowed, "permitted", limited).unwrap(),
            terminal
        );
        assert_eq!(snapshot(&reopened).basis(), committed_head.basis());
        assert_staging_empty(&reopened);
        reopened.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn non_fast_forwards_wrong_mapped_kinds_and_tag_replacement_refuse_without_partial_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("typed.bundle");
        let bytes = write_export(&source.node, &path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &path,
            &[
                mapping("refs/heads/topic", "refs/remotes/upstream/main", None),
                mapping("refs/heads/base", "refs/tags/stable", None),
            ],
            "initial",
            Default::default(),
        ));
        let before = snapshot(&destination);
        for (key, mappings) in [
            (
                "rewind",
                vec![
                    mapping(
                        "refs/heads/base",
                        "refs/remotes/upstream/main",
                        Some(source.child),
                    ),
                    mapping("refs/heads/main", "refs/heads/partial", None),
                ],
            ),
            (
                "tag-replacement",
                vec![mapping(
                    "refs/heads/main",
                    "refs/tags/stable",
                    Some(source.base),
                )],
            ),
            (
                "wrong-tracking-kind",
                vec![mapping(
                    "refs/tags/blob",
                    "refs/remotes/upstream/blob",
                    None,
                )],
            ),
            (
                "wrong-branch-kind",
                vec![mapping("refs/tags/blob", "refs/heads/blob", None)],
            ),
            (
                "duplicate-destination",
                vec![
                    mapping("refs/heads/main", "refs/heads/duplicate", None),
                    mapping("refs/heads/topic", "refs/heads/duplicate", None),
                ],
            ),
        ] {
            assert!(
                file_fetch(&destination, &path, &mappings, key, Default::default()).is_err(),
                "{key}"
            );
            assert!(
                buffered_fetch(&destination, &bytes, &mappings, key).is_err(),
                "{key}"
            );
            assert_eq!(snapshot(&destination).basis(), before.basis());
            assert_not_placed(
                &destination,
                &[
                    source.merge,
                    source.other,
                    source.private_tip,
                    source.private_blob,
                ],
            );
        }
        committed(file_fetch(
            &destination,
            &path,
            &[
                mapping("refs/heads/base", "refs/tags/stable", Some(source.base)),
                mapping("refs/tags/blob", "refs/tags/blob", None),
            ],
            "tag-permitted",
            Default::default(),
        ));
        assert_eq!(tip(&destination, "refs/tags/stable"), Some(source.base));
        assert_eq!(
            tip(&destination, "refs/tags/blob"),
            Some(source.private_blob)
        );
        assert_native_transfer(&source.node, &destination, source.private_blob);
        assert_missing(&destination, source.private_tip);
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

fn authenticated_session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::Authenticated(
        crate::AuthenticatedReceiveSession::new(
            principal(),
            IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
        )
        .with_authentication(AdmissionAuthentication::HttpToken),
    )
}

#[test]
fn mapped_fetch_preserves_authenticated_policy_evidence_and_original_terminal_identity() {
    use fgit_admission::evidence::PolicyDecisionRecord;
    use fgit_forge::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("authenticated.bundle");
        let bytes = write_export(&source.node, &path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let request = destination.request_context();
        let current = destination
            .runtime()
            .block_on(destination.read_review_protection_in(&request))
            .unwrap();
        let command = ProtectionCommand {
            expected_version: current.version().map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
            expected_epoch: current.policy_epoch,
            protection: ReviewProtection {
                administrators: vec![principal()],
                branches: Vec::new(),
                ref_policy: Some(compile_ref_policy(
                    "policy authentication { rule credential { when actor.authentication >= single_factor then allow } default deny \"verified credential required\" }",
                ).unwrap()),
            },
        };
        let installed = destination
            .runtime()
            .block_on(destination.admit_review_protection_durable_in(
                &request,
                &session("mapped-policy"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            installed.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let mappings = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            None,
        )];
        let refusal = file_fetch(
            &destination,
            &path,
            &mappings,
            "operator",
            Default::default(),
        )
        .unwrap();
        assert!(matches!(
            refusal.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        assert_not_placed(&destination, &[source.base, source.child, source.blob]);
        assert_eq!(
            fetch_as(
                &destination,
                &path,
                &mappings,
                authenticated_session("operator"),
                Default::default(),
                Default::default()
            )
            .unwrap(),
            refusal
        );
        let accepted = committed(fetch_as(
            &destination,
            &path,
            &mappings,
            authenticated_session("authenticated"),
            Default::default(),
            Default::default(),
        ));
        assert_eq!(
            buffered_fetch(&destination, &bytes, &mappings, "authenticated").unwrap(),
            accepted
        );
        let tx_id = accepted.session.tx_ids[0];
        let history = destination
            .runtime()
            .block_on(destination.snapshot_history_in(&request))
            .unwrap();
        let record = history
            .iter()
            .flat_map(|batch| &batch.batch.committed_rcrs)
            .find(|record| record.tx_id == tx_id)
            .unwrap()
            .clone();
        let identity = record.principal_snapshot_id.as_internal_object_id();
        let principal_receipt = destination
            .runtime()
            .block_on(crate::read_principal_snapshot_in(
                &destination.authority,
                request.authority(),
                destination.repository_id,
                fgit_types::Digest::new(identity.algorithm(), *identity.digest()),
                &|| false,
            ))
            .unwrap();
        assert_eq!(
            principal_receipt.authentication(),
            Some(AdmissionAuthentication::HttpToken)
        );
        let policy = destination
            .runtime()
            .block_on(crate::read_policy_decision_in(
                &destination.authority,
                request.authority(),
                destination.repository_id,
                record.policy_decision_root,
                &|| false,
            ))
            .unwrap();
        assert!(matches!(
            policy,
            PolicyDecisionRecord::AuthenticationActivated(_)
        ));
        assert_eq!(
            policy.authentication(),
            Some(AdmissionAuthentication::HttpToken)
        );
        assert_not_placed(
            &destination,
            &[source.merge, source.private_tip, source.private_blob],
        );
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

struct SwappedFile {
    input: fs::File,
    replacement: PathBuf,
    rewinds: usize,
}
impl Read for SwappedFile {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let offered = output.len().min(7);
        self.input.read(&mut output[..offered])
    }
}
impl Seek for SwappedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if position == SeekFrom::Start(0) {
            self.rewinds += 1;
            if self.rewinds == 2 {
                self.input = fs::File::open(&self.replacement)?;
            }
        }
        self.input.seek(position)
    }
}

#[test]
fn hidden_sources_and_a_changed_semantic_header_never_borrow_or_publish_candidate_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("complete.bundle");
        let bytes = write_export(&source.node, &path, &RefVisibility::new());
        let mut visibility = RefVisibility::new();
        visibility
            .push_rule(b"refs/heads/private", &Default::default())
            .unwrap();
        visibility
            .push_rule(b"refs/tags/blob", &Default::default())
            .unwrap();
        let hidden_path = root.0.join("visible.bundle");
        write_export(&source.node, &hidden_path, &visibility);
        let before_source = snapshot(&source.node);
        // Even the source node's existing private bytes cannot supply a ref
        // omitted from the authenticated bundle advertisement.
        assert!(
            file_fetch(
                &source.node,
                &hidden_path,
                &[mapping("refs/heads/private", "refs/heads/revived", None)],
                "hidden-source",
                Default::default()
            )
            .is_err()
        );
        assert_eq!(snapshot(&source.node).basis(), before_source.basis());
        assert_staging_empty(&source.node);

        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let before = snapshot(&destination);
        let old_line = format!("{} refs/heads/topic\n", source.child);
        let new_line = format!("{} refs/heads/topic\n", source.merge);
        let mut changed = bytes.clone();
        let at = changed
            .windows(old_line.len())
            .position(|part| part == old_line.as_bytes())
            .unwrap();
        changed[at..at + old_line.len()].copy_from_slice(new_line.as_bytes());
        let replacement = root.0.join("replacement.bundle");
        fs::write(&replacement, changed).unwrap();
        let mut reader = SwappedFile {
            input: fs::File::open(&path).unwrap(),
            replacement,
            rewinds: 0,
        };
        let request = destination.import_request_context(None);
        let mappings = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            None,
        )];
        let result =
            destination
                .runtime()
                .block_on(destination.fetch_full_git_bundle_reader_durable_in(
                    &request,
                    &session("header-race"),
                    &mut reader,
                    &mappings,
                    Default::default(),
                    Default::default(),
                ));
        assert!(matches!(
            result,
            Err(StreamBundleImportRefusal::Verification(
                BundleVerifyError::SourceChanged
            ))
        ));
        assert_eq!(snapshot(&destination).basis(), before.basis());
        assert_not_placed(
            &destination,
            &[source.base, source.child, source.merge, source.private_tip],
        );
        committed(file_fetch(
            &destination,
            &path,
            &mappings,
            "header-race",
            Default::default(),
        ));
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_not_placed(
            &destination,
            &[source.merge, source.private_tip, source.private_blob],
        );
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn cancellation_during_private_staging_drops_every_candidate_and_same_key_retry_can_commit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("cancellable.bundle");
        write_export(&source.node, &path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let before = snapshot(&destination);
        let request = destination.import_request_context(None);
        let saw_stage = Cell::new(false);
        let staging = destination.storage_root().join("staging");
        let mut live = || {
            if fs::read_dir(&staging).unwrap().any(|entry| {
                let entry = entry.unwrap();
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "stage")
                    && entry.metadata().unwrap().len() > 0
            }) {
                saw_stage.set(true);
            }
            !saw_stage.get()
        };
        let mappings = [mapping(
            "refs/heads/main",
            "refs/remotes/upstream/main",
            None,
        )];
        let mut input = fs::File::open(&path).unwrap();
        let result =
            destination
                .runtime()
                .block_on(destination.fetch_full_git_bundle_reader_controlled_in(
                    &request,
                    &session("cancel-retry"),
                    &mut input,
                    &mappings,
                    Default::default(),
                    Default::default(),
                    &mut live,
                ));
        assert!(
            saw_stage.get(),
            "stop must observe actual private candidate custody"
        );
        assert!(result.is_err());
        assert_eq!(snapshot(&destination).basis(), before.basis());
        assert_not_placed(
            &destination,
            &source.ids.iter().copied().collect::<Vec<_>>(),
        );
        committed(file_fetch(
            &destination,
            &path,
            &mappings,
            "cancel-retry",
            Default::default(),
        ));
        assert_native_transfer(&source.node, &destination, source.merge);
        assert_not_placed(&destination, &[source.private_tip, source.private_blob]);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

fn stored_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut length = body.len();
    let mut record = vec![(kind << 4) | (length as u8 & 15)];
    length >>= 4;
    while length != 0 {
        *record.last_mut().unwrap() |= 128;
        record.push((length & 127) as u8);
        length >>= 7;
    }
    let length = u16::try_from(body.len()).unwrap();
    record.extend_from_slice(&[0x78, 0x01, 0x01]);
    record.extend_from_slice(&length.to_le_bytes());
    record.extend_from_slice(&(!length).to_le_bytes());
    record.extend_from_slice(body);
    let (a, b) = body.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    record.extend_from_slice(&((b << 16) | a).to_be_bytes());
    record
}

fn seal_pack(format: GitHashAlgorithm, mut pack: Vec<u8>) -> Vec<u8> {
    let checksum = match format {
        GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&pack).to_vec(),
    };
    pack.extend(checksum);
    pack
}

#[test]
fn unselected_invalid_objects_are_verified_and_missing_graph_cannot_borrow_destination_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let path = root.0.join("valid.bundle");
        let bytes = write_export(&source.node, &path, &RefVisibility::new());
        let parsed = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let pack = parsed.pack_bytes();
        let prefix = &bytes[..bytes.len() - pack.len()];
        // This extra unselected object has a valid native ID, DEFLATE member
        // and pack checksum, but its tree body is structurally malformed.
        let mut bad_pack = pack[..pack.len() - format.digest_len()].to_vec();
        let count = u32::from_be_bytes(bad_pack[8..12].try_into().unwrap());
        bad_pack[8..12].copy_from_slice(&(count + 1).to_be_bytes());
        bad_pack.extend(stored_record(2, b"100644 broken\0"));
        let invalid = root.0.join("unselected-invalid.bundle");
        fs::write(
            &invalid,
            [prefix, seal_pack(format, bad_pack).as_slice()].concat(),
        )
        .unwrap();
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let empty = snapshot(&destination);
        let selected = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            None,
        )];
        assert!(
            file_fetch(
                &destination,
                &invalid,
                &selected,
                "unselected",
                Default::default()
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), empty.basis());
        assert_not_placed(
            &destination,
            &source.ids.iter().copied().collect::<Vec<_>>(),
        );
        committed(file_fetch(
            &destination,
            &path,
            &selected,
            "unselected",
            Default::default(),
        ));

        let before = snapshot(&destination);
        let commit = source.node.read_git_object(source.child).unwrap();
        let mut incomplete_pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        incomplete_pack.extend(stored_record(1, commit.payload()));
        let signature = match format {
            GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
            GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
        };
        let incomplete = root.0.join("missing-graph.bundle");
        let header = format!("{signature}{} refs/heads/topic\n\n", source.child);
        fs::write(
            &incomplete,
            [
                header.as_bytes(),
                seal_pack(format, incomplete_pack).as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        let mapped = [mapping("refs/heads/topic", "refs/heads/no-borrow", None)];
        assert!(
            file_fetch(
                &destination,
                &incomplete,
                &mapped,
                "missing",
                Default::default()
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), before.basis());
        assert!(tip(&destination, "refs/heads/no-borrow").is_none());
        assert_native_transfer(&source.node, &destination, source.child);
        assert_staging_empty(&destination);
        committed(file_fetch(
            &destination,
            &path,
            &mapped,
            "missing",
            Default::default(),
        ));
        assert_eq!(
            tip(&destination, "refs/heads/no-borrow"),
            Some(source.child)
        );
        assert_not_placed(
            &destination,
            &[source.merge, source.private_tip, source.private_blob],
        );
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}
