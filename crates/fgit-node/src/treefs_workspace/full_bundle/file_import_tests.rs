//! End-to-end native exports, real file readers and ordinary durable admission.
//! Fixtures enter through the public native directory importer.

#![cfg(unix)]

use super::*;
use crate::source_retrieval::integrity::bundle_verify::BundleVerifyError;
use crate::{StreamBundleExportQuery, StreamBundleImportQuery, StreamBundleImportRefusal};
use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

const METADATA_BYTES: usize = 1024;
const BLOB_BYTES: usize = 256 * 1024 + 17;

fn file_import(
    node: &OneNode,
    path: &Path,
    key: &str,
    query: StreamBundleImportQuery,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let mut input = fs::File::open(path).unwrap();
    node.runtime()
        .block_on(node.import_full_git_bundle_reader_durable_in(
            &request,
            &session(key),
            &mut input,
            query,
            AdmissionLimits::default(),
        ))
}

fn committed(result: Result<AdmissionResult, StreamBundleImportRefusal>) -> AdmissionResult {
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

fn authenticated_file_import(
    node: &OneNode,
    path: &Path,
    key: &str,
    authentication: fgit_admission::evidence::AdmissionAuthentication,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let session = LoopbackReceiveSession::Authenticated(
        crate::AuthenticatedReceiveSession::new(
            principal(),
            IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
        )
        .with_authentication(authentication),
    );
    let mut input = fs::File::open(path).unwrap();
    node.runtime()
        .block_on(node.import_full_git_bundle_reader_durable_in(
            &request,
            &session,
            &mut input,
            Default::default(),
            AdmissionLimits::default(),
        ))
}

#[test]
fn file_import_authentication_survives_policy_evaluation_transport_retry_and_reopen() {
    use fgit_admission::evidence::{AdmissionAuthentication, PolicyDecisionRecord};
    use fgit_forge::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, _, child, _) = fixture(&source_root, format);
        let path = source_root.0.join("authenticated.bundle");
        let bytes = write_export(&source, &path);
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let request = destination.request_context();
        let protection = destination
            .runtime()
            .block_on(destination.read_review_protection_in(&request))
            .unwrap();
        let command = ProtectionCommand {
            expected_version: protection
                .version()
                .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
            expected_epoch: protection.policy_epoch,
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
                &session("file-authentication-policy"),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            installed.1.outcome,
            DecisionOutcome::Committed { .. }
        ));

        let refused =
            file_import(&destination, &path, "operator-file", Default::default()).unwrap();
        assert!(refused.commands.iter().all(|command| matches!(
            command.terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        )));
        assert_missing(&destination, child);
        assert_staging_empty(&destination);
        assert_eq!(
            authenticated_file_import(
                &destination,
                &path,
                "operator-file",
                AdmissionAuthentication::HttpToken,
            )
            .unwrap(),
            refused,
            "a stronger retry must retain the original refusal"
        );

        let result = committed(authenticated_file_import(
            &destination,
            &path,
            "verified-file",
            AdmissionAuthentication::HttpToken,
        ));
        assert_native_transfer(&source, &destination, child);
        assert_staging_empty(&destination);
        let tx_id = result.session.tx_ids[0];
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
        // Buffered and file-backed import share the exact sealed command identity.
        assert_eq!(
            import(&destination, &bytes, "verified-file").unwrap(),
            result
        );
        destination.shutdown().unwrap();

        let reopened = OneNode::open_existing(target.config(format)).unwrap();
        let request = reopened.request_context();
        assert_eq!(
            file_import(&reopened, &path, "verified-file", Default::default()).unwrap(),
            result,
        );
        let identity = record.principal_snapshot_id.as_internal_object_id();
        let principal_receipt = reopened
            .runtime()
            .block_on(crate::read_principal_snapshot_in(
                &reopened.authority,
                request.authority(),
                reopened.repository_id,
                fgit_types::Digest::new(identity.algorithm(), *identity.digest()),
                &|| false,
            ))
            .unwrap();
        assert_eq!(
            principal_receipt.authentication(),
            Some(AdmissionAuthentication::HttpToken)
        );
        let policy = reopened
            .runtime()
            .block_on(crate::read_policy_decision_in(
                &reopened.authority,
                request.authority(),
                reopened.repository_id,
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
        reopened.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

fn write_export(node: &OneNode, path: &Path) -> Vec<u8> {
    let bytes = export(node, &RefVisibility::new()).into_bytes();
    fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn native_file_import_replays_identically_across_buffered_profiles_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (source, base, child, _) = fixture(&root, format);
        accepted(apply(&source, &[create("refs/heads/topic", base)], "topic"));
        let path = root.0.join("native.bundle");
        let bytes = write_export(&source, &path);
        let expected = snapshot(&source);
        let target = Scratch::new();
        let mut destination = empty_node(&target, format);
        let empty = snapshot(&destination);
        let first = committed(file_import(
            &destination,
            &path,
            "file-first",
            Default::default(),
        ));
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs, expected.snapshot().refs);
        assert_eq!(
            after.selected_closure().closure(),
            expected.selected_closure().closure()
        );
        assert_eq!(after.snapshot().head_target, empty.snapshot().head_target);
        assert_eq!(after.snapshot().outbox, empty.snapshot().outbox);
        assert_native_transfer(&source, &destination, child);
        assert_staging_empty(&destination);
        destination.push_quota.limit.max_events = 0;
        assert_eq!(import(&destination, &bytes, "file-first").unwrap(), first);
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap();
        let reopened = OneNode::open_existing(target.config(format)).unwrap();
        assert_eq!(
            file_import(&reopened, &path, "file-first", Default::default()).unwrap(),
            first
        );
        assert_staging_empty(&reopened);
        reopened.shutdown().unwrap();

        let second_root = Scratch::new();
        let mut second = empty_node(&second_root, format);
        let buffered = accepted(import(&second, &bytes, "buffered-first"));
        let basis = snapshot(&second).basis().clone();
        second.push_quota.limit.max_events = 0;
        // The terminal identity belongs to these commands, not a fresh payload
        // or current intake allowance. A header alone can recover that outcome.
        let end = bytes.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let header_path = root.0.join("header-only.bundle");
        fs::write(&header_path, &bytes[..end]).unwrap();
        let mut restricted = StreamBundleImportQuery::default();
        restricted.limits.max_streamed_blob_bytes = 1;
        restricted.limits.pack.max_object_bytes = 1;
        restricted.limits.graph.max_object_bytes = 1;
        assert_eq!(
            file_import(&second, &header_path, "buffered-first", restricted).unwrap(),
            buffered
        );
        assert_eq!(snapshot(&second).basis(), &basis);
        assert_staging_empty(&second);
        second.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn existing_ref_refusal_abandons_private_file_candidates_and_allowed_twin_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (source, base, child, _) = fixture(&root, format);
        accepted(apply(&source, &[create("refs/heads/topic", base)], "topic"));
        let path = root.0.join("candidate.bundle");
        let bytes = write_export(&source, &path);
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let request = destination.request_context();
        accepted(
            destination
                .runtime()
                .block_on(destination.fetch_full_git_bundle_durable_in(
                    &request,
                    &session("seed-base"),
                    &bytes,
                    &[BundleRefMapping {
                        source: reference("refs/heads/topic"),
                        destination: reference("refs/heads/main"),
                        expected_old: None,
                    }],
                    AdmissionLimits::default(),
                )),
        );
        assert_missing(&destination, child);
        let before = snapshot(&destination);
        let result = file_import(&destination, &path, "new-file-key", Default::default()).unwrap();
        assert_eq!(result.commands.len(), 2);
        assert!(result.commands.iter().all(|command| matches!(
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
        assert_missing(&destination, child);
        assert_native_transfer(&source, &destination, base);
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();

        let permitted_root = Scratch::new();
        let permitted = empty_node(&permitted_root, format);
        committed(file_import(
            &permitted,
            &path,
            "new-file-key",
            Default::default(),
        ));
        assert_native_transfer(&source, &permitted, child);
        assert_staging_empty(&permitted);
        permitted.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

fn stored_zlib(body: &[u8]) -> Vec<u8> {
    let mut output = vec![0x78, 0x01];
    let (mut a, mut b) = (1_u32, 0_u32);
    let mut chunks = body.chunks(65_535).peekable();
    if body.is_empty() {
        output.extend_from_slice(&[1, 0, 0, 255, 255]);
    }
    while let Some(chunk) = chunks.next() {
        let length = u16::try_from(chunk.len()).unwrap();
        output.push(u8::from(chunks.peek().is_none()));
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(&(!length).to_le_bytes());
        output.extend_from_slice(chunk);
        for byte in chunk {
            a = (a + u32::from(*byte)) % 65_521;
            b = (b + a) % 65_521;
        }
    }
    output.extend_from_slice(&((b << 16) | a).to_be_bytes());
    output
}

fn record(kind: u8, body: &[u8], base: &[u8]) -> Vec<u8> {
    let mut length = body.len();
    let mut output = vec![kind << 4 | (length as u8 & 15)];
    length >>= 4;
    while length != 0 {
        *output.last_mut().unwrap() |= 128;
        output.push((length & 127) as u8);
        length >>= 7;
    }
    output.extend_from_slice(base);
    output.extend(stored_zlib(body));
    output
}

fn native_bundle(
    format: GitHashAlgorithm,
    name: &str,
    target: GitOid,
    records: &[Vec<u8>],
) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        pack.extend_from_slice(record);
    }
    let checksum = match format {
        GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&pack).to_vec(),
    };
    pack.extend(checksum);
    let signature = match format {
        GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
        GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
    };
    [format!("{signature}{target} {name}\n\n").into_bytes(), pack].concat()
}

fn varint(mut length: usize, output: &mut Vec<u8>) {
    loop {
        let low = (length & 127) as u8;
        length >>= 7;
        output.push(low | if length == 0 { 0 } else { 128 });
        if length == 0 {
            break;
        }
    }
}

#[test]
fn bad_tail_typed_graph_prerequisites_and_external_bases_never_borrow_destination_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (source, base, child, blob_id) = fixture(&root, format);
        let path = root.0.join("intake.bundle");
        let bytes = write_export(&source, &path);
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_import(&destination, &path, "seed", Default::default()));
        let before = snapshot(&destination);
        let base_object = source.read_git_object(base).unwrap();
        let mut candidate = source.read_git_object(child).unwrap().payload().to_vec();
        candidate.extend_from_slice(b"external delta candidate\n");
        let candidate_id = git_object_id(format, GitObjectKind::Commit, &candidate);
        let mut program = Vec::new();
        varint(base_object.payload().len(), &mut program);
        varint(candidate.len(), &mut program);
        for literal in candidate.chunks(127) {
            program.push(literal.len() as u8);
            program.extend_from_slice(literal);
        }
        let thin = native_bundle(
            format,
            "refs/heads/thin",
            candidate_id,
            &[record(7, &program, base.as_bytes())],
        );
        let missing = native_bundle(
            format,
            "refs/heads/incomplete",
            base,
            &[record(1, base_object.payload(), &[])],
        );
        let wrong_kind = native_bundle(
            format,
            "refs/heads/blob",
            blob_id,
            &[record(
                3,
                source.read_git_object(blob_id).unwrap().payload(),
                &[],
            )],
        );
        let request = source.request_context();
        let prerequisite = source
            .runtime()
            .block_on(source.export_incremental_git_bundle_in(
                &request,
                &[reference("refs/heads/main")],
                &[base],
                &RefVisibility::new(),
                None,
            ))
            .unwrap()
            .1
            .into_bytes();
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut trailing = bytes.clone();
        trailing.push(0);
        for (index, invalid) in [corrupt, trailing, missing, wrong_kind, prerequisite, thin]
            .into_iter()
            .enumerate()
        {
            fs::write(&path, invalid).unwrap();
            assert!(
                file_import(
                    &destination,
                    &path,
                    &format!("bad-{index}"),
                    Default::default()
                )
                .is_err()
            );
            assert_eq!(snapshot(&destination).basis(), before.basis());
            assert_missing(&destination, candidate_id);
            assert_staging_empty(&destination);
        }
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

struct LargeFixture {
    node: OneNode,
    tip: GitOid,
    blob: GitOid,
    body: Vec<u8>,
    bundle: PathBuf,
}

fn large_fixture(scratch: &Scratch, format: GitHashAlgorithm) -> LargeFixture {
    let root = scratch.0.join("large-source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let mut state = 0x18a0_3e72_u32;
    let body: Vec<_> = (0..BLOB_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let blob = git_object_id(format, GitObjectKind::Blob, &body);
    let text = blob.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    let raw = [format!("blob {}\0", body.len()).as_bytes(), &body].concat();
    fs::write(directory.join(&text[2..]), stored_zlib(&raw)).unwrap();
    let tree = loose(
        &root,
        format,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 large\0".as_slice(), blob.as_bytes()].concat(),
    );
    let tip = loose(&root, format, GitObjectKind::Commit, "commit",
        format!("tree {tree}\nauthor Native <native@example.test> 1 +0000\ncommitter Native <native@example.test> 1 +0000\n\nlarge file\n").as_bytes());
    fs::write(root.join("refs/heads/main"), format!("{tip}\n")).unwrap();
    let (mut node, _) = OneNode::init(
        scratch
            .config(format)
            .with_max_object_bytes((2 * BLOB_BYTES) as u64),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.import_request_context(None);
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &root,
            principal(),
            b"native-large-source",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let bundle = scratch.0.join("large.bundle");
    let mut file = fs::File::create(&bundle).unwrap();
    let request = node.import_request_context(None);
    let mut query = StreamBundleExportQuery::default();
    query.limits.pack.max_object_bytes = METADATA_BYTES;
    query.limits.max_streamed_blob_bytes = BLOB_BYTES;
    node.runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &RefVisibility::new(),
            query,
            &mut file,
        ))
        .unwrap();
    file.flush().unwrap();
    drop(file);
    LargeFixture {
        node,
        tip,
        blob,
        body,
        bundle,
    }
}

fn blob_query() -> StreamBundleImportQuery {
    let mut query = StreamBundleImportQuery::default();
    query.limits.pack.max_object_bytes = METADATA_BYTES;
    query.limits.graph.max_object_bytes = METADATA_BYTES;
    query.limits.max_streamed_blob_bytes = BLOB_BYTES;
    query
}

fn blob_target(root: &Scratch, format: GitHashAlgorithm, maximum: usize) -> OneNode {
    let (mut node, _) = OneNode::init(
        root.config(format)
            .with_max_object_bytes(METADATA_BYTES as u64)
            .with_bundle_import_blob_limit(maximum),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}

fn assert_streamed_blob(node: &OneNode, identity: GitOid, expected: &[u8]) {
    assert!(
        node.read_git_object(identity).is_err(),
        "the eager metadata cap must remain small"
    );
    let mut stream = node
        .open_git_blob_stream(identity, expected.len() as u64)
        .unwrap();
    let mut chunk = [0_u8; 16 * 1024];
    let mut offset = 0;
    loop {
        let count = stream.read_tentative(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        assert_eq!(&chunk[..count], &expected[offset..offset + count]);
        offset += count;
    }
    assert_eq!(offset, expected.len());
    assert!(stream.is_verified());
}

#[test]
fn blob_policy_metadata_and_aggregate_limits_are_independent_and_allowed_transfer_is_native() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = large_fixture(&root, format);
        let policy_root = Scratch::new();
        let policy = blob_target(&policy_root, format, BLOB_BYTES - 1);
        let before_policy = snapshot(&policy);
        assert!(file_import(&policy, &source.bundle, "policy", blob_query()).is_err());
        assert_eq!(snapshot(&policy).basis(), before_policy.basis());
        assert_missing(&policy, source.blob);
        assert_staging_empty(&policy);
        policy.shutdown().unwrap();

        let target = Scratch::new();
        let destination = blob_target(&target, format, BLOB_BYTES);
        let before = snapshot(&destination);
        let mut metadata = blob_query();
        metadata.limits.pack.max_object_bytes = 32;
        metadata.limits.graph.max_object_bytes = 32;
        let mut blob_limit = blob_query();
        blob_limit.limits.max_streamed_blob_bytes = BLOB_BYTES - 1;
        let mut total = blob_query();
        total.limits.pack.max_total_expanded_bytes = BLOB_BYTES;
        for limited in [metadata, blob_limit, total] {
            assert!(file_import(&destination, &source.bundle, "bounded", limited).is_err());
            assert_eq!(snapshot(&destination).basis(), before.basis());
            assert_missing(&destination, source.blob);
            assert_missing(&destination, source.tip);
            assert_staging_empty(&destination);
        }
        committed(file_import(
            &destination,
            &source.bundle,
            "bounded",
            blob_query(),
        ));
        assert_native_transfer(&source.node, &destination, source.tip);
        assert_streamed_blob(&destination, source.blob, &source.body);
        assert_staging_empty(&destination);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

struct ReplacedHeader {
    input: Cursor<Vec<u8>>,
    replacement: Vec<u8>,
    rewinds: usize,
}

impl Read for ReplacedHeader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let offered = output.len().min(7);
        self.input.read(&mut output[..offered])
    }
}

impl Seek for ReplacedHeader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if position == SeekFrom::Start(0) {
            self.rewinds += 1;
            if self.rewinds == 2 {
                self.input = Cursor::new(self.replacement.clone());
            }
        }
        self.input.seek(position)
    }
}

#[test]
fn source_replacement_after_semantic_header_cannot_change_sealed_commands() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (source, _, tip, _) = fixture(&root, format);
        let path = root.0.join("stable.bundle");
        let bytes = write_export(&source, &path);
        let mut replacement = bytes.clone();
        let name = b"refs/heads/main";
        let at = replacement
            .windows(name.len())
            .position(|window| window == name)
            .unwrap();
        replacement[at..at + name.len()].copy_from_slice(b"refs/heads/swap");
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        let before = snapshot(&destination);
        let request = destination.import_request_context(None);
        let mut reader = ReplacedHeader {
            input: Cursor::new(bytes),
            replacement,
            rewinds: 0,
        };
        let result =
            destination
                .runtime()
                .block_on(destination.import_full_git_bundle_reader_durable_in(
                    &request,
                    &session("header-race"),
                    &mut reader,
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
        assert_missing(&destination, tip);
        assert_staging_empty(&destination);
        committed(file_import(
            &destination,
            &path,
            "header-race",
            Default::default(),
        ));
        assert_native_transfer(&source, &destination, tip);
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn cancellation_during_private_blob_write_settles_custody_and_fresh_same_key_retry_commits() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let source = large_fixture(&root, format);
    let target = Scratch::new();
    let destination = blob_target(&target, format, BLOB_BYTES);
    let before = snapshot(&destination);
    let request = destination.import_request_context(None);
    let saw_partial_stage = Cell::new(false);
    let staging = destination.storage_root().join("staging");
    let mut live = || {
        let partial = fs::read_dir(&staging).unwrap().any(|entry| {
            let entry = entry.unwrap();
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "stage")
                && entry.metadata().unwrap().len() > (BLOB_BYTES / 2) as u64
        });
        if partial {
            saw_partial_stage.set(true);
        }
        !saw_partial_stage.get()
    };
    let mut input = fs::File::open(&source.bundle).unwrap();
    let result =
        destination
            .runtime()
            .block_on(destination.import_full_git_bundle_reader_controlled_in(
                &request,
                &session("cancel-then-retry"),
                &mut input,
                blob_query(),
                Default::default(),
                &mut live,
            ));
    assert!(
        saw_partial_stage.get(),
        "cancellation must reach the real private streamed write"
    );
    assert!(result.is_err());
    assert_eq!(snapshot(&destination).basis(), before.basis());
    assert_missing(&destination, source.blob);
    assert_missing(&destination, source.tip);
    assert_staging_empty(&destination);
    committed(file_import(
        &destination,
        &source.bundle,
        "cancel-then-retry",
        blob_query(),
    ));
    assert_streamed_blob(&destination, source.blob, &source.body);
    assert_native_transfer(&source.node, &destination, source.tip);
    assert_staging_empty(&destination);
    destination.shutdown().unwrap();
    source.node.shutdown().unwrap();
}
