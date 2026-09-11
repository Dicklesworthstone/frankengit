use super::*;
use std::cell::RefCell;
use std::io::{Read, Write};

struct MemorySource {
    format: GitHashAlgorithm,
    objects: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
    polls: Cell<usize>,
    stop_at: Cell<usize>,
}
impl MemorySource {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            objects: BTreeMap::new(),
            reads: RefCell::new(Vec::new()),
            polls: Cell::new(0),
            stop_at: Cell::new(usize::MAX),
        }
    }
    fn put(&mut self, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let id = git_object_id(self.format, crypto_object_kind(kind), &body);
        self.objects.insert(id, (kind, body));
        id
    }
    fn tree(&mut self, entries: &[(&[u8], &[u8], GitOid)]) -> GitOid {
        self.put(ObjectType::Tree, tree_bytes(entries))
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid]) -> GitOid {
        self.put(ObjectType::Commit, commit_bytes(tree, parents))
    }
    fn admitted(&self) -> PermittedObjectClosure {
        PermittedObjectClosure::new(self.objects.keys().copied().collect())
    }
}
impl VisibilitySource for MemorySource {
    fn format(&self) -> GitHashAlgorithm {
        self.format
    }
    fn parse_limits(&self) -> ParseLimits {
        ParseLimits {
            tree_reference_bytes: self.format.digest_len(),
            ..ParseLimits::default()
        }
    }
    fn checkpoint(&self) -> Result<(), NodePackMaterializationRefusal> {
        let poll = self.polls.get().saturating_add(1);
        self.polls.set(poll);
        if poll >= self.stop_at.get() {
            Err(PackWriteError::from(PackError::DeadlineExceeded).into())
        } else {
            Ok(())
        }
    }
    fn load(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), NodePackMaterializationRefusal> {
        self.reads.borrow_mut().push(id);
        self.objects
            .get(&id)
            .cloned()
            .ok_or_else(|| PackWriteError::MissingCanonicalObject(id).into())
    }
}
fn tree_bytes(entries: &[(&[u8], &[u8], GitOid)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (mode, name, id) in entries {
        body.extend_from_slice(mode);
        body.push(b' ');
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(id.as_bytes());
    }
    body
}
fn commit_bytes(tree: GitOid, parents: &[GitOid]) -> Vec<u8> {
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in parents {
        body.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    body.extend_from_slice(b"author A <a@example.test> 1 +0000\ncommitter C <c@example.test> 1 +0000\n\nvisible graph fixture\n");
    body
}
fn tag_bytes(target: GitOid, kind: &str) -> Vec<u8> {
    format!(
        "object {target}\ntype {kind}\ntag release\ntagger A <a@example.test> 1 +0000\n\nrelease\n"
    )
    .into_bytes()
}
fn expect_code<T>(result: Result<T, NodePackMaterializationRefusal>, code: RefusalCode) {
    assert!(
        matches!(result, Err(NodePackMaterializationRefusal::DisclosureGraph(observed)) if observed == code)
    );
}

#[test]
fn disclosure_walk_keeps_shared_history_and_tags_without_reading_hidden_or_gitlink_bodies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let common = source.put(ObjectType::Blob, b"common".to_vec());
        let base_tree = source.tree(&[(b"100644", b"common", common)]);
        let base = source.commit(base_tree, &[]);
        let secret = source.put(ObjectType::Blob, b"never disclose this".to_vec());
        let private_tree = source.tree(&[(b"100644", b"private", secret)]);
        let private = source.commit(private_tree, &[base]);
        let public = source.put(ObjectType::Blob, b"public".to_vec());
        let tree = source.tree(&[
            (b"100644", b"public", public),
            (b"0160000", b"submodule", private),
        ]);
        let tip = source.commit(tree, &[base, base]);
        let tag = source.put(ObjectType::Tag, tag_bytes(tip, "commit"));
        let outer_tag = source.put(ObjectType::Tag, tag_bytes(tag, "tag"));
        source.put(ObjectType::Blob, b"admitted but unrelated".to_vec());
        let result = project_visible_closure(
            &source,
            &source.admitted(),
            [outer_tag, tip, outer_tag],
            &PackLimits::default(),
        )
        .unwrap();
        let expected = BTreeSet::from([common, base_tree, base, public, tree, tip, tag, outer_tag]);
        assert_eq!(result.objects(), &expected);
        assert_eq!(
            source
                .reads
                .borrow()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(source.reads.borrow().len(), expected.len());
        assert!(!result.objects().contains(&secret));
        assert!(!result.objects().contains(&private));
    }
}

#[test]
fn disclosure_walk_refuses_incomplete_authority_graph_before_reading_an_unadmitted_object() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let blob = source.put(ObjectType::Blob, b"not admitted".to_vec());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let admitted = PermittedObjectClosure::new(BTreeSet::from([tree]));
    expect_code(
        project_visible_closure(&source, &admitted, [tree], &PackLimits::default()),
        RefusalCode::ObjectClosureIncomplete,
    );
    assert_eq!(*source.reads.borrow(), vec![tree]);
    source.reads.borrow_mut().clear();
    expect_code(
        project_visible_closure(&source, &admitted, [tree, blob], &PackLimits::default()),
        RefusalCode::ObjectClosureIncomplete,
    );
    assert!(
        source.reads.borrow().is_empty(),
        "all roots are checked before any body read"
    );
    let empty = project_visible_closure(&source, &admitted, [], &PackLimits::default()).unwrap();
    assert!(
        empty.objects().is_empty(),
        "an empty visible ref set does not fall back to admitted history"
    );
    assert!(source.reads.borrow().is_empty());
}

#[test]
fn disclosure_walk_checks_required_kinds_even_for_unconstrained_or_already_visited_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let blob = source.put(ObjectType::Blob, b"not a tree or commit".to_vec());
        let bad_commit = source.commit(blob, &[]);
        expect_code(
            project_visible_closure(
                &source,
                &source.admitted(),
                [blob, bad_commit],
                &PackLimits::default(),
            ),
            RefusalCode::EvidenceInvalid,
        );
        let bad_tag = source.put(ObjectType::Tag, tag_bytes(blob, "commit"));
        expect_code(
            project_visible_closure(
                &source,
                &source.admitted(),
                [blob, bad_tag],
                &PackLimits::default(),
            ),
            RefusalCode::EvidenceInvalid,
        );
        let bad_tree = source.tree(&[(b"040000", b"directory", blob)]);
        expect_code(
            project_visible_closure(
                &source,
                &source.admitted(),
                [blob, bad_tree],
                &PackLimits::default(),
            ),
            RefusalCode::EvidenceInvalid,
        );
    }
}

#[test]
fn disclosure_walk_bounds_unique_nodes_frontier_and_aggregate_bytes_inclusively() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha256);
    let a = source.put(ObjectType::Blob, b"a".to_vec());
    let b = source.put(ObjectType::Blob, b"bb".to_vec());
    let tree = source.tree(&[(b"100644", b"a", a), (b"100644", b"b", b)]);
    let bytes = source
        .objects
        .values()
        .map(|(_, body)| body.len())
        .sum::<usize>();
    let exact = PackLimits {
        max_entries: 3,
        max_total_expanded_bytes: bytes,
        ..PackLimits::default()
    };
    assert_eq!(
        project_visible_closure(&source, &source.admitted(), [tree, tree], &exact)
            .unwrap()
            .objects()
            .len(),
        3
    );
    expect_code(
        project_visible_closure(
            &source,
            &source.admitted(),
            [tree],
            &PackLimits {
                max_entries: 2,
                ..exact.clone()
            },
        ),
        RefusalCode::ResourceBudgetExceeded,
    );
    expect_code(
        project_visible_closure(
            &source,
            &source.admitted(),
            [tree],
            &PackLimits {
                max_total_expanded_bytes: bytes - 1,
                ..exact
            },
        ),
        RefusalCode::ResourceBudgetExceeded,
    );
    source.reads.borrow_mut().clear();
    expect_code(
        project_visible_closure(
            &source,
            &source.admitted(),
            [a, b],
            &PackLimits {
                max_entries: 1,
                ..PackLimits::default()
            },
        ),
        RefusalCode::ResourceBudgetExceeded,
    );
    assert!(
        source.reads.borrow().is_empty(),
        "root frontier cannot grow beyond the ceiling before reads"
    );
}

#[test]
fn disclosure_walk_preserves_cancellation_without_returning_partial_permission() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let blob = source.put(ObjectType::Blob, b"body".to_vec());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let admitted = source.admitted();
    project_visible_closure(&source, &admitted, [tree], &PackLimits::default()).unwrap();
    let polls = source.polls.get();
    for stop in 1..=polls {
        source.polls.set(0);
        source.stop_at.set(stop);
        assert!(
            matches!(project_visible_closure(&source, &admitted, [tree], &PackLimits::default()),
            Err(NodePackMaterializationRefusal::Pack(error)) if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded)))
        );
    }
}

#[test]
fn hidden_head_is_not_reintroduced_as_an_unborn_protocol_v2_symref() {
    let limits = WireLimits::default();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let target = RefName::try_new(b"refs/heads/private-default").unwrap();
        let id = git_object_id(format, GitObjectKind::Blob, b"hidden");
        let mut hidden_refs = RefVisibility::new();
        hidden_refs.push_rule(target.as_bytes(), &limits).unwrap();
        for refs in [BTreeMap::new(), BTreeMap::from([(target.clone(), id)])] {
            let snapshot = AdmissionSnapshot {
                refs,
                head_target: Some(target.clone()),
                hidden_refs: hidden_refs.clone(),
                ..AdmissionSnapshot::default()
            };
            let repository =
                AdmissionUploadPackRepository::from_snapshot(&snapshot, format, &limits).unwrap();
            assert!(repository.advertised_refs().is_empty());
            assert_eq!(repository.symref_target(b"HEAD"), None);
            assert_eq!(repository.unborn_symref_target(), None);
            let capabilities = Capabilities::parse_v1(b"ls-refs", &limits).unwrap();
            let mut wire = V2UploadPack::new(capabilities, limits.clone()).unwrap();
            wire.push_packet(&Packet::Data(b"command=ls-refs\n".to_vec()), &repository)
                .unwrap();
            wire.push_packet(&Packet::Delimiter, &repository).unwrap();
            wire.push_packet(&Packet::Data(b"unborn\n".to_vec()), &repository)
                .unwrap();
            let result = wire.push_packet(&Packet::Flush, &repository).unwrap();
            assert_eq!(result.output, vec![Packet::Flush]);
        }
        let genuinely_unborn = AdmissionSnapshot {
            head_target: Some(target.clone()),
            ..AdmissionSnapshot::default()
        };
        let repository =
            AdmissionUploadPackRepository::from_snapshot(&genuinely_unborn, format, &limits)
                .unwrap();
        assert_eq!(repository.unborn_symref_target(), Some(target.as_bytes()));
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fgit-upload-disclosure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    scratch: Scratch,
    node: OneNode,
    config: NodeConfig,
    public: GitOid,
    private: GitOid,
    private_blob: GitOid,
    ancestor: GitOid,
    visible: BTreeSet<GitOid>,
}
fn fixture(format: GitHashAlgorithm) -> Fixture {
    let scratch = Scratch::new();
    let config = NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0x62; 16]),
        RepositoryId::from_bytes([0x63; 16]),
    )
    .with_object_format(format);
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let put = |kind, body| node.put_git_object(kind, body).unwrap().identity();
    let common = put(ObjectType::Blob, b"common ancestor body".to_vec());
    let tree0 = put(
        ObjectType::Tree,
        tree_bytes(&[(b"100644", b"common", common)]),
    );
    let ancestor = put(ObjectType::Commit, commit_bytes(tree0, &[]));
    let private_blob = put(ObjectType::Blob, b"deleted-only secret content".to_vec());
    let private_tree = put(
        ObjectType::Tree,
        tree_bytes(&[(b"100644", b"private", private_blob)]),
    );
    let private = put(ObjectType::Commit, commit_bytes(private_tree, &[ancestor]));
    let public_blob = put(ObjectType::Blob, b"current public content".to_vec());
    let public_tree = put(
        ObjectType::Tree,
        tree_bytes(&[
            (b"100644", b"public", public_blob),
            (b"160000", b"submodule", private),
        ]),
    );
    let public = put(ObjectType::Commit, commit_bytes(public_tree, &[ancestor]));
    let visible = BTreeSet::from([common, tree0, ancestor, public_blob, public_tree, public]);
    let mut objects = visible.clone();
    objects.extend([private_blob, private_tree, private]);
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let updates = [
        SourceRefUpdate {
            old: zero,
            new: public,
            ref_name: b"refs/heads/public".to_vec(),
        },
        SourceRefUpdate {
            old: zero,
            new: private,
            ref_name: b"refs/heads/private".to_vec(),
        },
    ];
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: u32::try_from(closure.objects.len()).unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(&updates, &receipt, closure).unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x64; 16]),
        idempotency_key: IdempotencyKey::new(b"disclosure-fixture-import".to_vec()).unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(imported.commands.iter().all(|command| matches!(
        command.terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    )));
    Fixture {
        scratch,
        node,
        config,
        public,
        private,
        private_blob,
        ancestor,
        visible,
    }
}

fn delete_private(node: &OneNode, private: GitOid) {
    let format = node.object_format;
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let caps = format!(
        "report-status delete-refs object-format={}",
        format.as_str()
    );
    let receive_limits = ReceiveLimits::default();
    let context = ReceiveContext::new(
        format,
        Capabilities::parse_v1(caps.as_bytes(), &receive_limits.wire).unwrap(),
        receive_limits.clone(),
        SignedPushProfile::Refuse,
    )
    .unwrap();
    let zero = "0".repeat(format.digest_len() * 2);
    let input = encode_packets(
        &[
            Packet::Data(format!("{private} {zero} refs/heads/private\0{caps}\n").into_bytes()),
            Packet::Flush,
        ],
        &receive_limits.wire,
    )
    .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x64; 16]),
        IdempotencyKey::new(b"delete-private-disclosure-fixture".to_vec()).unwrap(),
    );
    let outcome = node
        .runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &session,
            &materialized,
            context,
            &input,
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut || true,
        ))
        .unwrap();
    assert!(matches!(
        outcome.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
}

#[test]
fn real_import_delete_reopen_scopes_permission_and_refuses_a_mixed_head_proof() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            config,
            public,
            private,
            private_blob,
            visible,
            ..
        } = fixture(format);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let prior = node
            .prepare_visible_upload_pack(&request, &before, &WireLimits::default(), &deadline)
            .unwrap();
        assert!(prior.repository().contains_want(private));
        delete_private(&node, private);
        let after_request = node.request_context();
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&after_request))
            .unwrap();
        expect_code(
            prior.closure_for(&after),
            RefusalCode::AuthorityReceiptStale,
        );
        assert!(
            after
                .selected_closure()
                .closure()
                .objects()
                .contains(&private_blob),
            "the canonical admission history is deliberately unchanged"
        );
        node.shutdown().unwrap();
        let node = OneNode::open_existing(config).unwrap();
        let request = node.request_context();
        let reopened = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let scope = node
            .prepare_visible_upload_pack(&request, &reopened, &WireLimits::default(), &deadline)
            .unwrap();
        assert_eq!(scope.closure_for(&reopened).unwrap().objects(), &visible);
        assert!(scope.repository().contains_want(public));
        assert!(!scope.repository().contains_want(private));
        assert!(!scope.repository().is_common(private_blob));
        assert!(
            node.read_git_object(private_blob).is_ok(),
            "physical existence does not grant disclosure"
        );
        let export = node
            .runtime()
            .block_on(node.authority_selected_pack_payload())
            .unwrap();
        assert!(
            export.closure().closure().objects().contains(&private_blob),
            "trusted local historical export remains distinct from network disclosure"
        );
        node.shutdown().unwrap();
        drop(scratch);
    }
}

fn exchange(
    node: OneNode,
    version: u8,
    want: GitOid,
    have: Option<GitOid>,
) -> (
    OneNode,
    Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    Vec<u8>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let suffix = if version == 0 {
        String::new()
    } else {
        format!("\0version={version}\0")
    };
    let greeting = format!(
        "git-upload-pack {}\0host=loopback\0{suffix}",
        String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes())
    );
    let mut packets = vec![Packet::Data(greeting.into_bytes())];
    if version == 2 {
        packets.push(Packet::Data(b"command=fetch\n".to_vec()));
        packets.push(Packet::Data(
            format!("object-format={}\n", node.object_format.as_str()).into_bytes(),
        ));
        packets.push(Packet::Delimiter);
    }
    packets.push(Packet::Data(format!("want {want}\n").into_bytes()));
    if version != 2 {
        packets.push(Packet::Flush);
    }
    if let Some(have) = have {
        packets.push(Packet::Data(format!("have {have}\n").into_bytes()));
    }
    // Exercise v2's real acknowledgment branch for haves rather than letting
    // `done` suppress all ACKs and make the non-disclosure assertion vacuous.
    if version != 2 || have.is_none() {
        packets.push(Packet::Data(b"done\n".to_vec()));
    }
    if version == 2 {
        packets.push(Packet::Flush);
    }
    let input = encode_packets(&packets, &WireLimits::default()).unwrap();
    let worker = std::thread::spawn(move || {
        let result = node.serve_git_daemon_once(&listener);
        (node, result)
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    client.write_all(&input).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    let read = client.read_to_end(&mut response);
    drop(client);
    let (node, result) = worker.join().unwrap();
    if result.is_ok() {
        read.expect("successful session reaches response EOF");
    }
    (node, result, response)
}
fn extract_pack(response: &[u8], version: u8) -> Vec<u8> {
    if version != 2 {
        let start = response
            .windows(4)
            .position(|word| word == b"PACK")
            .expect("raw pack present");
        return response[start..].to_vec();
    }
    let mut offset = 0;
    let mut pack = Vec::new();
    while offset < response.len() {
        let length = usize::from_str_radix(
            std::str::from_utf8(&response[offset..offset + 4]).unwrap(),
            16,
        )
        .unwrap();
        if length < 4 {
            offset += 4;
            continue;
        }
        let data = &response[offset + 4..offset + length];
        if data.first() == Some(&1) {
            pack.extend_from_slice(&data[1..]);
        }
        assert_ne!(
            data.first(),
            Some(&3),
            "successful fetch carries no Fatal sideband"
        );
        offset += length;
    }
    assert!(pack.starts_with(b"PACK"));
    pack
}

#[test]
fn real_daemon_v0_v1_v2_refuses_deleted_wants_and_never_acks_or_subtracts_deleted_haves() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            mut node,
            config,
            public,
            private,
            private_blob,
            ancestor,
            visible,
        } = fixture(format);
        delete_private(&node, private);
        node.shutdown().unwrap();
        node = OneNode::open_existing(config).unwrap();
        let expected_bodies = visible
            .iter()
            .map(|id| node.read_git_object(*id).unwrap().payload().to_vec())
            .collect::<BTreeSet<_>>();
        for version in [0, 1, 2] {
            for disallowed in [private, private_blob] {
                let (returned, result, response) = exchange(node, version, disallowed, None);
                node = returned;
                assert!(
                    result.is_err(),
                    "deleted-only want must fail for {format:?} v{version}"
                );
                assert!(!response.windows(4).any(|word| word == b"PACK"));
            }
            let (returned, result, response) = exchange(node, version, public, Some(private));
            node = returned;
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "visible fetch: {result:?}"
            );
            let private_ack = format!("ACK {private}");
            assert!(
                !response
                    .windows(private_ack.len())
                    .any(|word| word == private_ack.as_bytes())
            );
            let pack_bytes = extract_pack(&response, version);
            let pack = fgit_pack::read_verified_pack(
                &pack_bytes,
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .unwrap();
            assert_eq!(
                pack.entries()
                    .iter()
                    .map(|entry| entry.inflated.clone())
                    .collect::<BTreeSet<_>>(),
                expected_bodies,
                "a deleted have cannot subtract the still-visible shared ancestor or leak its private tree"
            );
            // Permitted twin: the visible shared ancestor really IS common.
            // Require its ACK and removal from the emitted pack, so ignoring
            // every have cannot masquerade as a working disclosure boundary.
            let (returned, result, response) = exchange(node, version, public, Some(ancestor));
            node = returned;
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "visible have: {result:?}"
            );
            let public_ack = format!("ACK {ancestor}");
            assert!(
                response
                    .windows(public_ack.len())
                    .any(|word| word == public_ack.as_bytes())
            );
            let pack_bytes = extract_pack(&response, version);
            let pack = fgit_pack::read_verified_pack(
                &pack_bytes,
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .unwrap();
            assert_eq!(
                pack.entries().len(),
                3,
                "the visible have removes its commit, tree, and blob"
            );

            let (returned, result, response) = exchange(node, version, ancestor, None);
            node = returned;
            if version != 2 {
                // Legacy wants remain advertisement-bound: this node does not
                // advertise allow-reachable-sha1-in-want. Visibility supplies
                // common haves, not a new negotiated legacy want capability.
                assert!(
                    matches!(result,
                    Err(NodeGitDaemonServeRefusal::Transport(ref error))
                    if matches!(error.as_ref(), GitDaemonTransportRefusal::Wire(
                        WireError::WantNotAdvertised { oid }) if *oid == ancestor)),
                    "legacy unadvertised ancestor must retain its typed refusal: {result:?}"
                );
                assert!(!response.windows(4).any(|word| word == b"PACK"));
                continue;
            }
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "v2 visible historical commit remains fetchable: {result:?}"
            );
            let pack_bytes = extract_pack(&response, version);
            let pack = fgit_pack::read_verified_pack(
                &pack_bytes,
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .unwrap();
            assert_eq!(pack.entries().len(), 3);
        }
        node.shutdown().unwrap();
        drop(scratch);
    }
}

#[test]
fn hidden_ref_rules_select_the_negotiation_scope_before_any_hidden_body_read() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let blob = source.put(ObjectType::Blob, b"shared".to_vec());
        let tree = source.tree(&[(b"100644", b"shared", blob)]);
        let ancestor = source.commit(tree, &[]);
        let public = source.commit(tree, &[ancestor]);
        let private_blob = source.put(ObjectType::Blob, b"hidden only".to_vec());
        let private_tree = source.tree(&[(b"100644", b"private", private_blob)]);
        let private = source.commit(private_tree, &[ancestor]);
        let mut hidden_refs = RefVisibility::new();
        let limits = WireLimits {
            max_advertised_refs: 1,
            ..WireLimits::default()
        };
        hidden_refs
            .push_rule(b"refs/heads/private", &limits)
            .unwrap();
        let snapshot = AdmissionSnapshot {
            refs: BTreeMap::from([
                (RefName::try_new(b"refs/heads/public").unwrap(), public),
                (RefName::try_new(b"refs/heads/private").unwrap(), private),
            ]),
            hidden_refs,
            ..AdmissionSnapshot::default()
        };
        let repository =
            AdmissionUploadPackRepository::from_snapshot(&snapshot, format, &limits).unwrap();
        assert_eq!(
            repository.advertised_refs().len(),
            1,
            "hidden ref cannot consume the visible advertisement limit"
        );
        let closure = project_visible_closure(
            &source,
            &source.admitted(),
            repository
                .advertised_refs()
                .iter()
                .map(|reference| reference.oid),
            &PackLimits::default(),
        )
        .unwrap();
        let repository = repository.with_closure_objects(closure.objects().clone());
        for id in [public, ancestor, tree, blob] {
            assert!(repository.contains_want(id));
            assert!(repository.is_common(id));
        }
        for id in [private, private_tree, private_blob] {
            assert!(!repository.contains_want(id));
            assert!(!repository.is_common(id));
            assert!(!source.reads.borrow().contains(&id));
        }
    }
}
