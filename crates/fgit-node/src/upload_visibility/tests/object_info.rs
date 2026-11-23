//! Native object-info must disclose only the current visible graph, including
//! when physically retained history or an earlier projection knows more.

use super::*;

fn fixture(format: GitHashAlgorithm) -> Fixture {
    fixture_with_public_body(format, b"current public content".to_vec())
}

fn fixture_with_public_body(format: GitHashAlgorithm, body: Vec<u8>) -> Fixture {
    super::fixture_with_configuration(format, body, |config| {
        config.with_upload_pack_object_info(true)
    })
}

fn query_sizes(node: OneNode, objects: &[GitOid]) -> (OneNode, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let greeting = format!(
        "git-upload-pack {}\0host=loopback\0\0version=2\0",
        String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes())
    );
    let mut packets = vec![
        Packet::Data(greeting.into_bytes()),
        Packet::Data(b"command=object-info\n".to_vec()),
        Packet::Data(format!("object-format={}\n", node.object_format.as_str()).into_bytes()),
        Packet::Delimiter,
        Packet::Data(b"size\n".to_vec()),
    ];
    packets.extend(
        objects
            .iter()
            .map(|oid| Packet::Data(format!("oid {oid}\n").into_bytes())),
    );
    packets.push(Packet::Flush);
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
    assert!(result.is_ok(), "native object-info session: {result:?}");
    read.expect("successful metadata session reaches response EOF");
    assert!(
        matches!(result, Ok(GitDaemonSessionOutcome::EmptyRepository(_))),
        "object-info selects no pack: {result:?}"
    );
    let capability = encode_packets(
        &[Packet::Data(b"object-info\n".to_vec())],
        &WireLimits::default(),
    )
    .unwrap();
    assert!(
        response
            .windows(capability.len())
            .any(|bytes| bytes == capability)
    );
    assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
    (node, response)
}

fn assert_rows(response: &[u8], rows: &[(GitOid, Option<usize>)]) {
    // Git 2.54's protocol-caps.c writes these payloads without a terminal LF.
    let mut packets = vec![Packet::Data(b"size".to_vec())];
    packets.extend(rows.iter().map(|(oid, size)| {
        Packet::Data(match size {
            Some(size) => format!("{oid} {size}").into_bytes(),
            None => format!("{oid} ").into_bytes(),
        })
    }));
    packets.push(Packet::Flush);
    let expected = encode_packets(&packets, &WireLimits::default()).unwrap();
    assert!(
        response.ends_with(&expected),
        "exact ordered metadata rows differ: {}",
        String::from_utf8_lossy(response)
    );
}

#[test]
fn object_info_returns_visible_sizes_but_no_retained_or_absent_object_oracle_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            config,
            public,
            private,
            private_blob,
            visible,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let missing = git_object_id(
            format,
            GitObjectKind::Blob,
            b"never placed object-info object",
        );
        assert!(
            node.read_git_object(private_blob).is_ok(),
            "retained secret actually exists"
        );
        assert!(
            node.read_git_object(missing).is_err(),
            "absent twin actually is absent"
        );
        let mut rows = visible
            .iter()
            .map(|oid| {
                (
                    *oid,
                    Some(node.read_git_object(*oid).unwrap().payload().len()),
                )
            })
            .collect::<Vec<_>>();
        let public_size = node.read_git_object(public).unwrap().payload().len();
        rows.extend([
            (private_blob, None),
            (missing, None),
            (private, None),
            (public, Some(public_size)),
            (public, Some(public_size)),
        ]);
        let objects = rows.iter().map(|(oid, _)| *oid).collect::<Vec<_>>();
        let context = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        assert!(
            before
                .selected_closure()
                .closure()
                .objects()
                .contains(&private_blob)
        );
        for reopened in [false, true] {
            if reopened {
                node.shutdown().unwrap();
                node = OneNode::open_existing(config.clone()).unwrap();
                node.bring_into_service(HeadGeneration::FIRST).unwrap();
            }
            let (returned, response) = query_sizes(node, &objects);
            node = returned;
            assert_rows(&response, &rows);
            let context = node.request_context();
            let after = node
                .runtime()
                .block_on(node.materialize_admission_in(&context))
                .unwrap();
            assert_eq!(
                after.basis(),
                before.basis(),
                "metadata reads never publish"
            );
            assert_eq!(
                after.selected_closure().closure(),
                before.selected_closure().closure()
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn object_info_rechecks_current_hidden_policy_after_a_warm_visible_query() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            private,
            private_blob,
            ancestor,
            ..
        } = fixture(format);
        let secret_size = node.read_git_object(private_blob).unwrap().payload().len();
        let common_size = node.read_git_object(ancestor).unwrap().payload().len();
        let (node, response) = query_sizes(node, &[private_blob, ancestor]);
        assert_rows(
            &response,
            &[
                (private_blob, Some(secret_size)),
                (ancestor, Some(common_size)),
            ],
        );

        // Canonical hide policy changes the authenticated basis. The previously
        // warm metadata must not authorize a new session at that new basis.
        let request = node.request_context();
        let policy = fgit_codec::HiddenRefPolicyBody {
            rules: vec![b"refs/heads/private".to_vec()],
        };
        node.runtime()
            .block_on(
                fgit_admission::merge::native::protection::publish_hidden_ref_policy_async(
                    &node.authority,
                    request.authority(),
                    &node.head_key,
                    node.tenant_id,
                    Some(&policy),
                    fgit_codec::harness::tx_id(),
                ),
            )
            .unwrap();
        let missing = git_object_id(format, GitObjectKind::Blob, b"hidden policy absent twin");
        let (node, response) = query_sizes(node, &[private_blob, missing, private, ancestor]);
        assert_rows(
            &response,
            &[
                (private_blob, None),
                (missing, None),
                (private, None),
                (ancestor, Some(common_size)),
            ],
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn object_info_can_size_a_visible_blob_above_the_selected_payload_limit() {
    const SIZE: usize = 4096;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = vec![0x79; SIZE];
        let blob = git_object_id(format, GitObjectKind::Blob, &body);
        let Fixture {
            scratch: _scratch,
            node,
            mut config,
            ..
        } = fixture_with_public_body(format, body);
        node.shutdown().unwrap();
        config.selected_pack_limits.max_object_bytes = SIZE - 1;
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (node, response) = query_sizes(node, &[blob]);
        assert_rows(&response, &[(blob, Some(SIZE))]);
        node.shutdown().unwrap();
    }
}

#[test]
fn replacing_caller_closure_cannot_reuse_a_previous_metadata_proof() {
    let Fixture {
        scratch: _scratch,
        node,
        public,
        private,
        ..
    } = fixture(GitHashAlgorithm::Sha256);
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let visible = node
        .prepare_visible_upload_pack(&request, &materialized, &WireLimits::default(), &deadline)
        .unwrap();
    let repository = visible.repository();
    assert!(repository.supports_object_info());
    assert_eq!(
        repository.object_info_size(public).unwrap(),
        Some(node.read_git_object(public).unwrap().payload().len() as u64)
    );
    let replaced = repository
        .clone()
        .with_closure_objects(BTreeSet::from([private]));
    assert!(
        !replaced.supports_object_info(),
        "an asserted closure supplies no verified size facts"
    );
    assert!(replaced.object_info_size(public).is_err());
    assert!(replaced.object_info_size(private).is_err());

    // Use the same authenticated metadata with an already exhausted session,
    // without sleeping or racing a timer. Even a missing-object request must
    // observe cancellation before the provider can answer it.
    let mut expired = deadline;
    expired.started -= Duration::from_secs(3600);
    let mut exhausted = repository.clone();
    exhausted.object_info_proof = Some(super::super::object_info::ObjectInfoProof::new(
        Arc::clone(&visible.objects),
        expired,
    ));
    assert!(exhausted.object_info_checkpoint().is_err());
    assert!(exhausted.object_info_size(public).is_err());
    let absent = git_object_id(
        GitHashAlgorithm::Sha256,
        GitObjectKind::Blob,
        b"absent deadline twin",
    );
    assert!(exhausted.object_info_size(absent).is_err());
    node.shutdown().unwrap();
}
