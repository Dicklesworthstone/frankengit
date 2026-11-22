//! Native protocol-v2 negotiation-only requests share the upload view and
//! transport path, but cannot ask the pack materializer to do any work.

use super::*;

fn request(format: GitHashAlgorithm, arguments: &[Vec<u8>]) -> Vec<u8> {
    let mut packets = vec![
        Packet::Data(b"command=fetch\n".to_vec()),
        Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
        Packet::Delimiter,
    ];
    packets.extend(arguments.iter().cloned().map(Packet::Data));
    packets.push(Packet::Flush);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn negotiation(format: GitHashAlgorithm, haves: &[GitOid]) -> Vec<u8> {
    let mut arguments = vec![b"wait-for-done\n".to_vec()];
    arguments.extend(haves.iter().map(|id| format!("have {id}\n").into_bytes()));
    request(format, &arguments)
}

fn acknowledgments(ids: &[GitOid]) -> Vec<Packet> {
    let mut packets = vec![Packet::Data(b"acknowledgments\n".to_vec())];
    if ids.is_empty() {
        packets.push(Packet::Data(b"NAK\n".to_vec()));
    } else {
        packets.extend(
            ids.iter()
                .map(|id| Packet::Data(format!("ACK {id}\n").into_bytes())),
        );
    }
    packets.push(Packet::Flush);
    packets
}

fn packets(bytes: &[u8]) -> Vec<Packet> {
    let mut decoder = fgit_wire::PktLineDecoder::new(WireLimits::default()).unwrap();
    let result = decoder.push(bytes).unwrap();
    decoder.finish().unwrap();
    result
}

fn after_advertisement(bytes: &[u8]) -> Vec<Packet> {
    let packets = packets(bytes);
    let end = packets
        .iter()
        .position(|packet| matches!(packet, Packet::Flush))
        .unwrap()
        + 1;
    assert!(packets[..end].iter().any(|packet| {
        matches!(packet, Packet::Data(line) if line.windows(b"wait-for-done".len()).any(|part| part == b"wait-for-done"))
    }));
    packets[end..].to_vec()
}

#[test]
fn native_rounds_ack_only_visible_history_and_end_cleanly_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            config,
            public,
            private,
            ancestor,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let before = node.runtime().block_on(node.materialize_admission()).unwrap();
        let missing = git_object_id(format, GitObjectKind::Blob, b"not admitted");
        for reopened in [false, true] {
            if reopened {
                node.shutdown().unwrap();
                node = OneNode::open_existing(config.clone()).unwrap();
                node.bring_into_service(HeadGeneration::FIRST).unwrap();
            }
            let mut input = negotiation(format, &[ancestor, private, missing, public, ancestor]);
            input.extend_from_slice(&negotiation(format, &[private, missing]));
            input.extend_from_slice(&negotiation(format, &[]));
            let (returned, result, response) = raw_fetch(node, &input);
            node = returned;
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::EmptyRepository(_))),
                "{result:?}"
            );
            let mut expected = acknowledgments(&[ancestor, public]);
            expected.extend(acknowledgments(&[]));
            expected.extend(acknowledgments(&[]));
            assert_eq!(after_advertisement(&response), expected);
            assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
            assert!(!response.windows(b"ready\n".len()).any(|bytes| bytes == b"ready\n"));
            assert!(node.read_git_object(private).is_ok(), "retention is not disclosure");
        }
        assert_eq!(
            before.basis(),
            node.runtime().block_on(node.materialize_admission()).unwrap().basis()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn a_waiting_named_ref_round_cannot_contaminate_the_following_full_fetch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            private,
            visible,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let expected = visible
            .iter()
            .map(|id| node.read_git_object(*id).unwrap().payload().to_vec())
            .collect::<BTreeSet<_>>();
        let mut input = request(
            format,
            &[
                b"want-ref refs/heads/public\n".to_vec(),
                b"wait-for-done\n".to_vec(),
                format!("have {public}\n").into_bytes(),
                b"deepen 1\n".to_vec(),
                b"filter blob:none\n".to_vec(),
            ],
        );
        input.extend_from_slice(&request(
            format,
            &[format!("want {public}\n").into_bytes(), b"done\n".to_vec()],
        ));
        let (node, result, response) = raw_fetch(node, &input);
        let receipt = match result {
            Ok(GitDaemonSessionOutcome::Pack(receipt)) => receipt,
            other => panic!("fresh full fetch must produce a pack: {other:?}"),
        };
        assert!(receipt.pack_request().filter.is_none());
        assert!(receipt.pack_request().deepen.is_none());
        assert!(receipt.pack_request().haves.is_empty());
        assert_eq!(receipt.pack_request().wants, vec![public]);
        assert!(!response.windows(b"wanted-refs\n".len()).any(|part| part == b"wanted-refs\n"));
        assert!(!response.windows(b"shallow-info\n".len()).any(|part| part == b"shallow-info\n"));
        let pack = fgit_pack::read_verified_pack(
            &extract_pack(&response, 2),
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
            expected
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn http_have_only_rounds_reselect_current_visibility_without_requesting_a_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            private,
            ..
        } = fixture(format);
        let discovery = format!(
            "GET {}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: loopback\r\nGit-Protocol: version=2\r\n\r\n",
            String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes())
        );
        let head = parse_head(discovery.as_bytes(), HttpLimits::default()).unwrap().unwrap();
        let advertised = node.smart_http_upload_discovery_in(&head, WireLimits::default()).unwrap();
        assert!(advertised.body().windows(b"wait-for-done".len()).any(|part| part == b"wait-for-done"));
        for streamed in [false, true] {
            let (receipt, response) = http_fetch(&node, &negotiation(format, &[private]), streamed);
            assert!(!receipt.unwrap().pack_requested());
            assert_eq!(packets(&http_body(&response)), acknowledgments(&[private]));
        }
        hide_private(&node);
        let missing = git_object_id(format, GitObjectKind::Blob, b"never present");
        for streamed in [false, true] {
            for haves in [vec![private], vec![missing], vec![]] {
                let (receipt, response) = http_fetch(&node, &negotiation(format, &haves), streamed);
                assert!(!receipt.unwrap().pack_requested());
                assert_eq!(packets(&http_body(&response)), acknowledgments(&[]));
            }
            let (receipt, response) =
                http_fetch(&node, &negotiation(format, &[private, public]), streamed);
            assert!(!receipt.unwrap().pack_requested());
            assert_eq!(packets(&http_body(&response)), acknowledgments(&[public]));
        }
        assert!(node.read_git_object(private).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn native_negotiation_checks_the_original_view_deadline_for_every_have_class() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            private,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let context = node.request_context();
        let materialized = node.runtime().block_on(node.materialize_admission_in(&context)).unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let visible = node
            .prepare_visible_upload_pack(&context, &materialized, &WireLimits::default(), &deadline)
            .unwrap();
        let mut repository = visible.repository().clone();
        repository.negotiation_checkpoint().unwrap();
        let mut expired = deadline;
        expired.started -= Duration::from_secs(3600);
        repository.ref_in_want_deadline = Some(expired);
        assert!(repository.negotiation_checkpoint().is_err());
        let caps = Capabilities::parse_v2_advertisement(
            &[
                Packet::Data(b"version 2\n".to_vec()),
                Packet::Data(b"fetch=wait-for-done\n".to_vec()),
                Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
                Packet::Flush,
            ],
            &WireLimits::default(),
        )
        .unwrap();
        for haves in [vec![public], vec![private], vec![]] {
            let mut machine = fgit_wire::V2UploadPack::new(caps.clone(), WireLimits::default()).unwrap();
            assert_eq!(
                machine.push_bytes(&negotiation(format, &haves), &repository),
                Err(WireError::PackSourceRefused)
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn a_completed_round_does_not_hide_an_incomplete_following_command() {
    let Fixture { scratch: _scratch, node, public, .. } = fixture(GitHashAlgorithm::Sha1);
    let mut input = negotiation(GitHashAlgorithm::Sha1, &[public]);
    input.extend_from_slice(&encode_packets(
        &[Packet::Data(b"command=fetch\n".to_vec())],
        &WireLimits::default(),
    ).unwrap());
    let (node, result, response) = raw_fetch(node, &input);
    assert!(result.is_err());
    assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
    node.shutdown().unwrap();
}
