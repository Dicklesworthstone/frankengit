//! Exact current ref resolution through the native authenticated serving view.
//! These tests use persisted authority and real pack construction in both hash
//! domains; the raw Git listener is also the shared SSH command implementation.

use super::*;
use crate::NodeSmartHttpUploadReceipt;
use fgit_wire::smart_http::rpc::RpcError;
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits, parse_head};
use std::io::Cursor;

fn fetch_body(format: GitHashAlgorithm, names: &[&[u8]], controls: &[&[u8]]) -> Vec<u8> {
    let mut packets = vec![
        Packet::Data(b"command=fetch\n".to_vec()),
        Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
        Packet::Delimiter,
    ];
    for name in names {
        let mut line = b"want-ref ".to_vec();
        line.extend_from_slice(name);
        line.push(b'\n');
        packets.push(Packet::Data(line));
    }
    packets.extend(
        controls
            .iter()
            .map(|control| Packet::Data(control.to_vec())),
    );
    packets.extend([Packet::Data(b"done\n".to_vec()), Packet::Flush]);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn expected_refs(rows: &[(GitOid, &[u8])]) -> Vec<u8> {
    let mut packets = vec![Packet::Data(b"wanted-refs\n".to_vec())];
    for (oid, name) in rows {
        let mut line = format!("{oid} ").into_bytes();
        line.extend_from_slice(name);
        line.push(b'\n');
        packets.push(Packet::Data(line));
    }
    packets.extend([Packet::Delimiter, Packet::Data(b"packfile\n".to_vec())]);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn assert_ref_section(response: &[u8], rows: &[(GitOid, &[u8])]) {
    let expected = expected_refs(rows);
    assert!(
        response
            .windows(expected.len())
            .any(|bytes| bytes == expected)
    );
    assert_eq!(
        response
            .windows(b"wanted-refs\n".len())
            .filter(|bytes| *bytes == b"wanted-refs\n")
            .count(),
        1
    );
}

fn unknown_ref(name: &[u8]) -> Vec<u8> {
    let mut line = b"ERR unknown ref ".to_vec();
    line.extend_from_slice(name);
    line.push(b'\n');
    encode_packets(&[Packet::Data(line)], &WireLimits::default()).unwrap()
}

fn raw_fetch(
    node: OneNode,
    body: &[u8],
) -> (
    OneNode,
    Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    Vec<u8>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let greeting = format!(
        "git-upload-pack {}\0host=loopback\0\0version=2\0",
        String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes())
    );
    let mut input = encode_packets(
        &[Packet::Data(greeting.into_bytes())],
        &WireLimits::default(),
    )
    .unwrap();
    input.extend_from_slice(body);
    let worker = std::thread::spawn(move || {
        let result = node.serve_git_daemon_once(&listener);
        (node, result)
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream.write_all(&input).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    let read = stream.read_to_end(&mut response);
    drop(stream);
    let (node, result) = worker.join().unwrap();
    if result.is_ok() {
        read.expect("successful native fetch reaches EOF");
    }
    (node, result, response)
}

fn http_fetch(
    node: &OneNode,
    body: &[u8],
    streamed: bool,
) -> (
    Result<NodeSmartHttpUploadReceipt, NodeSmartHttpRefusal>,
    Vec<u8>,
) {
    let head = format!(
        "POST {}/git-upload-pack HTTP/1.1\r\nHost: loopback\r\nGit-Protocol: version=2\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n",
        String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes()),
        body.len()
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut response = Vec::new();
    let result = if streamed {
        node.smart_http_upload_stream_in(
            &request,
            &mut Cursor::new(body),
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut || true,
            &mut response,
        )
    } else {
        node.smart_http_upload_rpc_in(
            &request,
            body,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut || true,
            &mut response,
        )
    };
    (result, response)
}

fn http_body(response: &[u8]) -> Vec<u8> {
    let offset = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let header = std::str::from_utf8(&response[..offset]).unwrap();
    assert!(header.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(header.contains("application/x-git-upload-pack-result"));
    assert!(header.contains("Transfer-Encoding: chunked"));
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
    let mut cursor = offset;
    let mut body = Vec::new();
    while cursor < response.len() {
        let step = decoder.push(&response[cursor..]).unwrap();
        assert!(step.consumed > 0);
        cursor += step.consumed;
        body.extend_from_slice(step.data);
    }
    decoder.finish().unwrap();
    body
}

fn hide_private(node: &OneNode) {
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
}

#[test]
fn raw_fetch_by_ref_serves_exact_objects_and_refuses_retained_history_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            config,
            public,
            private,
            visible,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let bodies = visible
            .iter()
            .map(|oid| node.read_git_object(*oid).unwrap().payload().to_vec())
            .collect::<BTreeSet<_>>();
        for reopened in [false, true] {
            if reopened {
                node.shutdown().unwrap();
                node = OneNode::open_existing(config.clone()).unwrap();
                node.bring_into_service(HeadGeneration::FIRST).unwrap();
            }
            let body = fetch_body(format, &[b"refs/heads/public"], &[]);
            let (returned, result, response) = raw_fetch(node, &body);
            node = returned;
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "{result:?}"
            );
            assert!(
                response
                    .windows(b"fetch=shallow filter ref-in-want\n".len())
                    .any(|bytes| bytes == b"fetch=shallow filter ref-in-want\n")
            );
            assert_ref_section(&response, &[(public, b"refs/heads/public")]);
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
                bodies
            );
            for name in [
                b"refs/heads/private".as_slice(),
                b"refs/heads/missing",
                b"HEAD",
            ] {
                let (returned, result, response) =
                    raw_fetch(node, &fetch_body(format, &[name], &[]));
                node = returned;
                assert!(result.is_err());
                assert!(response.ends_with(&unknown_ref(name)));
                assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
                assert!(!response.windows(11).any(|bytes| bytes == b"wanted-refs"));
            }
        }
        assert_eq!(
            before.basis(),
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
        );
        assert!(
            node.read_git_object(private).is_ok(),
            "ref lookup cannot infer permission from retained objects"
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn http_ref_fetch_uses_current_visibility_and_combines_shallow_and_filter_sections() {
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
        let request = parse_head(discovery.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let advertised = node
            .smart_http_upload_discovery_in(&request, WireLimits::default())
            .unwrap();
        assert!(
            advertised
                .body()
                .windows(b"ref-in-want".len())
                .any(|bytes| bytes == b"ref-in-want")
        );
        for streamed in [false, true] {
            let (result, response) = http_fetch(
                &node,
                &fetch_body(format, &[b"refs/heads/private"], &[]),
                streamed,
            );
            assert!(result.unwrap().pack_requested());
            assert_ref_section(&http_body(&response), &[(private, b"refs/heads/private")]);
        }
        hide_private(&node);
        let Fixture {
            scratch: _absent_scratch,
            node: absent_node,
            private: absent_private,
            ..
        } = fixture(format);
        delete_private(&absent_node, absent_private);
        hide_private(&absent_node);
        for streamed in [false, true] {
            let controls = [b"deepen 1\n".as_slice(), b"filter blob:none\n"];
            let (result, response) = http_fetch(
                &node,
                &fetch_body(format, &[b"refs/heads/public"], &controls),
                streamed,
            );
            assert!(result.unwrap().pack_requested());
            let response = http_body(&response);
            assert_ref_section(&response, &[(public, b"refs/heads/public")]);
            let shallow = response
                .windows(b"shallow-info\n".len())
                .position(|bytes| bytes == b"shallow-info\n")
                .unwrap();
            let wanted = response
                .windows(b"wanted-refs\n".len())
                .position(|bytes| bytes == b"wanted-refs\n")
                .unwrap();
            assert!(shallow < wanted);
            let pack = fgit_pack::read_verified_pack(
                &extract_pack(&response, 2),
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .unwrap();
            assert!(!pack.entries().is_empty());
            assert!(
                pack.entries()
                    .iter()
                    .all(|entry| entry.header.kind != fgit_pack::EntryKind::Blob)
            );
            let (result, response) = http_fetch(
                &node,
                &fetch_body(format, &[b"refs/heads/private"], &[]),
                streamed,
            );
            assert!(
                matches!(result, Err(NodeSmartHttpRefusal::Rpc(error)) if matches!(*error, RpcError::Wire(WireError::UnknownWantedRef { ref name }) if name == b"refs/heads/private"))
            );
            let hidden_response = http_body(&response);
            assert_eq!(hidden_response, unknown_ref(b"refs/heads/private"));
            // An independent view of a deleted ref with the same
            // hide rule gives the identical answer, without weakening policy.
            let (result, response) = http_fetch(
                &absent_node,
                &fetch_body(format, &[b"refs/heads/private"], &[]),
                streamed,
            );
            assert!(result.is_err());
            assert_eq!(http_body(&response), hidden_response);
        }
        absent_node.shutdown().unwrap();
        node.shutdown().unwrap();
    }
}

#[test]
fn ref_fetch_requires_the_private_live_view_and_cannot_reuse_replaced_closure_scope() {
    let Fixture {
        scratch: _scratch,
        node,
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
    assert!(repository.supports_ref_in_want());
    repository.ref_in_want_checkpoint().unwrap();
    let replaced = repository
        .clone()
        .with_closure_objects(BTreeSet::from([private]));
    assert!(!replaced.supports_ref_in_want());
    assert!(replaced.ref_in_want_checkpoint().is_err());
    let mut expired = deadline;
    expired.started -= Duration::from_secs(3600);
    let mut exhausted = repository.clone();
    exhausted.ref_in_want_deadline = Some(expired);
    assert!(exhausted.ref_in_want_checkpoint().is_err());
    let caps = Capabilities::parse_v2_advertisement(
        &[
            Packet::Data(b"version 2\n".to_vec()),
            Packet::Data(b"fetch=ref-in-want\n".to_vec()),
            Packet::Data(b"object-format=sha256\n".to_vec()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    for name in [b"refs/heads/public".as_slice(), b"refs/heads/missing"] {
        let mut machine =
            fgit_wire::V2UploadPack::new(caps.clone(), WireLimits::default()).unwrap();
        assert!(
            machine
                .push_bytes(
                    &fetch_body(GitHashAlgorithm::Sha256, &[name], &[]),
                    &exhausted
                )
                .is_err()
        );
    }
    node.shutdown().unwrap();
}
