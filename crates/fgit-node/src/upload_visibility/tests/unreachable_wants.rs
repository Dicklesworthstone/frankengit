//! frankengit-aitq: real retained objects remain undisclosable after ref
//! deletion, and HTTP carries the same opaque Git refusal as git:// and SSH.

use super::*;
use fgit_wire::smart_http::rpc::RpcError;
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits, parse_head};
use std::io::{self, Cursor};

fn fetch_body(format: GitHashAlgorithm, version: u8, want: &str) -> Vec<u8> {
    let mut packets = Vec::new();
    if version == 2 {
        packets.extend([
            Packet::Data(b"command=fetch\n".to_vec()),
            Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
            Packet::Delimiter,
        ]);
    }
    packets.push(Packet::Data(format!("want {want}\n").into_bytes()));
    if version != 2 {
        packets.push(Packet::Flush);
    }
    packets.push(Packet::Data(b"done\n".to_vec()));
    if version == 2 {
        packets.push(Packet::Flush);
    }
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn http_head(node: &OneNode, version: u8, body_len: usize, http: &str) -> Vec<u8> {
    format!(
        "POST {}/git-upload-pack {http}\r\nHost: loopback\r\nGit-Protocol: version={version}\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {body_len}\r\n\r\n",
        String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes())
    )
    .into_bytes()
}

fn response_body(response: &[u8], http: &str) -> Vec<u8> {
    let boundary = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let header = std::str::from_utf8(&response[..boundary]).unwrap();
    assert!(header.starts_with(&format!("{http} 200 OK\r\n")));
    assert!(header.contains("application/x-git-upload-pack-result"));
    let body = &response[boundary..];
    if http == "HTTP/1.0" {
        assert!(!header.contains("Transfer-Encoding: chunked"));
        return body.to_vec();
    }
    assert!(header.contains("Transfer-Encoding: chunked"));
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
    let mut output = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let step = decoder.push(&body[offset..]).unwrap();
        assert!(step.consumed > 0);
        offset += step.consumed;
        output.extend_from_slice(step.data);
    }
    decoder.finish().unwrap();
    output
}

fn expected_error(want: GitOid) -> Vec<u8> {
    encode_packets(
        &[Packet::Data(
            format!("ERR upload-pack: not our ref {want}\n").into_bytes(),
        )],
        &WireLimits::default(),
    )
    .unwrap()
}

#[test]
fn http_reports_deleted_commit_blob_and_unknown_wants_without_disclosing_retained_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            config,
            public,
            private,
            private_blob,
            ..
        } = fixture(format);
        delete_private(&node, private);
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let unknown = git_object_id(format, GitObjectKind::Blob, b"never stored in this node");
        assert!(node.read_git_object(private).is_ok());
        assert!(node.read_git_object(private_blob).is_ok());
        assert!(node.read_git_object(unknown).is_err());

        for version in [0, 1, 2] {
            for http in ["HTTP/1.0", "HTTP/1.1"] {
                for streamed in [false, true] {
                    // A visible twin enters the real pack builder, not only
                    // the protocol parser used by the adapter unit tests.
                    let body = fetch_body(format, version, &public.to_string());
                    let head = http_head(&node, version, body.len(), http);
                    let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
                    let mut response = Vec::new();
                    let allowed = if streamed {
                        node.smart_http_upload_stream_in(
                            &request,
                            &mut Cursor::new(&body),
                            WireLimits::default(),
                            HttpLimits::default(),
                            1024 * 1024,
                            &mut || true,
                            &mut response,
                        )
                    } else {
                        node.smart_http_upload_rpc_in(
                            &request,
                            &body,
                            WireLimits::default(),
                            HttpLimits::default(),
                            1024 * 1024,
                            &mut || true,
                            &mut response,
                        )
                    };
                    assert!(allowed.unwrap().pack_requested());
                    assert!(response.windows(4).any(|bytes| bytes == b"PACK"));

                    for want in [private, private_blob, unknown] {
                        let body = fetch_body(format, version, &want.to_string());
                        let head = http_head(&node, version, body.len(), http);
                        let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
                        let mut response = Vec::new();
                        let result = if streamed {
                            node.smart_http_upload_stream_in(
                                &request,
                                &mut Cursor::new(&body),
                                WireLimits::default(),
                                HttpLimits::default(),
                                1024 * 1024,
                                &mut || true,
                                &mut response,
                            )
                        } else {
                            node.smart_http_upload_rpc_in(
                                &request,
                                &body,
                                WireLimits::default(),
                                HttpLimits::default(),
                                1024 * 1024,
                                &mut || true,
                                &mut response,
                            )
                        };
                        assert!(matches!(
                            result,
                            Err(NodeSmartHttpRefusal::Rpc(error))
                                if matches!(*error, RpcError::Wire(
                                    WireError::WantNotAdvertised { oid }
                                        | WireError::WantNotReachable { oid }
                                ) if oid == want)
                        ));
                        assert_eq!(
                            response_body(&response, http),
                            expected_error(want),
                            "{format:?} v{version} {http} streamed={streamed}"
                        );
                        assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
                    }
                }
            }
        }
        let after = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            before.basis(),
            after.basis(),
            "neither fetch nor refusal moves authority"
        );
        node.shutdown().unwrap();
        drop(scratch);
    }
}

#[test]
fn http_want_refusal_keeps_response_bounds_and_unrelated_parser_failures() {
    let Fixture {
        scratch,
        node,
        private,
        ..
    } = fixture(GitHashAlgorithm::Sha1);
    delete_private(&node, private);
    for version in [0, 1, 2] {
        let body = fetch_body(GitHashAlgorithm::Sha1, version, &private.to_string());
        let head = http_head(&node, version, body.len(), "HTTP/1.1");
        let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
        let mut output = Vec::new();
        let refused = node.smart_http_upload_rpc_in(
            &request,
            &body,
            WireLimits::default(),
            HttpLimits::default(),
            u64::try_from(expected_error(private).len() - 1).unwrap(),
            &mut || true,
            &mut output,
        );
        assert!(matches!(refused, Err(NodeSmartHttpRefusal::Http(_))));
        assert!(
            output.is_empty(),
            "the whole error packet is bounded before its HTTP head"
        );

        let malformed = fetch_body(GitHashAlgorithm::Sha1, version, "not-an-object-id");
        let head = http_head(&node, version, malformed.len(), "HTTP/1.1");
        let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
        let refused = node.smart_http_upload_rpc_in(
            &request,
            &malformed,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut || true,
            &mut output,
        );
        assert!(matches!(refused, Err(NodeSmartHttpRefusal::Rpc(_))));
        assert!(
            output.is_empty(),
            "unbounded parser input is not reflected into an ERR"
        );
    }
    node.shutdown().unwrap();
    drop(scratch);
}

struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn http_response_failure_remains_a_typed_io_error() {
    let Fixture {
        scratch,
        node,
        private,
        ..
    } = fixture(GitHashAlgorithm::Sha1);
    delete_private(&node, private);
    let body = fetch_body(GitHashAlgorithm::Sha1, 2, &private.to_string());
    let head = http_head(&node, 2, body.len(), "HTTP/1.1");
    let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
    let refused = node.smart_http_upload_rpc_in(
        &request,
        &body,
        WireLimits::default(),
        HttpLimits::default(),
        1024 * 1024,
        &mut || true,
        &mut BrokenWriter,
    );
    assert!(matches!(
        refused,
        Err(NodeSmartHttpRefusal::Io { operation: "write smart HTTP head", source })
            if source.kind() == io::ErrorKind::BrokenPipe
    ));
    node.shutdown().unwrap();
    drop(scratch);
}
