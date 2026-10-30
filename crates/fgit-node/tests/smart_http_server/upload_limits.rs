//! An accepted repository must either clone or explain its resource refusal
//! in the Git response, including to clients that request no progress output.

use super::*;

fn fetch(server: &Server, format: GitHashAlgorithm, commit: GitOid, v2: bool) -> Vec<u8> {
    let packets = if v2 {
        vec![
            Packet::Data(b"command=fetch\n".to_vec()),
            Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
            Packet::Delimiter,
            Packet::Data(format!("want {commit}\n").into_bytes()),
            Packet::Data(b"no-progress\n".to_vec()),
            Packet::Data(b"done\n".to_vec()),
            Packet::Flush,
        ]
    } else {
        vec![
            Packet::Data(
                format!(
                    "want {commit} side-band-64k object-format={}\n",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Flush,
            Packet::Data(b"done\n".to_vec()),
        ]
    };
    let body = encode_packets(&packets, &WireLimits::default()).unwrap();
    let request = request(
        server,
        "POST",
        "/git-upload-pack",
        &post_headers(
            "upload-pack",
            body.len(),
            if v2 {
                "Git-Protocol: version=2\r\n"
            } else {
                ""
            },
        ),
        &body,
    );
    response_body(&exchange(server, &request, 4096))
}

fn decode(bytes: &[u8]) -> Vec<Packet> {
    let mut decoder = PktLineDecoder::new(WireLimits::default()).unwrap();
    let packets = decoder.push(bytes).unwrap();
    decoder.finish().unwrap();
    packets
}

fn reopen(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    node
}

#[test]
fn quiet_uploads_report_the_envelope_and_clone_when_only_that_limit_is_raised() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        // Commit/tree metadata fits, but the selected blob does not fit the
        // aggregate envelope. Receive has its independent normal envelope.
        let small = config(&scratch, format).with_selected_pack_byte_envelope(1024);
        let server = Server::start(initialized(small.clone()), 3, true, 1);
        let (commit, input, expected_bodies) = commit_pack_with_blob(format, vec![b'x'; 4096]);
        let zero = "0".repeat(commit.as_bytes().len() * 2);
        let create = packets(
            format!(
                "{zero} {commit} refs/heads/topic\0report-status object-format={}",
                format.as_str()
            )
            .into_bytes(),
            &input,
        );
        let create_request = request(
            &server,
            "POST",
            "/git-receive-pack",
            &post_headers(
                "receive-pack",
                create.len(),
                "Idempotency-Key: upload-envelope-seed\r\n",
            ),
            &create,
        );
        let created = response_body(&exchange(&server, &create_request, 4096));
        assert!(
            created
                .windows(b"ok refs/heads/topic".len())
                .any(|part| part == b"ok refs/heads/topic")
        );
        let before = branch_generation(&small, b"refs/heads/topic", Some(commit));
        for v2 in [false, true] {
            let refused = decode(&fetch(&server, format, commit, v2));
            let [Packet::Data(message)] = refused.as_slice() else {
                panic!("resource refusal must withhold every pack/negotiation prefix: {refused:?}");
            };
            let message = std::str::from_utf8(message).unwrap();
            assert!(message.starts_with("ERR pack needs "), "{message}");
            assert!(message.contains("--pack-max-expanded-mib"), "{message}");
            assert!(message.ends_with('\n'));
        }
        let receipt = server.finish();
        assert_eq!(receipt.accepted_sessions(), 3);
        assert_eq!(receipt.completed_sessions(), 1);
        assert_eq!(receipt.refused_sessions(), 2);
        assert_eq!(
            branch_generation(&small, b"refs/heads/topic", Some(commit)),
            before
        );

        let large = small.clone().with_selected_pack_byte_envelope(8192);
        let server = Server::start(reopen(large.clone()), 2, false, 1);
        for v2 in [false, true] {
            let response = decode(&fetch(&server, format, commit, v2));
            let mut pack = Vec::new();
            for packet in response {
                if let Packet::Data(bytes) = packet
                    && bytes.first() == Some(&1)
                {
                    pack.extend_from_slice(&bytes[1..]);
                }
            }
            let verified = fgit_pack::read_verified_pack(
                &pack,
                format,
                &fgit_pack::PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .expect("raising the selected-pack envelope permits the same native request");
            let actual_bodies = verified
                .entries()
                .iter()
                .map(|entry| entry.inflated.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(actual_bodies, expected_bodies);
        }
        assert_eq!(server.finish().refused_sessions(), 0);
        assert_eq!(
            branch_generation(&large, b"refs/heads/topic", Some(commit)),
            before
        );
    }
}
