//! Cache reuse must survive the service's per-request node reopening.

use super::*;

fn fetch(server: &Server, format: GitHashAlgorithm, commit: GitOid) -> Vec<u8> {
    let payload = encode_packets(
        &[
            Packet::Data(b"command=fetch\n".to_vec()),
            Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
            Packet::Delimiter,
            Packet::Data(format!("want {commit}\n").into_bytes()),
            Packet::Data(b"done\n".to_vec()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let request = request(
        server,
        "POST",
        "/git-upload-pack",
        &post_headers("upload-pack", payload.len(), "Git-Protocol: version=2\r\n"),
        &payload,
    );
    let body = response_body(&exchange(server, &request, 4096));
    let mut decoder = PktLineDecoder::new(WireLimits::default()).unwrap();
    let packets = decoder.push(&body).unwrap();
    decoder.finish().unwrap();
    let mut pack = Vec::new();
    for packet in packets {
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
    .expect("each cache state serves a native checksum-verified pack");
    assert_eq!(verified.entries().len(), 3);
    pack
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
fn separate_http_children_share_pack_cache_and_disabled_siblings_keep_identical_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        // Exact received-pack reuse deliberately bypasses recompression. This
        // test isolates computation-cache sharing across reopened HTTP children;
        // received-pack reuse has its own native selection/refusal coverage.
        let config = config(&scratch, format)
            .with_pack_cache_bytes(1 << 20)
            .with_received_pack_cache_bytes(0);
        let server = Server::start(initialized(config.clone()), 3, true, 1);
        let observer = OneNode::open_existing(config.clone()).unwrap();
        assert_eq!(observer.pack_cache_stats().entries, 0);

        let (commit, input, _) = commit_pack(format);
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
                "Idempotency-Key: pack-cache-seed\r\n",
            ),
            &create,
        );
        let response = response_body(&exchange(&server, &create_request, 4096));
        assert!(
            response
                .windows(b"ok refs/heads/topic".len())
                .any(|v| v == b"ok refs/heads/topic")
        );

        let cold = fetch(&server, format, commit);
        let after_cold = observer.pack_cache_stats();
        assert!(after_cold.entries > 0);
        assert!(after_cold.resident_bytes <= config.pack_cache_bytes());
        let warm = fetch(&server, format, commit);
        assert_eq!(cold, warm);
        let after_warm = observer.pack_cache_stats();
        assert!(after_warm.compression_hits > after_cold.compression_hits);
        assert_eq!(after_warm.entries, after_cold.entries);
        assert_eq!(after_warm.resident_bytes, after_cold.resident_bytes);
        let receipt = server.finish();
        assert_eq!(receipt.completed_sessions(), 3);
        assert_eq!(receipt.refused_sessions(), 0);

        // Resetting one configuration clone creates a new cache, while the
        // original and previously opened nodes retain their warmed instance.
        let disabled_config = config.clone().with_pack_cache_bytes(0);
        assert_eq!(config.pack_cache_bytes(), 1 << 20);
        assert_eq!(disabled_config.pack_cache_bytes(), 0);
        let disabled_observer = OneNode::open_existing(disabled_config.clone()).unwrap();
        let disabled_server = Server::start(reopen(disabled_config), 2, false, 1);
        for _ in 0..2 {
            assert_eq!(fetch(&disabled_server, format, commit), cold);
        }
        let disabled = disabled_observer.pack_cache_stats();
        assert_eq!(disabled.entries, 0);
        assert_eq!(disabled.resident_bytes, 0);
        assert_eq!(disabled.compression_hits, 0);
        assert_eq!(disabled_server.finish().completed_sessions(), 2);
        assert_eq!(
            observer.pack_cache_stats().compression_hits,
            after_warm.compression_hits
        );
        observer.shutdown().unwrap();
        disabled_observer.shutdown().unwrap();
    }
}
