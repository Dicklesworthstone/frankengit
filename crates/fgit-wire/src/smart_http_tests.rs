use super::*;

fn discovery(extra: &str) -> Vec<u8> {
    format!("GET /team/project.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: example.test\r\n{extra}\r\n").into_bytes()
}
fn rpc(extra: &str) -> Vec<u8> {
    format!("POST /team/project.git/git-receive-pack HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-git-receive-pack-request\r\n{extra}\r\n").into_bytes()
}
fn decode_chunks(
    input: &[u8],
    framing: BodyFraming,
    width: usize,
    limits: HttpLimits,
) -> Result<(Vec<u8>, usize), HttpError> {
    let mut decoder = BodyDecoder::new(framing, limits)?;
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() && !decoder.is_complete() {
        let end = (cursor + width).min(input.len());
        let step = decoder.push(&input[cursor..end])?;
        assert!(
            step.consumed > 0 || step.complete,
            "decoder made no progress"
        );
        output.extend_from_slice(step.data);
        cursor += step.consumed;
    }
    decoder.finish()?;
    assert_eq!(decoder.decoded_bytes(), output.len() as u64);
    assert_eq!(decoder.wire_bytes(), cursor as u64);
    Ok((output, cursor))
}

#[test]
fn header_split_at_every_byte_preserves_body_boundary() {
    let request = discovery("Git-Protocol: version=2\r\n");
    for cut in 0..request.len() {
        assert!(
            parse_head(&request[..cut], HttpLimits::default())
                .unwrap()
                .is_none()
        );
    }
    let mut combined = request.clone();
    combined.extend(std::iter::repeat_n(255, 100_000));
    let head = parse_head(&combined, HttpLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(head.consumed, request.len());
    assert_eq!(head.repository_route, "/team/project.git");
    assert_eq!(head.requested_version, ProtocolVersion::V2);
    assert_eq!(head.operation, Operation::Discover(Service::UploadPack));
}

#[test]
fn head_exact_ceiling_succeeds_but_incomplete_ceiling_refuses() {
    let bytes = discovery("");
    let limits = HttpLimits {
        max_head_bytes: bytes.len(),
        max_target_bytes: 64,
        ..HttpLimits::default()
    };
    assert!(parse_head(&bytes, limits).unwrap().is_some());
    assert_eq!(
        parse_head(&vec![b'x'; limits.max_head_bytes], limits).unwrap_err(),
        HttpError::HeadTooLarge
    );
}

#[test]
fn contradictory_duplicate_and_list_lengths_are_rejected() {
    for header in [
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Content-Length: 1\r\ncontent-length: 2\r\n",
        "Content-Length: 1, 1\r\n",
        "Content-Length: +1\r\n",
        "Content-Length: -1\r\n",
        "Content-Length: 18446744073709551616\r\n",
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    ] {
        assert!(
            parse_head(&rpc(header), HttpLimits::default()).is_err(),
            "{header:?}"
        );
    }
}

#[test]
fn header_syntax_cannot_smuggle_request_or_authentication() {
    for header in [
        "Content-Length : 0\r\n",
        " Content-Length: 0\r\n",
        "X: a\nb\r\n",
        "X: a\rb\r\n",
        "X: a\0b\r\n",
        "X: value\r\n folded: value\r\n",
        "Host: second.test\r\n",
        "Authorization: a\r\nAuthorization: b\r\n",
        "Connection: authorization\r\n",
        "Git-Protocol: version=2\r\nGit-Protocol: version=1\r\n",
    ] {
        assert!(
            parse_head(&discovery(header), HttpLimits::default()).is_err(),
            "{header:?}"
        );
    }
}

#[test]
fn routes_are_exact_unambiguous_and_never_filesystem_paths() {
    for target in [
        "/../repo/info/refs?service=git-upload-pack",
        "/team//repo/info/refs?service=git-upload-pack",
        "/team/./repo/info/refs?service=git-upload-pack",
        "/team/%2e%2e/repo/info/refs?service=git-upload-pack",
        "/team%2frepo/info/refs?service=git-upload-pack",
        "/team\\repo/info/refs?service=git-upload-pack",
        "/r/info/refs?service=git-upload-pack&service=git-receive-pack",
        "/r/info/refs?service=git-upload-pack#fragment",
        "/r/info/refs",
        "/info/refs?service=git-upload-pack",
        "http://example.test/r/info/refs?service=git-upload-pack",
    ] {
        let input = format!("GET {target} HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert!(
            parse_head(input.as_bytes(), HttpLimits::default()).is_err(),
            "{target}"
        );
    }
}

#[test]
fn missing_http11_host_and_invalid_hosts_fail_closed() {
    for header in [
        "",
        "Host: \r\n",
        "Host: a b\r\n",
        "Host: a/b\r\n",
        "Host: a@b\r\n",
    ] {
        let input = format!("GET /r/info/refs?service=git-upload-pack HTTP/1.1\r\n{header}\r\n");
        assert_eq!(
            parse_head(input.as_bytes(), HttpLimits::default()).unwrap_err(),
            HttpError::InvalidHost
        );
    }
}

#[test]
fn discovery_cannot_contain_a_body_or_continue_handshake() {
    for header in [
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Expect: 100-continue\r\n",
    ] {
        assert_eq!(
            parse_head(&discovery(header), HttpLimits::default()).unwrap_err(),
            HttpError::BodyNotAllowed
        );
    }
    assert!(
        parse_head(&discovery("Content-Length: 0\r\n"), HttpLimits::default())
            .unwrap()
            .is_some()
    );
}

#[test]
fn rpc_requires_length_or_chunking_and_correct_media_type() {
    assert_eq!(
        parse_head(&rpc(""), HttpLimits::default()).unwrap_err(),
        HttpError::LengthRequired
    );
    let request = String::from_utf8(rpc("Content-Length: 0\r\n")).unwrap();
    let bad = request.replace(
        "application/x-git-receive-pack-request",
        "application/x-git-upload-pack-request",
    );
    assert_eq!(
        parse_head(bad.as_bytes(), HttpLimits::default()).unwrap_err(),
        HttpError::UnsupportedMediaType
    );
    let bytes = rpc("Transfer-Encoding: ChUnKeD\r\nExpect: 100-continue\r\n");
    let head = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    assert_eq!(head.body, BodyFraming::Chunked);
    assert!(head.expect_continue);
}

#[test]
fn encoded_bodies_and_trailers_are_explicit_refusals() {
    for (header, expected) in [
        (
            "Content-Length: 0\r\nContent-Encoding: gzip\r\n",
            HttpError::UnsupportedContentEncoding,
        ),
        (
            "Transfer-Encoding: chunked\r\nTrailer: Authorization\r\n",
            HttpError::TrailersNotSupported,
        ),
        (
            "Content-Length: 1\r\nExpect: something-else\r\n",
            HttpError::UnsupportedExpectation,
        ),
    ] {
        assert_eq!(
            parse_head(&rpc(header), HttpLimits::default()).unwrap_err(),
            expected
        );
    }
}

#[test]
fn credentials_are_available_only_explicitly_and_debug_is_redacted() {
    let input = discovery("Authorization: Bearer secret-never-log-this\r\n");
    let head = parse_head(&input, HttpLimits::default()).unwrap().unwrap();
    assert_eq!(head.authorization(), Some("Bearer secret-never-log-this"));
    let debug = format!("{head:?}");
    assert!(!debug.contains("secret-never-log-this"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn protocol_versions_are_bounded_explicit_and_duplicate_free() {
    for (text, expected) in [
        ("version=0", ProtocolVersion::V0),
        ("version=1", ProtocolVersion::V1),
        ("version=2", ProtocolVersion::V2),
        ("object-format=sha256:version=2", ProtocolVersion::V2),
    ] {
        assert_eq!(parse_protocol(Some(text)), Ok(expected));
    }
    for text in [
        "",
        "version=3",
        "version=02",
        "version=",
        "version=1:version=2",
        "version =2",
        "version=2:",
    ] {
        assert!(parse_protocol(Some(text)).is_err(), "{text}");
    }
}

#[test]
fn header_count_limit_is_independent_of_byte_limit() {
    let limits = HttpLimits {
        max_headers: 1,
        ..HttpLimits::default()
    };
    assert!(parse_head(&discovery(""), limits).unwrap().is_some());
    assert_eq!(
        parse_head(&discovery("X: y\r\n"), limits).unwrap_err(),
        HttpError::TooManyHeaders
    );
}

#[test]
fn every_body_fragmentation_preserves_binary_bytes_and_pipeline_tail() {
    let body = b"5\r\na\0b\r\n\r\n3\r\n\xffxy\r\n0\r\n\r\nNEXT";
    for width in 1..=body.len() {
        let (decoded, consumed) =
            decode_chunks(body, BodyFraming::Chunked, width, HttpLimits::default()).unwrap();
        assert_eq!(decoded, b"a\0b\r\n\xffxy");
        assert_eq!(&body[consumed..], b"NEXT");
    }
}

#[test]
fn fixed_length_never_consumes_the_next_request() {
    for width in 1..=8 {
        let (bytes, consumed) = decode_chunks(
            b"a\0\xffNEXT",
            BodyFraming::ContentLength(3),
            width,
            HttpLimits::default(),
        )
        .unwrap();
        assert_eq!(bytes, b"a\0\xff");
        assert_eq!(consumed, 3);
    }
}

#[test]
fn chunk_extensions_support_quoted_strings_and_escaped_quotes() {
    let input = b"3; foo=\"a; b\\\"c\";flag;bar=baz\r\nabc\r\n0\r\n\r\n";
    for width in 1..=input.len() {
        assert_eq!(
            decode_chunks(input, BodyFraming::Chunked, width, HttpLimits::default())
                .unwrap()
                .0,
            b"abc"
        );
    }
}

#[test]
fn malformed_chunk_syntax_and_control_bytes_are_refused() {
    for line in [
        b"".as_slice(),
        b"+1",
        b"-1",
        b"0x1",
        b"g",
        b"1\rX",
        b"10000000000000000",
        b"1;",
        b"1;=x",
        b"1;x=",
        b"1;x=\"unterminated",
        b"1;x=\"a\nb\"",
        b"1;x=\"a\0b\"",
    ] {
        assert!(chunk_size(line).is_err(), "{line:?}");
    }
    for input in [
        b"1\nx\r\n0\r\n\r\n".as_slice(),
        b"1\r\nxX\n0\r\n\r\n",
        b"0\r\nX",
    ] {
        assert!(decode_chunks(input, BodyFraming::Chunked, 1, HttpLimits::default()).is_err());
    }
}

#[test]
fn all_truncated_prefixes_fail_and_no_partial_body_becomes_complete() {
    let input = b"3\r\nabc\r\n0\r\n\r\n";
    for end in 0..input.len() {
        assert_eq!(
            decode_chunks(
                &input[..end],
                BodyFraming::Chunked,
                2,
                HttpLimits::default()
            ),
            Err(HttpError::TruncatedBody)
        );
    }
    assert_eq!(
        decode_chunks(
            b"ab",
            BodyFraming::ContentLength(3),
            1,
            HttpLimits::default()
        ),
        Err(HttpError::TruncatedBody)
    );
}

#[test]
fn decoder_errors_and_eof_permanently_poison_state() {
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
    assert_eq!(decoder.push(b"X\r\n").unwrap_err(), HttpError::InvalidChunk);
    assert_eq!(
        decoder.push(b"0\r\n\r\n").unwrap_err(),
        HttpError::FailedDecoder
    );
    assert_eq!(decoder.finish(), Err(HttpError::FailedDecoder));
    let mut decoder =
        BodyDecoder::new(BodyFraming::ContentLength(3), HttpLimits::default()).unwrap();
    assert_eq!(decoder.finish(), Err(HttpError::TruncatedBody));
    assert_eq!(decoder.push(b"abc").unwrap_err(), HttpError::FailedDecoder);
}

#[test]
fn limits_apply_to_announced_fixed_and_chunked_lengths_before_payload() {
    let limits = HttpLimits {
        max_body_bytes: 3,
        ..HttpLimits::default()
    };
    assert_eq!(
        BodyDecoder::new(BodyFraming::ContentLength(4), limits).unwrap_err(),
        HttpError::BodyTooLarge
    );
    assert_eq!(
        parse_head(&rpc("Content-Length: 4\r\n"), limits).unwrap_err(),
        HttpError::BodyTooLarge
    );
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, limits).unwrap();
    assert_eq!(decoder.push(b"4\r\n").unwrap_err(), HttpError::BodyTooLarge);
    assert_eq!(decoder.decoded_bytes(), 0);
}

#[test]
fn cumulative_chunk_sizes_cannot_escape_body_budget() {
    let limits = HttpLimits {
        max_body_bytes: 3,
        ..HttpLimits::default()
    };
    assert_eq!(
        decode_chunks(
            b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n",
            BodyFraming::Chunked,
            1,
            limits
        ),
        Err(HttpError::BodyTooLarge)
    );
    assert_eq!(
        decode_chunks(
            b"1\r\na\r\n2\r\nbc\r\n0\r\n\r\n",
            BodyFraming::Chunked,
            1,
            limits
        )
        .unwrap()
        .0,
        b"abc"
    );
}

#[test]
fn chunk_count_and_wire_overhead_have_independent_ceilings() {
    let input = b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n";
    let limits = HttpLimits {
        max_chunks: 1,
        ..HttpLimits::default()
    };
    assert_eq!(
        decode_chunks(input, BodyFraming::Chunked, input.len(), limits),
        Err(HttpError::TooManyChunks)
    );
    let limits = HttpLimits {
        max_body_bytes: 2,
        max_body_wire_bytes: 4,
        ..HttpLimits::default()
    };
    assert_eq!(
        decode_chunks(input, BodyFraming::Chunked, input.len(), limits),
        Err(HttpError::WireBudgetExceeded)
    );
}

#[test]
fn trailer_fields_never_override_authentication_or_lengths() {
    let input = b"0\r\nAuthorization: Bearer forged\r\n\r\n";
    assert_eq!(
        decode_chunks(
            input,
            BodyFraming::Chunked,
            input.len(),
            HttpLimits::default()
        ),
        Err(HttpError::TrailersNotSupported)
    );
}

#[test]
fn chunk_metadata_is_bounded_even_without_line_termination() {
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
    assert_eq!(
        decoder.push(&vec![b'1'; 1025]).unwrap_err(),
        HttpError::ChunkLineTooLarge
    );
}

#[test]
fn empty_bodies_complete_without_consuming_a_following_request() {
    for framing in [BodyFraming::Empty, BodyFraming::ContentLength(0)] {
        let mut decoder = BodyDecoder::new(framing, HttpLimits::default()).unwrap();
        assert_eq!(
            decoder.push(b"NEXT").unwrap(),
            BodyStep {
                consumed: 0,
                data: b"",
                complete: true
            }
        );
        decoder.finish().unwrap();
    }
    assert_eq!(
        decode_chunks(
            b"0\r\n\r\nNEXT",
            BodyFraming::Chunked,
            99,
            HttpLimits::default()
        )
        .unwrap(),
        (vec![], 5)
    );
}

#[test]
fn discovery_prefix_lengths_match_git_pkt_lines_and_v2_has_no_preamble() {
    for service in [Service::UploadPack, Service::ReceivePack] {
        for version in [ProtocolVersion::V0, ProtocolVersion::V1] {
            let prefix = discovery_prefix(service, version).unwrap();
            let count =
                usize::from_str_radix(std::str::from_utf8(&prefix[..4]).unwrap(), 16).unwrap();
            assert_eq!(count + 4, prefix.len());
            assert_eq!(&prefix[count..], b"0000");
            assert_eq!(
                &prefix[4..count],
                format!("# service={}\n", service.name()).as_bytes()
            );
        }
    }
    assert_eq!(
        discovery_prefix(Service::UploadPack, ProtocolVersion::V2),
        Ok(b"".as_slice())
    );
    assert_eq!(
        discovery_prefix(Service::ReceivePack, ProtocolVersion::V2),
        Err(HttpError::UnsupportedVersion)
    );
}

#[test]
fn response_headers_cannot_leak_auth_or_be_cached_as_cross_user_discovery() {
    let input = discovery("Authorization: Bearer super-secret\r\n");
    let request = parse_head(&input, HttpLimits::default()).unwrap().unwrap();
    let head = success_head(&request, Some(42));
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains("application/x-git-upload-pack-advertisement\r\n"));
    assert!(head.contains("Cache-Control: no-store\r\n"));
    assert!(head.contains("Content-Length: 42\r\n"));
    assert!(!head.contains("Transfer-Encoding"));
    assert!(!head.contains("super-secret"));
    assert!(success_head(&request, None).contains("Transfer-Encoding: chunked\r\n"));
}

#[test]
fn http10_never_receives_chunked_transfer_encoding() {
    let input = b"GET /r/info/refs?service=git-upload-pack HTTP/1.0\r\n\r\n";
    let request = parse_head(input, HttpLimits::default()).unwrap().unwrap();
    assert_eq!(request.http_version, HttpVersion::Http10);
    let head = success_head(&request, None);
    assert!(head.starts_with("HTTP/1.0 200 OK\r\n"));
    assert!(!head.contains("Transfer-Encoding"));
    assert!(!head.contains("Content-Length"));
    assert!(head.contains("Connection: close"));
}

#[test]
fn chunked_response_round_trips_binary_payload_without_empty_chunk_termination() {
    let mut encoder = ResponseEncoder::new(HttpVersion::Http11, None, 100).unwrap();
    let mut wire = Vec::new();
    for data in [b"abc".as_slice(), b"", b"\xff\0\r\n"] {
        let chunk = encoder.push(data).unwrap();
        wire.extend_from_slice(chunk.prefix.as_bytes());
        wire.extend_from_slice(chunk.data);
        wire.extend_from_slice(chunk.suffix);
    }
    wire.extend_from_slice(encoder.finish().unwrap());
    for width in 1..=wire.len() {
        assert_eq!(
            decode_chunks(&wire, BodyFraming::Chunked, width, HttpLimits::default())
                .unwrap()
                .0,
            b"abc\xff\0\r\n"
        );
    }
    assert!(encoder.finish().is_err());
    assert!(encoder.push(b"late").is_err());
}

#[test]
fn response_lengths_and_budgets_are_enforced_before_output() {
    let mut encoder = ResponseEncoder::new(HttpVersion::Http11, Some(3), 3).unwrap();
    assert_eq!(encoder.push(b"abcd").unwrap_err(), HttpError::BodyTooLarge);
    assert!(encoder.push(b"abc").is_err());
    let mut encoder = ResponseEncoder::new(HttpVersion::Http11, Some(3), 100).unwrap();
    assert_eq!(
        encoder.push(b"abcd").unwrap_err(),
        HttpError::ResponseLengthMismatch
    );
    let mut encoder = ResponseEncoder::new(HttpVersion::Http11, Some(3), 100).unwrap();
    encoder.push(b"ab").unwrap();
    assert!(encoder.finish().is_err());
    let mut encoder = ResponseEncoder::new(HttpVersion::Http11, Some(3), 100).unwrap();
    let chunk = encoder.push(b"abc").unwrap();
    assert!(chunk.prefix.is_empty());
    assert!(chunk.suffix.is_empty());
    assert_eq!(encoder.finish(), Ok(b"".as_slice()));
}

#[test]
fn close_delimited_responses_write_only_payload() {
    let mut encoder = ResponseEncoder::new(HttpVersion::Http10, None, 3).unwrap();
    let chunk = encoder.push(b"abc").unwrap();
    assert!(chunk.prefix.is_empty());
    assert_eq!(chunk.data, b"abc");
    assert!(chunk.suffix.is_empty());
    assert_eq!(encoder.finish(), Ok(b"".as_slice()));
}

#[test]
fn invalid_limit_profiles_are_rejected_before_parsing_or_decoding() {
    for limits in [
        HttpLimits {
            max_headers: 0,
            ..HttpLimits::default()
        },
        HttpLimits {
            max_chunks: 0,
            ..HttpLimits::default()
        },
        HttpLimits {
            max_head_bytes: 10,
            ..HttpLimits::default()
        },
        HttpLimits {
            max_target_bytes: 0,
            ..HttpLimits::default()
        },
        HttpLimits {
            max_body_wire_bytes: 1,
            ..HttpLimits::default()
        },
    ] {
        assert_eq!(
            parse_head(b"", limits).unwrap_err(),
            HttpError::InvalidLimits
        );
        assert_eq!(
            BodyDecoder::new(BodyFraming::Empty, limits).unwrap_err(),
            HttpError::InvalidLimits
        );
    }
}
