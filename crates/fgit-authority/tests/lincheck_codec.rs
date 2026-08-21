#![forbid(unsafe_code)]

use fgit_authority::history::{
    AuthorityHistoryBody, ClientId, History, HistoryEvent, LogicalTime, OperationId,
};
use fgit_authority::{AuthorityOp, AuthorityResponse, HeadKey, HeadRead};
use fgit_codec::{DecodeLimits, canonical_body_bytes, decode_body, encode_body};

fn fixture_history() -> History<AuthorityOp, AuthorityResponse> {
    let key = HeadKey::new(b"g".to_vec()).expect("golden head key is valid");
    History::new(vec![
        HistoryEvent::invocation(
            ClientId(1),
            LogicalTime(1),
            OperationId(7),
            AuthorityOp::ReadHead { key: key.clone() },
        ),
        HistoryEvent::response(
            ClientId(1),
            LogicalTime(2),
            OperationId(7),
            AuthorityResponse::ReadHead(HeadRead::Absent),
        ),
    ])
    .expect("golden history is structurally valid")
}

fn decode_hex(text: &str) -> Vec<u8> {
    let digits = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(digits.len() % 2, 0, "fixture contains complete hex pairs");
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            (high << 4) | low
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("fixture contains non-hex text"),
    }
}

#[test]
fn authority_history_payload_matches_the_v1_golden_fixture() {
    let body = AuthorityHistoryBody::new(fixture_history());
    let payload = canonical_body_bytes(&body).expect("authority history is encodable");
    let golden = decode_hex(include_str!("goldens/lincheck/authority_history_v1.hex"));

    assert_eq!(payload, golden);
}

#[test]
fn codec_frame_round_trip_preserves_the_validated_history() {
    let body = AuthorityHistoryBody::new(fixture_history());
    let frame = encode_body(&body).expect("authority history frame is encodable");
    let decoded = decode_body::<AuthorityHistoryBody>(&frame, DecodeLimits::DEFAULT)
        .expect("authority history frame is decodable");

    assert_eq!(decoded, body);
}
