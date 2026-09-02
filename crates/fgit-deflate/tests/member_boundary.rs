#![forbid(unsafe_code)]
//! The streaming inflater reports the exact zlib member boundary.
//!
//! A pack stream carries zlib members back to back with no outer framing, so
//! the transport that receives one over a duplex socket can only resume at the
//! next entry header if the inflater says how much of the supplied input the
//! finished member actually consumed. These tests pin that accounting.

use fgit_deflate::{
    DeflateLimits, DeflateProfile, InflateLimits, Inflater, StreamProgress, deflate_zlib,
};

fn member(payload: &[u8]) -> Vec<u8> {
    deflate_zlib(payload, DeflateLimits::GIT_OBJECT, DeflateProfile::DEFAULT)
        .expect("a small payload deflates")
}

#[test]
fn finished_member_reports_its_exact_consumed_length() {
    let payload = b"one bounded pack object body";
    let compressed = member(payload);
    let mut stream = compressed.clone();
    stream.extend_from_slice(b"NEXT-ENTRY-HEADER-BYTES");

    let mut inflater = Inflater::new_framed(InflateLimits::GIT_OBJECT).expect("limits validate");
    let progress = inflater
        .push(&stream)
        .expect("a valid member followed by foreign bytes inflates");

    assert_eq!(progress, StreamProgress::Finished);
    assert_eq!(
        inflater.consumed_input_bytes(),
        compressed.len(),
        "the member boundary must sit exactly at the zlib trailer"
    );
    assert_eq!(inflater.take_output(), payload);
}

#[test]
fn boundary_accounting_survives_byte_by_byte_delivery() {
    let payload = vec![0x5a_u8; 4_096];
    let compressed = member(&payload);

    let mut inflater = Inflater::new(InflateLimits::GIT_OBJECT).expect("limits validate");
    let mut finished_at = None;
    for (index, byte) in compressed.iter().enumerate() {
        let progress = inflater
            .push(core::slice::from_ref(byte))
            .expect("one byte at a time");
        if progress == StreamProgress::Finished {
            finished_at = Some(index + 1);
            break;
        }
    }

    assert_eq!(finished_at, Some(compressed.len()));
    assert_eq!(inflater.consumed_input_bytes(), compressed.len());
    assert_eq!(inflater.take_output(), payload);
}

#[test]
fn an_unfinished_member_has_consumed_no_more_than_supplied() {
    let compressed = member(b"payload that will be truncated");
    let cut = compressed.len() / 2;

    let mut inflater = Inflater::new(InflateLimits::GIT_OBJECT).expect("limits validate");
    let progress = inflater
        .push(&compressed[..cut])
        .expect("a truncated prefix only asks for more input");

    assert_eq!(progress, StreamProgress::NeedInput);
    assert!(inflater.consumed_input_bytes() <= cut);
}

#[test]
fn strict_mode_still_refuses_a_framing_suffix() {
    let compressed = member(b"a loose object is exactly one member");
    let mut stream = compressed;
    stream.push(0x00);

    let mut inflater = Inflater::new(InflateLimits::GIT_OBJECT).expect("limits validate");
    assert!(matches!(
        inflater.push(&stream),
        Err(fgit_deflate::InflateRefusal::TrailingGarbage)
    ));
}
