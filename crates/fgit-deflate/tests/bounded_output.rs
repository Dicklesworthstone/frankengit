#![forbid(unsafe_code)]
//! Output backpressure preserves zlib semantics and exact framing boundaries.
use fgit_deflate::{
    BoundedStreamProgress, CancellationProbe, DeflateLimits, DeflateProfile, InflateLimits,
    InflateRefusal, Inflater, NeverCancel, Resource, deflate_zlib, inflate_zlib,
};

fn member(body: &[u8], profile: DeflateProfile) -> Vec<u8> {
    deflate_zlib(body, DeflateLimits::GIT_OBJECT, profile).unwrap()
}

fn decode(
    input: &[u8],
    input_chunk: usize,
    output_limit: usize,
    framed: bool,
) -> Result<(Vec<u8>, usize, usize), InflateRefusal> {
    let mut inflater = if framed {
        Inflater::new_framed(InflateLimits::GIT_OBJECT)?
    } else {
        Inflater::new(InflateLimits::GIT_OBJECT)?
    };
    let mut output = Vec::new();
    let mut yields = 0;
    for bytes in input.chunks(input_chunk) {
        let mut progress =
            inflater.push_with_bounded_output(bytes, output_limit, &mut NeverCancel)?;
        loop {
            let fresh = inflater.take_output();
            assert!(fresh.len() <= output_limit.saturating_add(257));
            output.extend(fresh);
            match progress {
                BoundedStreamProgress::Finished => {
                    inflater.finish()?;
                    return Ok((output, inflater.consumed_input_bytes(), yields));
                }
                BoundedStreamProgress::NeedInput => break,
                BoundedStreamProgress::OutputReady => {
                    yields += 1;
                    progress =
                        inflater.push_with_bounded_output(&[], output_limit, &mut NeverCancel)?;
                }
            }
        }
    }
    inflater.finish()?;
    output.extend(inflater.take_output());
    Ok((output, inflater.consumed_input_bytes(), yields))
}

#[test]
fn bounded_drain_matches_existing_decoder_for_all_block_profiles_and_fragmentation() {
    let body = b"overlapping matches and repeated bytes: abababababxxxxxxxxxx".repeat(3000);
    for profile in [
        DeflateProfile::FAST_STORED,
        DeflateProfile::DEFAULT,
        DeflateProfile::DYNAMIC,
    ] {
        let encoded = member(&body, profile);
        let expected = inflate_zlib(&encoded, InflateLimits::GIT_OBJECT).unwrap();
        for input_chunk in [1, 17, 32 * 1024] {
            for output_limit in [1, 31, 16 * 1024] {
                let (observed, consumed, yields) =
                    decode(&encoded, input_chunk, output_limit, false).unwrap();
                assert_eq!(observed, expected);
                assert_eq!(consumed, encoded.len());
                if input_chunk == 32 * 1024 {
                    assert!(yields > 0);
                }
            }
        }
    }
}

#[test]
fn draining_does_not_consume_the_next_member_or_mask_a_strict_suffix() {
    let body = vec![b'x'; 256 * 1024];
    let encoded = member(&body, DeflateProfile::DYNAMIC);
    let mut framed = encoded.clone();
    framed.extend(b"NEXT-ENTRY-HEADER");
    let (observed, consumed, yields) = decode(&framed, framed.len(), 4096, true).unwrap();
    assert_eq!(observed, body);
    assert_eq!(consumed, encoded.len());
    assert!(yields > 32);
    assert!(matches!(
        decode(&framed, framed.len(), 4096, false),
        Err(InflateRefusal::TrailingGarbage)
    ));
}

#[test]
fn final_adler_and_truncation_are_not_authenticated_by_earlier_output() {
    let encoded = member(&vec![b'q'; 128 * 1024], DeflateProfile::DEFAULT);
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        decode(&corrupt, corrupt.len(), 1024, false),
        Err(InflateRefusal::Adler32Mismatch { .. })
    ));
    for omitted in 1..=4 {
        assert!(matches!(
            decode(
                &encoded[..encoded.len() - omitted],
                encoded.len(),
                1024,
                false
            ),
            Err(InflateRefusal::UnexpectedEnd)
        ));
    }
    assert!(decode(&encoded, encoded.len(), 1024, false).is_ok());
}

struct Cancel(bool);
impl CancellationProbe for Cancel {
    fn is_cancelled(&mut self) -> bool {
        self.0
    }
}

#[test]
fn cancellation_and_resource_limits_survive_output_yields() {
    let encoded = member(&vec![b'z'; 128 * 1024], DeflateProfile::DEFAULT);
    let mut inflater = Inflater::new(InflateLimits::GIT_OBJECT).unwrap();
    assert_eq!(
        inflater
            .push_with_bounded_output(&encoded, 1024, &mut NeverCancel)
            .unwrap(),
        BoundedStreamProgress::OutputReady
    );
    assert!(!inflater.take_output().is_empty());
    assert_eq!(
        inflater.push_with_bounded_output(&[], 1024, &mut Cancel(true)),
        Err(InflateRefusal::Cancelled)
    );
    for (limits, resource) in [
        (
            InflateLimits {
                max_output_bytes: 1024,
                ..InflateLimits::GIT_OBJECT
            },
            Resource::OutputBytes,
        ),
        (
            InflateLimits {
                max_work_units: 10,
                ..InflateLimits::GIT_OBJECT
            },
            Resource::WorkUnits,
        ),
        (
            InflateLimits {
                max_expansion_ratio: Some(1),
                ..InflateLimits::GIT_OBJECT
            },
            Resource::ExpansionRatio,
        ),
    ] {
        let mut inflater = Inflater::new(limits).unwrap();
        let mut input = encoded.as_slice();
        let error = loop {
            match inflater.push_with_bounded_output(input, 64, &mut NeverCancel) {
                Err(error) => break error,
                Ok(BoundedStreamProgress::OutputReady) => {
                    drop(inflater.take_output());
                    input = &[];
                }
                Ok(other) => panic!("expected {resource:?}, got {other:?}"),
            }
        };
        assert!(
            matches!(error, InflateRefusal::ResourceLimit { resource: found, .. } if found == resource)
        );
    }
}

#[test]
fn zero_output_allowance_refuses_before_input_and_can_be_corrected() {
    let encoded = member(b"valid twin", DeflateProfile::DEFAULT);
    let mut inflater = Inflater::new(InflateLimits::GIT_OBJECT).unwrap();
    assert!(matches!(
        inflater.push_with_bounded_output(&encoded, 0, &mut NeverCancel),
        Err(InflateRefusal::ResourceLimit {
            resource: Resource::Configuration,
            ..
        })
    ));
    assert_eq!(inflater.consumed_input_bytes(), 0);
    assert_eq!(
        inflater
            .push_with_bounded_output(&encoded, 1024, &mut NeverCancel)
            .unwrap(),
        BoundedStreamProgress::Finished
    );
    assert_eq!(inflater.take_output(), b"valid twin");
}
