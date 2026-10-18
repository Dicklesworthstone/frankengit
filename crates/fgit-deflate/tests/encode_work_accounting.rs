#![forbid(unsafe_code)]
//! Multi-member callers retain exact consumed work instead of refreshing the
//! compression allowance whenever a new zlib member starts.
use fgit_deflate::{DeflateLimits, DeflateProfile, DeflateRefusal, Deflater, Resource};

fn encode(limit: u64) -> Result<Deflater, DeflateRefusal> {
    let mut encoder = Deflater::new(
        DeflateLimits {
            max_work_units: limit,
            ..DeflateLimits::GIT_OBJECT
        },
        DeflateProfile::DEFAULT,
    )?;
    encoder.push(b"work accounting observes actual native compression, including finalization")?;
    encoder.finish()?;
    Ok(encoder)
}

#[test]
fn exact_encoder_work_counter_supports_a_shared_multi_member_allowance() {
    let first = encode(DeflateLimits::GIT_OBJECT.max_work_units).unwrap();
    let used = first.work_units();
    assert!(used > 0);
    assert_eq!(encode(used).unwrap().work_units(), used);
    assert!(matches!(
        encode(used - 1),
        Err(DeflateRefusal::ResourceLimit {
            resource: Resource::WorkUnits,
            ..
        })
    ));
    let total = used * 2 - 1;
    let remaining = total - first.work_units();
    assert!(
        encode(remaining).is_err(),
        "a new member cannot replenish the shared allowance"
    );
    assert!(encode(total - used + 1).is_ok());
}
