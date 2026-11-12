//! A bounded single-byte-range profile for already authorized LFS downloads.
//! Range never verifies custody or grants disclosure. The caller must verify
//! the complete original object before emitting either a range or its length.
use super::{Envelope, Failure, LfsObject};

const MAX_RANGE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Selection {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
}

/// A strong validator for the exact immutable representation, never an mtime.
pub(super) fn etag(object: LfsObject) -> String {
    format!("\"sha256-{}-{}\"", object.oid, object.size)
}

pub(super) fn select(envelope: &Envelope<'_>, object: LfsObject) -> Result<Selection, Failure> {
    let Some(value) = envelope.range().map_err(Failure::http)? else {
        // RFC 9110 §13.1.5: If-Range has no effect without Range.
        return Ok(Selection::Full);
    };
    if let Some(validator) = envelope.if_range().map_err(Failure::http)?
        && validator != etag(object)
    {
        // Weak tags, dates (we publish no Last-Modified), and mismatched tags
        // cannot prove representation equality. Resume becomes a full GET.
        return Ok(Selection::Full);
    }
    parse(value, object.size)
}

fn parse(value: &str, size: u64) -> Result<Selection, Failure> {
    if value.len() > MAX_RANGE_BYTES {
        return Err(Failure::bad("lfs_range_limit"));
    }
    let (unit, specification) = value
        .split_once('=')
        .filter(|(unit, _)| !unit.is_empty())
        .ok_or_else(|| Failure::bad("invalid_lfs_range"))?;
    // RFC 9110 §14.2 permits ignoring Range. This profile ignores unknown
    // units and all multi-range sets, preserving an ordinary verified 200.
    // It never claims a partial response for an unimplemented multipart body.
    if !unit.eq_ignore_ascii_case("bytes") || specification.contains(',') {
        return Ok(Selection::Full);
    }
    let (first, last) = specification
        .split_once('-')
        .ok_or_else(|| Failure::bad("invalid_lfs_range"))?;
    let (start, end) = if first.is_empty() {
        let suffix = decimal(last)?;
        if suffix == 0 || size == 0 {
            return Ok(Selection::Unsatisfiable);
        }
        (size.saturating_sub(suffix), size - 1)
    } else {
        let start = decimal(first)?;
        let last_value = if last.is_empty() {
            u64::MAX
        } else {
            decimal(last)?
        };
        // Compare the original decimal spelling as well: two overflowing
        // numerals must not lose their ordering merely because both saturate.
        let first_digits = first.trim_start_matches('0');
        let last_digits = last.trim_start_matches('0');
        if !last.is_empty() && (first_digits.len(), first_digits) > (last_digits.len(), last_digits)
        {
            return Err(Failure::bad("invalid_lfs_range"));
        }
        if start >= size {
            return Ok(Selection::Unsatisfiable);
        }
        (start, last_value.min(size - 1))
    };
    Ok(Selection::Partial { start, end })
}

fn decimal(value: &str) -> Result<u64, Failure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::bad("invalid_lfs_range"));
    }
    // RFC 9110 §14.1.2 permits arbitrarily large numerals. Saturation is exact
    // for this bounded payload profile: huge starts are unsatisfiable, whereas
    // huge end offsets and suffix lengths clamp to the complete object.
    Ok(value.bytes().fold(0_u64, |total, byte| {
        total
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ranges_have_exact_inclusive_bounds() {
        for (text, start, end) in [
            ("bytes=0-0", 0, 0),
            ("bytes=2-5", 2, 5),
            ("bytes=2-", 2, 9),
            ("bytes=2-999", 2, 9),
            ("bytes=-4", 6, 9),
            ("bytes=-10", 0, 9),
            ("bytes=-11", 0, 9),
            ("BYTES=0002-0005", 2, 5),
            ("bytes=2-9999999999999999999999999999999", 2, 9),
            ("bytes=-9999999999999999999999999999999", 0, 9),
        ] {
            assert_eq!(
                parse(text, 10).unwrap(),
                Selection::Partial { start, end },
                "{text}"
            );
        }
        for text in [
            "bytes=10-",
            "bytes=11-20",
            "bytes=-0",
            "bytes=9999999999999999999999999999999-",
            "bytes=9999999999999999999999999999999-10000000000000000000000000000000",
        ] {
            assert_eq!(parse(text, 10).unwrap(), Selection::Unsatisfiable, "{text}");
        }
        for text in ["bytes=0-", "bytes=0-0", "bytes=-1"] {
            assert_eq!(parse(text, 0).unwrap(), Selection::Unsatisfiable, "{text}");
        }
    }

    #[test]
    fn malformed_ranges_refuse_and_unsupported_profiles_remain_full_responses() {
        for text in [
            "",
            "bytes",
            "bytes=",
            "=0-1",
            "bytes=-",
            "bytes=5-4",
            "bytes=+1-2",
            "bytes=1--2",
            "bytes=1-+2",
            "bytes=1-a",
            "bytes= 1-2",
            "bytes=1 -2",
            "bytes=1-2 ",
            "bytes=10000000000000000000000000000000-9999999999999999999999999999999",
            "bytes=9999999999999999999999999999999-9999999999999999999999999999998",
        ] {
            assert!(parse(text, 10).is_err(), "{text}");
        }
        assert!(parse(&format!("bytes=0-{}", "9".repeat(MAX_RANGE_BYTES)), 10).is_err());
        for text in ["items=0-1", "bytes=0-1,3-4", "bytes=99-100,200-300"] {
            assert_eq!(parse(text, 10).unwrap(), Selection::Full, "{text}");
        }
    }
}
