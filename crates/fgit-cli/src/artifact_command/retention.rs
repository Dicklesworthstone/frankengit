//! CLI spelling of existing identity-owned retention profiles, not enforcement.
use fgit_object_fabric::RetentionProfile;
use std::collections::BTreeMap;

pub(super) fn parse(fields: &BTreeMap<&str, &str>) -> Result<RetentionProfile, String> {
    let ttl = fields.get("--ttl-secs");
    let days = fields.get("--retain-days");
    let permanent = fields.contains_key("--release-permanent");
    let hold = fields.get("--legal-hold-id");
    let reason = fields.get("--legal-hold-reason");
    let selections = usize::from(ttl.is_some())
        + usize::from(days.is_some())
        + usize::from(permanent)
        + usize::from(hold.is_some() || reason.is_some());
    if selections > 1 {
        return Err(
            "select only one retention profile: TTL, log days, permanent release or legal hold"
                .into(),
        );
    }
    if let Some(days) = days {
        return Ok(RetentionProfile::StandardLog {
            retain_days: super::options::decimal(days, 1, u64::from(u32::MAX))? as u32,
        });
    }
    if permanent {
        return Ok(RetentionProfile::ReleasePermanent);
    }
    if hold.is_some() || reason.is_some() {
        let hold = hold.ok_or("legal hold requires --legal-hold-id")?;
        let reason = reason.ok_or("legal hold requires --legal-hold-reason")?;
        if reason.is_empty() || reason.len() > 1024 {
            return Err("legal hold reason must contain 1..1024 UTF-8 bytes".into());
        }
        return Ok(RetentionProfile::LegalHold {
            hold_id: super::options::decimal(hold, 1, u64::MAX)?,
            reason: (*reason).into(),
        });
    }
    Ok(RetentionProfile::HotEphemeral {
        ttl_seconds: ttl.map_or(Ok(86400), |value| {
            super::options::decimal(value, 1, u64::MAX)
        })?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_existing_encodings_and_integer_boundaries() {
        assert_eq!(
            parse(&BTreeMap::new()).unwrap(),
            RetentionProfile::HotEphemeral { ttl_seconds: 86400 }
        );
        for (fields, expected) in [
            (
                vec![("--ttl-secs", "18446744073709551615")],
                RetentionProfile::HotEphemeral {
                    ttl_seconds: u64::MAX,
                },
            ),
            (
                vec![("--retain-days", "4294967295")],
                RetentionProfile::StandardLog {
                    retain_days: u32::MAX,
                },
            ),
            (
                vec![("--release-permanent", "true")],
                RetentionProfile::ReleasePermanent,
            ),
            (
                vec![
                    ("--legal-hold-id", "18446744073709551615"),
                    ("--legal-hold-reason", "Original β\nline"),
                ],
                RetentionProfile::LegalHold {
                    hold_id: u64::MAX,
                    reason: "Original β\nline".into(),
                },
            ),
        ] {
            let actual = parse(&fields.into_iter().collect()).unwrap();
            assert_eq!(actual.encode_canonical(), expected.encode_canonical());
            assert_eq!(
                RetentionProfile::decode_canonical(&actual.encode_canonical()).unwrap(),
                expected
            );
        }
        let limit = "β".repeat(512);
        assert!(
            parse(&BTreeMap::from([
                ("--legal-hold-id", "1"),
                ("--legal-hold-reason", limit.as_str())
            ]))
            .is_ok()
        );
        let over = format!("{limit}a");
        assert!(
            parse(&BTreeMap::from([
                ("--legal-hold-id", "1"),
                ("--legal-hold-reason", over.as_str())
            ]))
            .is_err()
        );
    }
    #[test]
    fn incomplete_ambiguous_and_overflowing_retention_is_not_defaulted() {
        for fields in [
            vec![("--ttl-secs", "0")],
            vec![("--ttl-secs", "01")],
            vec![("--ttl-secs", "18446744073709551616")],
            vec![("--retain-days", "4294967296")],
            vec![("--retain-days", "0")],
            vec![("--legal-hold-id", "1")],
            vec![("--legal-hold-reason", "missing ID")],
            vec![("--legal-hold-id", "0"), ("--legal-hold-reason", "reason")],
            vec![("--legal-hold-id", "1"), ("--legal-hold-reason", "")],
            vec![("--ttl-secs", "1"), ("--retain-days", "1")],
            vec![("--ttl-secs", "1"), ("--release-permanent", "true")],
            vec![
                ("--release-permanent", "true"),
                ("--legal-hold-reason", "missing ID"),
            ],
        ] {
            assert!(parse(&fields.into_iter().collect()).is_err());
        }
    }
}
