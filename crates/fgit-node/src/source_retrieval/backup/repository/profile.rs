//! Caller-selected limits, not automatic budget increases based on input size.
use super::archive::stream::TransferLimits;
use crate::NodeRequestContext;
use fgit_runtime::{BudgetClass, BudgetPolicy, ClassLimits};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(super) struct Profile {
    pub transfer: TransferLimits,
    pub timeout: Duration,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            transfer: TransferLimits::default(),
            timeout: Duration::from_secs(300),
        }
    }
}
impl Profile {
    pub fn with_timeout_cap(mut self, cap: Option<Duration>) -> Result<Self, String> {
        if let Some(cap) = cap {
            if cap.is_zero() {
                return Err("repository backup timeout cap must be positive".into());
            }
            self.timeout = self.timeout.min(cap);
        }
        Ok(self)
    }
    /// Runtime budgets for the node a backup command opens. The operator's
    /// `--timeout-secs` bounds its database and request contexts too; the
    /// per-context 15 s / 30 s defaults size ordinary requests and cancelled a
    /// large backup or restore mid-store ("cancelled after transmission") no
    /// matter what timeout the operator chose. Poll and cost quotas stay
    /// finite at the transfer class's defaults.
    pub fn node_budgets(self) -> Result<BudgetPolicy, String> {
        let limits = ClassLimits::finite(self.timeout, 1_000_000, 50_000_000);
        BudgetPolicy::finite_defaults()
            .with_class_limits(BudgetClass::Database, limits)
            .and_then(|policy| policy.with_class_limits(BudgetClass::Request, limits))
            .map_err(|error| format!("backup runtime budget refused: {error}"))
    }
    pub fn start(self) -> Deadline {
        Deadline {
            started: Instant::now(),
            timeout: self.timeout,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Deadline {
    started: Instant,
    timeout: Duration,
}
impl Deadline {
    pub fn check(self) -> Result<(), String> {
        if self.started.elapsed() >= self.timeout {
            Err("repository backup operation deadline exceeded".into())
        } else {
            Ok(())
        }
    }
    pub fn in_request(self, request: &NodeRequestContext) -> Result<(), String> {
        self.check().inspect_err(|_| request.cancel())
    }
}
#[derive(Default)]
pub(super) struct ProfileFlags {
    bytes: Option<u64>,
    blob_bytes: Option<u64>,
    seconds: Option<u64>,
}
impl ProfileFlags {
    pub fn set(&mut self, flag: &str, text: &str) -> Result<(), String> {
        if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{flag} requires canonical positive decimal"));
        }
        let value = text
            .parse::<u64>()
            .map_err(|_| format!("{flag} overflows"))?;
        let slot = match flag {
            "--max-archive-bytes" => {
                TransferLimits {
                    max_archive_bytes: value,
                    ..TransferLimits::default()
                }
                .validate()?;
                &mut self.bytes
            }
            "--max-blob-bytes" => {
                TransferLimits {
                    max_blob_bytes: value,
                    ..TransferLimits::default()
                }
                .validate()?;
                &mut self.blob_bytes
            }
            "--timeout-secs" if value <= 86_400 => &mut self.seconds,
            "--timeout-secs" => return Err("timeout must be in 1..=86400 seconds".into()),
            _ => return Err(format!("unknown backup profile flag: {flag}")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate {flag}"));
        }
        Ok(())
    }
    pub fn finish(self) -> Profile {
        let defaults = Profile::default();
        Profile {
            transfer: TransferLimits {
                max_archive_bytes: self.bytes.unwrap_or(defaults.transfer.max_archive_bytes),
                max_blob_bytes: self.blob_bytes.unwrap_or(defaults.transfer.max_blob_bytes),
            },
            timeout: Duration::from_secs(self.seconds.unwrap_or(defaults.timeout.as_secs())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_global_timeout_only_narrows_the_leaf_without_renewing_other_allowances() {
        let profile = Profile::default();
        assert_eq!(
            profile.with_timeout_cap(None).unwrap().timeout,
            profile.timeout
        );
        assert_eq!(
            profile
                .with_timeout_cap(Some(Duration::from_secs(900)))
                .unwrap()
                .timeout,
            Duration::from_secs(300)
        );
        let narrowed = profile
            .with_timeout_cap(Some(Duration::from_nanos(1)))
            .unwrap();
        assert_eq!(narrowed.timeout, Duration::from_nanos(1));
        assert_eq!(
            narrowed.transfer.max_archive_bytes,
            profile.transfer.max_archive_bytes
        );
        assert_eq!(
            narrowed.transfer.max_blob_bytes,
            profile.transfer.max_blob_bytes
        );
        assert!(profile.with_timeout_cap(Some(Duration::ZERO)).is_err());
    }
    #[test]
    fn defaults_and_explicit_limits_remain_independent() {
        let defaults = ProfileFlags::default().finish();
        assert_eq!(defaults.transfer.max_archive_bytes, 1 << 30);
        assert_eq!(defaults.transfer.max_blob_bytes, 32 * 1024 * 1024);
        assert_eq!(defaults.timeout, Duration::from_secs(300));
        let mut flags = ProfileFlags::default();
        flags.set("--max-archive-bytes", "1099511627776").unwrap();
        flags.set("--max-blob-bytes", "536870912").unwrap();
        flags.set("--timeout-secs", "86400").unwrap();
        let profile = flags.finish();
        assert_eq!(profile.transfer.max_archive_bytes, 1 << 40);
        assert_eq!(profile.transfer.max_blob_bytes, 512 * 1024 * 1024);
        assert_eq!(profile.timeout, Duration::from_hours(24));
    }
    #[test]
    fn malformed_duplicate_and_excessive_budgets_refuse() {
        for flag in ["--max-archive-bytes", "--max-blob-bytes", "--timeout-secs"] {
            for text in [
                "",
                "0",
                "01",
                "+1",
                "-1",
                " 1",
                "1.0",
                "18446744073709551616",
            ] {
                assert!(ProfileFlags::default().set(flag, text).is_err());
            }
            let mut flags = ProfileFlags::default();
            flags.set(flag, "1").unwrap();
            assert!(flags.set(flag, "2").is_err());
        }
        assert!(
            ProfileFlags::default()
                .set("--max-archive-bytes", "1099511627777")
                .is_err()
        );
        assert!(
            ProfileFlags::default()
                .set("--max-blob-bytes", "1099511627777")
                .is_err()
        );
        assert!(
            ProfileFlags::default()
                .set("--timeout-secs", "86401")
                .is_err()
        );
    }
    #[test]
    fn selecting_a_blob_limit_preserves_archive_and_deadline_bounds() {
        for maximum in [1_u64, 32 * 1024 * 1024, 1 << 40] {
            let mut flags = ProfileFlags::default();
            flags.set("--max-blob-bytes", &maximum.to_string()).unwrap();
            let profile = flags.finish();
            assert_eq!(profile.transfer.max_blob_bytes, maximum);
            assert_eq!(profile.transfer.max_archive_bytes, 1 << 30);
            assert_eq!(profile.timeout, Duration::from_secs(300));
        }
        let mut archive_only = ProfileFlags::default();
        archive_only.set("--max-archive-bytes", "1").unwrap();
        assert_eq!(
            archive_only.finish().transfer.max_blob_bytes,
            32 * 1024 * 1024
        );
    }

    #[test]
    fn the_same_deadline_is_shared_by_later_passes() {
        let deadline = Deadline {
            started: Instant::now(),
            timeout: Duration::ZERO,
        };
        assert!(deadline.check().is_err());
        let later = deadline;
        assert!(later.check().is_err());
        assert!(Profile::default().start().check().is_ok());
    }
}
