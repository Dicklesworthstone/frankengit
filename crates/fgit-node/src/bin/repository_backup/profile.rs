//! Caller-selected limits, not automatic budget increases based on input size.
use std::time::{Duration, Instant};
use fgit_node::NodeRequestContext;
use super::archive::stream::TransferLimits;

#[derive(Clone, Copy, Debug)]
pub(super) struct Profile {
    pub transfer: TransferLimits,
    pub timeout: Duration,
}
impl Default for Profile {
    fn default() -> Self { Self { transfer: TransferLimits::default(), timeout: Duration::from_secs(300) } }
}
impl Profile {
    pub fn start(self) -> Deadline { Deadline { started: Instant::now(), timeout: self.timeout } }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Deadline { started: Instant, timeout: Duration }
impl Deadline {
    pub fn check(self) -> Result<(), String> {
        if self.started.elapsed() >= self.timeout { Err("repository backup operation deadline exceeded".into()) } else { Ok(()) }
    }
    pub fn in_request(self, request: &NodeRequestContext) -> Result<(), String> {
        self.check().inspect_err(|_| request.cancel())
    }
}
#[derive(Default)]
pub(super) struct ProfileFlags { bytes: Option<u64>, seconds: Option<u64> }
impl ProfileFlags {
    pub fn set(&mut self, flag: &str, text: &str) -> Result<(), String> {
        if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{flag} requires canonical positive decimal"));
        }
        let value = text.parse::<u64>().map_err(|_| format!("{flag} overflows"))?;
        let slot = match flag {
            "--max-archive-bytes" => {
                TransferLimits { max_archive_bytes: value }.validate()?; &mut self.bytes
            }
            "--timeout-secs" if value <= 86_400 => &mut self.seconds,
            "--timeout-secs" => return Err("timeout must be in 1..=86400 seconds".into()),
            _ => return Err(format!("unknown backup profile flag: {flag}")),
        };
        if slot.replace(value).is_some() { return Err(format!("duplicate {flag}")); }
        Ok(())
    }
    pub fn finish(self) -> Profile {
        let defaults = Profile::default();
        Profile { transfer: TransferLimits { max_archive_bytes: self.bytes.unwrap_or(defaults.transfer.max_archive_bytes) },
            timeout: Duration::from_secs(self.seconds.unwrap_or(defaults.timeout.as_secs())) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_explicit_limits_remain_independent() {
        let defaults = ProfileFlags::default().finish();
        assert_eq!(defaults.transfer.max_archive_bytes, 1 << 30);
        assert_eq!(defaults.timeout, Duration::from_secs(300));
        let mut flags = ProfileFlags::default();
        flags.set("--max-archive-bytes", "1099511627776").unwrap();
        flags.set("--timeout-secs", "86400").unwrap();
        let profile = flags.finish();
        assert_eq!(profile.transfer.max_archive_bytes, 1 << 40);
        assert_eq!(profile.timeout, Duration::from_secs(86400));
    }
    #[test]
    fn malformed_duplicate_and_excessive_budgets_refuse() {
        for flag in ["--max-archive-bytes", "--timeout-secs"] {
            for text in ["", "0", "01", "+1", "-1", " 1", "1.0", "18446744073709551616"] {
                assert!(ProfileFlags::default().set(flag, text).is_err());
            }
            let mut flags = ProfileFlags::default(); flags.set(flag, "1").unwrap();
            assert!(flags.set(flag, "2").is_err());
        }
        assert!(ProfileFlags::default().set("--max-archive-bytes", "1099511627777").is_err());
        assert!(ProfileFlags::default().set("--timeout-secs", "86401").is_err());
    }
    #[test]
    fn the_same_deadline_is_shared_by_later_passes() {
        let deadline = Deadline { started: Instant::now(), timeout: Duration::ZERO };
        assert!(deadline.check().is_err());
        let later = deadline;
        assert!(later.check().is_err());
        assert!(Profile::default().start().check().is_ok());
    }
}
