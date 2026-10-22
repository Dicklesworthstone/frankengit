//! Selection over a complete bounded path inventory. Never substring or regex.
use super::*;
const MAX_PATHS: usize = 512;
const MAX_PATH_BYTES: usize = 256 * 1024;
const MAX_WORK: usize = 16 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathFilter(pub(super) BranchFilter);
impl PathFilter {
    #[must_use]
    pub const fn field(&self) -> &'static str {
        if self.0.ignore {
            "paths-ignore"
        } else {
            "paths"
        }
    }
    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.0.patterns()
    }
    pub(super) fn selects(
        &self,
        paths: &[Vec<u8>],
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool, TriggerSelectionError> {
        if paths.len() > MAX_PATHS {
            return Err(TriggerSelectionError::InvalidChangedPaths);
        }
        let mut bytes = 0usize;
        for path in paths {
            if cancelled() {
                return Err(TriggerSelectionError::Cancelled);
            }
            bytes = bytes
                .checked_add(path.len())
                .filter(|n| *n <= MAX_PATH_BYTES)
                .ok_or(TriggerSelectionError::InvalidChangedPaths)?;
            if path.is_empty()
                || path.len() > MAX_MATCH_BYTES
                || path.contains(&0)
                || path
                    .split(|b| *b == b'/')
                    .any(|p| p.is_empty() || p == b"." || p == b"..")
            {
                return Err(TriggerSelectionError::InvalidChangedPaths);
            }
        }
        if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(TriggerSelectionError::InvalidChangedPaths);
        }
        let tokens: usize = self.0.patterns.iter().map(|(_, _, p)| p.len()).sum();
        let setup = 2 * (MAX_MATCH_BYTES + 1) * self.0.patterns.len();
        let work = paths.iter().try_fold(0usize, |sum, p| {
            tokens
                .checked_mul(p.len() + 1)
                .and_then(|n| n.checked_add(setup))
                .and_then(|n| sum.checked_add(n))
        });
        if work.is_none_or(|n| n > MAX_WORK) {
            return Err(TriggerSelectionError::PathMatchBudget);
        }
        let mut selected = false;
        for path in paths {
            selected |= self.0.matches(path, cancelled)?;
        }
        if cancelled() {
            return Err(TriggerSelectionError::Cancelled);
        }
        Ok(selected)
    }
}
