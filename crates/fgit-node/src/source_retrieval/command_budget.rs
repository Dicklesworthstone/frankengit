//! One absolute operator deadline across preparation, native work and idle waits.
//! Cleanup keeps its independent budget; expiry never proves publication rollback.
use std::time::{Duration, Instant};

use fgit_runtime::{BudgetClass, boot::NodeRuntime};
use fsqlite_types::cx::Cx;

use crate::{GitDaemonSessionTimeout, NodeRequestContext, OneNode};

/// An optional wall-clock ceiling, created once at the host command boundary.
/// Absence preserves each operation's existing finite class policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatorDeadline {
    expires: Option<Instant>,
}
impl OperatorDeadline {
    pub fn new(timeout: Option<Duration>) -> Result<Self, String> {
        let expires = timeout
            .map(|duration| {
                GitDaemonSessionTimeout::try_new(duration).map_err(|e| e.to_string())?;
                Instant::now().checked_add(duration).ok_or_else(|| {
                    "operator command deadline is outside the clock range".to_owned()
                })
            })
            .transpose()?;
        Ok(Self { expires })
    }
    pub fn remaining(&self) -> Result<Option<Duration>, String> {
        self.expires
            .map(|end| {
                end.checked_duration_since(Instant::now())
                    .filter(|duration| !duration.is_zero())
                    .ok_or_else(|| {
                        "ResourceBudgetExceeded: operator command deadline expired".to_owned()
                    })
            })
            .transpose()
    }
    pub fn checkpoint(&self) -> Result<(), String> {
        self.remaining().map(|_| ())
    }
    /// Mint a runtime-owned context from the remaining command time, preserving
    /// the class's independent poll and cost limits and the runtime root ceiling.
    /// Calling this again never renews the command's absolute wall-clock budget.
    pub fn context(&self, runtime: &NodeRuntime, class: BudgetClass) -> Result<Cx, String> {
        let mut limits = runtime.profile().budgets().limits_for(class);
        if let Some(remaining) = self.remaining()? {
            limits.timeout = Some(remaining);
        }
        let cx = Cx::new();
        cx.set_native_cx(runtime.request_cx_with_budget(limits.at(runtime.now())));
        self.checkpoint()?;
        Ok(cx)
    }
    pub fn request(
        &self,
        node: &OneNode,
        class: BudgetClass,
    ) -> Result<NodeRequestContext, String> {
        Ok(NodeRequestContext {
            authority: self.context(node.runtime(), class)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_override_keeps_class_defaults_and_invalid_values_refuse() {
        assert_eq!(OperatorDeadline::default().remaining().unwrap(), None);
        assert!(OperatorDeadline::new(Some(Duration::ZERO)).is_err());
        assert!(OperatorDeadline::new(Some(Duration::MAX)).is_err());
    }
    #[test]
    fn copied_deadline_does_not_renew_and_expiry_is_sticky() {
        let original = OperatorDeadline::new(Some(Duration::from_secs(60))).unwrap();
        let copy = original;
        assert_eq!(copy.expires, original.expires);
        assert!(copy.remaining().unwrap().unwrap() <= Duration::from_secs(60));
        let expired = OperatorDeadline {
            expires: Some(Instant::now()),
        };
        for _ in 0..10 {
            assert!(
                expired
                    .checkpoint()
                    .unwrap_err()
                    .contains("ResourceBudgetExceeded")
            );
        }
    }
    #[test]
    fn exhausted_deadline_never_mints_another_native_request() {
        let runtime = fgit_runtime::boot::RuntimeProfile::production(2)
            .build()
            .unwrap();
        let expired = OperatorDeadline {
            expires: Some(Instant::now()),
        };
        assert!(expired.context(&runtime, BudgetClass::Database).is_err());
        assert!(
            expired
                .context(&runtime, BudgetClass::BackgroundController)
                .is_err()
        );
        let cleanup = OperatorDeadline::default()
            .context(&runtime, BudgetClass::Database)
            .unwrap();
        drop(cleanup);
        assert!(runtime.join_root(Duration::from_secs(5)));
    }
}
