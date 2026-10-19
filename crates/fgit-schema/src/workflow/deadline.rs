//! Workflow-authored time caps only attenuate externally granted execution time.

use super::{Node, WorkflowRefusal};

/// The trusted workflow profile's existing maximum whole-run duration.
pub const MAX_TIMEOUT_MINUTES: u16 = 60;

/// A positive, bounded number of minutes. This is a requested ceiling, never a
/// resource grant: execution must also enforce every narrower operator limit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimeoutMinutes(u16);

impl TimeoutMinutes {
    #[must_use]
    pub const fn from_minutes(minutes: u16) -> Option<Self> {
        if minutes > 0 && minutes <= MAX_TIMEOUT_MINUTES {
            Some(Self(minutes))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn minutes(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0 as u64 * 60
    }
}

pub(super) fn lower(
    node: Option<&Node>,
    path: &'static str,
) -> Result<Option<TimeoutMinutes>, WorkflowRefusal> {
    let Some(node) = node else {
        return Ok(None);
    };
    let Node::Scalar { value, .. } = node else {
        return Err(WorkflowRefusal::FieldShape {
            path,
            expected: "a positive decimal integer from 1 through 60",
            observed: node.shape(),
            span: node.span(),
        });
    };
    let timeout = (!value.is_empty()
        && value.len() <= 2
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit()))
    .then(|| value.parse::<u16>().ok())
    .flatten()
    .and_then(TimeoutMinutes::from_minutes);
    timeout.map(Some).ok_or(WorkflowRefusal::Malformed {
        expected: if path == "job.timeout-minutes" {
            "job.timeout-minutes as a positive decimal integer from 1 through 60"
        } else {
            "step.timeout-minutes as a positive decimal integer from 1 through 60"
        },
        span: node.span(),
    })
}
