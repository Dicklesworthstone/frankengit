//! An explicit replay gets one cumulative ordinal, not a new automatic policy.
//! Pure calculation: this module never grants trust, reads a diagnostic, touches
//! a registration store, or loops over HTTP sends. The caller verifies those
//! bindings and local at-least-once consent before requesting a replay plan.

#[derive(Debug, PartialEq, Eq)]
pub(super) struct AttemptPlan {
    pub(super) ordinal: u32,
    pub(super) invocation_limit: u32,
}

pub(super) fn plan(
    automatic_limit: u32,
    retained_attempt: Option<u32>,
    explicit_attempt: Option<u32>,
) -> Result<AttemptPlan, String> {
    if automatic_limit == 0 {
        return Err("ResourceBudgetExceeded: zero automatic webhook attempt limit".into());
    }
    let ordinal = match retained_attempt {
        Some(0) => return Err("dead-letter attempt must be positive; no replay attempted".into()),
        Some(previous) => {
            let next = previous.checked_add(1).ok_or("manual attempt overflow")?;
            if explicit_attempt.is_some_and(|attempt| attempt != next) {
                return Err("replay --attempt must follow the retained diagnostic attempt".into());
            }
            next
        }
        None => explicit_attempt.unwrap_or(1),
    };
    if !(1..=16).contains(&ordinal) {
        return Err("manual delivery attempt must be 1..16".into());
    }
    Ok(AttemptPlan {
        ordinal,
        // A normal manual deliver still meets the adapter's original automatic
        // limit. Only a verified replay can extend its ephemeral ceiling, and
        // only as far as this one invocation's ordinal. Later scheduler calls
        // reopen the unchanged persisted registration and retain its old cap.
        invocation_limit: if retained_attempt.is_some() {
            automatic_limit.max(ordinal)
        } else {
            automatic_limit
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_delivery_cannot_increase_the_automatic_transport_ceiling() {
        for automatic in 1..=16 {
            for ordinal in 1..=16 {
                let selected = plan(automatic, None, Some(ordinal)).unwrap();
                assert_eq!(selected.ordinal, ordinal);
                assert_eq!(selected.invocation_limit, automatic);
                assert_eq!(selected.ordinal <= selected.invocation_limit, ordinal <= automatic);
            }
            assert_eq!(plan(automatic, None, None).unwrap().ordinal, 1);
        }
    }

    #[test]
    fn replay_after_exhaustion_grants_only_its_next_cumulative_ordinal() {
        assert_eq!(plan(5, Some(5), None).unwrap(), AttemptPlan {
            ordinal: 6,
            invocation_limit: 6,
        });
        for automatic in 1..=16 {
            for previous in 1..16 {
                let selected = plan(automatic, Some(previous), None).unwrap();
                assert_eq!(selected.ordinal, previous + 1);
                assert_eq!(selected.invocation_limit, automatic.max(previous + 1));
                assert_eq!(selected, plan(automatic, Some(previous), Some(previous + 1)).unwrap());
            }
        }
    }

    #[test]
    fn replay_cannot_reset_an_ordinal_skip_a_diagnostic_or_escape_the_manual_bound() {
        for changed in [0, 1, 5, 7, 16, u32::MAX] {
            assert!(plan(5, Some(5), Some(changed)).is_err());
        }
        assert_eq!(plan(5, Some(15), None).unwrap().ordinal, 16);
        assert!(plan(5, Some(16), None).is_err());
        assert!(plan(5, Some(u32::MAX), None).unwrap_err().contains("overflow"));
        assert!(plan(5, Some(0), None).is_err());
    }

    #[test]
    fn invalid_limits_fail_instead_of_becoming_replay_allowances() {
        for retained in [None, Some(5)] {
            assert!(plan(0, retained, None).is_err());
        }
        for ordinal in [0, 17, u32::MAX] {
            assert!(plan(5, None, Some(ordinal)).is_err());
        }
    }
}
