use super::{MIN_OUTPUT_BYTES, USAGE};
use crate::agent_recover::options::{self as original, Options as OriginalOptions};
use fgit_agent::LogicalTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Acknowledge,
    AbortReserved,
}

pub(super) struct Options {
    pub original: OriginalOptions,
    pub observed_at: LogicalTime,
    pub action: Action,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 27
        || args.iter().any(|arg| arg.len() > 4096)
        || args.iter().map(String::len).sum::<usize>() > 32 * 1024
    {
        return Err(USAGE.into());
    }
    let mut common = args[..4].to_vec();
    let mut observed_at = None;
    let mut action = None;
    let mut at = 4;
    while let Some(flag) = args.get(at) {
        at += 1;
        if flag == "--trusted-local" {
            common.push(flag.clone());
            continue;
        }
        let value = args
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        if flag == "--action" {
            if action.is_some() {
                return Err("duplicate --action".into());
            }
            action = Some(match value.as_str() {
                "acknowledge" => Action::Acknowledge,
                "abort-reserved" => Action::AbortReserved,
                _ => return Err("--action must be acknowledge or abort-reserved".into()),
            });
        } else if flag == "--observed-at" {
            if observed_at.is_some() {
                return Err("duplicate --observed-at".into());
            }
            observed_at = Some(LogicalTime::new(
                fgit_schema::json::decimal(value)
                    .map_err(|_| "--observed-at requires canonical unsigned logical time")?,
            ));
        } else {
            common.extend([flag.clone(), value.clone()]);
        }
    }
    let original = original::parse_with_usage(&common, USAGE)?;
    let observed_at = observed_at.ok_or(
        "--observed-at is required in the original host's logical-time domain; cleanup never renews a run",
    )?;
    if original.maximum < MIN_OUTPUT_BYTES {
        return Err(format!(
            "agent settlement requires --max-output-bytes >= {MIN_OUTPUT_BYTES} before journal I/O"
        ));
    }
    Ok(Options {
        original,
        observed_at,
        action: action.unwrap_or(Action::Acknowledge),
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn arguments() -> Vec<String> {
        [
            "/node",
            &"11".repeat(16),
            &"22".repeat(16),
            "/journal",
            "--trusted-local",
            "--principal",
            &"33".repeat(16),
            "--run-id",
            &"44".repeat(16),
            "--effect-id",
            &"55".repeat(16),
            "--expected-run",
            &"66".repeat(32),
            "--expected-tail-entries",
            "3",
            "--expected-tail-bytes",
            "1024",
            "--expected-tail-digest",
            &"77".repeat(32),
            "--observed-at",
            "10001",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn settlement_requires_all_original_pins_and_an_explicit_cleanup_time() {
        let input = arguments();
        let options = parse(&input).unwrap();
        assert_eq!(options.observed_at.value(), 10001);
        assert_eq!(options.action, Action::Acknowledge);
        assert_eq!(options.original.expected_tail.entries, 3);
        for flag in [
            "--principal",
            "--run-id",
            "--effect-id",
            "--expected-run",
            "--expected-tail-entries",
            "--expected-tail-bytes",
            "--expected-tail-digest",
            "--observed-at",
        ] {
            let mut missing = input.clone();
            let at = missing
                .iter()
                .position(|argument| argument == flag)
                .unwrap();
            missing.drain(at..at + 2);
            assert!(parse(&missing).is_err(), "missing {flag}");
        }
        let mut untrusted = input.clone();
        untrusted.remove(4);
        assert!(parse(&untrusted).is_err());
        let mut repeated = input;
        repeated.extend(["--observed-at".into(), "10001".into()]);
        assert!(parse(&repeated).is_err());
    }

    #[test]
    fn abort_is_an_explicit_closed_action_and_keeps_every_original_pin() {
        for (name, expected) in [
            ("acknowledge", Action::Acknowledge),
            ("abort-reserved", Action::AbortReserved),
        ] {
            let mut input = arguments();
            input.extend(["--action".into(), name.into()]);
            let options = parse(&input).unwrap();
            assert_eq!(options.action, expected);
            assert_eq!(options.original.expected_tail.entries, 3);
            assert_eq!(options.observed_at.value(), 10001);
            for flag in ["--principal", "--expected-run", "--expected-tail-digest"] {
                let mut missing = input.clone();
                let at = missing
                    .iter()
                    .position(|argument| argument == flag)
                    .unwrap();
                missing.drain(at..at + 2);
                assert!(parse(&missing).is_err(), "{name}: missing {flag}");
            }
            input.extend(["--action".into(), name.into()]);
            assert!(parse(&input).is_err());
        }
        for name in ["", "abort", "cancel", "resume", "auto", "Abort-Reserved"] {
            let mut input = arguments();
            input.extend(["--action".into(), name.into()]);
            assert!(parse(&input).is_err(), "action {name:?}");
        }
    }

    #[test]
    fn time_encoding_output_capacity_and_all_input_bounds_refuse_before_io() {
        for value in ["", "01", "-1", "+1", "1.0", "18446744073709551616"] {
            let mut input = arguments();
            *input.last_mut().unwrap() = value.into();
            assert!(parse(&input).is_err(), "time {value:?}");
        }
        for value in ["0", "16", "8191", "1048577"] {
            let mut input = arguments();
            input.extend(["--max-output-bytes".into(), value.into()]);
            assert!(parse(&input).is_err(), "output {value}");
        }
        for value in ["8192", "1048576"] {
            let mut input = arguments();
            input.extend(["--max-output-bytes".into(), value.into()]);
            assert!(parse(&input).is_ok(), "output {value}");
        }
        let mut relative = arguments();
        relative[3] = "journal".into();
        assert!(parse(&relative).is_err());
        let mut oversized = arguments();
        oversized[0] = "x".repeat(4097);
        assert!(parse(&oversized).is_err());
        let mut resubmit = arguments();
        resubmit.extend(["--bundle".into(), "/new-publication".into()]);
        assert!(parse(&resubmit).is_err());
    }
}
