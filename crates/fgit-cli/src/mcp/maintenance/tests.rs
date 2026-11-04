use super::super::{backend, parse_options};
use super::*;

fn args(profile: &str, format: &str, agent: bool, context_only: bool) -> Vec<String> {
    let mut values: Vec<String> = ["/unused", &"11".repeat(16), &"22".repeat(16)]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if agent {
        values.extend(["--agent-token-file", "/private-token"].map(str::to_owned));
    } else {
        values.push("--trusted-local".into());
    }
    values.push(
        if context_only {
            "--allow-agent-context"
        } else {
            "--allow-source"
        }
        .into(),
    );
    if context_only && !agent {
        values.extend(["--principal".into(), "44".repeat(16)]);
    }
    values.extend(["--expected-incarnation".into(), "33".repeat(16)]);
    values.extend(
        [
            "--object-format",
            format,
            "--index-profile",
            profile,
            "--index-format",
            format,
            "--index-state",
            "init",
            "--index-state-dir",
            "/lexical",
            "--index-ref",
            "refs/heads/z",
            "--index-ref",
            "refs/heads/a",
        ]
        .map(str::to_owned),
    );
    if profile == "both" {
        values.extend(["--index-symbol-state-dir", "/symbols"].map(str::to_owned));
    }
    values
}
fn set(values: &mut [String], flag: &str, value: &str) {
    let index = values.iter().position(|s| s == flag).unwrap();
    values[index + 1] = value.into();
}
fn remove(values: &mut Vec<String>, flag: &str, has_value: bool) {
    let index = values.iter().position(|s| s == flag).unwrap();
    values.drain(index..index + if has_value { 2 } else { 1 });
}

#[cfg(unix)]
#[test]
fn explicit_operator_maintenance_is_independent_of_tool_profile_and_grants() {
    for agent in [false, true] {
        for context_only in [false, true] {
            for format in ["sha1", "sha256"] {
                for profile in ["lexical", "symbols", "both"] {
                    let options =
                        parse_options(&args(profile, format, agent, context_only)).unwrap();
                    let group = options.index_maintenance.as_ref().unwrap();
                    assert_eq!(group.configs().len(), if profile == "both" { 2 } else { 1 });
                    for config in group.configs() {
                        assert_eq!(config.format().as_str(), format);
                        assert_eq!(config.refs()[0].as_bytes(), b"refs/heads/a");
                        assert_eq!(config.interval(), Duration::from_secs(5));
                        assert_eq!(config.attempt_timeout(), Duration::from_secs(300));
                        assert!(config.initialize());
                    }
                    let with: Vec<_> = backend::tools_for_options(&options)
                        .iter()
                        .map(|tool| tool.name)
                        .collect();
                    let mut without = options.clone();
                    without.index_maintenance = None;
                    assert_eq!(
                        with,
                        backend::tools_for_options(&without)
                            .iter()
                            .map(|tool| tool.name)
                            .collect::<Vec<_>>()
                    );
                    assert!(!options.writes.any());
                    assert_eq!(options.source, !context_only);
                    assert_eq!(options.agent_context, context_only);
                    assert_eq!(options.principal.is_some(), !agent && context_only);
                    assert!(with.iter().all(
                        |name| !name.contains("index_build") && !name.contains("index_refresh")
                    ));
                }
            }
        }
    }
}

#[test]
fn partial_or_conflicting_configuration_is_never_silently_disabled() {
    for flag in [
        "--index-profile",
        "--index-format",
        "--index-state",
        "--index-state-dir",
        "--index-symbol-state-dir",
        "--expected-incarnation",
    ] {
        let mut values = args("both", "sha1", false, false);
        remove(&mut values, flag, true);
        assert!(parse_options(&values).is_err(), "{flag}");
    }
    let mut no_reads = args("lexical", "sha1", true, false);
    remove(&mut no_reads, "--allow-source", false);
    no_reads.push("--allow-issues".into());
    assert!(parse_options(&no_reads).is_err());
    for (flag, invalid) in [
        ("--index-profile", "auto"),
        ("--index-state", "repair"),
        ("--index-format", "sha256"),
        ("--index-state-dir", ""),
    ] {
        let mut values = args("both", "sha1", false, false);
        set(&mut values, flag, invalid);
        assert!(parse_options(&values).is_err(), "{flag}");
    }
    let mut alias = args("both", "sha1", false, false);
    set(&mut alias, "--index-symbol-state-dir", "/lexical");
    assert!(parse_options(&alias).is_err());
    let mut extra = args("lexical", "sha1", false, false);
    extra.extend(["--index-symbol-state-dir", "/symbols"].map(str::to_owned));
    assert!(parse_options(&extra).is_err());
    let mut duplicate = args("lexical", "sha1", false, false);
    duplicate.extend(["--index-state", "resume"].map(str::to_owned));
    assert!(parse_options(&duplicate).is_err());
}

#[cfg(unix)]
#[test]
fn exact_scope_schedule_and_attempt_bounds_are_preserved() {
    for flag in ["--index-interval-secs", "--index-attempt-timeout-secs"] {
        for value in ["0", "3601", "01", "-1", "1.5"] {
            let mut values = args("both", "sha1", false, false);
            values.extend([flag, value].map(str::to_owned));
            assert!(parse_options(&values).is_err(), "{flag}={value}");
        }
        for value in ["1", "3600"] {
            let mut values = args("both", "sha1", false, false);
            values.extend([flag, value].map(str::to_owned));
            assert!(parse_options(&values).is_ok());
        }
    }
    let mut values = args("both", "sha1", false, false);
    while values.iter().any(|v| v == "--index-ref") {
        remove(&mut values, "--index-ref", true);
    }
    assert!(parse_options(&values).is_err());
    for index in 0..32 {
        values.extend(["--index-ref".into(), format!("refs/heads/r{index}")]);
    }
    assert!(parse_options(&values).is_ok());
    values.extend(["--index-ref", "refs/heads/extra"].map(str::to_owned));
    assert!(parse_options(&values).is_err());
    let mut duplicate = args("lexical", "sha1", false, false);
    duplicate.extend(["--index-ref", "refs/heads/a"].map(str::to_owned));
    assert!(parse_options(&duplicate).is_err());
    let mut not_full = args("lexical", "sha1", false, false);
    set(&mut not_full, "--index-ref", "HEAD");
    assert!(parse_options(&not_full).is_err());
}
