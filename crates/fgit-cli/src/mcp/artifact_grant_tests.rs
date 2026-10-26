use super::*;

fn launch() -> Vec<String> {
    vec![
        "/unused/node".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
        "--allow-artifacts".into(),
        "--artifact-root".into(),
        "/unused/private-artifacts".into(),
        "--expected-incarnation".into(),
        "44".repeat(16),
    ]
}

#[test]
fn artifacts_require_the_independent_root_grant_and_incarnation_binding() {
    let complete = launch();
    #[cfg(target_os = "linux")]
    {
        let options = parse_options(&complete).unwrap();
        assert!(options.artifacts);
        assert_eq!(
            options.artifact_root,
            Some(PathBuf::from("/unused/private-artifacts"))
        );
        assert!(!options.issues && !options.pulls && !options.source);
        assert!(!options.writes.any() && !options.outcomes && options.principal.is_none());
        let mut combined = complete.clone();
        combined.push("--allow-source".into());
        let options = parse_options(&combined).unwrap();
        assert!(options.source && options.artifacts);
        assert!(!options.issues && !options.pulls && !options.writes.any());
    }
    #[cfg(not(target_os = "linux"))]
    assert!(
        parse_options(&complete)
            .unwrap_err()
            .contains("only on Linux")
    );

    for (flag, takes_value) in [
        ("--allow-artifacts", false),
        ("--artifact-root", true),
        ("--expected-incarnation", true),
        ("--trusted-local", false),
    ] {
        let mut missing = complete.clone();
        let index = missing.iter().position(|value| value == flag).unwrap();
        missing.remove(index);
        if takes_value {
            missing.remove(index);
        }
        assert!(parse_options(&missing).is_err(), "{flag}");
    }
    for root in ["", "relative", "/private/../elsewhere"] {
        let mut invalid = complete.clone();
        invalid[6] = root.into();
        assert!(parse_options(&invalid).is_err(), "{root}");
    }
    for extra in [
        vec!["--allow-artifacts".into()],
        vec!["--artifact-root".into(), "/another".into()],
        vec!["--principal".into(), "33".repeat(16)],
        vec!["--trust-domain".into(), "other".into()],
    ] {
        let mut invalid = complete.clone();
        invalid.extend(extra);
        assert!(parse_options(&invalid).is_err());
    }
}
