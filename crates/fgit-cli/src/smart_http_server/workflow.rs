//! Immutable operator configuration for the HTTP service's native CI sibling.

use super::{BTreeMap, Duration, GitHashAlgorithm, PathBuf, PrincipalId, RefName, number};
use fgit_node::workflow_watch::WorkflowWatchConfig;

pub(super) fn parse(
    flags: &BTreeMap<&str, &str>,
    inputs: Vec<Vec<u8>>,
) -> Result<Option<WorkflowWatchConfig>, String> {
    if inputs.is_empty() && !flags.keys().any(|name| name.starts_with("--workflow-")) {
        return Ok(None);
    }
    if !flags.contains_key("--workflow-trusted-local") {
        return Err("workflow service requires --workflow-trusted-local: trust all future selected scripts with host-user privileges".into());
    }
    if !flags.contains_key("--credentials-file") {
        return Err("workflow service requires explicit scoped --credentials-file".into());
    }
    if !flags.contains_key("--continuous") || !flags.contains_key("--stop-file") {
        return Err(
            "workflow service requires --continuous and --stop-file for owned execution drain"
                .into(),
        );
    }
    let required = |name: &str| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("workflow service requires {name}"))
    };
    let format = match required("--workflow-format")? {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--workflow-format must be sha1 or sha256".into()),
    };
    let reference = RefName::try_new(required("--workflow-ref")?.as_bytes())
        .map_err(|error| error.to_string())?;
    let interval = Duration::from_millis(number(flags, "--workflow-interval-ms", 1000, 60000)?);
    let mut config = WorkflowWatchConfig::try_new(
        format,
        reference,
        required("--workflow-dir")?.as_bytes().to_vec(),
        PathBuf::from(required("--workflow-run-parent")?),
        inputs,
        interval,
    )
    .and_then(|config| {
        let seconds = number(flags, "--workflow-attempt-timeout-secs", 300, 3600)
            .map_err(std::io::Error::other)?;
        config.with_attempt_timeout(Duration::from_secs(seconds))
    })
    .map_err(|error| error.to_string())?;

    if flags.contains_key("--workflow-publish-checks") != flags.contains_key("--workflow-principal")
    {
        return Err(
            "--workflow-publish-checks and --workflow-principal must be supplied together".into(),
        );
    }
    if let Some(publisher) = flags.get("--workflow-principal") {
        required("--expected-incarnation")?;
        config = config.with_publisher(
            PrincipalId::from_hex(publisher).map_err(|_| "invalid workflow check publisher")?,
        );
    }
    if flags.contains_key("--workflow-pull-request") && flags.contains_key("--workflow-merge-queue")
    {
        return Err(
            "--workflow-pull-request and --workflow-merge-queue are mutually exclusive".into(),
        );
    }
    if flags.contains_key("--workflow-pull-request") {
        config = config
            .with_pull_request(number(flags, "--workflow-pull-request", 1, u64::MAX)?)
            .map_err(|error| error.to_string())?;
    }
    if flags.contains_key("--workflow-merge-queue") {
        config = config
            .with_merge_queue(number(flags, "--workflow-merge-queue", 1, u64::MAX)?)
            .map_err(|error| error.to_string())?;
    }
    let merge_fields: BTreeMap<_, _> = flags
        .iter()
        .filter_map(|(name, value)| {
            crate::workflow_merge_watch::server_option(name).map(|name| (name, *value))
        })
        .collect();
    let merge = crate::workflow_merge_watch::parse(&merge_fields)?;
    if config.merge_queue().is_some() && merge.is_none() {
        return Err(
            "--workflow-merge-queue requires the complete workflow merge-candidate group".into(),
        );
    }
    if let Some(merge) = merge {
        if config.merge_queue().is_some() {
            merge.validate_queue_selection(
                config.reference(),
                flags.contains_key("--expected-incarnation"),
            )?;
        } else {
            merge.validate_selection(
                config.reference(),
                config.pull_request(),
                flags.contains_key("--expected-incarnation"),
            )?;
        }
        config = config
            .with_merge_candidate(merge.node_config()?)
            .map_err(|error| error.to_string())?;
    }
    if flags.contains_key("--workflow-artifact-logs") {
        let artifacts = fgit_node::TrustedWorkflowArtifactConfig::new_with_logs(
            PathBuf::from(required("--artifact-root")?),
            Vec::new(),
            16 * 1024 * 1024,
            64 * 1024 * 1024,
        )
        .map_err(str::to_owned)?;
        config = config.with_artifacts(artifacts);
    }
    Ok(Some(config))
}

#[cfg(test)]
mod tests {
    use super::super::{CredentialInput, parse as parse_server};
    use super::*;

    fn flags() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("--trusted-local", ""),
            ("--credentials-file", "/private/credentials"),
            ("--continuous", ""),
            ("--stop-file", "/private/control/http.stop"),
            ("--workflow-trusted-local", ""),
            ("--workflow-ref", "refs/heads/main"),
            ("--workflow-format", "sha256"),
            ("--workflow-dir", "ci"),
            ("--workflow-run-parent", "/private/runs"),
        ])
    }
    fn inputs() -> Vec<Vec<u8>> {
        vec![b"ci".to_vec()]
    }

    fn server_arguments() -> Vec<String> {
        let mut arguments = vec![
            "state".to_owned(),
            "11".repeat(16),
            "22".repeat(16),
            "127.0.0.1:0".to_owned(),
        ];
        for (name, value) in flags() {
            arguments.push(name.to_owned());
            if !value.is_empty() {
                arguments.push(value.to_owned());
            }
        }
        arguments.extend(["--workflow-input".to_owned(), "ci".to_owned()]);
        arguments
    }

    fn merge_arguments() -> Vec<String> {
        let mut arguments = server_arguments();
        arguments.extend(
            [
                "--expected-incarnation",
                "44444444444444444444444444444444",
                "--workflow-pull-request",
                "7",
                "--workflow-merge-candidate-ref",
                "refs/heads/ci/pr-7",
                "--workflow-merge-principal",
                "33333333333333333333333333333333",
                "--workflow-merge-author",
                "CI <ci@example.test>",
                "--workflow-merge-committer",
                "CI <ci@example.test>",
                "--workflow-merge-timestamp",
                "1700000000",
                "--workflow-merge-message",
                "Check the merged tree",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        arguments
    }

    fn queue_arguments() -> Vec<String> {
        let mut arguments = merge_arguments();
        let at = arguments
            .iter()
            .position(|value| value == "--workflow-pull-request")
            .unwrap();
        arguments[at] = "--workflow-merge-queue".into();
        arguments
    }

    #[test]
    fn queue_service_selects_target_and_retains_independent_endpoint_and_publisher_grants() {
        let options = parse_server(&queue_arguments()).unwrap();
        assert!(!options.allow_receive);
        assert!(!options.allow_queues);
        assert!(!options.allow_queue_landings);
        assert!(!options.allow_pulls);
        let service = options.workflow_service.unwrap();
        assert_eq!(service.merge_queue(), Some(7));
        assert!(service.pull_request().is_none());
        assert!(service.publisher().is_none());
        assert_eq!(service.reference().as_bytes(), b"refs/heads/main");
        assert_eq!(
            service.merge_candidate().unwrap().style(),
            fgit_forge::preparation::MergeCommitStyle::TwoParent
        );

        let mut arguments = queue_arguments();
        arguments.extend([
            "--workflow-publish-checks".into(),
            "--workflow-principal".into(),
            "55".repeat(16),
            "--workflow-merge-profile".into(),
            "exact-renames".into(),
            "--allow-queue-landings".into(),
        ]);
        let options = parse_server(&arguments).unwrap();
        assert!(options.allow_queue_landings);
        assert!(!options.allow_queues);
        assert!(!options.allow_receive);
        let service = options.workflow_service.unwrap();
        assert_ne!(
            service.publisher().unwrap(),
            service.merge_candidate().unwrap().principal()
        );
        assert_eq!(
            service.merge_candidate().unwrap().profile(),
            fgit_forge::preparation::MergeProfile::ExactRenamesV1
        );
    }

    #[test]
    fn queue_service_refuses_missing_candidate_identity_squash_or_ambiguous_selection() {
        for flag in [
            "--expected-incarnation",
            "--workflow-merge-candidate-ref",
            "--workflow-merge-principal",
            "--workflow-merge-author",
            "--workflow-merge-committer",
            "--workflow-merge-timestamp",
            "--workflow-merge-message",
        ] {
            let mut arguments = queue_arguments();
            let at = arguments.iter().position(|value| value == flag).unwrap();
            arguments.drain(at..at + 2);
            assert!(parse_server(&arguments).is_err(), "{flag}");
        }
        let mut absent = server_arguments();
        absent.extend(["--workflow-merge-queue".into(), "7".into()]);
        assert!(parse_server(&absent).is_err());
        for extra in [
            vec!["--workflow-pull-request", "7"],
            vec!["--workflow-merge-queue", "7"],
            vec!["--workflow-merge-method", "squash"],
        ] {
            let mut arguments = queue_arguments();
            arguments.extend(extra.into_iter().map(str::to_owned));
            assert!(parse_server(&arguments).is_err());
        }
        let mut arguments = queue_arguments();
        let at = arguments
            .iter()
            .position(|value| value == "--workflow-merge-candidate-ref")
            .unwrap();
        arguments[at + 1] = "refs/heads/main".into();
        assert!(parse_server(&arguments).is_err());
        for invalid in ["0", "01", "-1", "+1", "1.0", "18446744073709551616", ""] {
            let mut arguments = queue_arguments();
            let at = arguments
                .iter()
                .position(|value| value == "--workflow-merge-queue")
                .unwrap();
            arguments[at + 1] = invalid.into();
            assert!(parse_server(&arguments).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn queue_service_preserves_raw_candidate_ref_and_literal_message() {
        let mut arguments = queue_arguments();
        let at = arguments
            .iter()
            .position(|value| value == "--workflow-merge-candidate-ref")
            .unwrap();
        arguments[at] = "--workflow-merge-candidate-ref-hex".into();
        arguments[at + 1] = "726566732f68656164732f63692fff".into();
        let at = arguments
            .iter()
            .position(|value| value == "--workflow-merge-message")
            .unwrap();
        arguments[at + 1] = "--workflow-merge-queue".into();
        let service = parse_server(&arguments).unwrap().workflow_service.unwrap();
        assert_eq!(service.merge_queue(), Some(7));
        assert_eq!(
            service.merge_candidate().unwrap().reference().as_bytes(),
            b"refs/heads/ci/\xff"
        );
        assert_eq!(
            service.merge_candidate().unwrap().metadata().message,
            b"--workflow-merge-queue"
        );
    }

    #[test]
    fn merge_service_keeps_publication_and_network_authorities_explicit() {
        let options = parse_server(&merge_arguments()).unwrap();
        assert!(!options.allow_receive);
        assert!(!options.allow_source);
        assert!(!options.allow_pulls);
        assert!(!options.allow_protection);
        let service = options.workflow_service.unwrap();
        assert_eq!(service.pull_request(), Some(7));
        assert!(service.publisher().is_none());
        let merge = service.merge_candidate().unwrap();
        assert_eq!(merge.reference().as_bytes(), b"refs/heads/ci/pr-7");
        assert_eq!(merge.metadata().timestamp, 1_700_000_000);
        assert_eq!(merge.metadata().message, b"Check the merged tree");

        let mut literal = merge_arguments();
        let at = literal
            .iter()
            .position(|value| value == "--workflow-merge-message")
            .unwrap();
        literal[at + 1] = "--merge-method".into();
        let service = parse_server(&literal).unwrap().workflow_service.unwrap();
        assert_eq!(
            service.merge_candidate().unwrap().metadata().message,
            b"--merge-method"
        );

        let mut arguments = merge_arguments();
        arguments.extend([
            "--workflow-publish-checks".into(),
            "--workflow-principal".into(),
            "55".repeat(16),
            "--workflow-merge-method".into(),
            "squash".into(),
        ]);
        let service = parse_server(&arguments).unwrap().workflow_service.unwrap();
        assert_ne!(
            service.publisher().unwrap(),
            service.merge_candidate().unwrap().principal()
        );
        assert_eq!(
            service.merge_candidate().unwrap().style(),
            fgit_forge::preparation::MergeCommitStyle::Squash
        );
    }

    #[test]
    fn merge_service_refuses_partial_scope_or_implicit_identity() {
        for flag in [
            "--expected-incarnation",
            "--workflow-pull-request",
            "--workflow-merge-candidate-ref",
            "--workflow-merge-principal",
            "--workflow-merge-author",
            "--workflow-merge-committer",
            "--workflow-merge-timestamp",
            "--workflow-merge-message",
        ] {
            let mut arguments = merge_arguments();
            let at = arguments.iter().position(|value| value == flag).unwrap();
            arguments.drain(at..at + 2);
            assert!(parse_server(&arguments).is_err(), "{flag}");
        }
        let mut arguments = merge_arguments();
        let at = arguments
            .iter()
            .position(|value| value == "--workflow-merge-candidate-ref")
            .unwrap();
        arguments[at + 1] = "refs/heads/main".into();
        assert!(parse_server(&arguments).is_err());
        let mut arguments = merge_arguments();
        arguments.extend(["--workflow-merge-method".into(), "rebase".into()]);
        assert!(parse_server(&arguments).is_err());
    }

    #[test]
    fn server_requires_separate_execution_trust_and_reloadable_credentials() {
        let mut arguments = server_arguments();
        arguments.retain(|argument| argument != "--workflow-trusted-local");
        assert!(
            parse_server(&arguments)
                .err()
                .unwrap()
                .contains("--workflow-trusted-local")
        );

        let mut arguments = server_arguments();
        let at = arguments
            .iter()
            .position(|argument| argument == "--credentials-file")
            .unwrap();
        arguments.drain(at..at + 2);
        arguments.extend([
            "--token-file".into(),
            "token".into(),
            "--principal".into(),
            "33".repeat(16),
        ]);
        assert!(
            parse_server(&arguments)
                .err()
                .unwrap()
                .contains("--credentials-file")
        );
    }

    #[test]
    fn server_workflow_configuration_preserves_independent_endpoint_grants() {
        let arguments = server_arguments();
        for enabled in [
            None,
            Some("--allow-receive"),
            Some("--allow-issues"),
            Some("--allow-outcomes"),
            Some("--allow-pulls"),
            Some("--allow-source"),
            Some("--allow-protection"),
        ] {
            let mut selected = arguments.clone();
            if let Some(flag) = enabled {
                selected.push(flag.into());
            }
            let options = parse_server(&selected).unwrap();
            assert!(matches!(
                options.credentials,
                CredentialInput::Reloadable(_)
            ));
            assert!(options.workflow_service.unwrap().publisher().is_none());
            assert!(options.stop_file.is_some());
            assert!(options.index_maintenance.is_none());
            assert_eq!(options.allow_receive, enabled == Some("--allow-receive"));
            assert_eq!(options.allow_issues, enabled == Some("--allow-issues"));
            assert_eq!(options.allow_outcomes, enabled == Some("--allow-outcomes"));
            assert_eq!(options.allow_pulls, enabled == Some("--allow-pulls"));
            assert_eq!(options.allow_source, enabled == Some("--allow-source"));
            assert_eq!(
                options.allow_protection,
                enabled == Some("--allow-protection")
            );
            assert!(options.config.http_lfs_root().is_none());
            assert!(options.config.workflow_artifact_root().is_none());
        }
    }

    #[test]
    fn server_workflow_requires_owned_continuous_drain_and_finite_attempts() {
        for missing in ["--continuous", "--stop-file"] {
            let mut arguments = server_arguments();
            let at = arguments
                .iter()
                .position(|argument| argument == missing)
                .unwrap();
            let count = if missing == "--stop-file" { 2 } else { 1 };
            arguments.drain(at..at + count);
            assert!(parse_server(&arguments).is_err(), "{missing}");
        }
        let mut bounded = server_arguments();
        bounded.retain(|argument| argument != "--continuous");
        let at = bounded
            .iter()
            .position(|argument| argument == "--stop-file")
            .unwrap();
        bounded.drain(at..at + 2);
        assert!(parse_server(&bounded).is_err());

        for (name, value) in [
            ("--max-sessions", "2"),
            ("--idle-timeout-secs", "1"),
            ("--max-in-flight", "17"),
            ("--workflow-attempt-timeout-secs", "0"),
            ("--workflow-attempt-timeout-secs", "3601"),
            ("--workflow-interval-ms", "60001"),
        ] {
            let mut arguments = server_arguments();
            arguments.extend([name.into(), value.into()]);
            assert!(parse_server(&arguments).is_err(), "{name}={value}");
        }
    }

    #[test]
    fn server_workflow_inputs_are_repeated_bounded_and_unique() {
        let mut duplicate = server_arguments();
        duplicate.extend(["--workflow-input".into(), "ci".into()]);
        assert!(parse_server(&duplicate).is_err());

        let mut arguments = server_arguments();
        for index in 1..64 {
            arguments.extend(["--workflow-input".into(), format!("input{index}")]);
        }
        assert_eq!(
            parse_server(&arguments)
                .unwrap()
                .workflow_service
                .unwrap()
                .inputs()
                .len(),
            64
        );
        arguments.extend(["--workflow-input".into(), "overflow".into()]);
        assert!(
            parse_server(&arguments)
                .err()
                .unwrap()
                .contains("at most 64 inputs")
        );
    }

    #[test]
    fn server_can_configure_workflow_and_index_workers_together() {
        let mut arguments = server_arguments();
        arguments.extend(
            [
                "--allow-source",
                "--index-state-dir",
                "/private/index",
                "--index-state",
                "init",
                "--index-profile",
                "lexical",
                "--index-format",
                "sha256",
                "--index-ref",
                "refs/heads/main",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let options = parse_server(&arguments).unwrap();
        assert!(options.workflow_service.is_some());
        assert!(options.index_maintenance.is_some());
        assert!(options.allow_source);
        assert!(!options.allow_receive);
    }

    #[test]
    fn transport_trust_does_not_implicitly_authorize_running_repository_scripts() {
        assert!(parse(&BTreeMap::new(), Vec::new()).unwrap().is_none());
        for missing in [
            "--workflow-trusted-local",
            "--credentials-file",
            "--continuous",
            "--stop-file",
            "--workflow-ref",
            "--workflow-format",
            "--workflow-dir",
            "--workflow-run-parent",
        ] {
            let mut flags = flags();
            flags.remove(missing);
            assert!(parse(&flags, inputs()).is_err(), "{missing}");
        }
        assert!(parse(&flags(), Vec::new()).is_err());
        let config = parse(&flags(), inputs()).unwrap().unwrap();
        assert_eq!(config.format(), GitHashAlgorithm::Sha256);
        assert!(config.publisher().is_none());
        assert_eq!(config.attempt_timeout(), Duration::from_secs(300));
        assert_eq!(config.interval(), Duration::from_secs(1));
    }

    #[test]
    fn publisher_and_incarnation_are_explicit_and_no_network_scope_is_implied() {
        let publisher = "11".repeat(16);
        let incarnation = "22".repeat(16);
        let mut flags = flags();
        flags.insert("--workflow-publish-checks", "");
        assert!(parse(&flags, inputs()).is_err());
        flags.insert("--workflow-principal", &publisher);
        assert!(parse(&flags, inputs()).is_err());
        flags.insert("--expected-incarnation", &incarnation);
        let config = parse(&flags, inputs()).unwrap().unwrap();
        assert_eq!(
            config.publisher(),
            Some(PrincipalId::from_hex(&publisher).unwrap())
        );
        assert!(!flags.contains_key("--allow-source"));
        assert!(!flags.contains_key("--allow-receive"));
        flags.remove("--workflow-publish-checks");
        assert!(parse(&flags, inputs()).is_err());
    }

    #[test]
    fn finite_attempts_valid_sources_and_explicit_log_custody_are_required() {
        for (name, value) in [
            ("--workflow-attempt-timeout-secs", "0"),
            ("--workflow-attempt-timeout-secs", "3601"),
            ("--workflow-interval-ms", "9"),
            ("--workflow-interval-ms", "60001"),
            ("--workflow-pull-request", "0"),
            ("--workflow-ref", "refs/tags/v1"),
            ("--workflow-format", "sha512"),
            ("--workflow-run-parent", "relative"),
        ] {
            let mut flags = flags();
            flags.insert(name, value);
            assert!(parse(&flags, inputs()).is_err(), "{name}={value}");
        }
        let mut flags = flags();
        flags.insert("--workflow-artifact-logs", "");
        assert!(parse(&flags, inputs()).is_err());
        flags.insert("--artifact-root", "/private/artifacts");
        assert!(parse(&flags, inputs()).is_ok());
    }
}
