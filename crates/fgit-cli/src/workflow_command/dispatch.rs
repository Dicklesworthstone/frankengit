//! Explicit local batch dispatch. Matching an event is not proof it happened.

use super::{Options, parse};
use std::io::Write;

const USAGE: &str = "usage: fg workflow dispatch <storage-root> <tenant-id> <repository-id> <ref>
  --trusted-local --event push|workflow_dispatch
  --workflow <repository-directory> --input <top-level-path> [--input ...]
  --run-parent <absolute-private-directory> --run-id <32-lowercase-hex>
  --expected-head <snapshot-token> --expected-commit <native-oid>
  [--expected-incarnation <id>] [--object-format sha1|sha256]
  [--ref-hex] [--workflow-hex <hex> instead of --workflow] [--input-hex <hex>]

Unlike workflow run, --workflow selects a directory (usually .github/workflows).
Discover its direct .yml/.yaml children from ONE pinned canonical commit, compile
all of them, and execute those declaring the selected event. All selected code
must be trusted with your host-user privileges. This is NOT a hostile-code sandbox.
The event is an operator-supplied selection key, not evidence of an accepted push.
No unattended trigger, automatic retry, secret injection or green check is created.

At most 32 definitions, 1 MiB workflow text, 128 selected jobs and 512 selected
steps. Workflows share the native 600-second run and 16 MiB captured-output budgets.
Ordinary job failure does not suppress independent workflows. Lost containment,
cancellation, exhausted time/output, or infrastructure failure stops later work.

The parent must already be a nonsymlink 0700 directory. An exclusive
 dispatch-<run-id>/dispatch.json records the plan BEFORE any job. Each selected
child uses the existing workflow-<derived-id> marker, execution fence, proposal
journal and report. Occupied batch IDs always refuse; an interrupted dispatch
is NOT automatically resumed. Inspect child reports and use workflow recover or
workflow publish on their original directories; do not erase/replay the batch.
No matching triggers yields an explicit zero-run report, not a passing check.

Exit 0: selected runs succeeded (possibly zero); 1: non-green/stopped dispatch;
2: invalid request, infrastructure, output or node-close failure.";

fn options(args: &[String]) -> Result<(Options, String), String> {
    if args.first().map(String::as_str) != Some("dispatch") || args.len() < 5 {
        return Err(USAGE.into());
    }
    if args.len() > 2102
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("dispatch arguments exceed the bounded profile".into());
    }
    // Preserve the ordinary parser's input, byte-name, trust and size rules.
    // Consume only option positions; an option-looking path is still a value.
    let mut ordinary = args[..5].to_vec();
    ordinary[0] = "run".into();
    let mut event = None;
    let mut cursor = 5;
    while cursor < args.len() {
        let flag = &args[cursor];
        if flag == "--event" {
            let value = args.get(cursor + 1).ok_or("missing --event value")?;
            if event.is_some() || !matches!(value.as_str(), "push" | "workflow_dispatch") {
                return Err("supply one --event: push or workflow_dispatch".into());
            }
            event = Some(value.clone());
            cursor += 2;
        } else {
            ordinary.push(flag.clone());
            cursor += 1;
            if !matches!(flag.as_str(), "--trusted-local" | "--ref-hex") {
                if let Some(value) = args.get(cursor) {
                    ordinary.push(value.clone());
                    cursor += 1;
                }
            }
        }
    }
    let parsed = parse(&ordinary)?;
    if parsed.head.is_none() || parsed.commit.is_none() {
        return Err(
            "dispatch requires --expected-head and --expected-commit; no moving-source discovery"
                .into(),
        );
    }
    Ok((parsed, event.ok_or("--event is mandatory")?))
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["dispatch", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let (options, event) = options(args)?;
    #[cfg(target_os = "linux")]
    {
        execute(options, &event)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, event);
        Err("trusted workflow dispatch requires Linux; no alternative runner is selected".into())
    }
}

#[cfg(target_os = "linux")]
fn execute(options: Options, event: &str) -> Result<u8, String> {
    use fgit_node::{NodeConfig, OneNode};
    let expected = (
        options.head.ok_or("missing dispatch head")?,
        options.commit.ok_or("missing dispatch commit")?,
    );
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage, options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    let operation = (|| {
        if options
            .incarnation
            .is_some_and(|id| id != node.repository_incarnation_id())
        {
            return Err("repository incarnation changed; no dispatch started".to_owned());
        }
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        node.runtime()
            .block_on(node.dispatch_trusted_workflows_in(
                &request,
                &options.reference,
                &options.workflow,
                event,
                options.run_id,
                &options.parent,
                &options.inputs,
                expected,
                Default::default(),
            ))
            .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match operation {
        Ok(report) => finish(
            &mut std::io::stdout().lock(),
            &report.to_json(),
            report.succeeded(),
            cleanup.as_deref(),
        )
        .map_err(|e| {
            format!(
                "{e}; dispatch report remains at {}; do not replay the batch",
                report.run_directory.join("report.json").display()
            )
        }),
        Err(error) => Err(format!(
            "{error}{}; inspect any existing dispatch/child journals before retrying; an error is not proof that no job ran",
            cleanup.map_or_else(String::new, |e| format!("; node shutdown also failed: {e}"))
        )),
    }
}

#[cfg(any(target_os = "linux", test))]
fn finish(
    output: &mut impl Write,
    report: &str,
    succeeded: bool,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let error = cleanup.map_or_else(|| "null".to_owned(), super::quote);
    writeln!(output, "{{\"type\":\"workflow_dispatch_result\",\"schema_version\":1,\"node_closed\":{},\"node_cleanup_error\":{error},\"dispatch\":{report}}}", cleanup.is_none())
        .and_then(|()| output.flush()).map_err(|e| format!("dispatch receipt output incomplete: {e}"))?;
    Ok(if cleanup.is_some() {
        2
    } else {
        u8::from(!succeeded)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        [
            "dispatch",
            "/not-opened",
            &"11".repeat(16),
            &"22".repeat(16),
            "refs/heads/main",
            "--trusted-local",
            "--event",
            "push",
            "--workflow",
            ".github/workflows",
            "--input",
            ".github",
            "--run-parent",
            "/private",
            "--run-id",
            &"33".repeat(16),
            "--expected-head",
            &format!("alg:2:{}", "44".repeat(32)),
            "--expected-commit",
            &"55".repeat(20),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn dispatch_preserves_explicit_trust_source_pins_and_directory_selection() {
        let (parsed, event) = options(&args()).unwrap();
        assert_eq!(event, "push");
        assert_eq!(parsed.workflow, b".github/workflows");
        assert_eq!(parsed.inputs, [b".github".to_vec()]);
        assert!(parsed.head.is_some() && parsed.commit.is_some() && parsed.candidate.is_none());
        let mut raw = args();
        raw[7] = "workflow_dispatch".into();
        raw[8] = "--workflow-hex".into();
        raw[9] = "2e6769746875622fff".into();
        assert_eq!(options(&raw).unwrap().0.workflow, b".github/\xff");
    }

    #[test]
    fn dispatch_refuses_ambiguous_events_unpinned_sources_and_candidate_modes() {
        for flag in ["--event", "--expected-head", "--expected-commit"] {
            let mut missing = args();
            let at = missing.iter().position(|s| s == flag).unwrap();
            missing.drain(at..at + 2);
            assert!(options(&missing).is_err());
        }
        let mut untrusted = args();
        untrusted.remove(5);
        assert!(options(&untrusted).is_err());
        for extra in [
            vec!["--event", "push"],
            vec!["--event", "pull_request"],
            vec!["--bundle", "candidate.bundle"],
            vec!["--force"],
            vec!["--input", ".github"],
            vec!["--input", "../host"],
        ] {
            let mut input = args();
            input.extend(extra.into_iter().map(str::to_owned));
            assert!(options(&input).is_err());
        }
        for event in ["Push", "schedule", "push\n", ""] {
            let mut input = args();
            input[7] = event.into();
            assert!(options(&input).is_err());
        }
    }

    #[test]
    fn option_looking_values_do_not_become_dispatch_controls() {
        let mut input = args();
        input[13] = "--event".into();
        assert!(
            options(&input).is_err(),
            "a run-parent value is not another event flag"
        );
        let mut input = args();
        input[9] = "--event".into();
        input[11] = "--event".into();
        let (parsed, event) = options(&input).unwrap();
        assert_eq!(event, "push");
        assert_eq!(parsed.workflow, b"--event");
    }

    #[test]
    fn non_green_cleanup_and_output_loss_never_report_success() {
        let mut output = Vec::new();
        assert_eq!(finish(&mut output, "{}", false, None).unwrap(), 1);
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("\"dispatch\":{}")
        );
        let mut output = Vec::new();
        assert_eq!(
            finish(&mut output, "{}", true, Some("close\nfailed")).unwrap(),
            2
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("\"node_closed\":false")
        );
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(finish(&mut Broken, "{}", true, None).is_err());
    }
}
