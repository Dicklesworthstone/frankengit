//! Explicit merge selection layered over the shared workflow argument parser.
//! Extra fields are consumed only as option names, never from another value.
use super::*;
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::MergeCommitStyle;

const USAGE: &str =
    "usage: fg workflow run-merge-candidate <storage-root> <tenant-id> <repository-id> <target-ref>
  --trusted-local --bundle <stable-local-file> --candidate-commit <reviewed-merge-oid>
  --expected-commit <target-before-oid> --source-ref <incoming-branch>
  --expected-source <incoming-tip-oid> --merge-base <common-ancestor-oid>
  --workflow <candidate-path> --input <top-level-path> [--input <path> ...]
  --run-id <32-lowercase-hex> --run-parent <absolute-private-0700-directory>
  [--method merge-commit|squash]
  [--object-format sha1|sha256] [--expected-head <snapshot-token>]
  [--expected-incarnation <id>] [--ref-hex]
  [--source-ref-hex <hex> instead of --source-ref]
  [--workflow-hex <hex> instead of --workflow] [--input-hex <hex> instead of --input]
  [--artifact-root <absolute-private-directory> --artifact <workflow:job:output> ...]
  [--artifact-hex <workflow-path-hex:job:output-path-hex> ...]
  [--max-artifact-mib <1..64>] [--max-artifact-total-mib <1..512>]
  [--artifact-input <workflow:consumer:producer:output:destination> ...]
  [--artifact-input-hex <workflow-hex:consumer:producer:output-hex:destination-hex> ...]
  [--max-artifact-input-total-mib <1..512>]

Linux trusted-local execution only: review and trust the ACTUAL candidate's
workflow/scripts. They run with host-user privileges, not in a hostile sandbox.
Both branches are pinned under one authority snapshot. The default merge-commit
method requires ordered target/source parents. Explicit --method squash requires
one target parent. BOTH profiles require the exact target/source prerequisites
and verify both original histories and common-base ancestry. No method fallback.

All inputs and workflow scripts come from the verified merged tree. No objects
are staged, no temporary ref is created, no PR approval or canonical check is
published. Optional artifact capture binds the exact merged input and both
branch selections and the actual parent shape; durable output custody does not authorize a check or cache reuse.
Explicit artifact inputs deliver verified current-run outputs from successful
direct dependencies into .fgit-artifacts/ before the consumer's first script.
Delivery shares its own cumulative byte limit. See fg workflow run --help.
Source-only and canonical commands do not accept these merge flags.

The usual workflow journal, fresh job copies, resource limits, no-replay rule,
post-shutdown JSON result and exit codes apply. An occupied run ID refuses;
a missing report after interruption does not prove that no command ran.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["run-merge-candidate", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let (options, merge, style) = parse(args)?;
    #[cfg(target_os = "linux")]
    {
        super::execute(options, Some((merge, style)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, merge, style);
        Err(
            "trusted merge workflow execution requires Linux; no alternative runner is selected"
                .into(),
        )
    }
}

fn parse(args: &[String]) -> Result<(Options, NativeMerge, MergeCommitStyle), String> {
    if args.len() < 5 || args[0] != "run-merge-candidate" {
        return Err(USAGE.into());
    }
    if args.len() > 2110
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("merge workflow arguments exceed the bounded profile".into());
    }
    let mut common = args[..5].to_vec();
    common[0] = "run-candidate".into();
    let mut fields = BTreeMap::new();
    let mut cursor = 5;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if matches!(flag, "--trusted-local" | "--ref-hex") {
            common.push(flag.to_owned());
            continue;
        }
        // Consume the value together with its option. A value that happens to
        // spell --source-ref is data, not a second opportunity to select a ref.
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if matches!(
            flag,
            "--source-ref" | "--source-ref-hex" | "--expected-source" | "--merge-base" | "--method"
        ) {
            if fields.insert(flag, value.as_str()).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else {
            common.push(flag.to_owned());
            common.push(value.clone());
        }
    }
    let style = match fields.get("--method").copied().unwrap_or("merge-commit") {
        "merge-commit" => MergeCommitStyle::TwoParent,
        "squash" => MergeCommitStyle::Squash,
        _ => return Err("workflow method must be merge-commit or squash".into()),
    };
    let options = super::parse(&common)?;
    let source = match (fields.get("--source-ref"), fields.get("--source-ref-hex")) {
        (Some(text), None) => text.as_bytes().to_vec(),
        (None, Some(text)) => unhex(text, 4096)?,
        _ => return Err("supply exactly one of --source-ref and --source-ref-hex".into()),
    };
    if !source.starts_with(b"refs/heads/") || source.len() > 4096 {
        return Err("merge source must be a bounded full branch reference".into());
    }
    let source_ref = RefName::try_new(&source).map_err(|_| "invalid source reference")?;
    if source_ref == options.reference {
        return Err("merge requires distinct source and target branches".into());
    }
    let source_tip = native_oid(
        fields
            .get("--expected-source")
            .ok_or("missing --expected-source")?,
        options.format,
    )?;
    let base_tip = native_oid(
        fields.get("--merge-base").ok_or("missing --merge-base")?,
        options.format,
    )?;
    let candidate = options
        .candidate
        .as_ref()
        .ok_or("missing candidate inputs")?;
    let merge = NativeMerge {
        target_ref: options.reference.clone(),
        target_tip_before: candidate.base,
        source_ref,
        source_tip,
        base_tip,
        merge_commit: candidate.commit,
    };
    merge
        .validate()
        .map_err(|_| "invalid native merge coordinates")?;
    Ok((options, merge, style))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(format: GitHashAlgorithm) -> Vec<String> {
        vec![
            "run-merge-candidate".into(),
            "not-opened".into(),
            "11".repeat(16),
            "22".repeat(16),
            "refs/heads/main".into(),
            "--trusted-local".into(),
            "--workflow".into(),
            "ci/run.yml".into(),
            "--input".into(),
            "ci".into(),
            "--run-id".into(),
            "33".repeat(16),
            "--run-parent".into(),
            std::env::temp_dir().to_string_lossy().into_owned(),
            "--bundle".into(),
            "not-opened.bundle".into(),
            "--object-format".into(),
            format.as_str().into(),
            "--expected-commit".into(),
            "a".repeat(format.digest_len() * 2),
            "--candidate-commit".into(),
            "b".repeat(format.digest_len() * 2),
            "--source-ref".into(),
            "refs/heads/topic".into(),
            "--expected-source".into(),
            "c".repeat(format.digest_len() * 2),
            "--merge-base".into(),
            "d".repeat(format.digest_len() * 2),
        ]
    }
    #[test]
    fn exact_merge_coordinates_and_byte_refs_parse_without_io_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let input = args(format);
            let (options, merge, style) = parse(&input).unwrap();
            assert_eq!(style, MergeCommitStyle::TwoParent);
            assert_eq!(
                merge.target_tip_before,
                options.candidate.as_ref().unwrap().base
            );
            assert_eq!(
                merge.merge_commit,
                options.candidate.as_ref().unwrap().commit
            );
            assert_ne!(merge.source_tip, merge.target_tip_before);
            let mut bytes = input.clone();
            let at = bytes.iter().position(|s| s == "--source-ref").unwrap();
            bytes[at] = "--source-ref-hex".into();
            bytes[at + 1] = "726566732f68656164732fff".into();
            assert_eq!(
                parse(&bytes).unwrap().1.source_ref.as_bytes(),
                b"refs/heads/\xff"
            );
        }
    }
    #[test]
    fn no_implicit_parents_trust_or_force_and_no_merge_flags_in_other_modes() {
        let good = args(GitHashAlgorithm::Sha1);
        for flag in [
            "--source-ref",
            "--expected-source",
            "--merge-base",
            "--expected-commit",
            "--candidate-commit",
            "--bundle",
        ] {
            let mut missing = good.clone();
            let at = missing.iter().position(|s| s == flag).unwrap();
            missing.drain(at..at + 2);
            assert!(parse(&missing).is_err());
        }
        for extras in [
            vec!["--expected-source", "abcd"],
            vec!["--force", "true"],
            vec!["--source-ref-hex", "726566732f68656164732fff"],
            vec!["--principal", "admin"],
        ] {
            let mut input = good.clone();
            input.extend(extras.into_iter().map(str::to_owned));
            assert!(parse(&input).is_err());
        }
        let mut untrusted = good.clone();
        untrusted.remove(5);
        assert!(parse(&untrusted).is_err());
        let mut same = good.clone();
        let at = same.iter().position(|s| s == "--source-ref").unwrap();
        same[at + 1] = "refs/heads/main".into();
        assert!(parse(&same).is_err());
        for mode in ["run", "run-candidate"] {
            let mut input = good.clone();
            input[0] = mode.into();
            assert!(super::super::parse(&input).is_err());
        }
    }
    #[test]
    fn merge_flag_spelling_in_an_argument_value_does_not_change_selection() {
        let mut input = args(GitHashAlgorithm::Sha1);
        let at = input.iter().position(|s| s == "--bundle").unwrap();
        input[at + 1] = "--source-ref".into();
        let (options, merge, _) = parse(&input).unwrap();
        assert_eq!(
            options.candidate.unwrap().bundle,
            PathBuf::from("--source-ref")
        );
        assert_eq!(merge.source_ref.as_bytes(), b"refs/heads/topic");
        let at = input.iter().position(|s| s == "--expected-source").unwrap();
        input[at + 1] = "a".repeat(64);
        assert!(parse(&input).is_err());
    }
    #[test]
    fn method_is_explicit_bounded_and_never_inferred_from_argument_values() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            for (method, style) in [
                ("merge-commit", MergeCommitStyle::TwoParent),
                ("squash", MergeCommitStyle::Squash),
            ] {
                let mut input = args(format);
                input.extend(["--method".into(), method.into()]);
                assert_eq!(parse(&input).unwrap().2, style);
                input.extend(["--method".into(), method.into()]);
                assert!(parse(&input).is_err());
            }
            for method in [
                "",
                "rebase",
                "fast-forward-only",
                "Squash",
                "squash\n",
                "auto",
            ] {
                let mut input = args(format);
                input.extend(["--method".into(), method.into()]);
                assert!(parse(&input).is_err());
            }
            let mut input = args(format);
            input.push("--method".into());
            assert!(parse(&input).is_err());
            let mut input = args(format);
            let at = input.iter().position(|s| s == "--bundle").unwrap();
            input[at + 1] = "--method".into();
            assert_eq!(parse(&input).unwrap().2, MergeCommitStyle::TwoParent);
        }
    }
    #[test]
    fn squash_does_not_relax_branch_or_trust_preconditions() {
        let mut input = args(GitHashAlgorithm::Sha256);
        input.extend(["--method".into(), "squash".into()]);
        for flag in [
            "--expected-source",
            "--source-ref",
            "--merge-base",
            "--expected-commit",
        ] {
            let mut bad = input.clone();
            let at = bad.iter().position(|s| s == flag).unwrap();
            bad.drain(at..at + 2);
            assert!(parse(&bad).is_err());
        }
        let mut bad = input.clone();
        bad.retain(|s| s != "--trusted-local");
        assert!(parse(&bad).is_err());
        let mut ordinary = input;
        ordinary[0] = "run-candidate".into();
        assert!(super::super::parse(&ordinary).is_err());
    }
}
