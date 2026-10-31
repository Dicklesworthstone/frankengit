//! Prerequisite-scoped selection for the existing private-file streaming owner.

use super::{Options, parse_full};
use fgit_types::{GitOid, RefName};
use std::collections::BTreeSet;

pub(super) const USAGE: &str =
    "usage: fg bundle sync-export <storage-root> <tenant-id> <repository-id> <new-bundle-file>
  --streaming --trusted-local [--object-format sha1|sha256]
  --ref <refs/name>... --prerequisite <commit-oid>...
  [--max-output-mib N] [--max-expanded-mib N] [--max-object-mib N]
  [--max-blob-mib N]
  [--max-objects N] [--max-refs N] [--max-edges N]
  [--max-compression-work N] [--timeout-secs N]

Export exactly the named visible refs, omitting the complete verified history
of explicit native commit prerequisites. The receiver must already possess that
history. A prerequisite must belong to the current visible graph; a retained
or hidden object alone never authorizes export. Maximum 64 refs and 64 unique
prerequisites. The source head identifies the snapshot selected at the start.

Streaming retains bounded native metadata, a blob input chunk and compressor
state plus bounded identity/edge metadata. Output and expanded-byte defaults
are 128 MiB, with independent ceilings of 16384 MiB. Buffered object default
and ceiling are 32 MiB; the separate blob allowance defaults to 32 MiB and can
be raised through 16384 MiB without increasing metadata or aggregate limits.
Object count defaults to 100000 (ceiling 1000000), ref-header count to 4096
(ceiling 1000000), graph edges to 1000000 (ceiling 8000000), compression work
to 1000000000 (ceiling 1000000000000). Timeout is 1..3600 seconds, default 300,
narrowed by an explicit global timeout. Discovery and omitted-history validation
are bounded too; a tiny incremental pack does not imply tiny source work.
Visible source discovery also retains the native reader's 4000000-edge ceiling.

The output uses the full streaming export's private-file lifecycle: complete
native stream, node shutdown, file sync, create-only publication and parent sync.
An existing destination is never replaced. The Unix parent must already exist,
contain no symlink components, and stay under the local operator's control.
Cancellation is cooperative and cannot interrupt an operating-system call.
An error after publication reports the visible file; preserve that artifact.
The receipt includes reference_count, prerequisite_count, external_object_count,
native pack checksum and bundle SHA-256. This transfers Git source, not authority
or forge state. Existing sync-import retains its 128 MiB input limit.
Exit 0: complete locally durable export; 2: input/source/output/cleanup failure.";

#[derive(Debug)]
pub(super) struct Selection {
    pub(super) references: Vec<RefName>,
    pub(super) prerequisites: Vec<GitOid>,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 7
        || args.len() > 320
        || args.first().map(String::as_str) != Some("sync-export")
        || args
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        || args
            .iter()
            .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()))
            .is_none_or(|bytes| bytes > 64 * 1024)
    {
        return Err(USAGE.into());
    }
    let mut common = args[..5].to_vec();
    common[0] = "export".into();
    let mut names = Vec::new();
    let mut prerequisites = Vec::new();
    let mut at = 5;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        if matches!(flag, "--ref" | "--prerequisite") {
            let value = args
                .get(at)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1;
            let target = if flag == "--ref" {
                &mut names
            } else {
                &mut prerequisites
            };
            if target.len() == 64 {
                return Err(format!("too many {flag} values"));
            }
            target.push(value.as_str());
        } else {
            common.push(flag.into());
            if !matches!(flag, "--streaming" | "--trusted-local") {
                common.push(
                    args.get(at)
                        .ok_or_else(|| format!("missing value for {flag}"))?
                        .clone(),
                );
                at += 1;
            }
        }
    }
    if names.is_empty() || prerequisites.is_empty() {
        return Err("streaming sync-export requires refs and prerequisite commits".into());
    }
    // The full profile owns every byte/work/timeout option and both explicit
    // consent switches. Selection adds no alternate resource policy.
    let mut options = parse_full(&common)?;
    let mut seen_names = BTreeSet::new();
    let mut references = Vec::new();
    for name in names {
        let name = RefName::try_new(name.as_bytes()).map_err(|error| error.to_string())?;
        if !name.as_bytes().starts_with(b"refs/") || !seen_names.insert(name.clone()) {
            return Err("a unique full refs/ name is required".into());
        }
        references.push(name);
    }
    let mut seen_ids = BTreeSet::new();
    let mut ids = Vec::new();
    for text in prerequisites {
        let id = GitOid::from_hex(options.format, text).map_err(|error| error.to_string())?;
        if id.is_zero() || !seen_ids.insert(id) {
            return Err("a unique nonzero prerequisite commit is required".into());
        }
        ids.push(id);
    }
    options.incremental = Some(Selection {
        references,
        prerequisites: ids,
    });
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::GitHashAlgorithm;
    use std::time::Duration;

    fn args(format: GitHashAlgorithm, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "sync-export".into(),
            "/storage".into(),
            "11".repeat(16),
            "22".repeat(16),
            "/output/increment.bundle".into(),
            "--streaming".into(),
            "--trusted-local".into(),
            "--object-format".into(),
            format.as_str().into(),
            "--ref".into(),
            "refs/heads/main".into(),
            "--prerequisite".into(),
            "33".repeat(format.digest_len()),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        args
    }

    #[test]
    fn both_hash_domains_use_the_existing_stream_limits_and_typed_selection() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let options = super::super::parse(&args(format, &[])).unwrap();
            let selection = options.incremental.as_ref().unwrap();
            assert_eq!(options.format, format);
            assert_eq!(selection.references[0].as_bytes(), b"refs/heads/main");
            assert_eq!(selection.prerequisites[0].algorithm(), format);
            assert_eq!(options.query.timeout, Duration::from_secs(300));
            assert_eq!(options.query.limits.pack.max_entries, 100_000);
            assert_eq!(options.query.limits.pack.max_object_bytes, 32 * 1024 * 1024);
            assert_eq!(
                options.query.limits.max_streamed_blob_bytes,
                32 * 1024 * 1024
            );
            assert_eq!(options.query.limits.pack.max_input_bytes, 128 * 1024 * 1024);
            let expanded = parse(&args(
                format,
                &[
                    "--max-output-mib",
                    "16384",
                    "--max-expanded-mib",
                    "4096",
                    "--max-object-mib",
                    "1",
                    "--max-blob-mib",
                    "16384",
                    "--max-compression-work",
                    "7",
                    "--timeout-secs",
                    "12",
                ],
            ))
            .unwrap();
            assert_eq!(
                expanded.query.limits.envelope.max_bundle_bytes as u64,
                16384 * 1024 * 1024
            );
            assert_eq!(
                expanded.query.limits.pack.max_total_expanded_bytes as u64,
                4096 * 1024 * 1024
            );
            assert_eq!(expanded.query.limits.pack.max_object_bytes, 1024 * 1024);
            assert_eq!(
                expanded.query.limits.max_streamed_blob_bytes as u64,
                16384 * 1024 * 1024
            );
            assert_eq!(expanded.query.limits.max_compression_work, 7);
            assert_eq!(expanded.query.timeout, Duration::from_secs(12));
        }
    }

    #[test]
    fn invalid_frontiers_and_inapplicable_flags_refuse_before_source_access() {
        let format = GitHashAlgorithm::Sha1;
        for extra in [
            vec!["--ref", "refs/heads/main"],
            vec!["--ref", "main"],
            vec!["--prerequisite", "3333333333333333333333333333333333333333"],
            vec!["--prerequisite", "0000000000000000000000000000000000000000"],
            vec!["--prerequisite", "not-an-oid"],
            vec!["--allow-ref-updates"],
            vec!["--expect", "refs/heads/main=absent"],
            vec!["--max-output-mib", "16385"],
            vec!["--max-object-mib", "33"],
            vec!["--max-blob-mib", "16385"],
            vec!["--max-blob-mib", "0"],
            vec!["--max-blob-mib", "1", "--max-blob-mib", "2"],
            vec!["--max-objects", "0"],
            vec!["--streaming"],
            vec!["--timeout-secs", "0"],
        ] {
            assert!(parse(&args(format, &extra)).is_err(), "{extra:?}");
        }
        let mut input = args(format, &[]);
        input.pop();
        assert!(parse(&input).is_err());
        let mut input = args(format, &[]);
        input.retain(|arg| arg != "--trusted-local");
        assert!(parse(&input).is_err());
        let mut input = args(format, &[]);
        input.retain(|arg| arg != "--streaming");
        assert!(parse(&input).is_err());
        let mut input = args(format, &[]);
        input[12] = "33".repeat(32);
        assert!(parse(&input).is_err());
        let mut input = args(format, &[]);
        input.truncate(9);
        assert!(parse(&input).is_err());
    }

    #[test]
    fn each_frontier_count_has_a_permitted_boundary_and_refused_successor() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut input = args(format, &[]);
            for number in 1..64 {
                input.extend(["--ref".into(), format!("refs/heads/topic-{number}")]);
                input.extend([
                    "--prerequisite".into(),
                    format!("{number:0width$x}", width = format.digest_len() * 2),
                ]);
            }
            let options = parse(&input).unwrap();
            let selection = options.incremental.unwrap();
            assert_eq!(selection.references.len(), 64);
            assert_eq!(selection.prerequisites.len(), 64);
            let mut too_many_names = input.clone();
            too_many_names.extend(["--ref".into(), "refs/heads/extra".into()]);
            assert!(parse(&too_many_names).is_err());
            input.extend([
                "--prerequisite".into(),
                format!("{:0width$x}", 64, width = format.digest_len() * 2),
            ]);
            assert!(parse(&input).is_err());
        }
    }

    #[test]
    fn help_reports_prerequisites_publication_and_the_import_limit() {
        let mut output = Vec::new();
        super::super::run_with_output(
            &["sync-export".into(), "--streaming".into(), "--help".into()],
            &mut output,
        )
        .unwrap();
        let help = String::from_utf8(output).unwrap();
        for expected in [
            "--prerequisite",
            "create-only",
            "32 MiB",
            "128 MiB input limit",
        ] {
            assert!(help.contains(expected), "{help}");
        }
    }
}
