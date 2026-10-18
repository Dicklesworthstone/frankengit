//! Validated offline-verifier profiles. No input or scratch path is opened here.
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use fgit_node::source_retrieval::integrity::bundle_verify::{
    BundleExpectations, BundleVerifyLimits, MAX_EXPECTED_REFS,
};
use fgit_types::{GitHashAlgorithm, RefName};

use super::{USAGE, anchors};

#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) path: PathBuf,
    pub(crate) limits: BundleVerifyLimits,
    pub(crate) timeout: Duration,
    pub(crate) expectations: Option<BundleExpectations>,
    pub(crate) recovery_head: Option<RefName>,
    pub(crate) scratch_directory: Option<PathBuf>,
}
fn number(value: &str, maximum: usize) -> Result<usize, String> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("bundle verify limits require positive canonical decimal integers".into());
    }
    let value = value
        .parse::<usize>()
        .map_err(|_| "bundle verify limit overflow")?;
    if value > maximum {
        return Err("bundle verify limit exceeds this bounded profile".into());
    }
    Ok(value)
}
pub(crate) fn parse(args: &[String]) -> Result<Options, String> {
    if args.is_empty()
        || args.len() > 2 * MAX_EXPECTED_REFS + 32
        || args
            .iter()
            .try_fold(0_usize, |sum, arg| sum.checked_add(arg.len()))
            .is_none_or(|sum| sum > 2 * 1024 * 1024)
        || args
            .iter()
            .any(|arg| arg.len() > 8300 || arg.contains('\0'))
    {
        return Err(USAGE.into());
    }
    let mut path = None;
    let mut limits = BundleVerifyLimits::default();
    let mut timeout = Duration::from_secs(300);
    let mut seen = BTreeSet::new();
    let mut expected_hash = None;
    let mut expected_format = None;
    let mut expected_refs = Vec::new();
    let mut exact_refs = false;
    let mut recovery_head = None;
    let mut file_backed = false;
    let mut scratch_directory = None;
    let mut input_mib = None;
    let mut expanded_mib = None;
    let mut literal = false;
    let mut at = 0;
    while at < args.len() {
        let argument = args[at].as_str();
        at += 1;
        if !literal && argument == "--" {
            literal = true;
            continue;
        }
        if !literal && argument.starts_with('-') {
            if !matches!(argument, "--expect-ref" | "--expect-ref-hex") && !seen.insert(argument) {
                return Err("duplicate bundle verify option".into());
            }
            if argument == "--exact-refs" {
                exact_refs = true;
                continue;
            }
            if argument == "--file-backed" {
                file_backed = true;
                continue;
            }
            let value = args.get(at).ok_or("missing bundle verify option value")?;
            at += 1;
            match argument {
                "--scratch-dir" => {
                    if value.is_empty() || value.starts_with('-') || value.len() > 4096 {
                        return Err("scratch directory requires a nonempty local path".into());
                    }
                    scratch_directory = Some(PathBuf::from(value));
                }
                "--recovery-head-hex" => {
                    let name = anchors::unhex(value, 4096)?;
                    let reference = RefName::try_new(&name).map_err(|error| error.to_string())?;
                    if !reference.as_bytes().starts_with(b"refs/heads/") {
                        return Err("recovery head must name an advertised branch".into());
                    }
                    recovery_head = Some(reference);
                }
                "--expect-sha256" => {
                    expected_hash = Some(
                        anchors::unhex(value, 32)?
                            .try_into()
                            .map_err(|_| "expected exactly 32 SHA-256 bytes")?,
                    );
                }
                "--expect-format" => {
                    expected_format = Some(match value.as_str() {
                        "sha1" => GitHashAlgorithm::Sha1,
                        "sha256" => GitHashAlgorithm::Sha256,
                        _ => return Err("expected native format must be sha1 or sha256".into()),
                    });
                }
                "--expect-ref" | "--expect-ref-hex" => {
                    if expected_refs.len() == MAX_EXPECTED_REFS {
                        return Err("too many expected references".into());
                    }
                    expected_refs
                        .try_reserve(1)
                        .map_err(|_| "expectation allocation refused")?;
                    expected_refs.push((value.as_str(), argument == "--expect-ref-hex"));
                }
                "--max-input-mib" => {
                    input_mib = Some(number(value, 16_384)?);
                }
                "--max-expanded-mib" => {
                    expanded_mib = Some(number(value, 16_384)?);
                }
                "--max-objects" => {
                    let count = number(value, 100_000)?;
                    limits.pack.max_entries =
                        u32::try_from(count).map_err(|_| "object count overflow")?;
                    limits.graph.max_objects = count;
                }
                "--max-refs" => {
                    let count = number(value, 4096)?;
                    limits.envelope.max_references = count;
                    limits.graph.max_references = count;
                }
                "--timeout-secs" => timeout = Duration::from_secs(number(value, 3600)? as u64),
                _ => return Err("unknown bundle verify option".into()),
            }
        } else if argument.is_empty() || path.replace(PathBuf::from(argument)).is_some() {
            return Err("bundle verify requires exactly one nonempty input path".into());
        }
    }
    if file_backed != scratch_directory.is_some() {
        return Err("--file-backed and --scratch-dir must be supplied together".into());
    }
    let maximum_mib = if file_backed { 16_384 } else { 128 };
    if input_mib.is_some_and(|value| value > maximum_mib)
        || expanded_mib.is_some_and(|value| value > maximum_mib)
    {
        return Err(
            "limits above 128 MiB require --file-backed and a private --scratch-dir".into(),
        );
    }
    if let Some(mib) = input_mib {
        let bytes = mib
            .checked_mul(1024 * 1024)
            .ok_or("input limit exceeds address space")?;
        limits.envelope.max_bundle_bytes = bytes;
        limits.pack.max_input_bytes = bytes;
    }
    if let Some(mib) = expanded_mib {
        let bytes = mib
            .checked_mul(1024 * 1024)
            .ok_or("expanded limit exceeds address space")?;
        limits.pack.max_total_expanded_bytes = bytes;
        if !file_backed {
            limits.pack.max_cached_bytes = bytes;
        }
        limits.pack.max_object_bytes = limits.pack.max_object_bytes.min(bytes);
        limits.graph.max_object_bytes = limits.pack.max_object_bytes;
        limits.graph.max_payload_bytes = bytes as u64;
    }
    // Complete validation uses final limits, independent of option order,
    // before opening the input or installing any runtime resources.
    let expectations = anchors::assemble(
        expected_hash,
        expected_format,
        &expected_refs,
        exact_refs,
        &limits,
    )?;
    Ok(Options {
        recovery_head,
        scratch_directory,
        expectations,
        path: path.ok_or("bundle verify requires an input path")?,
        limits,
        timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn file_backed_selection_is_explicit_and_independent_of_option_order() {
        for input in [
            args(&[
                "input",
                "--file-backed",
                "--scratch-dir",
                "private",
                "--max-input-mib",
                "512",
                "--max-expanded-mib",
                "1024",
            ]),
            args(&[
                "--max-expanded-mib",
                "1024",
                "--max-input-mib",
                "512",
                "--scratch-dir",
                "private",
                "--file-backed",
                "input",
            ]),
        ] {
            let options = parse(&input).unwrap();
            let defaults = BundleVerifyLimits::default();
            assert_eq!(options.scratch_directory, Some(PathBuf::from("private")));
            assert_eq!(options.limits.envelope.max_bundle_bytes, 512 * 1024 * 1024);
            assert_eq!(options.limits.pack.max_input_bytes, 512 * 1024 * 1024);
            assert_eq!(
                options.limits.pack.max_total_expanded_bytes,
                1024 * 1024 * 1024
            );
            assert_eq!(options.limits.graph.max_payload_bytes, 1024 * 1024 * 1024);
            assert_eq!(
                options.limits.pack.max_object_bytes,
                defaults.pack.max_object_bytes
            );
            assert_eq!(
                options.limits.pack.max_cached_bytes,
                defaults.pack.max_cached_bytes
            );
            assert_eq!(
                options.limits.pack.max_delta_depth,
                defaults.pack.max_delta_depth
            );
            assert_eq!(options.limits.pack.max_entries, defaults.pack.max_entries);
            assert_eq!(options.limits.graph.max_objects, defaults.graph.max_objects);
            assert_eq!(
                options.limits.envelope.max_header_bytes,
                defaults.envelope.max_header_bytes
            );
        }
    }

    #[test]
    fn file_backed_defaults_do_not_enlarge_limits_and_tighter_limits_still_apply() {
        let defaults = BundleVerifyLimits::default();
        let options = parse(&args(&[
            "input",
            "--file-backed",
            "--scratch-dir",
            "private",
        ]))
        .unwrap();
        assert_eq!(
            options.limits.envelope.max_bundle_bytes,
            defaults.envelope.max_bundle_bytes
        );
        assert_eq!(
            options.limits.pack.max_total_expanded_bytes,
            defaults.pack.max_total_expanded_bytes
        );
        assert_eq!(
            options.limits.graph.max_payload_bytes,
            defaults.graph.max_payload_bytes
        );
        let options = parse(&args(&[
            "input",
            "--max-expanded-mib",
            "1",
            "--max-input-mib",
            "2",
            "--max-objects",
            "3",
            "--max-refs",
            "4",
            "--scratch-dir",
            "private",
            "--file-backed",
        ]))
        .unwrap();
        assert_eq!(options.limits.pack.max_object_bytes, 1024 * 1024);
        assert_eq!(options.limits.graph.max_object_bytes, 1024 * 1024);
        assert_eq!(options.limits.pack.max_total_expanded_bytes, 1024 * 1024);
        assert_eq!(options.limits.pack.max_entries, 3);
        assert_eq!(options.limits.envelope.max_references, 4);
    }

    #[test]
    fn invalid_or_incomplete_disk_profiles_refuse_without_opening_any_paths() {
        for input in [
            args(&["missing", "--file-backed"]),
            args(&["missing", "--scratch-dir", "private"]),
            args(&["missing", "--max-input-mib", "129"]),
            args(&["missing", "--max-expanded-mib", "129"]),
            args(&[
                "missing",
                "--file-backed",
                "--scratch-dir",
                "private",
                "--max-input-mib",
                "16385",
            ]),
            args(&[
                "missing",
                "--file-backed",
                "--scratch-dir",
                "private",
                "--max-expanded-mib",
                "16385",
            ]),
            args(&["missing", "--file-backed", "--scratch-dir", ""]),
            args(&[
                "missing",
                "--file-backed",
                "--scratch-dir",
                "private",
                "--file-backed",
            ]),
            args(&[
                "missing",
                "--file-backed",
                "--scratch-dir",
                "private",
                "--scratch-dir",
                "private",
            ]),
        ] {
            assert!(parse(&input).is_err(), "{input:?}");
        }
        assert!(parse(&args(&["missing", "--max-input-mib", "128"])).is_ok());
    }
}
