//! Explicit source/destination and verification profile selection.
use super::{USAGE, verify};
use fgit_crypto::lowercase_hex;
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) destination: PathBuf,
    pub(crate) resume: bool,
    pub(crate) verification: verify::Options,
}

pub(crate) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 2 * 4096 + 40
        || args
            .iter()
            .any(|arg| arg.len() > 8300 || arg.contains('\0'))
        || args
            .iter()
            .try_fold(0_usize, |n, arg| n.checked_add(arg.len()))
            .is_none_or(|n| n > 2 * 1024 * 1024)
    {
        return Err(USAGE.into());
    }
    let mut common = Vec::new();
    let mut paths = Vec::new();
    let (mut trusted, mut resume, mut head, mut literal) = (false, false, None, false);
    let mut at = 0;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        if !literal && flag == "--" {
            literal = true;
            continue;
        }
        if literal || !flag.starts_with('-') {
            if flag.is_empty() || paths.len() == 2 {
                return Err("bundle recover requires exactly two nonempty paths".into());
            }
            paths.push(flag.to_owned());
            continue;
        }
        match flag {
            "--trusted-local" => {
                if trusted {
                    return Err("duplicate --trusted-local".into());
                }
                trusted = true;
            }
            "--resume" => {
                if resume {
                    return Err("duplicate --resume".into());
                }
                resume = true;
            }
            "--head-ref" | "--head-ref-hex" => {
                if head.is_some() {
                    return Err("choose exactly one --head-ref or --head-ref-hex".into());
                }
                let value = args.get(at).ok_or("missing recovery head")?;
                at += 1;
                head = Some(if flag == "--head-ref" {
                    lowercase_hex(value.as_bytes())
                } else {
                    value.clone()
                });
            }
            "--exact-refs" | "--file-backed" => common.push(flag.to_owned()),
            "--max-input-mib" | "--max-expanded-mib" | "--max-objects" | "--max-refs"
            | "--timeout-secs" | "--expect-sha256" | "--expect-format" | "--expect-ref"
            | "--expect-ref-hex" | "--scratch-dir" => {
                let value = args.get(at).ok_or("missing bundle recovery option value")?;
                at += 1;
                common.push(flag.to_owned());
                common.push(value.clone());
            }
            _ => return Err(format!("unknown bundle recovery option {flag}")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required for local source materialization".into());
    }
    if paths.len() != 2 {
        return Err("bundle recover requires an input and a destination".into());
    }
    let destination = PathBuf::from(paths.pop().ok_or("missing recovery destination")?);
    if destination.file_name().is_none() {
        return Err("recovery destination must name a directory".into());
    }
    common.push("--recovery-head-hex".into());
    common.push(head.ok_or("an explicit advertised recovery branch is required")?);
    common.push("--".into());
    common.push(paths.pop().ok_or("missing recovery input")?);
    let verification = verify::parse(&common)?;
    Ok(Options {
        destination,
        resume,
        verification,
    })
}
