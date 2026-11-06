use super::{MAX_OUTPUT_BYTES, USAGE};
use fgit_agent::effect_journal::{
    EffectJournalPosition, MAX_EFFECT_JOURNAL_BYTES, MAX_EFFECT_JOURNAL_ENTRIES,
};
use fgit_agent::{EffectId, RunId};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(crate) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub directory: PathBuf,
    pub principal: PrincipalId,
    pub format: GitHashAlgorithm,
    pub run: RunId,
    pub effect: EffectId,
    pub expected_run: [u8; 32],
    pub expected_tail: EffectJournalPosition,
    pub maximum: usize,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    parse_with_usage(args, USAGE)
}

pub(crate) fn parse_with_usage(args: &[String], usage: &str) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 23
        || args.iter().any(|arg| arg.len() > 4096)
        || args.iter().map(String::len).sum::<usize>() > 32 * 1024
    {
        return Err(usage.into());
    }
    if args[0].is_empty() {
        return Err("storage root must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?;
    let directory = PathBuf::from(&args[3]);
    if !directory.is_absolute() {
        return Err("journal directory must be an explicitly selected absolute path".into());
    }
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut at = 4;
    while let Some(flag) = args.get(at) {
        at += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--principal"
                | "--run-id"
                | "--effect-id"
                | "--expected-run"
                | "--expected-tail-entries"
                | "--expected-tail-bytes"
                | "--expected-tail-digest"
                | "--object-format"
                | "--max-output-bytes"
        ) {
            return Err(format!("unknown agent journal option {flag}"));
        }
        let value = args
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        if flags.insert(flag.as_str(), value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted {
        return Err(
            "--trusted-local is required to authorize the selected journal operation".into(),
        );
    }
    let required = |name| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required; recovery never infers its own anchor"))
    };
    let principal = PrincipalId::from_hex(required("--principal")?)
        .map_err(|_| "invalid original principal ID")?;
    let run = RunId::new(u128::from_be_bytes(hex(required("--run-id")?)?));
    let effect = EffectId::new(u128::from_be_bytes(hex(required("--effect-id")?)?));
    let expected_run = hex(required("--expected-run")?)?;
    let entries = decimal(
        required("--expected-tail-entries")?,
        0,
        MAX_EFFECT_JOURNAL_ENTRIES,
    )?;
    let bytes = decimal(
        required("--expected-tail-bytes")?,
        1,
        MAX_EFFECT_JOURNAL_BYTES as u64,
    )?;
    let digest = hex(required("--expected-tail-digest")?)?;
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let maximum = decimal(
        flags.get("--max-output-bytes").copied().unwrap_or("65536"),
        1,
        MAX_OUTPUT_BYTES as u64,
    )? as usize;
    Ok(Options {
        storage: PathBuf::from(&args[0]),
        tenant,
        repository,
        directory,
        principal,
        format,
        run,
        effect,
        expected_run,
        expected_tail: EffectJournalPosition {
            entries,
            bytes,
            digest,
        },
        maximum,
    })
}

fn hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "expected exactly {} lowercase hexadecimal characters",
            N * 2
        ));
    }
    let mut bytes = [0; N];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[at * 2..at * 2 + 2], 16)
            .map_err(|_| "invalid lowercase hex")?;
    }
    Ok(bytes)
}

fn decimal(value: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("expected canonical unsigned decimal".into());
    }
    let number = value
        .parse::<u64>()
        .map_err(|_| "unsigned decimal overflow")?;
    if number < minimum || number > maximum {
        return Err(format!("value must be between {minimum} and {maximum}"));
    }
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
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
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn requires_every_independent_anchor_and_explicit_read_scope() {
        let input = args();
        let parsed = parse(&input).unwrap();
        assert_eq!(parsed.expected_tail.entries, 3);
        assert_eq!(parsed.expected_tail.bytes, 1024);
        assert_eq!(parsed.maximum, 65536);
        for flag in [
            "--principal",
            "--run-id",
            "--effect-id",
            "--expected-run",
            "--expected-tail-entries",
            "--expected-tail-bytes",
            "--expected-tail-digest",
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
        let mut duplicate = input;
        duplicate.extend(["--expected-tail-bytes".into(), "1024".into()]);
        assert!(parse(&duplicate).is_err());
    }

    #[test]
    fn refuses_unbounded_aliases_and_noncanonical_identity_encodings() {
        for (flag, value) in [
            ("--run-id", "A".repeat(32)),
            ("--effect-id", "0".repeat(31)),
            ("--expected-run", "0".repeat(65)),
            ("--expected-tail-entries", "32769".into()),
            ("--expected-tail-entries", "01".into()),
            ("--expected-tail-bytes", "16777217".into()),
            ("--expected-tail-bytes", "0".into()),
        ] {
            let mut input = args();
            let at = input.iter().position(|argument| argument == flag).unwrap();
            input[at + 1] = value;
            assert!(parse(&input).is_err(), "{flag}");
        }
        let mut relative = args();
        relative[3] = "journal".into();
        assert!(parse(&relative).is_err());
        let mut large = args();
        large[0] = "x".repeat(4097);
        assert!(parse(&large).is_err());
        let mut discovery = args();
        discovery.extend(["--discover-tail".into(), "true".into()]);
        assert!(parse(&discovery).is_err());
        let mut output = args();
        output.extend(["--max-output-bytes".into(), "1048577".into()]);
        assert!(parse(&output).is_err());
    }
}
