use super::USAGE;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub task: String,
    pub format: GitHashAlgorithm,
    pub sponsor: PrincipalId,
    pub beads_root: PathBuf,
    pub program: PathBuf,
    pub timeout: Duration,
    pub maximum: usize,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 21
        || args.iter().any(|arg| arg.len() > 4096)
        || args.iter().map(String::len).sum::<usize>() > 32 * 1024
    {
        return Err(USAGE.into());
    }
    if args[0].is_empty() {
        return Err("storage root must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|error| error.to_string())?;
    if args[3].is_empty()
        || args[3].len() > 256
        || args[3].starts_with('-')
        || !args[3]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err("an exact Beads task identifier is required".into());
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
            "--sponsor"
                | "--beads-root"
                | "--br"
                | "--object-format"
                | "--expires-after-secs"
                | "--max-output-bytes"
        ) {
            return Err(format!("unknown agent task option {flag}"));
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
            "--trusted-local is required to authorize local repository and task reads".into(),
        );
    }
    let required = |name| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required"))
    };
    let sponsor =
        PrincipalId::from_hex(required("--sponsor")?).map_err(|error| error.to_string())?;
    let program = PathBuf::from(required("--br")?);
    if !program.is_absolute() {
        return Err("--br must name an absolute, explicitly trusted Beads executable".into());
    }
    let beads_root = PathBuf::from(required("--beads-root")?);
    if !beads_root.is_absolute() {
        return Err("--beads-root must name an absolute Beads directory".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let integer = |flag: &str, fallback, minimum, maximum| {
        let value = flags
            .get(flag)
            .map(|text| fgit_schema::json::decimal(text))
            .transpose()
            .map_err(|error| format!("{flag}: {error}"))?
            .unwrap_or(fallback);
        if value < minimum || value > maximum {
            return Err(format!("{flag} must be between {minimum} and {maximum}"));
        }
        Ok(value)
    };
    Ok(Options {
        storage: PathBuf::from(&args[0]),
        tenant,
        repository,
        task: args[3].clone(),
        format,
        sponsor,
        beads_root,
        program,
        timeout: Duration::from_secs(integer("--expires-after-secs", 30, 1, 300)?),
        maximum: usize::try_from(integer(
            "--max-output-bytes",
            2 * 1024 * 1024,
            1,
            8 * 1024 * 1024,
        )?)
        .map_err(|_| "output limit is not representable")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Vec<String> {
        [
            "/store",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "fg-123.4",
            "--trusted-local",
            "--sponsor",
            "33333333333333333333333333333333",
            "--beads-root",
            "/tracker/.beads",
            "--br",
            "/tools/br",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn explicit_local_scope_and_bounded_options() {
        let parsed = parse(&input()).expect("explicit local task read");
        assert_eq!(parsed.task, "fg-123.4");
        assert_eq!(parsed.timeout, Duration::from_secs(30));
        let mut args = input();
        args.extend(["--expires-after-secs".into(), "300".into()]);
        assert_eq!(parse(&args).unwrap().timeout, Duration::from_secs(300));
        *args.last_mut().unwrap() = "301".into();
        assert!(parse(&args).is_err());
    }

    #[test]
    fn refuses_ambient_execution_aliases_and_duplicate_authority() {
        let mut args = input();
        args.remove(4);
        assert!(parse(&args).is_err());
        let mut args = input();
        *args.last_mut().unwrap() = "br".into();
        assert!(parse(&args).is_err());
        let mut args = input();
        args[3] = "--all".into();
        assert!(parse(&args).is_err());
        let mut args = input();
        args.extend([
            "--sponsor".into(),
            "44444444444444444444444444444444".into(),
        ]);
        assert!(parse(&args).is_err());
    }
}
