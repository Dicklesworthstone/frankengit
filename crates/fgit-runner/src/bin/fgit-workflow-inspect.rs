#![forbid(unsafe_code)]
//! Source-independent, read-only inspection of one retained local job result.

#[cfg(unix)]
mod unix {
    use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
    use fgit_runner::Commitment;
    use fgit_runner::coordinator::delivery::MAX_BATCH_FACTS;
    use fgit_runner::coordinator::delivery::journal::history::MAX_OBSERVATION_BYTES;
    use fgit_runner::coordinator::delivery::journal::{
        CheckJournalLimits, CheckJournalPin, CheckJournalScope, FileCheckJournal,
    };
    use fgit_types::{RepositoryId, TenantId};
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::PathBuf;

    const USAGE: &str = "usage: fgit-workflow-inspect ABSOLUTE_JOURNAL TENANT_HEX REPOSITORY_HEX JOURNAL_SHA256 BATCH_SHA256 FACT_INDEX [--minimum BYTES TAIL_SHA256]";

    #[derive(Debug)]
    struct Options {
        path: PathBuf,
        scope: CheckJournalScope,
        batch: Commitment,
        fact: usize,
        minimum: Option<CheckJournalPin>,
    }
    fn text(value: &OsString) -> Result<&str, &'static str> {
        value.to_str().ok_or(USAGE)
    }
    fn hex<const N: usize>(value: &OsString) -> Result<[u8; N], &'static str> {
        let value = text(value)?.as_bytes();
        if value.len() != N * 2 {
            return Err(USAGE);
        }
        let mut result = [0; N];
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(USAGE),
        };
        for (slot, [high, low]) in result.iter_mut().zip(value.as_chunks::<2>().0) {
            *slot = digit(*high)? * 16 + digit(*low)?;
        }
        Ok(result)
    }
    fn root(value: &OsString) -> Result<Commitment, &'static str> {
        let bytes = hex::<32>(value)?;
        let digest = Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&bytes).map_err(|_| USAGE)?,
        );
        Commitment::try_from_digest(digest).map_err(|_| USAGE)
    }
    fn number(value: &OsString) -> Result<u64, &'static str> {
        let input = text(value)?;
        let parsed = input.parse::<u64>().map_err(|_| USAGE)?;
        if parsed.to_string() != input {
            return Err(USAGE);
        }
        Ok(parsed)
    }
    fn parse(args: &[OsString]) -> Result<Options, &'static str> {
        if !matches!(args.len(), 6 | 9) {
            return Err(USAGE);
        }
        let path = PathBuf::from(&args[0]);
        if !path.is_absolute() {
            return Err(USAGE);
        }
        let scope = CheckJournalScope {
            tenant: TenantId::from_bytes(hex(&args[1])?),
            repository: RepositoryId::from_bytes(hex(&args[2])?),
            journal_id: root(&args[3])?,
        };
        let batch = root(&args[4])?;
        let fact = usize::try_from(number(&args[5])?).map_err(|_| USAGE)?;
        if fact >= MAX_BATCH_FACTS {
            return Err(USAGE);
        }
        let minimum = if args.len() == 9 {
            if text(&args[6])? != "--minimum" {
                return Err(USAGE);
            }
            let bytes = number(&args[7])?;
            if bytes < 72 {
                return Err(USAGE);
            }
            Some(CheckJournalPin::new(bytes, root(&args[8])?))
        } else {
            None
        };
        Ok(Options {
            path,
            scope,
            batch,
            fact,
            minimum,
        })
    }
    fn run(options: Options, output: &mut impl Write) -> Result<(), String> {
        let mut journal = FileCheckJournal::open(
            &options.path,
            options.scope,
            CheckJournalLimits::default(),
            options.minimum,
            &|| true,
        )
        .map_err(|error| error.to_string())?;
        let pin = journal.pin();
        let observation = journal
            .read_trusted_job(
                pin,
                options.batch,
                options.fact,
                MAX_OBSERVATION_BYTES,
                &|| true,
            )
            .map_err(|error| error.to_string())?;
        // All identifying strings below are typed digest/ID displays. The
        // report's original encoder escapes text and retains logs as hex.
        let json = format!(
            "{{\"schema_version\":1,\"authoritative_check\":false,\"snapshot_bytes\":{},\"snapshot_tail\":\"{}\",\"batch\":\"{}\",\"fact_index\":{},\"evidence\":\"{}\",\"run\":\"{}\",\"attempt\":\"{}\",\"source_head\":\"{}\",\"source_commit\":\"{}\",\"logical_now\":{},\"requires_containment\":{},\"report\":{}}}\n",
            pin.byte_len(),
            pin.tail(),
            options.batch,
            options.fact,
            observation.evidence(),
            observation.run_id(),
            observation.attempt_id(),
            observation.authority_head(),
            observation.source_commit(),
            observation.logical_now(),
            observation.requires_containment(),
            observation.report_json(),
        );
        output
            .write_all(json.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|_| "write observation response failed".to_owned())
    }
    pub fn main() -> std::process::ExitCode {
        // One extra argument diagnoses excess without collecting an unbounded list.
        let args = std::env::args_os().skip(1).take(10).collect::<Vec<_>>();
        let result = parse(&args)
            .map_err(str::to_owned)
            .and_then(|options| run(options, &mut std::io::stdout().lock()));
        match result {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn args() -> Vec<OsString> {
            [
                "/private/checks".to_owned(),
                "11".repeat(16),
                "22".repeat(16),
                "33".repeat(32),
                "44".repeat(32),
                "0".to_owned(),
            ]
            .into_iter()
            .map(OsString::from)
            .collect()
        }
        #[test]
        fn exact_scope_and_minimum_pin_are_explicit_not_inferred_from_paths() {
            let mut input = args();
            let options = parse(&input).unwrap();
            assert_eq!(options.scope.tenant, TenantId::from_bytes([0x11; 16]));
            assert_eq!(options.fact, 0);
            assert!(options.minimum.is_none());
            input.extend(["--minimum".into(), "72".into(), "55".repeat(32).into()]);
            assert_eq!(parse(&input).unwrap().minimum.unwrap().byte_len(), 72);
        }
        #[test]
        fn malformed_selectors_and_extra_arguments_refuse_before_open() {
            for (index, value) in [
                (0, "relative"),
                (1, "00"),
                (3, "guess"),
                (5, "128"),
                (5, "-1"),
                (5, "+1"),
                (5, "01"),
                (5, "18446744073709551616"),
            ] {
                let mut input = args();
                input[index] = value.into();
                assert!(parse(&input).is_err());
            }
            for count in [0, 1, 5, 7, 8, 10] {
                let mut input = args();
                input.resize(count, "unknown".into());
                assert!(parse(&input).is_err());
            }
            let mut input = args();
            input.extend(["--minimum".into(), "71".into(), "55".repeat(32).into()]);
            assert!(parse(&input).is_err());
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("workflow journal inspection requires the Unix private-file journal profile");
    std::process::ExitCode::FAILURE
}
