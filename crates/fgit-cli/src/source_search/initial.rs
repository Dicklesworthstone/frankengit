//! `fg search --initial` / `--context`: the node's shared Initial retrieval and
//! context-packet read (the HTTP search-initial/context-initial grammar) for a
//! trusted local operator. Persisted indexes are read, never built.
use super::{set_once, write_report};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId, TenantId};

const MAX_FIELDS: usize = 198;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const USAGE: &str =
    "usage: fg search (--initial | --context | --progressive) <storage-root> <tenant-id> <repository-id>
  --trusted-local [--object-format sha1|sha256] <field>=<value>...

Fields use the HTTP search-initial/context-initial grammar exactly, for example
  ref=refs/heads/main term_hex=5468696e67 path_prefix_hex=737263
  symbol_name_hex=5468696e67 symbol_match=prefix symbol_policy=required
  max_results_per_channel=20 context_selection=context-weighted-rrf-q16-v1
Use index_source=current-native-v1 to reuse original index generations after
metadata-only changes, revalidating the current visible native commit and tree.
It supports raw or ranked context and progressive output, preserving the original
index generations and pinning both phases to the one selected current source.
Without index_source, index source positions must match the exact current head.
Repeat term_hex, path_prefix_hex and symbol_kind for several values. The node
supplies object_format. Requires built lexical (and, for symbols, symbol)
indexes; nothing is built or refreshed and no repository state changes.
--progressive flushes the exact Initial answer and then emits a ranked context or
a RefinementFailed record as NDJSON. Both records share the original read and budget.
Exit 0: complete answer; 3: an explicitly truncated channel; 2: refusal.";

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Initial,
    Context,
    Progressive,
}
enum Output {
    Document(String),
    Streamed(bool),
}
pub(super) fn run(arguments: &[String], mode: Mode) -> Result<u8, String> {
    if arguments == ["--help"] {
        write_report(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    if arguments.len() < 4 || arguments.len() > 4 + 2 + MAX_FIELDS {
        return Err(USAGE.into());
    }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let mut trusted = false;
    let mut format = None;
    let mut fields = Vec::new();
    let mut at = 3;
    while at < arguments.len() {
        let argument = arguments[at].as_str();
        at += 1;
        match argument {
            "--trusted-local" if !trusted => trusted = true,
            "--object-format" => {
                let value = match arguments.get(at).map(String::as_str) {
                    Some("sha1") => GitHashAlgorithm::Sha1,
                    Some("sha256") => GitHashAlgorithm::Sha256,
                    _ => return Err("object format must be sha1 or sha256".into()),
                };
                set_once(&mut format, value, "--object-format")?;
                at += 1;
            }
            _ => {
                let (name, value) = argument
                    .split_once('=')
                    .filter(|(name, _)| !name.is_empty() && !name.starts_with('-'))
                    .ok_or_else(|| format!("expected <field>=<value>, got {argument:?}"))?;
                fields.push((name.to_owned(), value.to_owned()));
            }
        }
    }
    if !trusted {
        return Err("--trusted-local is required for a local retrieval read".into());
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(arguments[0].clone().into(), tenant, repository)
            .with_object_format(format.unwrap_or(GitHashAlgorithm::Sha1)),
    )
    .map_err(|error| error.to_string())?;
    let operation = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|error| error.to_string())
        .and_then(|()| {
            let read =
                fgit_node::source_retrieval::authorization::SourceReadContext::trusted_local_cli(
                    &node,
                );
            match mode {
                Mode::Progressive => node
                    .write_progressive_source_context(
                        &read,
                        fields,
                        MAX_OUTPUT_BYTES,
                        &mut std::io::stdout().lock(),
                    )
                    .map(Output::Streamed),
                Mode::Initial | Mode::Context => fgit_node::source_retrieval_json(
                    &node,
                    &read,
                    fields,
                    matches!(mode, Mode::Context),
                    MAX_OUTPUT_BYTES,
                )
                .map(Output::Document),
            }
            .map_err(|code| format!("retrieval refused: {code}"))
        });
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let document = match (operation, cleanup) {
        (Ok(Output::Document(document)), None) => document,
        (Ok(Output::Streamed(complete)), None) => return Ok(if complete { 0 } else { 3 }),
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("retrieval node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    write_report(&mut std::io::stdout().lock(), &document)?;
    // Both documents begin with their own (or, for a context packet, the
    // packet's) completeness flag; a truncated channel is not a complete answer.
    let complete = document
        .split_once("\"complete\":")
        .is_some_and(|(_, tail)| tail.starts_with("true"));
    Ok(if complete { 0 } else { 3 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<String> {
        let mut values = vec![
            "/nonexistent-fg-initial".to_owned(),
            "11".repeat(16),
            "22".repeat(16),
        ];
        values.extend(extra.iter().map(|value| (*value).to_owned()));
        values
    }

    #[test]
    fn malformed_invocations_refuse_before_opening_storage() {
        for mode in [Mode::Initial, Mode::Context, Mode::Progressive] {
            for repeated in ["sha1", "sha256"] {
                let arguments = args(&[
                    "--trusted-local",
                    "--object-format",
                    "sha1",
                    "--object-format",
                    repeated,
                    "ref=refs/heads/main",
                    "term_hex=74",
                ]);
                assert_eq!(
                    run(&arguments, mode),
                    Err("duplicate --object-format".into())
                );
            }
        }
        for extra in [
            vec!["ref=refs/heads/main"],
            vec!["--trusted-local", "term_hex"],
            vec!["--trusted-local", "=x"],
            vec!["--trusted-local", "--literal", "x"],
            vec!["--trusted-local", "--object-format", "sha512"],
            vec!["--trusted-local", "--trusted-local"],
        ] {
            let error = run(&args(&extra), Mode::Initial).unwrap_err();
            assert!(!error.contains("nonexistent"), "{extra:?}: {error}");
        }
        let mut huge = args(&["--trusted-local"]);
        huge.extend((0..=MAX_FIELDS).map(|n| format!("term_hex={n:02x}")));
        assert!(run(&huge, Mode::Context).is_err());
        assert!(run(&["--help".into()], Mode::Initial).is_ok());
    }

    #[test]
    fn a_well_formed_invocation_reaches_the_node() {
        // The permitted twin gets past argument checks and fails only at storage.
        let error = run(
            &args(&["--trusted-local", "ref=refs/heads/main", "term_hex=74"]),
            Mode::Initial,
        )
        .unwrap_err();
        assert!(!error.contains("expected <field>=<value>"), "{error}");
        assert!(!error.contains("--trusted-local is required"), "{error}");
    }
}
