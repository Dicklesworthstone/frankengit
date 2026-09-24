#![forbid(unsafe_code)]
//! Trusted-local executable for an existing node. No HTTP credential grants
//! indexing rights, no repository is created, and no predecessor is refreshed.
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_domain_tag};
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::{LexicalChannel, LexicalQuery};
use fgit_graph::{GenerationActivation, GenerationRecovery, GraphGenerationId};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestBytes, GitHashAlgorithm, InternalObjectId, RefName,
    RepositoryId, TenantId,
};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "fg-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF build genesis|INDEX_TOKEN\n\
fg-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF refresh INDEX_TOKEN\n\
fg-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF recover CANDIDATE_TOKEN\n\
fg-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF query content|path TOKEN [TOKEN ...]\n\
Index tokens are alg:CODE:LOWERCASE_HEX, as printed by build and HTTP indexed search.\n\
Open existing nodes only. Build/refresh require trusted local access and an explicit predecessor.";
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn token(id: &InternalObjectId) -> String {
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn decode(text: &str, bytes: usize) -> Result<Vec<u8>, String> {
    if text.len() != bytes * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Expected exact lowercase hexadecimal bytes.".to_owned());
    }
    let nibble = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| nibble(p[0]) * 16 + nibble(p[1]))
        .collect())
}
fn generation(text: &str) -> Result<GraphGenerationId, String> {
    let algorithm = internal_algorithm_id(IdentityDomain::Generation);
    let prefix = format!("alg:{}:", algorithm.code_point());
    let raw = text
        .strip_prefix(&prefix)
        .ok_or("Wrong generation algorithm/token.")?;
    let width = fgit_crypto::DigestAlgorithm::from_id(algorithm)
        .ok_or("Unknown generation algorithm.")?
        .digest_len();
    let bytes = decode(raw, width)?;
    if bytes.iter().all(|b| *b == 0) {
        return Err("Zero generation is not a candidate.".to_owned());
    }
    GraphGenerationId::from_internal_object_id(InternalObjectId::new(
        algorithm,
        internal_domain_tag(IdentityDomain::Generation),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&bytes).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())
}
#[derive(Debug)]
enum Action {
    Build(Option<GraphGenerationId>),
    Refresh(GraphGenerationId),
    Recover(GraphGenerationId),
    Query(LexicalQuery),
}
struct Command {
    root: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    reference: RefName,
    action: Action,
}
fn parse(args: &[OsString]) -> Result<Command, String> {
    if args.len() < 7 || args.len() > 39 {
        return Err(USAGE.to_owned());
    }
    if args.iter().any(|a| a.len() > 4096) {
        return Err("Argument exceeds 4096 bytes.".to_owned());
    }
    let text = |i: usize| {
        args[i]
            .to_str()
            .ok_or_else(|| "Only the node root may contain non-UTF-8 bytes.".to_owned())
    };
    let tenant = TenantId::from_bytes(
        decode(text(1)?, 16)?
            .try_into()
            .map_err(|_| "Invalid tenant.")?,
    );
    let repository = RepositoryId::from_bytes(
        decode(text(2)?, 16)?
            .try_into()
            .map_err(|_| "Invalid repository.")?,
    );
    let format = match text(3)? {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err(USAGE.to_owned()),
    };
    let reference = RefName::try_new(text(4)?.as_bytes()).map_err(|e| e.to_string())?;
    let action = match text(5)? {
        "build" if args.len() == 7 => Action::Build(if text(6)? == "genesis" {
            None
        } else {
            Some(generation(text(6)?)?)
        }),
        "refresh" if args.len() == 7 => Action::Refresh(generation(text(6)?)?),
        "recover" if args.len() == 7 => Action::Recover(generation(text(6)?)?),
        "query" if args.len() >= 8 => {
            let channel = match text(6)? {
                "content" => LexicalChannel::Content,
                "path" => LexicalChannel::Path,
                _ => return Err(USAGE.to_owned()),
            };
            let terms = (7..args.len())
                .map(|i| text(i).map(|s| s.as_bytes().to_vec()))
                .collect::<Result<Vec<_>, _>>()?;
            Action::Query(LexicalQuery::new(channel, &terms, &[]).map_err(|e| e.to_string())?)
        }
        _ => return Err(USAGE.to_owned()),
    };
    Ok(Command {
        root: PathBuf::from(&args[0]),
        tenant,
        repository,
        format,
        reference,
        action,
    })
}
fn activation_fields(activation: &GenerationActivation) -> String {
    format!(
        "\"index_token\":\"{}\",\"index_number\":{}",
        token(activation.generation_id.as_internal_object_id()),
        activation.authority_generation.get()
    )
}
fn execute(node: &OneNode, command: &Command) -> Result<String, NodeWorkspaceRefusal> {
    let context = node.request_context();
    match &command.action {
        Action::Build(predecessor) => {
            let (source, activation) =
                node.runtime().block_on(node.build_source_index_local_in(
                    &context,
                    &command.reference,
                    None,
                    None,
                    *predecessor,
                    SearchLimits::default(),
                ))?;
            Ok(format!(
                "{{\"type\":\"index_activation\",{},\"snapshot_token\":\"{}\",\"source_commit\":\"{}\",\"root_tree\":\"{}\",\"repository_transaction_created\":false}}",
                activation_fields(&activation),
                token(source.source_head.as_internal_object_id()),
                source.commit,
                source.tree
            ))
        }
        Action::Refresh(predecessor) => {
            let (source, activation, stats) =
                node.runtime().block_on(node.refresh_source_index_local_in(
                    &context,
                    &command.reference,
                    None,
                    None,
                    *predecessor,
                    SearchLimits::default(),
                    Default::default(),
                ))?;
            Ok(format!(
                "{{\"type\":\"index_refresh\",{},\"snapshot_token\":\"{}\",\"source_commit\":\"{}\",\"root_tree\":\"{}\",\"reused_documents\":{},\"rebuilt_documents\":{},\"reused_source_bytes\":{},\"rebuilt_source_bytes\":{},\"prior_documents_not_reused\":{},\"previous_payload_bytes_read\":{},\"previous_generation_bytes_read\":{},\"build_work_bytes\":{},\"repository_transaction_created\":false}}",
                activation_fields(&activation),
                token(source.source_head.as_internal_object_id()),
                source.commit,
                source.tree,
                stats.reused_documents,
                stats.rebuilt_documents,
                stats.reused_source_bytes,
                stats.rebuilt_source_bytes,
                stats.prior_documents_not_reused,
                stats.previous_payload_bytes_read,
                stats.previous_generation_bytes_read,
                stats.build_work_bytes
            ))
        }
        Action::Recover(candidate) => {
            let recovered = node.runtime().block_on(node.recover_source_index_local_in(
                &context,
                &command.reference,
                *candidate,
                None,
                Default::default(),
            ))?;
            let (state, selected) = match recovered {
                GenerationRecovery::Uninitialized => ("uninitialized", None),
                GenerationRecovery::Active { selected } => ("active", Some(selected)),
                GenerationRecovery::Superseded { selected, .. } => ("superseded", Some(selected)),
                GenerationRecovery::NotInSelectedHistory { selected } => {
                    ("not_in_selected_history", Some(selected))
                }
            };
            let selected = selected.map_or_else(
                || "null".to_owned(),
                |s| format!("{{{}}}", activation_fields(s.activation())),
            );
            Ok(format!(
                "{{\"type\":\"index_recovery\",\"candidate_token\":\"{}\",\"state\":\"{state}\",\"selected\":{selected},\"read_only\":true}}",
                token(candidate.as_internal_object_id())
            ))
        }
        Action::Query(query) => {
            let report = node.runtime().block_on(node.search_source_index_local_in(
                &context,
                &command.reference,
                None,
                None,
                None,
                None,
                query,
                None,
                Default::default(),
                Default::default(),
            ))?;
            let hits = report
                .results
                .hits
                .iter()
                .map(|h| {
                    format!(
                        "{{\"document_id\":{},\"path_hex\":\"{}\",\"blob\":\"{}\"}}",
                        h.document_id,
                        hex(&h.path),
                        h.blob
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!(
                "{{\"type\":\"index_query\",{},\"snapshot_token\":\"{}\",\"source_commit\":\"{}\",\"complete\":{},\"next_after\":{},\"hits\":[{}],\"read_only\":true}}",
                activation_fields(&report.generation),
                token(report.source.source_head.as_internal_object_id()),
                report.source.commit,
                report.results.complete,
                report
                    .results
                    .next_after
                    .map_or_else(|| "null".to_owned(), |n| n.to_string()),
                hits
            ))
        }
    }
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(40).collect();
    let command = match parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let config = NodeConfig::new(command.root.clone(), command.tenant, command.repository)
        .with_object_format(command.format)
        .with_worker_threads(2);
    let mut node = match OneNode::open_existing(config) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Open failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ready = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .map_err(|e| e.to_string())
        .and_then(|selected| {
            node.bring_into_service(selected.receipt().generation())
                .map_err(|e| e.to_string())
        });
    if let Err(error) = ready {
        eprintln!("Source authority unavailable: {error}");
        if let Err(close) = node.shutdown() {
            eprintln!("Shutdown also failed: {close}");
        }
        return ExitCode::FAILURE;
    }
    let result = execute(&node, &command);
    let shutdown = node.shutdown(); // Explicit even when the operation fails.
    let output_ok = match result {
        Ok(body) => match writeln!(io::stdout().lock(), "{body}") {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "Operation returned successfully but its receipt could not be written: {e}. Do not infer rollback."
                );
                false
            }
        },
        Err(NodeWorkspaceRefusal::SourceIndexPublication { candidate, error }) => {
            eprintln!(
                "Index publication was not confirmed: {error}\nCandidate: {}\nRecover this candidate; this error does not establish rollback.",
                token(candidate.as_internal_object_id())
            );
            false
        }
        Err(e) => {
            eprintln!("Operation failed: {e}");
            false
        }
    };
    if let Err(error) = shutdown {
        eprintln!(
            "Node shutdown failed: {error}. This does not undo any reported index activation."
        );
        return ExitCode::FAILURE;
    }
    if output_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(action: &[&str]) -> Vec<OsString> {
        let mut out: Vec<_> = [
            "/unused-node",
            "01010101010101010101010101010101",
            "02020202020202020202020202020202",
            "sha1",
            "refs/heads/main",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        out.extend(action.iter().map(|s| OsString::from(*s)));
        out
    }
    #[test]
    fn build_requires_explicit_genesis_or_exact_predecessor_before_open() {
        assert!(matches!(
            parse(&args(&["build", "genesis"])).unwrap().action,
            Action::Build(None)
        ));
        let token = format!("alg:2:{}", "a".repeat(64));
        assert!(matches!(
            parse(&args(&["build", &token])).unwrap().action,
            Action::Build(Some(_))
        ));
        for tail in [
            &["build"][..],
            &["build", "latest"],
            &["build", "genesis", "force"],
            &["init", "genesis"],
        ] {
            assert!(parse(&args(tail)).is_err());
        }
    }
    #[test]
    fn queries_are_bounded_whole_tokens_and_recovery_cannot_refresh_a_candidate() {
        assert!(parse(&args(&["query", "content", "needle", "NESTED"])).is_ok());
        for tail in [
            &["query", "content"][..],
            &["query", "symbol", "thing"],
            &["query", "content", "a.*"],
            &["recover", "latest"],
            &["recover", "genesis"],
        ] {
            assert!(parse(&args(tail)).is_err());
        }
        let mut many = args(&["query", "path"]);
        many.extend((0..33).map(|_| OsString::from("a")));
        assert!(parse(&many).is_err());
    }
    #[test]
    fn wrong_identity_width_case_hash_domain_and_unknown_format_refuse_before_open() {
        for index in [1, 2, 3] {
            let mut a = args(&["build", "genesis"]);
            a[index] = OsString::from("invalid");
            assert!(parse(&a).is_err());
        }
        for text in [
            format!("alg:2:{}", "0".repeat(64)),
            format!("alg:1:{}", "a".repeat(40)),
            format!("alg:2:{}", "A".repeat(64)),
        ] {
            assert!(generation(&text).is_err());
        }
    }
    #[test]
    fn refresh_requires_an_existing_exact_generation_without_implicit_bootstrap_or_force() {
        let token = format!("alg:2:{}", "b".repeat(64));
        assert!(
            matches!(parse(&args(&["refresh", &token])).unwrap().action, Action::Refresh(id) if id == generation(&token).unwrap())
        );
        for tail in [
            &["refresh"][..],
            &["refresh", "genesis"],
            &["refresh", "latest"],
            &["refresh", &token, "force"],
            &["refresh", &token, "extra"],
        ] {
            assert!(parse(&args(tail)).is_err());
        }
    }
}
