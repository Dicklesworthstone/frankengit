//! Authenticated persisted declaration reads. Shared envelope/query parsing and
//! row validation remain owned by the declaration service, not copied here.
use super::*;
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_domain_tag};
use fgit_forge::source_symbols::index::{self as data, AccessError, TableError};
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GraphGenerationId};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestBytes, HeadGeneration, InternalObjectId};
type Failure = AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
pub(in super::super) fn refusal(error: Failure) -> ApiError {
    match error {
        AccessError::Source(error) => read_error(error),
        AccessError::Uninitialized => ApiError::new(Status::Conflict, "symbol_index_uninitialized"),
        AccessError::Stale => ApiError::new(Status::Conflict, "symbol_index_stale"),
        AccessError::Index(data::Error::Cancelled | data::Error::Table(TableError::Cancelled))
        | AccessError::Generation(GenerationAuthorityError::ReadCancelled) => {
            ApiError::from_status(Status::Timeout, false)
        }
        AccessError::Index(data::Error::Limit(_) | data::Error::Table(TableError::Limit(_)))
        | AccessError::Generation(GenerationAuthorityError::ReadBudgetExceeded(_)) => {
            ApiError::too_large()
        }
        AccessError::Generation(GenerationAuthorityError::CheckpointUnresolved) => {
            ApiError::new(Status::Conflict, "index_checkpoint_unavailable")
        }
        // This is read-only: no storage failure becomes publication ambiguity.
        _ => ApiError::unavailable(),
    }
}
fn indexed_command(
    bytes: &[u8],
    format: GitHashAlgorithm,
) -> Result<(Command, Option<GenerationActivation>), ApiError> {
    let mut query = Vec::new();
    let mut token = None;
    let mut number = None;
    for (name, value) in parse_form(bytes, 150)? {
        match name.as_str() {
            "minimum_index_token" => {
                if token.replace(value).is_some() {
                    return Err(ApiError::bad("duplicate_field"));
                }
            }
            "minimum_index_number" => {
                if number.replace(value).is_some() {
                    return Err(ApiError::bad("duplicate_field"));
                }
            }
            _ => query.push((name, value)),
        }
    }
    let floor = match (token, number) {
        (None, None) => None,
        (Some(token), Some(number)) => {
            let algorithm = internal_algorithm_id(IdentityDomain::Generation);
            let prefix = format!("alg:{}:", algorithm.code_point());
            let width = fgit_crypto::DigestAlgorithm::from_id(algorithm)
                .ok_or_else(ApiError::unavailable)?
                .digest_len();
            let raw = unhex(
                token
                    .strip_prefix(&prefix)
                    .ok_or_else(|| ApiError::bad("invalid_index_token"))?,
                width,
            )?;
            if raw.len() != width || raw.iter().all(|b| *b == 0) {
                return Err(ApiError::bad("invalid_index_token"));
            }
            let digest =
                DigestBytes::try_new(&raw).map_err(|_| ApiError::bad("invalid_index_token"))?;
            let generation_id = GraphGenerationId::from_internal_object_id(InternalObjectId::new(
                algorithm,
                internal_domain_tag(IdentityDomain::Generation),
                CANONICAL_CODEC_VERSION,
                digest,
            ))
            .map_err(|_| ApiError::bad("invalid_index_token"))?;
            let authority_generation = HeadGeneration::try_new(parse_decimal(&number)?)
                .map_err(|_| ApiError::bad("invalid_index_number"))?;
            Some(GenerationActivation {
                generation_id,
                authority_generation,
            })
        }
        _ => return Err(ApiError::bad("incomplete_index_checkpoint")),
    };
    Ok((command_fields(query, format)?, floor))
}
pub(super) fn execute(
    node: &OneNode,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum: u64,
) -> Result<JsonReply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let (command, minimum) =
        indexed_command(&read_form(reader, framing, http)?, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let mut live = || !deadline.expired();
    let report = drive_request_while(
        node,
        &context,
        node.search_source_symbols_index_snapshot_local_in(
            &context,
            &command.selection.reference,
            command.selection.expected_head,
            command.selection.expected_commit,
            minimum.as_ref(),
            &command.query,
            command.limits,
            data::MAX_INDEX_BYTES,
        ),
        &mut live,
    )
    .map_err(refusal)?;
    let body = render(
        node,
        &command,
        &report,
        usize::try_from(maximum).unwrap_or(usize::MAX),
        &mut live,
    )?;
    Ok(JsonReply {
        status: Status::Success,
        body,
        terminal: None,
    })
}
fn token(id: &fgit_types::InternalObjectId) -> String {
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn render(
    node: &OneNode,
    command: &Command,
    report: &data::Report,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let source = &report.source;
    let query = &command.query;
    if source.tenant != node.tenant_id
        || source.repository != node.repository_id
        || source.incarnation != node.repository_incarnation_id()
        || source.format != node.object_format
        || source.reference != command.selection.reference
        || report.matches.len() > command.limits.max_matches
        || report.indexed_files + report.unsupported_language_files > 20_000
        || report.indexed_declarations > 20_000
        || report.indexed_source_bytes > 64 * 1024 * 1024
        || report.tables_read > report.indexed_files
        || report.payload_bytes_read > data::MAX_INDEX_BYTES
        || report.work_units > query.maximum_work()
        || report.generation_number == 0
        || report.matches.len() > report.indexed_declarations
        || report.generation.domain()
            != fgit_types::DomainTag::from_static("frankengit/generation/v1")
        || (!report.complete
            && (report.matches.len() != command.limits.max_matches
                || report.matches.len() >= report.indexed_declarations))
        || report.matches.windows(2).any(|p| {
            (&p[0].location.path, p[0].location.byte_offset)
                >= (&p[1].location.path, p[1].location.byte_offset)
        })
        || [source.commit, source.tree]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != node.object_format)
        || command
            .selection
            .expected_head
            .is_some_and(|id| id != source.head)
        || command
            .selection
            .expected_commit
            .is_some_and(|id| id != source.commit)
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_search_symbols_index\",\"schema_version\":1,",
                "\"profile\":{},\"index_profile\":{},\"authority_class\":\"deterministic-derived\",",
                "\"compiler_resolved\":false,\"macro_expansion\":false,\"cfg_evaluated\":false,",
                "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},{},",
                "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},",
                "\"index_token\":{},\"index_number\":{},\"read_only\":true,\"transaction_created\":false,\"published\":false,",
                "\"source_blobs_read\":0,\"source_bytes_read\":0,\"name_hex\":{},\"match\":{},",
                "\"complete\":{},\"completion\":{},\"max_matches\":{},\"returned_matches\":{},",
                "\"indexed_files\":{},\"indexed_declarations\":{},\"indexed_source_bytes\":{},",
                "\"unsupported_language_files\":{},\"non_regular_entries\":{},\"tables_read\":{},",
                "\"payload_bytes_read\":{},\"max_work\":{},\"work_units\":{},\"kinds\":["
            ),
            quote(PROFILE),
            quote(data::INDEX_PROFILE),
            quote(&source.tenant.to_string()),
            quote(&source.repository.to_string()),
            quote(&source.incarnation.to_string()),
            quote(source.format.as_str()),
            ref_fields("ref", &source.reference),
            quote(&source.head.to_string()),
            quote(&token(source.head.as_internal_object_id())),
            quote(&source.rcr.to_string()),
            quote(&source.commit.to_string()),
            quote(&source.tree.to_string()),
            quote(&token(&report.generation)),
            report.generation_number,
            quote(&hex(query.name())),
            quote(match query.mode() {
                SymbolMatchMode::Exact => "exact",
                SymbolMatchMode::Prefix => "prefix",
            }),
            report.complete,
            quote(if report.complete {
                "complete"
            } else {
                "match_limit"
            }),
            command.limits.max_matches,
            report.matches.len(),
            report.indexed_files,
            report.indexed_declarations,
            report.indexed_source_bytes,
            report.unsupported_language_files,
            report.non_regular_entries,
            report.tables_read,
            report.payload_bytes_read,
            query.maximum_work(),
            report.work_units
        ),
        maximum,
    )?;
    for (i, kind) in query.kinds().iter().enumerate() {
        check(live)?;
        append(
            &mut out,
            &format!("{}{}", if i == 0 { "" } else { "," }, quote(kind.as_str())),
            maximum,
        )?;
    }
    append(&mut out, "],\"path_prefix_hex\":[", maximum)?;
    for (i, path) in query.source_scope().prefixes().iter().enumerate() {
        check(live)?;
        append(
            &mut out,
            &format!(
                "{}{}",
                if i == 0 { "" } else { "," },
                quote(&hex(path.as_bytes()))
            ),
            maximum,
        )?;
    }
    append(&mut out, "],\"matches\":[", maximum)?;
    for (i, row) in report.matches.iter().enumerate() {
        check(live)?;
        if i != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(
            &mut out,
            &row_json(
                row,
                query,
                node.object_format,
                command.limits.max_file_bytes,
            )?,
            maximum,
        )?;
    }
    append(&mut out, "]}", maximum)?;
    check(live)?;
    Ok(out)
}
/// Initial retrieval retains the same symbol row, scope and profile validator.
pub(in super::super) fn render_initial(
    node: &OneNode,
    report: &data::Report,
    query: &SymbolQuery,
    budget: (usize, usize),
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    if report.payload_bytes_read > budget.1 {
        return Err(ApiError::unavailable());
    }
    let command = Command {
        selection: Selection {
            reference: report.source.reference.clone(),
            expected_head: Some(report.source.head),
            expected_commit: Some(report.source.commit),
        },
        query: query.clone(),
        limits: SearchLimits {
            max_matches: budget.0,
            ..Default::default()
        },
    };
    render(node, &command, report, maximum, live)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indexed_and_scanned_profiles_share_authorization_but_remain_explicit() {
        for (operation, indexed) in [("search-symbols", false), ("search-symbols-index", true)] {
            let raw = format!(
                "POST /r.git/api/v1/source/{operation} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n"
            );
            let head = fgit_wire::smart_http::head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(Request::parse(&head).unwrap().unwrap().indexed, indexed);
            assert!(
                !super::super::super::Request::parse(&head)
                    .unwrap()
                    .is_mutation()
            );
        }
    }
    #[test]
    fn missing_stale_corrupt_and_exhausted_indexes_are_not_empty_success_or_unknown_writes() {
        for error in [
            Failure::Uninitialized,
            Failure::Stale,
            Failure::Index(data::Error::CommitmentMismatch),
            Failure::Index(data::Error::Limit("index bytes")),
            Failure::Index(data::Error::Cancelled),
        ] {
            let reply = refusal(error);
            assert!(!reply.outcome_unknown);
            let mut raw = Vec::new();
            reply
                .send_named(
                    &mut raw,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "source_error",
                )
                .unwrap();
            let text = String::from_utf8(raw).unwrap();
            assert!(!text.contains("\"matches\""));
            assert!(!text.contains("200 OK"));
        }
    }
    #[test]
    fn checkpoint_pairs_are_typed_complete_and_cannot_enter_the_scanning_profile() {
        let form = "object_format=sha1&ref=refs/heads/main&name_hex=5468696e67";
        let pair = format!(
            "&minimum_index_token=alg:2:{}&minimum_index_number=7",
            "a".repeat(64)
        );
        let full = form.to_owned() + &pair;
        let (_, floor) = indexed_command(full.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
        assert_eq!(floor.unwrap().authority_generation.get(), 7);
        assert!(command(full.as_bytes(), GitHashAlgorithm::Sha1).is_err());
        for suffix in [
            "&minimum_index_number=1".to_owned(),
            format!("&minimum_index_token=alg:2:{}", "a".repeat(64)),
            pair.clone() + "&minimum_index_number=7",
            pair.replace("number=7", "number=0"),
            pair.replace("alg:2:", "alg:1:"),
            pair.replace(&"a".repeat(64), &"0".repeat(64)),
        ] {
            assert!(
                indexed_command(
                    (form.to_owned() + &suffix).as_bytes(),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
            );
        }
    }
}
