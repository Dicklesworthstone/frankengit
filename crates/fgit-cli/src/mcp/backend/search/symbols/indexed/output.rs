//! Keep current authorization, original index provenance, corpus coverage and
//! query completeness distinct. Rendering does not authenticate invented data.
use super::*;
use fgit_types::{RepositoryIncarnationId, TenantId};

pub(super) struct Scope {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub format: GitHashAlgorithm,
}

fn invalid() -> ToolError {
    ToolError::failed("invalid_symbol_index_report")
}

fn source_matches(source: &data::Source, scope: &Scope, input: &Input) -> bool {
    source.tenant == scope.tenant
        && source.repository == scope.repository
        && source.incarnation == scope.incarnation
        && source.format == scope.format
        && source.reference == input.selected.reference
        && [source.commit, source.tree]
            .iter()
            .all(|id| !id.is_zero() && id.algorithm() == scope.format)
}

fn validate(
    scope: &Scope,
    input: &Input,
    current: &data::Source,
    report: &data::Report,
) -> Result<usize, ToolError> {
    let indexed = &report.source;
    let limits = input.selected.limits;
    if !source_matches(current, scope, input)
        || !source_matches(indexed, scope, input)
        || current.commit != indexed.commit
        || current.tree != indexed.tree
        || (current.head == indexed.head
            && (current.rcr != indexed.rcr || current.forge != indexed.forge))
        || (input.mode == Mode::Exact && current != indexed)
        || input
            .selected
            .expected_head
            .is_some_and(|head| head != current.head)
        || input
            .selected
            .expected_commit
            .is_some_and(|commit| commit != current.commit)
        || !valid_generation(&report.generation)
        || report.generation_number == 0
        || report.matches.len() > limits.max_matches
        || report.matches.len() > report.indexed_declarations
        || (!report.complete
            && (report.matches.len() != limits.max_matches
                || report.matches.len() >= report.indexed_declarations))
        || report.tables_read > report.indexed_files
        || report.tables_read > limits.max_files
        || report.payload_bytes_read == 0
        || report.payload_bytes_read > input.maximum_payload_bytes
        || report.work_units > input.query.maximum_work()
        || report.matches.windows(2).any(|pair| {
            (&pair[0].location.path, pair[0].location.byte_offset)
                >= (&pair[1].location.path, pair[1].location.byte_offset)
        })
    {
        return Err(invalid());
    }
    if let Some(minimum) = &input.minimum {
        let number = minimum.authority_generation.get();
        if report.generation_number < number
            || (report.generation_number == number
                && &report.generation != minimum.generation_id.as_internal_object_id())
        {
            return Err(invalid());
        }
        // A higher number alone never establishes ancestry. The native
        // generation authority already proved it under this request context.
    }
    // Inventory totals cover the entire index, including out-of-query paths.
    // Per-query file/source-byte bounds apply to selected native table reads,
    // not these whole-manifest counters. Native coverage validates omissions.
    report.validate_coverage().map_err(|_| invalid())
}

fn source(source: &data::Source) -> Value {
    object([
        ("tenant_id", text(source.tenant.to_string())),
        ("repository_id", text(source.repository.to_string())),
        (
            "repository_incarnation",
            text(source.incarnation.to_string()),
        ),
        ("object_format", text(source.format.as_str())),
        ("reference_hex", text(hex(source.reference.as_bytes()))),
        ("source_head", text(source.head.to_string())),
        ("snapshot_token", text(head_token(source.head))),
        ("source_rcr", text(source.rcr.to_string())),
        (
            "forge_position_root",
            text(format!(
                "alg:{}:{}",
                source.forge.algorithm().code_point(),
                hex(source.forge.bytes().as_bytes())
            )),
        ),
        ("source_commit", text(source.commit.to_string())),
        ("source_tree", text(source.tree.to_string())),
    ])
}

pub(super) fn render(
    mut fields: Object,
    scope: &Scope,
    input: &Input,
    current: &data::Source,
    report: &data::Report,
    is_live: &mut impl FnMut() -> bool,
) -> Result<Object, ToolError> {
    live(is_live)?;
    let omitted_bytes = validate(scope, input, current, report)?;
    live(is_live)?;
    let mut retained = 0;
    let matches = render_rows(
        scope.format,
        &input.query,
        &report.matches,
        &mut retained,
        is_live,
    )?;
    let mut omissions = Vec::with_capacity(report.omissions.len());
    for omission in &report.omissions {
        live(is_live)?;
        retained = retained
            .checked_add(omission.path.len())
            .filter(|n| *n <= MAX_RETAINED_BYTES)
            .ok_or(ToolError::failed("resource_limit"))?;
        omissions.push(object([
            ("path_hex", text(hex(&omission.path))),
            ("blob", text(omission.blob.to_string())),
            ("source_bytes", text(omission.source_bytes.to_string())),
            ("reason", text(omission.reason.as_str())),
            (
                "byte_offset",
                omission
                    .byte_offset
                    .map_or(Value::Null, |n| text(n.to_string())),
            ),
            (
                "limit",
                omission.limit.map_or(Value::Null, |n| text(n.to_string())),
            ),
        ]));
    }
    fields.extend([
        ("type".into(), text("source_symbol_index_search")),
        ("schema_version".into(), json::number(1)),
        ("profile".into(), text("source-symbols-indexed-v1")),
        ("declaration_profile".into(), text(PROFILE)),
        (
            "index_profile".into(),
            text(if report.coverage_complete {
                data::INDEX_PROFILE
            } else {
                data::OMISSION_INDEX_PROFILE
            }),
        ),
        ("source_mode".into(), text(input.mode.label())),
        (
            "reference_hex".into(),
            text(hex(current.reference.as_bytes())),
        ),
        ("source_head".into(), text(current.head.to_string())),
        ("source_rcr".into(), text(current.rcr.to_string())),
        ("source_commit".into(), text(current.commit.to_string())),
        ("source_tree".into(), text(current.tree.to_string())),
        ("current_source".into(), source(current)),
        ("indexed_source".into(), source(&report.source)),
        (
            "distinct_provenance".into(),
            Value::Bool(current != &report.source),
        ),
        ("index_token".into(), text(token(&report.generation))),
        (
            "index_number".into(),
            text(report.generation_number.to_string()),
        ),
        (
            "minimum_index_token".into(),
            input.minimum.as_ref().map_or(Value::Null, |minimum| {
                text(token(minimum.generation_id.as_internal_object_id()))
            }),
        ),
        (
            "minimum_index_number".into(),
            input.minimum.as_ref().map_or(Value::Null, |minimum| {
                text(minimum.authority_generation.get().to_string())
            }),
        ),
        ("name_hex".into(), text(hex(input.query.name()))),
        (
            "match_mode".into(),
            text(match input.query.mode() {
                SymbolMatchMode::Exact => "exact",
                SymbolMatchMode::Prefix => "prefix",
            }),
        ),
        (
            "kinds".into(),
            Value::Array(
                input
                    .query
                    .kinds()
                    .iter()
                    .map(|kind| text(kind.as_str()))
                    .collect(),
            ),
        ),
        (
            "path_prefixes_hex".into(),
            Value::Array(
                input
                    .query
                    .source_scope()
                    .prefixes()
                    .iter()
                    .map(|path| text(hex(path.as_bytes())))
                    .collect(),
            ),
        ),
        ("matches".into(), Value::Array(matches)),
        ("complete".into(), Value::Bool(report.complete)),
        (
            "truncated_reason".into(),
            if report.complete {
                Value::Null
            } else {
                text("match_limit")
            },
        ),
        (
            "completion_scope".into(),
            text("matching-declarations-in-recorded-rust-files"),
        ),
        ("pagination_supported".into(), Value::Bool(false)),
        (
            "coverage_complete".into(),
            Value::Bool(report.coverage_complete),
        ),
        ("coverage_scope".into(), text("recorded-rust-files")),
        ("omissions".into(), Value::Array(omissions)),
        ("counter_encoding".into(), text("decimal-strings-v1")),
        ("read_only".into(), Value::Bool(true)),
        ("repository_changed".into(), Value::Bool(false)),
        ("index_changed".into(), Value::Bool(false)),
        ("transaction_created".into(), Value::Bool(false)),
        ("published".into(), Value::Bool(false)),
        ("compiler_resolved".into(), Value::Bool(false)),
        ("macro_expansion".into(), Value::Bool(false)),
        ("cfg_evaluated".into(), Value::Bool(false)),
    ]);
    for (name, value) in [
        ("match_count", report.matches.len()),
        ("max_matches", input.selected.limits.max_matches),
        ("max_files", input.selected.limits.max_files),
        ("max_file_bytes", input.selected.limits.max_file_bytes),
        ("max_total_bytes", input.selected.limits.max_total_bytes),
        ("max_payload_bytes", input.maximum_payload_bytes),
        ("indexed_files", report.indexed_files),
        ("indexed_declarations", report.indexed_declarations),
        ("indexed_source_bytes", report.indexed_source_bytes),
        (
            "unsupported_language_files",
            report.unsupported_language_files,
        ),
        ("non_regular_entries", report.non_regular_entries),
        ("omitted_files", report.omissions.len()),
        ("omitted_source_bytes", omitted_bytes),
        ("tables_read", report.tables_read),
        ("payload_bytes_read", report.payload_bytes_read),
        ("source_blobs_read", 0),
        ("source_bytes_read", 0),
    ] {
        fields.insert(name.into(), text(value.to_string()));
    }
    fields.insert("work_units".into(), text(report.work_units.to_string()));
    fields.insert(
        "max_work".into(),
        text(input.query.maximum_work().to_string()),
    );
    live(is_live)?;
    Ok(fields)
}
