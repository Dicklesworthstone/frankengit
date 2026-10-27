use super::{AgentContextRequest, profile, sponsor_authentication};
use crate::source_retrieval::context::InitialContext;
use crate::source_retrieval::current_index::{
    GenerationActivation, IndexedLexicalReport, LexicalSource,
};
use crate::source_retrieval::{SymbolChannel, SymbolPolicy, SymbolUnavailable};
use fgit_agent::{AuthorityReadReceipt, ContextPacket, IntentRun};
use fgit_forge::source_symbols::SymbolMatchMode;
use fgit_resource::algebra::Grade;
use fgit_schema::json::{Value, number, object, text};
use fgit_types::{Digest, InternalObjectId};

pub(super) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}
fn bytes(bytes: &[u8]) -> Value {
    text(hex(bytes))
}
fn count(value: usize) -> Value {
    number(value as u64)
}
fn optional<T>(value: Option<T>, encode: impl FnOnce(T) -> Value) -> Value {
    value.map_or(Value::Null, encode)
}
fn token(id: &InternalObjectId) -> Value {
    text(format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    ))
}
fn digest(value: Digest) -> Value {
    text(format!(
        "alg:{}:{}",
        value.algorithm().code_point(),
        hex(value.bytes().as_bytes())
    ))
}
fn generation(value: &GenerationActivation) -> Value {
    object([
        ("token", token(value.generation_id.as_internal_object_id())),
        ("number", text(value.authority_generation.get().to_string())),
    ])
}
fn list_bytes(values: &[Vec<u8>]) -> Value {
    Value::Array(values.iter().map(|value| bytes(value)).collect())
}
fn labels(values: &[[u8; 32]]) -> Value {
    Value::Array(values.iter().map(|value| bytes(value)).collect())
}

pub(super) fn intent(input: &AgentContextRequest<'_>) -> Value {
    let symbols = input
        .query
        .symbols()
        .map_or(Value::Null, |(query, policy)| {
            object([
                ("name_hex", bytes(query.name())),
                (
                    "match",
                    text(match query.mode() {
                        SymbolMatchMode::Exact => "exact",
                        SymbolMatchMode::Prefix => "prefix",
                    }),
                ),
                (
                    "policy",
                    text(match policy {
                        SymbolPolicy::Required => "required",
                        SymbolPolicy::Optional => "optional",
                    }),
                ),
                (
                    "kinds",
                    Value::Array(
                        query
                            .kinds()
                            .iter()
                            .map(|kind| text(kind.as_str()))
                            .collect(),
                    ),
                ),
            ])
        });
    object([
        ("profile", text(profile(input))),
        ("sponsor_id", text(input.sponsor.to_string())),
        (
            "sponsor_authentication",
            text(sponsor_authentication(input)),
        ),
        ("authorization_host", text(input.authorization.host())),
        ("reference_hex", bytes(input.reference.as_bytes())),
        ("terms_hex", list_bytes(input.query.content().terms())),
        (
            "path_prefixes_hex",
            list_bytes(input.query.content().prefixes()),
        ),
        ("symbols", symbols),
        (
            "expected_head",
            optional(input.expected_head, |head| {
                token(head.as_internal_object_id())
            }),
        ),
        (
            "minimum_lexical_generation",
            optional(input.checkpoints.lexical.as_ref(), generation),
        ),
        (
            "minimum_symbol_generation",
            optional(input.checkpoints.symbols.as_ref(), generation),
        ),
        (
            "lifetime_nanos",
            text(input.expires_after.as_nanos().to_string()),
        ),
        (
            "limits",
            object([
                (
                    "max_results_per_channel",
                    count(input.retrieval_limits.max_results_per_channel),
                ),
                ("max_work", number(input.retrieval_limits.max_work)),
                (
                    "max_index_payload_bytes",
                    count(input.retrieval_limits.max_payload_bytes),
                ),
                (
                    "max_result_bytes",
                    count(input.retrieval_limits.max_result_bytes),
                ),
                ("max_files", count(input.context_limits.max_files)),
                ("radius_bytes", count(input.context_limits.radius_bytes)),
                (
                    "max_source_bytes",
                    count(input.context_limits.max_source_bytes),
                ),
                (
                    "max_excerpt_bytes",
                    count(input.context_limits.max_excerpt_bytes),
                ),
                ("max_output_bytes", count(input.max_output_bytes)),
            ]),
        ),
    ])
}
fn source(value: &LexicalSource) -> Value {
    object([
        ("tenant_id", text(value.namespace.tenant.to_string())),
        (
            "repository_id",
            text(value.namespace.repository.to_string()),
        ),
        (
            "incarnation_id",
            text(value.namespace.incarnation.to_string()),
        ),
        (
            "object_format",
            text(value.namespace.object_format.as_str()),
        ),
        ("reference_hex", bytes(value.reference.as_bytes())),
        ("head", token(value.source_head.as_internal_object_id())),
        (
            "repository_commit",
            token(value.source_rcr.as_internal_object_id()),
        ),
        ("forge_position_root", digest(value.forge_position_root)),
        ("commit", text(value.commit.to_string())),
        ("tree", text(value.tree.to_string())),
    ])
}
fn lexical(
    value: &IndexedLexicalReport,
    live: &mut impl FnMut() -> Result<(), String>,
) -> Result<Value, String> {
    value
        .validate_coverage()
        .map_err(|error| error.to_string())?;
    let mut omissions = Vec::new();
    for row in &value.omissions {
        live()?;
        omissions.push(object([
            ("path_hex", bytes(&row.path)),
            ("blob", text(row.blob.to_string())),
            ("source_bytes", count(row.source_bytes)),
            ("reason", text(row.reason.as_str())),
            ("limit", count(row.limit)),
        ]));
    }
    Ok(object([
        ("generation", generation(&value.generation)),
        (
            "selected_generation_head",
            generation(&value.selected_generation_head),
        ),
        ("matches_returned", count(value.results.hits.len())),
        ("complete", Value::Bool(value.results.complete)),
        (
            "next_after",
            optional(value.results.next_after, |n| text(n.to_string())),
        ),
        ("coverage_complete", Value::Bool(value.coverage_complete)),
        ("index_omissions", Value::Array(omissions)),
        ("indexed_documents", count(value.indexed_documents)),
        ("indexed_source_bytes", count(value.indexed_source_bytes)),
        ("non_regular_entries", count(value.non_regular_entries)),
        ("payload_bytes_read", count(value.payload_bytes_read)),
        ("generation_bytes_read", count(value.generation_bytes_read)),
        ("work_units", number(value.results.work_units)),
    ]))
}
fn symbols(
    value: &SymbolChannel,
    live: &mut impl FnMut() -> Result<(), String>,
) -> Result<Value, String> {
    match value {
        SymbolChannel::NotRequested => Ok(object([("status", text("not_requested"))])),
        SymbolChannel::Unavailable(reason) => Ok(object([
            ("status", text("omitted")),
            (
                "reason",
                text(match reason {
                    SymbolUnavailable::Uninitialized => "uninitialized",
                    SymbolUnavailable::Stale => "stale",
                }),
            ),
        ])),
        SymbolChannel::Available(value) => {
            value
                .validate_coverage()
                .map_err(|error| error.to_string())?;
            let mut omissions = Vec::new();
            for row in &value.omissions {
                live()?;
                omissions.push(object([
                    ("path_hex", bytes(&row.path)),
                    ("blob", text(row.blob.to_string())),
                    ("source_bytes", count(row.source_bytes)),
                    ("reason", text(row.reason.as_str())),
                    ("byte_offset", optional(row.byte_offset, count)),
                    ("limit", optional(row.limit, count)),
                ]));
            }
            Ok(object([
                ("status", text("available")),
                ("generation", token(&value.generation)),
                (
                    "generation_number",
                    text(value.generation_number.to_string()),
                ),
                ("matches_returned", count(value.matches.len())),
                ("complete", Value::Bool(value.complete)),
                ("coverage_complete", Value::Bool(value.coverage_complete)),
                ("index_omissions", Value::Array(omissions)),
                (
                    "unsupported_language_files",
                    count(value.unsupported_language_files),
                ),
                ("non_regular_entries", count(value.non_regular_entries)),
                ("payload_bytes_read", count(value.payload_bytes_read)),
                ("work_units", number(value.work_units)),
            ]))
        }
    }
}

/// This evidence body has no executable/source-text fields. Raw paths remain
/// byte strings, and every source excerpt is separately retained below.
pub(super) fn evidence(
    context: &InitialContext,
    live: &mut impl FnMut() -> Result<(), String>,
) -> Result<Value, String> {
    let initial = context.retrieval();
    let mut files = Vec::new();
    for file in context.files() {
        live()?;
        let anchors = file
            .anchors()
            .iter()
            .zip(file.anchor_authorization_labels())
            .map(|(anchor, label)| {
                object([
                    ("channel", text(anchor.channel.as_str())),
                    ("position_domain", text(anchor.channel.position_domain())),
                    ("byte_offset", count(anchor.byte_offset)),
                    ("byte_length", count(anchor.byte_length)),
                    ("authorization_label", bytes(label)),
                ])
            })
            .collect();
        files.push(object([
            ("path_hex", bytes(file.path())),
            ("blob", text(file.blob().to_string())),
            ("source_bytes", count(file.source_bytes())),
            ("authorization_labels", labels(file.authorization_labels())),
            ("lineage_commitment", bytes(file.lineage_commitment())),
            ("anchors", Value::Array(anchors)),
            (
                "excerpt_windows",
                Value::Array(
                    file.excerpts()
                        .iter()
                        .map(|span| {
                            object([
                                ("byte_offset", count(span.offset())),
                                ("byte_length", count(span.untrusted_bytes().len())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]));
    }
    Ok(object([
        ("profile", text("agent-context-evidence-v1")),
        ("source", source(initial.source())),
        (
            "authorization_binding",
            bytes(initial.authorization().binding()),
        ),
        ("authorization_host", text(initial.authorization().host())),
        ("authorization_scope", text("whole-repository")),
        ("reusable_capability", Value::Bool(false)),
        (
            "lexical_generation",
            generation(&initial.generations().lexical),
        ),
        (
            "symbol_generation",
            optional(initial.generations().symbols.as_ref(), generation),
        ),
        ("content_channel", lexical(initial.content(), live)?),
        ("path_channel", lexical(initial.path(), live)?),
        ("symbol_channel", symbols(initial.symbols(), live)?),
        ("complete", Value::Bool(context.complete())),
        (
            "coverage_meaning",
            text(
                "all requested channels complete and every returned match hydrated; excerpts do not claim whole-file or repository completeness",
            ),
        ),
        ("selection", text("raw-path-prefix")),
        ("candidate_files", count(context.candidate_files())),
        ("omitted_candidate_files", count(context.omitted_files())),
        ("source_bytes_read", count(context.source_bytes_read())),
        ("excerpt_bytes", count(context.excerpt_bytes())),
        ("source_file_limit", count(context.source_file_limit())),
        (
            "lineage_metadata_bytes",
            count(context.lineage_metadata_bytes()),
        ),
        ("result_bytes", count(initial.result_bytes())),
        ("files", Value::Array(files)),
    ]))
}

fn receipt(value: &AuthorityReadReceipt) -> Result<Value, String> {
    Ok(object([
        (
            "receipt_id",
            text(
                value
                    .receipt_id()
                    .map_err(|error| error.to_string())?
                    .to_string(),
            ),
        ),
        ("repository_id", text(value.repository_id().to_string())),
        (
            "head",
            token(value.authority_head_id().as_internal_object_id()),
        ),
        (
            "generation",
            text(value.authority_head_generation().get().to_string()),
        ),
        (
            "backend_version_token",
            bytes(&value.backend_version_token().to_opaque_bytes()),
        ),
        (
            "decision_batch",
            optional(value.latest_decision_batch_id(), |id| {
                token(id.as_internal_object_id())
            }),
        ),
        (
            "repository_sequence",
            optional(value.latest_repository_sequence(), |n| {
                text(n.get().to_string())
            }),
        ),
        (
            "repository_commit",
            optional(value.latest_repository_commit_id(), |id| {
                token(id.as_internal_object_id())
            }),
        ),
        ("ref_root", digest(value.ref_root())),
        ("forge_position_root", digest(value.forge_position_root())),
        ("retention_root", digest(value.retention_root())),
        ("policy_epoch", text(value.policy_epoch().get().to_string())),
        ("format_epoch", text(value.format_epoch().get().to_string())),
        (
            "verified_at_logical_time",
            text(value.verified_at_logical_time().value().to_string()),
        ),
        (
            "logical_clock",
            text("unix-nanoseconds-plus-monotonic-elapsed-v1"),
        ),
        ("verifier_profile", bytes(&value.verifier_profile())),
    ]))
}

pub(super) fn document(
    input: &AgentContextRequest<'_>,
    run: &IntentRun,
    packet: &ContextPacket,
    intent: Value,
    evidence: Value,
    evidence_commitment: [u8; 32],
    context: &InitialContext,
    live: &mut impl FnMut() -> Result<(), String>,
) -> Result<Value, String> {
    let mut sources = Vec::new();
    let mut originals = packet.sources().iter();
    for file in context.files() {
        for span in file.excerpts() {
            live()?;
            let original = originals
                .next()
                .ok_or("agent packet source count mismatch")?;
            if original.untrusted_bytes() != span.untrusted_bytes() {
                return Err("agent packet source bytes mismatch".into());
            }
            sources.push(object([
                ("source_commitment", bytes(&original.identity_commitment())),
                ("channel", text("exact")),
                ("path_hex", bytes(file.path())),
                ("blob", text(file.blob().to_string())),
                ("byte_offset", count(span.offset())),
                ("byte_length", count(span.untrusted_bytes().len())),
                ("untrusted_bytes_hex", bytes(span.untrusted_bytes())),
                (
                    "untrusted_utf8",
                    optional(std::str::from_utf8(span.untrusted_bytes()).ok(), text),
                ),
                ("lineage_commitment", bytes(file.lineage_commitment())),
                ("authorization_labels", labels(file.authorization_labels())),
            ]));
        }
    }
    if originals.next().is_some() {
        return Err("agent packet source count mismatch".into());
    }
    let complete = context.complete();
    let document = object([
        ("type", text("agent_context")),
        ("schema_version", number(1)),
        ("profile", text(profile(input))),
        ("complete", Value::Bool(complete)),
        ("read_only", Value::Bool(true)),
        ("publication_authorized", Value::Bool(false)),
        ("run_persistence", text("invocation-only")),
        (
            "sponsor",
            object([
                ("principal_id", text(input.sponsor.to_string())),
                ("authentication", text(sponsor_authentication(input))),
                ("authorization_host", text(input.authorization.host())),
            ]),
        ),
        (
            "run",
            object([
                ("id", text(run.run_id().to_string())),
                (
                    "commitment",
                    text(
                        run.commitment()
                            .map_err(|error| error.to_string())?
                            .to_string(),
                    ),
                ),
                (
                    "expires_at_logical_time",
                    text(run.expiry().value().to_string()),
                ),
                (
                    "allowed_operations",
                    Value::Array(vec![
                        text("read_canonical_object"),
                        text("read_derived_generation"),
                    ]),
                ),
                (
                    "budget",
                    object([
                        ("bytes", number(run.resource_budget().get(Grade::Bytes))),
                        (
                            "egress_bytes",
                            number(run.resource_budget().get(Grade::EgressBytes)),
                        ),
                        (
                            "meaning",
                            text(
                                "single-invocation payload/result envelopes; authority and codec work retains native finite budgets",
                            ),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            "authority_receipt",
            receipt(packet.authority_read_receipt())?,
        ),
        ("request", intent),
        (
            "context_packet",
            object([
                ("packet_id", bytes(packet.packet_id().as_bytes())),
                (
                    "request_intent_commitment",
                    bytes(&packet.control().request_intent_commitment()),
                ),
                (
                    "ranking_and_fusion_identity",
                    bytes(&packet.control().ranking_and_fusion_identity()),
                ),
                (
                    "coverage_claims",
                    labels(packet.control().coverage_claims()),
                ),
                (
                    "omission_commitments",
                    labels(packet.control().omission_commitments()),
                ),
                ("source_count", count(packet.sources().len())),
            ]),
        ),
        ("retrieval_evidence", evidence),
        ("evidence_commitment", bytes(&evidence_commitment)),
        ("untrusted_sources", Value::Array(sources)),
    ]);
    // The owner encodes once against the caller's exact finite byte bound.
    // Keeping the value private means no partially encoded packet escapes.
    live()?;
    Ok(document)
}
