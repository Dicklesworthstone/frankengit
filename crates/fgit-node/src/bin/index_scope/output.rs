//! Bounded lossless operator JSON; raw repository paths never become JSON text.
use super::options::{Options, invalid};
use fgit_graph::lexical::scoped::ScopedLexicalReport;
use fgit_graph::lexical::{LexicalChannel, LexicalRefreshStats, LexicalSource};
use fgit_graph::{GenerationActivation, GenerationRecovery, GraphGenerationId};
use fgit_types::{InternalObjectId, RepositoryIncarnationId};
use std::io;
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn token(id: &InternalObjectId) -> String {
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
struct Output(String);
impl Output {
    fn push(&mut self, value: &str) -> io::Result<()> {
        if self
            .0
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > MAX_OUTPUT)
        {
            return Err(invalid("Operator response exceeds the byte ceiling."));
        }
        self.0
            .try_reserve(value.len())
            .map_err(|_| io::Error::other("Cannot allocate operator response."))?;
        self.0.push_str(value);
        Ok(())
    }
    fn pair(&mut self, key: &str, value: &str) -> io::Result<()> {
        self.push(&format!(",{}:{}", quote(key), quote(value)))
    }
    fn number(&mut self, key: &str, value: u64) -> io::Result<()> {
        // All counters are strings so consumers never round a cursor or floor.
        self.pair(key, &value.to_string())
    }
    fn flag(&mut self, key: &str, value: bool) -> io::Result<()> {
        self.push(&format!(",{}:{value}", quote(key)))
    }
    fn paths(&mut self, key: &str, paths: &[Vec<u8>]) -> io::Result<()> {
        self.push(&format!(",{}:[", quote(key)))?;
        for (i, path) in paths.iter().enumerate() {
            if i > 0 {
                self.push(",")?;
            }
            self.push(&quote(&hex(path)))?;
        }
        self.push("]")
    }
    fn activation(&mut self, prefix: &str, value: &GenerationActivation) -> io::Result<()> {
        self.pair(
            &format!("{prefix}_token"),
            &token(value.generation_id.as_internal_object_id()),
        )?;
        self.number(
            &format!("{prefix}_number"),
            value.authority_generation.get(),
        )
    }
    fn source(&mut self, source: &LexicalSource) -> io::Result<()> {
        self.pair("source_head", &source.source_head.to_string())?;
        self.pair(
            "snapshot_token",
            &token(source.source_head.as_internal_object_id()),
        )?;
        self.pair("source_rcr", &source.source_rcr.to_string())?;
        self.pair(
            "forge_position_root",
            &source.forge_position_root.to_string(),
        )?;
        self.pair("source_commit", &source.commit.to_string())?;
        self.pair("root_tree", &source.tree.to_string())
    }
    fn finish(mut self) -> io::Result<String> {
        self.push("}\n")?;
        Ok(self.0)
    }
}
fn start(
    kind: &str,
    options: &Options,
    incarnation: RepositoryIncarnationId,
) -> io::Result<Output> {
    let mut out = Output(format!("{{\"type\":{},\"schema_version\":1", quote(kind)));
    out.pair("tenant_id", &options.tenant.to_string())?;
    out.pair("repository_id", &options.repository.to_string())?;
    out.pair("repository_incarnation", &incarnation.to_string())?;
    out.pair("object_format", options.format.as_str())?;
    out.pair("ref_hex", &hex(options.reference.as_bytes()))?;
    out.pair("coverage", "explicit-path-union")?;
    out.flag("whole_repository", false)?;
    out.paths("scope_prefixes_hex", options.scope.prefixes())?;
    out.pair("scope_sha256", &hex(options.scope.digest()))?;
    out.flag("repository_state_changed", false)?;
    Ok(out)
}
pub fn candidate(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    id: GraphGenerationId,
    predecessor: Option<GraphGenerationId>,
) -> io::Result<String> {
    let mut out = start("scoped_index_candidate", options, incarnation)?;
    out.pair("candidate", &token(id.as_internal_object_id()))?;
    out.flag("publication_evidence", false)?;
    out.flag("recorded_before_index_effects", true)?;
    if let Some(previous) = predecessor {
        out.pair(
            "predecessor_token",
            &token(previous.as_internal_object_id()),
        )?;
    }
    if let Some(head) = options.head {
        out.pair("expected_head", &token(head.as_internal_object_id()))?;
    }
    if let Some(commit) = options.commit {
        out.pair("expected_commit", &commit.to_string())?;
    }
    out.finish()
}
pub fn built(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    source: &LexicalSource,
    activation: &GenerationActivation,
) -> io::Result<String> {
    let mut out = start("scoped_index_build", options, incarnation)?;
    out.source(source)?;
    out.activation("index", activation)?;
    out.flag("index_published", true)?;
    out.flag("freshness_at_delivery_claimed", false)?;
    out.finish()
}
/// Completed native preparation counters, not a speedup or source freshness claim.
pub fn refreshed(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    source: &LexicalSource,
    activation: &GenerationActivation,
    stats: &LexicalRefreshStats,
) -> io::Result<String> {
    let mut out = start("scoped_index_refresh", options, incarnation)?;
    out.source(source)?;
    out.activation("index", activation)?;
    out.flag("index_published", true)?;
    out.flag("freshness_at_delivery_claimed", false)?;
    refresh_counts(&mut out, stats)?;
    out.finish()
}
fn refresh_counts(out: &mut Output, stats: &LexicalRefreshStats) -> io::Result<()> {
    for (key, value) in [
        ("reused_documents", stats.reused_documents),
        ("rebuilt_documents", stats.rebuilt_documents),
        ("prior_documents_not_reused", stats.prior_documents_not_reused),
        ("reused_source_bytes", stats.reused_source_bytes),
        ("rebuilt_source_bytes", stats.rebuilt_source_bytes),
        ("previous_payload_bytes_read", stats.previous_payload_bytes_read),
        ("previous_generation_bytes_read", stats.previous_generation_bytes_read),
        ("build_work_bytes", stats.build_work_bytes),
    ] {
        out.number(key, value as u64)?;
    }
    Ok(())
}
pub fn searched(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    report: &ScopedLexicalReport,
    after: Option<u64>,
) -> io::Result<String> {
    if report.scope != options.scope {
        return Err(invalid("Unexpected result scope."));
    }
    let report = &report.index;
    let mut out = start("scoped_index_search", options, incarnation)?;
    out.flag("read_only", true)?;
    out.source(&report.source)?;
    out.activation("index", &report.generation)?;
    out.activation("selected_index", &report.selected_generation_head)?;
    out.pair(
        "channel",
        match report.query.channel() {
            LexicalChannel::Content => "content",
            LexicalChannel::Path => "path",
        },
    )?;
    out.paths("terms_hex", report.query.terms())?;
    out.paths("query_prefixes_hex", report.query.prefixes())?;
    out.flag("complete_within_scope", report.results.complete)?;
    for (key, value) in [("after", after), ("next_after", report.results.next_after)] {
        match value {
            Some(value) => out.number(key, value)?,
            None => out.push(&format!(",{}:null", quote(key)))?,
        }
    }
    for (key, value) in [
        ("indexed_documents", report.indexed_documents),
        ("indexed_source_bytes", report.indexed_source_bytes),
        ("non_regular_entries", report.non_regular_entries),
        ("segments_read", report.segments_read),
        ("payload_bytes_read", report.payload_bytes_read),
        ("generation_bytes_read", report.generation_bytes_read),
    ] {
        out.number(key, value as u64)?;
    }
    out.number("work_units", report.results.work_units)?;
    out.push(",\"hits\":[")?;
    for (i, hit) in report.results.hits.iter().enumerate() {
        if i > 0 {
            out.push(",")?;
        }
        out.push(&format!(
            "{{\"document_id\":{},\"path_hex\":{},\"blob\":{},\"content_bytes\":{},\"spans\":[",
            quote(&hit.document_id.to_string()),
            quote(&hex(&hit.path)),
            quote(&hit.blob.to_string()),
            quote(&hit.content_bytes.to_string())
        ))?;
        for (j, span) in hit.spans.iter().enumerate() {
            if j > 0 {
                out.push(",")?;
            }
            out.push(&format!(
                "{{\"query_index\":{},\"byte_offset\":{},\"byte_length\":{}}}",
                quote(&span.query_index.to_string()),
                quote(&span.byte_offset.to_string()),
                quote(&span.byte_length.to_string())
            ))?;
        }
        out.push("]}")?;
    }
    out.push("]")?;
    out.finish()
}
pub fn recovered(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    id: GraphGenerationId,
    result: &GenerationRecovery,
) -> io::Result<(String, bool)> {
    let mut out = start("scoped_index_recovery", options, incarnation)?;
    out.flag("read_only", true)?;
    out.pair("candidate", &token(id.as_internal_object_id()))?;
    let (state, resolved) = match result {
        GenerationRecovery::Uninitialized => ("uninitialized", false),
        GenerationRecovery::Active { selected } => {
            out.activation("selected_index", selected.activation())?;
            ("active", true)
        }
        GenerationRecovery::Superseded {
            activation,
            selected,
        } => {
            out.activation("candidate_index", activation)?;
            out.activation("selected_index", selected.activation())?;
            ("superseded", true)
        }
        GenerationRecovery::NotInSelectedHistory { selected } => {
            out.activation("selected_index", selected.activation())?;
            ("not_in_selected_history", false)
        }
    };
    out.pair("state", state)?;
    out.flag("candidate_membership_observed", resolved)?;
    out.flag("absence_proves_cancellation", false)?;
    out.flag("freshness_at_delivery_claimed", false)?;
    Ok((out.finish()?, resolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_json_escapes_strings_and_preserves_full_u64_counters() {
        assert_eq!(quote("\"\\\n\0"), "\"\\\"\\\\\\u000a\\u0000\"");
        let mut out = Output("{".into());
        out.number("id", u64::MAX).unwrap();
        assert!(out.0.ends_with("\"id\":\"18446744073709551615\""));
    }
    #[test]
    fn refresh_counters_preserve_zeroes_and_full_width_without_fabricating_counts() {
        let stats = LexicalRefreshStats {
            reused_documents: 2,
            rebuilt_documents: 0,
            prior_documents_not_reused: 1,
            reused_source_bytes: usize::MAX,
            rebuilt_source_bytes: 0,
            previous_payload_bytes_read: 42,
            previous_generation_bytes_read: 17,
            build_work_bytes: 99,
        };
        let mut out = Output("{".into());
        refresh_counts(&mut out, &stats).unwrap();
        assert!(out.0.contains("\"reused_documents\":\"2\""));
        assert!(out.0.contains("\"rebuilt_documents\":\"0\""));
        assert!(out.0.contains("\"prior_documents_not_reused\":\"1\""));
        assert!(out.0.contains(&format!("\"reused_source_bytes\":\"{}\"", usize::MAX)));
        assert!(out.0.contains("\"rebuilt_source_bytes\":\"0\""));
        assert!(out.0.contains("\"previous_payload_bytes_read\":\"42\""));
        assert!(out.0.contains("\"previous_generation_bytes_read\":\"17\""));
        assert!(out.0.ends_with("\"build_work_bytes\":\"99\""));
        let mut full = Output("x".repeat(MAX_OUTPUT));
        assert!(refresh_counts(&mut full, &stats).is_err());
        assert_eq!(full.0.len(), MAX_OUTPUT);
    }
    #[test]
    fn output_ceiling_refuses_before_growing_the_buffer() {
        let mut out = Output("x".repeat(MAX_OUTPUT - 1));
        out.push("x").unwrap();
        assert!(out.push("x").is_err());
        assert_eq!(out.0.len(), MAX_OUTPUT);
    }
}
