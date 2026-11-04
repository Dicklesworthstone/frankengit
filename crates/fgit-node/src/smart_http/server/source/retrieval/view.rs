//! Borrowed presentation view. Exact and revalidated reports keep their own
//! private constructors and validators; no index provenance is rewritten.
use super::*;
use crate::source_retrieval::GenerationVector;
use crate::source_retrieval::current_index::initial::{
    PROFILE as CURRENT_PROFILE, RevalidatedInitialReport,
};
use fgit_graph::lexical::{IndexedLexicalReport, LexicalSource};

#[derive(Clone, Copy)]
pub(super) enum InitialView<'a> {
    Exact(&'a InitialReport),
    Current(&'a RevalidatedInitialReport),
}

impl<'a> InitialView<'a> {
    pub(super) fn matches(self, mode: IndexSource) -> bool {
        matches!(
            (self, mode),
            (Self::Exact(_), IndexSource::Exact) | (Self::Current(_), IndexSource::Current)
        )
    }
    pub(super) fn profile(self) -> &'static str {
        match self {
            Self::Exact(_) => PROFILE,
            Self::Current(_) => CURRENT_PROFILE,
        }
    }
    pub(super) fn source(self) -> &'a LexicalSource {
        match self {
            Self::Exact(report) => report.source(),
            Self::Current(report) => report.current_source(),
        }
    }
    pub(super) fn content(self) -> &'a IndexedLexicalReport {
        match self {
            Self::Exact(report) => report.content(),
            Self::Current(report) => report.content(),
        }
    }
    pub(super) fn path(self) -> &'a IndexedLexicalReport {
        match self {
            Self::Exact(report) => report.path(),
            Self::Current(report) => report.path(),
        }
    }
    pub(super) fn symbols(self) -> &'a SymbolChannel {
        match self {
            Self::Exact(report) => report.symbols(),
            Self::Current(report) => report.symbols(),
        }
    }
    pub(super) fn generations(self) -> &'a GenerationVector {
        match self {
            Self::Exact(report) => report.generations(),
            Self::Current(report) => report.generations(),
        }
    }
    pub(super) fn complete(self) -> bool {
        match self {
            Self::Exact(report) => report.complete(),
            Self::Current(report) => report.complete(),
        }
    }
    pub(super) fn result_bytes(self) -> usize {
        match self {
            Self::Exact(report) => report.result_bytes(),
            Self::Current(report) => report.result_bytes(),
        }
    }
    pub(super) fn completed_payload_bytes_read(self) -> usize {
        match self {
            Self::Exact(report) => report.completed_payload_bytes_read(),
            Self::Current(report) => report.completed_payload_bytes_read(),
        }
    }
    pub(super) fn completed_work_units(self) -> u64 {
        match self {
            Self::Exact(report) => report.completed_work_units(),
            Self::Current(report) => report.completed_work_units(),
        }
    }
    pub(super) fn validate_labels(
        self,
        read: &SourceReadContext,
        labels: &InitialAuthorization,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        match self {
            Self::Exact(report) => labels.validate(read, report, live),
            Self::Current(report) => labels.validate_revalidated(read, report, live),
        }
    }
    pub(super) fn append_provenance(
        self,
        out: &mut String,
        maximum: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), ApiError> {
        let Self::Current(report) = self else {
            return Ok(());
        };
        check(live)?;
        append(
            out,
            "\"index_source\":\"current-native-v1\",\"current_source\":",
            maximum,
        )?;
        append(out, &source_json(report.current_source()), maximum)?;
        append(out, ",\"index_sources\":{\"lexical\":", maximum)?;
        append(out, &source_json(&report.content().source), maximum)?;
        append(out, ",\"symbols\":", maximum)?;
        let symbols = match report.symbols() {
            SymbolChannel::Available(symbols) => symbol_source_json(&symbols.source),
            SymbolChannel::NotRequested | SymbolChannel::Unavailable(_) => "null".into(),
        };
        append(out, &symbols, maximum)?;
        append(out, "},", maximum)?;
        check(live)
    }
}

fn source_json(source: &LexicalSource) -> String {
    format!(
        concat!(
            "{{\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},",
            "\"object_format\":{},{},\"source_head\":{},\"snapshot_token\":{},",
            "\"source_rcr\":{},\"forge_position_root\":{},\"source_commit\":{},\"root_tree\":{}}}"
        ),
        quote(&source.namespace.tenant.to_string()),
        quote(&source.namespace.repository.to_string()),
        quote(&source.namespace.incarnation.to_string()),
        quote(source.namespace.object_format.as_str()),
        ref_fields("ref", &source.reference),
        quote(&source.source_head.to_string()),
        quote(&token(source.source_head.as_internal_object_id())),
        quote(&source.source_rcr.to_string()),
        quote(&source.forge_position_root.to_string()),
        quote(&source.commit.to_string()),
        quote(&source.tree.to_string()),
    )
}

fn symbol_source_json(source: &fgit_forge::source_symbols::index::Source) -> String {
    format!(
        concat!(
            "{{\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},",
            "\"object_format\":{},{},\"source_head\":{},\"snapshot_token\":{},",
            "\"source_rcr\":{},\"forge_position_root\":{},\"source_commit\":{},\"root_tree\":{}}}"
        ),
        quote(&source.tenant.to_string()),
        quote(&source.repository.to_string()),
        quote(&source.incarnation.to_string()),
        quote(source.format.as_str()),
        ref_fields("ref", &source.reference),
        quote(&source.head.to_string()),
        quote(&token(source.head.as_internal_object_id())),
        quote(&source.rcr.to_string()),
        quote(&source.forge.to_string()),
        quote(&source.commit.to_string()),
        quote(&source.tree.to_string()),
    )
}
