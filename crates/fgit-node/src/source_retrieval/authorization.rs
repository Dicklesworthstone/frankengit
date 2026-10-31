//! Disclosure labels retain a host's independently checked read scope. They
//! are derived evidence, never credentials, delegation, retention pins or proof
//! of source authenticity. No client-supplied label can authorize a read.
use super::current_index::initial::RevalidatedInitialReport;
use super::{GenerationVector, InitialReport, RetrievalError, SymbolChannel, add_result};
use crate::OneNode;
use fgit_crypto::sha256_digest;
use fgit_forge::source_symbols::SymbolMatch;
use fgit_graph::lexical::{
    IndexedLexicalReport, LexicalChannel, LexicalHit, LexicalNamespace, LexicalSource,
};
use fgit_types::PrincipalId;

pub const PROFILE: &str = "source-read-result-labels-v1";
// Retained binary commitments, their hexadecimal wire references, position
// domain and field overhead. This is additional to the original row budget.
const ROW_BYTES: usize = 192;
const DESCRIPTOR_BYTES: usize = 768;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Host {
    TrustedLocalNative,
    TrustedLocalCli,
    TrustedLocalMcp,
    HttpCredential(PrincipalId),
}

/// A host attestation for one node's whole-repository read boundary. The local
/// constructors are explicit operator authority, NOT authentication. A host
/// must check its CLI flag/MCP grant before constructing one. Query prefixes
/// only narrow selection; they never become sparse capability grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReadContext {
    namespace: LexicalNamespace,
    host: Host,
}
impl SourceReadContext {
    const fn new(node: &OneNode, host: Host) -> Self {
        Self {
            namespace: LexicalNamespace {
                tenant: node.tenant_id,
                repository: node.repository_id,
                incarnation: node.repository_incarnation_id(),
                object_format: node.object_format,
            },
            host,
        }
    }
    /// Explicit whole-repository read authority supplied by a trusted local
    /// embedding. This is an operator attestation, not authentication.
    #[must_use]
    pub const fn trusted_local_native(node: &OneNode) -> Self {
        Self::new(node, Host::TrustedLocalNative)
    }
    /// Call only after this invocation's explicit trusted-local CLI opt-in.
    #[must_use]
    pub const fn trusted_local_cli(node: &OneNode) -> Self {
        Self::new(node, Host::TrustedLocalCli)
    }
    /// Call only after this launch's trusted-local MCP source-tool grant.
    #[must_use]
    pub const fn trusted_local_mcp(node: &OneNode) -> Self {
        Self::new(node, Host::TrustedLocalMcp)
    }
    // The source gateway retains this only after route/credential/UploadPack
    // and allow_source checks. An authenticated mutation session is insufficient.
    pub(crate) const fn http_credential(node: &OneNode, principal: PrincipalId) -> Self {
        Self::new(node, Host::HttpCredential(principal))
    }
    pub(crate) fn check_node(&self, node: &OneNode) -> Result<(), RetrievalError> {
        if self.namespace != Self::new(node, self.host.clone()).namespace {
            return Err(RetrievalError::Invalid("source read context namespace"));
        }
        Ok(())
    }
    #[must_use]
    pub const fn host(&self) -> &'static str {
        match self.host {
            Host::TrustedLocalNative => "trusted-local-native",
            Host::TrustedLocalCli => "trusted-local-cli",
            Host::TrustedLocalMcp => "trusted-local-mcp",
            Host::HttpCredential(_) => "http-repository-read-credential",
        }
    }
    #[must_use]
    pub const fn principal(&self) -> Option<PrincipalId> {
        match self.host {
            Host::HttpCredential(principal) => Some(principal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum InitialSourceMode {
    Exact,
    Revalidated,
}

/// Borrowed construction/validation input. It does not own, publish, authorize
/// or rewrite a source. Native readers retain each original provenance.
pub(crate) struct InitialLabelInput<'a> {
    disclosure: &'a LexicalSource,
    content: &'a IndexedLexicalReport,
    path: &'a IndexedLexicalReport,
    symbols: &'a SymbolChannel,
    vector: &'a GenerationVector,
    mode: InitialSourceMode,
}
impl<'a> InitialLabelInput<'a> {
    pub(crate) const fn exact(
        content: &'a IndexedLexicalReport,
        path: &'a IndexedLexicalReport,
        symbols: &'a SymbolChannel,
        vector: &'a GenerationVector,
    ) -> Self {
        Self {
            disclosure: &content.source,
            content,
            path,
            symbols,
            vector,
            mode: InitialSourceMode::Exact,
        }
    }
    pub(crate) const fn revalidated(
        disclosure: &'a LexicalSource,
        content: &'a IndexedLexicalReport,
        path: &'a IndexedLexicalReport,
        symbols: &'a SymbolChannel,
        vector: &'a GenerationVector,
    ) -> Self {
        Self {
            disclosure,
            content,
            path,
            symbols,
            vector,
            mode: InitialSourceMode::Revalidated,
        }
    }
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}
fn number(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn append_source(out: &mut Vec<u8>, source: &LexicalSource) {
    field(out, source.namespace.tenant.as_bytes());
    field(out, source.namespace.repository.as_bytes());
    field(out, source.namespace.incarnation.as_bytes());
    field(out, source.namespace.object_format.as_str().as_bytes());
    field(out, source.reference.as_bytes());
    for value in [
        source.source_head.to_string(),
        source.source_rcr.to_string(),
        source.forge_position_root.to_string(),
        source.commit.to_string(),
        source.tree.to_string(),
    ] {
        field(out, value.as_bytes());
    }
}
fn symbol_source(source: &fgit_forge::source_symbols::index::Source) -> LexicalSource {
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: source.tenant,
            repository: source.repository,
            incarnation: source.incarnation,
            object_format: source.format,
        },
        reference: source.reference.clone(),
        source_head: source.head,
        source_rcr: source.rcr,
        forge_position_root: source.forge,
        commit: source.commit,
        tree: source.tree,
    }
}
fn source_binding(
    context: &SourceReadContext,
    input: &InitialLabelInput<'_>,
) -> Result<[u8; 32], RetrievalError> {
    if input.disclosure.namespace != context.namespace {
        return Err(RetrievalError::MixedSource);
    }
    let mut out = b"frankengit/source-read-label-context/v1\0".to_vec();
    field(&mut out, context.host().as_bytes());
    field(
        &mut out,
        context
            .principal()
            .as_ref()
            .map_or(&[][..], |p| p.as_bytes()),
    );
    out.push(match input.mode {
        InitialSourceMode::Exact => 0,
        InitialSourceMode::Revalidated => 1,
    });
    append_source(&mut out, input.disclosure);
    append_source(&mut out, &input.content.source);
    match input.symbols {
        SymbolChannel::Available(symbols) => {
            out.push(1);
            append_source(&mut out, &symbol_source(&symbols.source));
        }
        _ => out.push(0),
    }
    field(
        &mut out,
        input.vector.lexical.generation_id.to_string().as_bytes(),
    );
    number(&mut out, input.vector.lexical.authority_generation.get());
    match &input.vector.symbols {
        Some(symbols) => {
            out.push(1);
            field(&mut out, symbols.generation_id.to_string().as_bytes());
            number(&mut out, symbols.authority_generation.get());
        }
        None => out.push(0),
    }
    Ok(sha256_digest(&out))
}
fn lexical_label(binding: &[u8; 32], channel: LexicalChannel, hit: &LexicalHit) -> [u8; 32] {
    let mut out = b"frankengit/source-read-lexical-result/v1\0".to_vec();
    out.extend_from_slice(binding);
    field(&mut out, position_domain(channel).as_bytes());
    number(&mut out, hit.document_id);
    field(&mut out, &hit.path);
    field(&mut out, hit.blob.to_string().as_bytes());
    number(&mut out, u64::from(hit.content_bytes));
    number(&mut out, hit.spans.len() as u64);
    for span in &hit.spans {
        number(&mut out, span.query_index as u64);
        number(&mut out, u64::from(span.byte_offset));
        number(&mut out, u64::from(span.byte_length));
    }
    sha256_digest(&out)
}
fn symbol_label(binding: &[u8; 32], row: &SymbolMatch) -> [u8; 32] {
    let mut out = b"frankengit/source-read-symbol-result/v1\0".to_vec();
    out.extend_from_slice(binding);
    field(&mut out, &row.name);
    field(&mut out, row.kind.as_str().as_bytes());
    out.push(u8::from(row.raw_identifier));
    let at = &row.location;
    field(&mut out, &at.path);
    field(&mut out, at.blob.to_string().as_bytes());
    for value in [
        at.byte_offset,
        at.line,
        at.byte_column,
        at.excerpt_offset,
        at.match_length,
    ] {
        number(&mut out, value as u64);
    }
    field(&mut out, &at.excerpt);
    sha256_digest(&out)
}
pub(crate) const fn position_domain(channel: LexicalChannel) -> &'static str {
    match channel {
        LexicalChannel::Content => "source-blob-bytes",
        LexicalChannel::Path => "raw-path-bytes",
    }
}

fn validate_joins(input: &InitialLabelInput<'_>) -> Result<(), RetrievalError> {
    super::check_lexical_join(input.content, input.path)?;
    if input.content.query.channel() != LexicalChannel::Content
        || input.path.query.channel() != LexicalChannel::Path
    {
        return Err(RetrievalError::Invalid("initial label channel"));
    }
    if input.vector.lexical != input.content.generation {
        return Err(RetrievalError::MixedGeneration);
    }
    let join = |original: &LexicalSource| match input.mode {
        InitialSourceMode::Exact if original != input.disclosure => {
            Err(RetrievalError::MixedSource)
        }
        InitialSourceMode::Exact => Ok(()),
        InitialSourceMode::Revalidated => {
            super::current_index::same_native_source(original, input.disclosure)
                .map_err(RetrievalError::Source)
        }
    };
    join(&input.content.source)?;
    match (input.symbols, &input.vector.symbols) {
        (SymbolChannel::Available(symbols), Some(generation)) => {
            join(&symbol_source(&symbols.source))?;
            if generation.generation_id.as_internal_object_id() != &symbols.generation
                || generation.authority_generation.get() != symbols.generation_number
            {
                return Err(RetrievalError::MixedGeneration);
            }
        }
        (SymbolChannel::Available(_), None) | (_, Some(_)) => {
            return Err(RetrievalError::MixedGeneration);
        }
        _ => {}
    }
    Ok(())
}
fn slots(count: usize) -> Result<Vec<[u8; 32]>, RetrievalError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| RetrievalError::Limit("authorization label allocation"))?;
    Ok(values)
}

/// Immutable labels retained by native Initial results. They bind the checked
/// host context and independently selected source/index provenance; they never
/// authorize another read, delegate authority or claim authenticity.
#[derive(Clone, Debug)]
pub struct InitialAuthorization {
    context: SourceReadContext,
    binding: [u8; 32],
    retained_bytes: usize,
    content: Vec<[u8; 32]>,
    path: Vec<[u8; 32]>,
    symbols: Vec<[u8; 32]>,
}
impl InitialAuthorization {
    pub(crate) fn bind(
        context: &SourceReadContext,
        input: InitialLabelInput<'_>,
        result_bytes: &mut usize,
        maximum: usize,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<Self, RetrievalError> {
        live()?;
        validate_joins(&input)?;
        let symbol_count = match input.symbols {
            SymbolChannel::Available(s) => s.matches.len(),
            _ => 0,
        };
        let content_count = input.content.results.hits.len();
        let path_count = input.path.results.hits.len();
        let count = content_count
            .checked_add(path_count)
            .and_then(|n| n.checked_add(symbol_count))
            .ok_or(RetrievalError::Limit("authorization labels"))?;
        let bytes = count
            .checked_mul(ROW_BYTES)
            .and_then(|n| n.checked_add(DESCRIPTOR_BYTES))
            .and_then(|n| n.checked_add(input.disclosure.reference.as_bytes().len()))
            .ok_or(RetrievalError::Limit("authorization labels"))?;
        // Both retained capacity and wire metadata are charged before reserve.
        add_result(result_bytes, bytes, maximum)?;
        let binding = source_binding(context, &input)?;
        let mut labels = Self {
            context: context.clone(),
            binding,
            retained_bytes: bytes,
            content: slots(content_count)?,
            path: slots(path_count)?,
            symbols: slots(symbol_count)?,
        };
        for (channel, rows, output) in [
            (
                LexicalChannel::Content,
                &input.content.results.hits,
                &mut labels.content,
            ),
            (
                LexicalChannel::Path,
                &input.path.results.hits,
                &mut labels.path,
            ),
        ] {
            for row in rows {
                live()?;
                output.push(lexical_label(&binding, channel, row));
            }
        }
        if let SymbolChannel::Available(symbols) = input.symbols {
            for row in &symbols.matches {
                live()?;
                labels.symbols.push(symbol_label(&binding, row));
            }
        }
        live()?;
        Ok(labels)
    }
    fn validate_input(
        &self,
        context: &SourceReadContext,
        input: InitialLabelInput<'_>,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        live()?;
        validate_joins(&input)?;
        if &self.context != context
            || self.binding != source_binding(context, &input)?
            || self.content.len() != input.content.results.hits.len()
            || self.path.len() != input.path.results.hits.len()
        {
            return Err(RetrievalError::Invalid("result authorization binding"));
        }
        for (channel, rows, labels) in [
            (
                LexicalChannel::Content,
                &input.content.results.hits,
                &self.content,
            ),
            (LexicalChannel::Path, &input.path.results.hits, &self.path),
        ] {
            for (row, label) in rows.iter().zip(labels) {
                live()?;
                if *label != lexical_label(&self.binding, channel, row) {
                    return Err(RetrievalError::Invalid("result authorization label"));
                }
            }
        }
        match input.symbols {
            SymbolChannel::Available(symbols) => {
                if self.symbols.len() != symbols.matches.len() {
                    return Err(RetrievalError::Invalid("symbol authorization count"));
                }
                for (row, label) in symbols.matches.iter().zip(&self.symbols) {
                    live()?;
                    if *label != symbol_label(&self.binding, row) {
                        return Err(RetrievalError::Invalid("symbol authorization label"));
                    }
                }
            }
            _ if !self.symbols.is_empty() => {
                return Err(RetrievalError::Invalid("symbol authorization state"));
            }
            _ => {}
        }
        live()
    }
    pub fn validate(
        &self,
        context: &SourceReadContext,
        report: &InitialReport,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        self.validate_input(
            context,
            InitialLabelInput::exact(
                report.content(),
                report.path(),
                report.symbols(),
                report.generations(),
            ),
            live,
        )
    }
    pub fn validate_revalidated(
        &self,
        context: &SourceReadContext,
        report: &RevalidatedInitialReport,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        self.validate_input(
            context,
            InitialLabelInput::revalidated(
                report.current_source(),
                report.content(),
                report.path(),
                report.symbols(),
                report.generations(),
            ),
            live,
        )
    }
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }
    /// Descriptor facts only: retained evidence never hands out a read context.
    #[must_use]
    pub const fn host(&self) -> &'static str {
        self.context.host()
    }
    #[must_use]
    pub const fn principal(&self) -> Option<PrincipalId> {
        self.context.principal()
    }
    #[must_use]
    pub fn lexical(&self, channel: LexicalChannel) -> &[[u8; 32]] {
        match channel {
            LexicalChannel::Content => &self.content,
            LexicalChannel::Path => &self.path,
        }
    }
    #[must_use]
    pub fn symbols(&self) -> &[[u8; 32]] {
        &self.symbols
    }
}
#[cfg(test)]
pub(super) const fn model_context(namespace: LexicalNamespace) -> SourceReadContext {
    SourceReadContext {
        namespace,
        host: Host::TrustedLocalNative,
    }
}
#[cfg(test)]
mod tests;
