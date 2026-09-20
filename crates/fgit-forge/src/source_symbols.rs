//! Bounded Rust declaration retrieval over one verified, capability-visible
//! tree. This is the `rust-declaration-heads-v1` initial retrieval channel, not a
//! compiler symbol graph, persistent symbol index or authorization authority.
mod engine;
pub use engine::{Error as SymbolSyntaxError, ErrorKind as SymbolSyntaxErrorKind,
    Kind as SymbolKind, MAX_WORK as MAX_SYMBOL_WORK};
use crate::source_search::{Discovery, DiscoveryContext, SearchCase, SearchCompletion,
    SearchError, SearchLimits, SourceMatch, SourceQuery, SourceSearchReport, discover};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity};
use fgit_treefs::{BaseView, ObjectSource, TreeCapability};
use fgit_types::{GitHashAlgorithm as Format, GitOid, RepositoryCommitId, RepositoryId};
use std::collections::BTreeMap;

pub const PROFILE: &str = "rust-declaration-heads-v1";
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolMatchMode { Exact, Prefix }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolQuery {
    name: Vec<u8>, mode: SymbolMatchMode, kinds: Vec<SymbolKind>,
    scope: SourceQuery, maximum_work: u64,
}
impl SymbolQuery {
    pub fn new(name: &[u8], mode: SymbolMatchMode, kinds: &[SymbolKind], prefixes: &[Vec<u8>], maximum_work: u64) -> Result<Self, SearchError> {
        if name.is_empty() || name.len() > engine::MAX_NAME_BYTES || !(name[0].is_ascii_alphabetic() || name[0] == b'_')
            || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') || kinds.len() > 8
            || maximum_work == 0 || maximum_work > MAX_SYMBOL_WORK
        { return Err(SearchError::InvalidQuery); }
        let mut kinds = kinds.to_vec(); kinds.sort_by_key(|k| k.as_str()); kinds.dedup();
        Ok(Self { name: name.to_vec(), mode, kinds, scope: SourceQuery::new(b"\0", SearchCase::Exact, prefixes)?, maximum_work })
    }
    #[must_use] pub fn name(&self) -> &[u8] { &self.name }
    #[must_use] pub const fn mode(&self) -> SymbolMatchMode { self.mode }
    #[must_use] pub fn kinds(&self) -> &[SymbolKind] { &self.kinds }
    #[must_use] pub const fn source_scope(&self) -> &SourceQuery { &self.scope }
    #[must_use] pub const fn maximum_work(&self) -> u64 { self.maximum_work }
    fn accepts(&self, name: &[u8], kind: SymbolKind) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&kind)) && match self.mode {
            SymbolMatchMode::Exact => name == self.name, SymbolMatchMode::Prefix => name.starts_with(&self.name),
        }
    }
}
/// Source/authority failures retain their owning error type. Unsupported or
/// malformed source is not an invalid query and never an empty answer.
#[derive(Debug)]
pub enum SymbolReadError<E> { Source(E), Syntax { path: Vec<u8>, error: SymbolSyntaxError } }
impl<E> SymbolReadError<E> {
    pub fn map_source<F>(self, map: impl FnOnce(E) -> F) -> SymbolReadError<F> {
        match self { Self::Source(e) => SymbolReadError::Source(map(e)), Self::Syntax {path,error} => SymbolReadError::Syntax {path,error} }
    }
}
impl<E> From<E> for SymbolReadError<E> { fn from(e: E) -> Self { Self::Source(e) } }
impl<E: std::fmt::Display> std::fmt::Display for SymbolReadError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Source(e) => std::fmt::Display::fmt(e,f), Self::Syntax {error,..} => std::fmt::Display::fmt(error,f) }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for SymbolReadError<E> {}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolMatch {
    pub name: Vec<u8>, pub kind: SymbolKind, pub raw_identifier: bool, pub location: SourceMatch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolSearchReport {
    pub repository: RepositoryId, pub source_rcr: RepositoryCommitId,
    pub source_commit: GitOid, pub source_tree: GitOid, pub matches: Vec<SymbolMatch>,
    pub completion: SearchCompletion, pub files_selected: usize, pub files_read: usize,
    pub bytes_read: usize, pub bytes_searched: usize, pub non_regular_entries: usize,
    pub unsupported_language_files: usize, pub declarations_examined: usize,
    pub macro_bodies_skipped: usize, pub attributes_skipped: usize, pub work_units: u64,
}
impl SymbolSearchReport {
    /// For the node's authenticated empty-tree selection; this constructs no
    /// authorization and is not used to suppress an unavailable source.
    #[must_use]
    pub fn empty(source: SourceSearchReport) -> Self {
        Self { repository: source.repository, source_rcr: source.source_rcr, source_commit: source.source_commit,
            source_tree: source.source_tree, matches: Vec::new(), completion: SearchCompletion::Complete,
            files_selected: 0, files_read: 0, bytes_read: 0, bytes_searched: 0, non_regular_entries: 0,
            unsupported_language_files: 0, declarations_examined: 0, macro_bodies_skipped: 0,
            attributes_skipped: 0, work_units: 0 }
    }
}
fn checkpoint(cancelled: &dyn Fn() -> bool) -> Result<(), SearchError> {
    if cancelled() { Err(SearchError::Cancelled) } else { Ok(()) }
}
fn oid<A: GitHashAlgorithm>(id: &fgit_crypto::GitOid<A>) -> Result<GitOid, SearchError> {
    let format = match A::DIGEST_LEN {20 => Format::Sha1,32 => Format::Sha256,_ => return Err(SearchError::InvalidObjectFormat)};
    let hex: String = id.digest_bytes().iter().map(|b|format!("{b:02x}")).collect();
    GitOid::from_hex(format,&hex).map_err(|_|SearchError::InvalidObjectFormat)
}

/// Inspect `.rs` regular files only, inside BOTH capability and query scope.
/// Every read is verified and charged. Names/kinds use exact bytes; no Unicode
/// normalization, semantic expansion, compiler execution or network lookup.
/// All counters and spans come from this one immutable TreeFS selection.
pub fn search_source_symbols<A: GitHashAlgorithm,S: ObjectSource<A>>(
    base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
    query: &SymbolQuery, limits: SearchLimits, cancelled: &dyn Fn() -> bool,
) -> Result<SymbolSearchReport,SymbolReadError<SearchError>> {
    limits.validate()?; checkpoint(cancelled)?;
    capability.authorize_root(now).map_err(SearchError::Capability)?;
    let mut discovery=Discovery { files:BTreeMap::new(),entries:0,excluded:0 };
    let mut context=DiscoveryContext {base,source,capability,now,query:&query.scope,limits,cancelled};
    discover(&mut context,None,0,&mut discovery)?;
    let mut report=SymbolSearchReport::empty(SourceSearchReport {
        repository:base.repository_id(),source_rcr:base.base_rcr_id(),source_commit:oid::<A>(base.base_commit_oid())?,
        source_tree:oid::<A>(base.base_tree_oid())?,matches:Vec::new(),completion:SearchCompletion::Complete,
        files_selected:0,files_read:0,bytes_read:0,bytes_searched:0,non_regular_entries:0,
    });
    report.files_selected=discovery.files.len(); report.non_regular_entries=discovery.excluded;
    report.unsupported_language_files=discovery.files.keys().filter(|p|!p.as_bytes().ends_with(b".rs")).count();
    let mut files:Vec<_>=discovery.files.into_iter().collect();files.sort_by(|a,b|a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut budget=engine::Budget::new(query.maximum_work).map_err(|_|SearchError::InvalidQuery)?;
    let mut result_bytes=0usize;
    'files: for (path,blob) in files {
        checkpoint(cancelled)?;
        if !path.as_bytes().ends_with(b".rs") { continue; }
        let grant=capability.authorize_read(&path,now).map_err(SearchError::Capability)?;
        let body=base.read_object(source,&blob,GitObjectKind::Blob,&grant).map_err(|e|SearchError::Source(Box::new(e)))?;
        capability.charge_fetch(body.len()as u64).map_err(SearchError::Capability)?;checkpoint(cancelled)?;
        if body.len()>limits.max_file_bytes {return Err(SearchError::Budget("symbol file bytes").into());}
        report.bytes_read=report.bytes_read.checked_add(body.len()).filter(|n|*n<=limits.max_total_bytes).ok_or(SearchError::Budget("symbol total bytes"))?;
        report.files_read+=1;let blob=oid::<A>(&blob)?;
        let scanned=engine::extract(&body,&mut budget,cancelled).map_err(|error|SymbolReadError::Syntax {path:path.as_bytes().to_vec(),error})?;
        report.bytes_searched+=body.len();report.macro_bodies_skipped+=scanned.macro_bodies_skipped;
        report.attributes_skipped+=scanned.attributes_skipped;
        for declaration in scanned.declarations {
            checkpoint(cancelled)?;
            let start=declaration.byte_offset;let end=start+declaration.byte_length;let name=&body[start..end];
            if !query.accepts(name,declaration.kind) {continue;}
            if report.matches.len()==limits.max_matches {report.completion=SearchCompletion::MatchLimit;break 'files;}
            let line_start=start-(declaration.byte_column-1);
            let excerpt_offset=line_start.max(start.saturating_sub(80));
            let upper=body.len().min(end.saturating_add(80));
            let excerpt_end=body[end..upper].iter().position(|b|*b==b'\n').map_or(upper,|n|end+n);
            result_bytes=result_bytes.checked_add(path.as_bytes().len()+name.len()+excerpt_end-excerpt_offset)
                .filter(|n|*n<=MAX_RESULT_BYTES).ok_or(SearchError::Budget("symbol result bytes"))?;
            report.matches.push(SymbolMatch {name:name.to_vec(),kind:declaration.kind,raw_identifier:declaration.raw_identifier,
                location:SourceMatch {path:path.as_bytes().to_vec(),blob,byte_offset:start,line:declaration.line,
                    byte_column:declaration.byte_column,match_length:declaration.byte_length,excerpt_offset,
                    excerpt:body[excerpt_offset..excerpt_end].to_vec()}});
        }
    }
    checkpoint(cancelled)?;report.work_units=budget.work;report.declarations_examined=budget.declarations;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_profiles_are_closed_bounded_case_sensitive_and_byte_preserving() {
        let query=SymbolQuery::new(b"Thing",SymbolMatchMode::Prefix,&[SymbolKind::Struct,SymbolKind::Struct],&[b"src".to_vec()],MAX_SYMBOL_WORK).unwrap();
        assert_eq!(query.kinds(),&[SymbolKind::Struct]);assert!(query.accepts(b"ThingMore",SymbolKind::Struct));
        assert!(!query.accepts(b"thing",SymbolKind::Struct));assert!(!query.accepts(b"Thing",SymbolKind::Function));
        for name in [b"".as_slice(),b"r#thing",b"1thing",b"a.b",b"\xff",&[b'x';129]] {
            assert!(SymbolQuery::new(name,SymbolMatchMode::Exact,&[],&[],MAX_SYMBOL_WORK).is_err());
        }
        for work in [0,MAX_SYMBOL_WORK+1] {assert!(SymbolQuery::new(b"x",SymbolMatchMode::Exact,&[],&[],work).is_err());}
        assert!(SymbolQuery::new(b"x",SymbolMatchMode::Exact,&[],&[b"../private".to_vec()],MAX_SYMBOL_WORK).is_err());
    }
}
