//! Explicit path coverage over the existing lexical generation protocol.
//!
//! A scope selects a union of exact paths and descendants, not permissions.
//! Its complete digest is both head-key material and canonical graph-view
//! identity. Even an empty scoped index cannot impersonate a full-tree index.
//! Payload codecs and word semantics are shared; publication and selection
//! retain the original authority, cancellation, budget and recovery paths.

use super::{
    AsyncAuthorityStore, AuthorityStore, GenerationActivation, GenerationReadLimits,
    GraphGenerationId, GraphViewId, HeadKey, IndexError, IndexedLexicalReport, LexicalError,
    LexicalIndexStore, LexicalNamespace, LexicalQuery, LexicalQueryLimits, LexicalReadLimits,
    LexicalSegment, LexicalSelection, LexicalSource, MAX_SEGMENTS, PreparedLexicalIndex, RefName,
    bounded_add, check, key_prefix, path_valid,
};

mod refresh;
pub use refresh::ScopedLexicalReuse;

const MAX_PREFIXES: usize = 128;
const MAX_PREFIX_BYTES: usize = 32 * 1024;
const DOMAIN: &[u8] = b"frankengit/source-lexical-scope/v1\0";

/// Immutable canonical coverage. An empty list is deliberately not a scope:
/// callers wanting whole-tree coverage must use the existing full-index API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalScope {
    prefixes: Vec<Vec<u8>>,
    digest: [u8; 32],
}
impl LexicalScope {
    pub fn new(prefixes: &[Vec<u8>]) -> Result<Self, IndexError> {
        if prefixes.is_empty() || prefixes.len() > MAX_PREFIXES {
            return Err(LexicalError::Invalid("explicit index scope").into());
        }
        let mut bytes = 0usize;
        for path in prefixes {
            if !path_valid(path)
                || path.split(|b| *b == b'/').count() > 64
                || path
                    .split(|b| *b == b'/')
                    .any(|p| p.eq_ignore_ascii_case(b".git"))
            {
                return Err(LexicalError::Invalid("index scope path").into());
            }
            bounded_add(
                &mut bytes,
                path.len(),
                MAX_PREFIX_BYTES,
                "index scope bytes",
            )?;
        }
        // Validate before copying. Input duplicates still consume admission
        // budgets. Collapse descendants, not similarly spelled siblings.
        let mut ordered = prefixes.to_vec();
        ordered.sort();
        let mut canonical: Vec<Vec<u8>> = Vec::new();
        for path in ordered {
            if !canonical
                .iter()
                .any(|prefix| super::super::under(&path, prefix))
            {
                canonical.push(path);
            }
        }
        let mut encoded = DOMAIN.to_vec();
        encoded.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
        for prefix in &canonical {
            encoded.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
            encoded.extend_from_slice(prefix);
        }
        Ok(Self {
            prefixes: canonical,
            digest: fgit_crypto::sha256_digest(&encoded),
        })
    }
    #[must_use]
    pub fn prefixes(&self) -> &[Vec<u8>] {
        &self.prefixes
    }
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn includes(&self, path: &[u8]) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| super::super::under(path, prefix))
    }
    fn view(&self) -> Result<GraphViewId, IndexError> {
        // Lowercase base32 retains ALL 256 digest bits in a bounded ASCII slug.
        // The last digit has four zero padding bits. This is a representation,
        // not a truncated identity or a second source of authority.
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut slug = b"lx-".to_vec();
        for at in (0..256).step_by(5) {
            let mut digit = 0usize;
            for bit in at..at + 5 {
                digit <<= 1;
                if bit < 256 {
                    digit |= usize::from((self.digest[bit / 8] >> (7 - bit % 8)) & 1);
                }
            }
            slug.push(ALPHABET[digit]);
        }
        Ok(GraphViewId::try_new(&slug)?)
    }
}

/// Prepared coverage cannot be stripped and published through the full-index
/// API. As for full indexes, the caller owns complete authorized enumeration.
#[derive(Debug)]
pub struct PreparedScopedLexicalIndex {
    scope: LexicalScope,
    inner: PreparedLexicalIndex,
}
impl PreparedScopedLexicalIndex {
    pub fn new(
        source: LexicalSource,
        scope: LexicalScope,
        segments: Vec<LexicalSegment>,
        non_regular_entries: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, IndexError> {
        check(live)?;
        if segments.len() > MAX_SEGMENTS {
            return Err(LexicalError::Limit("index segments").into());
        }
        for segment in &segments {
            for document in segment.documents() {
                check(live)?;
                if !scope.includes(&document.path) {
                    return Err(LexicalError::Invalid("document outside index scope").into());
                }
            }
        }
        let inner = PreparedLexicalIndex::new(source, segments, non_regular_entries, live)?;
        Ok(Self { scope, inner })
    }
    #[must_use]
    pub const fn scope(&self) -> &LexicalScope {
        &self.scope
    }
    #[must_use]
    pub const fn source(&self) -> &LexicalSource {
        self.inner.source()
    }
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.inner.document_count()
    }
    #[must_use]
    pub fn encoded_bytes(&self) -> usize {
        self.inner.encoded_bytes()
    }
}

/// A scoped selection never converts implicitly into a whole-tree selection.
#[derive(Clone, Debug)]
pub struct ScopedLexicalSelection {
    scope: LexicalScope,
    inner: LexicalSelection,
}
impl ScopedLexicalSelection {
    #[must_use]
    pub const fn source(&self) -> &LexicalSource {
        self.inner.source()
    }
    #[must_use]
    pub const fn activation(&self) -> &GenerationActivation {
        self.inner.activation()
    }
    #[must_use]
    pub const fn selected_head(&self) -> &GenerationActivation {
        self.inner.selected_head()
    }
}

/// `index.results.complete` means completion WITHIN this explicit coverage and
/// the query's further restrictions. It never means whole-repository coverage.
#[derive(Clone, Debug)]
pub struct ScopedLexicalReport {
    pub scope: LexicalScope,
    pub index: IndexedLexicalReport,
}

pub struct ScopedLexicalIndexStore<'a, S> {
    scope: LexicalScope,
    inner: LexicalIndexStore<'a, S>,
}
impl<'a, S> ScopedLexicalIndexStore<'a, S> {
    pub fn new(
        store: &'a S,
        namespace: LexicalNamespace,
        reference: RefName,
        scope: LexicalScope,
    ) -> Result<Self, IndexError> {
        let mut key = key_prefix(namespace, "scoped-head");
        key.extend_from_slice(&fgit_crypto::sha256_digest(reference.as_bytes()));
        key.extend_from_slice(scope.digest());
        let mut inner = LexicalIndexStore::new(store, namespace, reference)?;
        inner.head_key = HeadKey::new(key)?;
        inner.view = scope.view()?;
        Ok(Self { scope, inner })
    }
    fn agrees(&self, scope: &LexicalScope) -> Result<(), IndexError> {
        if &self.scope != scope {
            return Err(IndexError::SourceMismatch);
        }
        Ok(())
    }
    pub fn candidate_id(
        &self,
        prepared: &PreparedScopedLexicalIndex,
        predecessor: Option<GraphGenerationId>,
    ) -> Result<GraphGenerationId, IndexError> {
        self.agrees(&prepared.scope)?;
        self.inner.candidate_id(&prepared.inner, predecessor)
    }
    fn report(
        &self,
        index: IndexedLexicalReport,
        live: &mut impl FnMut() -> bool,
    ) -> Result<ScopedLexicalReport, IndexError> {
        for hit in &index.results.hits {
            check(live)?;
            if !self.scope.includes(&hit.path) {
                return Err(IndexError::SourceMismatch);
            }
        }
        check(live)?;
        Ok(ScopedLexicalReport {
            scope: self.scope.clone(),
            index,
        })
    }
}

impl<S: AuthorityStore> ScopedLexicalIndexStore<'_, S> {
    pub fn publish(
        &self,
        prepared: &PreparedScopedLexicalIndex,
        predecessor: Option<GraphGenerationId>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<GenerationActivation, IndexError> {
        self.agrees(&prepared.scope)?;
        self.inner.publish(&prepared.inner, predecessor, live)
    }
    pub fn select(
        &self,
        expected: Option<&GenerationActivation>,
        minimum: Option<&GenerationActivation>,
        limits: LexicalReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<ScopedLexicalSelection, IndexError> {
        Ok(ScopedLexicalSelection {
            scope: self.scope.clone(),
            inner: self.inner.select(expected, minimum, limits, live)?,
        })
    }
    pub fn search(
        &self,
        selection: &ScopedLexicalSelection,
        query: &LexicalQuery,
        after: Option<u64>,
        reads: LexicalReadLimits,
        limits: LexicalQueryLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<ScopedLexicalReport, IndexError> {
        self.agrees(&selection.scope)?;
        let report = self
            .inner
            .search(&selection.inner, query, after, reads, limits, live)?;
        self.report(report, live)
    }
    pub fn recover(
        &self,
        candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<crate::GenerationRecovery, IndexError> {
        self.inner.recover(candidate, minimum, limits, live)
    }
}

impl<S: AsyncAuthorityStore> ScopedLexicalIndexStore<'_, S> {
    pub async fn publish_async(
        &self,
        cx: &S::Context,
        prepared: &PreparedScopedLexicalIndex,
        predecessor: Option<GraphGenerationId>,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<GenerationActivation, IndexError> {
        self.agrees(&prepared.scope)?;
        self.inner
            .publish_async(cx, &prepared.inner, predecessor, live)
            .await
    }
    pub async fn select_async(
        &self,
        cx: &S::Context,
        expected: Option<&GenerationActivation>,
        minimum: Option<&GenerationActivation>,
        limits: LexicalReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<ScopedLexicalSelection, IndexError> {
        Ok(ScopedLexicalSelection {
            scope: self.scope.clone(),
            inner: self
                .inner
                .select_async(cx, expected, minimum, limits, live)
                .await?,
        })
    }
    pub async fn search_async(
        &self,
        cx: &S::Context,
        selection: &ScopedLexicalSelection,
        query: &LexicalQuery,
        after: Option<u64>,
        reads: LexicalReadLimits,
        limits: LexicalQueryLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<ScopedLexicalReport, IndexError> {
        self.agrees(&selection.scope)?;
        let report = self
            .inner
            .search_async(cx, &selection.inner, query, after, reads, limits, live)
            .await?;
        self.report(report, live)
    }
    pub async fn recover_async(
        &self,
        cx: &S::Context,
        candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<crate::GenerationRecovery, IndexError> {
        self.inner
            .recover_async(cx, candidate, minimum, limits, live)
            .await
    }
}

#[cfg(test)]
mod tests;
