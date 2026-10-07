//! Incremental recomposition that cannot shed its explicit coverage identity.
//! The existing refresh engine verifies every prior segment and owns token
//! semantics. This boundary retains the scope through reuse and preparation.

use super::super::{
    LexicalRefreshStats, LexicalReuse, MAX_INDEX_DOCUMENTS, RefreshDocument,
};
use super::{
    AsyncAuthorityStore, AuthorityStore, GenerationActivation, IndexError, LexicalError,
    LexicalReadLimits, LexicalScope, LexicalSource, PreparedScopedLexicalIndex,
    ScopedLexicalIndexStore, ScopedLexicalSelection, check,
};
use fgit_types::GitOid;

/// Verified postings from exactly one scoped generation. Its private inner
/// value cannot be converted to whole-tree reuse or published without scope.
#[derive(Debug)]
pub struct ScopedLexicalReuse {
    scope: LexicalScope,
    inner: LexicalReuse,
}

impl ScopedLexicalReuse {
    #[must_use]
    pub const fn scope(&self) -> &LexicalScope {
        &self.scope
    }

    #[must_use]
    pub const fn source(&self) -> &LexicalSource {
        self.inner.source()
    }

    #[must_use]
    pub const fn activation(&self) -> &GenerationActivation {
        self.inner.activation()
    }

    /// Reuse requires the same path, native blob, and explicit coverage. This
    /// hint never supplies source membership or a caller's read permission.
    #[must_use]
    pub fn document_bytes(&self, path: &[u8], blob: GitOid) -> Option<usize> {
        if !self.scope.includes(path) {
            return None;
        }
        self.inner.document_bytes(path, blob)
    }

    /// Recompose a COMPLETE newly enumerated inventory within the original
    /// coverage. Deleted and renamed paths are handled by the shared engine;
    /// an omitted old row is not implicitly retained. Source pins may advance,
    /// but namespace, reference, and scope cannot change during reuse.
    pub fn prepare(
        &self,
        source: LexicalSource,
        rows: &[RefreshDocument<'_>],
        excluded: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(PreparedScopedLexicalIndex, LexicalRefreshStats), IndexError> {
        check(live)?;
        // Bound the scope-validation pass before walking caller input. The
        // shared engine subsequently checks ordering, identity, bytes and work.
        if rows.len() > MAX_INDEX_DOCUMENTS {
            return Err(LexicalError::Limit("indexed documents").into());
        }
        for row in rows {
            check(live)?;
            if !self.scope.includes(row.path) {
                return Err(LexicalError::Invalid("document outside index scope").into());
            }
        }
        let (inner, stats) = self.inner.prepare(source, rows, excluded, live)?;
        Ok((
            PreparedScopedLexicalIndex {
                scope: self.scope.clone(),
                inner,
            },
            stats,
        ))
    }
}

impl<S: AuthorityStore> ScopedLexicalIndexStore<'_, S> {
    /// Verify every segment of the exact scoped selection before returning any
    /// reusable postings. Selection and payload reads share the same budget.
    pub fn load_refresh_base(
        &self,
        selection: &ScopedLexicalSelection,
        limits: LexicalReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<ScopedLexicalReuse, IndexError> {
        check(live)?;
        self.agrees(&selection.scope)?;
        let inner = self.inner.load_refresh_base(&selection.inner, limits, live)?;
        Ok(ScopedLexicalReuse {
            scope: self.scope.clone(),
            inner,
        })
    }
}

impl<S: AsyncAuthorityStore> ScopedLexicalIndexStore<'_, S> {
    /// Context-owned production counterpart. A foreign scope refuses before
    /// reading payloads; no synchronous bridge, fallback or write is introduced.
    pub async fn load_refresh_base_async(
        &self,
        cx: &S::Context,
        selection: &ScopedLexicalSelection,
        limits: LexicalReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<ScopedLexicalReuse, IndexError> {
        check(live)?;
        self.agrees(&selection.scope)?;
        let inner = self
            .inner
            .load_refresh_base_async(cx, &selection.inner, limits, live)
            .await?;
        Ok(ScopedLexicalReuse {
            scope: self.scope.clone(),
            inner,
        })
    }
}

#[cfg(test)]
mod tests;
