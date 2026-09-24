//! Recompose a complete lexical generation without reading unchanged blobs.
//! Reuse is possible only after every payload of an authenticated selection
//! verifies. Source membership/completeness and authorization remain the native
//! tree owner's job; these derived postings are never an access capability.

use super::{
    AsyncAuthorityStore, AuthorityStore, BTreeMap, Entry, GenerationActivation, GitOid,
    ImmutableRead, IndexError, IndexedDocument, LexicalError, LexicalIndexStore, LexicalReadLimits,
    LexicalSegment, LexicalSelection, LexicalSource, MAX_DOCUMENTS, MAX_FILE_BYTES,
    MAX_INDEX_BYTES, MAX_INDEX_DOCUMENTS, MAX_POSTINGS, MAX_SEGMENT_BYTES, MAX_SEGMENTS,
    MAX_SOURCE_BYTES, MAX_TERMS, Postings, PreparedLexicalIndex, SegmentRef, SourceDocument,
    StoreInstanceId, Term, before_read, bounded_add, check, path_valid, payload, payload_key,
};

/// A complete new inventory row. `None` explicitly requests the exact prior
/// path/blob's postings. `Some(&[])` is a freshly read empty blob, not reuse.
#[derive(Clone, Copy, Debug)]
pub struct RefreshDocument<'a> {
    pub path: &'a [u8],
    pub blob: GitOid,
    pub content: Option<&'a [u8]>,
}

/// Counts for one completed preparation, not an activation or a CPU benchmark.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LexicalRefreshStats {
    pub reused_documents: usize,
    pub rebuilt_documents: usize,
    pub reused_source_bytes: usize,
    pub rebuilt_source_bytes: usize,
    /// Includes replaced and deleted old rows. It is not just a deletion count.
    pub prior_documents_not_reused: usize,
    pub previous_payload_bytes_read: usize,
    pub previous_generation_bytes_read: usize,
    /// Source/token-copy byte accounting across all attempts, including splits.
    pub build_work_bytes: usize,
}

#[derive(Debug)]
struct SavedDocument {
    blob: GitOid,
    content_bytes: usize,
    // Dictionary indices preserve the original channel/term and first offset.
    postings: Vec<(usize, u32)>,
    copy_bytes: usize,
}

/// Verified immutable postings owned by one scoped selection. No public
/// constructor can turn arbitrary caller metadata into reusable postings.
#[derive(Debug)]
pub struct LexicalReuse {
    source: LexicalSource,
    activation: GenerationActivation,
    dictionary: Vec<Term>,
    documents: BTreeMap<Vec<u8>, SavedDocument>,
    payload_bytes: usize,
    generation_bytes: usize,
    retained_bytes: usize,
}

impl LexicalReuse {
    fn empty(selection: &LexicalSelection) -> Self {
        Self {
            source: selection.source().clone(),
            activation: selection.activation().clone(),
            dictionary: Vec::new(),
            documents: BTreeMap::new(),
            payload_bytes: selection.payload_bytes,
            generation_bytes: selection.generation_bytes,
            retained_bytes: 0,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &LexicalSource {
        &self.source
    }
    #[must_use]
    pub const fn activation(&self) -> &GenerationActivation {
        &self.activation
    }

    /// A same-path, same-native-blob match only. A new path, changed blob, or
    /// another hash format is not reusable. This does not authorize disclosure.
    #[must_use]
    pub fn document_bytes(&self, path: &[u8], blob: GitOid) -> Option<usize> {
        self.documents
            .get(path)
            .filter(|row| row.blob == blob)
            .map(|row| row.content_bytes)
    }

    fn retain(&mut self, amount: usize) -> Result<(), LexicalError> {
        // Bound modeled metadata, not platform-dependent allocator/RSS bytes.
        bounded_add(
            &mut self.retained_bytes,
            amount,
            MAX_INDEX_BYTES * 2,
            "refresh metadata",
        )
    }

    fn append(
        &mut self,
        segment: LexicalSegment,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), IndexError> {
        check(live)?;
        if segment.namespace != self.source.namespace {
            return Err(IndexError::SourceMismatch);
        }
        let mut rows: Vec<_> = segment
            .documents
            .iter()
            .map(|d| SavedDocument {
                blob: d.blob,
                content_bytes: d.content_bytes as usize,
                postings: Vec::new(),
                copy_bytes: 64 + d.path.len(),
            })
            .collect();
        // Invert once, not a dictionary scan for every document reused later.
        for (term, columns) in segment.terms {
            check(live)?;
            self.retain(13 + term.bytes.len())?;
            let index = self.dictionary.len();
            let term_bytes = term.bytes.len();
            self.dictionary.push(term);
            for (id, offset) in columns.documents.into_iter().zip(columns.offsets) {
                check(live)?;
                let at = segment
                    .documents
                    .binary_search_by_key(&id, |d| d.id)
                    .map_err(|_| LexicalError::Invalid("refresh posting document"))?;
                self.retain(12)?;
                rows[at].postings.push((index, offset));
                bounded_add(
                    &mut rows[at].copy_bytes,
                    25 + term_bytes,
                    MAX_INDEX_BYTES * 2,
                    "refresh document work",
                )?;
            }
        }
        for (document, row) in segment.documents.into_iter().zip(rows) {
            check(live)?;
            self.retain(64 + document.path.len())?;
            if self.documents.len() == MAX_INDEX_DOCUMENTS {
                return Err(LexicalError::Limit("indexed documents").into());
            }
            if self.documents.insert(document.path, row).is_some() {
                return Err(LexicalError::Invalid("duplicate refresh path").into());
            }
        }
        Ok(())
    }

    fn reused(&self, row: RefreshDocument<'_>) -> Result<&SavedDocument, LexicalError> {
        self.documents
            .get(row.path)
            .filter(|saved| saved.blob == row.blob)
            .ok_or(LexicalError::Invalid(
                "refresh requires exact prior path and blob",
            ))
    }

    fn singleton(
        &self,
        row: RefreshDocument<'_>,
        id: u64,
        live: &mut impl FnMut() -> bool,
    ) -> Result<LexicalSegment, LexicalError> {
        check(live)?;
        if let Some(content) = row.content {
            // Keep native verification and tokenization on the existing engine.
            return LexicalSegment::build(
                self.source.namespace,
                id,
                [SourceDocument {
                    path: row.path,
                    blob: row.blob,
                    content,
                }],
                live,
            );
        }
        let old = self.reused(row)?;
        let mut terms = BTreeMap::new();
        for &(term, offset) in &old.postings {
            check(live)?;
            terms.insert(
                self.dictionary[term].clone(),
                Postings {
                    documents: vec![id],
                    offsets: vec![offset],
                },
            );
        }
        Ok(LexicalSegment {
            namespace: self.source.namespace,
            documents: vec![IndexedDocument {
                id,
                path: row.path.to_vec(),
                blob: row.blob,
                content_bytes: old.content_bytes as u32,
            }],
            terms,
        })
    }

    fn segment(
        &self,
        rows: &[RefreshDocument<'_>],
        first: usize,
        work: &mut usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<LexicalSegment, LexicalError> {
        let mut result = LexicalSegment {
            namespace: self.source.namespace,
            documents: Vec::new(),
            terms: BTreeMap::new(),
        };
        let (mut postings, mut encoded_bound) = (0, 128);
        for (offset, &row) in rows.iter().enumerate() {
            check(live)?;
            let cost = match row.content {
                Some(bytes) => bytes.len() + row.path.len() + 64,
                None => self.reused(row)?.copy_bytes,
            };
            bounded_add(work, cost, 256 * 1024 * 1024, "refresh build work")?;
            let single = self.singleton(row, (first + offset + 1) as u64, live)?;
            let document = single
                .documents
                .into_iter()
                .next()
                .ok_or(LexicalError::Invalid("empty refresh document"))?;
            bounded_add(
                &mut encoded_bound,
                64 + document.path.len(),
                MAX_SEGMENT_BYTES,
                "segment bytes",
            )?;
            result.documents.push(document);
            // Same column concatenation and bounds as LexicalSegment::concatenate,
            // but consume one row at a time instead of retaining N full maps.
            for (term, columns) in single.terms {
                check(live)?;
                bounded_add(&mut postings, 1, MAX_POSTINGS, "postings")?;
                let count = result.terms.len();
                let target = match result.terms.entry(term) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        if count == MAX_TERMS {
                            return Err(LexicalError::Limit("dictionary terms"));
                        }
                        bounded_add(
                            &mut encoded_bound,
                            13 + entry.key().bytes.len(),
                            MAX_SEGMENT_BYTES,
                            "segment bytes",
                        )?;
                        entry.insert(Postings::default())
                    }
                };
                bounded_add(&mut encoded_bound, 12, MAX_SEGMENT_BYTES, "segment bytes")?;
                target.documents.extend(columns.documents);
                target.offsets.extend(columns.offsets);
            }
        }
        result.encode(live)?;
        check(live)?;
        Ok(result)
    }

    /// Prepare a COMPLETE replacement inventory. Absent old rows are deleted;
    /// new IDs are assigned in this generation's raw-path order, including after
    /// insertion/deletion. No ID escapes its exact generation. Fresh and reused
    /// rows have identical encoding/token semantics. Nothing is published here.
    ///
    /// The source owner must supply a complete independently verified inventory.
    /// Namespace/ref must match this base; source position may advance. Work,
    /// corpus size, segments and deterministic left-first splitting are bounded.
    pub fn prepare(
        &self,
        source: LexicalSource,
        rows: &[RefreshDocument<'_>],
        excluded: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(PreparedLexicalIndex, LexicalRefreshStats), IndexError> {
        check(live)?;
        if source.namespace != self.source.namespace || source.reference != self.source.reference {
            return Err(IndexError::SourceMismatch);
        }
        if rows.len() > MAX_INDEX_DOCUMENTS {
            return Err(LexicalError::Limit("indexed documents").into());
        }
        let mut stats = LexicalRefreshStats {
            previous_payload_bytes_read: self.payload_bytes,
            previous_generation_bytes_read: self.generation_bytes,
            ..Default::default()
        };
        let mut previous: Option<&[u8]> = None;
        let mut total_bytes = 0;
        for &row in rows {
            check(live)?;
            if !path_valid(row.path) || previous.is_some_and(|path| path >= row.path) {
                return Err(LexicalError::Invalid("document path order").into());
            }
            previous = Some(row.path);
            let bytes = match row.content {
                Some(bytes) => {
                    stats.rebuilt_documents += 1;
                    bounded_add(
                        &mut stats.rebuilt_source_bytes,
                        bytes.len(),
                        MAX_SOURCE_BYTES,
                        "source bytes",
                    )?;
                    bytes.len()
                }
                None => {
                    let bytes = self.reused(row)?.content_bytes;
                    stats.reused_documents += 1;
                    bounded_add(
                        &mut stats.reused_source_bytes,
                        bytes,
                        MAX_SOURCE_BYTES,
                        "source bytes",
                    )?;
                    bytes
                }
            };
            if bytes > MAX_FILE_BYTES {
                return Err(IndexError::Lexical(LexicalError::Limit("file bytes")));
            }
            bounded_add(&mut total_bytes, bytes, MAX_SOURCE_BYTES, "source bytes")?;
        }
        stats.prior_documents_not_reused = self.documents.len() - stats.reused_documents;
        let (mut parts, mut attempts, mut encoded_bytes) = (Vec::new(), 0, 0);
        for (group, chunk) in rows.chunks(MAX_DOCUMENTS).enumerate() {
            let mut pending = vec![(group * MAX_DOCUMENTS, chunk)];
            while let Some((first, input)) = pending.pop() {
                check(live)?;
                attempts += 1;
                if attempts > 256 {
                    return Err(IndexError::Lexical(LexicalError::Limit(
                        "segment build attempts",
                    )));
                }
                match self.segment(input, first, &mut stats.build_work_bytes, live) {
                    Ok(segment) => {
                        if parts.len() == MAX_SEGMENTS {
                            return Err(LexicalError::Limit("index segments").into());
                        }
                        bounded_add(
                            &mut encoded_bytes,
                            segment.encode(live)?.len(),
                            MAX_INDEX_BYTES,
                            "index bytes",
                        )?;
                        parts.push(segment);
                    }
                    Err(LexicalError::Limit(
                        "documents" | "dictionary terms" | "postings" | "segment bytes",
                    )) if input.len() > 1 => {
                        let middle = input.len() / 2;
                        pending.push((first + middle, &input[middle..]));
                        pending.push((first, &input[..middle]));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let prepared = PreparedLexicalIndex::new(source, parts, excluded, live)?;
        check(live)?;
        Ok((prepared, stats))
    }
}

impl<S> LexicalIndexStore<'_, S> {
    fn start_refresh(
        &self,
        selection: &LexicalSelection,
        instance: StoreInstanceId,
        limits: LexicalReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<LexicalReuse, IndexError> {
        limits.validate()?;
        check(live)?;
        self.check_source(selection.source())?;
        if selection.store_instance != instance {
            return Err(IndexError::SourceMismatch);
        }
        if selection.payload_bytes > limits.max_payload_bytes
            || selection.manifest.segments.len() > limits.max_segments
        {
            return Err(LexicalError::Limit("refresh index reads").into());
        }
        Ok(LexicalReuse::empty(selection))
    }
}

fn observe(
    base: &mut LexicalReuse,
    reference: &SegmentRef,
    read: ImmutableRead,
    limits: LexicalReadLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), IndexError> {
    check(live)?;
    let bytes = payload(read, reference.root, &mut base.payload_bytes, limits)?;
    let segment = LexicalSegment::decode(&bytes, reference.root, base.source.namespace, live)?;
    if SegmentRef::new(&segment, reference.root, bytes.len())? != *reference {
        return Err(LexicalError::CommitmentMismatch.into());
    }
    base.append(segment, live)
}

impl<S: AuthorityStore> LexicalIndexStore<'_, S> {
    /// Read/verify every segment of an already authenticated selection. The
    /// same metadata/payload allowance spans selection and these reads.
    pub fn load_refresh_base(
        &self,
        selection: &LexicalSelection,
        limits: LexicalReadLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<LexicalReuse, IndexError> {
        let mut base = self.start_refresh(selection, self.store.instance_id(), limits, live)?;
        for reference in &selection.manifest.segments {
            before_read(base.payload_bytes, limits, live)?;
            let read = self.store.read_immutable(&payload_key(
                self.namespace,
                "segment",
                reference.root,
            )?)?;
            observe(&mut base, reference, read, limits, live)?;
        }
        check(live)?;
        Ok(base)
    }
}

impl<S: AsyncAuthorityStore> LexicalIndexStore<'_, S> {
    /// Production counterpart: per-invocation context, no blocking adapter,
    /// head refresh, fallback, store listing, staging or generation write.
    pub async fn load_refresh_base_async(
        &self,
        cx: &S::Context,
        selection: &LexicalSelection,
        limits: LexicalReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<LexicalReuse, IndexError> {
        let mut base = self.start_refresh(selection, self.store.instance_id(), limits, live)?;
        for reference in &selection.manifest.segments {
            before_read(base.payload_bytes, limits, live)?;
            let read = self
                .store
                .read_immutable(cx, &payload_key(self.namespace, "segment", reference.root)?)
                .await?;
            observe(&mut base, reference, read, limits, live)?;
        }
        check(live)?;
        Ok(base)
    }
}

#[cfg(test)]
mod tests;
