//! One bounded maintenance attempt, separate from reads and repository writes.
//!
//! Canonical source chooses the target; the verified index head chooses one
//! predecessor. Neither observation is refreshed after preparation starts.
use crate::{ClosureSelectionSource, NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::{IndexError, LexicalIndexStore, LexicalReadLimits, LexicalSource};
use fgit_graph::{GenerationActivation, GraphGenerationId};
use fgit_types::cell::{ReadMode, admits_read, admits_staging_intake};
use fgit_types::{RefName, RepositoryAuthorityHeadId};

use super::super::super::{search_error, workspace_request_live};
use super::super::{index_error, live};

impl OneNode {
    /// Ensure one visible reference has an index for the source selected by
    /// this invocation. This explicitly authorizes local maintenance, unlike
    /// an HTTP read or an explicit-predecessor `build`/`refresh` request.
    ///
    /// Returns the source and activation already current, or builds genesis
    /// or refreshes the exact observed predecessor. A current index performs
    /// no source-blob reads, posting scan, staging or generation advance. Its
    /// manifest/catalogs are verified; this no-op is not a full payload audit.
    ///
    /// `minimum` is an independently retained index checkpoint. It must be
    /// resolved before any build, so a missing or rolled-back index never
    /// silently becomes a new genesis. `expected_head` optionally pins the
    /// canonical source observation (for a controller processing a known head).
    ///
    /// This is ONE attempt: source movement, CAS races, corruption, resource
    /// exhaustion and cancellation are returned without selecting a new basis.
    /// Publication uncertainty retains the original candidate through
    /// `SourceIndexPublication`. A subsequent controller invocation is not
    /// evidence that an unresolved earlier publication failed.
    pub async fn reconcile_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        minimum: Option<&GenerationActivation>,
        limits: SearchLimits,
        read_limits: LexicalReadLimits,
    ) -> Result<(LexicalSource, GenerationActivation), NodeWorkspaceRefusal> {
        self.reconcile_source_index_guarded_local_in(
            request,
            reference,
            expected_head,
            minimum,
            limits,
            read_limits,
            &mut |_| Ok(()),
        )
        .await
    }

    /// Reconcile through a durable candidate barrier. A current-index no-op
    /// never calls the barrier. Genesis and refresh delegate to the SAME
    /// guarded native builders; neither can publish before the callback returns
    /// Ok. Source/index pins, minimum checkpoints, and cancellation retain the
    /// unguarded entrypoint's semantics. No callback follows confirmed success.
    #[expect(
        clippy::too_many_arguments,
        reason = "publication barrier is separate from source selection and maintenance budgets"
    )]
    pub async fn reconcile_source_index_guarded_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        minimum: Option<&GenerationActivation>,
        limits: SearchLimits,
        read_limits: LexicalReadLimits,
        before_publish: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(LexicalSource, GenerationActivation), NodeWorkspaceRefusal> {
        limits.validate().map_err(search_error)?;
        live(request)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        admits_staging_intake(self.cell_state()).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        live(request)?;
        // Current canonical visibility is checked BEFORE any index metadata.
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let commit = *selected
            .snapshot()
            .refs
            .get(reference)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let head = selected.basis().id();
        if expected_head.is_some_and(|expected| expected != head) {
            return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                SourceBrowseError::SnapshotMoved,
            )));
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
        };
        let forge_position = selected.basis().body().forge_position_root;
        let store =
            LexicalIndexStore::new(&self.authority, self.lexical_namespace(), reference.clone())
                .map_err(index_error)?;
        let mut request_live = || workspace_request_live(request);
        let previous = match store
            .select_async(
                request.authority(),
                None,
                minimum,
                read_limits,
                &mut request_live,
            )
            .await
        {
            Ok(index) => Some(index),
            // Only a genuinely uninitialized index, without an unresolved
            // checkpoint, may select genesis. Corruption is never a cache miss.
            Err(IndexError::Uninitialized) if minimum.is_none() => None,
            Err(error) => return Err(index_error(error)),
        };
        live(request)?;
        if let Some(index) = &previous {
            let source = index.source();
            if source.source_head == head
                && source.commit == commit
                && source.source_rcr == rcr
                && source.forge_position_root == forge_position
            {
                return Ok((source.clone(), index.activation().clone()));
            }
        }
        let predecessor = previous
            .as_ref()
            .map(|index| index.activation().generation_id);
        drop(previous);
        drop(selected);
        // Each native builder revalidates these pins inside its own complete
        // TreeFS selection. A write after the observation above cannot be
        // silently accepted as the target of this same attempt.
        match predecessor {
            None => {
                self.build_source_index_guarded_local_in(
                    request,
                    reference,
                    Some(head),
                    Some(commit),
                    None,
                    limits,
                    before_publish,
                )
                .await
            }
            Some(predecessor) => self
                .refresh_source_index_guarded_local_in(
                    request,
                    reference,
                    Some(head),
                    Some(commit),
                    predecessor,
                    limits,
                    read_limits,
                    before_publish,
                )
                .await
                .map(|(source, activation, _stats)| (source, activation)),
        }
        // No cancellation probe after the builder confirms root publication.
    }
}
