//! Incremental projection of the authority-selected object union.
//!
//! A cached prefix is useful only after the ordinary head-edge verifier has
//! reached its exact authenticated basis. A matching generation, ref root, or
//! latest commit alone cannot prove that two heads share a history. Cold reads
//! and histories which do not reach the prefix retain the bounded genesis
//! walk; this cache is neither durable checkpointing nor a second authority.

use super::{
    ADMISSION_CLOSURE_KEY_PREFIX, AdmissionMaterializationRefusal, Arc, AsyncAuthorityStore,
    AuthenticatedHead, AuthoritySelectedClosure, BTreeSet, CachePermit, CanonicalRefState,
    ClosureSelectionSource, Digest, GitOid, ImmutableRead, MaterializedAdmissionState,
    PermittedObjectClosure, PublicationBasis, RefusalCode, RepositoryCommitId, RepositoryId,
    RwLock, admission_immutable_key, capsule_history, decode_body,
    ensure_materializer_catch_up_live, permitted_object_closure_root, repository_commit_id,
};

/// One disposable verified prefix shared by independently opened service
/// children. Their complete admission snapshots remain private to each child.
#[derive(Debug, Default)]
pub(super) struct AdmissionClosureCache {
    prefix: RwLock<Option<Arc<ClosurePrefix>>>,
}

impl AdmissionClosureCache {
    pub(super) fn read(
        &self,
    ) -> Result<Option<Arc<ClosurePrefix>>, AdmissionMaterializationRefusal> {
        self.prefix
            .read()
            .map(|prefix| prefix.as_ref().map(Arc::clone))
            .map_err(|_| AdmissionMaterializationRefusal::CachePoisoned)
    }

    pub(super) fn publish(
        &self,
        state: &MaterializedAdmissionState,
        is_cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<(), AdmissionMaterializationRefusal> {
        let mut slot = self
            .prefix
            .write()
            .map_err(|_| AdmissionMaterializationRefusal::CachePoisoned)?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        // A late historical reader must not displace a more recent
        // prefix installed by a sibling. Equality needs no new copy.
        if let Some(previous) = slot.as_ref()
            && previous.authenticated.verified_against() == state.authenticated.verified_against()
            && previous.authenticated.receipt().key() == state.authenticated.receipt().key()
            && previous.basis.body().repository_id == state.basis.body().repository_id
            && (previous.basis.generation() > state.basis.generation()
                || previous.basis == state.basis)
        {
            return Ok(());
        }
        let prefix = Arc::new(ClosurePrefix::from_state(state));
        ensure_materializer_catch_up_live(is_cancelled)?;
        *slot = Some(prefix);
        Ok(())
    }
}

/// Previously verified closure material owned by one admitted cache entry.
/// Store, repository, head slot and permit are checked on every lookup.
#[derive(Debug)]
pub(super) struct ClosurePrefix {
    pub(super) authenticated: AuthenticatedHead,
    pub(super) basis: PublicationBasis,
    pub(super) cache_permit: CachePermit,
    pub(super) roots: Arc<BTreeSet<Digest>>,
    pub(super) selected: Arc<AuthoritySelectedClosure>,
}

impl ClosurePrefix {
    pub(super) fn from_state(state: &MaterializedAdmissionState) -> Self {
        Self {
            authenticated: state.authenticated.clone(),
            basis: state.basis.clone(),
            cache_permit: state.cache_permit,
            roots: Arc::clone(&state.closure_roots),
            selected: Arc::clone(&state.selected_closure),
        }
    }
}

/// Selection precedes configuration validation; immutable closure reads remain
/// after it, preserving the materializer's existing refusal precedence.
pub(super) struct ClosureSelection {
    roots: BTreeSet<Digest>,
    pending: BTreeSet<Digest>,
    inherited: BTreeSet<GitOid>,
    source: ClosureSelectionSource,
}

impl ClosureSelection {
    pub(super) async fn materialize_in<Authority>(
        self,
        authority: &Authority,
        cx: &Authority::Context,
        repository_id: RepositoryId,
        is_cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<(AuthoritySelectedClosure, BTreeSet<Digest>), AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
    {
        ensure_materializer_catch_up_live(is_cancelled)?;
        let mut united = self.inherited;
        for closure_root in self.pending {
            ensure_materializer_catch_up_live(is_cancelled)?;
            let key =
                admission_immutable_key(ADMISSION_CLOSURE_KEY_PREFIX, repository_id, closure_root)
                    .map_err(AdmissionMaterializationRefusal::Key)?;
            let read = authority.read_immutable(cx, &key).await;
            ensure_materializer_catch_up_live(is_cancelled)?;
            let ImmutableRead::Present(frame) =
                read.map_err(AdmissionMaterializationRefusal::Authority)?
            else {
                return Err(AdmissionMaterializationRefusal::ImmutableAbsent(
                    closure_root,
                ));
            };
            let closure =
                decode_body::<PermittedObjectClosure>(&frame, fgit_codec::DecodeLimits::DEFAULT)
                    .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
            if permitted_object_closure_root(&closure)
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?
                != closure_root
            {
                return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                    RefusalCode::InternalInvariantBreach,
                ));
            }
            for (index, oid) in closure.objects().iter().enumerate() {
                if index % 1_024 == 0 {
                    ensure_materializer_catch_up_live(is_cancelled)?;
                }
                united.insert(*oid);
            }
        }
        ensure_materializer_catch_up_live(is_cancelled)?;
        let closure = PermittedObjectClosure::new(united);
        let root = permitted_object_closure_root(&closure)
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        Ok((
            AuthoritySelectedClosure {
                root,
                closure,
                source: self.source,
            },
            self.roots,
        ))
    }
}

pub(super) async fn select_in<Authority>(
    authority: &Authority,
    cx: &Authority::Context,
    current: &PublicationBasis,
    current_refs: &CanonicalRefState,
    mut prefix: Option<Arc<ClosurePrefix>>,
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> Result<ClosureSelection, AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
{
    let mut successor = current.body().clone();
    let mut successor_id = current.id();
    let mut walked = 0_usize;
    let mut latest_record: Option<RepositoryCommitId> = None;
    let mut roots = BTreeSet::new();

    loop {
        ensure_materializer_catch_up_live(is_cancelled)?;
        if let Some(cached) = prefix.take() {
            if successor_id != cached.basis.id() || successor != *cached.basis.body() {
                prefix = Some(cached);
            } else {
                // No object or closure root from the cache is used before this
                // exact match. Every edge from the selected head to here has
                // passed read_history_step_async's complete decision/checkpoint
                // verifier, including refusal-only and configuration transitions.
                let pending = roots.difference(&cached.roots).copied().collect();
                roots.extend(cached.roots.iter().copied());
                let latest = latest_record.or(match cached.selected.source {
                    ClosureSelectionSource::EmptyGenesis => None,
                    ClosureSelectionSource::RepositoryCommit(latest)
                    | ClosureSelectionSource::CumulativeHistory { latest, .. } => Some(latest),
                });
                let source = selection_source(latest, roots.len(), current_refs)?;
                ensure_materializer_catch_up_live(is_cancelled)?;
                return Ok(ClosureSelection {
                    roots,
                    pending,
                    inherited: cached.selected.closure.objects().clone(),
                    source,
                });
            }
        }

        let (basis, batch) = match capsule_history::predecessor_in(
            authority,
            cx,
            &successor,
            &mut walked,
            is_cancelled,
        )
        .await?
        {
            capsule_history::HistoryStep::Genesis => {
                let source = selection_source(latest_record, roots.len(), current_refs)?;
                return Ok(ClosureSelection {
                    pending: roots.clone(),
                    roots,
                    inherited: BTreeSet::new(),
                    source,
                });
            }
            capsule_history::HistoryStep::Checkpoint { predecessor } => {
                successor_id = predecessor.id();
                successor = predecessor.body().clone();
                continue;
            }
            capsule_history::HistoryStep::Decision { predecessor, batch } => (predecessor, batch),
        };

        if let (Some(record), None) = (batch.committed_rcrs.last(), latest_record) {
            let record_id = repository_commit_id(record)?;
            if successor.latest_committed_rcr_id != Some(record_id) {
                return Err(AdmissionMaterializationRefusal::LatestCommitMismatch {
                    expected: Box::new(record_id),
                    observed: successor.latest_committed_rcr_id.map(Box::new),
                });
            }
            if record.repository_id != successor.repository_id {
                return Err(
                    AdmissionMaterializationRefusal::SelectedCommitStateMismatch {
                        field: "repository_id",
                    },
                );
            }
            if record.resulting_ref_root != successor.ref_root {
                return Err(
                    AdmissionMaterializationRefusal::SelectedCommitStateMismatch {
                        field: "ref_root",
                    },
                );
            }
            if record.policy_epoch != successor.policy_epoch {
                fgit_admission::merge::native::protection::verify_epoch_advance_at(
                    authority,
                    cx,
                    &basis,
                    &successor,
                    &batch,
                    is_cancelled,
                )
                .await
                .map_err(|error| AdmissionMaterializationRefusal::Delivery(Box::new(error)))?;
            }
            latest_record = Some(record_id);
        }
        // Set insertion deduplicates repeated empty/event roots without the
        // old quadratic Vec::contains scan. Closure identities and the final
        // canonical object union do not depend on traversal order.
        roots.extend(
            batch
                .committed_rcrs
                .iter()
                .map(|record| record.object_closure_root),
        );
        successor_id = basis.id();
        successor = basis.body().clone();
    }
}

fn selection_source(
    latest: Option<RepositoryCommitId>,
    roots: usize,
    refs: &CanonicalRefState,
) -> Result<ClosureSelectionSource, AdmissionMaterializationRefusal> {
    match (latest, roots) {
        (None, 0) if refs.refs().is_empty() => Ok(ClosureSelectionSource::EmptyGenesis),
        (None, 0) => Err(AdmissionMaterializationRefusal::NonEmptyGenesisWithoutClosure),
        (None, _) | (Some(_), 0) => Err(AdmissionMaterializationRefusal::DecisionHistoryUnbound),
        (Some(latest), 1) => Ok(ClosureSelectionSource::RepositoryCommit(latest)),
        (Some(latest), united_roots) => Ok(ClosureSelectionSource::CumulativeHistory {
            latest,
            united_roots,
        }),
    }
}
