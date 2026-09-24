//! Stage-free inspection of every actual commit in a linear rebase bundle.
//! The old source lease selects the comparison, not external pack bases.

use super::*;
use crate::treefs_workspace::candidate_inspection::{
    InspectedBundle, InspectedRebaseCommit, RebaseBundleInspection,
};
use fgit_forge::review::compare_source_series;

const MAX_COMMITS: usize = 256;
const MAX_COMMIT_BODIES: usize = 16 * 1024 * 1024;

impl OneNode {
    /// Inspect a complete, untrusted linear series without staging any object.
    ///
    /// Both branch tips are selected at one current authenticated head. The
    /// expected old source is the ref lease; onto is the sole pack prerequisite.
    /// Only onto-reachable originals are available while unpacking and proving
    /// candidate closure. A source-only or hidden object is never an implicit
    /// external delta base, even if it already exists in this repository.
    ///
    /// After verification, return the old-source-to-result diff AND every
    /// parent-to-child diff, oldest first, under one cumulative review budget.
    /// This exposes transient changes that a final-tree-only review would miss.
    /// Exact native commit bodies retain all metadata for independent review.
    /// Full inspection refuses path filters, merge-base mode, more than 256
    /// commits, or more than 16 MiB of commit bodies. Empty series are supported.
    ///
    /// This proves structure and content, not algorithmic replay equivalence,
    /// authorship, approval, or permission to publish. Apply remains separate.
    pub async fn inspect_rebase_bundle_in(
        &self,
        request: &NodeRequestContext,
        source_ref: &RefName,
        onto_ref: &RefName,
        expected_source: GitOid,
        onto: GitOid,
        candidate: GitOid,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        options: &ReviewOptions,
    ) -> Result<RebaseBundleInspection, BundleInspectionRefusal> {
        options
            .validate()
            .map_err(|error| BundleInspectionRefusal::Review(Box::new(error)))?;
        if options.mode != ComparisonMode::Direct || !options.paths.is_empty() {
            return Err(invalid(
                "rebase inspection requires complete direct comparisons",
            ));
        }
        if source_ref == onto_ref
            || [source_ref, onto_ref].iter().any(|name| {
                !name.as_bytes().starts_with(b"refs/heads/") || name.as_bytes().len() > 4096
            })
            || [expected_source, onto, candidate]
                .iter()
                .any(|id| id.is_zero() || id.algorithm() != self.object_format)
        {
            return Err(invalid(
                "two distinct branches and exact native rebase coordinates required",
            ));
        }
        let envelope = CandidateEnvelope::parse_profile(input, 1, true)
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        envelope
            .bind(self.object_format, source_ref, onto, candidate)
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(BundleInspectionRefusal::Cell)?;
        if [source_ref, onto_ref]
            .iter()
            .any(|name| visibility.hides(name.as_bytes()))
        {
            return Err(BundleInspectionRefusal::RefUnavailable);
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| BundleInspectionRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(BundleInspectionRefusal::SnapshotMoved);
        }
        for (reference, expected) in [(source_ref, expected_source), (onto_ref, onto)] {
            if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
                return Err(BundleInspectionRefusal::RefUnavailable);
            }
            let current = selected
                .snapshot()
                .refs
                .get(reference)
                .ok_or(BundleInspectionRefusal::RefUnavailable)?;
            if *current != expected {
                return Err(BundleInspectionRefusal::ParentMoved);
            }
        }
        let exhaustion = Cell::new(None);
        let budget = ReadBudget {
            bytes: Cell::new(0),
            exhausted: Cell::new(false),
        };
        let maximum = usize::try_from(self.max_object_bytes)
            .unwrap_or(usize::MAX)
            .min(32 * 1024 * 1024);
        let fabric = || VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: maximum,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        let original = OriginalSource {
            inner: fabric(),
            allowed: selected.selected_closure().closure().objects(),
            budget: &budget,
        };
        let limits = MergeObjectLimits {
            max_object_bytes: maximum,
            ..MergeObjectLimits::default()
        };
        let base =
            validate_commit_closure(&original, onto, limits, &mut || original.live().is_ok());
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let base = base.map_err(BundleInspectionRefusal::Validation)?;
        let onto_source = OriginalSource {
            inner: fabric(),
            allowed: &base.objects,
            budget: &budget,
        };
        let pack_limits = PackLimits {
            max_input_bytes: MAX_BUNDLE_BYTES,
            max_entries: MAX_INSPECTION_OBJECTS,
            max_object_bytes: maximum,
            max_total_expanded_bytes: MAX_EXPANDED_BYTES,
            max_cached_bytes: MAX_EXPANDED_BYTES,
            ..PackLimits::default()
        };
        let unpacked = pack::unpack(
            envelope.pack,
            self.object_format,
            &pack_limits,
            &onto_source,
        );
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let unpacked = unpacked?;
        let source = InspectionSource {
            original: &onto_source,
            objects: &unpacked.objects,
            parse_limits: ParseLimits {
                max_object_bytes: maximum,
                tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: options.limits.max_tree_entries,
                ..ParseLimits::default()
            },
        };
        let commits = inspect_chain(&source, candidate, onto)?;
        let closure =
            validate_commit_closure(&source, candidate, limits, &mut || original.live().is_ok());
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let closure = closure.map_err(BundleInspectionRefusal::Validation)?;
        let transport_only_objects = unpacked.check_coverage(&closure.objects)?;

        // Only now is old-source history made available for the final comparison.
        // It was deliberately unavailable to the uploaded pack and candidate
        // closure validator. All reads still consume the SAME original budget.
        let old = validate_commit_closure(&original, expected_source, limits, &mut || {
            original.live().is_ok()
        });
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let old = old.map_err(BundleInspectionRefusal::Validation)?;
        let mut review_objects = base.objects.clone();
        for id in old.objects {
            if !review_objects.contains(&id) && review_objects.len() >= limits.max_objects {
                return Err(BundleInspectionRefusal::BudgetExceeded);
            }
            review_objects.insert(id);
        }
        let review_original = OriginalSource {
            inner: fabric(),
            allowed: &review_objects,
            budget: &budget,
        };
        let review_source = InspectionSource {
            original: &review_original,
            objects: &unpacked.objects,
            parse_limits: source.parse_limits,
        };
        let mut pairs = Vec::new();
        pairs
            .try_reserve_exact(commits.len() + 1)
            .map_err(|_| BundleInspectionRefusal::BudgetExceeded)?;
        pairs.push((expected_source, candidate));
        pairs.extend(commits.iter().map(|commit| (commit.parent, commit.id)));
        let comparisons =
            compare_source_series(&review_source, self.object_format, &pairs, options);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let comparisons =
            comparisons.map_err(|error| BundleInspectionRefusal::Review(Box::new(error)))?;
        let digest = sha256_digest(input);
        original.live().map_err(BundleInspectionRefusal::Source)?;
        Ok(RebaseBundleInspection {
            repository_id: self.repository_id,
            source_head: selected.basis().id(),
            source_reference: source_ref.clone(),
            onto_reference: onto_ref.clone(),
            expected_source,
            onto,
            candidate,
            commits,
            comparisons,
            bundle: InspectedBundle {
                sha256: digest,
                bytes: input.len(),
                pack_bytes: envelope.pack.len(),
                pack_objects: unpacked.objects.len(),
                expanded_bytes: unpacked.expanded_bytes,
                closure_objects: closure.objects.len(),
                transport_only_objects,
            },
        })
    }
}

fn inspect_chain(
    source: &InspectionSource<'_, '_>,
    candidate: GitOid,
    onto: GitOid,
) -> Result<Vec<InspectedRebaseCommit>, BundleInspectionRefusal> {
    let format = source.original.inner.object_format;
    let mut commits = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = candidate;
    let mut retained = 0_usize;
    while cursor != onto {
        source
            .checkpoint()
            .map_err(BundleInspectionRefusal::Source)?;
        if commits.len() >= MAX_COMMITS || !seen.insert(cursor) {
            return Err(invalid(
                "candidate does not form a bounded linear series to onto",
            ));
        }
        // Each rewritten commit must actually be supplied, not borrowed from
        // some unrelated previously admitted branch or an earlier inspection.
        let object = source
            .objects
            .get(&cursor)
            .ok_or_else(|| invalid("rewritten commit missing from uploaded pack"))?;
        if object.kind != ObjectType::Commit || object.body.len() > MAX_CANDIDATE_BYTES {
            return Err(invalid("rewritten object is not a bounded native commit"));
        }
        retained = retained
            .checked_add(object.body.len())
            .filter(|n| *n <= MAX_COMMIT_BODIES)
            .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
        let input = source
            .commit(cursor)
            .map_err(BundleInspectionRefusal::Source)?;
        let [parent] = input.parents.as_slice() else {
            return Err(invalid(
                "rebase inspection requires one parent per rewritten commit",
            ));
        };
        if input.tree.is_zero()
            || input.tree.algorithm() != format
            || parent.is_zero()
            || parent.algorithm() != format
        {
            return Err(invalid("invalid native rebase parent or tree"));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(object.body.len())
            .map_err(|_| BundleInspectionRefusal::BudgetExceeded)?;
        body.extend_from_slice(&object.body);
        commits
            .try_reserve(1)
            .map_err(|_| BundleInspectionRefusal::BudgetExceeded)?;
        commits.push(InspectedRebaseCommit {
            id: cursor,
            parent: *parent,
            tree: input.tree,
            body,
        });
        cursor = *parent;
    }
    commits.reverse();
    source
        .checkpoint()
        .map_err(BundleInspectionRefusal::Source)?;
    Ok(commits)
}
