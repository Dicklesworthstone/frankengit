//! Explicit current-source reads retain the index's original provenance.
//! This is a trusted-local read boundary, not a new remote grant or a rebuild.
use super::*;
use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseContent, SourceBrowseQuery};
use fgit_types::RepositoryCommitId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceMode {
    Exact,
    Revalidated,
}

// Namespace equality is deliberately repeated here: matching commit bytes in a
// different repository, incarnation, reference or hash domain never grants reuse.
pub(super) fn revalidates(indexed: &data::Source, current: &data::Source) -> bool {
    indexed.tenant == current.tenant
        && indexed.repository == current.repository
        && indexed.incarnation == current.incarnation
        && indexed.reference == current.reference
        && indexed.format == current.format
        && indexed.commit == current.commit
        && indexed.tree == current.tree
        && (indexed.head != current.head
            || (indexed.rcr == current.rcr && indexed.forge == current.forge))
}

impl OneNode {
    /// Exact-source persisted read. This retains the original strict contract:
    /// repository metadata changes require an explicit refresh or another mode.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, generation floor, query and independent read budgets are distinct contracts"
    )]
    pub async fn search_source_symbols_index_snapshot_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        minimum: Option<&GenerationActivation>,
        query: &SymbolQuery,
        limits: SearchLimits,
        maximum_payload_bytes: usize,
    ) -> Result<data::Report, Failure> {
        self.read_source_symbols_index_local_in(
            request,
            reference,
            expected_head,
            expected_commit,
            minimum,
            query,
            limits,
            maximum_payload_bytes,
            SourceMode::Exact,
        )
        .await
        .map(|(_, report)| report)
    }

    /// Revalidate an existing symbol index against the CURRENT visible native
    /// commit and root tree. The tuple is (current_source, original_index_report).
    /// Never replace report.source with current_source or advance its generation.
    /// Exact head/commit pins constrain the current read, not index provenance.
    ///
    /// Native commit/root-tree metadata reads use the existing bounded browser
    /// reader under this same request context. No source blob scan, publication,
    /// implicit refresh, generation fallback or renewed cancellation budget.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, generation floor, query and independent read budgets are distinct contracts"
    )]
    pub async fn search_source_symbols_index_revalidated_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        minimum: Option<&GenerationActivation>,
        query: &SymbolQuery,
        limits: SearchLimits,
        maximum_payload_bytes: usize,
    ) -> Result<(data::Source, data::Report), Failure> {
        self.read_source_symbols_index_local_in(
            request,
            reference,
            expected_head,
            expected_commit,
            minimum,
            query,
            limits,
            maximum_payload_bytes,
            SourceMode::Revalidated,
        )
        .await
    }

    pub(super) async fn current_symbol_source_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        selected: (
            RepositoryAuthorityHeadId,
            RepositoryCommitId,
            Digest,
            GitOid,
        ),
    ) -> Result<data::Source, Failure> {
        let (head, rcr, forge, commit) = selected;
        let query = SourceBrowseQuery {
            path: None,
            expected_head: Some(head),
            expected_commit: Some(commit),
            action: SourceBrowseAction::List {
                after: None,
                limit: 1,
            },
        };
        // The native reader verifies the original commit/root tree and checks
        // current visibility again. A moved head refuses; it is not reselected.
        let native = self
            .browse_source_local_in(request, reference, &query)
            .await
            .map_err(Failure::Source)?;
        live(request)?;
        if native.repository_id != self.repository_id
            || native.source_head != head
            || native.source_rcr != rcr
            || native.source_commit != commit
            || native.path.is_some()
            || native.object_id != native.root_tree
            || native.root_tree.is_zero()
            || native.root_tree.algorithm() != self.object_format
            || !matches!(native.content, SourceBrowseContent::Directory { .. })
        {
            return Err(Failure::Index(data::Error::Invalid(
                "current native source",
            )));
        }
        Ok(data::Source {
            tenant: self.tenant_id,
            repository: self.repository_id,
            incarnation: self.repository_incarnation_id(),
            format: self.object_format,
            reference: reference.clone(),
            head,
            rcr,
            forge,
            commit,
            tree: native.root_tree,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_crypto::{IdentityDomain, internal_object_id};
    use fgit_types::{CodecVersion, RepositoryId, RepositoryIncarnationId, TenantId};

    fn source(label: &[u8]) -> data::Source {
        let id = |domain, family| {
            internal_object_id(
                domain,
                SchemaId::new(SchemaFamily::from_static(family), 1, 0),
                CodecVersion::new(1, 0),
                label,
            )
        };
        data::Source {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            format: Format::Sha1,
            reference: RefName::try_new(b"refs/heads/main").unwrap(),
            head: RepositoryAuthorityHeadId::from_internal_object_id(id(
                IdentityDomain::RepositoryAuthorityHead,
                "repository-authority-head",
            ))
            .unwrap(),
            rcr: RepositoryCommitId::from_internal_object_id(id(
                IdentityDomain::RepositoryCommitRecord,
                "repository-commit-record",
            ))
            .unwrap(),
            forge: {
                let value = id(IdentityDomain::MerkleLeaf, "test-forge");
                Digest::new(value.algorithm(), *value.digest())
            },
            commit: fgit_crypto::git_object_id(
                Format::Sha1,
                fgit_crypto::GitObjectKind::Commit,
                b"commit",
            ),
            tree: fgit_crypto::git_object_id(
                Format::Sha1,
                fgit_crypto::GitObjectKind::Tree,
                b"tree",
            ),
        }
    }

    #[test]
    fn changed_metadata_can_revalidate_only_the_same_native_source() {
        let before = source(b"before");
        let after = source(b"after");
        assert_ne!(before.head, after.head);
        assert_ne!(before.rcr, after.rcr);
        assert_ne!(before.forge, after.forge);
        assert!(revalidates(&before, &before));
        assert!(revalidates(&before, &after));
        // The predicate cannot mutate either source or manufacture a new index.
        assert_eq!(before, source(b"before"));
        assert_eq!(after, source(b"after"));
    }

    #[test]
    fn all_namespace_ref_and_native_identity_coordinates_are_required() {
        let before = source(b"before");
        let mut changed = Vec::new();
        let mut s = source(b"after");
        s.tenant = TenantId::from_bytes([8; 16]);
        changed.push(s);
        let mut s = source(b"after");
        s.repository = RepositoryId::from_bytes([8; 16]);
        changed.push(s);
        let mut s = source(b"after");
        s.incarnation = RepositoryIncarnationId::from_bytes([8; 16]);
        changed.push(s);
        let mut s = source(b"after");
        s.reference = RefName::try_new(b"refs/heads/other").unwrap();
        changed.push(s);
        let mut s = source(b"after");
        s.format = Format::Sha256;
        changed.push(s);
        let mut s = source(b"after");
        s.commit = fgit_crypto::git_object_id(
            Format::Sha1,
            fgit_crypto::GitObjectKind::Commit,
            b"other commit",
        );
        changed.push(s);
        let mut s = source(b"after");
        s.tree = fgit_crypto::git_object_id(
            Format::Sha1,
            fgit_crypto::GitObjectKind::Tree,
            b"other tree",
        );
        changed.push(s);
        for s in changed {
            assert!(!revalidates(&before, &s));
        }
    }

    #[test]
    fn one_head_cannot_have_two_rcr_or_forge_identities() {
        let before = source(b"before");
        let mut different_rcr = before.clone();
        different_rcr.rcr = source(b"after").rcr;
        let mut different_forge = before.clone();
        different_forge.forge = source(b"after").forge;
        assert!(!revalidates(&before, &different_rcr));
        assert!(!revalidates(&before, &different_forge));
    }
}
