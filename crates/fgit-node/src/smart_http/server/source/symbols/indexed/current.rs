//! A distinct wire receipt for current-source revalidation. The nested result
//! retains its original exact-source profile; consumers must not relabel it.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceMode {
    Exact,
    Revalidated,
}
impl SourceMode {
    pub(super) fn parse(value: Option<&str>) -> Result<Self, ApiError> {
        match value.unwrap_or("exact") {
            "exact" => Ok(Self::Exact),
            "revalidated" => Ok(Self::Revalidated),
            _ => Err(ApiError::bad("unsupported_symbol_source_mode")),
        }
    }
}

fn source_json(source: &data::Source) -> String {
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

pub(super) fn render(
    node: &OneNode,
    command: &Command,
    current: &data::Source,
    report: &data::Report,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let indexed = &report.source;
    if current.tenant != node.tenant_id
        || current.repository != node.repository_id
        || current.incarnation != node.repository_incarnation_id()
        || current.format != node.object_format
        || current.reference != command.selection.reference
        || current.tenant != indexed.tenant
        || current.repository != indexed.repository
        || current.incarnation != indexed.incarnation
        || current.format != indexed.format
        || current.reference != indexed.reference
        || current.commit != indexed.commit
        || current.tree != indexed.tree
        || (current.head == indexed.head
            && (current.rcr != indexed.rcr || current.forge != indexed.forge))
        || command.selection.expected_head.is_some_and(|id| id != current.head)
        || command.selection.expected_commit.is_some_and(|id| id != current.commit)
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_search_symbols_index_revalidated\",\"schema_version\":1,",
                "\"source_mode\":\"revalidated\",\"read_only\":true,",
                "\"transaction_created\":false,\"published\":false,",
                "\"current_source\":{},\"indexed_source\":{},\"result\":"
            ),
            source_json(current),
            source_json(indexed),
        ),
        maximum,
    )?;
    // The request pins CURRENT source; the nested receipt describes ORIGINAL
    // index provenance. Use the unchanged strict renderer with those original
    // pins only after the complete current/index binding above has been checked.
    let original = Command {
        selection: Selection {
            reference: indexed.reference.clone(),
            expected_head: Some(indexed.head),
            expected_commit: Some(indexed.commit),
        },
        query: command.query.clone(),
        limits: command.limits,
    };
    let nested = super::render(
        node,
        &original,
        report,
        maximum
            .min(super::super::super::output::MAX_REPLY_BYTES)
            .saturating_sub(out.len() + 1),
        live,
    )?;
    append(&mut out, &nested, maximum)?;
    append(&mut out, "}", maximum)?;
    check(live)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    const FORM: &str = "object_format=sha1&ref=refs/heads/main&name_hex=5468696e67";

    #[test]
    fn strict_is_the_default_and_revalidation_is_never_an_error_fallback() {
        let (_, _, default) = indexed_command(FORM.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
        let (_, _, exact) = indexed_command(
            (FORM.to_owned() + "&source_mode=exact").as_bytes(), GitHashAlgorithm::Sha1,
        ).unwrap();
        let (_, _, current) = indexed_command(
            (FORM.to_owned() + "&source_mode=revalidated").as_bytes(), GitHashAlgorithm::Sha1,
        ).unwrap();
        assert_eq!(default, SourceMode::Exact);
        assert_eq!(exact, default);
        assert_eq!(current, SourceMode::Revalidated);
    }

    #[test]
    fn unknown_duplicate_or_scanning_modes_refuse_before_source_reads() {
        for extra in ["&source_mode=", "&source_mode=current", "&source_mode=REVALIDATED",
            "&source_mode=exact&source_mode=revalidated", "&source_mode=revalidated&force=true"] {
            assert!(indexed_command((FORM.to_owned() + extra).as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
        assert!(command((FORM.to_owned() + "&source_mode=revalidated").as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }

    #[test]
    fn revalidation_retains_the_exact_checkpoint_and_query() {
        let body = format!("{FORM}&source_mode=revalidated&minimum_index_token=alg:2:{}&minimum_index_number=7&match=prefix&kind=struct&path_prefix_hex=737263", "a".repeat(64));
        let (command, minimum, mode) = indexed_command(body.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
        assert_eq!(mode, SourceMode::Revalidated);
        assert_eq!(minimum.unwrap().authority_generation.get(), 7);
        assert_eq!(command.query.name(), b"Thing");
        assert_eq!(command.query.mode(), SymbolMatchMode::Prefix);
        assert_eq!(command.query.kinds(), &[SymbolKind::Struct]);
        assert_eq!(command.query.source_scope().prefixes()[0].as_bytes(), b"src");
    }

    // These are renderer contracts using real node namespace configuration and
    // synthetic typed receipts, not evidence of live source selection.
    fn with_report(mut test: impl FnMut(&OneNode, &Command, &data::Source, &data::Report)) {
        use fgit_crypto::{IdentityDomain, internal_object_id};
        use fgit_types::{CodecVersion, RepositoryAuthorityHeadId, RepositoryCommitId,
            RepositoryId, SchemaFamily, SchemaId, TenantId};
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let root = std::env::temp_dir().join(format!(
                "fg-symbol-current-render-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&root).unwrap();
            let (node, _) = OneNode::init(crate::NodeConfig::new(
                root.join("node"), TenantId::from_bytes([1; 16]), RepositoryId::from_bytes([2; 16]),
            ).with_object_format(format).with_worker_threads(2)).unwrap();
            let id = |domain, family, bytes: &[u8]| internal_object_id(
                domain, SchemaId::new(SchemaFamily::from_static(family), 1, 0),
                CodecVersion::new(1, 0), bytes,
            );
            let source = |label: &[u8]| data::Source {
                tenant: node.tenant_id,
                repository: node.repository_id,
                incarnation: node.repository_incarnation_id(),
                format,
                reference: RefName::try_new(b"refs/heads/main").unwrap(),
                head: RepositoryAuthorityHeadId::from_internal_object_id(id(
                    IdentityDomain::RepositoryAuthorityHead, "repository-authority-head", label,
                )).unwrap(),
                rcr: RepositoryCommitId::from_internal_object_id(id(
                    IdentityDomain::RepositoryCommitRecord, "repository-commit-record", label,
                )).unwrap(),
                forge: {
                    let value = id(IdentityDomain::MerkleLeaf, "test-forge", label);
                    fgit_types::Digest::new(value.algorithm(), *value.digest())
                },
                commit: fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Commit, b"commit"),
                tree: fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Tree, b"tree"),
            };
            let current = source(b"current");
            let report = data::Report {
                source: source(b"indexed"),
                matches: Vec::new(),
                complete: true,
                generation: id(IdentityDomain::Generation, "test-generation", b"generation"),
                generation_number: 7,
                indexed_files: 0,
                indexed_declarations: 0,
                indexed_source_bytes: 0,
                unsupported_language_files: 1,
                non_regular_entries: 0,
                tables_read: 0,
                payload_bytes_read: 128,
                work_units: 0,
            };
            let command = Command {
                selection: Selection {
                    reference: current.reference.clone(),
                    expected_head: Some(current.head),
                    expected_commit: Some(current.commit),
                },
                query: SymbolQuery::new(b"Thing", SymbolMatchMode::Exact, &[], &[], MAX_SYMBOL_WORK).unwrap(),
                limits: SearchLimits::default(),
            };
            test(&node, &command, &current, &report);
            node.shutdown().unwrap();
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn wrapper_preserves_original_receipt_and_charges_all_bytes_once() {
        with_report(|node, command, current, report| {
            let original = Command {
                selection: Selection {
                    reference: report.source.reference.clone(),
                    expected_head: Some(report.source.head),
                    expected_commit: Some(report.source.commit),
                },
                query: command.query.clone(),
                limits: command.limits,
            };
            let nested = super::super::render(node, &original, report, usize::MAX, &mut || true).unwrap();
            let body = render(node, command, current, report, usize::MAX, &mut || true).unwrap();
            assert!(body.contains(&format!("\"current_source\":{}", source_json(current))));
            assert!(body.contains(&format!("\"indexed_source\":{}", source_json(&report.source))));
            assert_eq!(body.split_once("\"result\":").unwrap().1, format!("{nested}}}"));
            assert_eq!(render(node, command, current, report, body.len(), &mut || true).unwrap(), body);
            for limit in [0, 1, nested.len(), body.len() - 1] {
                assert!(render(node, command, current, report, limit, &mut || true).is_err());
            }
        });
    }

    #[test]
    fn wrapper_cancellation_never_returns_a_partial_receipt() {
        with_report(|node, command, current, report| {
            let mut calls = 0;
            render(node, command, current, report, usize::MAX, &mut || { calls += 1; true }).unwrap();
            assert!(calls >= 4);
            for stop in 1..=calls {
                let mut seen = 0;
                assert!(render(node, command, current, report, usize::MAX, &mut || {
                    seen += 1;
                    seen != stop
                }).is_err());
                assert_eq!(seen, stop);
            }
        });
    }

    #[test]
    fn wrapper_rejects_changed_native_coordinates_current_pins_and_bad_nested_receipts() {
        with_report(|node, command, current, report| {
            let mut other = current.clone();
            other.commit = fgit_crypto::git_object_id(current.format, fgit_crypto::GitObjectKind::Commit, b"other");
            assert!(render(node, command, &other, report, usize::MAX, &mut || true).is_err());
            let mut other = current.clone(); other.tree = other.commit;
            assert!(render(node, command, &other, report, usize::MAX, &mut || true).is_err());
            let mut other = current.clone(); other.tenant = fgit_types::TenantId::from_bytes([9; 16]);
            assert!(render(node, command, &other, report, usize::MAX, &mut || true).is_err());
            // The old index coordinates cannot substitute for requested current pins.
            assert!(render(node, command, &report.source, report, usize::MAX, &mut || true).is_err());
            let mut malformed = report.clone(); malformed.generation_number = 0;
            assert!(render(node, command, current, &malformed, usize::MAX, &mut || true).is_err());
            let mut malformed = report.clone(); malformed.source.head = current.head;
            assert!(render(node, command, current, &malformed, usize::MAX, &mut || true).is_err());
            assert!(render(node, command, current, report, usize::MAX, &mut || true).is_ok());
        });
    }
}
