use super::*;

fn scope() -> Scope<'static> {
    Scope {
        store_root: Path::new("/cache-tests/store"),
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format: GitHashAlgorithm::Sha1,
    }
}

fn metadata(format: GitHashAlgorithm, message: &str) -> VerifiedCommitMetadata {
    let tree = git_object_id(format, ObjectType::Tree, b"");
    let parent = git_object_id(format, ObjectType::Commit, b"parent fixture");
    let body = format!(
        "tree {tree}\nparent {parent}\nparent {parent}\nauthor Test <t@example.invalid> 1 +0000\ncommitter Test <t@example.invalid> 123 +0000\nextra first\n continued\n\n{message}"
    );
    let id = git_object_id(format, ObjectType::Commit, body.as_bytes());
    VerifiedCommitMetadata::parse(id, body.as_bytes(), &ParseLimits::default()).unwrap()
}

#[test]
fn exact_verified_metadata_preserves_parent_order_dates_and_parser_budgets() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scope = Scope { format, ..scope() };
        let entry = metadata(format, "message is not retained");
        let id = entry.id;
        let expected = entry.try_copy().unwrap().into_commit();
        assert_eq!(expected.0.parents.len(), 2);
        assert_eq!(expected.0.parents[0], expected.0.parents[1]);
        assert_eq!(expected.1, Some(123));
        let cache = AncestryMetadataCache::new(16 * 1024);
        cache.insert(scope, &entry);
        assert_eq!(
            cache
                .lookup(scope, id, &ParseLimits::default(), usize::MAX)
                .unwrap()
                .unwrap()
                .into_commit(),
            expected
        );
        for narrowed in [
            ParseLimits {
                max_object_bytes: entry.body_bytes - 1,
                ..ParseLimits::default()
            },
            ParseLimits {
                max_header_lines: entry.header_lines - 1,
                ..ParseLimits::default()
            },
            ParseLimits {
                max_header_line_bytes: entry.maximum_header_line_bytes - 1,
                ..ParseLimits::default()
            },
        ] {
            assert!(matches!(
                cache.lookup(scope, id, &narrowed, usize::MAX),
                Some(Err(MergeSourceError::BudgetExceeded))
            ));
        }
        assert!(matches!(
            cache.lookup(scope, id, &ParseLimits::default(), entry.body_bytes - 1),
            Some(Err(MergeSourceError::BudgetExceeded))
        ));
        let exact = ParseLimits {
            max_object_bytes: entry.body_bytes,
            max_header_lines: entry.header_lines,
            max_header_line_bytes: entry.maximum_header_line_bytes,
            ..ParseLimits::default()
        };
        assert!(
            cache
                .lookup(scope, id, &exact, entry.body_bytes)
                .unwrap()
                .is_ok()
        );
    }
}

#[test]
fn repository_incarnation_format_and_store_are_all_part_of_scope() {
    let scope = scope();
    let entry = metadata(scope.format, "scope");
    let cache = AncestryMetadataCache::new(16 * 1024);
    cache.insert(scope, &entry);
    for other in [
        Scope {
            store_root: Path::new("/cache-tests/other-store"),
            ..scope
        },
        Scope {
            tenant: TenantId::from_bytes([4; 16]),
            ..scope
        },
        Scope {
            repository: RepositoryId::from_bytes([5; 16]),
            ..scope
        },
        Scope {
            incarnation: RepositoryIncarnationId::from_bytes([6; 16]),
            ..scope
        },
        Scope {
            format: GitHashAlgorithm::Sha256,
            ..scope
        },
    ] {
        assert!(
            cache
                .lookup(other, entry.id, &ParseLimits::default(), usize::MAX)
                .is_none()
        );
    }
    let other = Scope {
        store_root: Path::new("/cache-tests/other-store"),
        ..scope
    };
    cache.insert(other, &entry);
    assert!(
        cache
            .lookup(scope, entry.id, &ParseLimits::default(), usize::MAX)
            .is_none()
    );
    assert!(
        cache
            .lookup(other, entry.id, &ParseLimits::default(), usize::MAX)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn byte_bound_fifo_disable_and_busy_cache_fall_back_without_retaining_bodies() {
    let scope = scope();
    let first = metadata(scope.format, "first");
    let second = metadata(scope.format, "second");
    let third = metadata(scope.format, "third");
    let scope_bytes = OwnedScope::from_scope(scope).retained_bytes().unwrap();
    let budget = scope_bytes + first.retained_bytes().unwrap() + second.retained_bytes().unwrap();
    let cache = AncestryMetadataCache::new(budget);
    cache.insert(scope, &first);
    cache.insert(scope, &second);
    cache.insert(scope, &third);
    let read = |id| cache.lookup(scope, id, &ParseLimits::default(), usize::MAX);
    assert!(read(first.id).is_none());
    assert!(read(second.id).unwrap().is_ok());
    assert!(read(third.id).unwrap().is_ok());
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 2);
        assert!(state.retained_bytes <= budget);
        assert!(
            read(second.id).is_none(),
            "contention is a miss, never a wait"
        );
        cache.insert(scope, &first);
        assert_eq!(state.entries.len(), 2);
    }
    let disabled = AncestryMetadataCache::new(0);
    disabled.insert(scope, &first);
    assert!(
        disabled
            .lookup(scope, first.id, &ParseLimits::default(), usize::MAX)
            .is_none()
    );
    let undersized = AncestryMetadataCache::new(scope_bytes + first.retained_bytes().unwrap() - 1);
    undersized.insert(scope, &first);
    assert!(undersized.state.lock().unwrap().entries.is_empty());

    let large_message = "m".repeat(256 * 1024);
    let large = metadata(scope.format, &large_message);
    // Retained allocation depends on adjacency, not a commit's message size.
    assert_eq!(large.retained_bytes(), first.retained_bytes());
    let small_cache = AncestryMetadataCache::new(scope_bytes + large.retained_bytes().unwrap());
    small_cache.insert(scope, &large);
    assert!(
        small_cache
            .lookup(scope, large.id, &ParseLimits::default(), usize::MAX)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn invalid_native_bytes_or_ambiguous_edges_cannot_construct_cache_entries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let tree = git_object_id(format, ObjectType::Tree, b"");
        let valid = format!("tree {tree}\n\nvalid");
        let id = git_object_id(format, ObjectType::Commit, valid.as_bytes());
        assert!(matches!(
            VerifiedCommitMetadata::parse(id, b"changed bytes", &ParseLimits::default()),
            Err(MergeSourceError::InvalidObject(observed)) if observed == id
        ));
        for body in [
            format!("tree {tree}\ntree {tree}\n\nambiguous"),
            format!("tree {tree}\n continued\n\nambiguous"),
            format!("tree {tree}\nparent {tree}\n continued\n\nambiguous"),
            "tree invalid\n\nbad edge".into(),
        ] {
            let id = git_object_id(format, ObjectType::Commit, body.as_bytes());
            assert!(matches!(
                VerifiedCommitMetadata::parse(id, body.as_bytes(), &ParseLimits::default()),
                Err(MergeSourceError::InvalidObject(observed)) if observed == id
            ));
        }
        assert!(
            VerifiedCommitMetadata::parse(id, valid.as_bytes(), &ParseLimits::default()).is_ok()
        );
    }
}
