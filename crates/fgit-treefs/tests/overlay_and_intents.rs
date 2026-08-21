//! Overlay semantics, copy-on-write isolation, intent replay, and the epoch
//! invariant.
//!
//! These cover the bead's acceptance lines directly: the overlay stores intents
//! and content rather than tree copies, replay reproduces an overlay byte for
//! byte, two workspaces over one base cannot see each other, and
//! `staged >= visible >= durable` survives every write/flush/sync ordering.

use fgit_treefs::intent::{
    BasisEntry, IntentError, IntentLog, NetEffect, NoOpReason, TreeEditIntent,
};
use fgit_treefs::overlay::{
    ContentRef, EntryClass, FileMode, Overlay, OverlayEntry, OverlayLookup,
};
use fgit_treefs::path::TreePath;
use fgit_treefs::snapshot::{EpochRefusal, EpochSet, OverlayRoot, WorkspaceEpoch};

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("test path parses")
}

/// A base containing `count` files under `src/`, for sparseness assertions.
fn wide_base(count: usize) -> impl Fn(&TreePath) -> bool {
    move |candidate: &TreePath| {
        let bytes = candidate.as_bytes();
        if !bytes.starts_with(b"src/f") {
            return false;
        }
        let suffix = &bytes[b"src/f".len()..];
        core::str::from_utf8(suffix)
            .ok()
            .and_then(|text| text.parse::<usize>().ok())
            .is_some_and(|index| index < count)
    }
}

fn write(target: &[u8], body: &[u8]) -> TreeEditIntent {
    TreeEditIntent::Write {
        path: path(target),
        content: body.to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    }
}

// ---------------------------------------------------------------------------
// overlay semantics: read-through, shadowing, delete markers
// ---------------------------------------------------------------------------

/// An absent overlay entry means "consult the base"; it must never be confused
/// with a delete.
#[test]
fn absent_entry_reads_through_and_whiteout_does_not() {
    let mut overlay = Overlay::new();
    let untouched = path(b"src/f1");
    let deleted = path(b"src/f2");

    assert!(matches!(overlay.lookup(&untouched), OverlayLookup::Absent));

    overlay.put(deleted.clone(), OverlayEntry::Whiteout);
    assert!(matches!(overlay.lookup(&deleted), OverlayLookup::Deleted));
    assert!(
        matches!(overlay.lookup(&untouched), OverlayLookup::Absent),
        "deleting one path must not affect another"
    );
}

/// An overlay entry shadows whatever the base holds at the same path.
#[test]
fn overlay_entry_shadows_the_base() {
    let mut overlay = Overlay::new();
    let target = path(b"src/f1");
    let id = overlay.intern(b"overlay body".to_vec());
    overlay.put(
        target.clone(),
        OverlayEntry::File {
            content: ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    match overlay.lookup(&target) {
        OverlayLookup::Present(entry) => {
            assert!(entry.shadows_base());
            assert_eq!(overlay.body(entry).unwrap(), b"overlay body");
        }
        other => panic!("expected a present entry, got {other:?}"),
    }
}

/// Deleting a directory hides its descendants without enumerating them, which
/// is what keeps a sparse delete sparse.
#[test]
fn ancestor_whiteout_hides_descendants_without_enumerating_them() {
    let mut overlay = Overlay::new();
    overlay.put(path(b"src/vendor"), OverlayEntry::Whiteout);

    match overlay.lookup(&path(b"src/vendor/deep/nested/file.rs")) {
        OverlayLookup::DeletedByAncestor { ancestor } => {
            assert_eq!(ancestor.as_bytes(), b"src/vendor");
        }
        other => panic!("expected deletion by ancestor, got {other:?}"),
    }

    assert_eq!(
        overlay.stats().entry_count,
        1,
        "hiding a whole subtree must cost exactly one entry"
    );
    assert!(
        matches!(
            overlay.lookup(&path(b"src/vendored")),
            OverlayLookup::Absent
        ),
        "a sibling whose name merely shares a byte prefix is untouched"
    );
}

// ---------------------------------------------------------------------------
// sparseness: intents and content, never full-tree copies
// ---------------------------------------------------------------------------

/// Editing one file in a large base costs one entry and one body, regardless of
/// how big the base is.
#[test]
fn overlay_size_tracks_the_edit_not_the_base() {
    let small = wide_base(10);
    let huge = wide_base(100_000);

    let mut log = IntentLog::new();
    log.push(write(b"src/f7", b"edited"));

    let (overlay_small, _) = log.evaluate(&small);
    let (overlay_huge, _) = log.evaluate(&huge);

    assert_eq!(overlay_small.stats(), overlay_huge.stats());
    assert_eq!(overlay_huge.stats().entry_count, 1);
    assert_eq!(overlay_huge.stats().body_count, 1);
    assert_eq!(overlay_huge.stats().body_bytes, b"edited".len());
}

/// Writing identical bytes to many paths stores one body.
#[test]
fn identical_bodies_are_stored_once() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    for name in [&b"a.txt"[..], b"b.txt", b"c.txt", b"d.txt"] {
        log.push(write(name, b"same bytes"));
    }
    let (overlay, evaluation) = log.evaluate(&base);

    assert_eq!(overlay.stats().entry_count, 4);
    assert_eq!(
        overlay.stats().body_count,
        1,
        "four paths sharing bytes store one body"
    );
    assert_eq!(evaluation.surviving(), 4);
}

/// A mode-only change records no new body.
#[test]
fn chmod_against_a_base_file_copies_no_bytes() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Chmod {
        path: path(b"src/f3"),
        basis_entry: Some(BasisEntry {
            oid: vec![0x11; 20],
            mode: FileMode::Regular,
        }),
        after: FileMode::Executable,
    });
    let (overlay, evaluation) = log.evaluate(&base);

    assert_eq!(evaluation.surviving(), 1);
    assert_eq!(overlay.stats().entry_count, 1);
    assert_eq!(
        overlay.stats().body_bytes,
        0,
        "a mode-only change must not copy the file body"
    );
}

// ---------------------------------------------------------------------------
// copy-on-write isolation
// ---------------------------------------------------------------------------

/// Two workspaces over one base do not observe each other's writes.
#[test]
fn workspaces_sharing_a_base_are_isolated() {
    let base = wide_base(100);

    let mut left_log = IntentLog::new();
    left_log.push(write(b"src/f1", b"left"));
    let (left, _) = left_log.evaluate(&base);

    let mut right_log = IntentLog::new();
    right_log.push(write(b"src/f1", b"right"));
    right_log.push(write(b"src/f2", b"right only"));
    let (right, _) = right_log.evaluate(&base);

    let target = path(b"src/f1");
    let left_body = match left.lookup(&target) {
        OverlayLookup::Present(entry) => left.body(entry).unwrap().to_vec(),
        other => panic!("expected an entry, got {other:?}"),
    };
    let right_body = match right.lookup(&target) {
        OverlayLookup::Present(entry) => right.body(entry).unwrap().to_vec(),
        other => panic!("expected an entry, got {other:?}"),
    };

    assert_eq!(left_body, b"left");
    assert_eq!(right_body, b"right");
    assert!(
        matches!(left.lookup(&path(b"src/f2")), OverlayLookup::Absent),
        "the left workspace must not see the right workspace's second write"
    );
    assert_ne!(OverlayRoot::of(&left), OverlayRoot::of(&right));
}

/// Mutating one overlay after cloning it does not disturb the clone.
#[test]
fn cloned_overlays_do_not_share_mutable_state() {
    let mut original = Overlay::new();
    let id = original.intern(b"first".to_vec());
    original.put(
        path(b"a.txt"),
        OverlayEntry::File {
            content: ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let snapshot = original.clone();
    let root_before = OverlayRoot::of(&snapshot);

    original.put(path(b"b.txt"), OverlayEntry::Whiteout);

    assert_eq!(snapshot.stats().entry_count, 1);
    assert_eq!(original.stats().entry_count, 2);
    assert_eq!(
        OverlayRoot::of(&snapshot),
        root_before,
        "the clone's root must not move when the original is edited"
    );
}

// ---------------------------------------------------------------------------
// intent replay
// ---------------------------------------------------------------------------

/// Replaying a log against the same base reproduces the overlay byte for byte.
#[test]
fn intent_replay_reproduces_the_overlay_exactly() {
    let base = wide_base(50);
    let mut log = IntentLog::new();
    log.push(write(b"src/f1", b"one"));
    log.push(TreeEditIntent::CreateDirectory {
        path: path(b"docs"),
    });
    log.push(write(b"docs/readme.md", b"hello"));
    log.push(TreeEditIntent::CreateSymlink {
        path: path(b"link"),
        link_target: b"docs/readme.md".to_vec(),
    });
    log.push(TreeEditIntent::Delete {
        path: path(b"src/f2"),
    });
    log.push(TreeEditIntent::Chmod {
        path: path(b"src/f1"),
        basis_entry: None,
        after: FileMode::Executable,
    });
    log.push(TreeEditIntent::UpdateSubmodule {
        path: path(b"vendor/lib"),
        after_oid: vec![0xAB; 20],
    });
    log.push(TreeEditIntent::RecordConflictMarkers {
        path: path(b"src/f3"),
        marker: b"<<<<<<< ours\na\n=======\nb\n>>>>>>> theirs\n".to_vec(),
        merge_inputs: vec![b"ours".to_vec(), b"theirs".to_vec()],
    });

    let (first, first_eval) = log.evaluate(&base);
    let (second, second_eval) = log.evaluate(&base);

    assert_eq!(first, second, "replay must reproduce the overlay exactly");
    assert_eq!(OverlayRoot::of(&first), OverlayRoot::of(&second));
    assert_eq!(first_eval, second_eval);
    assert_eq!(
        first_eval.len(),
        log.len(),
        "the totality map has exactly one outcome per source intent"
    );
}

/// Replay is stable across many rounds, so nothing depends on allocation
/// addresses, map iteration order, or a clock.
#[test]
fn replay_is_stable_across_repeated_evaluation() {
    let base = wide_base(20);
    let mut log = IntentLog::new();
    for index in 0..16_u32 {
        log.push(write(
            format!("gen/{index}.txt").as_bytes(),
            format!("body {index}").as_bytes(),
        ));
    }

    let (reference, _) = log.evaluate(&base);
    let reference_root = OverlayRoot::of(&reference);
    for _ in 0..8 {
        let (again, _) = log.evaluate(&base);
        assert_eq!(OverlayRoot::of(&again), reference_root);
    }
}

// ---------------------------------------------------------------------------
// net-effect folding and totality
// ---------------------------------------------------------------------------

/// Repeated writes to one path collapse to the final content, and the
/// superseded intent is recorded as such rather than dropped.
#[test]
fn repeated_writes_collapse_and_name_their_successor() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(write(b"a.txt", b"first"));
    log.push(write(b"a.txt", b"second"));
    log.push(write(b"a.txt", b"third"));

    let (effect, evaluation) = log.fold(&base);

    assert_eq!(effect.len(), 1, "three writes to one path leave one effect");
    assert_eq!(evaluation.len(), 3);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::NoOp(NoOpReason::SupersededByLaterIntent { by_index: 1 })
    ));
    assert!(matches!(
        evaluation.outcomes()[1],
        NetEffect::NoOp(NoOpReason::SupersededByLaterIntent { by_index: 2 })
    ));
    assert!(matches!(
        evaluation.outcomes()[2],
        NetEffect::Survives { .. }
    ));
}

/// Create-then-delete within one log is explicit inverse cancellation, not a
/// silently vanished pair.
#[test]
fn create_then_delete_is_inverse_cancellation() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(write(b"scratch.txt", b"temporary"));
    log.push(TreeEditIntent::Delete {
        path: path(b"scratch.txt"),
    });

    let (effect, evaluation) = log.fold(&base);

    assert!(
        effect.is_empty(),
        "nothing survives a create/delete pair on a path absent from the base"
    );
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::NoOp(NoOpReason::InverseCancellation { by_index: 1 })
    ));
    assert!(matches!(
        evaluation.outcomes()[1],
        NetEffect::NoOp(NoOpReason::InverseCancellation { by_index: 1 })
    ));
}

/// Deleting a path that exists in the base survives as a whiteout — the
/// permitted counterpart of the cancellation case above.
#[test]
fn deleting_a_base_path_survives_as_a_whiteout() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Delete {
        path: path(b"src/f4"),
    });

    let (effect, evaluation) = log.fold(&base);

    assert_eq!(effect.len(), 1);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::Survives { .. }
    ));
    assert_eq!(
        effect.effects().get(&path(b"src/f4")),
        Some(&OverlayEntry::Whiteout)
    );
}

/// Writing the bytes that are already there is a named no-op.
#[test]
fn identical_rewrite_is_a_named_no_op() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(write(b"a.txt", b"same"));
    log.push(write(b"a.txt", b"same"));

    let (_, evaluation) = log.fold(&base);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::Survives { .. }
    ));
    assert!(matches!(
        evaluation.outcomes()[1],
        NetEffect::NoOp(NoOpReason::AlreadyIdentical)
    ));
}

/// Every source intent maps to exactly one outcome, and the fold is
/// target-disjoint by construction.
#[test]
fn every_intent_maps_to_exactly_one_outcome() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(write(b"a.txt", b"one"));
    log.push(write(b"a.txt", b"two"));
    log.push(TreeEditIntent::Delete {
        path: path(b"src/f1"),
    });
    log.push(TreeEditIntent::Rename {
        from: path(b"src/f2"),
        to: path(b"moved.txt"),
        basis_entry: Some(BasisEntry {
            oid: vec![0x22; 20],
            mode: FileMode::Regular,
        }),
    });
    log.push(TreeEditIntent::Rename {
        from: path(b"does/not/exist"),
        to: path(b"nowhere.txt"),
        basis_entry: None,
    });

    let (effect, evaluation) = log.fold(&base);

    assert_eq!(evaluation.len(), log.len());
    for outcome in evaluation.outcomes() {
        assert!(matches!(
            outcome,
            NetEffect::Survives { .. } | NetEffect::NoOp(_) | NetEffect::Error(_)
        ));
    }
    assert_eq!(
        evaluation.errors().len(),
        1,
        "the rename with a missing source is a statement error"
    );
    // A BTreeMap key set is disjoint by construction; assert the count matches
    // the distinct surviving targets so a regression to a Vec would be caught.
    let distinct: std::collections::BTreeSet<_> = effect.effects().keys().collect();
    assert_eq!(distinct.len(), effect.len());
}

/// An edit beneath a deleted ancestor is a statement error, while the same edit
/// beside it proceeds.
#[test]
fn edit_under_deleted_ancestor_errors_but_a_sibling_proceeds() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Delete { path: path(b"src") });
    log.push(write(b"src/f1", b"doomed"));
    log.push(write(b"docs/f1", b"fine"));

    let (_, evaluation) = log.fold(&base);

    assert!(matches!(evaluation.outcomes()[1], NetEffect::Error(_)));
    assert!(matches!(
        evaluation.outcomes()[2],
        NetEffect::Survives { .. }
    ));
}

// ---------------------------------------------------------------------------
// epoch invariant
// ---------------------------------------------------------------------------

/// A fresh set satisfies the invariant and every ordinary sequence preserves it.
#[test]
fn epochs_hold_the_invariant_across_write_flush_sync() {
    let mut epochs = EpochSet::new();
    assert!(epochs.invariant_holds());

    for _ in 0..5 {
        epochs = epochs.stage();
        assert!(epochs.invariant_holds());
        epochs = epochs.publish().expect("publish never exceeds staged");
        assert!(epochs.invariant_holds());
        epochs = epochs.sync().expect("sync never exceeds visible");
        assert!(epochs.invariant_holds());
    }

    assert_eq!(epochs.staged(), WorkspaceEpoch::from_u64(5));
    assert_eq!(epochs.visible(), epochs.staged());
    assert_eq!(epochs.durable(), epochs.visible());
}

/// Staging repeatedly without publishing leaves visible and durable behind, and
/// the invariant still holds — the three are separate facts.
#[test]
fn staging_without_publishing_leaves_the_others_behind() {
    let mut epochs = EpochSet::new();
    for _ in 0..4 {
        epochs = epochs.stage();
    }
    assert!(epochs.invariant_holds());
    assert_eq!(epochs.staged().get(), 4);
    assert_eq!(epochs.visible().get(), 0);
    assert_eq!(epochs.durable().get(), 0);

    epochs = epochs.publish().unwrap();
    assert_eq!(epochs.visible().get(), 4);
    assert_eq!(
        epochs.durable().get(),
        0,
        "publishing must not make anything durable"
    );

    epochs = epochs.sync().unwrap();
    assert_eq!(epochs.durable().get(), 4);
}

/// Syncing without publishing advances durable only to visible, never past it.
#[test]
fn sync_cannot_outrun_visible() {
    let epochs = EpochSet::new().stage().stage();
    let synced = epochs.sync().expect("sync with nothing visible is a no-op");
    assert_eq!(synced.durable().get(), 0);
    assert_eq!(synced.visible().get(), 0);
    assert_eq!(synced.staged().get(), 2);
    assert!(synced.invariant_holds());
}

/// A violating combination cannot be constructed at all.
#[test]
fn violating_epoch_sets_are_refused_at_construction() {
    assert!(matches!(
        EpochSet::try_new(
            WorkspaceEpoch::from_u64(1),
            WorkspaceEpoch::from_u64(2),
            WorkspaceEpoch::ZERO
        ),
        Err(EpochRefusal::VisibleAheadOfStaged { .. })
    ));
    assert!(matches!(
        EpochSet::try_new(
            WorkspaceEpoch::from_u64(5),
            WorkspaceEpoch::from_u64(2),
            WorkspaceEpoch::from_u64(3)
        ),
        Err(EpochRefusal::DurableAheadOfVisible { .. })
    ));

    // The permitted counterpart: the same shape, in a legal order.
    let ok = EpochSet::try_new(
        WorkspaceEpoch::from_u64(5),
        WorkspaceEpoch::from_u64(3),
        WorkspaceEpoch::from_u64(2),
    )
    .expect("a descending triple is legal");
    assert!(ok.invariant_holds());
}

// ---------------------------------------------------------------------------
// workspace-lease obligation
// ---------------------------------------------------------------------------

/// A reservation admits an overlay that fits and refuses one that outgrew it.
#[test]
fn workspace_lease_reservation_is_checked_not_assumed() {
    use fgit_treefs::capability::WorkspaceId;
    use fgit_treefs::obligation::{WorkspaceAbortReason, WorkspaceLeaseReservation};
    use fgit_treefs::overlay::OverlayStats;

    let reservation = WorkspaceLeaseReservation {
        workspace_id: WorkspaceId::from_bytes([1; 16]),
        reserved_bytes: 100,
        reserved_entries: 4,
    };

    let fits = OverlayStats {
        entry_count: 4,
        body_count: 2,
        body_bytes: 100,
    };
    assert!(reservation.admits(&fits), "exactly at the reservation fits");

    let too_many_bytes = OverlayStats {
        entry_count: 1,
        body_count: 1,
        body_bytes: 101,
    };
    assert!(!reservation.admits(&too_many_bytes));

    let too_many_entries = OverlayStats {
        entry_count: 5,
        body_count: 1,
        body_bytes: 1,
    };
    assert!(!reservation.admits(&too_many_entries));

    let abort = reservation.budget_exceeded(too_many_bytes);
    assert!(matches!(
        abort.reason,
        WorkspaceAbortReason::BudgetExceeded {
            reserved_bytes: 100,
            observed_bytes: 101
        }
    ));
    assert_eq!(abort.discarded, too_many_bytes);
}

/// The lease is declared as the workspace-overlay class and settles internally.
#[test]
fn workspace_lease_declares_its_class_and_grades() {
    use fgit_resource::{Grade, ObligationClass, ObligationKind, ObservationMode};
    use fgit_treefs::obligation::WorkspaceLease;

    assert_eq!(WorkspaceLease::CLASS, ObligationClass::WorkspaceLease);
    assert_eq!(WorkspaceLease::OBSERVATION, ObservationMode::Internal);
    assert!(WorkspaceLease::REQUIRED_GRADES.contains(&Grade::Bytes));
    assert!(WorkspaceLease::REQUIRED_GRADES.contains(&Grade::Objects));
}

// ---------------------------------------------------------------------------
// base-carried bodies: rename and chmod copy no bytes
// ---------------------------------------------------------------------------

/// Renaming a base-resident file names the base body instead of copying it.
#[test]
fn renaming_a_base_file_carries_the_body_without_copying_it() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Rename {
        from: path(b"src/f5"),
        to: path(b"renamed.rs"),
        basis_entry: Some(BasisEntry {
            oid: vec![0xAB; 20],
            mode: FileMode::Executable,
        }),
    });

    let (overlay, evaluation) = log.evaluate(&base);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::Survives { .. }
    ));
    assert_eq!(
        overlay.stats().body_bytes,
        0,
        "a rename must not copy the file body"
    );

    match overlay.lookup(&path(b"renamed.rs")) {
        OverlayLookup::Present(entry) => {
            let (oid, from) = entry
                .base_carry()
                .expect("the destination names the base body");
            assert_eq!(oid, &vec![0xAB; 20]);
            assert_eq!(from.as_bytes(), b"src/f5", "lineage records the source");
            match entry {
                OverlayEntry::File { mode, content, .. } => {
                    assert_eq!(*mode, FileMode::Executable, "the basis mode is preserved");
                    assert!(content.is_base_carried());
                }
                other => panic!("expected a file, got {other:?}"),
            }
        }
        other => panic!("expected an entry at the destination, got {other:?}"),
    }

    assert_eq!(
        overlay.entries().get(&path(b"src/f5")),
        Some(&OverlayEntry::Whiteout),
        "the source is whited out"
    );
}

/// Renaming a file staged earlier in the same log carries the staged body.
#[test]
fn renaming_a_staged_file_carries_the_staged_body() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(write(b"draft.txt", b"staged body"));
    log.push(TreeEditIntent::Rename {
        from: path(b"draft.txt"),
        to: path(b"final.txt"),
        basis_entry: None,
    });

    let (overlay, _) = log.evaluate(&base);
    match overlay.lookup(&path(b"final.txt")) {
        OverlayLookup::Present(entry) => {
            assert_eq!(overlay.body(entry).unwrap(), b"staged body");
        }
        other => panic!("expected the staged body at the destination, got {other:?}"),
    }
}

/// A base-resident source with no basis entry is a typed statement error, not a
/// guess — while the same rename with a basis proceeds.
#[test]
fn missing_basis_entry_is_refused_and_supplying_one_proceeds() {
    let base = wide_base(10);

    let mut without = IntentLog::new();
    without.push(TreeEditIntent::Rename {
        from: path(b"src/f6"),
        to: path(b"moved.rs"),
        basis_entry: None,
    });
    let (_, evaluation) = without.evaluate(&base);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::Error(IntentError::MissingBasisEntry { .. })
    ));

    let mut with = IntentLog::new();
    with.push(TreeEditIntent::Rename {
        from: path(b"src/f6"),
        to: path(b"moved.rs"),
        basis_entry: Some(BasisEntry {
            oid: vec![0xCD; 20],
            mode: FileMode::Regular,
        }),
    });
    let (_, evaluation) = with.evaluate(&base);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::Survives { .. }
    ));
}

/// A chmod against a base file names the base body and changes only the mode.
#[test]
fn chmod_against_a_base_file_names_the_base_body() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Chmod {
        path: path(b"src/f8"),
        basis_entry: Some(BasisEntry {
            oid: vec![0xEF; 20],
            mode: FileMode::Regular,
        }),
        after: FileMode::Executable,
    });

    let (overlay, _) = log.evaluate(&base);
    match overlay.lookup(&path(b"src/f8")) {
        OverlayLookup::Present(OverlayEntry::File { content, mode, .. }) => {
            assert_eq!(*mode, FileMode::Executable);
            assert_eq!(
                content,
                &ContentRef::Base {
                    oid: vec![0xEF; 20],
                    from: path(b"src/f8"),
                }
            );
        }
        other => panic!("expected a base-carried file, got {other:?}"),
    }
    assert_eq!(overlay.stats().body_bytes, 0);
}

/// A chmod to the mode the base already has is a named no-op.
#[test]
fn chmod_to_the_existing_base_mode_is_a_no_op() {
    let base = wide_base(10);
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Chmod {
        path: path(b"src/f9"),
        basis_entry: Some(BasisEntry {
            oid: vec![0x01; 20],
            mode: FileMode::Executable,
        }),
        after: FileMode::Executable,
    });
    let (_, evaluation) = log.evaluate(&base);
    assert!(matches!(
        evaluation.outcomes()[0],
        NetEffect::NoOp(NoOpReason::AlreadyIdentical)
    ));
}

/// A base-carried body and an overlay-staged body with the same mode are
/// different overlay states, so they must not share an overlay root.
#[test]
fn base_carried_and_staged_bodies_are_distinguishable() {
    let base = wide_base(10);

    let mut carried = IntentLog::new();
    carried.push(TreeEditIntent::Rename {
        from: path(b"src/f1"),
        to: path(b"target.txt"),
        basis_entry: Some(BasisEntry {
            oid: vec![0x77; 20],
            mode: FileMode::Regular,
        }),
    });
    let (carried_overlay, _) = carried.evaluate(&base);

    let mut staged = IntentLog::new();
    staged.push(TreeEditIntent::Delete {
        path: path(b"src/f1"),
    });
    staged.push(write(b"target.txt", b"staged instead"));
    let (staged_overlay, _) = staged.evaluate(&base);

    assert_ne!(
        OverlayRoot::of(&carried_overlay),
        OverlayRoot::of(&staged_overlay)
    );
}
