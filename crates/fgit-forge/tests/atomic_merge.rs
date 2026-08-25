//! Evidence for FG-029a's three acceptance conditions.
//!
//! Every forbidden case is paired with the near-identical permitted case, so
//! the tests show where the boundary is rather than only that a wall exists.

use fgit_codec::CryptoBodyIdentity;
use fgit_codec::attest::BodyIdentity;
use fgit_codec::schema::RepositoryCommitRecord;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_diff::{TreeEntry, TreeMergeError, TreeMergeOptions};
use fgit_forge::event::ForgeEventBatch;
use fgit_forge::event::event_id;
use fgit_forge::merge::RecordFrame;
use fgit_forge::{
    AggregateHead, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventPayload, ForgeRefusal,
    MergeAttempt, MergeEffectPackage, MergeSide, ObservedTips, PullRequestNumber, RefIntent,
    StaleTips, merge_pull_request_tree,
};
use fgit_treefs::WorkspaceEpoch;
use fgit_types::numeric::CodecVersion;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, DomainTag, GitOid,
    GitOidSha256, InternalObjectId, OPAQUE_ID_LEN, PolicyEpoch, PrincipalSnapshotId, RepositoryId,
    RepositorySequence, SchemaId, TxId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

/// A native Git object identity.
///
/// Deliberately separate from `digest`: a ref tip, a merge commit and a tree
/// entry name Git objects, while the roots on a commit record are internal
/// digests. `fgit-types` offers no conversion between them, which is the type
/// system enforcing the same domain split section 6 states in prose.
const fn oid(tag: u8) -> GitOid {
    GitOid::Sha256(GitOidSha256::from_bytes([tag; GitOidSha256::LEN]))
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("32-byte corpus fixture body"),
        )
    };
}

const fn pull_request() -> PullRequestNumber {
    match PullRequestNumber::try_new(41) {
        Some(number) => number,
        None => panic!("41 is nonzero"),
    }
}

fn merge_event() -> ForgeEvent {
    ForgeEvent {
        aggregate: pull_request().into(),
        version: AggregateVersion::try_new(4).expect("a nonzero version"),
        payload: ForgeEventPayload::MergeCommitted {
            merge_commit: digest(0x51),
            target_ref: b"refs/heads/main".to_vec(),
            target_tip_before: digest(0x40),
            target_tip_after: digest(0x51),
        },
    }
}

fn ref_intent() -> RefIntent {
    RefIntent {
        name: b"refs/heads/main".to_vec(),
        expected_tip: oid(0x40),
        new_tip: oid(0x51),
    }
}

fn package() -> MergeEffectPackage {
    MergeEffectPackage {
        objects: vec![oid(0x51), oid(0x52)],
        ref_intent: ref_intent(),
        event: merge_event(),
    }
}

/// Every root the frame supplies is distinct and distinguishable, so a record
/// field that silently took a neighbour's value would show up as equality.
fn frame() -> RecordFrame {
    RecordFrame {
        repository_id: RepositoryId::from_bytes([7; OPAQUE_ID_LEN]),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, 0x60),
        principal_snapshot_id: derived!(PrincipalSnapshotId, 0x61),
        canonical_request_digest: digest(0x62),
        ref_delta_root: digest(0x6a),
        resulting_ref_root: digest(0x63),
        object_closure_root: digest(0x64),
        resulting_forge_position_root: digest(0x65),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(0x66),
        invariant_evidence_root: digest(0x67),
        outbox_effect_root: digest(0x68),
        retention_delta_root: digest(0x69),
    }
}

fn seal(package: &MergeEffectPackage) -> RepositoryCommitRecord {
    package
        .seal_into_record(&CryptoBodyIdentity, frame())
        .expect("a well formed package seals")
}

// ------------------------------------------------- acceptance (1): one record

/// The merge RCR carries BOTH the ref delta and the `MergeCommitted` event.
///
/// Asserting only that the two fields are populated would pass on a record that
/// stamped the same digest into both, or that copied a neighbouring root. So
/// the check is that each root equals the identity of the body it is supposed
/// to commit to, that the two differ from each other, and that neither collides
/// with any other root on the record.
///
/// # What `frankengit-asa3` changed here, and what it deliberately did not
///
/// The event root is still derived from the package's own bytes. The ref delta
/// root is now the frame's, because the RCR field commits to the ref effect a
/// decision published -- a fold over every ref the transaction moved -- and
/// this crate holds one requested movement. It previously stamped the
/// `RefIntent` identity into that field, which is why `RefIntent` and
/// admission's `CanonicalRefDelta` had come to share one identity domain.
///
/// The atomicity property this test exists for is untouched: both roots still
/// land on ONE record, and there is still no second record to split them onto.
/// What is added is the assertion that the two identities are now distinct
/// bodies, which is the thing that would silently regress if the domains were
/// ever merged back.
#[test]
fn the_merge_record_carries_the_ref_delta_and_the_event_together() {
    let package = package();
    let roots = package
        .roots(&CryptoBodyIdentity)
        .expect("both bodies have identities");
    let record = seal(&package);

    assert_eq!(record.ref_delta_root, frame().ref_delta_root);
    assert_eq!(record.forge_event_batch_root, roots.forge_event_batch_root);
    assert_ne!(
        record.ref_delta_root, record.forge_event_batch_root,
        "two different bodies must not commit to the same root"
    );
    assert_ne!(
        record.ref_delta_root, roots.ref_intent_root,
        "the published ref delta and the requested ref intent are different \
         bodies and must not share one identity"
    );

    // The event root this crate produces is not any of the roots the frame
    // supplied, so the field is not a copy of a neighbour.
    for supplied in [
        record.resulting_ref_root,
        record.object_closure_root,
        record.resulting_forge_position_root,
        record.policy_decision_root,
        record.invariant_evidence_root,
        record.outbox_effect_root,
        record.retention_delta_root,
        record.canonical_request_digest,
    ] {
        assert_ne!(record.ref_delta_root, supplied);
        assert_ne!(record.forge_event_batch_root, supplied);
    }
}

/// The two roots this crate derives are independently load-bearing.
///
/// This is the test that would fail if `roots` derived one root and reused it,
/// or if the event were left out of the batch that gets hashed. Changing the
/// event must move the event root and leave the ref intent root alone, and
/// changing the ref intent must do the reverse.
///
/// Asserted on `roots()` rather than on the sealed record, because since
/// `frankengit-asa3` the record's `ref_delta_root` is supplied by the frame:
/// reading independence off the record would now be reading it off a constant,
/// which is a test that passes while proving nothing about this crate. The
/// companion assertion -- that the record faithfully carries what each side
/// produced -- lives in
/// `the_merge_record_carries_the_ref_delta_and_the_event_together`.
#[test]
fn each_root_moves_only_for_its_own_body() {
    let derive = |package: &MergeEffectPackage| {
        package
            .roots(&CryptoBodyIdentity)
            .expect("both bodies have identities")
    };
    let baseline = derive(&package());

    let mut altered_event = package();
    altered_event.event.version = AggregateVersion::try_new(5).expect("a nonzero version");
    let altered_event = derive(&altered_event);
    assert_ne!(
        baseline.forge_event_batch_root, altered_event.forge_event_batch_root,
        "a different event must produce a different event root"
    );
    assert_eq!(
        baseline.ref_intent_root, altered_event.ref_intent_root,
        "changing the event must not disturb the ref intent root"
    );

    let mut altered_ref = package();
    altered_ref.ref_intent.new_tip = oid(0x7a);
    let altered_ref = derive(&altered_ref);
    assert_ne!(
        baseline.ref_intent_root, altered_ref.ref_intent_root,
        "a different ref intent must produce a different ref intent root"
    );
    assert_eq!(
        baseline.forge_event_batch_root, altered_ref.forge_event_batch_root,
        "changing the ref intent must not disturb the event root"
    );
}

// ------------------------------- acceptance (2): typed version admission

#[test]
fn an_aggregate_write_against_the_wrong_version_is_refused_and_the_right_one_proceeds() {
    let at_seven = AggregateHead::at(
        pull_request(),
        AggregateVersion::try_new(7).expect("a nonzero version"),
    );

    // Forbidden: the caller believes the stream is at 6 when it is at 7. This
    // is the case that must never be resolved by taking the later write.
    assert_eq!(
        at_seven.admit(ExpectedVersion::Exactly(
            AggregateVersion::try_new(6).expect("a nonzero version")
        )),
        Err(ForgeRefusal::VersionConflict {
            expected: ExpectedVersion::Exactly(
                AggregateVersion::try_new(6).expect("a nonzero version")
            ),
            observed: Some(AggregateVersion::try_new(7).expect("a nonzero version")),
        })
    );

    // Permitted twin: the same call one version later.
    assert_eq!(
        at_seven.admit(ExpectedVersion::Exactly(
            AggregateVersion::try_new(7).expect("a nonzero version")
        )),
        Ok(AggregateVersion::try_new(8).expect("a nonzero version")),
        "admission returns the version the new event will carry"
    );
}

/// `NewStream` and `Exactly(FIRST)` are different assertions, and collapsing
/// them would let a create silently append to a stream that already existed.
#[test]
fn creating_an_aggregate_that_already_exists_is_refused_and_an_empty_one_is_not() {
    let existing = AggregateHead::at(pull_request(), AggregateVersion::FIRST);
    assert_eq!(
        existing.admit(ExpectedVersion::NewStream),
        Err(ForgeRefusal::VersionConflict {
            expected: ExpectedVersion::NewStream,
            observed: Some(AggregateVersion::FIRST),
        })
    );

    let fresh = AggregateHead::empty(pull_request());
    assert_eq!(
        fresh.admit(ExpectedVersion::NewStream),
        Ok(AggregateVersion::FIRST)
    );

    // And the mirror: an empty stream is not at any version, so an exact
    // expectation against it is a conflict rather than a silent create.
    assert_eq!(
        fresh.admit(ExpectedVersion::Exactly(AggregateVersion::FIRST)),
        Err(ForgeRefusal::VersionConflict {
            expected: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            observed: None,
        })
    );
}

// --------------------------------------- staleness on both sides of the merge

fn attempt() -> MergeAttempt {
    MergeAttempt {
        pull_request: pull_request(),
        source_ref: b"refs/heads/feature".to_vec(),
        target_ref: b"refs/heads/main".to_vec(),
        source_tip: oid(0x30),
        target_tip: oid(0x40),
        base_tip: oid(0x20),
        workspace_epoch: WorkspaceEpoch::from_u64(9),
    }
}

#[test]
fn a_merge_whose_source_or_target_moved_is_refused_naming_the_side_that_moved() {
    let attempt = attempt();

    // Forbidden, axis one: the source moved.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: oid(0x31),
            target_tip: oid(0x40),
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        }),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Source,
            tips: StaleTips {
                computed_against: oid(0x30),
                observed: oid(0x31),
            },
        })
    );

    // Forbidden, axis two: the target moved. A separate axis, because a merge
    // that is fine on one side and stale on the other is the common case.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: oid(0x30),
            target_tip: oid(0x41),
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        }),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Target,
            tips: StaleTips {
                computed_against: oid(0x40),
                observed: oid(0x41),
            },
        })
    );

    // Permitted twin: neither moved.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: oid(0x30),
            target_tip: oid(0x40),
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        }),
        Ok(())
    );
}

// -------------------------------------------------- conflicts are not merges

fn entry(path: &[u8], object: u8) -> TreeEntry<GitOid> {
    TreeEntry {
        path: path.to_vec(),
        mode: fgit_diff::TreeMode(0o100_644),
        object: oid(object),
    }
}

#[test]
fn a_conflicted_merge_is_refused_and_a_clean_one_produces_a_tree() {
    // Forbidden: both sides changed the same path differently.
    let refusal = merge_pull_request_tree(
        [entry(b"a", 0x01)],
        [entry(b"a", 0x02)],
        [entry(b"a", 0x03)],
        TreeMergeOptions::default(),
    );
    assert_eq!(
        refusal,
        Err(ForgeRefusal::MergeConflicted { paths: 1 }),
        "a partially merged tree has no meaning as a commit"
    );

    // Permitted twin: only one side changed the path, so the merge is clean.
    let merged = merge_pull_request_tree(
        [entry(b"a", 0x01)],
        [entry(b"a", 0x02)],
        [entry(b"a", 0x01)],
        TreeMergeOptions::default(),
    )
    .expect("a one-sided change merges cleanly");
    assert_eq!(merged.entries, vec![entry(b"a", 0x02)]);
}

// ------------------------------------ acceptance (3): event wire behaviour

#[test]
fn every_event_kind_survives_the_roundtrip_as_itself() {
    let kinds = [
        ForgeEventPayload::PullRequestOpened {
            source_ref: b"refs/heads/feature".to_vec(),
            target_ref: b"refs/heads/main".to_vec(),
            source_tip: digest(0x30),
            target_tip: digest(0x40),
        },
        ForgeEventPayload::PullRequestHeadAdvanced {
            source_tip: digest(0x31),
        },
        ForgeEventPayload::MergeCommitted {
            merge_commit: digest(0x51),
            target_ref: b"refs/heads/main".to_vec(),
            target_tip_before: digest(0x40),
            target_tip_after: digest(0x51),
        },
        ForgeEventPayload::PullRequestClosed { withdrawn: true },
    ];
    for payload in kinds {
        let event = ForgeEvent {
            aggregate: pull_request().into(),
            version: AggregateVersion::FIRST,
            payload,
        };
        let bytes = encode_body(&event).expect("encodes");
        let decoded: ForgeEvent = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded, event);
    }
}

/// An event kind this build does not implement is refused, not skipped.
///
/// The payload length of an unknown kind is unknowable, so a decoder that
/// tolerated the tag would read every following field from the wrong offset and
/// produce a confidently wrong body that still has a valid identity.
#[test]
fn an_unknown_event_kind_on_the_wire_is_refused_and_a_known_one_is_not() {
    let event = ForgeEvent {
        aggregate: pull_request().into(),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
    };
    let bytes = encode_body(&event).expect("encodes");

    // Locate the kind tag by diffing against a frame that differs ONLY in
    // `version`, so both payloads are the same length.
    //
    // Diffing against a different KIND does not work, and this test caught
    // that in its own first version: the frame carries a payload length
    // prefix ahead of the payload, so two frames whose payloads differ in
    // length first diverge at that prefix rather than at the tag. The locator
    // found 21 -- the byte length of a PullRequestClosed payload, 8 + 8 + 4 + 1
    // -- and pointed four bytes into the header. Holding the payload length
    // fixed removes the prefix from the comparison entirely.
    let mut sibling = event.clone();
    sibling.version = AggregateVersion::try_new(2).expect("a nonzero version");
    let sibling = encode_body(&sibling).expect("encodes");
    let divergence = bytes
        .iter()
        .zip(sibling.iter())
        .position(|(left, right)| left != right)
        .expect("the two frames differ at the version");
    // `version` is a big-endian u64, and 1 and 2 differ only in its last
    // byte, so the field starts seven bytes earlier and the kind tag begins
    // immediately after it.
    let kind_offset = divergence + 1;
    assert_eq!(
        &bytes[kind_offset..kind_offset + 4],
        &4_u32.to_be_bytes(),
        "the located field must be the tag that says PullRequestClosed"
    );

    for unknown in [0_u32, 5, 99, u32::from(u16::MAX)] {
        let mut corrupted = bytes.clone();
        corrupted[kind_offset..kind_offset + 4].copy_from_slice(&unknown.to_be_bytes());
        match decode_body::<ForgeEvent>(&corrupted, DecodeLimits::DEFAULT) {
            Err(CodecRefusal::VariantUnknown {
                field, observed, ..
            }) => {
                assert_eq!(field, "kind");
                assert_eq!(observed, unknown);
            }
            other => panic!("kind {unknown} must be refused, got {other:?}"),
        }
    }

    // Permitted twin: the untouched frame, differing only in those four bytes.
    let decoded: ForgeEvent = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded, event);
}

/// The batch is ordered, and its identity depends on that order.
#[test]
fn a_batch_commits_to_event_order_rather_than_to_a_set() {
    let first = merge_event();
    let mut second = merge_event();
    second.version = AggregateVersion::try_new(5).expect("a nonzero version");

    let forward = ForgeEventBatch {
        events: vec![first.clone(), second.clone()],
    };
    let reversed = ForgeEventBatch {
        events: vec![second, first],
    };
    assert_ne!(
        encode_body(&forward).expect("encodes"),
        encode_body(&reversed).expect("encodes"),
        "two events on one aggregate are only meaningful in stream order"
    );

    let decoded: ForgeEventBatch = decode_body(
        &encode_body(&forward).expect("encodes"),
        DecodeLimits::DEFAULT,
    )
    .expect("decodes");
    assert_eq!(decoded, forward);
}

/// The schema this build implements, pinned so a change is a deliberate act.
#[test]
fn the_event_declares_its_registered_domain_and_schema() {
    assert_eq!(
        ForgeEvent::DOMAIN.as_str(),
        "frankengit/forge-event/v1",
        "the domain must be the one the crypto registry pins for ForgeEventId"
    );
    assert_eq!(ForgeEvent::SCHEMA_MAJOR, 1);
    assert_eq!(ForgeEvent::SCHEMA_MINOR, 0);
    assert_eq!(
        ForgeEventBatch::DOMAIN.as_str(),
        "frankengit/forge-event-batch/v1"
    );
}

/// The workspace epoch is a binding, not a label.
///
/// Before this test existed the field was written by every caller and read by
/// nobody: deleting it would have broken no assertion and changed no decision,
/// which is the definition of a decorative dependency. The refusal below is
/// what makes `fgit-treefs` load-bearing here rather than merely imported.
#[test]
fn a_merge_computed_in_a_workspace_that_has_since_advanced_is_refused() {
    let attempt = attempt();

    // Forbidden: both refs are exactly where the merge left them, so the two
    // tip axes pass and only the workspace has moved. That isolation is the
    // point -- a test that also moved a tip would pass on a build that ignored
    // the epoch entirely.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: oid(0x30),
            target_tip: oid(0x40),
            workspace_epoch: WorkspaceEpoch::from_u64(10),
        }),
        Err(ForgeRefusal::WorkspaceMoved {
            computed_in: WorkspaceEpoch::from_u64(9),
            observed: WorkspaceEpoch::from_u64(10),
        }),
        "a tree computed over content the workspace no longer holds cannot be admitted"
    );

    // Permitted twin: the same call at the epoch the merge was computed in.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: oid(0x30),
            target_tip: oid(0x40),
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        }),
        Ok(())
    );
}

/// When more than one axis has moved the refusal is deterministic.
#[test]
fn a_ref_that_moved_is_reported_before_a_workspace_that_also_moved() {
    let attempt = attempt();
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: oid(0x31),
            target_tip: oid(0x40),
            workspace_epoch: WorkspaceEpoch::from_u64(10),
        }),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Source,
            tips: StaleTips {
                computed_against: oid(0x30),
                observed: oid(0x31),
            },
        }),
        "the fixed order is source, target, workspace"
    );
}

// --------------------------------------------- the refusal arms nothing reached

/// A `BodyIdentity` that refuses whatever it is handed.
///
/// Both identity-side refusal arms are unreachable through the real
/// `CryptoBodyIdentity`, and correctly so: this crate's domains are pinned in
/// the crypto registry, so a body built here always has an identity. That makes
/// the arms look dead when they are not — they exist for callers supplying
/// their own identity, and for the day a domain is retired. A stub is the only
/// honest way to reach them, and it reaches them through the real public
/// signature rather than by calling anything private.
struct RefusingIdentity(CodecRefusal);

impl BodyIdentity for RefusingIdentity {
    fn identify(
        &self,
        _domain: DomainTag,
        _schema: SchemaId,
        _codec_version: CodecVersion,
        _canonical_body: &[u8],
    ) -> Result<InternalObjectId, CodecRefusal> {
        Err(self.0.clone())
    }
}

fn unregistered() -> CodecRefusal {
    CodecRefusal::identity_domain_unregistered(ForgeEvent::DOMAIN)
}

/// A ref intent is identified as a ref intent, not as an admission ref delta.
///
/// `frankengit-asa3`, the SCHEMA STOP `BlackOx` raised. [`RefIntent`] used to
/// declare `frankengit/admission-ref-delta/v1`, the identity that
/// `fgit_admission::CanonicalRefDelta` also declares, with an incompatible
/// payload: one ref plus the tip it is conditional on, against a map from every
/// moved ref to its surviving value. One identity domain that decodes to two
/// body shapes is the §5.2 key-reuse case that must fail closed.
///
/// Pinned as literals rather than compared against the sibling constant,
/// because the sibling is in `fgit-admission` at L4 and this crate is L2. The
/// cross-crate half of this property -- that the same logical movement produces
/// two different digests under the two domains -- is asserted from admission,
/// where both types are nameable.
///
/// This is a claim about a published wire identity, so it is written as an
/// exact expected value: a test that merely asserted the two constants differ
/// would keep passing if a future edit moved `RefIntent` onto some third
/// domain, which is a different published meaning again.
#[test]
fn a_ref_intent_carries_its_own_identity_domain() {
    assert_eq!(
        RefIntent::DOMAIN,
        DomainTag::from_static("frankengit/forge-ref-intent/v1")
    );
    assert_eq!(
        RefIntent::SCHEMA_FAMILY,
        fgit_types::SchemaFamily::from_static("forge-ref-intent")
    );
    assert_ne!(
        RefIntent::DOMAIN,
        DomainTag::from_static("frankengit/admission-ref-delta/v1"),
        "the ref intent must not reclaim the canonical ref delta's identity"
    );

    // The permitted twin of the refusal above: this domain is registered, so a
    // real identity resolves for it rather than being refused as unknown. A
    // domain constant nothing has registered would make every merge unsealable.
    assert!(
        package()
            .roots(&CryptoBodyIdentity)
            .is_ok_and(|roots| roots.ref_intent_root != roots.forge_event_batch_root)
    );
}

/// An unregistered domain is reported as a missing identity, not as a codec
/// problem, and the two are not interchangeable.
///
/// The distinction matters to a caller: `IdentityUnavailable` says this build
/// cannot name the body at all, which is a configuration or registry fault,
/// while `BodyUnrepresentable` says the bytes themselves were the problem.
/// Collapsing them would send an operator to the wrong place.
#[test]
fn an_event_whose_domain_has_no_identity_is_refused_distinctly_from_bad_bytes() {
    let event = merge_event();

    assert_eq!(
        event_id(&RefusingIdentity(unregistered()), &event),
        Err(ForgeRefusal::IdentityUnavailable { body: "ForgeEvent" })
    );

    // Near-identical case, different cause: the identity fails for a reason
    // that is not an unregistered domain, so it surfaces as the codec refusal
    // it actually was rather than being relabelled.
    let other = CodecRefusal::VariantUnknown {
        field: "kind",
        observed: 77,
        offset: 3,
    };
    assert_eq!(
        event_id(&RefusingIdentity(other.clone()), &event),
        Err(ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(other)
        })
    );

    // Permitted twin: the real identity, which resolves both domains.
    assert!(event_id(&CryptoBodyIdentity, &event).is_ok());
}

/// The same two arms on the package side, which names the body that failed.
///
/// `roots` derives two identities, so the refusal has to say which one failed
/// or a caller cannot tell a bad ref intent from a bad event batch.
#[test]
fn a_package_root_refusal_names_the_body_that_failed() {
    let package = package();

    assert_eq!(
        package.roots(&RefusingIdentity(unregistered())),
        Err(ForgeRefusal::IdentityUnavailable { body: "RefIntent" }),
        "the ref intent is derived first, so it is the one that reports"
    );

    assert!(package.roots(&CryptoBodyIdentity).is_ok());
}

/// The version counter refuses exhaustion instead of wrapping.
///
/// A wrap here would be silent history corruption: version 1 would follow
/// `u64::MAX`, and an aggregate whose stream restarted at 1 would accept writes
/// that expected the beginning of time.
#[test]
fn a_saturated_aggregate_version_refuses_to_advance_and_one_below_it_does_not() {
    let last = AggregateVersion::try_new(u64::MAX).expect("u64::MAX is nonzero");
    assert_eq!(
        last.next(),
        Err(ForgeRefusal::VersionExhausted { observed: last })
    );

    // Permitted twin at the exact boundary: one position short still advances,
    // and lands on the value that has no successor.
    let penultimate = AggregateVersion::try_new(u64::MAX - 1).expect("nonzero");
    assert_eq!(penultimate.next(), Ok(last));

    // And the same boundary reached through the admission path, so the refusal
    // is not confined to the counter in isolation.
    let head = AggregateHead::at(pull_request(), last);
    assert_eq!(
        head.admit(ExpectedVersion::Exactly(last)),
        Err(ForgeRefusal::VersionExhausted { observed: last })
    );
}

/// A merge engine refusal is carried through, not converted into a conflict.
///
/// The difference is load-bearing: `MergeConflicted` means the merge ran and
/// the sides disagree, which a human resolves. `MergeRefused` means the merge
/// never ran, which a human cannot resolve by choosing a side. Reporting the
/// second as the first would send someone to resolve conflicts that do not
/// exist.
#[test]
fn a_merge_the_engine_declines_is_refused_as_declined_rather_than_as_conflicted() {
    // Git tree order is a precondition of the engine, not something it repairs.
    let unsorted = [entry(b"b", 0x01), entry(b"a", 0x02)];
    assert_eq!(
        merge_pull_request_tree(
            unsorted,
            [entry(b"a", 0x02)],
            [entry(b"a", 0x02)],
            TreeMergeOptions::default(),
        ),
        Err(ForgeRefusal::MergeRefused {
            cause: TreeMergeError::UnsortedOrDuplicatePath
        })
    );

    // Permitted twin: the same entries in order merge cleanly.
    let sorted = [entry(b"a", 0x02), entry(b"b", 0x01)];
    let merged = merge_pull_request_tree(
        sorted.clone(),
        sorted.clone(),
        sorted,
        TreeMergeOptions::default(),
    )
    .expect("sorted entries merge");
    assert_eq!(merged.entries.len(), 2);
}
