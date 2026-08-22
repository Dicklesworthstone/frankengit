//! `TxId` derivation: order-independence, semantic sensitivity, and a pinned golden.
//!
//! The contract's promise is a biconditional, so both directions are tested.
//! Same semantics, any presentation → same identity. Different semantics, any
//! field → different identity. A test that only checked the first direction
//! would pass against a derivation that returned a constant.

use fgit_authority::{
    ExpectedOld, IdempotencyKey, ProposedNew, PushOption, RefCommand, RequestRefusal, ScopedEntry,
    SealAttempt, SemanticRequest, TxIdPreimage, canonical_request_digest, derive_tx_id,
};
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId, TxId};
use fgit_types::label::{AsciiSlug, SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;

const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0)
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

const fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x33; 16])
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; 20]))
}

fn ref_name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn slug(text: &'static str) -> AsciiSlug {
    AsciiSlug::from_static(text)
}

fn command(name: &str, old: u8, new: u8) -> RefCommand {
    RefCommand {
        name: ref_name(name),
        expected_old: ExpectedOld::Exactly(oid(old)),
        proposed_new: ProposedNew::Update(oid(new)),
        force: false,
    }
}

fn key() -> IdempotencyKey {
    IdempotencyKey::new(b"client-key-0001".to_vec()).expect("a bounded key")
}

fn request_from(commands: Vec<RefCommand>) -> SemanticRequest {
    SemanticRequest::build(
        schema(),
        GitHashAlgorithm::Sha1,
        true,
        commands,
        vec![PushOption::new(b"ci.skip".to_vec()).expect("a bounded option")],
        vec![ScopedEntry::new(slug("forge"), slug("merge-pr"), b"42".to_vec()).expect("bounded")],
    )
    .expect("an admissible request")
}

fn tx_id_of(request: &SemanticRequest) -> TxId {
    let attempt = SealAttempt {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: principal(),
        idempotency_key: key(),
        request: request.clone(),
    };
    attempt.derive().expect("a derivable identity").0
}

#[test]
fn reordering_ref_commands_does_not_change_the_identity() {
    let ascending = request_from(vec![
        command("refs/heads/a", 1, 2),
        command("refs/heads/b", 3, 4),
        command("refs/heads/c", 5, 6),
    ]);
    let shuffled = request_from(vec![
        command("refs/heads/c", 5, 6),
        command("refs/heads/a", 1, 2),
        command("refs/heads/b", 3, 4),
    ]);

    assert_eq!(
        ascending.ref_commands(),
        shuffled.ref_commands(),
        "canonicalization must put both orderings into the same order"
    );
    assert_eq!(
        tx_id_of(&ascending),
        tx_id_of(&shuffled),
        "the caller's ordering is framing, not semantics"
    );
}

#[test]
fn reordering_scoped_entries_does_not_change_the_identity() {
    let build = |entries: Vec<ScopedEntry>| {
        SemanticRequest::build(
            schema(),
            GitHashAlgorithm::Sha1,
            false,
            vec![command("refs/heads/main", 1, 2)],
            Vec::new(),
            entries,
        )
        .expect("an admissible request")
    };
    let one = ScopedEntry::new(slug("forge"), slug("close-issue"), b"7".to_vec()).expect("bounded");
    let two = ScopedEntry::new(slug("policy"), slug("epoch"), b"3".to_vec()).expect("bounded");

    assert_eq!(
        tx_id_of(&build(vec![one.clone(), two.clone()])),
        tx_id_of(&build(vec![two, one]))
    );
}

#[test]
fn push_option_order_is_semantics_and_does_change_the_identity() {
    let build = |options: Vec<PushOption>| {
        SemanticRequest::build(
            schema(),
            GitHashAlgorithm::Sha1,
            false,
            vec![command("refs/heads/main", 1, 2)],
            options,
            Vec::new(),
        )
        .expect("an admissible request")
    };
    let first = PushOption::new(b"a".to_vec()).expect("bounded");
    let second = PushOption::new(b"b".to_vec()).expect("bounded");

    assert_ne!(
        tx_id_of(&build(vec![first.clone(), second.clone()])),
        tx_id_of(&build(vec![second, first])),
        "push option order is client-visible semantics, not transport framing"
    );
}

#[test]
fn every_semantic_field_change_changes_the_identity() {
    let base = request_from(vec![command("refs/heads/main", 1, 2)]);
    let baseline = tx_id_of(&base);

    let variants: Vec<(&str, SemanticRequest)> = vec![
        (
            "ref name",
            request_from(vec![command("refs/heads/other", 1, 2)]),
        ),
        (
            "expected old",
            request_from(vec![command("refs/heads/main", 9, 2)]),
        ),
        (
            "proposed new",
            request_from(vec![command("refs/heads/main", 1, 9)]),
        ),
        ("force flag", {
            let mut only = command("refs/heads/main", 1, 2);
            only.force = true;
            request_from(vec![only])
        }),
        ("expected-old shape", {
            let mut only = command("refs/heads/main", 1, 2);
            only.expected_old = ExpectedOld::Absent;
            request_from(vec![only])
        }),
        ("unspecified expectation", {
            let mut only = command("refs/heads/main", 1, 2);
            only.expected_old = ExpectedOld::Unspecified;
            request_from(vec![only])
        }),
        ("deletion", {
            let mut only = command("refs/heads/main", 1, 2);
            only.proposed_new = ProposedNew::Delete;
            request_from(vec![only])
        }),
        (
            "atomic flag",
            SemanticRequest::build(
                schema(),
                GitHashAlgorithm::Sha1,
                false,
                vec![command("refs/heads/main", 1, 2)],
                vec![PushOption::new(b"ci.skip".to_vec()).expect("bounded")],
                vec![
                    ScopedEntry::new(slug("forge"), slug("merge-pr"), b"42".to_vec())
                        .expect("bounded"),
                ],
            )
            .expect("an admissible request"),
        ),
        (
            "push option value",
            SemanticRequest::build(
                schema(),
                GitHashAlgorithm::Sha1,
                true,
                vec![command("refs/heads/main", 1, 2)],
                vec![PushOption::new(b"ci.run".to_vec()).expect("bounded")],
                vec![
                    ScopedEntry::new(slug("forge"), slug("merge-pr"), b"42".to_vec())
                        .expect("bounded"),
                ],
            )
            .expect("an admissible request"),
        ),
        (
            "scoped entry value",
            SemanticRequest::build(
                schema(),
                GitHashAlgorithm::Sha1,
                true,
                vec![command("refs/heads/main", 1, 2)],
                vec![PushOption::new(b"ci.skip".to_vec()).expect("bounded")],
                vec![
                    ScopedEntry::new(slug("forge"), slug("merge-pr"), b"43".to_vec())
                        .expect("bounded"),
                ],
            )
            .expect("an admissible request"),
        ),
        (
            "request schema",
            SemanticRequest::build(
                SchemaId::new(SchemaFamily::from_static("receive-pack"), 2, 0),
                GitHashAlgorithm::Sha1,
                true,
                vec![command("refs/heads/main", 1, 2)],
                vec![PushOption::new(b"ci.skip".to_vec()).expect("bounded")],
                vec![
                    ScopedEntry::new(slug("forge"), slug("merge-pr"), b"42".to_vec())
                        .expect("bounded"),
                ],
            )
            .expect("an admissible request"),
        ),
    ];

    for (field, variant) in variants {
        assert_ne!(
            baseline,
            tx_id_of(&variant),
            "changing the {field} must change the transaction identity"
        );
    }
}

#[test]
fn every_identity_input_outside_the_request_changes_the_identity() {
    let request = request_from(vec![command("refs/heads/main", 1, 2)]);
    let digest = canonical_request_digest(&request).expect("a derivable digest");
    let base = TxIdPreimage {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: principal(),
        idempotency_key: key(),
        canonical_request_digest: digest,
    };
    let baseline = derive_tx_id(&base).expect("a derivable identity");

    let mut other_tenant = base.clone();
    other_tenant.tenant_id = TenantId::from_bytes([0x99; 16]);
    let mut other_repository = base.clone();
    other_repository.repository_id = RepositoryId::from_bytes([0x99; 16]);
    let mut other_principal = base.clone();
    other_principal.authenticated_principal_id = PrincipalId::from_bytes([0x99; 16]);
    let mut other_key = base;
    other_key.idempotency_key = IdempotencyKey::new(b"client-key-0002".to_vec()).expect("bounded");

    for (field, variant) in [
        ("tenant", other_tenant),
        ("repository", other_repository),
        ("principal", other_principal),
        ("idempotency key", other_key),
    ] {
        assert_ne!(
            baseline,
            derive_tx_id(&variant).expect("a derivable identity"),
            "changing the {field} must change the transaction identity"
        );
    }
}

/// Reconstruct the domain-separated preimage by hand and hash it.
///
/// This is deliberately a *second* implementation of the derivation's outer
/// layer, written from the documented construction rather than by calling the
/// function under test: length-prefixed domain tag, length-prefixed schema
/// family, big-endian major and minor, big-endian body length, then the body.
/// If domain separation, the schema pin, or the length framing changes, the two
/// implementations disagree and this test fails.
fn oracle_digest(canonical_body: &[u8]) -> [u8; 32] {
    const TAG: &[u8] = b"frankengit/ref-txn/v2";
    const FAMILY: &[u8] = b"ref-txn";
    const MAJOR: u16 = 2;
    const MINOR: u16 = 0;

    let mut preimage = Vec::new();
    preimage.push(u8::try_from(TAG.len()).expect("the tag is short"));
    preimage.extend_from_slice(TAG);
    preimage.push(u8::try_from(FAMILY.len()).expect("the family is short"));
    preimage.extend_from_slice(FAMILY);
    preimage.extend_from_slice(&MAJOR.to_be_bytes());
    preimage.extend_from_slice(&MINOR.to_be_bytes());
    preimage.extend_from_slice(&(canonical_body.len() as u64).to_be_bytes());
    preimage.extend_from_slice(canonical_body);
    fgit_crypto::sha256_digest(&preimage)
}

#[test]
fn the_derivation_is_deterministic() {
    let request = request_from(vec![
        command("refs/heads/main", 0xAA, 0xBB),
        command("refs/tags/v1", 0xCC, 0xDD),
    ]);
    assert_eq!(
        tx_id_of(&request),
        tx_id_of(&request),
        "the derivation must be a function of its inputs"
    );
    assert_eq!(
        tx_id_of(&request).as_internal_object_id().domain().as_str(),
        "frankengit/ref-txn/v2",
        "the identity must carry the ref-transaction domain tag"
    );
}

/// The golden: an independent reconstruction of the derivation must agree.
///
/// This pins the layer this crate owns — domain separation, the schema pin, the
/// length framing, and the field order of the identity preimage — against a
/// second implementation rather than against a recorded literal. A recorded
/// literal is not available to a code-first wave: producing one would mean
/// running the code under test and writing down whatever it said, which pins
/// nothing and is indistinguishable from regenerating a golden to force green.
///
/// The layer *below* this one, the canonical encoding of the preimage body, is
/// pinned by `fgit-codec`'s own checked-in golden corpus, which its owner
/// maintains. Each layer is pinned by the party that can pin it honestly.
#[test]
fn the_derivation_matches_an_independent_reconstruction() {
    let request = request_from(vec![
        command("refs/heads/main", 0xAA, 0xBB),
        command("refs/tags/v1", 0xCC, 0xDD),
    ]);
    let digest = canonical_request_digest(&request).expect("a derivable digest");
    let preimage = TxIdPreimage {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: principal(),
        idempotency_key: key(),
        canonical_request_digest: digest,
    };

    let derived = derive_tx_id(&preimage).expect("a derivable identity");
    let canonical_body =
        fgit_codec::wire::canonical_body_bytes(&preimage).expect("an encodable preimage");
    let expected = oracle_digest(&canonical_body);

    assert_eq!(
        derived.as_internal_object_id().digest().as_bytes(),
        expected.as_slice(),
        "the transaction identity does not match an independent reconstruction of \
         its documented preimage; if the construction changed deliberately, change \
         the reconstruction in the same commit and say why"
    );
}

#[test]
fn a_different_domain_would_produce_a_different_identity() {
    // The domain tag is committed by the preimage header, so changing it alone
    // must change the digest. Reconstructing with the wrong tag proves the
    // separation is load-bearing rather than decorative.
    let request = request_from(vec![command("refs/heads/main", 1, 2)]);
    let digest = canonical_request_digest(&request).expect("a derivable digest");
    let preimage = TxIdPreimage {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: principal(),
        idempotency_key: key(),
        canonical_request_digest: digest,
    };
    let canonical_body =
        fgit_codec::wire::canonical_body_bytes(&preimage).expect("an encodable preimage");

    let mut wrong_domain = Vec::new();
    const WRONG: &[u8] = b"frankengit/txn-seal/v1";
    wrong_domain.push(u8::try_from(WRONG.len()).expect("short"));
    wrong_domain.extend_from_slice(WRONG);
    wrong_domain.push(7_u8);
    wrong_domain.extend_from_slice(b"ref-txn");
    wrong_domain.extend_from_slice(&2_u16.to_be_bytes());
    wrong_domain.extend_from_slice(&0_u16.to_be_bytes());
    wrong_domain.extend_from_slice(&(canonical_body.len() as u64).to_be_bytes());
    wrong_domain.extend_from_slice(&canonical_body);

    assert_ne!(
        oracle_digest(&canonical_body).as_slice(),
        fgit_crypto::sha256_digest(&wrong_domain).as_slice(),
        "two domains must not agree on one body"
    );
}

#[test]
fn two_commands_on_one_ref_are_refused_and_two_refs_proceed() {
    let duplicated = SemanticRequest::build(
        schema(),
        GitHashAlgorithm::Sha1,
        true,
        vec![
            command("refs/heads/main", 1, 2),
            command("refs/heads/main", 3, 4),
        ],
        Vec::new(),
        Vec::new(),
    )
    .expect_err("contradictory duplicates must be refused, not merged");
    assert!(matches!(
        duplicated,
        RequestRefusal::RefCommandDuplicated { .. }
    ));

    SemanticRequest::build(
        schema(),
        GitHashAlgorithm::Sha1,
        true,
        vec![
            command("refs/heads/main", 1, 2),
            command("refs/heads/next", 3, 4),
        ],
        Vec::new(),
        Vec::new(),
    )
    .expect("two commands on two different refs must proceed");
}

#[test]
fn a_mixed_object_format_request_is_refused_and_a_matching_one_proceeds() {
    let mixed = SemanticRequest::build(
        schema(),
        GitHashAlgorithm::Sha256,
        true,
        vec![command("refs/heads/main", 1, 2)],
        Vec::new(),
        Vec::new(),
    )
    .expect_err("a sha1 object id under a sha256 repository has no single meaning");
    assert!(matches!(mixed, RequestRefusal::ObjectFormatMismatch { .. }));

    SemanticRequest::build(
        schema(),
        GitHashAlgorithm::Sha1,
        true,
        vec![command("refs/heads/main", 1, 2)],
        Vec::new(),
        Vec::new(),
    )
    .expect("a matching object format must proceed");
}

// ---------------------------------------------------------------------------
// frankengit-2u7e: SealedRequest admission checks.
//
// `SemanticRequest::build` is the NPC 5.2 boundary -- the sealed request is the
// body whose identity must be stable, so these checks are what stop one seal
// body owning two logical shapes. Two of its four name-constructible refusals
// were tested (RefCommandDuplicated, ObjectFormatMismatch, both above); the
// other two had zero assertions anywhere in the workspace.
//
// `check_bound` is `observed > limit`, so EXACTLY the limit is permitted at
// every site. Each permitted twin below sits on that exact value, which is the
// case a `>`/`>=` slip flips.
// ---------------------------------------------------------------------------

/// A slug built at runtime, since the file's existing `slug` takes `&'static str`
/// and these tests generate names in a loop.
fn runtime_slug(text: &str) -> AsciiSlug {
    AsciiSlug::try_new("test", text.as_bytes()).expect("an admissible slug")
}

fn entry(namespace: &str, key: &str) -> ScopedEntry {
    ScopedEntry::new(runtime_slug(namespace), runtime_slug(key), Vec::new())
        .expect("an admissible entry")
}

fn distinct_commands(count: usize) -> Vec<RefCommand> {
    (0..count)
        .map(|index| command(&format!("refs/heads/b{index}"), 1, 2))
        .collect()
}

/// Entries distinct in BOTH namespace and key.
///
/// Varying only one half would make the bound tests below depend on the
/// duplicate guard's other clause: with a shared namespace, dropping the key
/// clause makes every entry collide and the bound tests fail for a reason that
/// has nothing to do with bounds. Mutation `mc` demonstrated exactly that
/// coupling before this was fixed.
fn distinct_entries(count: usize) -> Vec<ScopedEntry> {
    (0..count)
        .map(|index| entry(&format!("ns{index}"), &format!("k{index}")))
        .collect()
}

fn build_with(
    ref_commands: Vec<RefCommand>,
    push_options: Vec<PushOption>,
    scoped_entries: Vec<ScopedEntry>,
) -> Result<SemanticRequest, RequestRefusal> {
    SemanticRequest::build(
        schema(),
        GitHashAlgorithm::Sha1,
        true,
        ref_commands,
        push_options,
        scoped_entries,
    )
}

/// Acceptance (1): each collection bound reports its OWN field, count and limit.
///
/// The three `check_bound` calls sit on consecutive lines, each hand-passing a
/// `(field, length, limit)` triple. That adjacency is the defect class: passing
/// `push_options.len()` against `MAX_SCOPED_ENTRIES`, or labelling a refusal
/// with a neighbour's field string, refuses and permits at the wrong sizes
/// while looking entirely correct. Asserting only the variant would not see it,
/// so all three payload fields are pinned.
#[test]
fn each_collection_bound_refuses_naming_its_own_field_count_and_limit() {
    let over_commands = build_with(
        distinct_commands(fgit_authority::MAX_REF_COMMANDS + 1),
        Vec::new(),
        Vec::new(),
    )
    .expect_err("one command past the bound must refuse");
    assert!(
        matches!(
            over_commands,
            RequestRefusal::BoundExceeded {
                field: "ref_commands",
                observed,
                limit,
            } if observed == fgit_authority::MAX_REF_COMMANDS + 1
                && limit == fgit_authority::MAX_REF_COMMANDS
        ),
        "ref_commands must name itself and its own limit; got {over_commands:?}",
    );

    let over_options = build_with(
        Vec::new(),
        vec![
            PushOption::new(Vec::new()).expect("an empty option is admissible");
            fgit_authority::MAX_PUSH_OPTIONS + 1
        ],
        Vec::new(),
    )
    .expect_err("one push option past the bound must refuse");
    assert!(
        matches!(
            over_options,
            RequestRefusal::BoundExceeded {
                field: "push_options",
                observed,
                limit,
            } if observed == fgit_authority::MAX_PUSH_OPTIONS + 1
                && limit == fgit_authority::MAX_PUSH_OPTIONS
        ),
        "push_options must name itself and its own limit; got {over_options:?}",
    );

    let over_entries = build_with(
        Vec::new(),
        Vec::new(),
        distinct_entries(fgit_authority::MAX_SCOPED_ENTRIES + 1),
    )
    .expect_err("one scoped entry past the bound must refuse");
    assert!(
        matches!(
            over_entries,
            RequestRefusal::BoundExceeded {
                field: "scoped_entries",
                observed,
                limit,
            } if observed == fgit_authority::MAX_SCOPED_ENTRIES + 1
                && limit == fgit_authority::MAX_SCOPED_ENTRIES
        ),
        "scoped_entries must name itself and its own limit; got {over_entries:?}",
    );
}

/// Acceptance (2): the permitted twins, at exactly the limit.
///
/// `check_bound` is `observed > limit`, so a collection of exactly the limit is
/// admissible. Without these the bounds could each be off by one in the
/// conservative direction and every refusal test above would still pass.
#[test]
fn each_collection_bound_permits_exactly_its_limit() {
    build_with(
        distinct_commands(fgit_authority::MAX_REF_COMMANDS),
        Vec::new(),
        Vec::new(),
    )
    .expect("exactly MAX_REF_COMMANDS is inside the bound");

    build_with(
        Vec::new(),
        vec![
            PushOption::new(Vec::new()).expect("an empty option is admissible");
            fgit_authority::MAX_PUSH_OPTIONS
        ],
        Vec::new(),
    )
    .expect("exactly MAX_PUSH_OPTIONS is inside the bound");

    build_with(
        Vec::new(),
        Vec::new(),
        distinct_entries(fgit_authority::MAX_SCOPED_ENTRIES),
    )
    .expect("exactly MAX_SCOPED_ENTRIES is inside the bound");
}

/// The two byte-length bounds, refusal and permitted twin together.
///
/// These live on the value constructors rather than on `build`, so they are a
/// separate surface with their own field strings.
#[test]
fn the_value_byte_bounds_refuse_one_over_and_permit_exactly_the_limit() {
    PushOption::new(vec![b'x'; fgit_authority::MAX_PUSH_OPTION_BYTES])
        .expect("exactly MAX_PUSH_OPTION_BYTES is inside the bound");
    let option = PushOption::new(vec![b'x'; fgit_authority::MAX_PUSH_OPTION_BYTES + 1])
        .expect_err("one byte past the bound must refuse");
    assert!(
        matches!(
            option,
            RequestRefusal::BoundExceeded {
                field: "push_option",
                observed,
                limit,
            } if observed == fgit_authority::MAX_PUSH_OPTION_BYTES + 1
                && limit == fgit_authority::MAX_PUSH_OPTION_BYTES
        ),
        "the push-option byte bound must name itself; got {option:?}",
    );

    ScopedEntry::new(
        runtime_slug("ns"),
        runtime_slug("k"),
        vec![b'x'; fgit_authority::MAX_SCOPED_VALUE_BYTES],
    )
    .expect("exactly MAX_SCOPED_VALUE_BYTES is inside the bound");
    let value = ScopedEntry::new(
        runtime_slug("ns"),
        runtime_slug("k"),
        vec![b'x'; fgit_authority::MAX_SCOPED_VALUE_BYTES + 1],
    )
    .expect_err("one byte past the bound must refuse");
    assert!(
        matches!(
            value,
            RequestRefusal::BoundExceeded {
                field: "scoped_entry_value",
                observed,
                limit,
            } if observed == fgit_authority::MAX_SCOPED_VALUE_BYTES + 1
                && limit == fgit_authority::MAX_SCOPED_VALUE_BYTES
        ),
        "the scoped-entry value bound must name itself; got {value:?}",
    );
}

/// Acceptance (3): the duplicate guard is TWO clauses, so it needs two twins.
///
/// `if left.namespace == right.namespace && left.key == right.key`. A refusal
/// case paired with a wholly-unrelated permitted case cannot distinguish this
/// from a one-clause guard: drop `&& key` and entries sharing a namespace would
/// wrongly refuse; drop the namespace clause and entries sharing a key across
/// namespaces would. Each twin isolates one clause by varying only that half.
///
/// The scan is `windows(2)` over entries sorted by `(namespace, key)`, so the
/// permitted pairs are also the ones a broken sort would mis-adjacent.
#[test]
fn scoped_entries_are_duplicates_only_when_both_namespace_and_key_match() {
    let duplicated = build_with(
        Vec::new(),
        Vec::new(),
        vec![entry("ns", "k"), entry("ns", "k")],
    )
    .expect_err("two entries sharing a namespace AND a key are duplicates");
    assert!(
        matches!(duplicated, RequestRefusal::ScopedEntryDuplicated { .. }),
        "expected ScopedEntryDuplicated, got {duplicated:?}",
    );

    // Twin isolating the key clause: same namespace, different key.
    build_with(
        Vec::new(),
        Vec::new(),
        vec![entry("ns", "one"), entry("ns", "two")],
    )
    .expect("a shared namespace alone is not a duplicate");

    // Twin isolating the namespace clause: different namespace, same key.
    build_with(
        Vec::new(),
        Vec::new(),
        vec![entry("alpha", "k"), entry("beta", "k")],
    )
    .expect("a shared key alone is not a duplicate");
}
