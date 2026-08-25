#![forbid(unsafe_code)]
//! The hidden-ref policy, proven end to end on the production carrier
//! (`frankengit-jkbo`, acceptance lines 2 and 3).
//!
//! Every other test of this feature builds a policy by hand or sets
//! `AdmissionSnapshot::hidden_refs` directly. None of them shows that a policy a
//! repository actually *stores* reaches the guards, and for most of this bead's
//! life it could not: the rule list lived on a schema major-1 configuration body
//! that [`OneNode`] can neither write nor open, so the feature was correct and
//! inert.
//!
//! The carrier ruling moved the rules into a separate `HiddenRefPolicyBody`
//! named by a `policy_root`, and `frankengit-fg059` gave the incarnation carrier
//! that field at schema 2.1 — the carrier `OneNode::init` actually stages. So
//! the helpers below run the whole chain against the durable store:
//!
//! 1. initialize a repository through the production path;
//! 2. push `refs/heads/main` and `refs/private/secret`, at two *different*
//!    objects, through the production durable receive path;
//! 3. stage a policy body hiding `refs/private`;
//! 4. stage a 2.1 configuration naming it by `policy_root`, differing from the
//!    configuration the node itself staged *only* by that field;
//! 5. publish a head selecting it, by authenticated exact-predecessor CAS;
//! 6. reopen the node and materialize through `materialize_admission_in`;
//! 7. record what the policy answers, what the production upload-pack view
//!    advertises, and what a real protocol-v2 `ls-refs` session emits.
//!
//! Step 7 is the part no other test reaches. `upload_advertisement_visibility`
//! proves a snapshot-carried policy filters the advertisement, but it hands the
//! view a hand-built snapshot; nothing joined that to a stored policy.
//!
//! # Why every assertion is paired
//!
//! The two read-side tests run the identical repository twice — same refs, same
//! objects, same production push — differing only in whether a policy was ever
//! staged, and assert the *difference* the policy makes rather than an absolute
//! list. That matters two ways. It cannot be satisfied by a view that serves
//! nothing, and it does not have to assume whether `HEAD` is advertised at all:
//! whatever else the advertisement contains must be identical on both sides, and
//! the hidden ref must be the one and only entry that disappears.
//!
//! The write-side test pairs differently, because there the repository has to
//! stay the same: one push beneath the stored rule and one push to a name no
//! rule matches, into the *same* repository under the *same* policy. Without
//! that twin the refusal is equally explained by a repository that refuses every
//! push — and that is not hypothetical, since a malformed stored rule is
//! specified to refuse the whole snapshot rather than one name.
//!
//! The two refs point at *different* blobs on purpose. With one shared object
//! the hidden ref's object id would still be advertised as the visible ref's,
//! and the wire test could not tell "the name is gone" from "the ref is gone".
//! Distinct objects make the object id independently checkable, which is the
//! stronger disclosure: advertising a hidden ref's oid leaks more than the fact
//! that it exists.
//!
//! # What "end to end" does and does not mean here
//!
//! The wire test drives `serve_git_daemon_upload_pack`, which is the exact
//! function `fg serve` calls at `src/lib.rs:6266` after materializing, over
//! in-memory streams instead of a TCP socket, answering the exact `ls-refs`
//! command `git ls-remote` sends over protocol v2. What is NOT covered is the
//! socket and the CLI: **`fg` has no command that stores a hidden-ref policy**
//! (its usage line offers `init`, `import`, `doctor`, `export`, `serve` and
//! nothing else), so a shell-level `git ls-remote` against `fg serve` cannot be
//! made to hide anything today. These tests stage the policy through the same
//! authority API a configuration command would have to use. That gap is
//! recorded on the bead rather than papered over with a fixture.

use std::convert::Infallible;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_admission::AdmissionLimits;
use fgit_authority::{
    AuthorityLimits, CasOutcome, HeadKey, HeadRead, IdempotencyKey, StoreInstanceId,
    authority_head_identity, read_repository_incarnation_configuration_async,
    stage_hidden_ref_policy_async, stage_latest_repository_incarnation_configuration_async,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_codec::{
    DecodeLimits, HiddenRefPolicyBody, RepositoryAuthorityHeadBody,
    RepositoryIncarnationConfigurationBodyV2_1, decode_body, encode_body,
};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_git_object::ParseLimits;
use fgit_node::{
    GitDaemonSessionOutcome, LoopbackReceiveSession, NodeConfig, OneNode,
    serve_git_daemon_upload_pack,
};
use fgit_runtime::{BudgetClass, RuntimeProfile};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefusalCode, RepositoryId, TenantId,
};
use fgit_wire::receive::{ReceiveContext, ReceiveLimits, SignedPushProfile};
use fgit_wire::{
    Capabilities, GitObjectFormat, PackPayloadSource, Packet, UploadPackRepository, WireError,
    WireLimits, encode_packets,
};
use fsqlite_types::cx::Cx as FsqliteCx;

const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";
const STORE_INSTANCE: StoreInstanceId = StoreInstanceId::from_raw(1);
const REPOSITORY_ID: RepositoryId = RepositoryId::from_bytes([0x0B; 16]);
const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const VISIBLE_REF: &[u8] = b"refs/heads/main";
const HIDDEN_REF: &[u8] = b"refs/private/secret";
const HIDE_RULE: &[u8] = b"refs/private";
const VISIBLE_BLOB: &[u8] = b"hidden-ref policy end-to-end: the advertised blob\n";
const HIDDEN_BLOB: &[u8] = b"hidden-ref policy end-to-end: the concealed blob\n";
/// A ref beneath the stored hide rule, created after the policy exists.
const REFUSED_REF: &[u8] = b"refs/private/attempted";
const REFUSED_BLOB: &[u8] = b"hidden-ref policy end-to-end: the refused push blob\n";
/// Its permitted twin: same repository, same policy, a name no rule matches.
const ADMITTED_REF: &[u8] = b"refs/heads/other";
const ADMITTED_BLOB: &[u8] = b"hidden-ref policy end-to-end: the admitted push blob\n";

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-hidden-ref-policy-e2e-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(root, TenantId::from_bytes([0x4C; 16]), REPOSITORY_ID)
}

fn authority_path(root: &Path) -> String {
    root.join(AUTHORITY_DATABASE_FILE)
        .into_os_string()
        .into_string()
        .expect("test scratch paths are UTF-8")
}

fn head_key(repository_id: RepositoryId) -> HeadKey {
    let mut bytes = Vec::with_capacity(HEAD_KEY_PREFIX.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(HEAD_KEY_PREFIX);
    bytes.extend_from_slice(repository_id.as_bytes());
    HeadKey::new(bytes).expect("the fixed node head key is within the key bound")
}

fn visible_oid() -> GitOid {
    git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, VISIBLE_BLOB)
}

fn hidden_oid() -> GitOid {
    git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, HIDDEN_BLOB)
}

// ---------------------------------------------------------------------------
// Two real refs at two real objects, through the production durable receive path
// ---------------------------------------------------------------------------

fn receive_context() -> ReceiveContext {
    let limits = ReceiveLimits::default();
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"report-status delete-refs", &limits.wire)
            .expect("fixed capabilities parse"),
        limits,
        SignedPushProfile::Refuse,
    )
    .expect("fixed receive context is coherent")
}

fn object_header(kind: u8, declared_size: usize) -> Vec<u8> {
    let mut remaining = declared_size;
    let mut first = (kind << 4) | u8::try_from(remaining & 0x0f).expect("masked size");
    remaining >>= 4;
    if remaining == 0 {
        return vec![first];
    }
    first |= 0x80;
    let mut header = vec![first];
    while remaining != 0 {
        let mut next = u8::try_from(remaining & 0x7f).expect("masked size");
        remaining >>= 7;
        if remaining != 0 {
            next |= 0x80;
        }
        header.push(next);
    }
    header
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("small bounded fixture");
    let mut output = vec![0x78, 0x01, 0x01];
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&(!length).to_le_bytes());
    output.extend_from_slice(bytes);
    let (adler_a, adler_b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next_a = (a + u32::from(*byte)) % 65_521;
        (next_a, (b + next_a) % 65_521)
    });
    output.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
    output
}

/// A bounded whole-object pack carrying `bodies` as blobs, in order.
fn blob_pack(bodies: &[&[u8]]) -> Vec<u8> {
    let count = u32::try_from(bodies.len()).expect("small bounded fixture");
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&count.to_be_bytes());
    for body in bodies {
        pack.extend_from_slice(&object_header(3, body.len()));
        pack.extend_from_slice(&zlib_stored(body));
    }
    let trailer = sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

/// Drives one complete receive session through the production durable path and
/// returns its authenticated per-command outcomes.
///
/// `creations` are `(ref name, blob body)` pairs; each ref is created from the
/// zero id at the blob's native identity, and the pack carries exactly those
/// blobs. The session re-materializes internally through the node's own
/// projection, so the policy the guard sees is the one the repository stores at
/// the moment of the push, not one this helper supplies.
fn push(
    node: &OneNode,
    creations: &[(&[u8], &[u8])],
    idempotency_key: &[u8],
) -> Vec<DecisionOutcome> {
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("the current head materializes before a receive");

    let mut packets = Vec::with_capacity(creations.len() + 1);
    for (index, (name, body)) in creations.iter().enumerate() {
        let name = String::from_utf8(name.to_vec()).expect("fixed ASCII ref name");
        let oid = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, body);
        // Only the first command carries the capability suffix, as a client does.
        let command = if index == 0 {
            format!("{ZERO_OID} {oid} {name}\0report-status")
        } else {
            format!("{ZERO_OID} {oid} {name}")
        };
        packets.push(Packet::Data(command.into_bytes()));
    }
    packets.push(Packet::Flush);

    let bodies: Vec<&[u8]> = creations.iter().map(|(_, body)| *body).collect();
    let mut input =
        encode_packets(&packets, &WireLimits::default()).expect("bounded command packets encode");
    input.extend_from_slice(&blob_pack(&bodies));

    let mut live = || true;
    let outcome = node
        .runtime()
        .block_on(
            node.receive_loopback_pack_durable_in(
                &node.request_context(),
                &LoopbackReceiveSession::authenticated(
                    PrincipalId::from_bytes([0x73; 16]),
                    IdempotencyKey::new(idempotency_key.to_vec())
                        .expect("bounded retry key constructs"),
                ),
                &materialized,
                receive_context(),
                &input,
                ParseLimits::default(),
                AdmissionLimits::default(),
                &mut live,
            ),
        )
        .expect("the verified raw pack reaches durable admission");

    outcome
        .commands
        .iter()
        .map(|command| command.terminal.outcome.clone())
        .collect()
}

/// Publishes [`VISIBLE_REF`] and [`HIDDEN_REF`] at two distinct objects.
///
/// Both refs are created BEFORE any policy exists, which is the only order that
/// makes the later assertions meaningful: a push to an already-hidden ref is
/// refused, so a policy staged first would leave nothing to hide.
fn push_two_refs(node: &OneNode) {
    assert_ne!(
        visible_oid(),
        hidden_oid(),
        "the fixture objects must differ, or the object-id assertions are vacuous"
    );
    let outcomes = push(
        node,
        &[(VISIBLE_REF, VISIBLE_BLOB), (HIDDEN_REF, HIDDEN_BLOB)],
        b"hidden-ref-policy-end-to-end-genesis",
    );

    assert_eq!(outcomes.len(), 2);
    for outcome in &outcomes {
        assert!(
            matches!(outcome, DecisionOutcome::Committed { .. }),
            "both fixture refs must be published before any policy exists, got {outcome:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// A policy the repository DURABLY STORES
// ---------------------------------------------------------------------------

/// Stages a policy hiding `rules` and republishes the head's configuration at
/// schema 2.1 naming it by `policy_root`.
///
/// The republished configuration is read back from the one the node itself
/// staged and differs from it ONLY by `policy_root`. Any other difference would
/// make a passing assertion ambiguous: a changed `root_layout` or
/// `repository_incarnation_id` would fail materialization for its own reasons,
/// and a coincidentally different one could pass for the wrong reason.
fn publish_policy(root: &Path, repository_id: RepositoryId, rules: &[&[u8]]) {
    let runtime = RuntimeProfile::production(1)
        .build()
        .expect("the bounded test runtime builds");
    {
        let cx = FsqliteCx::new();
        cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
        let mut store = runtime
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                authority_path(root),
                STORE_INSTANCE,
                AuthorityLimits::default(),
            ))
            .expect("the persistent authority store reopens");

        let head_key = head_key(repository_id);
        let HeadRead::Present(receipt) = runtime
            .block_on(store.read_head(&cx, &head_key))
            .expect("the initialized repository has a persistent authority head")
        else {
            panic!("the initialized repository unexpectedly has no authority head");
        };
        let mut advanced: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT)
                .expect("the current authority head decodes");

        let existing = runtime
            .block_on(read_repository_incarnation_configuration_async(
                &store,
                &cx,
                &advanced.configuration_root,
            ))
            .expect("the head names a resolvable incarnation configuration");
        assert!(
            existing.policy_root.is_none(),
            "the node's own configuration must start policy-free, or this test \
             could pass against a policy it did not stage"
        );

        let policy = HiddenRefPolicyBody {
            rules: rules.iter().map(|rule| rule.to_vec()).collect(),
        };
        let policy_root = runtime
            .block_on(stage_hidden_ref_policy_async(&store, &cx, &policy))
            .expect("the policy body stages in persistent Fsqlite");

        let configuration = RepositoryIncarnationConfigurationBodyV2_1 {
            root_layout: existing.root_layout,
            object_format: existing.object_format,
            repository_incarnation_id: existing.repository_incarnation_id,
            policy_root: Some(policy_root),
        };
        let configuration_root = runtime
            .block_on(stage_latest_repository_incarnation_configuration_async(
                &store,
                &cx,
                &configuration,
            ))
            .expect("the policy-bearing configuration stages");

        let predecessor =
            authority_head_identity(&advanced).expect("the predecessor head has an identity");
        advanced.generation = advanced
            .generation
            .next()
            .expect("the current generation has a successor");
        advanced.predecessor_head_id = Some(predecessor);
        advanced.configuration_root = configuration_root;
        let advanced_bytes = encode_body(&advanced).expect("the head selecting the policy encodes");
        assert!(matches!(
            runtime
                .block_on(store.compare_exchange_head(
                    &cx,
                    &head_key,
                    receipt.token(),
                    advanced.generation,
                    &advanced_bytes,
                ))
                .expect("the authenticated exact-predecessor CAS publishes the head"),
            CasOutcome::Committed(_)
        ));

        runtime
            .block_on(store.close(&cx))
            .expect("the persistent authority worker closes before node reopen");
    }
    assert!(
        runtime.join_root(Duration::from_secs(5)),
        "the authority mutation runtime reaches quiescence"
    );
}

// ---------------------------------------------------------------------------
// A real protocol-v2 ls-refs session, the command `git ls-remote` issues
// ---------------------------------------------------------------------------

struct EmptyPayload;

impl PackPayloadSource for EmptyPayload {
    fn next_chunk(&mut self, _maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(None)
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:04x}", payload.len() + 4).into_bytes();
    framed.extend_from_slice(payload);
    framed
}

/// A v2 greeting, one `ls-refs` command, a flush — the exchange `git ls-remote`
/// performs and nothing more.
fn ls_refs_session() -> Vec<u8> {
    let mut payload = b"git-upload-pack /demo.git\0".to_vec();
    payload.extend_from_slice(b"version=2\0");
    let mut wire = frame(&payload);
    wire.extend_from_slice(&frame(b"command=ls-refs"));
    wire.extend_from_slice(b"0001");
    wire.extend_from_slice(b"0000");
    wire
}

// ---------------------------------------------------------------------------
// One repository, observed three ways
// ---------------------------------------------------------------------------

/// What one repository shows a principal.
struct Observed {
    ref_count: usize,
    hides_hidden: bool,
    hides_visible: bool,
    advertised: Vec<Vec<u8>>,
    served: Vec<u8>,
}

/// Builds a repository storing `rules` (or storing no policy at all) and records
/// what it answers, then shuts the node down.
///
/// The upload-pack view comes from
/// `OneNode::durable_admission_upload_pack_repository_in`, the production
/// entrypoint, rather than from re-composing materialization and
/// `from_snapshot` here. Re-composing them would test my own assembly instead of
/// the node's.
/// Initializes a repository, publishes both fixture refs, optionally stores a
/// policy, and reopens through the production path.
///
/// The scratch directory is returned because it must outlive the node.
fn open_repository(rules: Option<&[&[u8]]>) -> (ScratchDirectory, OneNode) {
    let scratch = ScratchDirectory::new();
    let node_config = config(scratch.0.clone());

    let (created, _) =
        OneNode::init(node_config.clone()).expect("the genesis configuration persists");
    push_two_refs(&created);
    created.shutdown().expect("the initialized node quiesces");

    if let Some(rules) = rules {
        publish_policy(&scratch.0, REPOSITORY_ID, rules);
    }

    let node = OneNode::open_existing(node_config).expect("the published head opens");
    (scratch, node)
}

fn observe(rules: Option<&[&[u8]]>) -> Observed {
    let (_scratch, node) = open_repository(rules);

    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("the authenticated head materializes");
    let ref_count = materialized.snapshot().refs.len();
    let hides_hidden = materialized.snapshot().hidden_refs.hides(HIDDEN_REF);
    let hides_visible = materialized.snapshot().hidden_refs.hides(VISIBLE_REF);
    drop(materialized);

    let repository = node
        .runtime()
        .block_on(node.durable_admission_upload_pack_repository_in(
            &node.request_context(),
            &WireLimits::default(),
        ))
        .expect("the materialized snapshot becomes an upload-pack view");
    let advertised = repository
        .advertised_refs()
        .iter()
        .map(|reference| reference.name.clone())
        .collect();

    let mut served = Vec::new();
    let outcome = serve_git_daemon_upload_pack(
        &mut Cursor::new(ls_refs_session()),
        &mut served,
        &repository,
        Capabilities::parse_v1(b"agent=hidden-ref-policy-e2e", &WireLimits::default())
            .expect("deterministic test capabilities"),
        WireLimits::default(),
        |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
    )
    .expect("an ls-refs-only session completes without a pack");
    assert!(
        !matches!(outcome, GitDaemonSessionOutcome::Pack(_)),
        "an ls-refs-only session must not produce a pack"
    );

    node.shutdown().expect("the node quiesces");

    Observed {
        ref_count,
        hides_hidden,
        hides_visible,
        advertised,
        served,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// The property, each half paired with the identical repository storing nothing
// ---------------------------------------------------------------------------

#[test]
fn a_stored_policy_reaches_the_snapshot_and_removes_exactly_that_ref_from_the_advertisement() {
    let without = observe(None);
    let with = observe(Some(&[HIDE_RULE]));

    // The refs exist on both sides. Without this the omission below is also
    // satisfied by a repository that never published the ref at all.
    assert_eq!(
        without.ref_count, 2,
        "the twin repository publishes both refs"
    );
    assert_eq!(
        with.ref_count, 2,
        "hiding is a view over canonical state, not a deletion from it"
    );

    // Acceptance line 2, at the only site that decides anything in production:
    // the policy the repository STORES reaches the materialized snapshot.
    assert!(
        with.hides_hidden,
        "a rule the repository stores must reach the materialized snapshot — if \
         this fails, the feature is inert no matter how many unit tests pass"
    );
    assert!(
        !with.hides_visible,
        "a ref no stored rule names must stay visible"
    );
    // The repository-level permitted twin. Without it, `hides_hidden` above is
    // also satisfied by a pipeline that hides `refs/private` for some reason
    // unrelated to anything the repository stores.
    assert!(
        !without.hides_hidden,
        "a repository that stores no policy must hide nothing"
    );
    assert!(!without.hides_visible);

    // Acceptance line 3, fetch half, stated as the difference the policy makes.
    // Exact rather than "does not contain", and difference rather than absolute,
    // so it cannot pass against a view that serves nothing and does not have to
    // assume whether HEAD is advertised.
    assert!(
        without
            .advertised
            .iter()
            .any(|name| name.as_slice() == HIDDEN_REF),
        "the twin must advertise the hidden ref, or the omission proves nothing; \
         got {:?}",
        names(&without.advertised)
    );
    let expected: Vec<Vec<u8>> = without
        .advertised
        .iter()
        .filter(|name| name.as_slice() != HIDDEN_REF)
        .cloned()
        .collect();
    assert_eq!(
        names(&with.advertised),
        names(&expected),
        "the stored policy must remove the hidden ref from the production fetch \
         advertisement and change nothing else"
    );
}

#[test]
fn a_stored_policy_keeps_the_hidden_name_and_object_id_out_of_a_real_ls_refs_session() {
    // The closest reachable thing to `git ls-remote`: the exact serve function
    // `fg serve` calls, answering the exact command `git ls-remote` sends, with
    // the policy resolved from durable storage rather than handed in.
    //
    // Asserted on the SERVED BYTES rather than on a parsed ref list, because the
    // property is that nothing about the ref reaches the client — a ref filtered
    // out of one section but named in another would still be a disclosure.
    let without = observe(None);
    let with = observe(Some(&[HIDE_RULE]));

    let hidden_oid = hidden_oid().to_string().into_bytes();
    let visible_oid = visible_oid().to_string().into_bytes();

    // The twin first: this is what makes every absence below evidence.
    assert!(
        contains(&without.served, HIDDEN_REF),
        "with no stored policy the ls-refs session must list the hidden ref, or \
         its absence below is attributable to something other than the policy; \
         got {}",
        String::from_utf8_lossy(&without.served)
    );
    assert!(
        contains(&without.served, &hidden_oid),
        "with no stored policy the ls-refs session must carry its object id too"
    );

    assert!(
        !contains(&with.served, HIDDEN_REF),
        "the hidden ref's name must not appear anywhere in the bytes an ls-remote \
         client reads; got {}",
        String::from_utf8_lossy(&with.served)
    );
    // Strictly more than the name: advertising a hidden ref's object id leaks
    // what the ref points at, which is worse than leaking that it exists. The
    // two fixture refs deliberately name different objects so this is checkable
    // at all.
    assert!(
        !contains(&with.served, &hidden_oid),
        "the hidden ref's object id must not appear either; got {}",
        String::from_utf8_lossy(&with.served)
    );

    // The permitted twin inside the same session: an implementation that
    // answered nothing would satisfy both absences above.
    assert!(
        contains(&with.served, VISIBLE_REF),
        "the visible ref must still be listed; got {}",
        String::from_utf8_lossy(&with.served)
    );
    assert!(
        contains(&with.served, &visible_oid),
        "the visible ref's object id must still be served"
    );
}

#[test]
fn a_stored_policy_refuses_a_push_beneath_the_hidden_prefix_and_admits_its_twin() {
    // Acceptance line 3's push half, from DURABLE storage. `fgit-admission`
    // already proves a stored rule list drives the guard, but it builds the
    // snapshot in memory after a codec round trip. This drives the production
    // receive path against a repository that genuinely stores the policy, so the
    // guard sees a policy the node resolved for itself.
    //
    // Note the receive path re-materializes through the node's own projection
    // rather than trusting the `MaterializedAdmission` a caller hands it, so the
    // policy consulted here is the repository's at the moment of the push.
    let (_scratch, node) = open_repository(Some(&[HIDE_RULE]));

    let refused = push(
        &node,
        &[(REFUSED_REF, REFUSED_BLOB)],
        b"hidden-ref-policy-end-to-end-refused",
    );
    assert_eq!(refused.len(), 1);
    assert!(
        matches!(
            refused[0],
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ),
        "a push creating a ref beneath the stored hide rule must be refused as \
         hidden-ref-unauthorized, got {:?}",
        refused[0]
    );

    // The permitted twin, in the SAME repository under the SAME stored policy,
    // differing only in the ref name. Without it the refusal above is equally
    // explained by a repository that refuses every push — and that is not a
    // hypothetical, since a malformed stored rule is specified to refuse the
    // whole snapshot rather than one name.
    let admitted = push(
        &node,
        &[(ADMITTED_REF, ADMITTED_BLOB)],
        b"hidden-ref-policy-end-to-end-admitted",
    );
    assert_eq!(admitted.len(), 1);
    assert!(
        matches!(admitted[0], DecisionOutcome::Committed { .. }),
        "a push to a ref no stored rule names must still commit, got {:?}",
        admitted[0]
    );

    node.shutdown().expect("the node quiesces");
}

/// Ref names as lossy text, so an assertion failure is readable.
fn names(refs: &[Vec<u8>]) -> Vec<String> {
    refs.iter()
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect()
}
