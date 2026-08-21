//! An authority publication names the epochs its public operations can witness.
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §9 distinguishes a body that has been
//! staged from one made visible by an authority-head replacement.  This test
//! drives only the public `FsqliteAuthorityStore` operations against a
//! file-backed database: it establishes that body-first storage is `Staged`
//! until the successful conditional replacement, and that a subsequent head
//! read witnesses `Visible`.
//!
//! It intentionally makes no assertion about [`PublicationEpoch::Durable`].
//! The currently published authority surface neither drives nor reports the
//! WAL-to-main durability predicate, so these inputs cannot establish that
//! epoch. A separate test-owned connection can positively witness a checkpoint
//! without widening the production statement surface; that evidence still does
//! not turn this publication result into a durable acknowledgement.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use fgit_authority::{
    AuthorityLimits, CasOutcome, HeadGeneration, HeadKey, HeadRead, ImmutableKey, ImmutableRead,
    PutOutcome, StoreInstanceId,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fgit_types::PublicationEpoch;
use fsqlite_types::cx::Cx as FsqliteCx;

/// A file-backed database that removes SQLite sidecars with its main file.
///
/// The test is about the persistent authority surface, not the distinct
/// `:memory:` configuration.  Sidecar cleanup prevents a stale prior test from
/// changing the meaning of the next one.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("fgit-zru1-{}-{label}.db", std::process::id()));
        let scratch = Self { path };
        scratch.remove();
        scratch
    }

    fn as_str(&self) -> &str {
        self.path.to_str().expect("a temporary path is valid UTF-8")
    }

    fn remove(&self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut path = self.path.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(path));
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.remove();
    }
}

fn deterministic_node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/epoch-witness".to_vec()).expect("the head key is admissible")
}

fn immutable_key() -> ImmutableKey {
    ImmutableKey::new(b"authority/epoch-witness/candidate".to_vec())
        .expect("the immutable key is admissible")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("the test generation is nonzero")
}

/// Determine only the two epochs that this public surface can establish.
///
/// A present candidate body with a head that still carries some other body is
/// `Staged`.  Once a head read carries the exact candidate body, the authority
/// root makes it `Visible`. This helper deliberately has no `Durable` branch:
/// its inputs contain no durability-profile observation.
fn observed_public_epoch(
    node: &NodeRuntime,
    store: &FsqliteAuthorityStore,
    cx: &FsqliteCx,
    candidate_key: &ImmutableKey,
    candidate_body: &[u8],
    authority_head: &HeadKey,
) -> PublicationEpoch {
    let stored_body = node
        .block_on(store.read_immutable(cx, candidate_key))
        .expect("the candidate body is readable through the authority surface");
    assert_eq!(
        stored_body,
        ImmutableRead::Present(candidate_body.to_vec()),
        "the epoch witness requires the exact staged candidate body"
    );

    match node
        .block_on(store.read_head(cx, authority_head))
        .expect("the authority head is readable")
    {
        HeadRead::Present(receipt) if receipt.body() == candidate_body => PublicationEpoch::Visible,
        HeadRead::Present(_) | HeadRead::Absent => PublicationEpoch::Staged,
    }
}

#[test]
fn body_first_publication_witnesses_staged_then_visible_without_claiming_durable() {
    let node = deterministic_node();
    let scratch = Scratch::new("staged-visible");
    let cx = FsqliteCx::new();
    cx.set_native_cx(node.request_cx(BudgetClass::Request));

    let mut store = node
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            scratch.as_str().to_owned(),
            StoreInstanceId::from_raw(1),
            AuthorityLimits::default(),
        ))
        .expect("the file-backed authority store opens");

    let authority_head = head_key();
    let candidate_key = immutable_key();
    let base_body = b"epoch-base";
    let candidate_body = b"epoch-candidate";

    node.block_on(store.initialize_head(&cx, &authority_head, generation(1), base_body))
        .expect("the base authority head initializes");
    let base_receipt = match node
        .block_on(store.read_head(&cx, &authority_head))
        .expect("the initialized head is readable")
    {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("the initialized head must be visible"),
    };

    assert_eq!(
        node.block_on(store.put_if_absent(&cx, &candidate_key, candidate_body))
            .expect("the candidate body stages"),
        PutOutcome::Created,
    );
    assert_eq!(
        observed_public_epoch(
            &node,
            &store,
            &cx,
            &candidate_key,
            candidate_body,
            &authority_head,
        ),
        PublicationEpoch::Staged,
        "a candidate body exists before the authority root references it"
    );

    let publish = node
        .block_on(store.compare_exchange_head(
            &cx,
            &authority_head,
            base_receipt.token(),
            generation(2),
            candidate_body,
        ))
        .expect("the exact-predecessor publication completes");
    assert!(
        matches!(publish, CasOutcome::Committed(_)),
        "the test requires the candidate's head replacement to win"
    );
    assert_eq!(
        observed_public_epoch(
            &node,
            &store,
            &cx,
            &candidate_key,
            candidate_body,
            &authority_head,
        ),
        PublicationEpoch::Visible,
        "the successful CAS and subsequent head read make the candidate observable"
    );

    node.block_on(store.close(&cx))
        .expect("the store closes through the awaited lifecycle path");
}
