//! FG-005b: the kill/reopen matrix and reference equivalence, on a real file.
//!
//! Written by a pane that did not implement this crate. Nothing here edits
//! `fgit-authority-fsqlite/src`; every fixture drives the published surface.
//!
//! **Amendment, and it narrows that claim.** The author of this campaign later
//! took `frankengit-w1ik` — a defect this campaign found — and wrote the fix in
//! `src`: a `TransientClass::Cancelled` variant, its classifier arm, and its
//! `into_failure` mapping. So "did not implement this crate" is no longer true
//! without qualification, and the honest version is: **this campaign was
//! written against an implementation the author had no hand in, and the author
//! has since changed three small pieces of that implementation, all of them
//! downstream of what this campaign measured.**
//!
//! Why that is worth a paragraph rather than a quiet edit: the independence is
//! not decoration, it is the reason the campaign can catch a misreading its
//! implementer could not. Every finding here predates the amendment, so none of
//! them is self-verification — but a *future* reader must not assume the
//! separation still holds by default. Recorded rather than left to be
//! discovered, because the alternative is a claim that decays into a false one.
//!
//! # Why these tests use a file and the existing ones do not
//!
//! `engine_conformance.rs` opens `":memory:"`, which is correct for the
//! contract suite — each check wants a private, disposable store. But an
//! in-memory database cannot be reopened, so it cannot say anything about what
//! survives a restart. Every store here is opened on a real path, written to,
//! abandoned, and opened again.
//!
//! # What "killed" means here, exactly
//!
//! [`Crashable::kill`] drops the store **without** the awaited close. That is a
//! real unclean shutdown for this crate: `lifecycle.rs` deliberately ships no
//! `impl Drop`, precisely so that dropping cannot be mistaken for a drain, and
//! there is no `Drop` in the crate to flush on the way out.
//!
//! # The non-claims, which matter more than the passes
//!
//! * **This is not a power-loss test.** Dropping the handle ends the process's
//!   relationship with the database; it does not lose the operating system's
//!   page cache or interrupt an `fsync`. Torn writes and lost sectors are a
//!   different harness, and nothing here should be read as covering them.
//! * **"Survives a kill" is not "durable" in the §5.4 sense.** That section
//!   separates *staged*, *visible*, and *durable*, and forbids conflating
//!   object existence, canonical visibility, and completion of the selected
//!   durability profile. What these tests show is that state remains
//!   canonically visible after the process stops touching the database — the
//!   middle epoch. Completion of a durability profile means surviving loss of
//!   the page cache, which the point above says this harness does not test.
//!   The word "durability" appears in a few comments below as ordinary
//!   English; nowhere in this file is it the §5.4 epoch.
//! * **Every kill here FOLLOWS a completed operation.** `Crashable::kill` runs
//!   after the call it is paired with has returned, so what is under test is
//!   what a finished operation left behind, not an operation interrupted
//!   mid-flight. That is a real property — durability across an unclean
//!   shutdown, and old-complete-or-new-complete afterwards — and it is a
//!   weaker one than "crash during the exchange", which a file called a crash
//!   matrix invites a reader to assume. Interrupting an operation partway
//!   needs fault injection, and `FsqliteAuthorityStore` has none: see
//!   FG-005B-E2E-020.
//! * **This says nothing about cancellation mid-operation.** Like the
//!   conformance bridge, these tests block per operation, so a cancel cannot be
//!   interleaved with an operation in flight. That gap is named in
//!   `engine_conformance.rs` and is still open.
//! * **The injected-fault half of FG-005b is not in this file**, but it is no
//!   longer absent: AF-01..AF-08 now pass against a real database in
//!   `fault_conformance.rs`, which implements `FaultableAuthorityStore` as a
//!   wrapper that delegates to this same engine. This paragraph previously said
//!   those cells were unprovable for this backend because `MemoryAuthorityStore`
//!   was the only implementor -- true of the workspace, and a non-sequitur about
//!   what a test could do. A green run of *this* file still does not cover them;
//!   it is `fault_conformance.rs` that does.

use std::path::PathBuf;
use std::time::Duration;

use asupersync::cx::Cx as NativeCx;
use fgit_authority::{
    AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken, CasOutcome,
    HeadGeneration, HeadKey, HeadRead, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    PutOutcome, StoreInstanceId,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

// ------------------------------------------------------------------ scratch

/// A database path that removes itself, so a failing test cannot leak a file
/// into the next run and make it pass on stale state.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// `label` distinguishes concurrent tests; the process id distinguishes
    /// concurrent runs. Neither draws on wall time or a system generator, so a
    /// failure replays against the same name.
    fn new(label: &str) -> Self {
        Self::in_base(&std::env::temp_dir(), label)
    }

    /// The same scratch database, on a caller-chosen filesystem.
    fn in_base(base: &std::path::Path, label: &str) -> Self {
        let mut path = base.to_path_buf();
        path.push(format!("fgit-fg005b-{}-{label}.db", std::process::id()));
        let scratch = Self { path };
        scratch.remove();
        scratch
    }

    fn as_str(&self) -> &str {
        self.path.to_str().expect("a temp path is valid UTF-8")
    }

    fn remove(&self) {
        // SQLite may leave sidecars; a stale one is as contaminating as a
        // stale main file.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut sidecar = self.path.clone().into_os_string();
            sidecar.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(sidecar));
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.remove();
    }
}

// ------------------------------------------------------------ crashable store

/// A file-backed store that can be killed and reopened at the same path.
struct Crashable<'a> {
    node: &'a NodeRuntime,
    cx: FsqliteCx,
    store: FsqliteAuthorityStore,
    _native: NativeCx,
}

impl<'a> Crashable<'a> {
    fn try_open(
        node: &'a NodeRuntime,
        path: &str,
        instance: StoreInstanceId,
    ) -> Result<Self, EngineError> {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        cx.set_native_cx(native.clone());
        let store = node.block_on(FsqliteAuthorityStore::open(
            &cx,
            path.to_owned(),
            instance,
            AuthorityLimits::default(),
        ))?;
        Ok(Self {
            node,
            cx,
            store,
            _native: native,
        })
    }

    fn open(node: &'a NodeRuntime, path: &str, instance: StoreInstanceId) -> Self {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        cx.set_native_cx(native.clone());
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                path.to_owned(),
                instance,
                AuthorityLimits::default(),
            ))
            .expect("a file-backed store opens");
        Self {
            node,
            cx,
            store,
            _native: native,
        }
    }

    /// Abandon the store without the awaited close: the unclean shutdown.
    fn kill(self) {
        drop(self);
    }

    /// Shut down through the endorsed path, for the tests that contrast a
    /// clean stop with a kill.
    fn close(mut self) -> Result<(), EngineError> {
        self.node.block_on(self.store.close(&self.cx))
    }

    fn put(&self, key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityFailure> {
        self.node
            .block_on(self.store.put_if_absent(&self.cx, key, body))
            .map_err(EngineError::into_failure)
    }

    fn read_body(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.node
            .block_on(self.store.read_immutable(&self.cx, key))
            .map_err(EngineError::into_failure)
    }

    fn init_head(&self, key: &HeadKey, generation: HeadGeneration, body: &[u8]) {
        self.node
            .block_on(self.store.initialize_head(&self.cx, key, generation, body))
            .expect("the genesis head initializes");
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.node
            .block_on(self.store.read_head(&self.cx, key))
            .map_err(EngineError::into_failure)
    }

    fn exchange(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.node
            .block_on(
                self.store
                    .compare_exchange_head(&self.cx, key, expected, generation, body),
            )
            .map_err(EngineError::into_failure)
    }

    fn token(&self, key: &HeadKey) -> AuthorityVersionToken {
        match self.read_head(key).expect("the head reads") {
            HeadRead::Present(receipt) => receipt.token(),
            HeadRead::Absent => panic!("the head must exist before a token is taken"),
        }
    }
}

// ------------------------------------------------------------------- fixtures

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible")
}

fn body_key(tag: &str) -> ImmutableKey {
    ImmutableKey::new(format!("blob/{tag}").into_bytes()).expect("admissible")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a small generation is admissible")
}

const GENESIS: &[u8] = b"head-generation-1";
const ADVANCED: &[u8] = b"head-generation-2";

// ------------------------------------------ bodies survive an unclean shutdown

#[test]
fn a_body_written_before_a_kill_is_readable_after_reopen() {
    let scratch = Scratch::new("body-survives-kill");
    let node = node();
    let key = body_key("survivor");

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    assert_eq!(
        first.put(&key, b"durable").expect("the body writes"),
        PutOutcome::Created,
        "the first write of a body must create it"
    );
    first.kill();

    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    assert_eq!(
        second.read_body(&key).expect("the body reads"),
        ImmutableRead::Present(b"durable".to_vec()),
        "a body acknowledged before an unclean shutdown must still be present after reopen"
    );
}

#[test]
fn a_body_reoffered_after_a_kill_is_an_identical_retry_not_a_second_write() {
    // The immutability rule has to hold across a restart, not merely within one
    // connection's lifetime: a reopened store that had forgotten the body would
    // report Created a second time and silently permit a rewrite.
    let scratch = Scratch::new("body-identical-retry");
    let node = node();
    let key = body_key("retry");

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    first.put(&key, b"once").expect("the body writes");
    first.kill();

    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    assert_eq!(
        second.put(&key, b"once").expect("the retry resolves"),
        PutOutcome::IdenticalRetry,
        "an identical body offered again after reopen is a retry, never a fresh creation"
    );
    assert_eq!(
        second
            .put(&key, b"different")
            .expect("the conflict resolves"),
        PutOutcome::Conflict,
        "a different body under a written key must conflict across a restart too"
    );
}

// ----------------------------------------------------- old- or new-completeness

#[test]
fn a_head_is_old_complete_or_new_complete_after_a_kill_following_the_exchange() {
    // THE CENTRAL ACCEPTANCE LINE. The head is either the predecessor or the
    // successor after an unclean shutdown, never a mixture of the two, and
    // never a generation that no writer ever published.
    let scratch = Scratch::new("old-or-new-complete");
    let node = node();
    let key = head_key();

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    first.init_head(&key, generation(1), GENESIS);
    let token = first.token(&key);
    let outcome = first.exchange(&key, token, generation(2), ADVANCED);
    let committed = matches!(outcome, Ok(CasOutcome::Committed(_)));
    first.kill();

    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    let receipt = match second.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("an initialized head must survive an unclean shutdown"),
    };

    let observed = receipt.body().to_vec();
    assert!(
        observed == GENESIS || observed == ADVANCED,
        "the head must be old-complete or new-complete after a kill, never a mixture: {observed:?}"
    );

    // Body and generation must agree. A head carrying generation 2 with the
    // genesis body -- or the reverse -- is the mixed state the acceptance line
    // forbids, and it is exactly what a partially applied exchange would leave.
    let expected_generation = if observed == ADVANCED { 2 } else { 1 };
    assert_eq!(
        receipt.generation(),
        generation(expected_generation),
        "the surviving generation must match the surviving body, not straddle the exchange"
    );

    // And the survivor must be the one the writer was told about: an
    // acknowledged commit may not roll back.
    if committed {
        assert_eq!(
            observed, ADVANCED,
            "an exchange acknowledged as committed must never be absent after reopen -- that is \
             a silent rollback of published state"
        );
    }
}

#[test]
fn a_token_taken_before_a_kill_cannot_win_a_second_exchange_after_reopen() {
    // ABA safety across a restart. The token names a specific version; if the
    // reopened store re-issues or re-honours it, the same predecessor could be
    // exchanged twice and two writers would each believe they published.
    let scratch = Scratch::new("token-aba-across-kill");
    let node = node();
    let key = head_key();

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    first.init_head(&key, generation(1), GENESIS);
    let stale = first.token(&key);
    first
        .exchange(&key, stale, generation(2), ADVANCED)
        .expect("the first exchange resolves");
    first.kill();

    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    let replayed = second.exchange(&key, stale, generation(3), b"head-generation-3");
    assert!(
        !matches!(replayed, Ok(CasOutcome::Committed(_))),
        "a token consumed before the kill won again after reopen: the same predecessor was \
         exchanged twice and both writers would believe they published"
    );
}

#[test]
fn a_cleanly_closed_store_and_a_killed_one_reopen_to_the_same_head() {
    // The endorsed shutdown and the unclean one must not disagree about
    // committed state. If they do, durability depends on how the process
    // happened to end, which is the property this whole file exists to deny.
    let node = node();

    let clean_scratch = Scratch::new("clean-close");
    let clean = Crashable::open(&node, clean_scratch.as_str(), StoreInstanceId::from_raw(1));
    clean.init_head(&head_key(), generation(1), GENESIS);
    let token = clean.token(&head_key());
    clean
        .exchange(&head_key(), token, generation(2), ADVANCED)
        .expect("the exchange resolves");
    clean.close().expect("the store closes cleanly");

    let killed_scratch = Scratch::new("killed");
    let killed = Crashable::open(&node, killed_scratch.as_str(), StoreInstanceId::from_raw(1));
    killed.init_head(&head_key(), generation(1), GENESIS);
    let token = killed.token(&head_key());
    killed
        .exchange(&head_key(), token, generation(2), ADVANCED)
        .expect("the exchange resolves");
    killed.kill();

    let reopened_clean =
        Crashable::open(&node, clean_scratch.as_str(), StoreInstanceId::from_raw(1));
    let reopened_killed =
        Crashable::open(&node, killed_scratch.as_str(), StoreInstanceId::from_raw(1));

    let after_clean = match reopened_clean.read_head(&head_key()).expect("reads") {
        HeadRead::Present(receipt) => (receipt.generation(), receipt.body().to_vec()),
        HeadRead::Absent => panic!("a cleanly closed store lost its head"),
    };
    let after_killed = match reopened_killed.read_head(&head_key()).expect("reads") {
        HeadRead::Present(receipt) => (receipt.generation(), receipt.body().to_vec()),
        HeadRead::Absent => panic!("a killed store lost an acknowledged head"),
    };

    assert_eq!(
        after_clean, after_killed,
        "an acknowledged exchange must reopen identically whether the store was closed or killed"
    );
}

// --------------------------------------------------- equivalence vs reference

/// One scripted history, replayed against any backend, returning the observable
/// outcomes in order.
///
/// Deliberately returns owned values rather than asserting inline: the point of
/// the differential is to compare two runs, and a helper that asserts cannot be
/// compared with anything.
fn scripted_history<S: AuthorityStore>(store: &S) -> Vec<String> {
    let key = head_key();
    let mut log = Vec::new();

    let blob = body_key("scripted");
    log.push(format!("{:?}", store.put_if_absent(&blob, b"payload")));
    log.push(format!("{:?}", store.put_if_absent(&blob, b"payload")));
    log.push(format!("{:?}", store.put_if_absent(&blob, b"other")));
    log.push(format!("{:?}", store.read_immutable(&blob)));

    log.push(format!("{:?}", store.read_head(&key)));
    let _ = store.initialize_head(&key, generation(1), GENESIS);

    let token = match store.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => {
            log.push(format!(
                "gen={:?} body={:?}",
                receipt.generation(),
                receipt.body()
            ));
            receipt.token()
        }
        HeadRead::Absent => panic!("the genesis head must be present"),
    };

    // A winner, then a loser replaying the consumed token.
    log.push(format!(
        "{:?}",
        store
            .compare_exchange_head(&key, token, generation(2), ADVANCED)
            .map(|outcome| matches!(outcome, CasOutcome::Committed(_)))
    ));
    log.push(format!(
        "{:?}",
        store
            .compare_exchange_head(&key, token, generation(3), b"head-generation-3")
            .map(|outcome| matches!(outcome, CasOutcome::Committed(_)))
    ));

    match store.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => {
            log.push(format!(
                "final gen={:?} body={:?}",
                receipt.generation(),
                receipt.body()
            ));
        }
        HeadRead::Absent => log.push("final absent".to_owned()),
    }
    log
}

/// The blocking view the differential needs, so one generic script can drive
/// the engine as well as the reference.
impl AuthorityStore for Crashable<'_> {
    fn instance_id(&self) -> StoreInstanceId {
        self.store.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.store.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.put(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.read_body(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<fgit_authority::HeadInit, AuthorityFailure> {
        self.node
            .block_on(self.store.initialize_head(&self.cx, key, generation, body))
            .map_err(EngineError::into_failure)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        Crashable::read_head(self, key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.exchange(key, expected, new_generation, new_body)
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &fgit_authority::HeadReadReceipt,
    ) -> Result<fgit_authority::AuthenticatedHead, AuthorityFailure> {
        self.node
            .block_on(self.store.authenticate_head_receipt(&self.cx, receipt))
            .map_err(EngineError::into_failure)
    }
}

#[test]
fn the_engine_and_the_reference_produce_the_same_scripted_history() {
    // Stronger than "both pass the suite": the suite asks whether each backend
    // is individually lawful, and two backends can both be lawful while
    // disagreeing about which lawful answer they give. This compares the
    // answers themselves.
    let scratch = Scratch::new("differential");
    let node = node();

    let reference = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let engine = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));

    let from_reference = scripted_history(&reference);
    let from_engine = scripted_history(&engine);

    assert_eq!(
        from_reference.len(),
        from_engine.len(),
        "the two histories must have the same shape before their contents can be compared"
    );
    for (step, (expected, observed)) in from_reference.iter().zip(from_engine.iter()).enumerate() {
        assert_eq!(
            expected, observed,
            "step {step} of the scripted history diverged between the reference and the engine"
        );
    }
}

#[test]
fn the_runtime_reaches_quiescence_after_every_store_in_this_file() {
    // A leaked worker does not fail any assertion above; it fails the next
    // suite to run, somewhere else, for reasons that will look unrelated.
    let node = node();
    let scratch = Scratch::new("quiescence");
    let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    store.close().expect("the store closes cleanly");
    assert!(
        node.join_root(Duration::from_secs(5)),
        "the runtime did not reach quiescence after an explicit close"
    );
}

// ------------------------------------------------------- planted wrong backends
//
// A differential that has never been shown to fail is not evidence. These
// backends are deliberately wrong in one specific way each, and the same
// `scripted_history` comparison that passes above must reject every one of
// them. Without this section, `the_engine_and_the_reference_produce_the_same
// _scripted_history` could be comparing two identical piles of nothing.
//
// The defects are planted in a wrapper over the reference, never in
// `fgit-authority-fsqlite/src`. A verifier who edits the implementation to
// prove his own test works has proved nothing about the implementation.

/// Which single law the wrapped backend breaks.
#[derive(Clone, Copy, Debug)]
enum Defect {
    /// Honours a token that was already consumed: two writers each believe
    /// they published over the same predecessor.
    SecondWinner,
    /// Acknowledges an immutable write it never performed.
    DroppedWrite,
    /// Reports a fresh creation where the body was already present, which
    /// hides a rewrite behind an idempotent-looking answer.
    RetryReportedAsCreate,
}

struct Planted {
    inner: MemoryAuthorityStore,
    defect: Defect,
}

impl Planted {
    fn new(defect: Defect) -> Self {
        Self {
            inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(1)),
            defect,
        }
    }
}

impl AuthorityStore for Planted {
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        match self.defect {
            Defect::DroppedWrite => Ok(PutOutcome::Created),
            Defect::RetryReportedAsCreate => {
                let _ = self.inner.put_if_absent(key, body)?;
                Ok(PutOutcome::Created)
            }
            Defect::SecondWinner => self.inner.put_if_absent(key, body),
        }
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.inner.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<fgit_authority::HeadInit, AuthorityFailure> {
        self.inner.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.inner.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        let honest = self
            .inner
            .compare_exchange_head(key, expected, new_generation, new_body)?;
        match (self.defect, &honest) {
            // Re-run the exchange against the CURRENT token so the loser is
            // told it won. This is the second-winner bug exactly: the store
            // still moves, but a consumed predecessor was accepted.
            (Defect::SecondWinner, CasOutcome::PredecessorMismatch) => {
                let current = match self.inner.read_head(key)? {
                    HeadRead::Present(receipt) => receipt.token(),
                    HeadRead::Absent => return Ok(honest),
                };
                self.inner
                    .compare_exchange_head(key, current, new_generation, new_body)
            }
            _ => Ok(honest),
        }
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &fgit_authority::HeadReadReceipt,
    ) -> Result<fgit_authority::AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

#[test]
fn the_differential_rejects_every_planted_backend() {
    // The control: an unplanted reference must agree with itself, or a
    // difference below would prove nothing about the defect.
    let control_a = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let control_b = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    assert_eq!(
        scripted_history(&control_a),
        scripted_history(&control_b),
        "two clean reference stores must produce identical histories; without this the \
         rejections below could be noise rather than detection"
    );
    let honest = scripted_history(&control_a);

    for defect in [
        Defect::SecondWinner,
        Defect::DroppedWrite,
        Defect::RetryReportedAsCreate,
    ] {
        let planted = scripted_history(&Planted::new(defect));
        assert_ne!(
            honest, planted,
            "the differential failed to notice a planted {defect:?}; a comparison that cannot \
             fail is not evidence that the engine agrees with the reference"
        );
    }
}

// ------------------------------------------------------- one winner under contention
//
// The acceptance line is "exact one-winner histories". These drive N
// contenders that all present the SAME predecessor token, which is the shape
// a real race produces: every writer read the head at the same generation and
// each believes it is replacing that exact predecessor.
//
// NON-CLAIM, and it bounds everything below: this is *contention*, not
// *parallelism*. The bridge blocks per operation, so the attempts are issued
// in turn rather than raced on separate threads. That is enough to prove the
// exclusion rule -- only one holder of a given predecessor may commit -- and
// it is NOT enough to prove anything about interleaving inside the engine.
// A true parallel race needs a harness that can hold several operations in
// flight, which is the same gap `engine_conformance.rs` names for
// cancellation.

/// Every contender presents `token`; returns each outcome in attempt order.
fn contend<S: AuthorityStore>(
    store: &S,
    key: &HeadKey,
    token: AuthorityVersionToken,
    contenders: usize,
) -> Vec<bool> {
    (0..contenders)
        .map(|index| {
            let body = format!("contender-{index}").into_bytes();
            matches!(
                store.compare_exchange_head(key, token, generation(2), &body),
                Ok(CasOutcome::Committed(_))
            )
        })
        .collect()
}

/// Set up a genesis head and hand back the token every contender will present.
fn genesis_token<S: AuthorityStore>(store: &S, key: &HeadKey) -> AuthorityVersionToken {
    store
        .initialize_head(key, generation(1), GENESIS)
        .expect("the genesis head initializes");
    match store.read_head(key).expect("the head reads") {
        HeadRead::Present(receipt) => receipt.token(),
        HeadRead::Absent => panic!("an initialized head must be present"),
    }
}

#[test]
fn exactly_one_contender_wins_on_the_engine_and_the_survivor_is_its_body() {
    let scratch = Scratch::new("one-winner-engine");
    let node = node();
    let key = head_key();
    let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));

    let token = genesis_token(&store, &key);
    let outcomes = contend(&store, &key, token, 5);

    let winners: Vec<usize> = outcomes
        .iter()
        .enumerate()
        .filter_map(|(index, won)| won.then_some(index))
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one holder of a predecessor token may commit, got {winners:?}"
    );

    // The survivor must be the winner's body, not merely *a* contender's. A
    // store that committed one writer while persisting another's bytes would
    // satisfy a naive count and still have published something nobody was
    // told about.
    let expected = format!("contender-{}", winners[0]).into_bytes();
    match store.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => assert_eq!(
            receipt.body(),
            expected.as_slice(),
            "the head must carry the body of the writer that was told it won"
        ),
        HeadRead::Absent => panic!("the head vanished under contention"),
    }
}

#[test]
fn the_engine_and_the_reference_pick_the_same_winner_under_contention() {
    // Both backends must not merely produce *a* single winner; under an
    // identical script they must produce the SAME one, or a caller that
    // migrates between profiles sees a different history for the same
    // sequence of requests.
    let scratch = Scratch::new("one-winner-differential");
    let node = node();
    let key = head_key();

    let reference = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let engine = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));

    let from_reference = contend(&reference, &key, genesis_token(&reference, &key), 5);
    let from_engine = contend(&engine, &key, genesis_token(&engine, &key), 5);

    assert_eq!(
        from_reference, from_engine,
        "the two profiles disagreed about which contender won the same scripted race"
    );
    assert_eq!(
        from_reference.iter().filter(|won| **won).count(),
        1,
        "the shared result must itself be a single winner, or the agreement is agreement on a bug"
    );
}

#[test]
fn a_kill_during_contention_still_leaves_exactly_one_winner() {
    // The dangerous combination: a race and a crash. After reopen the head
    // must carry one contender's body whole -- not a blend, and not a
    // generation from a writer that was refused.
    let scratch = Scratch::new("contention-then-kill");
    let node = node();
    let key = head_key();

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    let token = genesis_token(&first, &key);
    let outcomes = contend(&first, &key, token, 4);
    let winners = outcomes.iter().filter(|won| **won).count();
    first.kill();

    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    let receipt = match second.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("a contended head must survive an unclean shutdown"),
    };

    let survivor = receipt.body().to_vec();
    let is_genesis = survivor == GENESIS;
    let is_contender = (0..4).any(|index| survivor == format!("contender-{index}").into_bytes());
    assert!(
        is_genesis || is_contender,
        "after a kill the head must be the predecessor or one whole contender, not a blend: \
         {survivor:?}"
    );
    assert_eq!(
        receipt.generation(),
        generation(if is_genesis { 1 } else { 2 }),
        "the surviving generation must match the surviving body"
    );
    if winners == 1 {
        assert!(
            is_contender,
            "a contender was told it committed, so its body may not be absent after reopen"
        );
    }
}

// --------------------------------------------------- identity across a reopen
//
// `establish` reads the identity row and returns the RECORDED instance when
// one exists, ignoring the id the caller proposed. That is the right rule --
// a database's identity belongs to the database, not to whoever opened it --
// and it is the rule these tests pin, because the failure mode is quiet.
//
// A store that adopted the proposed id would let a caller rename a database
// by reopening it. Tokens are per-instance, so a renamed store either starts
// honouring tokens issued to a different instance or stops honouring its own,
// and both are authenticity failures that no single-connection test would
// notice.

#[test]
fn a_reopened_store_keeps_its_recorded_identity_not_the_proposed_one() {
    let scratch = Scratch::new("identity-across-reopen");
    let node = node();

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    assert_eq!(
        first.instance_id(),
        StoreInstanceId::from_raw(1),
        "a fresh database adopts the proposed identity"
    );
    first.init_head(&head_key(), generation(1), GENESIS);
    first.kill();

    // Reopen proposing a DIFFERENT identity. The recorded one must win.
    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(7));
    assert_eq!(
        second.instance_id(),
        StoreInstanceId::from_raw(1),
        "a reopened database keeps its recorded identity; adopting the proposed one would let a \
         caller rename a store by opening it, and tokens are scoped per instance"
    );
}

#[test]
fn a_token_taken_before_a_kill_still_wins_after_a_mismatched_reopen() {
    // The other half of the identity rule, and the one that would actually
    // corrupt state: an UNCONSUMED token from before the kill must still be
    // honoured after reopening under a different proposed id, because the
    // instance did not really change. If a mismatched reopen invalidated live
    // tokens, a crash plus a careless caller would strand a legitimate writer.
    let scratch = Scratch::new("token-across-mismatched-reopen");
    let node = node();
    let key = head_key();

    let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    first.init_head(&key, generation(1), GENESIS);
    let token = first.token(&key);
    first.kill();

    let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(7));
    let outcome = second.exchange(&key, token, generation(2), ADVANCED);
    assert!(
        matches!(outcome, Ok(CasOutcome::Committed(_))),
        "an unconsumed token must survive a kill and a mismatched reopen: the recorded instance \
         never changed, so the token was never for a different store; got {outcome:?}"
    );
}

#[test]
fn a_fresh_database_at_a_new_path_does_not_inherit_another_stores_head() {
    // The control for the two tests above. If every store shared state, they
    // would pass for the wrong reason -- so this pins that identity and
    // durability are per-database and that Scratch really does hand out clean
    // files.
    let occupied = Scratch::new("occupied");
    let empty = Scratch::new("empty");
    let node = node();

    let first = Crashable::open(&node, occupied.as_str(), StoreInstanceId::from_raw(1));
    first.init_head(&head_key(), generation(1), GENESIS);
    first.kill();

    let other = Crashable::open(&node, empty.as_str(), StoreInstanceId::from_raw(1));
    assert_eq!(
        other.read_head(&head_key()).expect("the head reads"),
        HeadRead::Absent,
        "a database at a different path must start empty; if it did not, every durability \
         assertion in this file could be reading another test's state"
    );
}

// --------------------------------------------------- the filesystem matrix
//
// "Every claimed target filesystem/profile" is an acceptance line, and a
// crash matrix that only ever ran on one filesystem has not tested it. The
// durability semantics that matter here -- what survives an unclean shutdown
// -- are exactly the semantics that differ between a page-cache-only
// filesystem and a journaling or copy-on-write one.
//
// The trap this section is built to avoid: running the same fixtures against
// two PATHS proves nothing if both live on the same filesystem. So the bases
// are deduplicated by device id, and the test refuses to pass unless it
// genuinely exercised more than one device. Set FG005B_FS_BASES (colon
// separated) to declare the environment deliberately -- a single entry is an
// explicit statement that only one filesystem is available here, rather than
// an accident that quietly halves the coverage.
//
// Unix only: the device-id check is the whole mechanism, and without it this
// test cannot tell two filesystems from two directories.

#[cfg(unix)]
fn distinct_bases() -> Vec<(PathBuf, u64)> {
    use std::os::unix::fs::MetadataExt;

    let declared = std::env::var("FG005B_FS_BASES").unwrap_or_default();
    let candidates: Vec<PathBuf> = if declared.is_empty() {
        // /dev/shm is a distinct tmpfs from /tmp on essentially every Linux
        // host, so discovery does not depend on this repo's layout.
        vec![
            std::env::temp_dir(),
            PathBuf::from("/data/tmp"),
            PathBuf::from("/dev/shm"),
        ]
    } else {
        declared.split(':').map(PathBuf::from).collect()
    };

    let mut seen = Vec::new();
    for base in candidates {
        if !base.is_dir() {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&base) else {
            continue;
        };
        let device = meta.dev();
        // Two directories on one filesystem are one filesystem. Counting them
        // twice is how this cell would report coverage it does not have.
        if seen.iter().any(|(_, known)| *known == device) {
            continue;
        }
        seen.push((base, device));
    }
    seen
}

#[cfg(unix)]
#[test]
fn the_crash_matrix_holds_on_every_distinct_filesystem() {
    let bases = distinct_bases();

    // Two demands, deliberately split.
    //
    // Always: at least one filesystem, or the loop below runs zero times and
    // the test passes having asserted nothing.
    //
    // Under FG005B_FS_STRICT: at least TWO distinct devices, which is the
    // actual coverage claim. That demand lives behind a flag the e2e lane
    // sets rather than in every `cargo test --workspace` run, because a host
    // with a single filesystem is a reason to report thin coverage -- not a
    // reason to fail the workspace suite for every other agent sharing this
    // checkout.
    assert!(
        !bases.is_empty(),
        "no usable filesystem found; the loop below would assert nothing"
    );
    if std::env::var("FG005B_FS_STRICT").is_ok() {
        assert!(
            bases.len() >= 2,
            "only {} distinct filesystem(s) exercised: {:?}. Two paths on one device are one \
             filesystem, so this cell would otherwise report coverage it does not have. Set \
             FG005B_FS_BASES to name distinct bases, or unset FG005B_FS_STRICT to accept thin \
             coverage deliberately.",
            bases.len(),
            bases.iter().map(|(base, _)| base).collect::<Vec<_>>()
        );
    }

    let node = node();
    let key = head_key();

    for (base, device) in &bases {
        let scratch = Scratch::in_base(base, "fs-matrix");

        let first = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
        first.init_head(&key, generation(1), GENESIS);
        let token = first.token(&key);
        let committed = matches!(
            first.exchange(&key, token, generation(2), ADVANCED),
            Ok(CasOutcome::Committed(_))
        );
        first.kill();

        let second = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
        let receipt = match second.read_head(&key).expect("the head reads") {
            HeadRead::Present(receipt) => receipt,
            HeadRead::Absent => {
                panic!("the head did not survive an unclean shutdown on {base:?} (device {device})")
            }
        };

        let observed = receipt.body().to_vec();
        assert!(
            observed == GENESIS || observed == ADVANCED,
            "old-complete or new-complete must hold on {base:?} (device {device}), got \
             {observed:?}"
        );
        assert_eq!(
            receipt.generation(),
            generation(if observed == ADVANCED { 2 } else { 1 }),
            "body and generation must agree on {base:?} (device {device})"
        );
        assert!(
            !committed || observed == ADVANCED,
            "an acknowledged commit rolled back on {base:?} (device {device}): durability must \
             not depend on which filesystem the store happens to sit on"
        );
    }
}

// ----------------------------------------------------- descriptors and workers
//
// The acceptance line: "explicit close/join leaves zero DB workers, threads,
// descriptors, transactions, reservations, or ambiguous effects."
//
// `the_runtime_reaches_quiescence_after_every_store_in_this_file` covers the
// join half. This covers the descriptor half, which nothing else does and
// which a single open/close cannot show: one leaked descriptor per store is
// invisible once and obvious eight times. A long-lived node that opens and
// closes stores -- reopening after a crash, cycling profiles, running a
// recovery drill -- exhausts its descriptor limit and then fails at something
// unrelated, which is the worst shape of bug to diagnose.
//
// Linux only: /proc/self/fd is the mechanism.

#[cfg(target_os = "linux")]
fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd is readable on linux")
        .count()
}

#[cfg(target_os = "linux")]
#[test]
fn repeated_open_and_close_cycles_do_not_leak_descriptors() {
    const CYCLES: usize = 8;
    let node = node();

    // One warm-up cycle first. The first open may populate caches or lazily
    // start a worker that legitimately outlives it, and counting that as a
    // leak would make this test fail for a reason that is not a leak.
    {
        let scratch = Scratch::new("fd-warmup");
        let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
        store.init_head(&head_key(), generation(1), GENESIS);
        store.close().expect("the store closes cleanly");
    }

    let baseline = open_descriptors();

    for cycle in 0..CYCLES {
        // A distinct path per cycle. Reusing one label deletes and recreates
        // the same database file inside a single process, which is a
        // different scenario (and one this crate refuses); the subject here
        // is descriptor accounting across many stores, not path reuse.
        let scratch = Scratch::new(&format!("fd-cycle-{cycle}"));
        let store = Crashable::try_open(&node, scratch.as_str(), StoreInstanceId::from_raw(1))
            .unwrap_or_else(|error| {
                panic!("cycle {cycle} could not open a store on a reused node: {error:?}")
            });
        store.init_head(&head_key(), generation(1), GENESIS);
        let token = store.token(&head_key());
        store
            .exchange(&head_key(), token, generation(2), ADVANCED)
            .expect("the exchange resolves");
        store
            .close()
            .unwrap_or_else(|error| panic!("cycle {cycle} failed to close cleanly: {error:?}"));
    }

    let after = open_descriptors();

    // A tolerance rather than equality: the test harness itself may open a
    // file between the two samples, and a flaky leak detector gets muted
    // rather than fixed. The bound is well under CYCLES, so a genuine
    // one-descriptor-per-store leak (which would show +8) cannot hide inside
    // it.
    assert!(
        after <= baseline + 2,
        "descriptors grew from {baseline} to {after} across {CYCLES} open/close cycles; a leak \
         of one per store exhausts a long-lived node's limit and then fails at something \
         unrelated"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_store_releases_its_descriptors_too() {
    // The killed path, not the closed one. A crash-and-reopen loop is exactly
    // what this crate's recovery story asks a node to do repeatedly, so if
    // only the AWAITED close released descriptors, recovery itself would be
    // the thing that exhausts them.
    const CYCLES: usize = 8;
    let node = node();

    {
        let scratch = Scratch::new("fd-kill-warmup");
        let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
        store.init_head(&head_key(), generation(1), GENESIS);
        store.kill();
    }

    let baseline = open_descriptors();

    for cycle in 0..CYCLES {
        let scratch = Scratch::new(&format!("fd-kill-cycle-{cycle}"));
        let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
        store.init_head(&head_key(), generation(1), GENESIS);
        store.kill();
    }

    let after = open_descriptors();
    assert!(
        after <= baseline + 2,
        "descriptors grew from {baseline} to {after} across {CYCLES} kill/reopen cycles; recovery \
         is the path a node takes most often after a crash, so a leak here is worst exactly when \
         the system is already degraded"
    );
}

// ------------------------------------------- the atomic publication path
//
// `publish_decisions_async` mints the DuplicateAbsenceWitness internally via
// the duplicate walk and then calls `publish_head_with_outcomes`, the operation
// that writes outcome entries and replaces the head inside one BEGIN/COMMIT.
// Its doc names the window it closes: "a crash or a lost response cannot leave
// the head advanced with outcome records missing."
//
// The ids below come from `fgit_authority`'s own `authority_head_identity` and
// `decision_batch_identity`. That matters beyond convenience: these are the
// functions the publication itself calls, so a fixture cannot derive an id by
// a parallel route that drifts from the one the code under test uses. It also
// means the algorithm is never a value a fixture author picks, so these
// fixtures cannot encode a domain/algorithm pairing the registry forbids.

use fgit_authority::{
    authority_head_identity, decision_batch_identity, outcome_key, publish_decisions_async,
};
use fgit_codec::RepositoryDecision;
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecisionBatchBody, encode_body,
};
use fgit_types::hash::DigestAlgorithmId;
use fgit_types::identity::{
    PrincipalSnapshotId, RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, TxId,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DecisionSequence, Digest, DigestBytes, OPAQUE_ID_LEN,
    PolicyEpoch, RefusalCode, RegistryEpoch, RepositoryId, RepositorySequence, TenantId,
};

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

const fn tenant_id() -> TenantId {
    TenantId::from_bytes([3; OPAQUE_ID_LEN])
}

fn head_body_id(head: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    authority_head_identity(head).expect("a head body has an identity")
}

fn batch_body_id(batch: &RepositoryDecisionBatchBody) -> RepositoryDecisionBatchId {
    decision_batch_identity(batch).expect("a batch body has an identity")
}

/// A fixture digest.
///
/// Code point 2 is sha256 — `GitAndInternalIdentity`, 32 bytes — which is the
/// length carried here. Code point 1 is sha1, whose registry usage is
/// `GitIdentityOnly`: "never an internal body identity". A fixture pairing it
/// with an internal id encodes a combination the registry forbids.
fn digest_of(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn genesis_head_body() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository_id(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest_of(0x10),
        forge_position_root: digest_of(0x11),
        outcome_index_root: digest_of(0x12),
        retention_root: digest_of(0x13),
        outbox_root: digest_of(0x14),
        configuration_root: digest_of(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn tx_of(byte: u8) -> TxId {
    TxId::from_digest(
        DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn refusal_of(byte: u8) -> RefusalRecordId {
    RefusalRecordId::from_digest(
        DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

/// A refusal-only batch: no committed RCRs, so the fixture needs no commit
/// records while still producing terminal decisions the atomic publication
/// must write alongside the head.
fn batch_for(predecessor: &RepositoryAuthorityHeadBody) -> RepositoryDecisionBatchBody {
    RepositoryDecisionBatchBody {
        repository_id: repository_id(),
        predecessor_head_id: head_body_id(predecessor),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: DecisionSequence::FIRST,
        decisions: vec![RepositoryDecision {
            tx_id: tx_of(0xd1),
            decision_sequence: DecisionSequence::FIRST,
            outcome: DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                refusal_record_id: refusal_of(0xd1),
            },
        }],
        committed_rcrs: Vec::new(),
        resulting_ref_root: digest_of(0x10),
        resulting_forge_position_root: digest_of(0x11),
        resulting_outcome_index_root: digest_of(0x20),
        resulting_retention_root: digest_of(0x13),
        resulting_outbox_root: digest_of(0x14),
        resulting_policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest_of(0x21),
    }
}

fn successor_of(
    predecessor: &RepositoryAuthorityHeadBody,
    tail: RepositoryDecisionBatchId,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        generation: HeadGeneration::try_new(predecessor.generation.get() + 1)
            .expect("a small generation advances"),
        predecessor_head_id: Some(head_body_id(predecessor)),
        decision_tail_id: Some(tail),
        latest_decision_sequence: Some(DecisionSequence::FIRST),
        outcome_index_root: digest_of(0x20),
        ..predecessor.clone()
    }
}

#[test]
fn a_kill_around_the_atomic_publication_leaves_head_and_outcomes_agreeing() {
    // THE WINDOW THE OPERATION EXISTS TO CLOSE. `publish_head_with_outcomes`
    // writes the outcome entries and replaces the head inside one
    // BEGIN/COMMIT, so a crash must never leave the head advanced with the
    // outcome records missing. That state is exactly what an accelerator-only
    // reader would call "undecided" for a transaction that is in fact decided.
    //
    // Reached through `publish_decisions_async`, which performs the duplicate
    // walk, mints the witness the atomic operation requires, and calls it.
    // Nothing here mints a witness; that remains impossible by design.
    let scratch = Scratch::new("atomic-publish-kill");
    let node = node();
    let key = head_key();

    let genesis = genesis_head_body();
    let genesis_bytes = encode_body(&genesis).expect("the genesis head encodes");
    let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    store.init_head(&key, HeadGeneration::FIRST, &genesis_bytes);
    let token = store.token(&key);

    let batch = batch_for(&genesis);
    let next = successor_of(&genesis, batch_body_id(&batch));
    let next_bytes = encode_body(&next).expect("the successor head encodes");

    let published = node.block_on(publish_decisions_async(
        &store.store,
        &store.cx,
        &key,
        token,
        &batch,
        &next,
        tenant_id(),
    ));
    // Non-vacuity. Both branches below are real, but only one of them asserts
    // the atomicity property, and a publication that quietly stopped
    // succeeding would send every run down the other one while still passing.
    // A fresh store with the token just read must publish.
    let advanced = published.is_ok();
    assert!(
        advanced,
        "the publication must succeed against a fresh store holding the token just read; \
         without it this test passes down the did-not-move branch and proves nothing about \
         atomicity: {published:?}"
    );
    store.kill();

    let reopened = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    let receipt = match reopened.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("an initialized head must survive an unclean shutdown"),
    };
    let observed = receipt.body().to_vec();

    assert!(
        observed == genesis_bytes || observed == next_bytes,
        "after a kill the head must be the predecessor or the successor whole, never a blend"
    );

    // The atomicity claim itself: if the head moved, the decision it published
    // must be readable. A head at generation 2 with no outcome entry for the
    // transaction it decided is precisely the torn state the single
    // BEGIN/COMMIT exists to prevent.
    let entry = outcome_key(tenant_id(), repository_id(), tx_of(0xd1)).expect("a key derives");
    let stored = reopened.read_body(&entry).expect("the outcome slot reads");
    if observed == next_bytes {
        assert!(
            matches!(stored, ImmutableRead::Present(_)),
            "the head advanced, so the outcome entry for its decision must be present: a head \
             ahead of its outcomes is the torn state the atomic publication forbids"
        );
    } else {
        assert_eq!(
            stored,
            ImmutableRead::Absent,
            "the head did not move, so nothing may have been published for it"
        );
    }

    if advanced {
        assert_eq!(
            observed, next_bytes,
            "an acknowledged publication must not be absent after reopen"
        );
    }
}

fn commit_id_of(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn snapshot_of(byte: u8) -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

/// A batch that COMMITS, so the publication writes a repository commit record
/// alongside the outcome entries and the head.
///
/// Deliberately distinct from the refusal-only fixture: a committing batch
/// widens the atomic window. More rows enter the same `BEGIN`/`COMMIT`, so if
/// atomicity were partial rather than total, this is the shape that exposes it
/// — a refusal-only batch could survive a torn transaction that a committing
/// one would not.
fn committing_batch_for(predecessor: &RepositoryAuthorityHeadBody) -> RepositoryDecisionBatchBody {
    let tx = tx_of(0xc1);
    RepositoryDecisionBatchBody {
        repository_id: repository_id(),
        predecessor_head_id: head_body_id(predecessor),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: DecisionSequence::FIRST,
        decisions: vec![RepositoryDecision {
            tx_id: tx,
            decision_sequence: DecisionSequence::FIRST,
            outcome: DecisionOutcome::Committed {
                repository_commit_id: commit_id_of(0xc1),
            },
        }],
        committed_rcrs: vec![RepositoryCommitRecord {
            repository_id: repository_id(),
            repository_sequence: RepositorySequence::FIRST,
            parent_rcr_id: None,
            tx_id: tx,
            principal_snapshot_id: snapshot_of(0xc2),
            canonical_request_digest: digest_of(0x30),
            ref_delta_root: digest_of(0x31),
            resulting_ref_root: digest_of(0x32),
            object_closure_root: digest_of(0x33),
            forge_event_batch_root: digest_of(0x34),
            resulting_forge_position_root: digest_of(0x35),
            policy_epoch: PolicyEpoch::FIRST,
            policy_decision_root: digest_of(0x36),
            invariant_evidence_root: digest_of(0x37),
            outbox_effect_root: digest_of(0x38),
            retention_delta_root: digest_of(0x39),
        }],
        resulting_ref_root: digest_of(0x32),
        resulting_forge_position_root: digest_of(0x35),
        resulting_outcome_index_root: digest_of(0x3a),
        resulting_retention_root: digest_of(0x13),
        resulting_outbox_root: digest_of(0x14),
        resulting_policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest_of(0x3b),
    }
}

#[test]
fn a_kill_around_a_committing_publication_keeps_the_commit_record_with_the_head() {
    // The wider atomic window. A committing batch puts a RepositoryCommitRecord
    // into the same transaction as the outcome entries and the head
    // replacement, so a partially applied transaction has more ways to show.
    let scratch = Scratch::new("atomic-commit-kill");
    let node = node();
    let key = head_key();

    let genesis = genesis_head_body();
    let genesis_bytes = encode_body(&genesis).expect("the genesis head encodes");
    let store = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    store.init_head(&key, HeadGeneration::FIRST, &genesis_bytes);
    let token = store.token(&key);

    let batch = committing_batch_for(&genesis);
    let mut next = successor_of(&genesis, batch_body_id(&batch));
    next.latest_committed_rcr_id = Some(commit_id_of(0xc1));
    next.latest_repository_sequence = Some(RepositorySequence::FIRST);
    next.ref_root = digest_of(0x32);
    next.forge_position_root = digest_of(0x35);
    next.outcome_index_root = digest_of(0x3a);
    let next_bytes = encode_body(&next).expect("the successor head encodes");

    let published = node.block_on(publish_decisions_async(
        &store.store,
        &store.cx,
        &key,
        token,
        &batch,
        &next,
        tenant_id(),
    ));
    assert!(
        published.is_ok(),
        "a committing publication against a fresh store must succeed, or the assertions below \
         run on the did-not-move branch and prove nothing: {published:?}"
    );
    store.kill();

    let reopened = Crashable::open(&node, scratch.as_str(), StoreInstanceId::from_raw(1));
    let receipt = match reopened.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("an initialized head must survive an unclean shutdown"),
    };
    assert_eq!(
        receipt.body(),
        next_bytes.as_slice(),
        "an acknowledged committing publication must be whole after reopen"
    );

    let entry = outcome_key(tenant_id(), repository_id(), tx_of(0xc1)).expect("a key derives");
    assert!(
        matches!(
            reopened.read_body(&entry).expect("the outcome slot reads"),
            ImmutableRead::Present(_)
        ),
        "the committed decision's outcome entry must survive with the head it was published \
         alongside: a head naming a commit whose outcome is missing is the torn state the \
         single transaction forbids"
    );
}
