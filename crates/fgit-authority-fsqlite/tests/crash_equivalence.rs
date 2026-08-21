//! FG-005b: the kill/reopen matrix and reference equivalence, on a real file.
//!
//! Written by a pane that did not implement this crate. Nothing here edits
//! `fgit-authority-fsqlite/src`; every fixture drives the published surface.
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
//! * **This says nothing about cancellation mid-operation.** Like the
//!   conformance bridge, these tests block per operation, so a cancel cannot be
//!   interleaved with an operation in flight. That gap is named in
//!   `engine_conformance.rs` and is still open.
//! * **The injected-fault half of FG-005b is absent, not passing.** AF-01..AF-08
//!   require `FaultableAuthorityStore`, and `MemoryAuthorityStore` is the only
//!   implementation in the workspace. Ambiguity, duplication and
//!   lost-request-versus-lost-response are therefore **unproved for this
//!   backend**, and a green run of this file must not be read as covering them.

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
        let mut path = std::env::temp_dir();
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

// ------------------------------------------------------- durability of bodies

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
fn a_head_is_old_complete_or_new_complete_after_a_kill_at_the_exchange() {
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
    match replayed {
        Ok(CasOutcome::Committed(_)) => panic!(
            "a token consumed before the kill won again after reopen: the same predecessor was \
             exchanged twice and both writers would believe they published"
        ),
        Ok(_) | Err(_) => {}
    }
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
