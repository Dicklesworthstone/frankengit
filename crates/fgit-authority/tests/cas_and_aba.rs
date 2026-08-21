//! Conditional replacement: loser behaviour, single-winner races, ABA defence,
//! and monotone generation.

use fgit_authority::{
    AuthorityClient, AuthorityFailure, AuthorityObserver, AuthorityOp, AuthorityRefusal,
    AuthorityResponse, AuthorityStore, AuthorityVersionToken, CasOutcome, ClientId,
    HeadGeneration, HeadInit, HeadKey, HeadRead, HeadReadReceipt, Interleaving,
    MemoryAuthorityStore, StoreInstanceId, drive,
};

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn head_key(name: &str) -> HeadKey {
    HeadKey::new(name.as_bytes().to_vec()).expect("admissible head key")
}

fn created(store: &MemoryAuthorityStore, key: &HeadKey, body: &[u8]) -> HeadReadReceipt {
    match store
        .initialize_head(key, HeadGeneration::FIRST, body)
        .expect("head creation")
    {
        HeadInit::Created(receipt) => receipt,
        other => panic!("a fresh head slot must be created, observed {other:?}"),
    }
}

fn commit(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
    expected: AuthorityVersionToken,
    generation: u64,
    body: &[u8],
) -> HeadReadReceipt {
    match store
        .compare_exchange_head(key, expected, HeadGeneration::from_raw(generation), body)
        .expect("conditional replacement")
    {
        CasOutcome::Committed(receipt) => receipt,
        CasOutcome::PredecessorMismatch => {
            panic!("a conditional write on the exact predecessor token must publish")
        }
    }
}

#[test]
fn every_write_mints_a_distinct_token() {
    let store = store();
    let key = head_key("repo/head");
    let first = created(&store, &key, b"head-1");
    let second = commit(&store, &key, first.token(), 2, b"head-2");
    let third = commit(&store, &key, second.token(), 3, b"head-3");

    assert_ne!(first.token(), second.token());
    assert_ne!(second.token(), third.token());
    assert_ne!(first.token(), third.token());
    assert_eq!(store.issued_versions(), 3, "one token per write, no reuse");
}

#[test]
fn a_byte_identical_restore_mints_a_third_token_and_defeats_the_first_holder() {
    let store = store();
    let key = head_key("repo/head");

    let first = created(&store, &key, b"state-a");
    let second = commit(&store, &key, first.token(), 2, b"state-b");
    let third = commit(&store, &key, second.token(), 3, b"state-a");

    assert_eq!(
        third.body(),
        b"state-a",
        "the restore must republish the byte-identical body"
    );
    assert_ne!(
        third.token(),
        first.token(),
        "a byte-identical restore must not resurrect the original token"
    );
    assert_ne!(third.token(), second.token());

    let outcome = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(4), b"state-c")
        .expect("a stale but issued token loses rather than erroring");
    assert_eq!(
        outcome,
        CasOutcome::PredecessorMismatch,
        "a writer that slept through A -> B -> A must not be allowed to publish"
    );

    let live = commit(&store, &key, third.token(), 4, b"state-c");
    assert_eq!(
        live.generation(),
        HeadGeneration::from_raw(4),
        "the adjacent permitted case, a writer holding the current token, must proceed"
    );
}

#[test]
fn a_stale_generation_is_refused_and_a_strictly_increasing_one_is_accepted() {
    let store = store();
    let key = head_key("repo/head");
    let first = created(&store, &key, b"head-1");
    let seventh = commit(&store, &key, first.token(), 7, b"head-7");

    let equal = store
        .compare_exchange_head(
            &key,
            seventh.token(),
            HeadGeneration::from_raw(7),
            b"head-7b",
        )
        .expect_err("an equal generation must be refused");
    assert_eq!(
        equal,
        AuthorityFailure::Refused(AuthorityRefusal::NonMonotoneGeneration {
            current: HeadGeneration::from_raw(7),
            proposed: HeadGeneration::from_raw(7),
        })
    );

    let lower = store
        .compare_exchange_head(&key, seventh.token(), HeadGeneration::from_raw(3), b"head-3")
        .expect_err("a lower generation must be refused");
    assert_eq!(
        lower,
        AuthorityFailure::Refused(AuthorityRefusal::NonMonotoneGeneration {
            current: HeadGeneration::from_raw(7),
            proposed: HeadGeneration::from_raw(3),
        })
    );

    let eighth = commit(&store, &key, seventh.token(), 8, b"head-8");
    assert_eq!(eighth.generation(), HeadGeneration::from_raw(8));
}

#[test]
fn a_conditional_write_against_an_absent_head_is_refused() {
    let store = store();
    let present = head_key("repo/present");
    let absent = head_key("repo/absent");
    let receipt = created(&store, &present, b"head-1");

    let refused = store
        .compare_exchange_head(&absent, receipt.token(), HeadGeneration::from_raw(2), b"x")
        .expect_err("a token issued for another key must be refused");
    assert_eq!(
        refused,
        AuthorityFailure::Refused(AuthorityRefusal::TokenKeyMismatch)
    );

    let published = commit(&store, &present, receipt.token(), 2, b"head-2");
    assert_eq!(published.generation(), HeadGeneration::from_raw(2));
}

/// A logical client that reads the head and then attempts one conditional write.
struct Contender {
    key: HeadKey,
    label: u8,
    retry: bool,
    stage: Stage,
    token: Option<AuthorityVersionToken>,
    generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Read,
    Write,
    Done,
}

impl Contender {
    fn new(key: &HeadKey, label: u8, retry: bool) -> Self {
        Self {
            key: key.clone(),
            label,
            retry,
            stage: Stage::Read,
            token: None,
            generation: 0,
        }
    }
}

impl AuthorityClient for Contender {
    fn next_op(&mut self) -> Option<AuthorityOp> {
        match self.stage {
            Stage::Read => Some(AuthorityOp::ReadHead {
                key: self.key.clone(),
            }),
            Stage::Write => self.token.map(|expected| AuthorityOp::CompareExchangeHead {
                key: self.key.clone(),
                expected,
                new_generation: HeadGeneration::from_raw(self.generation + 1),
                new_body: vec![b'c', self.label],
            }),
            Stage::Done => None,
        }
    }

    fn observe(&mut self, response: &AuthorityResponse) {
        match response {
            AuthorityResponse::ReadHead(HeadRead::Present(receipt)) => {
                self.token = Some(receipt.token());
                self.generation = receipt.generation().raw();
                self.stage = Stage::Write;
            }
            AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
                if self.retry =>
            {
                self.stage = Stage::Read;
            }
            _ => self.stage = Stage::Done,
        }
    }
}

/// Records every response so a race can be judged after the run.
#[derive(Default)]
struct Recorder {
    responses: Vec<(ClientId, AuthorityResponse)>,
}

impl Recorder {
    fn cas_outcomes(&self) -> Vec<(ClientId, CasOutcome)> {
        self.responses
            .iter()
            .filter_map(|(client, response)| match response {
                AuthorityResponse::CompareExchangeHead(outcome) => {
                    Some((*client, outcome.clone()))
                }
                _ => None,
            })
            .collect()
    }
}

impl AuthorityObserver for Recorder {
    fn on_invoke(&mut self, _client: ClientId, _step: u64, _op: &AuthorityOp) {}

    fn on_return(&mut self, client: ClientId, _step: u64, response: &AuthorityResponse) {
        self.responses.push((client, response.clone()));
    }
}

#[test]
fn exactly_one_of_eight_contenders_wins_the_head() {
    let store = store();
    let key = head_key("repo/head");
    created(&store, &key, b"head-1");

    let mut clients: Vec<Box<dyn AuthorityClient>> = (0..8_u8)
        .map(|label| Box::new(Contender::new(&key, label, false)) as Box<dyn AuthorityClient>)
        .collect();
    let mut recorder = Recorder::default();

    // Every client reads in round one, so all eight hold the same predecessor
    // token; every client then attempts the same generation in round two.
    let summary = drive(
        &store,
        &mut clients,
        &Interleaving::round_robin(8, 2),
        &mut recorder,
    );
    assert_eq!(summary.steps, 16);
    assert_eq!(summary.skipped, 0);

    let outcomes = recorder.cas_outcomes();
    assert_eq!(outcomes.len(), 8, "every contender must have attempted");
    let winners = outcomes
        .iter()
        .filter(|(_, outcome)| matches!(outcome, CasOutcome::Committed(_)))
        .count();
    assert_eq!(winners, 1, "the head CAS, not the schedule, elects the winner");

    let HeadRead::Present(head) = store.read_head(&key).expect("head read") else {
        panic!("the head must still be published");
    };
    assert_eq!(head.generation(), HeadGeneration::from_raw(2));
}

#[test]
fn a_cas_loser_rereads_and_wins_on_its_next_attempt() {
    let store = store();
    let key = head_key("repo/head");
    created(&store, &key, b"head-1");

    let mut clients: Vec<Box<dyn AuthorityClient>> = (0..2_u8)
        .map(|label| Box::new(Contender::new(&key, label, true)) as Box<dyn AuthorityClient>)
        .collect();
    let mut recorder = Recorder::default();
    drive(
        &store,
        &mut clients,
        &Interleaving::round_robin(2, 6),
        &mut recorder,
    );

    let outcomes = recorder.cas_outcomes();
    let winners = outcomes
        .iter()
        .filter(|(_, outcome)| matches!(outcome, CasOutcome::Committed(_)))
        .count();
    let losers = outcomes
        .iter()
        .filter(|(_, outcome)| matches!(outcome, CasOutcome::PredecessorMismatch))
        .count();
    assert_eq!(winners, 2, "both contenders eventually publish");
    assert_eq!(losers, 1, "exactly one attempt lost the first race");

    let HeadRead::Present(head) = store.read_head(&key).expect("head read") else {
        panic!("the head must still be published");
    };
    assert_eq!(
        head.generation(),
        HeadGeneration::from_raw(3),
        "two publications advance the generation exactly twice"
    );
}

#[test]
fn an_interleaving_is_data_and_replays_identically() {
    let left = Interleaving::seeded(4, 20, 0xC0FF_EE01);
    let right = Interleaving::seeded(4, 20, 0xC0FF_EE01);
    assert_eq!(left.order(), right.order());
    assert_ne!(
        left.order(),
        Interleaving::seeded(4, 20, 0xC0FF_EE02).order(),
        "a different seed must produce a different schedule"
    );
    assert_eq!(Interleaving::round_robin(3, 2).len(), 6);
    assert!(Interleaving::explicit(Vec::new()).is_empty());
    assert_eq!(ClientId::from_raw(2).index(), 2);
}
