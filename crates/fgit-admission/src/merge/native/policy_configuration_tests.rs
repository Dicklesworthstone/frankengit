//! Exact production helper with a ready-only reference authority, not a native
//! runtime or metadata-authorization qualification.

#[path = "../../../../fgit-chronicle/tests/support/policy_transition.rs"]
mod fixture;

use core::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityStore, AuthorityVersionToken, CapabilityRevocationAuthorityFailure,
    CapabilityRevocationTransitionRefusal, CasOutcome, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome,
    StoreInstanceId, body_key_for_id, initialize_repository,
    read_head_selected_capability_revocation_generation,
};
use fgit_chronicle::{ChronicleRefusal, PublicationVerdict, publish_with_cumulative};
use fgit_crypto::IdentityDomain;
use fgit_types::{CANONICAL_CODEC_VERSION, HeadGeneration, InternalObjectId};

use super::{PolicyConfigurationFailure, seal_policy_configuration_async};
use fixture::{Fixture, TENANT, digest, plan, roots};

#[derive(Default)]
struct TestContext {
    cancelled: AtomicBool,
    puts: AtomicUsize,
    cancel_after_put: Option<usize>,
}

impl TestContext {
    fn live(&self) -> Result<(), AuthorityFailure> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled))
        } else {
            Ok(())
        }
    }
}

/// Test-only already-resolved futures, matching the authority conformance
/// reference surface. Every call sees the original supplied context.
struct AsyncMirror<'a>(&'a MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncMirror<'_> {
    type Context = TestContext;
    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        cx: &TestContext,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let result = cx.live().and_then(|()| {
            let result = self.0.put_if_absent(key, body)?;
            let ordinal = cx.puts.fetch_add(1, Ordering::SeqCst) + 1;
            if cx.cancel_after_put == Some(ordinal) {
                cx.cancelled.store(true, Ordering::SeqCst);
                return Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled));
            }
            Ok(result)
        });
        core::future::ready(result)
    }

    fn read_immutable(
        &self,
        cx: &TestContext,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        core::future::ready(cx.live().and_then(|()| self.0.read_immutable(key)))
    }
    fn initialize_head(
        &self,
        cx: &TestContext,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        core::future::ready(
            cx.live()
                .and_then(|()| self.0.initialize_head(key, generation, body)),
        )
    }
    fn read_head(
        &self,
        cx: &TestContext,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        core::future::ready(cx.live().and_then(|()| self.0.read_head(key)))
    }
    fn compare_exchange_head(
        &self,
        cx: &TestContext,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        core::future::ready(cx.live().and_then(|()| {
            self.0
                .compare_exchange_head(key, expected, generation, body)
        }))
    }
    fn authenticate_head_receipt(
        &self,
        cx: &TestContext,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        core::future::ready(
            cx.live()
                .and_then(|()| self.0.authenticate_head_receipt(receipt)),
        )
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let Poll::Ready(output) = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("reference fixture futures are ready");
    };
    output
}

#[test]
fn helper_stages_exact_dependencies_before_returning_a_publishable_candidate() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let event = digest(0xa0);
    let reference = fixture.transition(&current, event);
    let cx = TestContext::default();
    let publication = ready(seal_policy_configuration_async(
        &AsyncMirror(&fixture.store),
        &cx,
        TENANT,
        &current.authenticated,
        plan(&current, 0xa1, event),
        roots(&current, 0xa1),
        event,
        &current.cumulative,
        current.authenticated.receipt().token(),
    ))
    .expect("production helper prepares and stages");
    assert_eq!(cx.puts.load(Ordering::SeqCst), 2);
    assert_eq!(
        publication.head().configuration_root,
        reference.configuration_root()
    );
    ready(
        fgit_authority::verify_capability_revocation_epoch_transition_async(
            &AsyncMirror(&fixture.store),
            &cx,
            current.basis.body(),
            publication.head(),
            publication.batch().committed_rcrs[0].forge_event_batch_root,
        ),
    )
    .expect("the exact read-only helper used by native protection replay accepts this candidate");
    assert_eq!(
        fixture.store.read_head(&fixture.key).expect("pre-CAS head"),
        HeadRead::Present(current.authenticated.receipt().clone())
    );
    assert!(matches!(
        publish_with_cumulative(
            &fixture.store,
            &fixture.key,
            publication.expected_head_token(),
            &publication,
            TENANT,
            &current.cumulative
        )
        .expect("publish returned candidate"),
        PublicationVerdict::Published(_)
    ));
    let current = fixture.current();
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &fixture.store,
            TENANT,
            &current.authenticated
        )
        .expect("new epoch is usable")
        .body(),
        reference.generation()
    );
}

#[test]
fn explicit_no_root_configuration_keeps_its_bytes_without_enabling_revocation() {
    let fixture = Fixture::new(false);
    let current = fixture.current();
    let cx = TestContext::default();
    let publication = ready(seal_policy_configuration_async(
        &AsyncMirror(&fixture.store),
        &cx,
        TENANT,
        &current.authenticated,
        plan(&current, 0xa1, digest(0xa0)),
        roots(&current, 0xa1),
        digest(0xa0),
        &current.cumulative,
        current.authenticated.receipt().token(),
    ))
    .expect("supported absent root");
    assert_eq!(cx.puts.load(Ordering::SeqCst), 0);
    assert_eq!(
        publication.head().configuration_root,
        current.basis.body().configuration_root
    );
    assert!(matches!(
        publish_with_cumulative(
            &fixture.store,
            &fixture.key,
            publication.expected_head_token(),
            &publication,
            TENANT,
            &current.cumulative
        )
        .expect("existing policy transition"),
        PublicationVerdict::Published(_)
    ));
    let current = fixture.current();
    assert!(matches!(
        read_head_selected_capability_revocation_generation(
            &fixture.store,
            TENANT,
            &current.authenticated
        ),
        Err(CapabilityRevocationAuthorityFailure::ConfigurationHasNoRevocationRoot)
    ));
}

#[test]
fn no_root_from_another_basis_and_wrong_token_cannot_bypass_carry_forward() {
    let enabled = Fixture::new(true);
    let absent = Fixture::new(false);
    let required = enabled.current();
    let absent_current = absent.current();
    let cx = TestContext::default();
    assert!(matches!(
        ready(seal_policy_configuration_async(
            &AsyncMirror(&absent.store),
            &cx,
            TENANT,
            &absent_current.authenticated,
            plan(&required, 0xa1, digest(0xa0)),
            roots(&required, 0xa1),
            digest(0xa0),
            &absent_current.cumulative,
            absent_current.authenticated.receipt().token(),
        )),
        Err(PolicyConfigurationFailure::Chronicle(
            ChronicleRefusal::RevocationTransitionMismatch {
                field: "predecessor identity"
            }
        ))
    ));
    assert!(matches!(
        ready(seal_policy_configuration_async(
            &AsyncMirror(&absent.store),
            &cx,
            TENANT,
            &absent_current.authenticated,
            plan(&absent_current, 0xa1, digest(0xa0)),
            roots(&absent_current, 0xa1),
            digest(0xa0),
            &absent_current.cumulative,
            AuthorityVersionToken::from_opaque_bytes([0xff; 16]),
        )),
        Err(PolicyConfigurationFailure::Chronicle(
            ChronicleRefusal::RevocationTransitionMismatch {
                field: "predecessor token"
            }
        ))
    ));
    assert_eq!(cx.puts.load(Ordering::SeqCst), 0);
}

#[test]
fn mismatched_event_refuses_before_placing_new_configuration() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let cx = TestContext::default();
    assert!(matches!(
        ready(seal_policy_configuration_async(
            &AsyncMirror(&fixture.store),
            &cx,
            TENANT,
            &current.authenticated,
            plan(&current, 0xa1, digest(0xa0)),
            roots(&current, 0xa1),
            digest(0xb0),
            &current.cumulative,
            current.authenticated.receipt().token(),
        )),
        Err(PolicyConfigurationFailure::Chronicle(
            ChronicleRefusal::RevocationTransitionMismatch {
                field: "policy event root"
            }
        ))
    ));
    assert_eq!(cx.puts.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .store
            .read_head(&fixture.key)
            .expect("head unchanged"),
        HeadRead::Present(current.authenticated.receipt().clone())
    );
}

#[test]
fn cancellation_before_or_after_each_dependency_is_unpublished_and_exactly_retryable() {
    for point in 0..3 {
        let fixture = Fixture::new(true);
        let current = fixture.current();
        let cx = TestContext {
            cancelled: AtomicBool::new(point == 0),
            cancel_after_put: (point != 0).then_some(point),
            ..TestContext::default()
        };
        assert!(matches!(
            ready(seal_policy_configuration_async(
                &AsyncMirror(&fixture.store),
                &cx,
                TENANT,
                &current.authenticated,
                plan(&current, 0xa1, digest(0xa0)),
                roots(&current, 0xa1),
                digest(0xa0),
                &current.cumulative,
                current.authenticated.receipt().token(),
            )),
            Err(PolicyConfigurationFailure::Revocation(_))
        ));
        assert_eq!(cx.puts.load(Ordering::SeqCst), point);
        assert_eq!(
            fixture
                .store
                .read_head(&fixture.key)
                .expect("no candidate escaped"),
            HeadRead::Present(current.authenticated.receipt().clone())
        );
        let retry = TestContext::default();
        let publication = ready(seal_policy_configuration_async(
            &AsyncMirror(&fixture.store),
            &retry,
            TENANT,
            &current.authenticated,
            plan(&current, 0xa1, digest(0xa0)),
            roots(&current, 0xa1),
            digest(0xa0),
            &current.cumulative,
            current.authenticated.receipt().token(),
        ))
        .expect("fresh context stages identical dependencies");
        assert_eq!(
            retry.puts.load(Ordering::SeqCst),
            2,
            "never reuse a placement acknowledgement"
        );
        assert!(matches!(
            publish_with_cumulative(
                &fixture.store,
                &fixture.key,
                publication.expected_head_token(),
                &publication,
                TENANT,
                &current.cumulative
            )
            .expect("retry publishes"),
            PublicationVerdict::Published(_)
        ));
        let current = fixture.current();
        assert!(
            read_head_selected_capability_revocation_generation(
                &fixture.store,
                TENANT,
                &current.authenticated
            )
            .is_ok()
        );
    }
}

#[test]
fn missing_configuration_and_staged_content_conflict_are_not_published_refusals() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let reference = fixture.transition(&current, digest(0xa0));
    let identity = InternalObjectId::new(
        reference.configuration_root().algorithm(),
        IdentityDomain::RepositoryConfiguration.domain_tag(),
        CANONICAL_CODEC_VERSION,
        *reference.configuration_root().bytes(),
    );
    fixture
        .store
        .put_if_absent(
            &body_key_for_id(&identity).expect("new config slot"),
            b"conflicting configuration",
        )
        .expect("adversarial slot");
    let failure = ready(seal_policy_configuration_async(
        &AsyncMirror(&fixture.store),
        &TestContext::default(),
        TENANT,
        &current.authenticated,
        plan(&current, 0xa1, digest(0xa0)),
        roots(&current, 0xa1),
        digest(0xa0),
        &current.cumulative,
        current.authenticated.receipt().token(),
    ))
    .expect_err("dependency conflict stays undecided");
    assert!(matches!(
        failure,
        PolicyConfigurationFailure::Revocation(CapabilityRevocationTransitionRefusal::Authority(_))
    ));
    assert_eq!(
        fixture
            .store
            .read_head(&fixture.key)
            .expect("head unchanged"),
        HeadRead::Present(current.authenticated.receipt().clone())
    );

    let incomplete = Fixture {
        store: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x903)),
        key: fixture.key.clone(),
    };
    initialize_repository(&incomplete.store, &incomplete.key, current.basis.body())
        .expect("head fixture with absent selected config");
    let current = incomplete.current();
    let cx = TestContext::default();
    assert!(matches!(
        ready(seal_policy_configuration_async(
            &AsyncMirror(&incomplete.store),
            &cx,
            TENANT,
            &current.authenticated,
            plan(&current, 0xa1, digest(0xa0)),
            roots(&current, 0xa1),
            digest(0xa0),
            &current.cumulative,
            current.authenticated.receipt().token(),
        )),
        Err(PolicyConfigurationFailure::Revocation(_))
    ));
    assert_eq!(cx.puts.load(Ordering::SeqCst), 0);
}
