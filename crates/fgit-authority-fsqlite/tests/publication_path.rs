//! The production publication path, checked at the type level.
//!
//! t7ip's root cause was that no production path ran from publication to a
//! durable store: `AuthorityStore` is synchronous, `MemoryAuthorityStore` was
//! its only implementation, and `FsqliteAuthorityStore` had inherent async
//! methods reachable by no generic caller. `publish_decisions_async` is the
//! answer to that, and this file exists so the answer is checked rather than
//! asserted — a publication path that does not instantiate against the durable
//! store is a claim, not a path.
//!
//! Nothing here runs. It compiles, which is the whole assertion: if
//! `FsqliteAuthorityStore` ever stops satisfying the bounds the generic
//! publication requires, this file stops building and says so by name, instead
//! of the gap being rediscovered by whoever next tries to compose a live node.

#![forbid(unsafe_code)]

use std::future::Future;

use fgit_authority::{
    AuthorityVersionToken, HeadKey, OutcomeFailure, PublicationOutcome, publish_decisions_async,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody};
use fgit_types::identity::TenantId;
use fsqlite_types::cx::Cx;

/// The durable store admits the generic publication.
///
/// Returning the future rather than awaiting it keeps this a pure type-level
/// obligation: no runtime, no database, no I/O.
fn the_durable_store_admits_the_generic_publication<'a>(
    store: &'a FsqliteAuthorityStore,
    cx: &'a Cx,
    head_key: &'a HeadKey,
    expected: AuthorityVersionToken,
    batch: &'a RepositoryDecisionBatchBody,
    head: &'a RepositoryAuthorityHeadBody,
    tenant_id: TenantId,
) -> impl Future<Output = Result<PublicationOutcome, OutcomeFailure>> + 'a {
    publish_decisions_async(store, cx, head_key, expected, batch, head, tenant_id)
}

/// And its future is `Send`.
///
/// §3.2 is the reason this is a separate obligation: a production surface whose
/// futures cannot cross threads cannot be spawned on a multi-threaded runtime,
/// which is most of the point of being async. `Send` is easy to lose by
/// accident — one non-`Send` value held across an await inside the publication
/// would do it — and the loss surfaces at the spawn site in another crate,
/// where it reads as that caller's problem.
fn the_publication_future_crosses_threads<'a>(
    store: &'a FsqliteAuthorityStore,
    cx: &'a Cx,
    head_key: &'a HeadKey,
    expected: AuthorityVersionToken,
    batch: &'a RepositoryDecisionBatchBody,
    head: &'a RepositoryAuthorityHeadBody,
    tenant_id: TenantId,
) -> impl Future<Output = Result<PublicationOutcome, OutcomeFailure>> + Send + 'a {
    publish_decisions_async(store, cx, head_key, expected, batch, head, tenant_id)
}

/// A test binary needs at least one test, and this one states the claim.
#[test]
fn the_production_publication_path_exists() {
    // Naming the two obligations is what makes them live code. A lint
    // exception would have silenced the unused warning just as well and would
    // have been the wrong tool: §3.1 rules those out, and a suppressed warning
    // is indistinguishable from a check that has quietly stopped meaning
    // anything. Referencing them keeps the compiler on the hook.
    let _admits = the_durable_store_admits_the_generic_publication;
    let _sendable = the_publication_future_crosses_threads;

    // Both are discharged by the compiler. If this binary built,
    // `publish_decisions_async` instantiates against the durable store and its
    // future is `Send`.
}
