//! Change one exact read against the real embedded authority. This is a
//! deterministic failure fixture, not an alternate store or a load campaign.

use crate::{FsqliteCx, OneNode};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityRefusal,
    AuthorityVersionToken, CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey,
    ImmutableRead, PutOutcome, StoreInstanceId,
};
use fgit_runtime::meter::ClassLimits;
use fgit_types::HeadGeneration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    Cancel,
    Deadline,
    Capacity,
    Unavailable,
    NoResponse,
    Absent,
    Corrupt,
}

pub(super) struct ReadFault<'a> {
    node: &'a OneNode,
    key: ImmutableKey,
    fault: Fault,
    fired: AtomicBool,
}

impl<'a> ReadFault<'a> {
    pub(super) const fn new(node: &'a OneNode, key: ImmutableKey, fault: Fault) -> Self {
        Self {
            node,
            key,
            fault,
            fired: AtomicBool::new(false),
        }
    }

    pub(super) fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl AsyncAuthorityStore for ReadFault<'_> {
    type Context = FsqliteCx;

    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.node.authority)
    }

    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.node.authority)
    }

    async fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        if *key == self.key && !self.fired.swap(true, Ordering::SeqCst) {
            match self.fault {
                Fault::Cancel => cx.cancel(),
                Fault::Deadline => cx.set_native_cx(self.node.runtime.request_cx_with_budget(
                    ClassLimits::finite(Duration::ZERO, 1_000, 1_000).at(self.node.runtime.now()),
                )),
                Fault::Capacity => {
                    return Err(AuthorityFailure::Refused(
                        AuthorityRefusal::CapacityExhausted {
                            occupancy: 1,
                            limit: 1,
                        },
                    ));
                }
                Fault::Unavailable => {
                    return Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable));
                }
                Fault::NoResponse => {
                    return Err(AuthorityFailure::Ambiguous(
                        fgit_authority::AmbiguityReason::NoResponse,
                    ));
                }
                Fault::Absent => return Ok(ImmutableRead::Absent),
                Fault::Corrupt => {
                    return Ok(ImmutableRead::Present(
                        b"corrupt canonical history".to_vec(),
                    ));
                }
            }
        }
        AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await
    }

    async fn put_if_absent(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body).await
    }

    async fn initialize_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        AsyncAuthorityStore::initialize_head(&self.node.authority, cx, key, generation, body).await
    }

    async fn read_head(&self, cx: &FsqliteCx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        AsyncAuthorityStore::read_head(&self.node.authority, cx, key).await
    }

    async fn compare_exchange_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        AsyncAuthorityStore::compare_exchange_head(
            &self.node.authority,
            cx,
            key,
            expected,
            generation,
            body,
        )
        .await
    }

    async fn authenticate_head_receipt(
        &self,
        cx: &FsqliteCx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        AsyncAuthorityStore::authenticate_head_receipt(&self.node.authority, cx, receipt).await
    }
}
