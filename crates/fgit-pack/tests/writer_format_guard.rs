#![forbid(unsafe_code)]
//! FG-058 / decision D3: the pack planner refuses a root whose identity is in a
//! different hash domain than the pack being planned, and refuses it *before*
//! loading anything.
//!
//! `PackError::ObjectFormatMismatch` carries no discriminating field — only
//! `expected` and `actual` — and this crate raises it from `verify.rs` as well
//! as from the planner's `ensure_format` helper, which itself serves three call
//! sites. So the variant alone cannot say which guard fired. What this file
//! pins instead is the *entry point* and the *ordering*: the refusal is reached
//! through `PackPlanner::plan`, and the object source is never consulted.
//!
//! The ordering is the part a bare refusal test would miss. A planner that
//! loaded every root first and only then checked the format would still return
//! `ObjectFormatMismatch`, while doing unbounded work on objects from a domain
//! it was always going to reject.

use std::cell::Cell;

use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackError, PackLimits,
    PackPlanner, PackWriteError, PackWriteProfile,
};
use fgit_types::{GitOidSha1, GitOidSha256};

/// A source that records whether it was asked for anything and then refuses.
///
/// It never returns an object: this file is about the guard in front of it, so
/// the only thing that matters is whether the planner reached it at all.
#[derive(Default)]
struct RecordingSource {
    consulted: Cell<bool>,
}

impl CanonicalObjectSource for RecordingSource {
    fn load(&self, _id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.consulted.set(true);
        Err(PackError::NativeObjectIdMismatch.into())
    }
}

fn planner() -> PackPlanner {
    PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    )
}

fn sha1_root() -> ObjectId {
    ObjectId::from(GitOidSha1::from_bytes([0x11; 20]))
}

fn sha256_root() -> ObjectId {
    ObjectId::from(GitOidSha256::from_bytes([0x11; 32]))
}

#[test]
fn a_root_in_another_hash_domain_is_refused_before_the_source_is_consulted() {
    let source = RecordingSource::default();
    let mut live = || true;

    let refusal = planner()
        .plan(&source, &[sha256_root()], &mut live)
        .expect_err("a root from another hash domain cannot be planned into this pack");

    assert!(
        matches!(
            &refusal,
            PackWriteError::Pack(PackError::ObjectFormatMismatch { expected, actual })
                if *expected == ObjectFormat::Sha1 && *actual == ObjectFormat::Sha256
        ),
        "the refusal must name both formats, got {refusal:?}"
    );
    assert!(
        !source.consulted.get(),
        "the format guard must refuse before any object is loaded; loading first would do \
         unbounded work on a domain the planner was always going to reject"
    );
}

/// The permitted twin, and the other half of the ordering claim.
///
/// Same call, same source, same shape — only the root's hash domain differs. A
/// matching root must get *past* the format guard, which is observable here as
/// the source being consulted. Without this, the test above would pass equally
/// against a planner that refused every root and never loaded anything.
#[test]
fn a_root_in_the_packs_own_domain_reaches_the_source() {
    let source = RecordingSource::default();
    let mut live = || true;

    let outcome = planner().plan(&source, &[sha1_root()], &mut live);

    assert!(
        source.consulted.get(),
        "a root in the pack's own object format must pass the format guard and reach the source"
    );
    assert!(
        !matches!(
            outcome,
            Err(PackWriteError::Pack(PackError::ObjectFormatMismatch { .. }))
        ),
        "a matching root must not be refused as a format mismatch, got {outcome:?}"
    );
}
