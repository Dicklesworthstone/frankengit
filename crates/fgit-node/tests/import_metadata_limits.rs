#![forbid(unsafe_code)]
//! Actual canonical closure frames and native file-backed authority boundaries.
use fgit_admission::PermittedObjectClosure;
use fgit_authority::{
    AuthorityLimits, AuthorityRefusal, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fgit_types::{GitHashAlgorithm, GitOid};
use fsqlite_types::cx::Cx;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn closure(format: GitHashAlgorithm, count: usize) -> PermittedObjectClosure {
    let objects = (0..count)
        .map(|n| {
            let text = format!("{:0width$x}", n + 1, width = format.digest_len() * 2);
            GitOid::from_hex(format, &text).unwrap()
        })
        .collect::<BTreeSet<_>>();
    PermittedObjectClosure::new(objects)
}
struct Harness {
    runtime: NodeRuntime,
    cx: Cx,
    root: PathBuf,
}
impl Harness {
    fn new() -> Self {
        let runtime = RuntimeProfile::deterministic().build().unwrap();
        let cx = Cx::new();
        cx.set_native_cx(runtime.request_cx(BudgetClass::Transfer));
        let root = std::env::temp_dir().join(format!(
            "fg-import-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self { runtime, cx, root }
    }
    fn open(&self, name: &str, limits: AuthorityLimits) -> FsqliteAuthorityStore {
        self.runtime
            .block_on(FsqliteAuthorityStore::open(
                &self.cx,
                self.root.join(name).to_str().unwrap().to_owned(),
                StoreInstanceId::from_raw(1),
                limits,
            ))
            .unwrap()
    }
    fn close(&self, mut store: FsqliteAuthorityStore) {
        self.runtime.block_on(store.close(&self.cx)).unwrap();
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn key() -> ImmutableKey {
    ImmutableKey::new(b"test/import-closure".to_vec()).unwrap()
}
#[test]
fn canonical_closure_explains_the_old_object_count_cliff_without_waiting_for_a_deadline() {
    let h = Harness::new();
    for (format, name) in [
        (GitHashAlgorithm::Sha1, "sha1"),
        (GitHashAlgorithm::Sha256, "sha256"),
    ] {
        let overhead = encode_body(&closure(format, 0)).unwrap().len();
        let width = encode_body(&closure(format, 1)).unwrap().len() - overhead;
        let old = AuthorityLimits {
            body_bytes: 1 << 20,
            ..Default::default()
        };
        let maximum = (old.body_bytes - overhead) / width;
        let valid = encode_body(&closure(format, maximum)).unwrap();
        let too_large = encode_body(&closure(format, maximum + 1)).unwrap();
        assert!(valid.len() <= old.body_bytes && too_large.len() > old.body_bytes);
        let store = h.open(name, old);
        assert_eq!(
            h.runtime
                .block_on(store.put_if_absent(&h.cx, &key(), &valid))
                .unwrap(),
            PutOutcome::Created
        );
        let error = h
            .runtime
            .block_on(store.put_if_absent(
                &h.cx,
                &ImmutableKey::new(b"test/oversize".to_vec()).unwrap(),
                &too_large,
            ))
            .unwrap_err();
        assert!(
            matches!(error,EngineError::Contract(AuthorityRefusal::BodyTooLarge{len,limit}) if len==too_large.len() && limit==old.body_bytes),
            "{error:?}"
        );
        eprintln!(
            "closure boundary: {} overhead={overhead} oid_bytes={width} maximum_objects={maximum} rejected_bytes={}",
            format.as_str(),
            too_large.len()
        );
        h.close(store);
    }
}
#[test]
fn default_authority_can_retain_a_hundred_thousand_object_closure_in_both_hash_domains() {
    let h = Harness::new();
    for (format, name) in [
        (GitHashAlgorithm::Sha1, "large-sha1"),
        (GitHashAlgorithm::Sha256, "large-sha256"),
    ] {
        let expected = closure(format, 100_202);
        let frame = encode_body(&expected).unwrap();
        assert!(frame.len() > 1 << 20);
        assert!(
            frame.len() <= AuthorityLimits::default().body_bytes,
            "{} closure bytes {} exceed default authority profile {}",
            format.as_str(),
            frame.len(),
            AuthorityLimits::default().body_bytes
        );
        assert_eq!(
            decode_body::<PermittedObjectClosure>(&frame, DecodeLimits::DEFAULT).unwrap(),
            expected
        );
        let store = h.open(name, Default::default());
        assert_eq!(
            h.runtime
                .block_on(store.put_if_absent(&h.cx, &key(), &frame))
                .unwrap(),
            PutOutcome::Created
        );
        assert_eq!(
            h.runtime
                .block_on(store.put_if_absent(&h.cx, &key(), &frame))
                .unwrap(),
            PutOutcome::IdenticalRetry
        );
        h.close(store);
        let reopened = h.open(name, Default::default());
        assert_eq!(
            h.runtime
                .block_on(reopened.read_immutable(&h.cx, &key()))
                .unwrap(),
            ImmutableRead::Present(frame)
        );
        h.close(reopened);
    }
}

#[test]
fn canonical_frame_default_is_bounded_and_preserves_explicit_store_limits() {
    let limits = AuthorityLimits::default();
    assert_eq!(limits.body_bytes as u64, DecodeLimits::DEFAULT.frame_bytes);
    assert_eq!(
        (
            limits.immutable_slots,
            limits.head_slots,
            limits.version_tokens
        ),
        (1 << 16, 1 << 12, 1 << 20)
    );
    let h = Harness::new();
    let store = h.open("exact-default-bound", limits);
    let exact = vec![0x61; limits.body_bytes];
    assert_eq!(
        h.runtime
            .block_on(store.put_if_absent(&h.cx, &key(), &exact))
            .unwrap(),
        PutOutcome::Created
    );
    let oversized = vec![0x62; limits.body_bytes + 1];
    let missing = ImmutableKey::new(b"test/must-not-exist".to_vec()).unwrap();
    let error = h
        .runtime
        .block_on(store.put_if_absent(&h.cx, &missing, &oversized))
        .unwrap_err();
    assert!(
        matches!(error,EngineError::Contract(AuthorityRefusal::BodyTooLarge{len,limit}) if len==oversized.len() && limit==limits.body_bytes)
    );
    assert_eq!(
        h.runtime
            .block_on(store.read_immutable(&h.cx, &missing))
            .unwrap(),
        ImmutableRead::Absent
    );
    h.close(store);
    let reopened = h.open("exact-default-bound", limits);
    assert_eq!(
        h.runtime
            .block_on(reopened.read_immutable(&h.cx, &key()))
            .unwrap(),
        ImmutableRead::Present(exact)
    );
    h.close(reopened);
}
