use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let root = Self(std::env::temp_dir().join(format!(
            "fg-invocation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir(&root.0).unwrap();
        root
    }
    fn store(&self) -> PathBuf {
        self.0.join("invocations")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn a_dropped_or_incomplete_claim_never_becomes_a_new_execution() {
    let root = Root::new();
    let first = Invocation::create(&root.store(), "one", b"request").unwrap();
    let exact = fs::read(first.directory.join("request")).unwrap();
    assert_eq!(sha256_digest(&exact), first.request_id);
    drop(first);
    for body in [b"request".as_slice(), b"different"] {
        assert!(matches!(
            Invocation::create(&root.store(), "one", body),
            Err(Refusal::AlreadyReserved(_))
        ));
    }
    fs::create_dir(root.store().join("interrupted-before-write")).unwrap();
    assert!(matches!(
        Invocation::create(&root.store(), "interrupted-before-write", b"request"),
        Err(Refusal::AlreadyReserved(_))
    ));
    assert!(Invocation::create(&root.store(), "independent", b"request").is_ok());
}
#[test]
fn only_one_concurrent_caller_can_acquire_execution_custody() {
    let root = Root::new();
    let store = root.store();
    let outcomes = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| Invocation::create(&store, "same", b"request")))
            .collect();
        tasks
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Err(Refusal::AlreadyReserved(_))))
            .count(),
        7
    );
}
#[test]
fn invalid_roots_and_metadata_bounds_refuse_beside_valid_inputs() {
    let root = Root::new();
    assert!(matches!(
        Invocation::create(&root.store(), "oversized", &vec![0; MAX_REQUEST + 1]),
        Err(Refusal::Limit)
    ));
    assert!(!root.store().exists());
    fs::create_dir(root.store()).unwrap();
    fs::set_permissions(root.store(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Invocation::create(&root.store(), "one", b"x"),
        Err(Refusal::InvalidStorage)
    ));
    fs::set_permissions(root.store(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Invocation::create(&root.store(), "one", b"x").is_ok());
    symlink(root.store(), root.0.join("link")).unwrap();
    assert!(matches!(
        Invocation::create(&root.0.join("link"), "two", b"x"),
        Err(Refusal::InvalidStorage)
    ));
}
#[test]
fn canonical_field_boundaries_preserve_argv_order_and_empty_values() {
    let encode = |items: Vec<&[u8]>| {
        let mut fields = Fields::default();
        fields.list(items.into_iter()).unwrap();
        fields.0
    };
    assert_ne!(encode(vec![b"ab", b"c"]), encode(vec![b"a", b"bc"]));
    assert_ne!(encode(vec![b"x", b"y"]), encode(vec![b"y", b"x"]));
    assert_ne!(encode(vec![]), encode(vec![b""]));
    assert_eq!(frame(REQUEST_MAGIC, b"x"), frame(REQUEST_MAGIC, b"x"));
}
