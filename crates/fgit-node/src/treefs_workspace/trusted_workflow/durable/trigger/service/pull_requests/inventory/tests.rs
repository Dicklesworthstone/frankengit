use super::*;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SCOPE: [u8; 32] = [11; 32];
const BINDING: [u8; 32] = [12; 32];

struct Parent(PathBuf);
impl Parent {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-pr-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf {
        self.0.join(format!("pull-requests-{}", hex(&SCOPE)))
    }
    fn open(&self, maximum: usize) -> Inventory {
        Inventory::open(&self.0, SCOPE, BINDING, maximum, &|| true).unwrap()
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn entry(number: u64, initialized: bool) -> Entry {
    Entry {
        number,
        reference: RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap(),
        initialized,
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn resign(bytes: &mut Vec<u8>) {
    bytes.truncate(bytes.len() - 32);
    bytes.extend_from_slice(&sha256_digest(bytes));
}

#[test]
fn original_membership_and_phase_survive_reopen_and_capacity_changes() {
    let parent = Parent::new();
    let mut inventory = parent.open(2);
    let pending = vec![entry(2, false), entry(9, false)];
    inventory.replace(pending.clone(), &|| true).unwrap();
    drop(inventory);
    let mut inventory = parent.open(64);
    assert_eq!(inventory.entries(), pending);
    let initialized = vec![entry(2, true), entry(9, true)];
    inventory.replace(initialized.clone(), &|| true).unwrap();
    assert!(inventory.replace(pending, &|| true).is_err());
    assert!(inventory.replace(vec![entry(2, true)], &|| true).is_err());
    let mut rebound = initialized.clone();
    rebound[0].reference = RefName::try_new(b"refs/heads/replacement").unwrap();
    assert!(inventory.replace(rebound, &|| true).is_err());
    drop(inventory);
    assert!(Inventory::open(&parent.0, SCOPE, BINDING, 1, &|| true).is_err());
    assert_eq!(parent.open(2).entries(), initialized);
}

#[test]
fn late_lock_acquirer_adopts_membership_created_after_its_prelock_observation() {
    let parent = Parent::new();
    let mut first = parent.open(2);
    first.replace(vec![entry(7, true)], &|| true).unwrap();
    let original = fs::read(parent.root().join("inventory")).unwrap();
    drop(first);
    let _owner = Owner::open(&parent.root()).unwrap();
    // The first observation saw no root; an intervening completed owner has
    // since admitted a member. The under-lock read is decisive.
    let (members, bytes) = load_locked(&parent.root(), false, &SCOPE, &BINDING, 2, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(members, vec![entry(7, true)]);
    assert_eq!(bytes, original);
    assert_eq!(fs::read(parent.root().join("inventory")).unwrap(), original);
}

#[test]
fn owner_loss_record_loss_or_changed_publisher_cannot_initialize_a_fresh_view() {
    let parent = Parent::new();
    let inventory = parent.open(2);
    assert!(Inventory::open(&parent.0, SCOPE, BINDING, 2, &|| true).is_err());
    drop(inventory);
    // Binding is durable even while the collection contains no members.
    assert!(Inventory::open(&parent.0, SCOPE, [99; 32], 2, &|| true).is_err());
    fs::remove_file(parent.root().join("inventory")).unwrap();
    assert!(Inventory::open(&parent.0, SCOPE, BINDING, 2, &|| true).is_err());
    assert!(!parent.root().join("inventory").exists());
    fs::remove_file(parent.root().join("owner.lock")).unwrap();
    assert!(Inventory::open(&parent.0, SCOPE, BINDING, 2, &|| true).is_err());
    assert!(!parent.root().join("owner.lock").exists());
}

#[test]
fn interrupted_fixed_staging_preserves_original_record_and_resumes_boundedly() {
    let parent = Parent::new();
    let mut inventory = parent.open(3);
    inventory.replace(vec![entry(1, true)], &|| true).unwrap();
    let original = fs::read(parent.root().join("inventory")).unwrap();
    let staging = parent.root().join("inventory.next");
    assert!(matches!(
        inventory.replace(vec![entry(1, true), entry(2, false)], &|| !staging.exists()),
        Err(WorkflowWatchError::CollectionSelectionStopped)
    ));
    assert_eq!(fs::read(parent.root().join("inventory")).unwrap(), original);
    assert!(staging.is_file());
    drop(inventory);
    let mut inventory = parent.open(3);
    assert_eq!(inventory.entries(), &[entry(1, true)]);
    inventory
        .replace(vec![entry(1, true), entry(2, false)], &|| true)
        .unwrap();
    assert!(!staging.exists());
    assert_eq!(fs::read_dir(parent.root()).unwrap().count(), 2);
}

#[test]
fn cancelled_open_and_replace_do_not_mutate_membership() {
    let parent = Parent::new();
    assert!(matches!(
        Inventory::open(&parent.0, SCOPE, BINDING, 3, &|| false),
        Err(WorkflowWatchError::CollectionSelectionStopped)
    ));
    assert!(!parent.root().exists());
    let mut inventory = parent.open(3);
    let original = fs::read(parent.root().join("inventory")).unwrap();
    assert!(matches!(
        inventory.replace(vec![entry(1, false)], &|| false),
        Err(WorkflowWatchError::CollectionSelectionStopped)
    ));
    assert_eq!(fs::read(parent.root().join("inventory")).unwrap(), original);
}

#[test]
fn symlink_hardlink_and_unbounded_record_are_refused_without_following_them() {
    for mode in 0..3 {
        let parent = Parent::new();
        drop(parent.open(2));
        let record = parent.root().join("inventory");
        let original = fs::read(&record).unwrap();
        fs::remove_file(&record).unwrap();
        let foreign = parent.0.join("foreign");
        private_write(&foreign, &original);
        match mode {
            0 => symlink(&foreign, &record).unwrap(),
            1 => fs::hard_link(&foreign, &record).unwrap(),
            _ => {
                private_write(&record, &original);
                OpenOptions::new()
                    .write(true)
                    .open(&record)
                    .unwrap()
                    .set_len(MAX_BYTES as u64 + 1)
                    .unwrap();
            }
        }
        assert!(Inventory::open(&parent.0, SCOPE, BINDING, 2, &|| true).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), original);
    }
}

#[test]
fn integrity_scope_order_and_initialization_are_independently_validated() {
    let members = vec![entry(1, false), entry(7, true)];
    let bytes = encode(&members, &SCOPE, &BINDING, 2).unwrap();
    assert_eq!(decode(&bytes, &SCOPE, &BINDING, 2).unwrap(), members);
    assert!(decode(&bytes, &[13; 32], &BINDING, 2).is_err());
    assert!(decode(&bytes, &SCOPE, &[13; 32], 2).is_err());
    assert!(decode(&bytes, &SCOPE, &BINDING, 1).is_err());
    for offset in [0, 8, 40, 74, 82, 84] {
        let mut altered = bytes.clone();
        altered[offset] ^= 0xff;
        resign(&mut altered);
        assert!(
            decode(&altered, &SCOPE, &BINDING, 2).is_err(),
            "accepted modified field at {offset}"
        );
    }
    let mut corrupt = bytes.clone();
    corrupt[90] ^= 1;
    assert!(decode(&corrupt, &SCOPE, &BINDING, 2).is_err());
    assert!(decode(&bytes[..bytes.len() - 1], &SCOPE, &BINDING, 2).is_err());
    let mut appended = bytes.clone();
    appended.insert(appended.len() - 32, 0);
    resign(&mut appended);
    assert!(decode(&appended, &SCOPE, &BINDING, 2).is_err());
    assert!(encode(&[entry(7, true), entry(1, false)], &SCOPE, &BINDING, 2).is_err());
    assert!(encode(&[entry(1, true), entry(1, true)], &SCOPE, &BINDING, 2).is_err());
}
