#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use fgit_authority::{AuthorityLimits, ImmutableKey, ImmutableRead, StoreInstanceId};
use fgit_authority_fsqlite::{FsqliteAuthorityStore, companions};
use fgit_runtime::boot::RuntimeProfile;
use fgit_runtime::meter::BudgetClass;
use fsqlite::{AsyncConnection, SqliteValue};
use fsqlite_types::cx::Cx;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn native_wal_checkpoint_and_fec_files_belong_to_the_closed_authority_image() {
    let root = std::env::temp_dir().join(format!("fg-authority-companions-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let scratch = Scratch(root);
    let db = scratch.0.join(companions::DATABASE);
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    runtime.block_on(async {
        let key = ImmutableKey::new(b"companion-probe".to_vec()).unwrap();
        let mut store = FsqliteAuthorityStore::open(
            &cx,
            db.to_str().unwrap(),
            StoreInstanceId::from_raw(17),
            AuthorityLimits::default(),
        )
        .await
        .unwrap();
        let mut connection = AsyncConnection::open(&cx, db.to_str().unwrap().to_owned())
            .await
            .unwrap();
        let budget = connection
            .query(&cx, "PRAGMA raptorq_repair_symbols=7")
            .await
            .unwrap();
        assert_eq!(budget[0].get(0), Some(&SqliteValue::Integer(7)));
        store
            .put_if_absent(&cx, &key, b"before checkpoint")
            .await
            .unwrap();
        for name in [
            companions::DATABASE,
            companions::WAL,
            "authority.fsqlite-wal-fec",
            "authority.fsqlite-wal-fec.lock",
        ] {
            assert!(
                scratch.0.join(name).is_file(),
                "missing live engine file {name}"
            );
        }
        store.close(&cx).await.unwrap();
        let checkpoint = connection
            .query(&cx, "PRAGMA wal_checkpoint(TRUNCATE)")
            .await
            .unwrap();
        assert_eq!(checkpoint[0].get(0), Some(&SqliteValue::Integer(0)));
        connection.close(&cx).await.unwrap();
        let mut reopened = AsyncConnection::open(&cx, db.to_str().unwrap().to_owned())
            .await
            .unwrap();
        let budget = reopened
            .query(&cx, "PRAGMA raptorq_repair_symbols")
            .await
            .unwrap();
        assert_eq!(budget[0].get(0), Some(&SqliteValue::Integer(7)));
        reopened.close(&cx).await.unwrap();
        let mut store = FsqliteAuthorityStore::open(
            &cx,
            db.to_str().unwrap(),
            StoreInstanceId::from_raw(17),
            AuthorityLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            store.read_immutable(&cx, &key).await.unwrap(),
            ImmutableRead::Present(b"before checkpoint".to_vec())
        );
        store.close(&cx).await.unwrap();
    });
    companions::validate_closed_image(&scratch.0).unwrap();
    let foreign = scratch.0.join("authority.fsqlite-unreviewed");
    fs::write(&foreign, b"preserve").unwrap();
    let refusal = companions::validate_closed_image(&scratch.0).unwrap_err();
    assert_eq!(refusal.kind(), std::io::ErrorKind::InvalidData);
    assert!(refusal.to_string().contains("authority.fsqlite-unreviewed"));
    assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
}
