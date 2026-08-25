#![forbid(unsafe_code)]
//! The hidden-ref policy, proven end to end on the production carrier.
//!
//! Every other test of this feature builds a policy by hand or sets
//! `AdmissionSnapshot.hidden_refs` directly. None of them shows that a policy a
//! repository actually *stores* reaches the guards, and for most of
//! `frankengit-jkbo`'s life it could not: the rule list lived on a schema
//! major-1 configuration body that `OneNode` can neither write nor open, so the
//! feature was correct and inert.
//!
//! The carrier ruling moved the rules into a separate `HiddenRefPolicyBody`
//! named by a `policy_root`, and `frankengit-fg059` gave the incarnation carrier
//! that field at schema 2.1 — which is the carrier `OneNode::init` actually
//! stages. So this test does the whole chain against the durable store:
//!
//! 1. initialize a repository through the production path;
//! 2. stage a policy body hiding `refs/private/*`;
//! 3. stage a 2.1 configuration naming it by `policy_root`;
//! 4. publish a head selecting that configuration, by authenticated CAS;
//! 5. reopen the node and materialize;
//! 6. assert the policy arrives in the materialized snapshot.
//!
//! If this passes, the feature is reachable. If it fails, everything else about
//! it is decoration.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_authority::{
    AuthorityLimits, CasOutcome, HeadKey, HeadRead, StoreInstanceId, authority_head_identity,
    stage_hidden_ref_policy_async, stage_latest_repository_incarnation_configuration_async,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_codec::{
    DecodeLimits, HiddenRefPolicyBody, RepositoryAuthorityHeadBody,
    RepositoryIncarnationConfigurationBodyV2_1, decode_body, encode_body,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_runtime::{BudgetClass, RuntimeProfile};
use fgit_types::{RepositoryId, TenantId};
use fsqlite_types::cx::Cx as FsqliteCx;

const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";
const STORE_INSTANCE: StoreInstanceId = StoreInstanceId::from_raw(1);

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-hidden-ref-policy-e2e-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x4C; 16]),
        RepositoryId::from_bytes([0x0B; 16]),
    )
}

fn authority_path(root: &Path) -> String {
    root.join(AUTHORITY_DATABASE_FILE)
        .into_os_string()
        .into_string()
        .expect("test scratch paths are UTF-8")
}

fn head_key(repository_id: RepositoryId) -> HeadKey {
    let mut bytes = Vec::with_capacity(HEAD_KEY_PREFIX.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(HEAD_KEY_PREFIX);
    bytes.extend_from_slice(repository_id.as_bytes());
    HeadKey::new(bytes).expect("the fixed node head key is within the key bound")
}

/// Stages a policy hiding `rules`, republishes the head's configuration at 2.1
/// naming it, and returns nothing — the repository now *stores* that policy.
fn publish_policy(root: &Path, repository_id: RepositoryId, rules: &[&[u8]]) {
    let runtime = RuntimeProfile::production(1)
        .build()
        .expect("the bounded test runtime builds");
    {
        let cx = FsqliteCx::new();
        cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
        let mut store = runtime
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                authority_path(root),
                STORE_INSTANCE,
                AuthorityLimits::default(),
            ))
            .expect("the persistent authority store reopens");

        let head_key = head_key(repository_id);
        let HeadRead::Present(receipt) = runtime
            .block_on(store.read_head(&cx, &head_key))
            .expect("the initialized repository has a persistent authority head")
        else {
            panic!("the initialized repository unexpectedly has no authority head");
        };
        let mut advanced: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT)
                .expect("the genesis authority head decodes");

        // The configuration the node staged at init, so the republished one
        // differs ONLY by its policy_root. Any other difference would make a
        // pass ambiguous.
        let existing: RepositoryIncarnationConfigurationBodyV2_1 = {
            let key = fgit_authority::body_key_for_configuration_root(&advanced.configuration_root)
                .expect("the configuration root has an immutable key");
            let fgit_authority::ImmutableRead::Present(bytes) = runtime
                .block_on(store.read_immutable(&cx, &key))
                .expect("the staged configuration is readable")
            else {
                panic!("the head names a configuration that is not present");
            };
            decode_body(&bytes, DecodeLimits::DEFAULT).expect("the 2.1 configuration decodes")
        };

        let policy = HiddenRefPolicyBody {
            rules: rules.iter().map(|rule| rule.to_vec()).collect(),
        };
        let policy_root = runtime
            .block_on(stage_hidden_ref_policy_async(&store, &cx, &policy))
            .expect("the policy body stages in persistent Fsqlite");

        let configuration = RepositoryIncarnationConfigurationBodyV2_1 {
            policy_root: Some(policy_root),
            ..existing
        };
        let configuration_root = runtime
            .block_on(stage_latest_repository_incarnation_configuration_async(
                &store,
                &cx,
                &configuration,
            ))
            .expect("the policy-bearing configuration stages");

        let predecessor =
            authority_head_identity(&advanced).expect("the predecessor head has an identity");
        advanced.generation = advanced
            .generation
            .next()
            .expect("the genesis generation has a successor");
        advanced.predecessor_head_id = Some(predecessor);
        advanced.configuration_root = configuration_root;
        let advanced_bytes = encode_body(&advanced).expect("the head selecting the policy encodes");
        assert!(matches!(
            runtime
                .block_on(store.compare_exchange_head(
                    &cx,
                    &head_key,
                    receipt.token(),
                    advanced.generation,
                    &advanced_bytes,
                ))
                .expect("the authenticated exact-predecessor CAS publishes the head"),
            CasOutcome::Committed(_)
        ));

        runtime
            .block_on(store.close(&cx))
            .expect("the persistent authority worker closes before node reopen");
    }
    assert!(
        runtime.join_root(Duration::from_secs(5)),
        "the authority mutation runtime reaches quiescence"
    );
}

#[test]
fn a_stored_policy_reaches_the_materialized_snapshot() {
    let scratch = ScratchDirectory::new();
    let node_config = config(scratch.0.clone());
    let repository_id = RepositoryId::from_bytes([0x0B; 16]);

    let (created, _) =
        OneNode::init(node_config.clone()).expect("the genesis configuration persists");
    created.shutdown().expect("the initialized node quiesces");

    publish_policy(&scratch.0, repository_id, &[b"refs/private"]);

    let node = OneNode::open_existing(node_config).expect("the policy-bearing head opens");
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("the authenticated head materializes");

    let policy = &materialized.snapshot().hidden_refs;
    assert!(
        policy.hides(b"refs/private/secret"),
        "a rule the repository STORES must reach the materialized snapshot — if this \
         fails, the feature is inert no matter how many unit tests pass"
    );
    // The permitted twin: without it this passes against a policy that hides
    // everything, which would be equally broken and far more obvious.
    assert!(
        !policy.hides(b"refs/heads/main"),
        "a ref no stored rule names must stay visible"
    );

    node.shutdown().expect("the node quiesces");
}
