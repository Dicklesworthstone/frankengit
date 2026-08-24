#![forbid(unsafe_code)]
//! A persisted authority head selects the repository configuration consumed by
//! [`OneNode::open_existing`].
//!
//! This test deliberately publishes a malformed current-v2 configuration
//! through the same durable `FsqliteAuthorityStore` and authenticated-head CAS
//! that an embedded node reopens. It is not a memory-store or synchronous
//! reader substitute for the production open path.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_authority::{
    AuthorityLimits, CasOutcome, HeadKey, HeadRead, OutcomeFailure, PutOutcome, StoreInstanceId,
    authority_head_identity, body_key, canonical_body_id,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, RepositoryAuthorityHeadBody,
    decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_node::{NodeConfig, NodeRefusal, OneNode};
use fgit_runtime::{BudgetClass, RuntimeProfile};
use fgit_types::error::TypeRefusal;
use fgit_types::hash::Digest;
use fgit_types::label::{DomainTag, SchemaFamily};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, RepositoryId, TenantId};
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
            "frankengit-persisted-configuration-refusals-{}-{sequence}",
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
        RepositoryId::from_bytes([0x0A; 16]),
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

/// An encoder-only frame with the exact current-v2 configuration identity but
/// an unallocated object-format code point. The type keeps the malformed value
/// out of the production vocabulary while making its canonical root precise.
struct UnknownV2ObjectFormatConfiguration;

impl CanonicalBody for UnknownV2ObjectFormatConfiguration {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-configuration/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-configuration");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(RootLayoutVersion::RefStateMerkleV1.code_point());
        out.write_scalar(u16::MAX);
        out.write_opaque_id(&[0xD4; 16]);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let _ = input.read_scalar::<u16>("root_layout")?;
        let _ = input.read_scalar::<u16>("object_format")?;
        let _ = input.read_opaque_id("repository_incarnation_id")?;
        Ok(Self)
    }
}

fn publish_malformed_configuration(root: &Path, repository_id: RepositoryId) {
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

        let malformed = UnknownV2ObjectFormatConfiguration;
        let malformed_key = body_key(IdentityDomain::RepositoryConfiguration, &malformed)
            .expect("the malformed v2 frame has a canonical immutable key");
        let malformed_bytes =
            encode_body(&malformed).expect("the malformed v2 frame encodes canonically");
        assert!(matches!(
            runtime
                .block_on(store.put_if_absent(&cx, &malformed_key, &malformed_bytes))
                .expect("the malformed configuration stages in persistent Fsqlite"),
            PutOutcome::Created
        ));
        let malformed_identity = canonical_body_id(
            IdentityDomain::RepositoryConfiguration,
            CANONICAL_CODEC_VERSION,
            &malformed,
        )
        .expect("the selected malformed root derives from its exact bytes");
        let malformed_root =
            Digest::new(malformed_identity.algorithm(), *malformed_identity.digest());

        let head_key = head_key(repository_id);
        let HeadRead::Present(receipt) = runtime
            .block_on(store.read_head(&cx, &head_key))
            .expect("the initialized repository has a persistent authority head")
        else {
            panic!("the initialized repository unexpectedly has no authority head");
        };
        let mut advanced: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT)
                .expect("the known genesis authority head decodes");
        let predecessor =
            authority_head_identity(&advanced).expect("the predecessor head has an identity");
        advanced.generation = advanced
            .generation
            .next()
            .expect("the genesis generation has a successor");
        advanced.predecessor_head_id = Some(predecessor);
        advanced.configuration_root = malformed_root;
        let advanced_bytes =
            encode_body(&advanced).expect("the head selecting malformed configuration encodes");
        assert!(matches!(
            runtime
                .block_on(store.compare_exchange_head(
                    &cx,
                    &head_key,
                    receipt.token(),
                    advanced.generation,
                    &advanced_bytes,
                ))
                .expect("the authenticated exact-predecessor CAS publishes the malformed head"),
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
fn open_existing_refuses_a_persistently_published_unknown_v2_object_format() {
    let scratch = ScratchDirectory::new();
    let node_config = config(scratch.0.clone());
    let repository_id = RepositoryId::from_bytes([0x0A; 16]);

    let (created, _) = OneNode::init(
        node_config
            .clone()
            .with_object_format(GitHashAlgorithm::Sha256),
    )
    .expect("the known-v2 SHA-256 genesis configuration persists");
    created
        .shutdown()
        .expect("the initialized node quiesces before the persistent mutation");

    // Permitted twin: the same persistent authority head selected by genesis
    // opens through the production asynchronous Fsqlite reader before the
    // adversarial successor replaces it.
    let permitted = OneNode::open_existing(node_config.clone())
        .expect("the known-v2 persistent head opens through the production path");
    permitted
        .shutdown()
        .expect("the permitted production open quiesces cleanly");

    publish_malformed_configuration(&scratch.0, repository_id);

    assert!(matches!(
        OneNode::open_existing(node_config),
        Err(NodeRefusal::Authority(error))
            if matches!(
                error.as_ref(),
                OutcomeFailure::Codec(CodecRefusal::Type(TypeRefusal::CodePointUnknown {
                    field: "GitHashAlgorithm",
                    observed: 65_535,
                }))
            )
    ));
}
