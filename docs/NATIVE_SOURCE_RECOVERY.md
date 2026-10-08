# Native preparation of a bare source recovery

Related: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`, comprehensive plan
sections 21 and 23. This materializes Git source, not FrankenGit authority,
forge events, credentials, a complete capsule, or a currentness assertion.

`fg bundle verify INPUT.bundle --recovery-head-hex HEX` adds an explicitly
requested `recovery` object to the existing verification JSON. HEX is the
lowercase hexadecimal spelling of a full advertised `refs/heads/...` name.
Existing verification without that flag keeps its original report shape.

The native engine validates the full bundle, every reconstructed object and
all typed local graph dependencies once. The same resolver supplies the exact
pack offsets and native IDs used to construct idx-v2. A forward REF_DELTA does
not borrow a base from another repository. The original pack is preserved,
not repacked. The derived index includes exact encoded-entry CRCs and native
pack/index trailers. `fgit-pack` owns its encoding; the existing native idx
reader checks its structure and checksum before return.

The additional object uses profile `native-bare-source-layout-v1`, a
`pack_offset` into the verified input, and `head_ref_hex`, `index_hex`,
`packed_refs_hex`, `config_hex`, `head_hex`. No arbitrary output path or
configuration directive is accepted from the bundle. All refs remain raw
bytes inside packed-refs; HEAD names the explicitly selected advertised branch.
Prefix-overlapping namespaces refuse instead of producing an unmaintainable
repository. Native SHA-1/SHA-256 identities remain separate domains.

Preparation is read-only. A filesystem owner must reserve a new or exactly
identified recovery directory, stage/sync/read back the index, pack and metadata,
then publish HEAD last. A content-verification report alone never authorizes
writing over an existing repository or resolving a publication uncertainty.

Input/expanded/object/reference limits and cancellation retain the existing
native verifier boundaries. Index output also obeys the selected pack byte and
index-entry ceilings. The CLI bounds the complete layout report to 16 MiB and
checks cancellation while hex-encoding metadata. There is no streaming claim;
input and index/metadata consume separately bounded memory.

## Evidence boundary

The fixed fixtures in `tests/fixtures/native_bundle_recovery/` were independently
encoded and checked with Git 2.47.3: bundle verification, fetch, strict fsck and
reading the recovered file succeeded for SHA-1 and SHA-256. Their idx goldens
are the bytes emitted by that Git's `index-pack --index-version=2`. Both packs
contain a REF_DELTA before its base and an annotated tag.

The added Rust tests cover those exact bytes, coordinate/domain/duplicate
refusals, index limits, cancellation, raw ref names, namespace conflicts and
matched-pin/graph checks. They were authored but not compiled or run in the
editing environment, which has no Rust toolchain. Fixture-oracle success is
not native Rust execution, power-loss durability, a full-workspace gate or a
bead closure. Native acceptance still requires a built `fg` at the tested SHA.
