# Native binary patch preparation through the CLI

`fg patch prepare` accepts the explicit profile `exact-binary-v1`. This connects
the CLI preflight to the already implemented native binary literal/delta decoder
and the existing TreeFS candidate/admission path. The original `exact-v1` profile
still rejects compressed binary patches before opening the node. Neither profile
accepts rename/copy records, non-regular modes, fuzzy offsets or an external Git
fallback. Mixed ordinary text and binary changes are accepted by the new profile.

```sh
fg patch prepare NODE TENANT REPOSITORY refs/heads/main edit.patch candidate.bundle \
  --trusted-local --profile exact-binary-v1 --workspace-id WORKSPACE_ID \
  --expected-base BASE_OID --author 'Author <author@example.invalid>' \
  --timestamp TIMESTAMP --message 'Reviewed binary edits'
```

The source commit, full native old/new blob IDs, forward result and reverse image
are verified by the existing native engine. Decode limits remain shared across
the patch and across both directions. No existing byte, file or record allowance
is increased. A malformed later member, wrong reverse image, mismatched native
hash domain or exhausted limit produces no bundle. The caller's original
read/capability and authority checks are unchanged.

Preparation returns `profile: exact-binary-v1`, exact candidate/root IDs and the
patch/bundle hashes. It does not publish repository state. Inspect the saved
bundle and then use ordinary `fg patch apply` with the independent base/candidate,
principal and original idempotency key. The apply API does not accept a patch
profile because it admits the reviewed bundle, not a mutable encoding recipe.
Restart recovery repeats that original bundle and key; preparation or disconnect
never proves publication or non-publication.

The operator splice compiler can supply `--binary literal`, `--binary delta`, or
`--binary delta-runs`; these select encoding, not another native authorization
path. Private-file splice operands are documented in SOURCE_EDIT_SPLICE_FILES.md.
The actual Node CLI to Rust prepare/apply/restart path is exercised by
`scripts/e2e/suites/smokes/source_splice_native.sh` with prebuilt `FG_BIN` and an
explicit `NODE_BIN` or Node on PATH. Its independent Python object/bundle checks
verify desired bytes and untouched siblings in both hash formats. No mock server
or Git subprocess participates in this campaign. Existing patch and native binary
node tests remain applicable. This advances the live-fg operator boundary
(x2mv.4.59), not its complete production-entrypoint qualification.
