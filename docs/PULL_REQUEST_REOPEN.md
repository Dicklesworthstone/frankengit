# Reopen a closed native pull request

Bridge work: `frankengit-root-doctrine-x2mv.4.20`. Consumers are the existing
native node API, `fg pr` commands and authenticated HTTP PR metadata routes.

## Command and HTTP route

```
fg pr reopen ./fgit-data TENANT_ID REPOSITORY_ID NUMBER \
  --trusted-local --principal PRINCIPAL_ID --idempotency-key RETRY_KEY \
  --source-ref refs/heads/topic --expected-source SOURCE_OID \
  --target-ref refs/heads/main --expected-target TARGET_OID \
  --expected-version CLOSED_VERSION --title 'Resume review' --body 'Exact body'
```

Supply the exact positive closed version, both complete branch names and tips,
and all title/body bytes. `--body-file` and byte-preserving reference-hex options
have the same semantics as existing PR commands. SHA-1 and SHA-256 remain typed;
`--object-format` must agree with the submitted tips when explicitly supplied.

HTTP uses `POST /REPOSITORY_ROUTE/api/v1/pulls/NUMBER/reopen`, with the existing
PR write grant, authentication and `Idempotency-Key` requirements. The body is
`application/x-www-form-urlencoded`, with all eight existing metadata fields:
`expected_version`, `object_format`, `source_ref`, `target_ref`, `source_tip`,
`target_tip`, `title`, `body`. It is a write, never a GET or read permission.
The principal comes from authentication, not a form field.

## Canonical behavior

Only an immediately preceding closed native metadata event can reopen. An open
PR cannot reopen again. Ordinary updates do not reopen closed PRs. Merged PRs
and legacy-only closed streams cannot be resurrected. Source and target branch
identities cannot change, but the request may explicitly refresh their tips and
full metadata. Admission verifies both tips against live refs and checks the
existing visibility, native-object, version and publication conditions.

Reopen is native action code 4 inside the existing lifecycle event, not a new
opening event or an Update alias. Existing action codes/bytes remain unchanged.
Older decoders refuse the unknown action rather than treating it as an update;
readers must support it before these events are published to their repositories.
The original Open event still determines `opened_by`; reopening supplies the
new `last_metadata_actor`. Reads render the resulting PR as open.

The event, aggregate frontier and outbox obligation publish through the existing
sealed metadata transaction and single authority-head CAS. Reopening changes no
Git ref and grants no review approval. Existing review/merge checks still apply.
For a lost response, retry the exact same command, actor and key. A successful
old reopen retried after a later closure returns its original outcome; it does
not reopen again or enqueue another delivery. Another reopening after that
closure requires a new explicit command against its newer exact version.

## Verification boundary

The combined coverage on main includes the native transition/codec matrix,
SHA-1/SHA-256 command parsing, exact text and ref bytes, HTTP route selection,
missing/version/authority-field refusals, and the public node API over
file-backed storage. Concurrent CLI/HTTP parser changes and tests are retained;
this integration adds CLI byte-preservation and durable-node regressions.
The node tests cover coupled metadata/outbox publication, unchanged code roots,
opener preservation, replay after a later closure and physical node reopen,
stale competing requests, retargeting and moved tips. They do not simulate
process death or execute a live HTTP listener.

Focused targets are `fgit-forge`'s `event::pull_request::reopen_tests`, `fgit-cli`'s
`pull_request::reopen_tests`, `fgit-node`'s
`smart_http::server::pulls::request::tests`, and the `fgit-node` integration
target `pull_request_reopen`. The implementation environment has no Rust
toolchain: tests are checked in but not executed; no compilation, rustfmt,
Clippy, batch gate or bead closure is claimed. MCP/browser controls, PR comments,
merge strategies and the rest of the bridge work are outside this slice.
