# SSH deploy-key reference ceilings

`fg serve-ssh --deploy-keys-file` can restrict a deploy key to exact native refs
or namespaces while preserving ordinary repository policy. This extends the
same byte-preserving ceiling used by HTTP credentials to the actual SSH command
and receive path. It is operator-owned transport authorization; it does not
create a canonical identity store or activate repository policy snapshots.

## Configure a scoped key

A legacy table retains its existing three-column rows and unrestricted ref
ceiling. Opt into the scoped format with this first noncomment line:

```text
frankengit-ssh-deploy-keys-v2
```

Every following registration must contain four fields:

```text
<ed25519-public-key-hex> <principal-hex> <read,write> <ref-write-ceiling>
```

For example, this fourth field permits only descendants of `refs/heads/agent/`:

```text
prefix:726566732f68656164732f6167656e742f
```

Use `exact:<hex>` for a complete ref, `prefix:<hex>` for a slash-terminated
namespace, and commas for a union. `all` preserves the unrestricted ceiling;
`none` permits no ref writes. All reference bytes use lowercase hex, including
non-UTF-8 bytes. Prefixes match byte boundaries: `refs/heads/agent/` grants
neither `refs/heads/agent` nor `refs/heads/agents/topic`.

The ceiling is independent of service grants: `write` does not grant `read`,
and a ref selector cannot grant receive-pack to a read-only key. The ordinary
read view and repository protection rules still apply. Each ceiling admits at
most 64 selectors and 4096 decoded reference bytes. The complete key table
retains its 64 KiB and 256 logical-key limits. Missing fourth fields, duplicate
keys or selectors, mixed versions, pseudorefs, invalid native names, and any
malformed unrelated row refuse the complete snapshot. Legacy parsers reject
versioned input instead of discarding the ceiling.

## One command, one authorization snapshot

The SSH layer proves possession of the Ed25519 key before resolving the
repository and requested service. The live source then selects the principal
and ref ceiling from one fully validated file read. Both travel in one
`SshCommandGrant` and stay fixed for that command, including across rekey.
Atomically replace the private regular file to revoke, rotate or narrow grants
for later commands. A malformed or unavailable replacement grants nothing.
An already admitted bounded command keeps its selected grant.

A legacy principal-only authorization consumer refuses scoped receive grants;
it cannot silently strip the ceiling. SSH receive also refuses a missing grant
without substituting the raw Git daemon's operator principal.

## Receive and recovery semantics

The guarded receive coordinator checks every original command immediately after
bounded command framing, before reading PACK bytes, acquiring a writer slot,
binding retry keys or starting any non-atomic microbatch. One forbidden sibling
rejects the complete attempt, so a permitted prefix cannot publish. Native
admission repeats the check on the validated full request as a second boundary.
Creation, advancement and deletion all pass through the same byte check.

A scope refusal returns the existing Git ERR response. It says this attempt
was denied and that a prior outcome remains recoverable. No per-ref terminal
verdict is invented. Ref ceilings never enter the principal's transaction or
whole-session retry identity. Thus narrowing a credential denies a retry that
would now exceed its grant while leaving the original canonical outcome intact
for an independently authorized recovery reader. Pack encoding and key-file
rotation do not rewrite historical decisions.

## Focused verification

The added tests exercise strict versioned and legacy parsing, unchanged
canonical deploy-key encoding, permitted and refused native bytes, invalid
whole-table replacement, command-time revocation and scope narrowing, encrypted
SSH exec propagation, and the real persisted receive/quarantine/admission/recovery
path for SHA-1 and SHA-256. The encrypted protocol suite and persisted native
receive suite are separate tests, not a claimed external-client end-to-end run.

```sh
cargo test -p fgit-types --lib ref_write_scope
cargo test -p fgit-identity --test deploy_key_table
cargo test -p fgit-ssh --test ssh_session_security
cargo test -p fgit-node --lib ssh::deploy_keys
cargo test -p fgit-node --lib ssh::authorization_tests
cargo test -p fgit-node --lib ssh::ref_scope_tests
```
