# Multiple repositories on one SSH listener

`fg serve-ssh --repositories-file` serves an explicit catalog of existing
repositories through one encrypted SSH listener. Each route selects a tenant,
repository, expected canonical incarnation, storage root and live deploy-key
source. A path is an operator routing hint. The selected node authenticates its
canonical authority head before serving Git; the catalog does not publish
repository state or create an account/organization identity registry.

The existing single-repository command and its path aliases remain available.
The catalog profile uses exact qualified paths and refuses alias fallback.

## Configure the catalog

Create a private regular file in an operator-owned directory. On Unix it must
have no group/other permission bits, one hard link, and no final symlink. For
example, set its permissions to `0600`. The complete file is bounded to 256 KiB,
each line to 16 KiB, and the catalog to 64 repositories. Blank lines and full-line
`#` comments are accepted. Trailing comments and quoted/escaped path fields are
not part of this format; fields cannot contain whitespace.

The first noncomment line is the format header:

```text
frankengit-ssh-repositories-v1
```

Each subsequent noncomment line has exactly eight whitespace-separated fields:

```text
<tenant/repository.git> <absolute-storage-root> <tenant-id> <repository-id> <expected-incarnation> <absolute-deploy-keys-file> <read-only|read-write> <absolute-lfs-root|->
```

All three IDs use their canonical 32-character lowercase hex encoding. Inspect
each repository locally before configuring its route:

```sh
fg doctor /srv/frankengit/core <tenant-id> <repository-id>
```

The authenticated report includes `repository_incarnation=<32-character-id>`
and `object_format=sha1|sha256`. Copy the incarnation into the fifth field. An
invented or stale value refuses startup. A retained authenticated creation or
resolution receipt can also supply this expectation. The serve command opens
existing repositories and does not create missing roots.

This illustrative two-repository table must be filled with the identities and
paths of the actual repositories before use:

```text
frankengit-ssh-repositories-v1
engineering/core.git /srv/frankengit/core 11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 /etc/frankengit/core.keys read-write /srv/frankengit-lfs
research/models.git /srv/frankengit/models 44444444444444444444444444444444 55555555555555555555555555555555 66666666666666666666666666666666 /etc/frankengit/models.keys read-only -
```

The final field enables the [receive LFS payload policy](RECEIVE_LFS_PAYLOAD_POLICY.md)
for that repository, using an existing absolute private custody root. `-`
disables that optional policy. LFS storage still scopes payloads by tenant,
repository and canonical incarnation even when repositories use one custody
root. Configuring it does not create an LFS HTTP upload listener or grant upload
access. The global `--require-lfs-payloads` flag is refused in catalog mode;
choose each route's policy explicitly in the table.

Every storage root is resolved before any node opens. Duplicate route paths,
duplicate tenant/repository/incarnation triples, symlink aliases of the same
root, and ancestor/descendant storage roots refuse the entire catalog. Distinct
tenants may use the same repository ID. Any malformed row, missing key file,
invalid identity, stale incarnation, or unavailable required LFS root refuses
startup before listener bind. A valid first row cannot hide a later failure.

## Start the listener

```sh
fg serve-ssh 127.0.0.1:2222 \
  --repositories-file /etc/frankengit/repositories \
  --host-key-file /etc/frankengit/ssh-host-key \
  --allow-receive \
  --max-in-flight 8 \
  --continuous --stop-file /run/frankengit/ssh.stop
```

The host-key file uses the existing single-repository SSH host-key format.
Use the existing [service lifetime controls](GIT_SERVICE_LIFETIME.md) for stop
files, signals, finite session deadlines and drain behavior. Bounded mode uses
`--max-sessions` instead of `--continuous --stop-file`; its default is 1,000
accepted sessions. Both modes retain the 1..16 global in-flight limit. Session,
receive envelope and pack limits use the same flags as single-repository SSH.
Inline deploy-key/principal/scope arguments and a global expected-incarnation
override are refused in catalog mode.

An ordinary Git remote for the first example is
`ssh://git@127.0.0.1:2222/engineering/core.git`. Routes contain exactly two ASCII
slug components separated by one slash; components may contain letters,
digits, `.`, `_` and `-`, cannot be `.` or `..`, and cannot start with `-`.
The complete route is at most 512 bytes. Letter case and the `.git` suffix are
literal. The SSH command parser removes one leading slash from the client
path; it does not add a suffix, decode path aliases, or search another tenant.

## Authorization and isolation

The peer must prove possession of its Ed25519 key before command authorization.
The parsed path selects one immutable catalog entry, and that entry's live
authorizer receives the actual repository ID. The same entry selects the node
used for dispatch. There is no path-hash fallback and no node lease before
authorization. An unknown route, an unauthorized key, a denied service and an
unavailable authorization source produce the same command refusal, without
repository data. This is response uniformity, not constant-time route secrecy.

Each deploy-key file supports the existing legacy and
[v2 ref-write ceiling](SSH_REF_WRITE_SCOPES.md) formats. It is fully reread at
each command. Atomically replacing that file changes the principal, read/write
service grants and ref ceiling for later commands without restarting the
listener. An already authorized command retains its selected principal and
ceiling. An invalid replacement grants nothing; there is no last-good-table
fallback.

A push requires all three deployment/credential gates:

1. The listener was started with `--allow-receive`.
2. The catalog row selects `read-write`.
3. The selected key grants `write`, and every original ref command lies within
   its ref-write ceiling.

Repository protection and native admission still apply. `write` does not
grant `read`, and neither catalog mode grants access to an unlisted key. Ref
ceilings are checked before any sibling ref can publish. The routing table is a
startup snapshot; changing a route, incarnation or deployment ceiling requires
a controlled restart. Updating a key file alone does not change those bounds.

Each route owns its writer gate, push quota, node pool and cache domains.
Captured node configurations pin the canonical incarnation, including on cold
reopen. Replacing a repository directory with a newly created incarnation does
not silently retarget a route. Directory parents and deployment files remain
operator-controlled inputs; the profile is not a defense against a privileged
operator replacing all authority inputs.

## Resource and shutdown boundaries

The CLI divides its configured computed-pack, received-pack and ancestry
metadata cache budgets across the number of routes, rounding down. Cache
retention therefore does not multiply these three listener budgets by the
catalog size. These limits do not bound total process RSS or every database and
request allocation. Embedded callers constructing `NodeConfig` directly choose
their own per-route budgets.

The listener bounds active sessions globally. Each route retains at most
`floor(max_in_flight / route_count)` idle child nodes; the sum of retained idle
children cannot exceed the global in-flight limit. With more routes than slots,
completed child nodes close instead of remaining cached. The anchor node owns
the listener runtime and accepted-session deadline profile. Node opening uses
existing finite native operation contexts; a stalled filesystem call is not
claimed to be interruptible by the SSH deadline.

On controlled stop, the owned listener closes before accepted children drain,
then all route pools close and the anchor shuts down. Accepted pushes may still
commit while draining. A lost response or timeout never proves non-commit.

Readiness emits `ssh_listening` with `schema_version: 1`, the bound `address`,
`routing: "explicit-v1"`, the repository count, `allow_receive`, and
`lifetime: "bounded" | "continuous"`. It does not emit catalog paths, keys or
identity triples. Continuous completion emits the existing `ssh_drained`
transport counters. These counters are not canonical transaction receipts.

## Focused verification and remaining scope

The test sources cover exact route selection, legacy single-repository
compatibility, live grant replacement, principal/ref-ceiling propagation,
catalog and file bounds, canonical-root ambiguity, incarnation replacement,
deadline checks and pool retirement. The native encrypted TCP test serves two
tenants with the same repository ID, different Git hash formats and different
keys. It pushes the same ref name independently, checks isolated advertisements,
compares denied/missing route behavior, and reopens both repositories to verify
their persisted refs and blob contents. This is an in-repository encrypted
client test, not an upstream Git/OpenSSH differential qualification.

```sh
cargo test --locked -p fgit-ssh --test ssh_session_security
cargo test --locked -p fgit-node --lib ssh::routing::tests -- --test-threads=1
cargo test --locked -p fgit-cli --bin fg ssh_server::repositories::tests -- --test-threads=1
```

This delivers the explicit deployment-routing part of NB-08
(`frankengit-root-doctrine-x2mv.1.3`). Canonical account/organization/team SSH-key
administration, automatic repository discovery, hosted tenant lifecycle and
complete external-client qualification remain separate work. The broader bead
is not closed by this catalog implementation.
