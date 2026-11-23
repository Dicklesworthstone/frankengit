# Multiple repositories on one HTTP listener

`fg serve-http --repositories-file` serves an explicit catalog of existing
repositories on one loopback HTTP listener. Ordinary Git clients use each
repository's exact URL for clone, fetch and push. Selected native issue,
outcome, pull-request and source endpoints use the same route and credential
binding. Each route selects a canonical repository incarnation; neither the
URL nor the catalog publishes repository state.

The single-repository command retains its existing syntax and behavior. This
catalog profile is an operator-owned deployment configuration, not an account
directory or a TLS service. Authenticated discovery exposes only the configured
routes for which the supplied credential has a read grant.

## Configure the catalog

Create a private regular file in an operator-owned directory. On Unix it must
have no group/other permission bits, exactly one hard link, and no final symlink.
Mode `0600` is suitable. Catalog mode requires this Unix private-file profile.
The complete file is bounded to 256 KiB, each line to 16 KiB, and the catalog to
64 repositories. Blank lines and full-line `#` comments are accepted. Fields
cannot contain whitespace; quoting, trailing comments and path expansion are
not supported.

The first noncomment line is the version header:

```text
frankengit-http-repositories-v1
```

Every remaining noncomment line has exactly eight fields:

```text
</tenant/repository.git> <absolute-storage-root> <tenant-id> <repository-id> <expected-incarnation> <absolute-credentials-file> <services> <required-lfs-root|->
```

The three IDs use canonical 32-character lowercase hex. Obtain the incarnation
from an authenticated local report, such as `fg doctor`, or provision each
credential-table header through the existing single-repository command:

```sh
fg serve-http /srv/frankengit/core \
  11111111111111111111111111111111 22222222222222222222222222222222 \
  127.0.0.1:0 --trusted-local --print-credentials-header
```

This provisioning operation authenticates the repository without opening a
listener. Its returned header includes the actual canonical incarnation. A
missing or stale catalog incarnation refuses startup; the catalog never creates
a missing repository root.

The services field is `read-only` for credentialed Git reads only, or a
comma-separated subset of `receive,issues,outcomes,pulls,source` in exactly that
order. Names cannot repeat. These are deployment ceilings, not credential
scopes. Each selected service also needs its corresponding global `--allow-*`
flag and the requesting token's existing independent grant.

| Catalog service | Required listener flag | Credential requirement |
| --- | --- | --- |
| Git clone/fetch, including `read-only` rows | No additional flag | `read` |
| `receive` | `--allow-receive` | `receive`, plus the ref-write ceiling |
| `issues` | `--allow-issues` | The specific issue operation's grant |
| `outcomes` | `--allow-outcomes` | `outcomes-read` in the original principal's namespace |
| `pulls` | `--allow-pulls` | The specific pull-request, review or merge grant |
| `source` | `--allow-source` | The existing source operation's grant |

Enabling a peer service never enables another. For example, an issues-enabled
row does not enable Git receive, and a receive-enabled row still refuses push
without `--allow-receive`. A `read-only` row remains Git-read-only even when all
five global flags are supplied.

This illustrative table must be filled with actual identities and paths:

```text
frankengit-http-repositories-v1
/engineering/core.git /srv/frankengit/core 11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 /etc/frankengit/core.credentials receive,issues,outcomes,pulls,source -
/research/models.git /srv/frankengit/models 44444444444444444444444444444444 55555555555555555555555555555555 66666666666666666666666666666666 /etc/frankengit/models.credentials read-only -
```

The route begins with `/` and has exactly two ASCII slug components. Each can
contain letters, digits, `.`, `_` and `-`, cannot be `.` or `..`, and cannot begin
with `-`. The complete route is at most 512 bytes. Case and the optional `.git`
suffix are literal. The service does not decode percent escapes, add suffixes,
look up filesystem paths from a URL, or fall back to a repository-ID alias.

The final field can require the existing
[receive LFS payload policy](RECEIVE_LFS_PAYLOAD_POLICY.md) at an absolute private
custody root. `-` disables that optional policy. It grants no LFS upload or
download endpoint and no credential scope. The root must already exist and
pass the same custody validation as the single-repository service.

Every catalog row, root, expected incarnation and credential table validates
before readiness. Canonical root aliases, parent/child storage roots, duplicate
routes and duplicate tenant/repository/incarnation triples refuse the complete
catalog. Distinct tenants can use the same repository ID. A valid first row
cannot conceal an invalid later row.

## Start the listener

```sh
fg serve-http 127.0.0.1:8080 \
  --trusted-local --repositories-file /etc/frankengit/http-repositories \
  --allow-receive --allow-issues --allow-outcomes --allow-pulls --allow-source \
  --max-in-flight 8 \
  --continuous --stop-file /run/frankengit/http.stop
```

The first example repository has URL
`http://127.0.0.1:8080/engineering/core.git`. Ordinary Git may use a credential
helper with the token as its Basic password; Bearer authentication retains its
existing behavior. Native APIs require their existing Bearer authentication.
The catalog does not alter Git object identity, upload-pack negotiation,
receive quarantine, protection checks or authority-head publication.

The listener accepts numeric loopback addresses only. `--trusted-origin` has
the same exact origin semantics as the single-repository service and applies
to every catalog entry. Forwarded identity headers do not authenticate.

Bounded mode defaults to 1,024 accepted requests, four simultaneous requests and
a 300-second idle timeout. `--max-sessions` accepts 1..1,000,000;
`--max-in-flight` accepts 1..16; `--idle-timeout-secs` accepts 1..86,400.
Continuous mode requires an initially absent stop file and refuses
`--max-sessions` or `--idle-timeout-secs`. Stop files, SIGTERM and SIGINT use the
existing [service lifetime controls](GIT_SERVICE_LIFETIME.md).

The shared `--session-timeout-secs` and `--processing-timeout-secs` bounds each
accept 1..3,600 seconds and default to 300. Receive input, expanded receive and
served pack profiles use the same flags and bounds as single-repository HTTP:

```text
--receive-max-input-mib <1..1024>
--receive-max-expanded-mib <1..65536>
--pack-max-expanded-mib <1..65536>
--pack-max-blob-mib <non-zero>
--pack-cache-mib <0..65536>
--received-pack-cache-mib <0..65536>
```

Global credential, principal and incarnation options are refused in catalog
mode because each row must bind those inputs. Global LFS, artifact,
discussion/protection/queue service options, index maintenance and workflow
controllers are also outside this catalog profile; unsupported flags refuse
before any listener opens. Existing single-repository deployments keep those
features. The global `--require-lfs-payloads` option is refused here; use each
row's final field instead.

## Discover repositories and open the browser

Open `/ui/` on the listener to use the repository home page. The public page
contains no repository names or credentials. Enter an operator bearer credential
and select **Connect** to request the readable catalog. **Disconnect** clears
the list and cancels outstanding work; a late response cannot restore it. The
page makes no automatic discovery request, stores no credential in browser
storage, and sends no ambient cookie credentials. Navigating away also cancels
the connection. Source-enabled entries link to their existing repository browser;
Git-only entries display their exact clone path.

Credential entry is enabled only on the exact `/ui/` page, with no query,
fragment or embedded URL credentials, over HTTPS or loopback HTTP. The browser
enforces its own finite request deadline and a 128 KiB decoded response limit,
including when a reverse proxy compresses the response.

Native clients can make the same read request:

```http
GET /api/v1/repositories HTTP/1.1
Host: localhost:8080
Authorization: Bearer <64-character-lowercase-hex-operator-token>
```

The endpoint accepts `GET` with no query or body. It does not accept Basic
credentials, `Expect: 100-continue`, or Git protocol negotiation. A successful
response has this shape:

```json
{
  "type": "repository_catalog",
  "schema_version": 1,
  "complete": true,
  "repositories": [
    {"path": "/team/core.git", "source_url": "/team/core.git/ui/"},
    {"path": "/team/mirror.git", "source_url": null}
  ]
}
```

Rows use sorted, unique literal paths. `source_url` is the same-origin source
browser path when that listener service is enabled, otherwise `null`. Git read
grants remain discoverable on Git-only routes. Receive-only, metadata-only and
unknown grants reveal no row. The same supplied token is independently checked
against each route's complete current credential file and exact
tenant/repository/incarnation binding; a matching principal or token on one
route never authorizes another. Canonical sponsored `fgagent_` credentials are
refused here: their authorization requires an explicit repository and remains
available through the existing repository-specific APIs.

`complete` means every configured entry was checked for this request. It is
not a canonical repository registry, a source snapshot, a global credential
epoch, or proof that a later repository request will succeed. Each credential
file owns its independently opened snapshot. Rotation applies on subsequent
authentication, and the chosen repository endpoint authenticates again. For a
single-repository listener, discovery also supports its existing literal path
when it is at most 512 bytes and consists of safe ASCII slug components; an
unsupported lookup key is refused without normalization or an alias.

The server buffers the complete authorized response before writing success.
There is no partial catalog on a broken binding, invalid later credential row,
unavailable credential file, exhausted read quota, timeout or response limit.
These failures expose no affected route, credential material or hidden-entry
count. Error responses use `type: "repository_discovery_error"`,
`schema_version: 1`, a stable `code`, and `outcome_unknown: false`:

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `authentication_required` | Missing, malformed or unrecognized operator bearer credential. |
| 403 | `read_scope_required` | The credential matched a table but has no readable route. |
| 400 | `invalid_request` | Unsupported query, body or request framing. |
| 405 | `method_not_allowed` | Only `GET` is supported. |
| 408 | `request_timeout` | The original connection deadline expired. |
| 413 | `response_too_large` | The complete response exceeds its byte envelope. |
| 429 | `rate_limited` | A selected principal exhausted that repository's read quota. |
| 503 | `catalog_unavailable` | The complete catalog could not be authenticated safely. |

Both the catalog and its static browser assets use `Cache-Control: no-store`,
`Vary: Authorization`, `nosniff`, and a strict same-origin content security
policy. API responses are capped at 128 KiB and the ingress response ceiling.
Discovery keeps the accepted connection's original deadline through credential
reads and response delivery, uses only matched repositories' read quotas, and
never opens a repository node, takes a writer slot, or changes canonical state.

## Live credentials and isolation

Each credential file uses the existing incarnation-bound
`frankengit-http-credentials-v1` or
[v2 ref-write scope](HTTP_REF_WRITE_SCOPES.md) format. It stores token digests,
principal IDs and explicit grants. The route's live file is reread for every
authentication. Atomically replacing it changes grants, principals or ref
ceilings for subsequent requests without restarting the listener. A header-only
table revokes every token. Missing or invalid replacements fail closed without
a last-good-table fallback. Already authenticated requests retain their captured
bounded grant.

Repository-specific routing selects one immutable entry before authentication. Its credential
source and node configuration stay together through dispatch. No other route's
token, writer gate, push quota or cached node can satisfy that selection. Stock
Git's attempt-scoped push URLs remain under the selected route; retry IDs do not
authorize another repository or bypass authentication.

Every captured node configuration pins the authenticated incarnation, including
on cold reopen. Replacing a repository with a new incarnation cannot silently
retarget an existing route. Storage parents, catalogs and credential files remain
operator-controlled inputs; this is not protection against a privileged host
operator replacing all authority inputs.

Catalog routes and deployment ceilings are fixed until controlled restart.
Changing a credential table does not change the route or its incarnation.

## Resource and shutdown behavior

In-flight requests share one global listener limit. Each repository retains its
own writer gate and quotas. Computed-pack, received-pack and ancestry metadata
cache budgets are divided across the route count, rounding down, so adding rows
does not multiply these retention budgets. Idle node retention is likewise
divided across routes. These limits are not a bound on total process RSS or
all database and request allocations.

Controlled shutdown drains accepted requests and closes all route pools before
the anchor node shuts down. Accepted pushes can still commit while draining.
A timeout, lost response or refused transport counter never proves non-commit;
recover with the original operation's outcome contract.

Readiness emits `smart_http_listening` with `schema_version: 1`, the numeric
bound `address`, `routing: "explicit-v1"`, the repository count,
`credential_mode: "reloadable"`, and `lifetime: "bounded" | "continuous"`.
It does not emit catalog paths, credential material or repository identity
triples. Completion emits `smart_http_drained` with accepted, completed and
refused transport counts. Those counters are not canonical transaction receipts.

## Focused verification

```sh
cargo test --locked -p fgit-cli --test http_repository_options -- --test-threads=1
cargo test --locked -p fgit-node --lib smart_http::server::discovery::tests -- --test-threads=1
node --test tests/browser/repository-discovery.test.mjs
```

The focused target includes production catalog parsing and private-file reads,
root and incarnation validation, independent service ceilings, cache-budget
division, real repository preparation and startup cleanup. Its binary tests
launch the actual `fg` executable, serve two tenants with the same repository ID
and different Git hash formats, compare authorized advertisements, refuse token
cross-use, enforce the global receive ceiling, revoke one route without affecting
the other, drain, and reopen the repositories. A later invalid credential table
refuses startup before readiness and releases previously prepared nodes.

These are native implementation and executable tests. Their presence is not a
completed verification gate or a pinned upstream Git differential qualification.
Discovery tests cover full credential-file checks, cross-tenant and incarnation
isolation, live rotation and revocation, exact root routing, complete failures,
bounded responses, read quota separation, public static shells, and browser
disconnect/deadline races. Canonical account/team lifecycle, discovering routes
outside the configured catalog, dynamic catalog reload and multi-repository
workflow/index controllers remain separate work.
