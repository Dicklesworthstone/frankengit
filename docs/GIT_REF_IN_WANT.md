# Fetch exact refs with Git protocol v2

FrankenGit's authenticated upload-pack views can advertise `ref-in-want` as
part of the protocol-v2 `fetch` capability. A client may then request an exact
visible ref name with `want-ref`, alongside or instead of ordinary object-ID
wants. This lets fetch select the ref at the serving request's own snapshot,
rather than relying on an object ID observed by an earlier `ls-refs` request.

This extension is disabled by default, matching Git's default
`uploadpack.allowRefInWant` setting. Enable it with `--enable-ref-in-want` on
`fg serve`, `fg serve-ssh` or `fg serve-http`, or with
`NodeConfig::with_upload_pack_ref_in_want(true)` in an embedding. The selection
is inherited by reopened service children and applies to catalog repositories.
It requires the same current authorized view; a cached graph does not enable
the feature. A `want-ref` request without the advertised extension is refused,
while an ordinary permitted object-ID want remains supported.

## Selection and response

The shared Rust wire machine resolves each name exclusively within the
request's authenticated advertised-ref view. Names are exact raw bytes: `HEAD`
works when its target exists and is visible, while `main` does not expand to
`refs/heads/main`. Annotated tags retain their own tag-object identity. Ref
aliases may share an object; pack selection includes that object once while
the response reports every distinct requested name.

A successful response that contains a pack also contains a `wanted-refs`
section with exactly the requested names and their selected native object IDs.
Rows retain request order. Section order is acknowledgments, shallow-info,
wanted-refs, then packfile, with each applicable section separated by a Git
delimiter. A `done` request omits acknowledgments. A negotiation-only response
contains no wanted-ref rows and no pack. Each stateless HTTP round resolves
its own immutable authorized view; it does not reuse mutable connection state
from an earlier HTTP request.

Both SHA-1 and SHA-256 repositories use their native object-ID widths. The
same wire implementation serves raw Git, the shared SSH Git command path,
and smart HTTP. `supports_ref_in_want` is an explicit provider contract;
parser support or arbitrary physical object presence cannot enable the
advertisement.

## Bounds and refusal behavior

- `max_wants` jointly counts distinct explicit OID selectors and requested ref
  names. Different names count separately even if they resolve to one OID.
  Repeated explicit OID wants remain idempotent; repeating a `want-ref` name
  is a typed duplicate error, as in the pinned Git implementation.
- Every name obeys `max_ref_name_bytes` and Git's strict ref-name grammar.
  Wanted-ref rows also obey packet-size and aggregate response-byte limits.
  The complete future receipt is charged before retaining a name, and final
  output charges acknowledgments, shallow data and the packfile prefix too.
- A bounded private offset index is built once over the advertised names.
  Name resolution then uses binary search; it neither scans all advertised
  refs for each request nor clones the entire advertised-name collection.
  `max_advertised_refs` bounds index construction, and ambiguous duplicate
  names or mixed object formats refuse.
- Hidden and absent names both return `UnknownWantedRef`; error rendering
  reflects only the already validated name supplied by the client. A broad
  custom ref resolver cannot bypass the advertised-ref disclosure boundary.
- Live request checkpoints cover lookup, unknown and duplicate names, snapshot
  revalidation, and response assembly. Refusal or cancellation releases no
  partial wanted-ref response or pack request. A substituted view with a
  different selected name/OID pair refuses instead of mixing snapshots.

All existing object-closure, filtering, shallow-history, pack construction and
transport limits continue to govern the resulting OID selection. The receipt
is a snapshot-bound name-to-OID answer, not an independent authority-head
inclusion proof or a promise that the ref will remain unchanged later.

## Sources and validation boundary

The source contract is Git's [protocol-v2 fetch specification at
v2.54.0](https://github.com/git/git/blob/v2.54.0/Documentation/gitprotocol-v2.adoc),
including its `wanted-refs` framing, and the [pinned client
parser](https://github.com/git/git/blob/v2.54.0/fetch-pack.c).
Duplicate-name refusal follows `parse_want_ref` in the [pinned upload-pack
implementation](https://github.com/git/git/blob/v2.54.0/upload-pack.c).
The specification and client parser place shallow-info before wanted-refs;
FrankenGit follows that interoperable order even though that pinned server's
send function calls them in the opposite order.

`crates/fgit-wire/tests/ref_in_want.rs` exercises both native hash domains,
byte-fragmented requests, exact selectors and aliases, hidden/absent twins,
response order, resource boundaries, cancellation, replaced snapshots,
stateless negotiation, and complete HTTP-body admission. Native node tests
exercise authenticated serving and scoped errors. Source-derived cases and
SANS-I/O/adapter tests are distinct from executing a pinned stock-client
campaign; execution results must be reported at their actual tested revision.
