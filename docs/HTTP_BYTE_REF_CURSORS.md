# Lossless HTTP reference pagination

The source ref inventory supports an explicit `cursor_encoding=hex` form field.
Use it on the first request and every continuation to paginate arbitrary valid
Git reference bytes without converting them to UTF-8. It works for `namespace=all`,
`branches` and `tags`; it does not change which refs are visible.

```text
POST {REPO_URL}/api/v1/source/refs
Content-Type: application/x-www-form-urlencoded

object_format=sha256&namespace=branches&limit=50&cursor_encoding=hex
```

In this mode the response includes `cursor_encoding:"hex"`, and its `after` and
`next_after` strings encode exact reference bytes as lowercase hex. Null
`next_after` means the visible namespace has no more rows. Supply the returned
string unchanged as `after`, retain `cursor_encoding=hex`, and send the original
`snapshot_token` as `expected_head`. The token still pins the exact current
authority head. Any authority change refuses continuation instead of mixing pages.
Reference rows themselves keep their existing `ref` (UTF-8 or null), authoritative
`ref_hex`, and native `object_id` fields.

Default requests and explicit `cursor_encoding=utf8` keep the existing text
cursor behavior and response bytes. In that legacy mode a needed non-UTF-8 cursor
still refuses the page instead of falsely reporting completion. Hex mode is
opt-in, so existing clients never accidentally interpret encoded bytes as a ref.
To traverse a byte-named inventory, begin a new hex-mode traversal rather than
reinterpreting an existing text cursor.

The encoding selector accepts only `utf8` and `hex`. Hex cursors must be nonempty,
even-length, lowercase, at most 8192 characters, and decode to a valid full ref
inside the selected namespace. A supplied cursor still requires `expected_head`.
Unknown/duplicate form fields, malformed native ref bytes and missing/stale pins
refuse; there is no replacement-character conversion, implicit latest-head retry,
new read permission, retention lease or historical snapshot service.

The existing read credential, source-read quota, 256 KiB form, six-field form
ceiling, 100-row page ceiling, complete response bound and canonical hidden-ref
policy remain unchanged. These are refusal bounds, not whole-operation resource
or latency guarantees.

`byte_ref_http` integration tests run actual TCP listeners and native file-backed
nodes in both Git hash domains. They cover all byte-sorted refs exactly once,
fixed/chunked forms, restart, malformed and missing cursors, stale authority,
complete terminal pages and byte-identical default UTF-8 responses. Native cursor
unit tests exercise exact-byte round trips and bounded closed grammar. These
focused tests do not establish a release gate or arbitrary-scale performance.
