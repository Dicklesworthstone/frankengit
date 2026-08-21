# Upload-pack packet transcripts

`oracle-v0-depth-request.pkt` and `oracle-v2-ls-refs-request.pkt` are exact
raw requests captured from the pinned Git 2.54.0 oracle used by the independent
audit. The final container-only LF after their `0000` flush is stripped by the
test helper; it is not part of the captured pkt-line stream. These two fixtures
prove the mixed LF rule: request capabilities and controls may be LF-free while
advertisement records remain LF-terminated.

The smaller `v1-*` and `v2-*` fixtures remain constructed state-machine cases:
their role is bounded transition coverage only, not an upstream-conformance
claim. The `111...` identity is an advertised want and the `222...` identity is
a common have in that synthetic repository.

Fixtures that end in a `0000` control marker retain the customary final
text-file LF after that marker. Tests strip only that container-only LF before
presenting bytes to the pkt-line decoder. `v1-fetch-request.pkt` instead ends
at the LF belonging to its final `done` data packet, which is protocol data.

- `v1-advertisement.pkt` is a v0/v1 ref advertisement followed by a flush.
- `v1-fetch-request.pkt` has a `want` with `multi_ack_detailed` and
  `side-band-64k`, then flush, common `have`, and `done`.
- `v2-ls-refs.pkt` is a constructed `ls-refs` command request with a ref prefix.
- `v2-fetch.pkt` is a constructed `fetch` command request with an advertised
  client capability, want/have negotiation, shallow/deepen and filter syntax,
  `done`, and flush.
