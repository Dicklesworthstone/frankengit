# fgit-deflate

`fgit-deflate` is FrankenGit's owned, safe-Rust zlib/DEFLATE decoder. It
implements RFC 1950 framing (including Adler-32) and RFC 1951 stored, fixed,
and dynamic-Huffman blocks without invoking or linking a native compression
library.

The public decoder is streaming: `Inflater::push` may make output available
after each supplied compressed chunk, while `Inflater::finish` authenticates
the zlib Adler-32 trailer. Output obtained before a successful `finish` is
tentative and callers must discard it after any refusal. `inflate_zlib` is the
one-shot convenience API and returns bytes only after the trailer verifies.

The exact typed refusal vocabulary is `InflateRefusal`:

- `ResourceLimit` for input, output, ratio, work, nesting/window, table, and
  allocation budgets;
- `Cancelled` for caller-provided cancellation checks;
- `InvalidZlibHeader`, `PresetDictionaryUnsupported`, and `Adler32Mismatch`;
- `UnexpectedEnd`, `TrailingGarbage`, and `StoredLengthMismatch`;
- `ReservedBlockType`, `InvalidBlockType`, `InvalidHuffmanCode`,
  `IncompleteHuffmanSet`, `OversubscribedHuffmanSet`,
  `InvalidCodeLength`, and `InvalidLengthOrDistanceCode`;
- `DistanceTooFar` and `InvalidUtf8` is intentionally absent because DEFLATE
  is byte-oriented.

These refusals are deterministic and never silently truncate output. The
crate deliberately does not yet expose an encoder: deterministic DEFLATE
emission is a later extension of this exact crate, not a hidden system-zlib
fallback.
