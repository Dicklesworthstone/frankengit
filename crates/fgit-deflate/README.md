# fgit-deflate

`fgit-deflate` is FrankenGit's owned, safe-Rust zlib/DEFLATE decoder. It is
the D4 inflater slice selected for loose-object and pack quarantine: RFC 1950
framing (including Adler-32) plus RFC 1951 stored, fixed-Huffman, and
dynamic-Huffman blocks, with no native compression library, FFI, subprocess,
or dependency edge.

The public decoder is streaming: `Inflater::push` may make output available
after each supplied compressed chunk, while `Inflater::finish` authenticates
the zlib Adler-32 trailer. Output obtained before a successful `finish` is
tentative and callers must discard it after any refusal. `inflate_zlib` is the
one-shot convenience API and returns bytes only after the trailer verifies.

## Admission and resource boundary

An `Inflater` accepts exactly one zlib member. It checks the advertised window
before allocating it; bounds retained input before copying it; bounds Huffman
tables and dynamic code-length collections before construction; and reserves
output before emitting a literal or match. Every profile must set a nonzero
ratio ceiling as well as input, pending-input, output, window, collection,
table, and deterministic work ceilings. `InflateLimits::GIT_OBJECT` is the
conservative object/pack-admission profile. Concatenated members and any bytes
after the Adler-32 trailer are a refusal, not a hidden multi-member mode.

The decoder has no ambient runtime, clock, or I/O authority. A caller supplies
deadline cancellation through `CancellationProbe`; `push_with_control` checks
that control between bounded decoding steps and returns `Cancelled`. This
crate neither commits decoded bytes nor decides an object's identity: callers
keep the stream in quarantine and verify the enclosing Git commitments.

## Exact refusal vocabulary

`InflateRefusal` is the entire non-success vocabulary:

- `ResourceLimit` for invalid limits and for input, retained input, output,
  expansion-ratio, window, Huffman-symbol, dynamic-collection, work, or
  allocation budgets;
- `Cancelled` for caller-provided cancellation checks;
- `InvalidZlibHeader`, `PresetDictionaryUnsupported`, and `Adler32Mismatch`;
- `UnexpectedEnd`, `TrailingGarbage`, and `StoredLengthMismatch`;
- `ReservedBlockType`, `InvalidHuffmanCode`, `IncompleteHuffmanSet`, and
  `OversubscribedHuffmanSet` for malformed DEFLATE coding structure;
- `InvalidCodeLength`, `InvalidLengthOrDistanceCode`, and `DistanceTooFar`.

These refusals are deterministic and never silently truncate output. The
crate deliberately does not yet expose an encoder: deterministic DEFLATE
emission is a later extension of this exact crate, not a hidden system-zlib
fallback. The checked-in fixtures are offline reference inputs for this
decoder, not encoder goldens or differential evidence.
