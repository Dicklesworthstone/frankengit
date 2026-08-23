#!/usr/bin/env python3
"""Generates the Evidence-Carrying Change golden corpus.

This is a second implementation. It reads two documented layouts and links
nothing:

  * the frame, from the table at the top of `crates/fgit-codec/src/wire.rs`;
  * the ECC payload, from the table on `impl CanonicalBody for
    EvidenceCarryingChange` in `crates/fgit-agent/src/ecc.rs`.

It must never import, link, or shell out to any Rust crate, and it must never
be wired into cargo. Nothing in the Rust tests invokes it; the suite only ever
reads the committed `.golden` files.

Run from the repository root:

    python3 crates/fgit-agent/tests/goldens/generate.py
"""

import os

# ---- frame constants, from wire.rs ---------------------------------------
MAGIC = b"FGC1"
CODEC_MAJOR = 1
CODEC_MINOR = 0
DOMAIN = b"frankengit/evidence-carrying-change/v1"
SCHEMA_FAMILY = b"evidence-carrying-change"
SCHEMA_MAJOR = 1
SCHEMA_MINOR = 0

# ---- code points, from ecc.rs -------------------------------------------
OBSERVED, EXECUTED, INFERRED, STATISTICAL, OMITTED, UNRESOLVED = 1, 2, 3, 4, 5, 6
SATISFIED, PARTIAL, NOT_APPLICABLE, BLOCKED, UNSATISFIED = 1, 2, 3, 4, 5
# refresh relations, from refresh.rs
FAST_FORWARDED, REBASED_REPLAY, REBASED_PATCH, MERGED_PROOF, CONFLICT_REFUSED = 1, 2, 3, 4, 5
BEFORE_REFRESH, AFTER_REFRESH = 1, 2


def u16(value):
    return value.to_bytes(2, "big")


def u32(value):
    return value.to_bytes(4, "big")


def ident(value):
    """A 16-byte opaque id. OPAQUE_ID_LEN is 16, the width of a u128."""
    return value.to_bytes(16, "big")


def length_prefixed(raw):
    return u32(len(raw)) + raw


def sequence(items):
    return u32(len(items)) + b"".join(items)


def option(inner):
    return b"\x00" if inner is None else b"\x01" + inner


def party_facts(base, unreported=()):
    """Seven OPTIONAL identities in IndependenceDimension::ALL order.

    Each is an option tag: 0x00 unreported, or 0x01 followed by 16 bytes.
    `unreported` is a set of 0-based dimension indices left unstated.
    """
    return b"".join(
        option(None if offset in unreported else ident(base + offset))
        for offset in range(7)
    )


def refresh_receipt(relation, from_base, to_base):
    """u16 relation code point, then two 16-byte bases."""
    return u16(relation) + ident(from_base) + ident(to_base)


def payload(intent_run, producer_base, evidence, dispositions, non_claims, verifiers,
            producer_unreported=(), refreshed=None):
    out = ident(intent_run)
    out += party_facts(producer_base, producer_unreported)
    out += sequence([
        u16(record[0]) + ident(record[1])
        + option(None if len(record) < 3 or record[2] is None else u16(record[2]))
        for record in evidence
    ])
    out += sequence(
        [option(None if code is None else u16(code)) for code in dispositions]
    )
    out += sequence([ident(value) for value in non_claims])
    out += sequence(
        [ident(verifier) + party_facts(base, unreported) + (b"\x01" if upheld else b"\x00")
         for verifier, base, upheld, unreported in verifiers]
    )
    out += option(refreshed)
    return out


def frame(body, codec_major=CODEC_MAJOR, domain=DOMAIN, schema_major=SCHEMA_MAJOR):
    return (
        MAGIC
        + u16(codec_major)
        + u16(CODEC_MINOR)
        + length_prefixed(domain)
        + length_prefixed(SCHEMA_FAMILY)
        + u16(schema_major)
        + u16(SCHEMA_MINOR)
        + length_prefixed(body)
    )


# ---- the vectors ---------------------------------------------------------
MINIMAL = payload(
    intent_run=0x01,
    producer_base=0x10,
    evidence=[],
    dispositions=[],
    non_claims=[],
    verifiers=[],
)

# One evidence record per class, a requirement whose disposition is absent
# (the case §10.2 forbids from disappearing), two non-claims, and two
# verifiers: the first shares nothing, the second shares the producer's
# workspace exactly (base 0x10, so its dimension 0 identity collides).
POPULATED = payload(
    intent_run=0x0A1B2C3D,
    producer_base=0x10,
    evidence=[
        (OBSERVED, 0xA1),
        (EXECUTED, 0xA2),
        (INFERRED, 0xA3),
        (STATISTICAL, 0xA4),
        (OMITTED, 0xA5),
        (UNRESOLVED, 0xA6),
    ],
    dispositions=[SATISFIED, None, PARTIAL, NOT_APPLICABLE, BLOCKED, UNSATISFIED],
    non_claims=[0xC1, 0xC2],
    verifiers=[(0x99, 0x20, True, ()), (0x98, 0x10, False, ())],
)

# The mixed case the bare-u128 encoding could not express at all: the producer
# never reported its oracle or sponsor, and the verifier never reported its
# human oversight. Every unreported dimension must decode back as unreported --
# a decoder that recovered an identity here would manufacture independence.
UNREPORTED = payload(
    intent_run=0x55,
    producer_base=0x10,
    evidence=[(EXECUTED, 0xB1)],
    dispositions=[SATISFIED],
    non_claims=[],
    verifiers=[(0x97, 0x20, True, {6})],
    producer_unreported={4, 5},
)

# A refreshed bundle: the basis MOVED, so the same class appears twice --
# once checked before the refresh and once after. A decoder that lost the side,
# or that read an unstated side as "after", would let the stale record vouch
# for the new base.
REFRESHED = payload(
    intent_run=0x77,
    producer_base=0x10,
    evidence=[
        (EXECUTED, 0xD1, BEFORE_REFRESH),
        (EXECUTED, 0xD2, AFTER_REFRESH),
        (OBSERVED, 0xD3, None),
    ],
    dispositions=[SATISFIED],
    non_claims=[],
    verifiers=[(0x96, 0x20, True, ())],
    refreshed=refresh_receipt(REBASED_REPLAY, 0xBA5E, 0xBA5F),
)

CASES = []


def case(name, description, body, kind="valid", expect=None, **frame_kwargs):
    CASES.append((name, description, frame(body, **frame_kwargs), body, kind, expect))


case(
    "ecc__minimal",
    "An ECC carrying no evidence, no requirements, and no verifiers.\n"
    "Every sequence is empty, so the payload is the identities plus five zero counts.",
    MINIMAL,
)
case(
    "ecc__populated",
    "One evidence record per class, a requirement with NO disposition,\n"
    "two non-claims, and two verifiers -- the second sharing the producer's workspace.",
    POPULATED,
)

case(
    "ecc__unreported_dimensions",
    "The producer leaves oracle and sponsor unreported and the verifier leaves human\n"
    "unreported. These must decode back as unreported, never as recovered identities.",
    UNREPORTED,
)

case(
    "ecc__refreshed",
    "A refresh receipt (RebasedByIntentReplay, basis 0xba5e -> 0xba5f) with one evidence\n"
    "record checked BEFORE the refresh, one AFTER, and one that does not state its side.",
    REFRESHED,
)

# Planted defects. Each must produce a typed refusal, never a decode.
case(
    "ecc__populated__unknown_evidence_class",
    "The first evidence record carries class code point 0x00ff, which no build defines.\n"
    "A decoder that mapped it to a default would silently reclassify evidence.",
    POPULATED.replace(u16(OBSERVED) + ident(0xA1), u16(0x00FF) + ident(0xA1), 1),
    kind="defect",
    expect="VariantUnknown",
)
case(
    "ecc__populated__unknown_disposition",
    "A requirement disposition carries code point 0x00fe, which no build defines.",
    POPULATED.replace(b"\x01" + u16(BLOCKED), b"\x01" + u16(0x00FE), 1),
    kind="defect",
    expect="VariantUnknown",
)
case(
    "ecc__populated__option_tag_invalid",
    "The absent disposition's option tag is 0x02 rather than 0x00 or 0x01.",
    POPULATED.replace(u16(SATISFIED) + b"\x00" + b"\x01" + u16(PARTIAL),
                      u16(SATISFIED) + b"\x02" + b"\x01" + u16(PARTIAL), 1),
    kind="defect",
    expect="OptionTagInvalid",
)
case(
    "ecc__refreshed__unknown_relation",
    "The refresh receipt names relation code point 0x00fd, which no build defines.",
    REFRESHED.replace(u16(REBASED_REPLAY) + ident(0xBA5E), u16(0x00FD) + ident(0xBA5E), 1),
    kind="defect",
    expect="VariantUnknown",
)
case(
    "ecc__refreshed__unknown_refresh_side",
    "An evidence record claims refresh side 0x00fc, which no build defines.",
    REFRESHED.replace(b"\x01" + u16(BEFORE_REFRESH), b"\x01" + u16(0x00FC), 1),
    kind="defect",
    expect="VariantUnknown",
)
case(
    "ecc__populated__trailing_byte_appended",
    "One extra byte after a complete payload. A canonical body has exactly one\n"
    "byte string, so a trailing byte is refused rather than ignored.",
    POPULATED + b"\x00",
    kind="defect",
    expect="TrailingBytes",
)
case(
    "ecc__populated__payload_truncated",
    "The final verifier's upheld byte is missing.",
    POPULATED[:-1],
    kind="defect",
    expect="InputTruncated",
)
case(
    "ecc__populated__domain_swapped",
    "A correct payload framed under another body's domain tag. Domain separation\n"
    "must refuse it even though the payload bytes themselves are well formed.",
    POPULATED,
    kind="defect",
    expect="DomainUnexpected",
    domain=b"frankengit/refusal-record/v1",
)
case(
    "ecc__populated__codec_major_bumped",
    "Codec major 2. A future major may reorder fields, so a decoder that guessed\n"
    "would be confidently wrong.",
    POPULATED,
    kind="defect",
    expect="CodecMajorUnsupported",
    codec_major=2,
)
case(
    "ecc__populated__schema_major_bumped",
    "Schema major 2, refused for the same reason at body level.",
    POPULATED,
    kind="defect",
    expect="SchemaMajorUnsupported",
    schema_major=2,
)

HEADER = """# frankengit-ecc-golden v1
{description}
# Bytes derived from the written layout tables by a separate implementation,
# not emitted by the encoder under test. See README.md for the exact limits
# of that independence.
schema = evidence-carrying-change
kind = {kind}
"""


def main():
    directory = os.path.dirname(os.path.abspath(__file__))
    for name, description, frame_bytes, body, kind, expect in CASES:
        text = HEADER.format(
            description="\n".join("# " + line for line in description.split("\n")),
            kind=kind,
        )
        if expect is not None:
            text += f"expect = {expect}\n"
        text += f"frame_len = {len(frame_bytes)}\n"
        text += f"canonical_body_len = {len(body)}\n"
        text += f"bytes = {frame_bytes.hex()}\n"
        path = os.path.join(directory, name + ".golden")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"{name}: frame {len(frame_bytes)} bytes, payload {len(body)}")


if __name__ == "__main__":
    main()
