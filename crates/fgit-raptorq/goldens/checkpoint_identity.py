#!/usr/bin/env python3
"""Independent oracle for the checkpoint_segment_v1 identity preimage.

FG-077a. The Rust round-trip and corpus tests prove BEHAVIOUR: encode, lose
symbols, decode, refuse hostile input. None of them pin the wire framing, so a
change applied consistently to both the encode and the decode side would pass
every one of them while silently minting different identities for the same
bytes. That is the same round-trip-is-not-a-golden gap recorded against
fg020's ObjectEnvelope.

This script recomputes the DUR-012 and DUR-014 checkpoint identities from the
SPEC rather than from the implementation, so the pinned constants in
`checkpoint.rs` are checked against a second derivation instead of against
themselves. `Sha256Hasher` is a hand-written FIPS 180-4 SHA-256 in
`fgit-crypto/src/hashing.rs`; `hashlib.sha256` is therefore an independent
implementation of the same function, not the same code called twice.

Framing, from fgit-crypto::internal_id_preimage_header:

    u8(len(domain_tag))    || domain_tag
    u8(len(schema_family)) || schema_family
    u16be(schema_major)    || u16be(schema_minor)
    u64be(body_len)
    || canonical_body

If this disagrees with the Rust constants, ONE OF THEM IS WRONG AND IT MAY WELL
BE THIS FILE. When seal.py disagreed with fgit-crypto during FG-057, the oracle
was the side at fault. Diagnose before changing either, and never edit the
implementation merely to match a script.

Run:  python3 crates/fgit-raptorq/goldens/checkpoint_identity.py
"""

import hashlib

# The exact literal pinned in checkpoint.rs. Kept short and printable so a
# reviewer can retype it.
BODY = b"frankengit fg077a checkpoint golden vector"

# Domain tags come from the fgit-crypto identity registry rows that already
# bind these two domains to their durable classes; the schema families are
# declared in checkpoint.rs.
CASES = (
    (
        "DUR-012",
        "ForgeEvent",
        "frankengit/forge-checkpoint/v1",
        "frankengit.forge-event-checkpoint-segment",
        "d5d8b1effa326c166ef52362e9342b312e1dfb76c83f6c0f6a148ed36a653e80",
    ),
    (
        "DUR-014",
        "PolicyKey",
        "frankengit/policy-checkpoint/v1",
        "frankengit.policy-key-format-checkpoint",
        "a616f9829ba49f34f2dee84e74fbc168f4bda6f7e7c8d9b475f118e072d27326",
    ),
)


def preimage_header(domain_tag: str, family: str, major: int, minor: int, body_len: int) -> bytes:
    tag = domain_tag.encode("ascii")
    fam = family.encode("ascii")
    if len(tag) > 255 or len(fam) > 255:
        raise ValueError("a registered label must fit its length prefix")
    out = bytearray()
    out.append(len(tag))
    out += tag
    out.append(len(fam))
    out += fam
    out += major.to_bytes(2, "big")
    out += minor.to_bytes(2, "big")
    out += body_len.to_bytes(8, "big")
    return bytes(out)


def checkpoint_identity(domain_tag: str, family: str, body: bytes) -> str:
    header = preimage_header(domain_tag, family, 1, 0, len(body))
    return hashlib.sha256(header + body).hexdigest()


def main() -> int:
    wrong = 0
    seen = {}
    for durable, cls, tag, family, expected in CASES:
        actual = checkpoint_identity(tag, family, BODY)
        ok = actual == expected
        wrong += not ok
        print(f"  {'OK   ' if ok else 'WRONG'}  {durable} {cls:11s} {actual}")
        if not ok:
            print(f"         pinned in checkpoint.rs: {expected}")
        seen[durable] = actual

    # Domain separation is the property the two rows exist for. Asserting the
    # digests merely match their pins would not catch a change that moved BOTH
    # classes onto one domain.
    if seen["DUR-012"] == seen["DUR-014"]:
        print("  WRONG  the two classes share an identity; domain separation is gone")
        wrong += 1
    else:
        print("  OK     the two classes have distinct identities for identical bytes")

    print(f"\n{len(CASES) + 1 - wrong}/{len(CASES) + 1} checks passed")
    return 1 if wrong else 0


if __name__ == "__main__":
    raise SystemExit(main())
