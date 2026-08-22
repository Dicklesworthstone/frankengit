#!/usr/bin/env python3
"""Independently derive the FG-077a checkpoint identity corpus.

The checked-in ``checkpoint_vectors.tsv`` is consumed by the Rust integration
test; this script is offline evidence tooling and is never invoked by an E2E
suite. It derives the documented preimage framing with Python's stdlib
``hashlib``, independent from the Rust implementation under test.

The preimage is:

    u8(len(domain_tag)) || domain_tag || u8(len(schema_family)) || schema_family
    || u16be(schema_major) || u16be(schema_minor) || u64be(body_len)
    || canonical_body

Run from this directory or any other working directory:

    python3 crates/fgit-raptorq/goldens/checkpoint_identity.py

Review the resulting TSV diff. Rust tests must only read the checked-in TSV;
regenerating vectors from Rust output would make the evidence tautological.
"""

import hashlib
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
MARKER = "# franken-registry-v1"
HEADER = "case_id\tdurable_class\tcanonical_body_hex\tcheckpoint_digest_hex"

# Domain tags are the registered DUR-012/DUR-014 identity domains. The schema
# families are the profile's published schemas. These values deliberately live
# outside Rust so a same-file framing edit cannot silently re-bless the corpus.
CASES = (
    (
        "DUR-012",
        "frankengit/forge-checkpoint/v1",
        "frankengit.forge-event-checkpoint-segment",
    ),
    (
        "DUR-014",
        "frankengit/policy-checkpoint/v1",
        "frankengit.policy-key-format-checkpoint",
    ),
)

# Include the former inline-golden body and cross the 128-byte symbol boundary.
BODIES = (
    ("one-octet", bytes([0])),
    ("legacy-text", b"frankengit fg077a checkpoint golden vector"),
    ("one-symbol", bytes(range(128))),
    ("one-symbol-plus-one", bytes(range(129))),
)

# The legacy values preserve the exact FG-077a pins, independently checking
# that an accidental oracle change is not mistaken for a production regression.
LEGACY_EXPECTED = {
    "DUR-012": "d5d8b1effa326c166ef52362e9342b312e1dfb76c83f6c0f6a148ed36a653e80",
    "DUR-014": "a616f9829ba49f34f2dee84e74fbc168f4bda6f7e7c8d9b475f118e072d27326",
}


def preimage_header(domain_tag: str, family: str, body_len: int) -> bytes:
    tag = domain_tag.encode("ascii")
    schema_family = family.encode("ascii")
    if len(tag) > 255 or len(schema_family) > 255:
        raise ValueError("registered labels must fit their u8 length prefixes")
    return (
        len(tag).to_bytes(1, "big")
        + tag
        + len(schema_family).to_bytes(1, "big")
        + schema_family
        + (1).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + body_len.to_bytes(8, "big")
    )


def checkpoint_identity(domain_tag: str, family: str, body: bytes) -> str:
    return hashlib.sha256(preimage_header(domain_tag, family, len(body)) + body).hexdigest()


def vectors() -> list[str]:
    rows = []
    for case_id, body in BODIES:
        for durable_class, domain_tag, family in CASES:
            rows.append(
                "\t".join(
                    [
                        case_id,
                        durable_class,
                        body.hex(),
                        checkpoint_identity(domain_tag, family, body),
                    ]
                )
            )
    return rows


def main() -> int:
    legacy_body = dict(BODIES)["legacy-text"]
    failures = 0
    legacy_digests = {}
    for durable_class, domain_tag, family in CASES:
        actual = checkpoint_identity(domain_tag, family, legacy_body)
        expected = LEGACY_EXPECTED[durable_class]
        if actual != expected:
            print(f"WRONG {durable_class}: expected {expected}, derived {actual}")
            failures += 1
        else:
            print(f"OK    {durable_class}: preserved FG-077a legacy pin")
        legacy_digests[durable_class] = actual

    if legacy_digests["DUR-012"] == legacy_digests["DUR-014"]:
        print("WRONG durable-class domain separation disappeared")
        failures += 1
    else:
        print("OK    DUR-012 and DUR-014 remain domain-separated")

    output = MARKER + "\n" + HEADER + "\n" + "\n".join(vectors()) + "\n"
    (HERE / "checkpoint_vectors.tsv").write_text(output, encoding="ascii")
    print("wrote 8 vectors across body lengths 1, 42, 128, and 129")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
