#!/usr/bin/env python3
import argparse
from pathlib import Path
import tempfile
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, fixture, document, require
from full_bundle_smoke import invoke, decode_export


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-incremental-bundle-") as directory:
        root = Path(directory)
        raw_source, source, target = root / "raw", root / "source", root / "target"
        f = fixture(raw_source, algorithm)
        invoke(binary, ["init", source, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", source, TENANT, REPOSITORY, PRINCIPAL, "source-fixture", raw_source])
        for ref in ("main", "topic"):
            (raw_source / "refs/heads" / ref).write_text(f["base"] + "\n", encoding="ascii")
        def seed(path):
            invoke(binary, ["init", path, TENANT, REPOSITORY, algorithm])
            invoke(binary, ["import", path, TENANT, REPOSITORY, PRINCIPAL, "base-fixture", raw_source])
        def refs(path):
            return document(invoke(binary, ["branch", "list", path, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm]))
        def args(op, path, bundle, *extra):
            return ["bundle", op, path, TENANT, REPOSITORY, bundle, "--trusted-local", "--object-format", algorithm, *extra]
        def upload(path, bundle, main=None, topic=None):
            return args("sync-import", path, bundle, "--principal", PRINCIPAL, "--key-stdin", "--allow-ref-updates",
                        "--expect", "refs/heads/main=" + (main or f["base"]), "--expect", "refs/heads/topic=" + (topic or f["base"]))
        seed(target)
        before_source, before_target = refs(source), refs(target)
        output = root / "increment.bundle"
        command = args("sync-export", source, output, "--ref", "refs/heads/main", "--ref", "refs/heads/topic", "--prerequisite", f["base"])
        exported = document(invoke(binary, command))
        require(exported["type"] == "git_bundle_incremental_export" and exported["object_count"] == 2, "incremental export must omit all base objects")
        require(exported["reference_count"] == 2 and exported["prerequisite_count"] == 1 and not exported["repository_changed"], "export scope")
        raw = output.read_bytes()
        header, pack = raw.split(b"\n\n", 1)
        lines = header.split(b"\n")
        prerequisites = [line[1:].split(b" ", 1)[0].decode("ascii") for line in lines if line.startswith(b"-")]
        require(prerequisites == [f["base"]], "declared prerequisite identity")
        plain_header = b"\n".join(line for line in lines if not line.startswith(b"-"))
        advertised, objects = decode_export(plain_header + b"\n\n" + pack, algorithm)
        require(set(objects) == {f["target"], f["source"]}, "exact incremental pack inventory")
        require(advertised == {b"refs/heads/main": f["target"], b"refs/heads/topic": f["source"]}, "exact named ref set")
        invoke(binary, command, code=2)
        require(output.read_bytes() == raw and refs(source) == before_source, "create-only export and unchanged source")
        missing_consent = upload(target, output)
        missing_consent.remove("--allow-ref-updates")
        invoke(binary, missing_consent, code=2, data=b"no-consent")
        require(refs(target) == before_target, "missing consent changed authority")
        key = b"byte-exact-incremental-key\n"
        report = document(invoke(binary, upload(target, output), data=key))
        require(report["type"] == "git_bundle_import" and report["atomic"] and report["command_committed"], "one atomic ref update")
        require(report["reference_count"] == 2 and report["node_closed"] and report["cleanup_error"] is None, "complete receipt")
        require(key.strip().decode() not in str(report), "key must not be printed")
        settled = refs(target)
        require(settled["branches"] == before_source["branches"], "two exact destination updates")
        require(document(invoke(binary, upload(target, output), data=key)) == report, "identical terminal replay")
        require(refs(target) == settled, "replay advanced head")
        collision = document(invoke(binary, upload(target, output), code=3, data=b"fresh-stale-leases"))
        require(not collision["command_committed"] and collision["refusal_record_id"] is not None, "stale expectations refuse canonically")
        require(refs(target)["branches"] == settled["branches"], "stale lease moved refs")
        require(document(invoke(binary, upload(target, output), code=3, data=b"fresh-stale-leases")) == collision, "refusal replay")
        known = refs(target)
        invoke(binary, upload(target, output, main=f["target"]), code=2, data=key)
        require(refs(target) == known, "same key with changed expected-old rewrote authority")
        full = root / "roundtrip.bundle"
        document(invoke(binary, args("export", target, full)))
        _, restored = decode_export(full.read_bytes(), algorithm)
        require(set(restored) == {f[k] for k in ("base", "tree", "blob", "target", "source")}, "roundtrip complete history")
        empty = root / "empty"
        invoke(binary, ["init", empty, TENANT, REPOSITORY, algorithm])
        before = refs(empty)
        invoke(binary, upload(empty, output, main="absent", topic="absent"), code=2, data=b"missing-prerequisite")
        require(refs(empty) == before, "missing prerequisites published history")
        fresh = root / "fresh"
        seed(fresh)
        stable = refs(fresh)
        bad = root / "corrupt.bundle"
        bad.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        invoke(binary, upload(fresh, bad), code=2, data=b"corrupt-pack")
        wrong = root / "wrong-prerequisite.bundle"
        wrong.write_bytes(raw.replace(("-" + f["base"] + " ").encode(), ("-" + f["blob"] + " ").encode(), 1))
        invoke(binary, upload(fresh, wrong), code=2, data=b"blob-prerequisite")
        require(refs(fresh) == stable, "invalid prerequisite or checksum changed authority")
        protection = ["protection", "set", fresh, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm,
                      "--principal", PRINCIPAL, "--idempotency-key", "protect-main", "--expected-version", "0", "--expected-epoch", "1",
                      "--admin", PRINCIPAL, "--require-reviewer", "refs/heads/main:" + "e4" * 16]
        # `fg protection set` receipts name the decision `committed` (the
        # branch and bundle receipts use `command_committed`).
        require(document(invoke(binary, protection))["committed"] is True, "protection activation")
        protected = refs(fresh)
        result = document(invoke(binary, upload(fresh, output), code=3, data=b"protected-sync"))
        require(result["refusal_code"] == "ProtectedRefTransitionDenied", "incremental transfer bypassed required review")
        require(refs(fresh)["branches"] == protected["branches"], "atomic protected refusal moved unprotected companion ref")
        print(f"INCREMENTAL_BUNDLE_CLI format={algorithm} reduced_pack=2 explicit_leases=checked replay=checked prerequisites=checked atomic_protection=checked")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True, type=Path)
    args = parser.parse_args()
    for algorithm in ("sha1", "sha256"):
        run_format(args.fg.resolve(), algorithm)


if __name__ == "__main__":
    main()
