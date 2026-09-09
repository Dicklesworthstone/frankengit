#!/usr/bin/env python3
"""Real fg source-review campaign. --self-test validates fixtures/checker only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zlib

TENANT, REPO, PRINCIPAL = "e1" * 16, "e2" * 16, "e3" * 16
TARGET, SOURCE = "refs/heads/main", "refs/heads/topic"
BASE = {b"binary": (0o100644, b"\0old"), b"delete": (0o100644, b"deleted\n"),
        b"keep": (0o100644, b"keep\n"), b"mode": (0o100644, b"run\n"),
        b"src/text": (0o100644, b"one\r\ntwo\r\nthree"),
        b"target-only": (0o100644, b"original\n"),
        b"type": (0o100644, b"was a file\n"), b"type.ext": (0o100644, b"unmoved\n")}
OURS = dict(BASE)
OURS[b"target-only"] = (0o100644, b"target change\n")
THEIRS = dict(BASE)
THEIRS.update({b"binary": (0o100644, b"\0new"), b"empty": (0o100644, b""),
               b"mode": (0o100755, b"run\n"), b"link": (0o120000, b"src/text"),
               b"src/text": (0o100644, b"one\r\nchanged\r\nthree\n"),
               b"invalid-\xff": (0o100644, b"\xff\ntext"),
               b"control": (0o100644, b"x\x1b[2Jy\n")})
del THEIRS[b"delete"]
del THEIRS[b"type"]
THEIRS[b"type/child"] = (0o100644, b"now a directory\n")


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def oid(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def build_tree(files, algorithm, store):
    hierarchy, entries = {}, {}
    for path, (mode, body) in files.items():
        parts = path.split(b"/")
        parent = hierarchy
        for name in parts[:-1]:
            parent = parent.setdefault(name, {})
        parent[parts[-1]] = (mode, body)
    def walk(directory, prefix=b""):
        records = []
        for name, value in directory.items():
            path = prefix + name
            if isinstance(value, dict):
                mode, identity, body = 0o40000, walk(value, path + b"/"), None
            else:
                mode, body = value
                identity = store("blob", body)
            entries[path] = {"oid": identity, "mode": f"{mode:06o}", "body": body}
            records.append((name, mode, identity))
        records.sort(key=lambda row: row[0] + (b"/" if row[1] == 0o40000 else b"\0"))
        body = b"".join(f"{mode:o} ".encode() + name + b"\0" + bytes.fromhex(identity)
                        for name, mode, identity in records)
        return store("tree", body)
    return walk(hierarchy), entries


def fixture(root, algorithm):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
                                ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"))
    def store(kind, body):
        identity = oid(algorithm, kind, body)
        path = root / "objects" / identity[:2] / identity[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return identity
    def commit(tree, parents, label):
        body = f"tree {tree}\n" + "".join(f"parent {parent}\n" for parent in parents)
        body += f"author Fixture <f@example.invalid> 1 +0000\ncommitter Fixture <f@example.invalid> 1 +0000\n\n{label}\n"
        return store("commit", body.encode())
    values = {}
    for label, files in [("base", BASE), ("ours", OURS), ("theirs", THEIRS)]:
        tree, entries = build_tree(files, algorithm, store)
        identity = commit(tree, [] if label == "base" else [values["base"]["commit"]], label)
        values[label] = {"commit": identity, "tree": tree, "entries": entries}
    (root / TARGET).write_text(values["ours"]["commit"] + "\n")
    (root / SOURCE).write_text(values["theirs"]["commit"] + "\n")
    return values


def public_identity(entry):
    return None if entry is None else {key: entry[key] for key in ["oid", "mode"]}


def expected_entries(values, mode, prefixes=()):
    before = values["base" if mode == "merge-base" else "ours"]["entries"]
    after = values["theirs"]["entries"]
    return {path: (before.get(path), after.get(path)) for path in sorted(before.keys() | after.keys())
            if public_identity(before.get(path)) != public_identity(after.get(path))
            and (not prefixes or any(path == p or path.startswith(p + b"/") for p in prefixes))}


def line_offsets(body):
    offsets = [0] + [index + 1 for index, byte in enumerate(body) if byte == 10]
    if offsets[-1] != len(body):
        offsets.append(len(body))
    return offsets


def validate(report, values, algorithm, mode="direct", prefixes=(), pr=None, context=3):
    require(report["type"] == "source_review" and report["profile"] == "path-myers-v1", "profile")
    require(report["schema_version"] == 1 and report["complete"] is True, "completeness")
    require(report["scope"] == "selected_paths" and report["line_origin"] == 0, "scope/line origin")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPO, "repository binding")
    require(report["object_format"] == algorithm and report["comparison"] == mode, "comparison binding")
    require(report["node_closed"] is True and report["pull_request"] == pr, "lifecycle/PR binding")
    require(report["snapshot_token"].startswith("alg:") and report["source_head"], "head identity")
    require(report["before_reference_hex"] == TARGET.encode().hex(), "target binding")
    require(report["after_reference_hex"] == SOURCE.encode().hex(), "source binding")
    require(report["requested_before"] == values["ours"]["commit"], "before tip")
    require(report["requested_after"] == values["theirs"]["commit"], "after tip")
    before = values["base" if mode == "merge-base" else "ours"]
    require(report["compared_before"] == before["commit"] and report["before_tree"] == before["tree"], "base binding")
    require(report["after_tree"] == values["theirs"]["tree"], "after tree")
    require(report["path_prefixes_hex"] == [p.hex() for p in sorted(set(prefixes))], "path scope")
    require(report["context_lines"] == context, "context setting")
    entries = expected_entries(values, mode, prefixes)
    require(report["entry_count"] == len(entries) == len(report["entries"]), "entry count")
    for row, (path, (a, b)) in zip(report["entries"], entries.items()):
        require(row["path_hex"] == path.hex(), "raw path/order")
        require(row["before"] == public_identity(a) and row["after"] == public_identity(b), "entry identities")
        expected_kind = "Added" if a is None else "Deleted" if b is None else (
            "TypeChanged" if int(a["mode"], 8) & 0o170000 != int(b["mode"], 8) & 0o170000 else
            "ModeChanged" if a["mode"] != b["mode"] else "Modified")
        require(row["change"] == expected_kind, "change class")
        old = b"" if a is None or a["body"] is None else a["body"]
        new = b"" if b is None or b["body"] is None else b["body"]
        content = row["content"]
        blob = lambda entry: entry is not None and entry["body"] is not None
        kind = ("identical" if blob(a) and blob(b) and a["oid"] == b["oid"] else
                "object_only" if not blob(a) and not blob(b) else
                "binary" if b"\0" in old or b"\0" in new else "text")
        require(content["kind"] == kind, "content class")
        if kind in ["binary", "text"]:
            require(content["before_bytes"] == len(old) and content["after_bytes"] == len(new), "blob lengths")
        if kind != "text":
            continue
        require(content["algorithm"] in ["MyersTrace", "MyersLinearRefinement"], "algorithm")
        require(type(content["additions"]) is int and type(content["deletions"]) is int, "line counts")
        require(content["additions"] - content["deletions"] == len(line_offsets(new)) - len(line_offsets(old)), "line delta")
        cursor, result, new_cursor = 0, b"", 0
        for hunk in content["hunks"]:
            for side, body, key in [("old", old, "before"), ("new", new, "after")]:
                span = hunk[side]
                offsets = line_offsets(body)
                start, end = span["byte_start"], span["byte_end"]
                require(type(start) is int and type(end) is int and 0 <= start <= end <= len(body), "byte interval")
                line, count = span["line_start"], span["line_count"]
                require(type(line) is int and type(count) is int and 0 <= line <= line + count < len(offsets), "line interval")
                require(offsets[line] == start and offsets[line + count] == end, "line/byte mapping")
                require(bytes.fromhex(hunk[key + "_hex"]) == body[start:end], "hunk bytes")
                try:
                    decoded = body[start:end].decode()
                except UnicodeDecodeError:
                    decoded = None
                require(hunk[key + "_text"] == decoded, "lossless text")
            require(hunk["old"]["byte_start"] >= cursor and hunk["new"]["byte_start"] >= new_cursor, "hunk ordering")
            result += old[cursor:hunk["old"]["byte_start"]] + bytes.fromhex(hunk["after_hex"])
            cursor, new_cursor = hunk["old"]["byte_end"], hunk["new"]["byte_end"]
        result += old[cursor:]
        require(result == new, "hunks reconstruct exact new blob")


def invoke(binary, args, code=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=180)
    require(result.returncode == code, f"exit {result.returncode} != {code}: {result.stderr!r}; {result.stdout[:500]!r}")
    return result


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-review-") as temporary:
        root = Path(temporary)
        values = fixture(root / "source", algorithm)
        node = root / "node"
        invoke(binary, ["init", node, TENANT, REPO, algorithm])
        invoke(binary, ["import", node, TENANT, REPO, PRINCIPAL, "review-fixture", root / "source"])
        state = ["at", node, TENANT, REPO, "latest"]
        before_state = invoke(binary, state).stdout
        base = ["diff", node, TENANT, REPO, TARGET, SOURCE, "--trusted-local", "--object-format", algorithm]
        queries = 0
        for mode in ["direct", "merge-base"]:
            for prefixes in [(), (b"src",), (b"invalid-\xff",), (b"absent",)]:
                for context in [0, 3]:
                    args = base + ["--comparison", mode, "--context-lines", str(context)]
                    for prefix in prefixes:
                        args += ["--path-hex", prefix.hex()]
                    response = invoke(binary, args)
                    require(b"\x1b" not in response.stdout, "raw terminal control")
                    report = json.loads(response.stdout)
                    validate(report, values, algorithm, mode, prefixes, context=context)
                    require(invoke(binary, args).stdout == response.stdout, "nondeterministic report")
                    queries += 1
        require(invoke(binary, state).stdout == before_state, "review mutated canonical state")
        for extra in [["--max-changes", "1"], ["--max-blob-bytes", "1"], ["--path", "../private"],
                      ["--comparison", "automatic"], ["--expected-head", "alg:1:" + "ab" * 32]]:
            require(not invoke(binary, base + extra, 2).stdout, "error returned successful output")
        open_args = ["pr", "open", node, TENANT, REPO, "17", "--trusted-local", "--principal", PRINCIPAL,
                     "--idempotency-key", "review-open", "--expected-version", "0", "--source-ref", SOURCE,
                     "--target-ref", TARGET, "--expected-source", values["theirs"]["commit"],
                     "--expected-target", values["ours"]["commit"], "--title", "Review", "--body", ""]
        invoke(binary, open_args)
        pr_args = ["pr", "diff", node, TENANT, REPO, "17", "--trusted-local", "--object-format", algorithm]
        response = invoke(binary, pr_args)
        report = json.loads(response.stdout)
        validate(report, values, algorithm, "merge-base", pr={"number": 17, "version": 1})
        state_after_open = invoke(binary, state).stdout
        require(invoke(binary, pr_args + ["--expected-head", report["snapshot_token"], "--expected-version", "1"]).stdout == response.stdout, "pinned replay")
        require(not invoke(binary, pr_args + ["--expected-version", "2"], 2).stdout, "version mismatch disclosed output")
        require(invoke(binary, state).stdout == state_after_open, "PR review mutated state")
        print(json.dumps({"type": "source_review_smoke", "format": algorithm, "queries": queries,
                          "rust_executed": True, "passed": True}))


def synthetic(values, algorithm):
    report = {"type": "source_review", "profile": "path-myers-v1", "schema_version": 1,
              "complete": True, "scope": "selected_paths", "line_origin": 0, "tenant_id": TENANT,
              "repository_id": REPO, "object_format": algorithm, "comparison": "direct",
              "node_closed": True, "pull_request": None, "snapshot_token": "alg:1:" + "ab" * 32,
              "source_head": "fixture head", "before_reference_hex": TARGET.encode().hex(),
              "after_reference_hex": SOURCE.encode().hex(), "requested_before": values["ours"]["commit"],
              "requested_after": values["theirs"]["commit"], "compared_before": values["ours"]["commit"],
              "before_tree": values["ours"]["tree"], "after_tree": values["theirs"]["tree"],
              "path_prefixes_hex": [b"src/text".hex()], "context_lines": 3, "entry_count": 1}
    a, b = expected_entries(values, "direct", (b"src/text",))[b"src/text"]
    old, new = a["body"], b["body"]
    def whole(body):
        return {"byte_start": 0, "byte_end": len(body), "line_start": 0, "line_count": len(line_offsets(body)) - 1}
    report["entries"] = [{"path_hex": b"src/text".hex(), "change": "Modified", "before": public_identity(a), "after": public_identity(b),
                          "content": {"kind": "text", "algorithm": "MyersTrace", "additions": 2, "deletions": 2,
                                      "before_bytes": len(old), "after_bytes": len(new),
                                      "hunks": [{"old": whole(old), "new": whole(new), "before_hex": old.hex(), "after_hex": new.hex(),
                                                 "before_text": old.decode(), "after_text": new.decode()}]}}]
    return report


def self_test():
    rejected = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as directory:
            values = fixture(Path(directory), algorithm)
            for path in Path(directory).glob("objects/*/*"):
                raw = zlib.decompress(path.read_bytes())
                require(hashlib.new(algorithm, raw).hexdigest() == path.parent.name + path.name, "fixture identity")
            valid = synthetic(values, algorithm)
            validate(valid, values, algorithm, prefixes=(b"src/text",))
            corruptions = [("complete", False), ("entry_count", 0), ("requested_before", "0" * 40),
                           ("compared_before", values["base"]["commit"]), ("repository_id", "wrong"),
                           ("line_origin", 1), ("node_closed", False), ("entries", []),
                           ("path_prefixes_hex", []), ("comparison", "merge-base")]
            for key, value in corruptions:
                invalid = copy.deepcopy(valid)
                invalid[key] = value
                try:
                    validate(invalid, values, algorithm, prefixes=(b"src/text",))
                except (AssertionError, KeyError, ValueError):
                    rejected += 1
                else:
                    raise AssertionError(f"checker accepted changed {key}")
            for field, value in [("after_hex", "00"), ("before_text", "invented"),
                                 ("new", {"byte_start": 0, "byte_end": 1, "line_start": 0, "line_count": 3})]:
                invalid = copy.deepcopy(valid)
                invalid["entries"][0]["content"]["hunks"][0][field] = value
                try:
                    validate(invalid, values, algorithm, prefixes=(b"src/text",))
                except (AssertionError, KeyError, ValueError):
                    rejected += 1
                else:
                    raise AssertionError(f"checker accepted changed hunk {field}")
    print(json.dumps({"type": "source_review_checker_self_test", "corruptions_rejected": rejected, "rust_executed": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--fg", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        binary = args.fg.resolve(strict=True)
        print(json.dumps({"binary": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
        for algorithm in ["sha1", "sha256"]:
            run_format(binary, algorithm)


if __name__ == "__main__":
    main()
