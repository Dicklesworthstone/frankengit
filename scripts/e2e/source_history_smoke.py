#!/usr/bin/env python3
"""Real fg DAG-history/blame campaign. --self-test runs fixtures/checker only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = "e1" * 16, "e2" * 16, "e3" * 16
REF = "refs/heads/main"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def lines(body):
    parts = body.split(b"\n")
    return [part + b"\n" for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def fixture(root, algorithm):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {REF}\n")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
        ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"))
    objects, commits = {}, {}
    def store(kind, body):
        oid = identity(algorithm, kind, body)
        objects[oid] = kind, body
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid
    empty = store("blob", b"")
    binary = store("blob", b"binary\0data")
    link = store("blob", b"file")
    def commit(content, parents, label):
        blob = store("blob", content)
        entries = [(b"binary", b"100644", binary), (b"empty", b"100644", empty),
                   (b"file", b"100644", blob), (b"link", b"120000", link), (b"\xff", b"100755", blob)]
        tree = store("tree", b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid)
                                     for name, mode, oid in entries))
        body = (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents) +
                "author Claimed <claimed@example.invalid> 1 +0000\n"
                "committer Claimed <claimed@example.invalid> 1 +0000\n\n" + label + "\n").encode()
        oid = store("commit", body)
        commits[oid] = {"tree": tree, "parents": list(parents), "body": body, "blob": blob, "content": content}
        return oid
    base = commit(b"a\r\nb\nc\nd\n", [], "base")
    left = commit(b"A\r\nb\nc\nd\n", [base], "left")
    right = commit(b"a\r\nb\nC\nd\n", [base], "right")
    tip = commit(b"A\r\nb\nC\nd\nresolved\xff", [left, right], "merge\x1b[2J\u202e")
    (root / REF).write_text(tip + "\n")
    return {"algorithm": algorithm, "objects": objects, "commits": commits, "tip": tip,
            "order": [tip, min(left, right), max(left, right), base], "origins": [left, base, right, base, tip]}


def check_header(report, fixture):
    require(report["schema_version"] == 1 and report["complete"] is True, "complete schema")
    require(report["node_closed"] is True and report["author_headers_authenticated"] is False, "ownership/authorship")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "repository binding")
    require(report["object_format"] == fixture["algorithm"] and report["source_commit"] == fixture["tip"], "native tip binding")
    require(report["reference_hex"] == REF.encode().hex(), "ref binding")
    require(isinstance(report["source_head"], str) and report["source_head"], "head identity")
    require(re.fullmatch(r"alg:[1-9][0-9]*:[0-9a-f]+", report["snapshot_token"]) is not None, "head token")


def check_record(record, fixture, oid):
    expected = fixture["commits"][oid]
    require(record["commit"] == oid and record["tree"] == expected["tree"], "commit/tree")
    require(record["parents"] == expected["parents"], "parent order")
    require(bytes.fromhex(record["body_hex"]) == expected["body"], "raw body")
    require(record["body_text"] == expected["body"].decode(), "lossless body text")
    require(identity(fixture["algorithm"], "commit", bytes.fromhex(record["body_hex"])) == oid, "native commit hash")


def check_log(report, fixture, after=0, limit=50):
    check_header(report, fixture)
    require(report["type"] == "commit_history" and report["profile"] == "topo-oid-v1", "log profile")
    require(report["scope"] == "reachable_commit_dag" and report["total_commits"] == 4, "complete DAG")
    require(report["after"] == after and report["limit"] == limit, "page selection")
    expected = fixture["order"][after:after + limit]
    require(len(report["commits"]) == len(expected), "page length")
    require(report["next_after"] == (after + len(expected) if after + len(expected) < 4 else None), "continuation")
    for row, oid in zip(report["commits"], expected):
        check_record(row, fixture, oid)


def check_blame(report, fixture, start=0, end=5, path=b"file"):
    check_header(report, fixture)
    tip = fixture["commits"][fixture["tip"]]
    require(report["type"] == "source_blame" and report["profile"] == "exact-lines-all-parents-v1", "blame profile")
    require(report["scope"] == "same_path" and report["path_hex"] == path.hex(), "path scope")
    require(report["tree"] == tip["tree"] and report["blob"] == tip["blob"], "file identity")
    require(report["total_lines"] == 5 and report["line_origin"] == 0, "line convention")
    require(report["first_line"] == start and report["end_line"] == end, "line window")
    chunks = lines(tip["content"])
    selected = b"".join(chunks[start:end])
    byte_start = sum(map(len, chunks[:start]))
    require(report["content_byte_start"] == byte_start and bytes.fromhex(report["content_hex"]) == selected, "selected bytes")
    try:
        decoded = selected.decode()
    except UnicodeDecodeError:
        decoded = None
    require(report["content_text"] == decoded, "invalid UTF8 not laundered")
    require(report["graph_commits"] == 4 and 0 <= report["comparisons"] <= 128, "work accounting")
    require(report["max_diff_work"] == 1_000_000, "diff profile work bound")
    require(set(report["algorithms"]) <= {"MyersTrace", "MyersLinearRefinement"}, "diff path")
    require(len(report["lines"]) == end - start, "line result count")
    expected_origins = fixture["origins"][start:end]
    require([row["commit"] for row in report["origins"]] == sorted(set(expected_origins)), "unique origin table")
    for row in report["origins"]:
        check_record(row, fixture, row["commit"])
    for index, (row, origin) in enumerate(zip(report["lines"], expected_origins), start):
        original = fixture["commits"][origin]
        original_lines = lines(original["content"])
        before = sum(map(len, chunks[:index]))
        origin_start = sum(map(len, original_lines[:index]))
        require(row["line"] == index and row["byte_start"] == before and row["byte_end"] == before + len(chunks[index]), "current spans")
        require(row["origin_commit"] == origin and row["origin_blob"] == original["blob"], "origin identity")
        require(row["origin_line"] == index and row["origin_byte_start"] == origin_start and
                row["origin_byte_end"] == origin_start + len(original_lines[index]), "origin spans")
        require(chunks[index] == original_lines[index], "exact originating bytes")


def fabricated(fixture, start=0, end=5):
    tip = fixture["commits"][fixture["tip"]]
    common = {"schema_version": 1, "complete": True, "node_closed": True, "author_headers_authenticated": False,
              "tenant_id": TENANT, "repository_id": REPOSITORY, "object_format": fixture["algorithm"],
              "source_commit": fixture["tip"], "reference_hex": REF.encode().hex(),
              "source_head": "fixture-head", "snapshot_token": "alg:1:" + "ab" * 32}
    def record(oid):
        c = fixture["commits"][oid]
        return {"commit": oid, "tree": c["tree"], "parents": c["parents"], "body_hex": c["body"].hex(), "body_text": c["body"].decode()}
    log = dict(common, type="commit_history", profile="topo-oid-v1", scope="reachable_commit_dag",
               total_commits=4, after=0, limit=50, next_after=None, commits=[record(oid) for oid in fixture["order"]])
    chunks = lines(tip["content"])
    selected = b"".join(chunks[start:end])
    try:
        decoded = selected.decode()
    except UnicodeDecodeError:
        decoded = None
    blame = dict(common, type="source_blame", profile="exact-lines-all-parents-v1", scope="same_path", path_hex=b"file".hex(),
                 tree=tip["tree"], blob=tip["blob"], total_lines=5, line_origin=0, first_line=start, end_line=end,
                 content_byte_start=sum(map(len, chunks[:start])), content_hex=selected.hex(), content_text=decoded,
                 graph_commits=4, comparisons=4, max_diff_work=1_000_000, algorithms=["MyersTrace"],
                 origins=[record(oid) for oid in sorted(set(fixture["origins"][start:end]))], lines=[])
    for index in range(start, end):
        origin = fixture["origins"][index]
        original = fixture["commits"][origin]
        origin_lines = lines(original["content"])
        a, b = sum(map(len, chunks[:index])), sum(map(len, origin_lines[:index]))
        blame["lines"].append({"line": index, "byte_start": a, "byte_end": a + len(chunks[index]),
            "origin_commit": origin, "origin_blob": original["blob"], "origin_line": index,
            "origin_byte_start": b, "origin_byte_end": b + len(origin_lines[index])})
    return log, blame


def invoke(binary, args, code=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=120)
    require(result.returncode == code, f"exit {result.returncode} wanted {code}: {result.stderr!r} {result.stdout!r}")
    return result


def run(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-source-history-") as temporary:
        root = Path(temporary); source = root / "source"; node = root / "node"
        f = fixture(source, algorithm)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "history-source", source])
        state = ["at", node, TENANT, REPOSITORY, "latest"]
        before = invoke(binary, state).stdout
        base = [node, TENANT, REPOSITORY, REF, "--trusted-local", "--object-format", algorithm]
        first = json.loads(invoke(binary, ["log", *base, "--limit", "2"]).stdout)
        check_log(first, f, limit=2)
        token = first["snapshot_token"]
        tail = json.loads(invoke(binary, ["log", *base, "--after", "2", "--limit", "2", "--expected-head", token]).stdout)
        check_log(tail, f, after=2, limit=2)
        for start, end, path in [(0, 5, b"file"), (1, 4, b"file"), (0, 5, b"\xff"), (5, 5, b"file")]:
            args = ["blame", *base, "--path-hex", path.hex(), "--line-start", str(start), "--line-end", str(end), "--expected-head", token]
            response = invoke(binary, args)
            require(b"\x1b" not in response.stdout and b"\xff" not in response.stdout, "unsafe raw bytes")
            check_blame(json.loads(response.stdout), f, start, end, path)
            require(invoke(binary, args).stdout == response.stdout, "non-deterministic repeat")
        for args in [["log", *base, "--after", "1"], ["log", *base, "--max-commits", "1"],
                     ["blame", *base, "--path", "link"], ["blame", *base, "--path", "binary"],
                     ["blame", *base, "--path", "file", "--line-end", "6"],
                     ["blame", *base, "--path", "file", "--max-blob-bytes", "1"],
                     ["blame", *base, "--path", "../file"]]:
            require(not invoke(binary, args, 2).stdout, "failed query returned successful data")
        require(invoke(binary, state).stdout == before, "read commands moved authority")
        print(json.dumps({"type": "source_history_smoke", "format": algorithm, "passed": True, "rust_executed": True}))


def self_test():
    negatives = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as temporary:
            f = fixture(Path(temporary), algorithm)
            for path in Path(temporary).glob("objects/*/*"):
                raw = zlib.decompress(path.read_bytes())
                require(hashlib.new(algorithm, raw).hexdigest() == path.parent.name + path.name, "fixture object identity")
            log, blame = fabricated(f)
            check_log(log, f); check_blame(blame, f)
            for start, end in [(1, 4), (5, 5)]:
                _, partial = fabricated(f, start, end); check_blame(partial, f, start, end)
            mutations = [lambda x: x.update(complete=False), lambda x: x.update(node_closed=False),
                         lambda x: x.update(author_headers_authenticated=True), lambda x: x.update(source_commit="0" * 40),
                         lambda x: x.update(content_hex="00"), lambda x: x.update(line_origin=1),
                         lambda x: x["lines"][0].update(origin_commit=f["tip"]),
                         lambda x: x["lines"][2].update(origin_line=0),
                         lambda x: x["lines"][1].update(byte_start=99),
                         lambda x: x["origins"].pop(), lambda x: x.update(path_hex="00"),
                         lambda x: x.update(graph_commits=3), lambda x: x["origins"][0].update(body_hex="00")]
            for mutate in mutations:
                bad = copy.deepcopy(blame); mutate(bad)
                try:
                    check_blame(bad, f)
                except (AssertionError, KeyError, ValueError, IndexError):
                    negatives += 1
                else:
                    raise AssertionError("checker accepted corrupted blame")
            for mutate in [lambda x: x.update(next_after=2), lambda x: x["commits"].reverse(),
                           lambda x: x.update(total_commits=3), lambda x: x["commits"][0].update(parents=[]),
                           lambda x: x["commits"].pop()]:
                bad = copy.deepcopy(log); mutate(bad)
                try:
                    check_log(bad, f)
                except (AssertionError, KeyError, ValueError, IndexError):
                    negatives += 1
                else:
                    raise AssertionError("checker accepted corrupted history")
    print(json.dumps({"type": "source_history_checker", "passed": True, "corrupted_reports_rejected": negatives, "rust_executed": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.fg is not None:
        binary = args.fg.resolve(strict=True)
        print(json.dumps({"binary": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
        for algorithm in ["sha1", "sha256"]:
            run(binary, algorithm)
    else:
        parser.error("supply --fg or --self-test")


if __name__ == "__main__":
    main()
