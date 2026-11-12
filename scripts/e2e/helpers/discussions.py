#!/usr/bin/env python3
"""Real fg process/reopen boundaries for discussions; no Git or fixture authority."""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile


def campaign(fg, work, fmt):
    root = work / ("node-" + fmt)
    tenant, repository, actor = "11" * 16, "22" * 16, "33" * 16
    calls = 0
    checks = []

    def passed(name):
        checks.append(name)
        print(f"DISCUSSION-{fmt}-{name} passed", flush=True)

    def stderr(data, args):
        if data:
            print(f"FG_STDERR format={fmt} command={calls} {' '.join(map(str, args[:2]))}", file=sys.stderr, flush=True)
            sys.stderr.write(data.decode(errors="replace"))
            if not data.endswith(b"\n"):
                sys.stderr.write("\n")
            sys.stderr.flush()

    def invoke(args, expected=0, decode=True):
        nonlocal calls
        calls += 1
        try:
            result = subprocess.run([str(fg), *map(str, args)], capture_output=True, timeout=90)
        except subprocess.TimeoutExpired as error:
            stderr(error.stderr, args)
            raise
        # Successful commands can also emit warnings. Preserve all emitted stderr,
        # including expected parser/refusal diagnostics, in the harness evidence.
        stderr(result.stderr, args)
        if result.returncode != expected:
            raise AssertionError(
                f"{args[:2]}: exit {result.returncode}, expected {expected}\n"
                f"{result.stdout.decode(errors='replace')}"
            )
        if not decode:
            return result
        value = json.loads(result.stdout)
        assert value["node_closed"] is True, value
        assert value["tenant_id"] == tenant and value["repository_id"] == repository
        assert value["object_format"] == fmt
        return value

    def command(family, action, number, version, key, fields=(), storage=None):
        args = [family, action, root if storage is None else storage, tenant, repository,
                number, "--trusted-local", "--object-format", fmt, "--principal", actor,
                "--idempotency-key", key]
        if version is not None:
            args.extend(["--expected-version", version])
        return [*args, *fields]

    def mutation(family, action, number, version, key, fields=(), expected=0):
        value = invoke(command(family, action, number, version, key, fields), expected)
        assert value["type"] == family + "_publication"
        assert value["number"] == number and value["expected_version"] == version
        assert value["principal_id"] == actor
        assert value["action"]["name"] == action
        assert value["command_committed"] == (expected == 0)
        assert value["outcome"] == ("committed" if expected == 0 else "refused")
        assert value["refs_changed"] is False
        assert key not in json.dumps(value), "private retry key leaked in receipt"
        return value

    def read(family="discussion", action="show", number=7, fields=(), expected=0):
        args = [family, action, root, tenant, repository]
        if action == "show":
            args.append(number)
        return invoke([*args, "--trusted-local", "--object-format", fmt, *fields], expected)

    def same_outcome(first, replay):
        for name in ["tx_id", "decision_sequence", "repository_commit_id",
                     "refusal_record_id", "refusal_code", "outcome"]:
            assert first[name] == replay[name], name

    def recover(key, original):
        value = invoke(["outcome", root, tenant, repository, "--trusted-local",
                        "--object-format", fmt, "--principal", actor,
                        "--idempotency-key", key], 0 if original["command_committed"] else 3)
        assert value["terminal"] is True and value["read_only"] is True
        assert value["request_reexecuted"] is False
        assert value["state"] == original["outcome"]
        assert value["transaction"]["tx_id"] == original["tx_id"]
        decision = value["decision"]
        assert decision["decision_sequence"] == original["decision_sequence"]
        if original["command_committed"]:
            assert decision["repository_commit_id"] == original["repository_commit_id"]
        else:
            assert decision["code"] == original["refusal_code"]
            assert decision["refusal_record_id"] == original["refusal_record_id"]
        assert key not in json.dumps(value)

    # Malformed commands must be rejected before even trying to open storage.
    unopened = work / ("must-not-open-" + fmt)
    assert not unopened.exists()
    for action, version, fields in [
        ("edit", 1, []),
        ("comment", 1, ["--body", ""]),
        ("close", 0, []),
        ("edit", 1, ["--label", "issue-only"]),
    ]:
        invalid = invoke(command("discussion", action, 7, version, "parser-private", fields, unopened), 2, False)
        assert invalid.stdout == b""
        assert b"cannot open discussion node" not in invalid.stderr
        assert b"invalid discussion" in invalid.stderr or b"inapplicable discussion option" in invalid.stderr
        assert not unopened.exists()
    passed("PARSER-BEFORE-IO")

    invoke(["init", root, tenant, repository, fmt], decode=False)
    assert read(action="list")["discussions"] == []
    body_file = work / ("discussion-body-" + fmt + ".txt")
    comment_file = work / ("discussion-comment-" + fmt + ".txt")
    original = "Design é 🦀\r\n<script>data only</script>\n**Literal document**\n"
    comment = "Authored reply é\r\n{\"principal\":\"not authority\"}\n"
    body_file.write_bytes(original.encode())
    comment_file.write_bytes(comment.encode())
    open_fields = ["--title", "Independent design", "--body-file", body_file]
    opened = mutation("discussion", "open", 7, 0, "discussion-open-private", open_fields)
    same_outcome(opened, mutation("discussion", "open", 7, 0, "discussion-open-private", open_fields))
    first = read()
    assert first["discussion"]["body"] == original
    assert first["discussion"]["version"] == 1
    assert first["discussion"]["comments"] == 0 and first["discussion"]["locked"] is False
    assert first["events"][0]["action"]["body"] == original
    mutation("issue", "open", 7, 0, "separate-issue-private",
             ["--title", "Independent issue", "--body", "Issue body", "--label", "issue-only"])
    issue_before = read("issue")
    mutation("discussion", "open", 9, 0, "discussion-next-private", ["--title", "Next design", "--body", ""])
    list_pin = read(action="list", fields=["--limit", 1])
    assert [row["number"] for row in list_pin["discussions"]] == [7]
    assert list_pin["next_after"] == 7
    commented = mutation("discussion", "comment", 7, 1, "discussion-comment-private", ["--body-file", comment_file])
    history_pin = read(fields=["--limit", 1])
    assert history_pin["next_after_version"] == 1
    assert history_pin["discussion"]["comments"] == 1
    passed("LITERAL-TEXT")

    mutation("discussion", "lock", 7, 2, "discussion-lock-private")
    locked_fields = ["--body", "Must remain refused after unlock"]
    locked = mutation("discussion", "comment", 7, 3, "locked-comment-private", locked_fields, 3)
    assert locked["refusal_code"] == "ProtectedRefTransitionDenied"
    locked_read = read()["discussion"]
    assert locked_read["version"] == 3 and locked_read["comments"] == 1 and locked_read["locked"] is True
    mutation("discussion", "edit", 7, 3, "discussion-rename-private", ["--title", "Renamed design"])
    mutation("discussion", "close", 7, 4, "discussion-close-private")
    closed = read()["discussion"]
    assert closed["state"] == "closed" and closed["locked"] is True
    assert closed["title"] == "Renamed design" and closed["body"] == original and closed["comments"] == 1
    mutation("discussion", "unlock", 7, 5, "discussion-unlock-private")
    mutation("discussion", "comment", 7, 6, "closed-comment-private", ["--body", "Closed but unlocked reply"])
    closed = read()["discussion"]
    assert closed["state"] == "closed" and closed["locked"] is False and closed["comments"] == 2
    mutation("discussion", "reopen", 7, 7, "discussion-reopen-private")
    mutation("discussion", "edit", 7, 8, "discussion-clear-private", ["--body", ""])
    current = read()
    assert current["discussion"]["version"] == 9
    assert current["discussion"]["state"] == "open" and current["discussion"]["locked"] is False
    assert current["discussion"]["title"] == "Renamed design" and current["discussion"]["body"] == ""
    assert current["discussion"]["comments"] == 2
    assert current["discussion"]["opened_by"] == actor and current["discussion"]["last_actor"] == actor
    assert [event["action"]["name"] for event in current["events"]] == [
        "open", "comment", "lock", "edit", "close", "unlock", "comment", "reopen", "edit"]
    assert [event["version"] for event in current["events"]] == list(range(1, 10))
    assert all(event["actor"] == actor for event in current["events"])
    assert current["events"][1]["action"]["body"] == comment
    passed("LIFECYCLE")
    passed("LOCK-REFUSAL")

    stale_fields = ["--title", "Must not overwrite"]
    stale = mutation("discussion", "edit", 7, 1, "stale-version-private", stale_fields, 3)
    assert stale["refusal_code"] == "EvidenceStale"
    assert read()["discussion"] == current["discussion"]
    passed("STALE-REFUSAL")
    before_conflict = read(action="list")["snapshot_token"]
    changed = invoke(command("discussion", "open", 7, 0, "discussion-open-private",
                             ["--title", "Changed sealed title", "--body", original]), 2, False)
    assert changed.stdout == b""
    assert b"idempotency key already bound" in changed.stderr
    assert read(action="list")["snapshot_token"] == before_conflict
    same_outcome(opened, mutation("discussion", "open", 7, 0, "discussion-open-private", open_fields))
    passed("KEY-REUSE")

    retained = read(fields=["--after-version", 1, "--limit", 1, "--expected-head", history_pin["snapshot_token"]])
    assert retained["discussion"] == history_pin["discussion"]
    assert retained["next_after_version"] is None
    assert len(retained["events"]) == 1 and retained["events"][0]["version"] == 2
    assert retained["events"][0]["action"]["body"] == comment
    mutation("discussion", "edit", 9, 1, "discussion-next-edit-private", ["--body", "Later body"])
    mutation("discussion", "open", 10, 0, "discussion-later-private", ["--title", "After pinned page", "--body", ""])
    tail = read(action="list", fields=["--after", 7, "--expected-head", list_pin["snapshot_token"]])
    assert [row["number"] for row in tail["discussions"]] == [9]
    assert tail["discussions"][0]["body"] == "" and tail["discussions"][0]["version"] == 1
    assert tail["next_after"] is None
    events, after = [], 0
    while True:
        flags = ["--limit", 3, "--expected-head", current["snapshot_token"]]
        if after:
            flags.extend(["--after-version", after])
        page = read(fields=flags)
        assert page["discussion"] == current["discussion"]
        events.extend(page["events"])
        after = page["next_after_version"]
        if after is None:
            break
    assert events == current["events"]
    passed("PINNED-PAGES")
    before = read(action="list")["snapshot_token"]
    for action, selector in [("list", "--after"), ("show", "--after-version")]:
        args = ["discussion", action, root, tenant, repository]
        if action == "show":
            args.append(7)
        missing = invoke([*args, "--trusted-local", "--object-format", fmt, selector, 1], 2, False)
        assert missing.stdout == b"" and b"continuation requires --expected-head" in missing.stderr
    assert read(action="list")["snapshot_token"] == before
    passed("PIN-REQUIRED")

    issue_after = read("issue")
    assert issue_after["issue"] == issue_before["issue"] and issue_after["events"] == issue_before["events"]
    mutation("issue", "comment", 7, 1, "separate-issue-comment-private", ["--body", "Only the issue changes"])
    assert read("issue")["issue"]["version"] == 2
    unchanged = read()
    assert unchanged["discussion"] == current["discussion"] and unchanged["events"] == current["events"]
    passed("ISSUE-ISOLATION")
    absent = read(number=8, expected=4)
    assert absent["found"] is False and absent["discussion"] is None and absent["events"] == []
    assert absent["next_after_version"] is None
    passed("MISSING")

    before = read(action="list")["snapshot_token"]
    for data in [b"\xff", b"x" * 65537, b"text\0data"]:
        body_file.write_bytes(data)
        invalid = invoke(command("discussion", "edit", 7, 9, "invalid-file-private",
                                 ["--body-file", body_file]), 2, False)
        assert invalid.stdout == b""
    assert read(action="list")["snapshot_token"] == before
    passed("BODY-REFUSAL")
    # Recovery needs only the original identity. Deleted source files are not authority.
    body_file.unlink()
    comment_file.unlink()
    for key, receipt in [("discussion-open-private", opened), ("discussion-comment-private", commented),
                         ("locked-comment-private", locked), ("stale-version-private", stale)]:
        recover(key, receipt)
    same_outcome(opened, mutation("discussion", "open", 7, 0, "discussion-open-private",
                                 ["--title", "Independent design", "--body", original]))
    same_outcome(commented, mutation("discussion", "comment", 7, 1, "discussion-comment-private", ["--body", comment]))
    same_outcome(locked, mutation("discussion", "comment", 7, 3, "locked-comment-private", locked_fields, 3))
    same_outcome(stale, mutation("discussion", "edit", 7, 1, "stale-version-private", stale_fields, 3))
    assert read(action="list")["snapshot_token"] == before
    final = read()
    assert final["discussion"] == current["discussion"] and final["events"] == current["events"]
    passed("RESTART-RECOVERY")

    # Explicit append requests preserve their identity as the aggregate changes.
    # Each invocation is a fresh process. Forced CAS interleavings are separately
    # exercised by the admission and native-node regression targets.
    mutation("discussion", "open", 11, 0, "append-discussion-open",
             ["--title", "Concurrent replies", "--body", "Original description"])
    appended_body = "Independent é\r\n<script>literal reply</script>"
    append_fields = ["--body", appended_body]
    appended = mutation("discussion", "append-comment", 11, None, "append-first-private", append_fields)
    mutation("discussion", "append-comment", 11, None, "append-second-private", append_fields)
    mutation("discussion", "edit", 11, 3, "append-preserved-edit", ["--title", "Preserved title"])
    mutation("discussion", "append-comment", 11, None, "append-third-private", ["--body", "After edit"])
    mutation("discussion", "close", 11, 5, "append-closed-discussion")
    mutation("discussion", "append-comment", 11, None, "append-closed-private", ["--body", "Closed but unlocked"])
    append_state = read(number=11)
    assert append_state["discussion"]["version"] == 7
    assert append_state["discussion"]["comments"] == 4
    assert append_state["discussion"]["title"] == "Preserved title"
    assert append_state["discussion"]["body"] == "Original description"
    assert append_state["discussion"]["state"] == "closed"
    assert [event["action"]["body"] for event in append_state["events"]
            if event["action"]["name"] == "comment"] == [appended_body, appended_body, "After edit", "Closed but unlocked"]
    passed("APPEND-PRESERVES-CHANGES")

    mutation("discussion", "lock", 11, 7, "append-lock")
    refused_fields = ["--body", "Refused even after later unlock"]
    append_refused = mutation("discussion", "append-comment", 11, None, "append-refused-private", refused_fields, 3)
    assert append_refused["refusal_code"] == "ProtectedRefTransitionDenied"
    same_outcome(appended, mutation("discussion", "append-comment", 11, None, "append-first-private", append_fields))
    mutation("discussion", "unlock", 11, 8, "append-unlock")
    same_outcome(append_refused, mutation("discussion", "append-comment", 11, None, "append-refused-private", refused_fields, 3))
    strict_stale = mutation("discussion", "comment", 11, 1, "append-strict-twin", ["--body", "Strict remains stale"], 3)
    assert strict_stale["refusal_code"] == "EvidenceStale"
    assert read(number=11)["discussion"]["comments"] == 4
    passed("APPEND-LOCK-STRICT-TWINS")

    before_append_retry = read(action="list")["snapshot_token"]
    for action, version, fields in [
        ("append-comment", None, ["--body", "Changed bytes"]),
        ("comment", 1, append_fields),
    ]:
        conflict = invoke(command("discussion", action, 11, version, "append-first-private", fields), 2, False)
        assert conflict.stdout == b"" and b"idempotency key already bound" in conflict.stderr
    invalid = invoke(command("discussion", "append-comment", 11, 9, "append-invalid-version", append_fields), 2, False)
    assert invalid.stdout == b"" and b"inapplicable discussion option" in invalid.stderr
    recover("append-first-private", appended)
    recover("append-refused-private", append_refused)
    same_outcome(appended, mutation("discussion", "append-comment", 11, None, "append-first-private", append_fields))
    assert read(action="list")["snapshot_token"] == before_append_retry
    passed("APPEND-ORIGINAL-RECOVERY")
    return {"format": fmt, "commands": calls, "result": "passed", "checks": checks}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path)
    args = parser.parse_args()

    def run(work):
        work.mkdir(parents=True, exist_ok=True)
        results = []
        for fmt in ("sha1", "sha256"):
            results.append(campaign(args.fg.resolve(), work, fmt))
            (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        for result in results:
            print(f"DISCUSSION_LIFECYCLE format={result['format']} passed commands={result['commands']}", flush=True)

    if args.work is not None:
        run(args.work)
    else:
        with tempfile.TemporaryDirectory(prefix="frankengit-discussions-") as work:
            run(pathlib.Path(work))


if __name__ == "__main__":
    main()
