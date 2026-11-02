#!/usr/bin/env python3
"""Actual fg process boundaries for canonical milestones; no fixture authority or Git."""
import argparse
import json
import pathlib
import subprocess
import tempfile


def campaign(fg, work, fmt):
    root = work / ("node-" + fmt)
    tenant, repository, actor = "11" * 16, "22" * 16, "33" * 16
    calls = 0

    def invoke(args, expected=0, decode=True):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(fg), *map(str, args)], capture_output=True, timeout=90)
        if result.returncode != expected:
            raise AssertionError(
                f"{args[:2]}: exit {result.returncode}, expected {expected}\n"
                f"{result.stdout.decode(errors='replace')}\n{result.stderr.decode(errors='replace')}"
            )
        if not decode:
            return result
        value = json.loads(result.stdout)
        assert value["node_closed"] is True
        return value

    def mutation(family, action, number, version, key, fields=(), expected=0):
        result = invoke([
            family, action, root, tenant, repository, number, "--trusted-local",
            "--object-format", fmt, "--principal", actor, "--idempotency-key", key,
            "--expected-version", version, *fields,
        ], expected)
        assert result["type"] == family + "_publication"
        assert result["number"] == number and result["expected_version"] == version
        assert result["action"]["name"] == action
        assert result["command_committed"] == (expected == 0)
        assert result["outcome"] == ("committed" if expected == 0 else "refused")
        assert result["refs_changed"] is False
        assert key not in json.dumps(result), "private retry key leaked"
        return result

    def read(family="milestone", action="show", number=7, fields=(), expected=0):
        args = [family, action, root, tenant, repository]
        if action == "show":
            args.append(number)
        return invoke([*args, "--trusted-local", "--object-format", fmt, *fields], expected)

    def same_outcome(a, b):
        for field in ["tx_id", "decision_sequence", "repository_commit_id", "refusal_record_id", "refusal_code", "outcome"]:
            assert a[field] == b[field], field

    def assign(issue, issue_version, milestone_version, key, expected=0, milestone=7):
        return mutation("issue", "set-milestone", issue, issue_version, key,
                        ["--milestone", milestone, "--expected-milestone-version", milestone_version], expected)

    def counts(open_count, closed_count, state="open"):
        value = read()["milestone"]
        assert (value["open_issues"], value["closed_issues"], value["state"]) == (open_count, closed_count, state)
        return value

    invoke(["init", root, tenant, repository, fmt], decode=False)
    assert read(action="list")["milestones"] == []
    body = work / ("body-" + fmt + ".txt")
    original = "Release acceptance\r\n<script>data only</script>\né 🦀\n"
    body.write_bytes(original.encode())
    opening = ["--title", "Release one", "--body-file", body, "--due-at", 0]
    opened = mutation("milestone", "open", 7, 0, "milestone-open-private", opening)
    same_outcome(opened, mutation("milestone", "open", 7, 0, "milestone-open-private", opening))
    first = read()
    assert first["milestone"]["body"] == original and first["milestone"]["due_at"] == 0
    assert first["milestone"]["version"] == 1
    assert [e["action"]["name"] for e in first["events"]] == ["open"]
    mutation("milestone", "open", 9, 0, "milestone-next-private", ["--title", "Next release", "--body", ""])
    for issue in [1, 2, 3]:
        mutation("issue", "open", issue, 0, "issue-open-" + str(issue), ["--title", "Task " + str(issue), "--body", ""])
        assert read("issue", number=issue)["issue"]["milestone"] is None
    assignment = assign(1, 1, 1, "assign-one-private")
    assign(2, 1, 1, "assign-two-private")
    mutation("issue", "close", 2, 2, "close-task-two-private")
    counts(1, 1)
    pinned = read()
    mutation("milestone", "edit", 7, 1, "edit-milestone-private", ["--title", "Release revised", "--clear-due-at"])
    changed = counts(1, 1)
    assert changed["title"] == "Release revised" and changed["body"] == original and changed["due_at"] is None
    stale = assign(3, 1, 1, "stale-milestone-private", expected=3)
    assert stale["refusal_code"] == "EvidenceStale"
    assert read("issue", number=3)["issue"]["version"] == 1
    assign(3, 1, 2, "assign-three-private")
    counts(2, 1)
    assert read(fields=["--expected-head", pinned["snapshot_token"]]) == pinned, "pinned counts must not use current issue membership"
    mutation("milestone", "close", 7, 2, "close-milestone-private")
    counts(2, 1, "closed")
    assert read("issue", number=1)["issue"]["milestone"] == 7
    refused = assign(1, 2, 3, "closed-milestone-private", expected=3)
    assert refused["refusal_code"] == "ProtectedRefTransitionDenied"
    same_outcome(assignment, assign(1, 1, 1, "assign-one-private"))
    mutation("issue", "clear-milestone", 2, 3, "clear-closed-private")
    counts(2, 0, "closed")
    mutation("milestone", "reopen", 7, 3, "reopen-milestone-private")
    same_outcome(refused, assign(1, 2, 3, "closed-milestone-private", expected=3))
    same_outcome(stale, assign(3, 1, 1, "stale-milestone-private", expected=3))
    assign(2, 4, 4, "reattach-closed-issue-private")
    counts(2, 1)
    # Membership maintenance works for locked issues; it does not unlock discussion.
    mutation("issue", "lock", 1, 2, "lock-issue-private")
    mutation("issue", "clear-milestone", 1, 3, "clear-locked-private")
    assign(1, 4, 4, "attach-locked-private")
    assert read("issue", number=1)["issue"]["locked"] is True
    # Moving membership between milestones changes counts only at the shared publication.
    assign(3, 2, 1, "move-task-private", milestone=9)
    counts(1, 1)
    assert read(number=9)["milestone"]["open_issues"] == 1
    selected = read("issue", "search", fields=["--milestone", 7, "--limit", 1, "--max-scan", 1])
    assert selected["query"]["milestone"] == 7 and [i["number"] for i in selected["issues"]] == [1]
    continuation = read("issue", "search", fields=["--milestone", 7, "--after", selected["next_after"], "--expected-head", selected["snapshot_token"]])
    assert [i["number"] for i in continuation["issues"]] == [2]
    assert read("issue", "search", fields=["--milestone", "none"])["issues"] == []
    page = read(action="list", fields=["--limit", 1])
    assert [m["number"] for m in page["milestones"]] == [7] and page["next_after"] == 7
    mutation("milestone", "edit", 9, 1, "edit-second-private", ["--body", "later"])
    tail = read(action="list", fields=["--after", 7, "--expected-head", page["snapshot_token"]])
    assert [m["number"] for m in tail["milestones"]] == [9] and tail["milestones"][0]["body"] == ""
    current = read()
    events = []
    after = 0
    while True:
        flags = ["--limit", 1, "--expected-head", current["snapshot_token"]]
        if after:
            flags.extend(["--after-version", after])
        history = read(fields=flags)
        assert history["milestone"] == current["milestone"]
        events.extend(history["events"])
        after = history["next_after_version"]
        if after is None:
            break
    assert events == current["events"]
    assert [e["action"]["name"] for e in events] == ["open", "edit", "close", "reopen"]
    absent = read(number=8, expected=4)
    assert absent["milestone"] is None and not absent["found"] and absent["events"] == []
    before = read(action="list")["snapshot_token"]
    invalid = ["milestone", "edit", root, tenant, repository, 7, "--trusted-local", "--object-format", fmt,
               "--principal", actor, "--idempotency-key", "invalid-body-private", "--expected-version", 4, "--body-file", body]
    for data in [b"\xff", b"x" * 65537, b"text\0data"]:
        body.write_bytes(data)
        assert invoke(invalid, 2, False).stdout == b""
    assert read(action="list")["snapshot_token"] == before
    # Source bodies can disappear; stable-key outcome recovery still identifies the original commit.
    body.unlink()
    recovered = invoke(["outcome", root, tenant, repository, "--trusted-local", "--object-format", fmt,
                        "--principal", actor, "--idempotency-key", "milestone-open-private"], decode=False)
    assert json.loads(recovered.stdout)["transaction"]["tx_id"] == opened["tx_id"]
    assert read(action="list")["snapshot_token"] == before
    return {"format": fmt, "commands": calls, "result": "passed"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", type=pathlib.Path, required=True)
    parser.add_argument("--work", type=pathlib.Path)
    args = parser.parse_args()
    def run(work):
        work.mkdir(parents=True, exist_ok=True)
        results = [campaign(args.fg.resolve(), work, fmt) for fmt in ("sha1", "sha256")]
        (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        for result in results:
            print(f"MILESTONE_LIFECYCLE format={result['format']} passed commands={result['commands']}", flush=True)
    if args.work is not None:
        run(args.work)
    else:
        with tempfile.TemporaryDirectory(prefix="frankengit-milestones-") as work:
            run(pathlib.Path(work))


if __name__ == "__main__":
    main()
