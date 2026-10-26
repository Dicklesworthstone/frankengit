#!/usr/bin/env python3
"""Contested writes and concurrent additive comments on one persisted HTTP node.

x2mv.4.27 acceptance 3. Eight stock git clients push distinct children of
one base to refs/heads/main while eight HTTP clients edit issue #1 at the same
expected version, all released by one barrier. A second barrier releases eight
append-comment requests against that same issue, with distinct actors and keys
and no expected versions. Strict edits and additive comments repeat their exact
requests before and after a server restart. The campaign records facts and
prints one JSON summary; scripts/e2e/suites/node/concurrent_writers.sh
asserts each property under its own acceptance ID.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TENANT, REPOSITORY = "c1" * 16, "c2" * 16
PUSHERS = ISSUE_EDITORS = 8
TIMEOUT = 600
# A loser's push must end in a typed report, never a transport failure.
UNKNOWN_MARKERS = ("outcome unknown", "error: 503", "returned error: 5", "unexpected disconnect",
                   "the remote end hung up")


def principal(index: int) -> str:
    return f"{index:02x}" * 16


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def git_env(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and not k.upper().endswith("_PROXY")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_NAME="Concurrent writer", GIT_AUTHOR_EMAIL="writer@example.invalid",
               GIT_COMMITTER_NAME="Concurrent writer", GIT_COMMITTER_EMAIL="writer@example.invalid",
               GIT_AUTHOR_DATE="2000-01-01T00:00:00+0000",
               GIT_COMMITTER_DATE="2000-01-01T00:00:00+0000")
    return env


def run(args: list, env: dict[str, str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in args], env=env, cwd=cwd, capture_output=True,
                          text=True, timeout=TIMEOUT)


def checked(args: list, env: dict[str, str], cwd: Path | None = None) -> str:
    result = run(args, env, cwd)
    require(result.returncode == 0, f"{args[:3]!r} failed: {result.stderr[-4000:]}")
    return result.stdout.strip()


@contextlib.contextmanager
def serve(fg: str, node: Path, root: Path, grants: Path, ordinal: int):
    stop = root / f"stop-{ordinal}"
    stdout, stderr = root / f"server-{ordinal}.out", root / f"server-{ordinal}.err"
    args = [fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
            "--credentials-file", grants, "--allow-receive", "--allow-issues", "--allow-outcomes",
            "--max-in-flight", "16", "--session-timeout-secs", "300",
            "--processing-timeout-secs", "300", "--continuous", "--stop-file", stop]
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen([str(a) for a in args], stdout=out, stderr=err)
        try:
            started, ready = time.monotonic(), None
            while time.monotonic() - started < TIMEOUT and ready is None:
                for line in stdout.read_text().splitlines():
                    with contextlib.suppress(json.JSONDecodeError):
                        value = json.loads(line)
                        if value.get("type") == "smart_http_listening":
                            ready = value
                require(process.poll() is None, "HTTP server exited before readiness")
                time.sleep(0.02)
            require(ready is not None, "HTTP server never reported readiness")
            yield ready["url"]
            stop.touch(exist_ok=False)
            process.wait(timeout=180)
            require(process.returncode == 0, f"server did not drain: {stderr.read_bytes()[-4000:]!r}")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def api(url: str, path: str, token: str, *, fields: dict | None = None, key: str | None = None):
    endpoint = urllib.parse.urlsplit(url)
    headers = {"Connection": "close", "Authorization": f"Bearer {token}"}
    body = None
    if key is not None:
        headers["Idempotency-Key"] = key
    if fields is not None:
        body = urllib.parse.urlencode(fields).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=TIMEOUT)
    try:
        connection.request("GET" if fields is None else "POST", endpoint.path + path,
                           body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        connection.close()


def find(value, name):
    """The first value under key `name` anywhere in a decoded JSON document."""
    if isinstance(value, dict):
        if name in value:
            return value[name]
        for child in value.values():
            found = find(child, name)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = find(child, name)
            if found is not None:
                return found
    return None


def exercise(fg: str, git: str, root: Path) -> dict:
    env = git_env(root / "home")
    node = root / "node"
    checked([fg, "init", node, TENANT, REPOSITORY, "sha1"], env)
    header = checked([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                      "--print-credentials-header"], env)
    tokens = {index: secrets.token_hex(32) for index in range(PUSHERS + ISSUE_EDITORS + 1)}
    grants = root / "grants"
    scopes = "read,receive,issues-read,issues-write,outcomes-read"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(header + "\n" + "".join(
            f"{hashlib.sha256(token.encode()).hexdigest()} {principal(index + 1)} {scopes}\n"
            for index, token in tokens.items()))
    admin = tokens[PUSHERS + ISSUE_EDITORS]

    base = root / "base"
    checked([git, "init", "-q", "-b", "main", base], env)
    (base / "README").write_text("contested base\n")
    checked([git, "-C", base, "add", "README"], env)
    checked([git, "-C", base, "commit", "-qm", "base"], env)
    base_tip = checked([git, "-C", base, "rev-parse", "HEAD"], env)
    clients = []
    for index in range(PUSHERS):
        clone = root / f"pusher-{index}"
        checked([git, "clone", "-q", base, clone], env)
        (clone / f"writer-{index}.txt").write_text(f"writer {index}\n")
        checked([git, "-C", clone, "add", "-A"], env)
        checked([git, "-C", clone, "commit", "-qm", f"writer {index}"], env)
        clients.append((index, clone, checked([git, "-C", clone, "rev-parse", "HEAD"], env)))

    def push(url: str, index: int, clone: Path) -> subprocess.CompletedProcess:
        return run([git, "-c", f"http.extraHeader=Authorization: Bearer {tokens[index]}",
                    "-C", clone, "push", "--porcelain", url, "HEAD:refs/heads/main"], env)

    def edit(url: str, index: int):
        editor = PUSHERS + index
        return api(url, "/api/v1/issues/1/edit", tokens[editor],
                   fields={"expected_version": "1", "title": f"Edited by writer {editor}"},
                   key=f"contested-edit-{editor}")

    def append_comment(url: str, index: int):
        writer = PUSHERS + index
        return api(url, "/api/v1/issues/1/append-comment", tokens[writer],
                   fields={"body": f"Appended by writer {writer}"},
                   key=f"concurrent-comment-{writer}")

    def comment_receipt(response, index: int) -> dict:
        status, body = response
        try:
            value = json.loads(body)
        except json.JSONDecodeError:
            return {}
        if not isinstance(value, dict) or value.get("type") != "issue_publication":
            return {}
        outcome = value.get("outcome")
        if (value.get("schema_version") != 1 or value.get("tenant_id") != TENANT
                or value.get("repository_id") != REPOSITORY or value.get("number") != 1
                or value.get("principal_id") != principal(PUSHERS + index + 1)
                or value.get("action") != "append-comment"
                or value.get("expected_version", "missing") is not None
                or not isinstance(value.get("tx_id"), str) or not value["tx_id"]
                or outcome not in ("committed", "refused")
                or status != (200 if outcome == "committed" else 409)):
            return {}
        record = "repository_commit_id" if outcome == "committed" else "refusal_record_id"
        return value if isinstance(value.get(record), str) and value[record] else {}

    def issue_observation(response) -> tuple:
        status, body = response
        require(status == 200, f"issue history read failed: {status} {body[:400]}")
        value = json.loads(body)
        require(value.get("type") == "issue_history" and value.get("found") is True,
                "issue history is not a canonical observation")
        require(value.get("next_after_version") is None, "issue history was truncated")
        return value["issue"], value["events"]

    def remote_main(url: str) -> str | None:
        refs = checked([git, "-c", f"http.extraHeader=Authorization: Bearer {admin}",
                        "ls-remote", url, "refs/heads/main"], env)
        return refs.split()[0] if refs else None

    summary: dict = {"type": "concurrent_writers_summary", "writers": PUSHERS + ISSUE_EDITORS,
                     "comment_writers": ISSUE_EDITORS}
    with serve(fg, node, root, grants, 1) as url:
        setup = run([git, "-c", f"http.extraHeader=Authorization: Bearer {admin}", "-C", base,
                     "push", url, "HEAD:refs/heads/main"], env)
        require(setup.returncode == 0, f"initial push failed: {setup.stderr[-4000:]}")
        status, body = api(url, "/api/v1/issues/1/open", admin,
                           fields={"expected_version": "0", "title": "Contested", "body": "x"},
                           key="contested-open")
        require(status == 200, f"issue open failed: {status} {body[:400]}")

        barrier = threading.Barrier(PUSHERS + ISSUE_EDITORS)
        def contest(slot: int):
            barrier.wait(timeout=120)
            started = time.monotonic()
            if slot < PUSHERS:
                index, clone, _ = clients[slot]
                result = push(url, index, clone)
                return ("push", slot, result.returncode, result.stdout + result.stderr,
                        time.monotonic() - started)
            status, body = edit(url, slot - PUSHERS)
            return ("edit", slot - PUSHERS, status, body, time.monotonic() - started)
        with ThreadPoolExecutor(max_workers=PUSHERS + ISSUE_EDITORS) as pool:
            results = list(pool.map(contest, range(PUSHERS + ISSUE_EDITORS)))

        (root / "contest.json").write_text(json.dumps(
            [{"kind": r[0], "client": r[1], "status": r[2], "output": r[3], "seconds": r[4]}
             for r in results], indent=1))
        pushes = [r for r in results if r[0] == "push"]
        edits = [r for r in results if r[0] == "edit"]
        main_after_contest = remote_main(url)
        tips = {clone_tip: index for index, _, clone_tip in clients}
        summary["main_after_contest_client"] = tips.get(main_after_contest, main_after_contest)
        # A client whose commit is main must have been told it won.
        summary["committed_push_reported_refused"] = sum(
            1 for r in pushes if tips.get(main_after_contest) == r[1] and r[2] != 0)
        winners = [r for r in pushes if r[2] == 0]
        summary["push_winners"] = len(winners)
        summary["push_typed_refusals"] = sum(
            1 for r in pushes if r[2] != 0 and ("[rejected]" in r[3] or "[remote rejected]" in r[3]
                                                or "\n!\t" in r[3] or r[3].startswith("!\t")
                                                or "rejected" in r[3]))
        summary["push_unknown"] = sum(
            1 for r in pushes if r[2] != 0 and any(m in r[3].lower() for m in UNKNOWN_MARKERS))
        winning_tip = clients[winners[0][1]][2] if len(winners) == 1 else None
        summary["main_is_the_winner"] = remote_main(url) == winning_tip is not None
        summary["edit_winners"] = sum(1 for r in edits if r[2] == 200)
        summary["edit_typed_refusals"] = sum(
            1 for r in edits if r[2] == 409 and '"outcome":"refused"' in r[3])
        summary["edit_unknown"] = sum(1 for r in edits if r[2] not in (200, 409))
        summary["slowest_writer_s"] = round(max(r[4] for r in results), 3)

        status, shown = api(url, "/api/v1/issues/1", admin)
        issue = json.loads(shown) if status == 200 else {}
        winning_edit = [r for r in edits if r[2] == 200]
        summary["issue_version"] = find(issue, "version")
        summary["issue_title_is_the_winner"] = bool(winning_edit) and find(issue, "title") == (
            f"Edited by writer {PUSHERS + winning_edit[0][1]}")
        events = find(issue, "events")
        summary["issue_events"] = len(events) if isinstance(events, list) else None

        # Additive twin: all commenters start together on the now-edited issue.
        # They preserve that edit and each other's text rather than competing
        # for its observed predecessor. There are no mutation auto-retries.
        comment_barrier = threading.Barrier(ISSUE_EDITORS)
        def comment_contest(index: int):
            comment_barrier.wait(timeout=120)
            started = time.monotonic()
            reply = append_comment(url, index)
            return (index, reply, time.monotonic() - started)
        with ThreadPoolExecutor(max_workers=ISSUE_EDITORS) as pool:
            comments = list(pool.map(comment_contest, range(ISSUE_EDITORS)))
        (root / "comments.json").write_text(json.dumps(
            [{"client": index, "status": reply[0], "output": reply[1], "seconds": seconds}
             for index, reply, seconds in comments], indent=1))
        receipts = [comment_receipt(reply, index) for index, reply, _ in comments]
        summary["comment_committed"] = sum(receipt.get("outcome") == "committed" for receipt in receipts)
        summary["comment_refused"] = sum(receipt.get("outcome") == "refused" for receipt in receipts)
        summary["comment_unknown"] = sum(not receipt for receipt in receipts)
        summary["comment_transactions_unique"] = len({receipt.get("tx_id") for receipt in receipts if receipt}) == ISSUE_EDITORS
        summary["slowest_comment_s"] = round(max(seconds for _, _, seconds in comments), 3)
        comment_history = issue_observation(api(url, "/api/v1/issues/1?limit=100", admin))
        current, events = comment_history
        summary["issue_version_after_comments"] = current["version"]
        summary["issue_events_after_comments"] = len(events)
        summary["issue_comment_count"] = current["comments"]
        summary["comments_preserve_issue_fields"] = all(
            current[field] == issue["issue"][field] for field in ("title", "body", "labels", "state", "assignees"))
        appended = [event for event in events if event["action"]["name"] == "comment"]
        expected_comments = {(principal(PUSHERS + index + 1), f"Appended by writer {PUSHERS + index}")
                             for index in range(ISSUE_EDITORS)}
        summary["comment_history_exact"] = (
            len(appended) == ISSUE_EDITORS
            and {(event["actor"], event["action"]["body"]) for event in appended} == expected_comments
            and [event["version"] for event in appended] == list(range(3, 3 + ISSUE_EDITORS)))
        comment_retries = [append_comment(url, index) for index, _, _ in comments]
        summary["comment_retries_identical"] = all(
            retry == reply for retry, (_, reply, _) in zip(comment_retries, comments))
        summary["comments_unchanged_by_retries"] = issue_observation(
            api(url, "/api/v1/issues/1?limit=100", admin)) == comment_history

        # Exact retries before restart: each client repeats its command. A
        # terminal original must replay byte-identically; an original with
        # no reported outcome must now resolve to a terminal one.
        edit_retries = [edit(url, r[1]) for r in edits]
        summary["edit_retries_identical"] = all(
            (retry[0], retry[1]) == (r[2], r[3])
            for retry, r in zip(edit_retries, edits) if r[2] in (200, 409))
        summary["unknown_edits_resolved_by_retry"] = all(
            retry[0] in (200, 409) for retry, r in zip(edit_retries, edits) if r[2] not in (200, 409))
        push_retries = [push(url, clients[r[1]][0], clients[r[1]][1]) for r in pushes]
        (root / "retries.json").write_text(json.dumps(
            [{"client": r[1], "status": retry.returncode, "output": retry.stdout + retry.stderr}
             for retry, r in zip(push_retries, pushes)], indent=1))
        def typed(result) -> bool:
            return result.returncode == 0 or "rejected" in (result.stdout + result.stderr)
        known = [(retry, r) for retry, r in zip(push_retries, pushes)
                 if r[2] == 0 or "rejected" in r[3]]
        summary["push_retry_outcomes_stable"] = all(
            (retry.returncode == 0) == (r[2] == 0) for retry, r in known)
        summary["unknown_pushes_resolved_by_retry"] = all(
            typed(retry) for retry, r in zip(push_retries, pushes)
            if not (r[2] == 0 or "rejected" in r[3]))
        summary["main_unchanged_by_retries"] = remote_main(url) == winning_tip

    # Restart on the same persisted node: state and exact retries survive.
    with serve(fg, node, root, grants, 2) as url:
        summary["main_survives_restart"] = remote_main(url) == winning_tip is not None
        summary["issue_survives_restart"] = issue_observation(
            api(url, "/api/v1/issues/1?limit=100", admin)) == comment_history
        comment_retries = [append_comment(url, index) for index, _, _ in comments]
        summary["comment_retries_identical_after_restart"] = all(
            retry == reply for retry, (_, reply, _) in zip(comment_retries, comments))
        summary["comments_unchanged_after_restart_retries"] = issue_observation(
            api(url, "/api/v1/issues/1?limit=100", admin)) == comment_history
        edit_retries = [edit(url, r[1]) for r in edits]
        summary["edit_retries_identical_after_restart"] = all(
            (retry[0], retry[1]) == (r[2], r[3])
            for retry, r in zip(edit_retries, edits) if r[2] in (200, 409))

        # A planted lost response after a successful CAS: the client sends a
        # valid edit and closes before reading, so it never learns the
        # outcome. The edit commits; `fg outcome` recovers it from the key.
        status, shown = api(url, "/api/v1/issues/1", admin)
        version = find(json.loads(shown), "version")
        planted_editor = PUSHERS + ISSUE_EDITORS
        planted_key = "planted-lost-response"
        endpoint = urllib.parse.urlsplit(url)
        form = urllib.parse.urlencode(
            {"expected_version": str(version), "title": "Planted lost reply"}).encode()
        request = (f"POST {endpoint.path}/api/v1/issues/1/edit HTTP/1.1\r\n"
                   f"Host: 127.0.0.1\r\nAuthorization: Bearer {tokens[planted_editor]}\r\n"
                   f"Idempotency-Key: {planted_key}\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(form)}\r\nConnection: close\r\n\r\n").encode() + form
        with socket.create_connection((endpoint.hostname, endpoint.port), timeout=30) as raw:
            raw.sendall(request)
            raw.shutdown(socket.SHUT_RDWR)
        deadline = time.monotonic() + 120
        committed = False
        while time.monotonic() < deadline and not committed:
            status, shown = api(url, "/api/v1/issues/1", admin)
            committed = status == 200 and find(json.loads(shown), "title") == "Planted lost reply"
            time.sleep(0.5)
        summary["planted_lost_reply_committed"] = committed
    # With the server stopped, recover the planted outcome from its key alone.
    recovered = run([fg, "outcome", node, TENANT, REPOSITORY, "--trusted-local",
                     "--principal", principal(planted_editor + 1),
                     "--idempotency-key", planted_key], env)
    report = {}
    with contextlib.suppress(json.JSONDecodeError):
        report = json.loads(recovered.stdout)
    decision = find(report, "decision")
    summary["planted_lost_outcome_exit"] = recovered.returncode
    summary["planted_lost_outcome_kind"] = (
        decision.get("kind") if isinstance(decision, dict) else None)
    summary["planted_lost_reply_logged"] = "reply lost after canonical outcome" in (
        (root / "server-2.err").read_text(errors="replace"))
    return summary


def main() -> None:
    global PUSHERS, ISSUE_EDITORS
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--git", default="git")
    parser.add_argument("--pushers", type=int, default=PUSHERS)
    parser.add_argument("--editors", type=int, default=ISSUE_EDITORS)
    parser.add_argument("--summary", type=Path, help="also write the JSON summary here")
    options = parser.parse_args()
    PUSHERS, ISSUE_EDITORS = options.pushers, options.editors
    if not (1 <= PUSHERS <= 16 and 1 <= ISSUE_EDITORS <= 16):
        parser.error("pushers and editors must each be between 1 and 16")
    root = Path(tempfile.mkdtemp(prefix="fg-concurrent-writers-"))
    try:
        summary = exercise(options.fg, options.git, root)
    except BaseException:
        print(json.dumps({"type": "concurrent_writers_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    print(json.dumps(summary, sort_keys=True), flush=True)
    if options.summary is not None:
        options.summary.write_text(json.dumps(summary, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
