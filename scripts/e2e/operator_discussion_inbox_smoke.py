"""Native equal-number discussion/issue inbox isolation and disclosure grants."""
import json

from operator_inbox_smoke import SCRIPT, connection, http_thread, run_inbox_case
from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, require


def inbox_page(c, root, fmt, kind):
    page = json.loads(c.run("inbox", "list", root, TENANT, REPOSITORY, "--trusted-local",
                            "--principal", PRINCIPAL, "--object-format", fmt,
                            "--kind", kind, "--include-muted"))
    require(page["complete"] is True and page["node_closed"] is True and page["read_only"] is True,
            "native namespace inbox read is incomplete")
    return page


def threads(c, root, fmt, kind):
    return inbox_page(c, root, fmt, kind)["threads"]


def compare_list(observed, native, kind):
    page = observed["pages"][0]
    require(observed["complete"] is True and observed["read_only"] is True
            and observed["mutation_submitted"] is False and observed["page_count"] == 1
            and observed["snapshot_token"] == native["snapshot_token"]
            and observed["principal_id"] == native["principal_id"] == PRINCIPAL
            and observed["repository_incarnation"] == native["repository_incarnation"]
            and page["threads"] == [http_thread(row, kind) for row in native["threads"]]
            and page["source_positions"] == {
                "authority_head_generation": int(native["source_generation"]),
                "forge_position_root": native["forge_position_root"],
                "outbox_root": native["outbox_root"], "complete": True},
            "restored disclosure differs from the independent canonical Rust inbox page")


def seed_discussions(c, root, fmt):
    for number in (1, 2):
        result = json.loads(c.run("discussion", "open", root, TENANT, REPOSITORY, number,
            "--trusted-local", "--object-format", fmt, "--principal", PRINCIPAL,
            "--idempotency-key", f"inbox-discussion-open-{number}", "--expected-version", "0",
            "--title", f"Separate native discussion {number}", "--body", "Discussion-only canonical source"))
        require(result["command_committed"] is True and result["node_closed"] is True,
                "native discussion seed did not commit and close")
    return threads(c, root, fmt, "discussion")


def run_discussion_inbox_case(c, server, directory, root, fmt, token, incarnation, grants, seeded):
    require(threads(c, root, fmt, "discussion") == seeded,
            "issue preference mutations changed equal-number discussion preferences")
    original_issues = threads(c, root, fmt, "issue")
    # The issue-only grants left by the issue campaign must not disclose discussions.
    before = c.run("at", root, TENANT, REPOSITORY, "latest")
    denied = c.node_command(SCRIPT, ["list", *connection(server, token, "discussion")], 2, error_reply=True)
    require(denied["http_status"] == 403 and denied["state"] == "read_incomplete"
            and denied["operation_completed"] is False
            and c.run("at", root, TENANT, REPOSITORY, "latest") == before,
            "issue read permission disclosed or changed discussion inbox state")
    # Add exactly one disclosure scope for the permitted twin.
    grants("issues-read,outcomes-read,notifications-write,discussions-read")
    allowed = c.node_command(SCRIPT, ["list", *connection(server, token, "discussion")])
    require(allowed["complete"] is True and allowed["read_only"] is True
            and allowed["mutation_submitted"] is False and allowed["pages"][0]["target_kind"] == "discussion"
            and [row["number"] for row in allowed["pages"][0]["threads"]] == [1, 2]
            and c.run("at", root, TENANT, REPOSITORY, "latest") == before,
            "restored discussion disclosure did not produce a complete native observation")
    compare_list(allowed, inbox_page(c, root, fmt, "discussion"), "discussion")

    def canonical():
        page = json.loads(c.run("discussion", "show", root, TENANT, REPOSITORY, "1",
                               "--trusted-local", "--object-format", fmt))
        require(page["found"] is True and page["node_closed"] is True and page["has_more"] is False,
                "native canonical discussion read is incomplete")
        return page

    work = directory / "discussion-inbox"
    work.mkdir(mode=0o700)
    # Reuse every real action/refusal/recovery/prefix check with issue read/write
    # and discussion write scopes all absent from this HTTP credential.
    run_inbox_case(c, server, work, root, fmt, token, incarnation, grants, canonical, kind="discussion")
    require(threads(c, root, fmt, "issue") == original_issues,
            "discussion preferences changed equal-number issue state")
    c.facts[f"{fmt}_discussion_inbox_namespace_isolation"] = True

    # The reciprocal refusal also changes only one scope for its permitted twin.
    before = c.run("at", root, TENANT, REPOSITORY, "latest")
    denied = c.node_command(SCRIPT, ["list", *connection(server, token)], 2, error_reply=True)
    require(denied["http_status"] == 403 and denied["state"] == "read_incomplete"
            and denied["operation_completed"] is False
            and c.run("at", root, TENANT, REPOSITORY, "latest") == before,
            "discussion read permission disclosed or changed issue inbox state")
    grants("issues-read,outcomes-read,notifications-write,discussions-read")
    allowed = c.node_command(SCRIPT, ["list", *connection(server, token)])
    require(allowed["complete"] is True and allowed["read_only"] is True
            and allowed["mutation_submitted"] is False and threads(c, root, fmt, "issue") == original_issues
            and c.run("at", root, TENANT, REPOSITORY, "latest") == before,
            "restored issue disclosure lost canonical namespace state")
    compare_list(allowed, inbox_page(c, root, fmt, "issue"), "issue")
    c.facts[f"{fmt}_discussion_inbox_disclosure_grant_twins"] = True
