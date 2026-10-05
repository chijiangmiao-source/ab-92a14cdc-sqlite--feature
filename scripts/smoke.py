#!/usr/bin/env python3
"""API/HTTP smoke for the archive snapshot review service.

Submits the valid multi-level snapshot and every crafted violation scenario
to a running service, checks the health endpoint, verifies that the HTML page
shows the same first-violation evidence as the JSON API, and confirms that a
failed review clears the previous success conclusion.  It then exercises the
row-key path query endpoint: multi-level hits, in-leaf misses, keys outside
the tree range, gaps between divider bounds, and stale-conclusion
invalidation after another submission or a failed review.

Exits 0 when every check passes, 1 otherwise.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import fixtures  # noqa: E402
from app.fixtures import valid_snapshot  # noqa: E402

BASE = os.environ.get("AUDIT_BASE_URL", "http://127.0.0.1:8080")

_failures = []


def check(name, ok, extra=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not ok else ""))
    if not ok:
        _failures.append(name)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def get_json(path):
    status, body = get(path)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, {}


def result_section(html_text):
    """The server-rendered verdict section (the page's JS also mentions the
    query-entry markup, so entry checks must be scoped to this section)."""
    return html_text.split('<section id="result">', 1)[1].split("</section>", 1)[0]


def post_json(payload):
    req = urllib.request.Request(
        BASE + "/api/audit",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def post_form(fields):
    req = urllib.request.Request(
        BASE + "/",
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main():
    print(f"smoke against {BASE}")
    try:
        status, body = get("/health")
    except urllib.error.URLError as exc:
        check("health endpoint", False, f"unreachable: {exc}")
        print("\n1 failure(s)")
        return 1
    ok = status == 200 and json.loads(body).get("status") == "ok"
    check("health endpoint", ok, f"status={status}")

    status, body = get("/")
    check("review page loads", status == 200 and b'audit-form' in body)

    # --- valid multi-level snapshot with a cross-page BLOB -----------------
    data, root = valid_snapshot()
    status, res = post_json({"snapshot_b64": b64(data), "root_page": root})
    check("valid snapshot accepted", status == 200 and res.get("verdict") == "accepted",
          f"status={status} error={res.get('error')}")
    pages = res.get("pages", [])
    owners = [p["page"] for p in pages]
    check("unique page ownership", len(owners) == len(set(owners)))
    kinds = {p["page"]: p["kind"] for p in pages}
    check(
        "overflow chain owned",
        kinds.get(6) == "overflow" and kinds.get(7) == "overflow"
        and res["summary"]["overflow_chains"] == 1,
        f"kinds={kinds}",
    )
    check(
        "rowid ranges reported",
        res["summary"].get("rowid_min") == 1 and res["summary"].get("rowid_max") == 12,
        f"summary={res.get('summary')}",
    )
    status, last = get("/api/audit/last")
    check("last verdict stored", status == 200 and json.loads(last)["verdict"] == "accepted")

    # --- crafted violations: API and page must show the same first evidence --
    scenarios = fixtures.invalid_scenarios()
    for name, (snap, root_page, code, page, offset) in scenarios.items():
        status, res = post_json({"snapshot_b64": b64(snap), "root_page": root_page})
        err = res.get("error") or {}
        ok = (
            status == 422
            and res.get("verdict") == "rejected"
            and err.get("code") == code
            and err.get("page") == page
            and err.get("offset") == offset
        )
        check(f"{name}: api rejects with first evidence", ok,
              f"status={status} err={err}")
        status, html_text = post_form(
            {"snapshot_b64": b64(snap), "root_page": str(root_page)}
        )
        ok = (
            status == 422
            and f'id="error-code"><code>{code}</code>' in html_text
            and f'id="error-page">{page}<' in html_text
            and f'id="error-offset">{offset}<' in html_text
        )
        check(f"{name}: page shows same evidence", ok, f"status={status}")

    # --- a failed review clears the earlier success conclusion -------------
    status, last = get("/api/audit/last")
    last = json.loads(last)
    check(
        "failed review cleared stored success",
        status == 200
        and last.get("verdict") == "rejected"
        and last["error"]["code"] == scenarios["bad_magic"][2],
        f"last={last.get('error')}",
    )

    # --- row-key path queries on the latest accepted conclusion ------------
    data, root = valid_snapshot()
    status, res = post_json({"snapshot_b64": b64(data), "root_page": root})
    check("path: valid snapshot accepted",
          status == 200 and res.get("verdict") == "accepted",
          f"status={status} error={res.get('error')}")

    status, html_text = post_form({"snapshot_b64": b64(data), "root_page": str(root)})
    check(
        "path: accepted page offers query entry",
        status == 200
        and 'id="path-query"' in result_section(html_text)
        and 'id="rowid-input"' in result_section(html_text),
    )

    status, res = get_json("/api/audit/last/path?rowid=7")
    ok = (
        status == 200
        and res.get("conclusion") == "hit"
        and [s["page"] for s in res["path"]] == [2, 11]
        and [s["child_page"] for s in res["path"]] == [11, 4]
        and res["path"][0]["via"] == "cell"
        and res["path"][0]["key_lower"] is None
        and res["path"][0]["key_upper"] == 8
        and res["path"][1]["via"] == "rightmost"
        and res["path"][1]["key_lower"] == 4
        and res["path"][1]["key_upper"] is None
        and res["leaf"] == {"page": 4, "rowid_range": [5, 8], "exact_cell": True}
    )
    check("path: multi-level hit reaches leaf 4", ok, f"res={res}")
    ok = all(
        isinstance(s["pointer_offset"], int)
        and int.from_bytes(data[s["pointer_offset"] : s["pointer_offset"] + 4], "big")
        == s["child_page"]
        for s in res["path"]
    )
    check("path: step offsets point at raw child pointers", ok)

    status, res = get_json("/api/audit/last/path?rowid=500")
    check(
        "path: out-of-tree high key misses without path",
        status == 200
        and res.get("conclusion") == "out_of_range"
        and res["path"] == []
        and res["leaf"] is None,
        f"res={res}",
    )
    status, res = get_json("/api/audit/last/path?rowid=-4")
    check(
        "path: out-of-tree negative key misses without path",
        status == 200
        and res.get("conclusion") == "out_of_range"
        and res["path"] == []
        and res["leaf"] is None,
        f"res={res}",
    )

    # Submitting another snapshot replaces the previous conclusions.
    gdata, groot = fixtures.gapped_snapshot()
    status, res = post_json({"snapshot_b64": b64(gdata), "root_page": groot})
    check("path: gapped snapshot accepted",
          status == 200 and res.get("verdict") == "accepted",
          f"status={status} error={res.get('error')}")

    status, res = get_json("/api/audit/last/path?rowid=11")
    check(
        "path: in-leaf miss keeps leaf range",
        status == 200
        and res.get("conclusion") == "leaf_miss"
        and res["leaf"] == {"page": 5, "rowid_range": [9, 12], "exact_cell": False}
        and [s["page"] for s in res["path"]] == [2],
        f"res={res}",
    )

    status, res = get_json("/api/audit/last/path?rowid=5")
    check(
        "path: gap between dividers has no leaf (old conclusion replaced)",
        status == 200
        and res.get("conclusion") == "no_leaf"
        and res["path"] == []
        and res["leaf"] is None,
        f"res={res}",
    )

    # A failed review invalidates the stored paths.
    bad, bad_root, code, page, offset = scenarios["bad_magic"]
    status, res = post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
    check("path: failing snapshot rejected", status == 422)
    status, res = get_json("/api/audit/last/path?rowid=7")
    check("path: failed review invalidates stored paths", status == 404,
          f"status={status}")
    status, html_text = post_form({"snapshot_b64": b64(bad), "root_page": str(bad_root)})
    check(
        "path: rejected page has no query entry",
        status == 422 and 'id="path-query"' not in result_section(html_text),
    )

    print(f"\n{len(_failures)} failure(s)" if _failures else "\nall smoke checks passed")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
