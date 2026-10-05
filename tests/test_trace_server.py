"""HTTP acceptance for rowid path tracing and conclusion staleness rules.

Covers the acceptance scenarios required for the review Compose pipeline:
multi-level tree hit, in-leaf miss, gap/outside-tree queries, and the rule
that a trace may only reference the most recent *accepted* conclusion (a
rejection, the pre-submission state or a newly submitted snapshot all make
the old path unreadable).
"""

import base64
import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from app import fixtures
from app.fixtures import (
    second_valid_snapshot,
    trace_gap_snapshot,
    valid_snapshot,
)
from app.server import Handler


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class TraceEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def post_json(self, payload):
        req = urllib.request.Request(
            self.base + "/api/audit",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def post_form(self, fields):
        req = urllib.request.Request(
            self.base + "/",
            data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def submit(self, data, root):
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(status, 200, res)
        self.assertEqual(res["verdict"], "accepted")
        return res

    def trace_json(self, rowid):
        return self.get(f"/api/audit/trace?rowid={urllib.parse.quote(str(rowid))}")

    # -- multi-level tree hit -------------------------------------------------

    def test_multi_level_hit_returns_ordered_root_to_leaf_path(self):
        self.submit(*valid_snapshot())
        status, body = self.trace_json(7)
        self.assertEqual(status, 200)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "found")
        self.assertEqual(t["root_page"], 2)
        self.assertEqual([s["page"] for s in t["path"]], [2, 11])
        self.assertEqual([s["child_page"] for s in t["path"]], [11, 4])
        # Each step documents bounds, pointer choice and raw snapshot offset.
        self.assertEqual(t["path"][0]["key_bounds_label"], "(-inf, 8]")
        self.assertEqual(t["path"][1]["key_bounds_label"], "(4, +inf]")
        self.assertEqual(t["path"][1]["choice"], "right_most")
        for step in t["path"]:
            self.assertIsInstance(step["pointer_offset"], int)
        # The reached leaf is shown with its full range and an exact cell.
        self.assertEqual(t["leaf"]["page"], 4)
        self.assertEqual(t["leaf"]["rowid_range"], [5, 8])
        self.assertEqual(t["leaf"]["rowids"], [5, 6, 7, 8])
        self.assertTrue(t["leaf"]["exact_cell"])

    def test_hit_via_the_roots_right_most_pointer(self):
        self.submit(*valid_snapshot())
        status, body = self.trace_json(12)
        self.assertEqual(status, 200)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "found")
        self.assertEqual(t["path"][0]["choice"], "right_most")
        self.assertEqual(t["path"][0]["child_page"], 5)
        self.assertEqual(t["leaf"]["page"], 5)

    # -- in-leaf miss ----------------------------------------------------------

    def test_in_leaf_miss_is_distinguishable_from_hit(self):
        self.submit(*trace_gap_snapshot())
        status, body = self.trace_json(3)
        self.assertEqual(status, 200)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "leaf_missing")
        self.assertEqual(t["leaf"]["page"], 3)
        self.assertEqual(t["leaf"]["rowid_range"], [1, 4])
        self.assertEqual(t["leaf"]["rowids"], [1, 2, 4])
        self.assertFalse(t["leaf"]["exact_cell"])
        self.assertIn("no cell", t["message"])

    def test_between_separator_keys_is_distinguishable(self):
        self.submit(*trace_gap_snapshot())
        status, body = self.trace_json(5)
        self.assertEqual(status, 200)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "between_separator_keys")
        self.assertEqual(t["leaf"]["page"], 4)
        self.assertEqual(t["leaf"]["rowid_range"], [6, 8])
        self.assertFalse(t["leaf"]["exact_cell"])

    # -- outside the whole tree -------------------------------------------------

    def test_outside_tree_query_does_not_fabricate_a_path_verdict(self):
        self.submit(*valid_snapshot())
        status, body = self.trace_json(13)
        self.assertEqual(status, 200)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "outside_tree")
        self.assertFalse(t["leaf"]["exact_cell"])
        self.assertEqual(t["tree_rowid_range"], [1, 12])
        status, body = self.trace_json(0)
        self.assertEqual(json.loads(body)["outcome"], "outside_tree")

    def test_invalid_rowid_rejected(self):
        self.submit(*valid_snapshot())
        status, body = self.get("/api/audit/trace?rowid=abc")
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(body)["code"], "ROWID_INVALID")

    # -- stale / non-current conclusions must never be readable ------------------

    def test_trace_unavailable_before_first_submission(self):
        # The handler reads module-level state shared with every in-process
        # server; force the "nothing submitted yet" state directly.
        from app import server as server_mod

        with server_mod._lock:
            saved = (
                server_mod._last_result,
                server_mod._last_accepted_data,
                server_mod._last_accepted_root,
            )
            server_mod._last_result = None
            server_mod._last_accepted_data = None
            server_mod._last_accepted_root = None
        try:
            with urllib.request.urlopen(
                self.base + "/api/audit/trace?rowid=7"
            ) as resp:
                self.fail("expected 409")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 409)
            payload = json.loads(exc.read())
            self.assertEqual(payload["code"], "NO_ACCEPTED_CONCLUSION")
        finally:
            with server_mod._lock:
                (
                    server_mod._last_result,
                    server_mod._last_accepted_data,
                    server_mod._last_accepted_root,
                ) = saved

    def test_failed_verdict_invalidates_the_old_path(self):
        self.submit(*valid_snapshot())
        status, _ = self.trace_json(7)
        self.assertEqual(status, 200)

        bad, bad_root, code, _, _ = fixtures.invalid_scenarios()[
            "shared_overflow_page"
        ]
        status, res = self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        self.assertEqual(status, 422)
        self.assertEqual(res["verdict"], "rejected")

        # The old accepted path is gone; no fabricated descent is served.
        status, body = self.trace_json(7)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["code"], "NO_ACCEPTED_CONCLUSION")
        status, last = self.get("/api/audit/last")
        self.assertEqual(json.loads(last)["verdict"], "rejected")

    def test_new_snapshot_submission_invalidates_the_old_path(self):
        self.submit(*valid_snapshot())
        status, body = self.trace_json(7)
        self.assertEqual(json.loads(body)["leaf"]["page"], 4)

        # Submit a different, also-accepted snapshot: the old tree's path must
        # no longer be answerable; queries resolve against the new root only.
        self.submit(*second_valid_snapshot())
        status, body = self.trace_json(7)
        self.assertEqual(status, 200)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "outside_tree")
        self.assertEqual(t["leaf"]["page"], 2)
        self.assertEqual(t["leaf"]["rowid_range"], [100, 200])
        status, body = self.trace_json(100)
        t = json.loads(body)
        self.assertEqual(t["outcome"], "found")
        self.assertEqual(t["leaf"]["page"], 2)
        self.assertTrue(t["leaf"]["exact_cell"])

    def test_bad_input_submission_also_clears_stored_success(self):
        self.submit(*valid_snapshot())
        status, res = self.post_json(
            {"snapshot_b64": "!!!not-base64!!!", "root_page": 2}
        )
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "BASE64_INVALID")
        status, body = self.trace_json(7)
        self.assertEqual(status, 409)

    # -- form / page behavior stays consistent -----------------------------------

    def test_accepted_form_page_offers_trace_entry(self):
        data, root = valid_snapshot()
        status, text = self.post_form({"snapshot_b64": b64(data), "root_page": str(root)})
        self.assertEqual(status, 200)
        self.assertIn('id="trace-card"', text)
        self.assertIn('id="trace-form"', text)
        self.assertIn("/api/audit/trace", text)

    def test_rejected_form_page_has_no_trace_entry(self):
        bad, bad_root, *_ = fixtures.invalid_scenarios()["bad_magic"]
        status, text = self.post_form(
            {"snapshot_b64": b64(bad), "root_page": str(bad_root)}
        )
        self.assertEqual(status, 422)
        # The trace card is offered only by the server-rendered accepted
        # result; inspect that section only (the page's JS source mentions the
        # same id while building future accepted responses).
        rendered = text.split("<script>")[0]
        self.assertNotIn('id="trace-card"', rendered)
        self.assertIn('id="error-card"', rendered)

    def test_trace_html_page_renders_path_and_leaf(self):
        self.submit(*valid_snapshot())
        status, body = self.get("/trace?rowid=7")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('id="trace-path-table"', text)
        self.assertIn('data-outcome="found"', text)
        self.assertIn('id="trace-leaf-page">4<', text)
        self.assertIn('id="trace-exact-cell">是<', text)
        self.assertIn("2043", text)  # raw child pointer offset shown

    def test_trace_html_page_renders_distinguishable_miss(self):
        self.submit(*trace_gap_snapshot())
        status, body = self.get("/trace?rowid=3")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('data-outcome="leaf_missing"', text)
        self.assertIn('id="trace-exact-cell">否<', text)

    def test_trace_html_page_refuses_stale_conclusion(self):
        self.submit(*valid_snapshot())
        bad, bad_root, *_ = fixtures.invalid_scenarios()["bad_magic"]
        self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        status, body = self.get("/trace?rowid=7")
        self.assertEqual(status, 409)
        self.assertIn('id="trace-error"', body.decode())


if __name__ == "__main__":
    unittest.main()
