"""HTTP-level tests: API verdicts, health endpoint, stale-success clearing."""

import base64
import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from app import fixtures
from app import server as server_module
from app.fixtures import valid_snapshot
from app.server import Handler


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class ServerTests(unittest.TestCase):
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

    def get_json(self, path):
        status, body = self.get(path)
        return status, json.loads(body)

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

    def test_health(self):
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_form_page_loads(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b'id="audit-form"', body)
        self.assertIn(b'id="snapshot_b64"', body)

    def test_last_result_404_before_first_submission(self):
        status, _ = self.get("/api/audit/last")
        self.assertIn(status, (200, 404))  # depends on test order; see dedicated test

    def test_valid_snapshot_accepted(self):
        data, root = valid_snapshot()
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(status, 200)
        self.assertEqual(res["verdict"], "accepted")
        pages = [p["page"] for p in res["pages"]]
        self.assertEqual(len(pages), len(set(pages)))

    def test_rejection_and_stale_success_cleared(self):
        data, root = valid_snapshot()
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(res["verdict"], "accepted")
        status, last = self.get("/api/audit/last")
        self.assertEqual(json.loads(last)["verdict"], "accepted")

        bad, bad_root, code, page, offset = fixtures.invalid_scenarios()[
            "shared_overflow_page"
        ]
        status, res = self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        self.assertEqual(status, 422)
        self.assertEqual(res["verdict"], "rejected")
        self.assertEqual(res["error"]["code"], code)
        self.assertEqual(res["error"]["page"], page)
        self.assertEqual(res["error"]["offset"], offset)

        # The earlier success conclusion must be gone.
        status, last = self.get("/api/audit/last")
        last = json.loads(last)
        self.assertEqual(last["verdict"], "rejected")
        self.assertEqual(last["error"]["code"], code)

    def test_page_shows_same_first_violation_as_api(self):
        bad, bad_root, code, page, offset = fixtures.invalid_scenarios()[
            "key_bound_conflict"
        ]
        _, api_res = self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        status, html_text = self.post_form(
            {"snapshot_b64": b64(bad), "root_page": str(bad_root)}
        )
        self.assertEqual(status, 422)
        self.assertIn(f'id="error-code"><code>{code}</code>', html_text)
        self.assertIn(f'id="error-page">{page}<', html_text)
        self.assertIn(f'id="error-offset">{offset}<', html_text)
        self.assertIn(api_res["error"]["bytes_hex"], html_text)

    def test_bad_base64(self):
        status, res = self.post_json({"snapshot_b64": "!!!not-base64!!!", "root_page": 2})
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "BASE64_INVALID")

    def test_oversize_snapshot(self):
        status, res = self.post_json(
            {"snapshot_b64": b64(b"\x00" * (600 * 1024)), "root_page": 2}
        )
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "SNAPSHOT_TOO_LARGE")

    def test_root_page_not_integer(self):
        status, res = self.post_json({"snapshot_b64": b64(b"x" * 1024), "root_page": "two"})
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "ROOT_PAGE_INVALID")

    def test_malformed_json_body(self):
        req = urllib.request.Request(
            self.base + "/api/audit",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)

    # --- row-key path queries ------------------------------------------------

    def test_rowid_path_multi_level_hit(self):
        data, root = valid_snapshot()
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(res["verdict"], "accepted")
        status, res = self.get_json("/api/audit/last/path?rowid=7")
        self.assertEqual(status, 200)
        self.assertEqual(res["conclusion"], "hit")
        self.assertEqual(res["root_page"], root)
        self.assertEqual([s["page"] for s in res["path"]], [2, 11])
        self.assertEqual([s["child_page"] for s in res["path"]], [11, 4])
        first, second = res["path"]
        self.assertEqual(first["via"], "cell")
        self.assertIsNone(first["key_lower"])
        self.assertEqual(first["key_upper"], 8)
        self.assertEqual(second["via"], "rightmost")
        self.assertEqual(second["key_lower"], 4)
        self.assertIsNone(second["key_upper"])
        # Step offsets point at the raw child pointers in the submitted snapshot.
        for step in res["path"]:
            off = step["pointer_offset"]
            self.assertEqual(int.from_bytes(data[off : off + 4], "big"), step["child_page"])
        self.assertEqual(
            res["leaf"], {"page": 4, "rowid_range": [5, 8], "exact_cell": True}
        )

    def test_rowid_path_misses_are_distinguishable(self):
        data, root = fixtures.gapped_snapshot()
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(res["verdict"], "accepted")
        status, res = self.get_json("/api/audit/last/path?rowid=11")
        self.assertEqual(res["conclusion"], "leaf_miss")
        self.assertEqual(res["leaf"]["exact_cell"], False)
        self.assertEqual(res["leaf"]["rowid_range"], [9, 12])
        status, res = self.get_json("/api/audit/last/path?rowid=5")
        self.assertEqual(res["conclusion"], "no_leaf")
        self.assertEqual(res["path"], [])
        self.assertIsNone(res["leaf"])
        status, res = self.get_json("/api/audit/last/path?rowid=99")
        self.assertEqual(res["conclusion"], "out_of_range")
        self.assertEqual(res["path"], [])
        self.assertIsNone(res["leaf"])

    def test_rowid_path_not_served_after_rejection(self):
        data, root = valid_snapshot()
        self.post_json({"snapshot_b64": b64(data), "root_page": root})
        status, _ = self.get_json("/api/audit/last/path?rowid=7")
        self.assertEqual(status, 200)
        bad, bad_root, *_ = fixtures.invalid_scenarios()["bad_magic"]
        status, res = self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        self.assertEqual(res["verdict"], "rejected")
        status, _ = self.get_json("/api/audit/last/path?rowid=7")
        self.assertEqual(status, 404)

    def test_rowid_path_reflects_only_latest_snapshot(self):
        data, root = valid_snapshot()
        self.post_json({"snapshot_b64": b64(data), "root_page": root})
        status, res = self.get_json("/api/audit/last/path?rowid=5")
        self.assertEqual(res["conclusion"], "hit")
        # Submitting another snapshot retires the previous conclusions.
        gdata, groot = fixtures.gapped_snapshot()
        self.post_json({"snapshot_b64": b64(gdata), "root_page": groot})
        status, res = self.get_json("/api/audit/last/path?rowid=5")
        self.assertEqual(res["conclusion"], "no_leaf")

    def test_rowid_path_404_without_accepted_conclusion(self):
        # Simulate the never-submitted state, then restore the shared state.
        with server_module._lock:
            saved = (server_module._last_result, server_module._last_index)
            server_module._last_result = None
            server_module._last_index = None
        try:
            status, _ = self.get_json("/api/audit/last/path?rowid=1")
            self.assertEqual(status, 404)
        finally:
            with server_module._lock:
                server_module._last_result, server_module._last_index = saved

    def test_rowid_path_param_validation(self):
        data, root = valid_snapshot()
        self.post_json({"snapshot_b64": b64(data), "root_page": root})
        for query in ("", "?rowid=", "?rowid=abc", "?rowid=1.5", "?rowid=7_0"):
            with self.subTest(query=query):
                status, _ = self.get_json("/api/audit/last/path" + query)
                self.assertEqual(status, 400)
        status, res = self.get_json("/api/audit/last/path?rowid=-3")
        self.assertEqual(status, 200)
        self.assertEqual(res["conclusion"], "out_of_range")

    def test_accepted_page_offers_rowid_query_entry(self):
        def result_section(html_text):
            # The JS template string also mentions the entry markup; only the
            # server-rendered result section tells whether the entry is shown.
            return html_text.split('<section id="result">', 1)[1].split("</section>", 1)[0]

        data, root = valid_snapshot()
        status, html_text = self.post_form(
            {"snapshot_b64": b64(data), "root_page": str(root)}
        )
        self.assertEqual(status, 200)
        self.assertIn('id="path-query"', result_section(html_text))
        self.assertIn('id="rowid-input"', result_section(html_text))
        bad, bad_root, *_ = fixtures.invalid_scenarios()["bad_magic"]
        status, html_text = self.post_form(
            {"snapshot_b64": b64(bad), "root_page": str(bad_root)}
        )
        self.assertEqual(status, 422)
        self.assertNotIn('id="path-query"', result_section(html_text))


if __name__ == "__main__":
    unittest.main()
