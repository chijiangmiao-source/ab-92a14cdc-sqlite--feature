"""HTTP review service for snapshot page-ownership audits.

Endpoints:
  GET  /health           liveness probe
  GET  /                 review form (HTML)
  POST /                 form submit, server-rendered verdict (HTML)
  POST /api/audit        JSON {snapshot_b64, root_page} -> verdict JSON
  GET  /api/audit/last   most recent verdict (404 before the first submission)
  GET  /api/audit/last/path?rowid=N
                         root-to-leaf path for a row key, resolved solely from
                         the most recent *accepted* verdict (404 when none is
                         stored, e.g. after a failed review)

Every submission atomically replaces the stored verdict, so a failed review
always clears any earlier success conclusion along with its row-key paths.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .sqlite_audit import (
    MAX_SNAPSHOT_BYTES,
    audit_snapshot_with_index,
    resolve_rowid_path,
)

MAX_BODY_BYTES = 2 * 1024 * 1024
# Largest base64 string that can decode to <= MAX_SNAPSHOT_BYTES.
MAX_B64_CHARS = ((MAX_SNAPSHOT_BYTES + 2) // 3) * 4 + 8

_lock = threading.Lock()
_last_result: dict | None = None
# Route index of the most recent accepted verdict; None whenever the latest
# submission did not pass review, so stale paths are never served.
_last_index: dict | None = None


def _rejected(code, message):
    return {
        "verdict": "rejected",
        "root_page": None,
        "page_size": None,
        "page_count": None,
        "error": {
            "code": code,
            "message": message,
            "page": None,
            "offset": None,
            "bytes_hex": None,
            "detail": {},
        },
        "pages": [],
        "summary": {},
    }


def evaluate_with_index(snapshot_b64, root_page) -> tuple[dict, dict | None]:
    """Decode inputs and run the audit; returns (verdict dict, route index).

    The route index is only present when the snapshot passed review.
    """
    if not isinstance(snapshot_b64, str) or not snapshot_b64.strip():
        return _rejected("SNAPSHOT_MISSING", "snapshot_b64 is required"), None
    compact = "".join(snapshot_b64.split())
    if len(compact) > MAX_B64_CHARS:
        return _rejected(
            "SNAPSHOT_TOO_LARGE",
            f"base64 payload exceeds the {MAX_SNAPSHOT_BYTES}-byte snapshot budget",
        ), None
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        return _rejected("BASE64_INVALID", f"snapshot is not valid base64: {exc}"), None
    if len(data) > MAX_SNAPSHOT_BYTES:
        return _rejected(
            "SNAPSHOT_TOO_LARGE",
            f"decoded snapshot is {len(data)} bytes; the limit is {MAX_SNAPSHOT_BYTES}",
        ), None
    try:
        root = int(root_page)
    except (TypeError, ValueError):
        return _rejected("ROOT_PAGE_INVALID", "root_page must be an integer"), None
    if root < 1:
        return _rejected("ROOT_PAGE_INVALID", "root_page must be >= 1"), None
    return audit_snapshot_with_index(data, root)


def evaluate(snapshot_b64, root_page) -> dict:
    """Decode inputs and run the audit; always returns a verdict dict."""
    result, _index = evaluate_with_index(snapshot_b64, root_page)
    return result


def run_audit(snapshot_b64, root_page) -> dict:
    """Evaluate and atomically replace the stored verdict (clears stale success)."""
    global _last_result, _last_index
    result, index = evaluate_with_index(snapshot_b64, root_page)
    with _lock:
        _last_result = result
        # The route index exists only for accepted verdicts, so a rejection
        # or a newer snapshot atomically retires every earlier path.
        _last_index = index
    return result


def last_result() -> dict | None:
    with _lock:
        return _last_result


def last_path_index() -> dict | None:
    with _lock:
        return _last_index


# ---------------------------------------------------------------------------
# HTML rendering

# Row-key query entry shown on accepted verdicts (server-rendered and
# JS-rendered pages share this exact markup; the query itself always goes
# through GET /api/audit/last/path).
PATH_QUERY_HTML = (
    '<div id="path-query"><h3>行键路径查询</h3>'
    '<p>行键：<input id="rowid-input" inputmode="numeric" size="12"> '
    '<button type="button" onclick="queryPath()">查询路径</button></p>'
    '<div id="path-result"></div></div>'
)


def render_result_html(result: dict | None) -> str:
    if result is None:
        return '<section id="result"></section>'
    esc = html.escape
    out = ['<section id="result">']
    verdict = result["verdict"]
    out.append(
        f'<h2>裁决：<span id="verdict" class="verdict-{esc(verdict)}">{esc(verdict)}</span></h2>'
    )
    error = result.get("error")
    if error:
        page = error["page"] if error["page"] is not None else "-"
        offset = error["offset"] if error["offset"] is not None else "-"
        out.append('<div id="error-card"><h3>首个违规证据</h3><dl>')
        out.append(f'<dt>错误码</dt><dd id="error-code"><code>{esc(error["code"])}</code></dd>')
        out.append(f'<dt>页面号</dt><dd id="error-page">{page}</dd>')
        out.append(f'<dt>文件偏移</dt><dd id="error-offset">{offset}</dd>')
        out.append(
            f'<dt>原始字节</dt><dd id="error-bytes"><code>{esc(error["bytes_hex"] or "-")}</code></dd>'
        )
        out.append(f'<dt>说明</dt><dd id="error-message">{esc(error["message"])}</dd>')
        out.append("</dl></div>")
    summary = result.get("summary") or {}
    if summary:
        out.append(
            '<p id="summary">'
            f'B-tree 页 {summary.get("btree_pages", 0)}，'
            f'溢出页 {summary.get("overflow_pages", 0)}（链 {summary.get("overflow_chains", 0)} 条），'
            f'空闲页 {summary.get("freelist_pages", 0)}/{summary.get("freelist_declared", 0)}，'
            f'行键范围 {summary.get("rowid_min")}..{summary.get("rowid_max")}'
            "</p>"
        )
    if result.get("pages"):
        out.append(
            '<table id="pages-table"><thead><tr>'
            "<th>页面</th><th>归属</th><th>引用来源</th><th>行键范围</th>"
            "</tr></thead><tbody>"
        )
        for p in result["pages"]:
            rng = p["rowid_range"]
            rng_text = f"{rng[0]}..{rng[1]}" if rng else "-"
            out.append(
                f'<tr><td>{p["page"]}</td><td>{esc(p["kind"])}</td>'
                f"<td>{esc(p['referenced_by'])}</td><td>{esc(rng_text)}</td></tr>"
            )
        out.append("</tbody></table>")
    if verdict == "accepted":
        out.append(PATH_QUERY_HTML)
    out.append("</section>")
    return "".join(out)


PAGE_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>星载归档快照复核</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem; color: #1b1f24; }
textarea { width: 100%; font-family: ui-monospace, monospace; }
.verdict-accepted { color: #0a7d2c; font-weight: 700; }
.verdict-rejected { color: #b00020; font-weight: 700; }
table { border-collapse: collapse; margin-top: 1rem; }
th, td { border: 1px solid #ccc; padding: 4px 8px; font-size: 14px; }
code { background: #f2f2f2; padding: 1px 4px; }
#error-card { border: 1px solid #b00020; padding: 0.5rem 1rem; margin-top: 1rem; }
</style>
</head>
<body>
<h1>星载归档库快照导入复核</h1>
<p>提交不超过 512KiB 的 Base64 SQLite 快照与表根页号，核验指定表根下的
B-tree 页面、溢出负载与空闲链互不共用页面。</p>
<form id="audit-form" method="post" action="/">
<p>表根页号：<input name="root_page" id="root_page" value="2" size="8"></p>
<p>Base64 快照：<br>
<textarea name="snapshot_b64" id="snapshot_b64" rows="12" cols="80"></textarea></p>
<p><button type="submit">提交复核</button></p>
</form>
__RESULT__
<script>
const esc = s => String(s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const PATH_QUERY_HTML = '<div id="path-query"><h3>行键路径查询</h3>'
  + '<p>行键：<input id="rowid-input" inputmode="numeric" size="12"> '
  + '<button type="button" onclick="queryPath()">查询路径</button></p>'
  + '<div id="path-result"></div></div>';
const CONCLUSION_LABELS = {
  hit: '命中：叶页内存在精确单元',
  leaf_miss: '叶内缺失：行键位于叶页范围内，但无精确单元',
  out_of_range: '未命中：行键位于全树范围之外',
  no_leaf: '未命中：行键位于分隔边界之间，无对应叶页',
};
function fmtBounds(lower, upper) {
  const l = lower === null ? '-∞' : String(lower);
  const u = upper === null ? '+∞' : String(upper);
  return '(' + l + ', ' + u + (upper === null ? ')' : ']');
}
function renderResult(res) {
  let h = `<h2>裁决：<span id="verdict" class="verdict-${res.verdict}">${esc(res.verdict)}</span></h2>`;
  if (res.error) {
    h += '<div id="error-card"><h3>首个违规证据</h3><dl>'
      + `<dt>错误码</dt><dd id="error-code"><code>${esc(res.error.code)}</code></dd>`
      + `<dt>页面号</dt><dd id="error-page">${res.error.page ?? '-'}</dd>`
      + `<dt>文件偏移</dt><dd id="error-offset">${res.error.offset ?? '-'}</dd>`
      + `<dt>原始字节</dt><dd id="error-bytes"><code>${esc(res.error.bytes_hex || '-')}</code></dd>`
      + `<dt>说明</dt><dd id="error-message">${esc(res.error.message)}</dd></dl></div>`;
  }
  if (res.pages && res.pages.length) {
    h += '<table id="pages-table"><thead><tr><th>页面</th><th>归属</th><th>引用来源</th><th>行键范围</th></tr></thead><tbody>';
    for (const p of res.pages) {
      const rng = p.rowid_range ? `${p.rowid_range[0]}..${p.rowid_range[1]}` : '-';
      h += `<tr><td>${p.page}</td><td>${esc(p.kind)}</td><td>${esc(p.referenced_by)}</td><td>${esc(rng)}</td></tr>`;
    }
    h += '</tbody></table>';
  }
  if (res.verdict === 'accepted') h += PATH_QUERY_HTML;
  document.getElementById('result').innerHTML = h;
}
async function queryPath() {
  const raw = document.getElementById('rowid-input').value.trim();
  const resp = await fetch('/api/audit/last/path?rowid=' + encodeURIComponent(raw));
  renderPath(await resp.json());
}
function renderPath(res) {
  const el = document.getElementById('path-result');
  if (!el) return;
  if (res.error) {
    el.innerHTML = '<p id="path-error">' + esc(res.error) + '</p>';
    return;
  }
  let h = '<p id="path-conclusion">' + esc(CONCLUSION_LABELS[res.conclusion] || res.conclusion) + '</p>';
  if (res.path && res.path.length) {
    h += '<table id="path-table"><thead><tr>'
      + '<th>当前页</th><th>采用的子页指针</th><th>键界（下界排他，上界包含）</th><th>指针偏移</th>'
      + '</tr></thead><tbody>';
    for (const s of res.path) {
      const via = s.via === 'rightmost'
        ? '最右指针 → 页 ' + s.child_page
        : '单元 ' + s.cell_index + '（分隔键 ' + s.divider_key + '）→ 页 ' + s.child_page;
      h += '<tr><td>' + s.page + '</td><td>' + esc(via) + '</td><td>'
        + esc(fmtBounds(s.key_lower, s.key_upper)) + '</td><td>' + s.pointer_offset + '</td></tr>';
    }
    h += '</tbody></table>';
  }
  if (res.leaf) {
    h += '<p id="path-leaf">叶页 ' + res.leaf.page
      + '，完整行键范围 ' + res.leaf.rowid_range[0] + '..' + res.leaf.rowid_range[1]
      + '，精确单元：' + (res.leaf.exact_cell ? '是' : '否') + '</p>';
  }
  el.innerHTML = h;
}
document.getElementById('audit-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const resp = await fetch('/api/audit', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      snapshot_b64: document.getElementById('snapshot_b64').value,
      root_page: Number(document.getElementById('root_page').value),
    }),
  });
  renderResult(await resp.json());
});
</script>
</body>
</html>"""


def render_page(result: dict | None) -> str:
    return PAGE_TEMPLATE.replace("__RESULT__", render_result_html(result))


# ---------------------------------------------------------------------------
# HTTP handler


class Handler(BaseHTTPRequestHandler):
    server_version = "ArchiveAudit/1.0"

    def log_message(self, fmt, *args):  # keep test output clean
        pass

    def _send(self, body: bytes, status: int, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, status=200):
        self._send(
            json.dumps(obj, indent=2).encode("utf-8"),
            status,
            "application/json; charset=utf-8",
        )

    def _send_html(self, text, status=200):
        self._send(text.encode("utf-8"), status, "text/html; charset=utf-8")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send_json({"status": "ok"})
        elif path == "/":
            self._send_html(render_page(None))
        elif path == "/api/audit/last":
            result = last_result()
            if result is None:
                self._send_json({"error": "no audit submitted yet"}, 404)
            else:
                self._send_json(result)
        elif path == "/api/audit/last/path":
            self._handle_path_query()
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_path_query(self):
        params = parse_qs(urlparse(self.path).query)
        raw = (params.get("rowid") or [""])[0].strip()
        if not raw:
            self._send_json({"error": "rowid query parameter is required"}, 400)
            return
        if not re.fullmatch(r"[+-]?[0-9]+", raw):
            self._send_json({"error": "rowid must be an integer"}, 400)
            return
        index = last_path_index()
        if index is None:
            self._send_json(
                {"error": "no accepted audit conclusion available for path queries"},
                404,
            )
            return
        self._send_json(resolve_rowid_path(index, int(raw)))

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self._send_json({"error": "request body too large"}, 413)
            return
        body = self.rfile.read(length) if length else b""
        if path == "/api/audit":
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                self._send_json({"error": "invalid JSON body"}, 400)
                return
            if not isinstance(payload, dict):
                self._send_json({"error": "JSON object expected"}, 400)
                return
            result = run_audit(payload.get("snapshot_b64"), payload.get("root_page"))
            self._send_json(result, 200 if result["verdict"] == "accepted" else 422)
        elif path in ("/", "/audit"):
            form = parse_qs(body.decode("utf-8", "replace"))
            result = run_audit(
                form.get("snapshot_b64", [""])[0], form.get("root_page", [""])[0]
            )
            self._send_html(
                render_page(result), 200 if result["verdict"] == "accepted" else 422
            )
        else:
            self._send_json({"error": "not found"}, 404)


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"archive audit review listening on :{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
