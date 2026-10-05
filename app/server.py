"""HTTP review service for snapshot page-ownership audits.

Endpoints:
  GET  /health                liveness probe
  GET  /                      review form (HTML)
  POST /                      form submit, server-rendered verdict (HTML)
  POST /api/audit             JSON {snapshot_b64, root_page} -> verdict JSON
  GET  /api/audit/last        most recent verdict (404 before the first submission)
  GET  /api/audit/trace       rowid descent against the latest ACCEPTED verdict
                              (?rowid=N); 409 once that conclusion is gone

Every submission atomically replaces the stored verdict, so a failed review
always clears any earlier success conclusion -- including the decoded snapshot
bytes kept for rowid descent tracing.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .sqlite_audit import MAX_SNAPSHOT_BYTES, audit_snapshot, trace_rowid_path

MAX_BODY_BYTES = 2 * 1024 * 1024
# Largest base64 string that can decode to <= MAX_SNAPSHOT_BYTES.
MAX_B64_CHARS = ((MAX_SNAPSHOT_BYTES + 2) // 3) * 4 + 8

_lock = threading.Lock()
_last_result: dict | None = None
# Decoded bytes of the latest *accepted* verdict only.  Any rejection (or a
# newly submitted snapshot) clears them, so a rowid trace can never read an
# outdated or failed conclusion.
_last_accepted_data: bytes | None = None
_last_accepted_root: int | None = None


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


def evaluate(snapshot_b64, root_page) -> dict:
    """Decode inputs and run the audit; always returns a verdict dict."""
    if not isinstance(snapshot_b64, str) or not snapshot_b64.strip():
        return _rejected("SNAPSHOT_MISSING", "snapshot_b64 is required")
    compact = "".join(snapshot_b64.split())
    if len(compact) > MAX_B64_CHARS:
        return _rejected(
            "SNAPSHOT_TOO_LARGE",
            f"base64 payload exceeds the {MAX_SNAPSHOT_BYTES}-byte snapshot budget",
        )
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        return _rejected("BASE64_INVALID", f"snapshot is not valid base64: {exc}")
    if len(data) > MAX_SNAPSHOT_BYTES:
        return _rejected(
            "SNAPSHOT_TOO_LARGE",
            f"decoded snapshot is {len(data)} bytes; the limit is {MAX_SNAPSHOT_BYTES}",
        )
    try:
        root = int(root_page)
    except (TypeError, ValueError):
        return _rejected("ROOT_PAGE_INVALID", "root_page must be an integer")
    if root < 1:
        return _rejected("ROOT_PAGE_INVALID", "root_page must be >= 1")
    return audit_snapshot(data, root)


def run_audit(snapshot_b64, root_page) -> dict:
    """Evaluate and atomically replace the stored verdict (clears stale success).

    The decoded snapshot bytes are retained only while the current verdict is
    accepted; any rejection -- and every new submission -- drops the previously
    retained bytes, so rowid traces can never follow a stale or failed path.
    """
    global _last_result, _last_accepted_data, _last_accepted_root
    result = evaluate(snapshot_b64, root_page)
    accepted_data = None
    accepted_root = None
    if result["verdict"] == "accepted":
        # evaluate() already validated the base64 on this same input; keep the
        # exact audited bytes for rowid descent tracing.
        try:
            accepted_data = base64.b64decode(
                "".join(snapshot_b64.split()), validate=True
            )
        except (binascii.Error, ValueError):  # pragma: no cover - cannot happen
            accepted_data = None
        accepted_root = result["root_page"]
    with _lock:
        _last_result = result
        _last_accepted_data = accepted_data
        _last_accepted_root = accepted_root
    return result


def last_result() -> dict | None:
    with _lock:
        return _last_result


def current_accepted() -> tuple[dict, bytes, int] | None:
    """The current accepted verdict together with its audited bytes, or None."""
    with _lock:
        if (
            _last_result is not None
            and _last_result["verdict"] == "accepted"
            and _last_accepted_data is not None
        ):
            return _last_result, _last_accepted_data, _last_accepted_root
    return None


def trace_last_accepted(rowid_raw) -> tuple[int, dict]:
    """Trace one rowid through the latest accepted conclusion only.

    Returns (http_status, payload).  A missing/stale conclusion (nothing
    submitted yet, last verdict rejected, or a newer snapshot submitted) is a
    distinguishable 409 -- no path is ever synthesized for an old verdict.
    """
    current = current_accepted()
    if current is None:
        return (
            409,
            {
                "error": (
                    "no accepted review conclusion is current; a rowid trace "
                    "requires the most recent submission to be an accepted one"
                ),
                "code": "NO_ACCEPTED_CONCLUSION",
            },
        )
    verdict, data, root = current
    try:
        rowid = int(str(rowid_raw).strip())
    except (TypeError, ValueError, AttributeError):
        return (
            422,
            {
                "error": "rowid must be an integer",
                "code": "ROWID_INVALID",
            },
        )
    if not -(1 << 63) <= rowid < (1 << 63):
        return (
            422,
            {
                "error": "rowid must be a signed 64-bit integer",
                "code": "ROWID_INVALID",
            },
        )
    trace = trace_rowid_path(data, root, rowid)
    trace["verdict"] = verdict["verdict"]
    return 200, trace


# ---------------------------------------------------------------------------
# HTML rendering


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
        out.append(render_trace_form_html())
    out.append("</section>")
    return "".join(out)


def render_trace_form_html() -> str:
    """Rowid descent query entry; shown only on an accepted verdict page."""
    return (
        '<div id="trace-card"><h3>行键抵达路径查询</h3>'
        "<p>输入行键，沿指定表根的真实子页指针逐页下降，"
        "查看经过的内部页、采用的指针、半开键界与叶页落点。</p>"
        '<form id="trace-form" method="get" action="/trace">'
        '<p>行键（rowid）：<input name="rowid" id="trace-rowid" size="12">'
        '<button type="submit">查询路径</button></p>'
        "</form>"
        '<section id="trace-result"></section></div>'
    )


def _trace_step_rows(trace: dict) -> str:
    esc = html.escape
    rows = []
    for step in trace["path"]:
        if step["choice"] == "right_most":
            pointer = f'右子页指针 -> 页 {step["child_page"]}'
            cell = "-"
        else:
            pointer = (
                f'单元 {step["cell_index"]} 子页指针 -> 页 {step["child_page"]}'
            )
            cell = step["cell_index"]
        rows.append(
            f'<tr><td>{step["page"]}</td><td>{cell}</td>'
            f"<td>{esc(pointer)}</td>"
            f'<td><code>{esc(step["key_bounds_label"])}</code></td>'
            f'<td>{step["pointer_offset"]}</td></tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="5">表根即叶页，无内部下降步骤</td></tr>')
    return "".join(rows)


def render_trace_html(trace: dict | None, error: str | None = None) -> str:
    """Server-rendered trace result (mirrors the JSON /api/audit/trace)."""
    if error:
        return (
            '<section id="trace-result"><div id="trace-error" class="trace-miss">'
            f"<p>{html.escape(error)}</p></div></section>"
        )
    esc = html.escape
    leaf = trace["leaf"]
    rng = leaf["rowid_range"]
    rng_text = f"{rng[0]}..{rng[1]}" if rng else "（空叶页）"
    out = [
        '<section id="trace-result">',
        f'<h4>查询行键：<code id="trace-rowid-value">{trace["rowid"]}</code></h4>',
        f'<p id="trace-outcome" data-outcome="{esc(trace["outcome"])}">'
        f"结论：<b>{esc(trace['outcome'])}</b></p>",
        f'<p id="trace-message">{esc(trace["message"])}</p>',
        '<table id="trace-path-table"><thead><tr>'
        "<th>当前页</th><th>单元</th><th>采用的子页指针</th>"
        "<th>半开键界</th><th>指针原始偏移</th>"
        "</tr></thead><tbody>",
        _trace_step_rows(trace),
        "</tbody></table>",
        '<div id="trace-leaf-card"><h4>叶页落点</h4><dl>',
        f'<dt>叶页</dt><dd id="trace-leaf-page">{leaf["page"]}</dd>',
        f"<dt>叶页完整行键范围</dt><dd>{esc(rng_text)}</dd>",
        "<dt>叶内全部行键</dt>"
        f'<dd id="trace-leaf-rowids">{esc(", ".join(map(str, leaf["rowids"]))) or "-"}</dd>',
        f'<dt>是否存在精确单元</dt><dd id="trace-exact-cell">'
        f'{"是" if leaf["exact_cell"] else "否"}</dd>',
        "</dl></div>",
        "</section>",
    ]
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
#trace-card { border: 1px solid #0a7d2c; padding: 0.5rem 1rem; margin-top: 1rem; }
.trace-miss { border: 1px solid #b06a00; padding: 0.5rem 1rem; margin-top: 0.5rem; }
#trace-path-table td code { background: none; }
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
  if (res.verdict === 'accepted') {
    h += '<div id="trace-card"><h3>行键抵达路径查询</h3>'
      + '<p>输入行键，沿指定表根的真实子页指针逐页下降，查看经过的内部页、采用的指针、半开键界与叶页落点。</p>'
      + '<form id="trace-form" method="get" action="/trace">'
      + '<p>行键（rowid）：<input name="rowid" id="trace-rowid" size="12">'
      + '<button type="submit">查询路径</button></p>'
      + '<section id="trace-result"></section></div>';
  }
  document.getElementById('result').innerHTML = h;
}
function renderTrace(res) {
  let h = `<h4>查询行键：<code id="trace-rowid-value">${esc(res.rowid)}</code></h4>`
    + `<p id="trace-outcome" data-outcome="${esc(res.outcome)}">结论：<b>${esc(res.outcome)}</b></p>`
    + `<p id="trace-message">${esc(res.message)}</p>`;
  h += '<table id="trace-path-table"><thead><tr><th>当前页</th><th>单元</th><th>采用的子页指针</th><th>半开键界</th><th>指针原始偏移</th></tr></thead><tbody>';
  if (!res.path.length) {
    h += '<tr><td colspan="5">表根即叶页，无内部下降步骤</td></tr>';
  }
  for (const s of res.path) {
    const cell = s.choice === 'right_most' ? '-' : s.cell_index;
    const ptr = s.choice === 'right_most'
      ? `右子页指针 -> 页 ${s.child_page}`
      : `单元 ${s.cell_index} 子页指针 -> 页 ${s.child_page}`;
    h += `<tr><td>${s.page}</td><td>${cell}</td><td>${esc(ptr)}</td>`
      + `<td><code>${esc(s.key_bounds_label)}</code></td><td>${s.pointer_offset}</td></tr>`;
  }
  h += '</tbody></table>';
  const leaf = res.leaf;
  const rng = leaf.rowid_range ? `${leaf.rowid_range[0]}..${leaf.rowid_range[1]}` : '（空叶页）';
  h += '<div id="trace-leaf-card"><h4>叶页落点</h4><dl>'
    + `<dt>叶页</dt><dd id="trace-leaf-page">${leaf.page}</dd>`
    + `<dt>叶页完整行键范围</dt><dd>${esc(rng)}</dd>`
    + `<dt>叶内全部行键</dt><dd id="trace-leaf-rowids">${esc(leaf.rowids.join(', ')) || '-'}</dd>`
    + `<dt>是否存在精确单元</dt><dd id="trace-exact-cell">${leaf.exact_cell ? '是' : '否'}</dd>`
    + '</dl></div>';
  return h;
}
document.addEventListener('submit', async (ev) => {
  if (ev.target.id !== 'trace-form') return;
  ev.preventDefault();
  const rowid = document.getElementById('trace-rowid').value;
  const resp = await fetch('/api/audit/trace?rowid=' + encodeURIComponent(rowid));
  const payload = await resp.json();
  const box = document.getElementById('trace-result');
  if (!resp.ok) {
    box.innerHTML = '<div id="trace-error" class="trace-miss"><p>'
      + esc(payload.error || 'trace unavailable') + '</p></div>';
    return;
  }
  box.innerHTML = renderTrace(payload);
});
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
        parsed = urlparse(self.path)
        path = parsed.path
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
        elif path == "/api/audit/trace":
            query = parse_qs(parsed.query)
            status, payload = trace_last_accepted(query.get("rowid", [""])[0])
            self._send_json(payload, status)
        elif path == "/trace":
            self._send_html(*self._render_trace_page(parsed.query))
        else:
            self._send_json({"error": "not found"}, 404)

    def _render_trace_page(self, query: str):
        """Full-page rowid trace (progressive enhancement of the JSON API)."""
        rowid_raw = parse_qs(query).get("rowid", [""])[0]
        status, payload = trace_last_accepted(rowid_raw)
        current = current_accepted()
        result = current[0] if current else last_result()
        page = render_page(result)
        fragment = (
            render_trace_html(payload)
            if status == 200
            else render_trace_html(None, payload["error"])
        )
        placeholder = '<section id="trace-result"></section>'
        if placeholder in page:
            page = page.replace(placeholder, fragment)
        else:
            # No accepted verdict rendered (no trace card): show the standalone
            # result/error above the page script.
            page = page.replace("<script>", fragment + "<script>", 1)
        return page, status

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
