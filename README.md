# 星载归档库快照导入复核

导入维护快照前，复核员需确认**指定表根**下的 B-tree 页面、溢出负载（overflow）
与空闲链（freelist）互不共用页面，避免后续写入损坏仍可读取的遥测记录。

本服务接收不超过 **512KiB** 的 Base64 SQLite 快照与表根页号，通过 API 与页面
展示：裁决、逐页归属、引用来源、行键范围与首个原始字节错误。

## 复核规则

**快照准入**（否则拒绝）：

- `SQLite format 3` 魔数（仅 SQLite 3）
- 页大小 512–4096 字节且为 2 的幂
- 每页保留字节为 0
- 非自动清理模式（头部 52/64 偏移均为 0）
- 文件大小为页大小整数倍

**解析范围**：数据库头部、表内部页（0x05）、表叶页（0x0d）、变长整数、
本地/溢出负载切分、溢出页链、空闲页干链（trunk chain）。

**结构校验**：

- 单元边界与指针数组（越界指针、指针数组溢出、内容区非法均拒绝）
- 子树行键严格递增（叶内递增；内部分隔键 ≥ 左子树最大键且 < 右子树最小键）
- 溢出链恰好覆盖声明负载（页数精确、末页 next=0，截断/超长均拒绝）
- 页面唯一归属：活页重复归属、B-tree 成环（祖先回指）、活页进入空闲链均拒绝
- 空闲链页数须与头部声明一致

**首个违规证据**：审计按确定顺序（头部 → B-tree 中序 → 溢出链 → 空闲链）
在首个违规处停止，稳定报告 `page`（页面号）、`offset`（绝对文件偏移）与
`bytes_hex`（该处原始字节）。每次提交都会原子替换服务端保存的结论——
失败的复核会清除旧的成功结论（`GET /api/audit/last` 可验证）。

## 运行

```bash
# 本地（无依赖，Python 3.11+）
python -m app.server            # http://127.0.0.1:8080
python -m unittest discover -v  # 代码测试
python scripts/smoke.py         # 针对运行中服务的 API/HTTP 冒烟

# Docker Compose：构建检查 + 代码测试 + API/HTTP 冒烟，verify 完成后退出
docker compose up --build --exit-code-from verify --abort-on-container-exit
echo $?   # 0 = 全部通过；非 0 = 存在失败
docker compose down
```

`verify` 服务：镜像构建阶段即运行单元测试（构建检查），启动后等待 `web`
健康检查通过，再次运行覆盖页面所有权场景的代码测试，随后执行
`scripts/smoke.py`（提交合法与违规快照、请求 `/health`、核对拒绝证据、
确认页面与接口展示同一首个违规证据、并验证行键路径查询的命中/未命中与
旧结论失效），最后以退出码报告结果。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康端点，`{"status":"ok"}` |
| GET | `/` | 复核表单页面（JS 走 `/api/audit`，表单 POST 由服务端渲染同一证据） |
| POST | `/` | 表单提交（`snapshot_b64`, `root_page`），HTML 裁决页 |
| POST | `/api/audit` | JSON 提交；200 接受 / 422 拒绝 |
| GET | `/api/audit/last` | 最近一次裁决（首次提交前 404） |
| GET | `/api/audit/trace?rowid=N` | 沿最近一次**通过**结论的真实子页指针，返回行键到叶页的有序下降路径（409 见下） |
| GET | `/trace?rowid=N` | 同一查询的服务端渲染页（表单查询入口的无 JS 回退） |

`POST /api/audit` 请求体：

```json
{"snapshot_b64": "U1FMaXRl...", "root_page": 2}
```

响应（拒绝示例）：

```json
{
  "verdict": "rejected",
  "root_page": 2,
  "page_size": 1024,
  "page_count": 12,
  "error": {
    "code": "PAGE_OWNERSHIP_CONFLICT",
    "message": "page 6 is already owned as overflow (...) and cannot also be ...",
    "page": 6,
    "offset": 4609,
    "bytes_hex": "00000007...",
    "detail": {"first_kind": "overflow", "first_referenced_by": "...", "...": "..."}
  },
  "pages": [
    {"page": 2, "kind": "btree_root", "referenced_by": "requested table root",
     "reference_offset": null, "rowid_range": [1, 12]}
  ],
  "summary": {"btree_pages": 5, "overflow_pages": 2, "overflow_chains": 1,
              "freelist_pages": 3, "freelist_declared": 3,
              "rowid_min": 1, "rowid_max": 12}
}
```

## 行键抵达路径（通过复核后）

复核通过后，裁决页提供**行键查询入口**；`GET /api/audit/trace?rowid=N` 不看汇总
行键范围，而是重新解析快照并沿各内部页中**真实存储的子页指针**逐页下降，返回从
指定表根到目标叶页的有序路径。路径的每一步说明：

- `page`：当前内部页；
- `choice` / `cell_index` / `child_page`：采用的是某个单元的子页指针，还是页头的
  最右子页指针，以及它指向的子页；
- `key_bounds_label`：由相邻分隔键形成的半开键界 `(lower, upper]`——单元分隔键
  满足“行键 ≤ 分隔键走左子树、大于走右子树”，因此下界开、上界闭；
- `pointer_offset`：被采用的指针在**快照中的原始绝对偏移**（该处 4 字节即所跟子页）。

命中叶页后还返回 `leaf.page`、该叶的**完整行键范围**、叶内全部行键以及
`exact_cell`（是否存在该精确单元）。结论可区分，绝不伪造路径：

| `outcome` | 含义 |
| --- | --- |
| `found` | 抵达叶页且叶内存在该行键的精确单元 |
| `leaf_missing` | 行键落在已审计叶页的行键跨度内，但该叶没有此单元 |
| `between_separator_keys` | 行键夹在两条分隔边界之间，没有对应叶页覆盖 |
| `outside_tree` | 行键位于全树行键范围之外（仍给出真实下降到的边界叶页，但无精确单元） |

**只能引用最近一次通过的复核结论**：首次尚未提交、最近一次为失败裁决（含非法
载荷），或随后提交了另一份快照后，旧路径一律不可读，接口返回
`409 NO_ACCEPTED_CONCLUSION`；`rowid` 非整数时返回 `422 ROWID_INVALID`。每次提交
都会原子替换结论与用于查询的快照字节，失败提交会清空此前保留的成功字节。

## 错误码

| 代码 | 含义 |
| --- | --- |
| `HEADER_TOO_SHORT` / `BAD_MAGIC` | 头部过短 / 非 SQLite 3 |
| `PAGE_SIZE_UNSUPPORTED` | 页大小越出 512–4096 或非 2 的幂 |
| `RESERVED_BYTES_PRESENT` | 存在保留字节 |
| `AUTO_VACUUM_ENABLED` | 自动清理/增量清理模式 |
| `TRUNCATED_PAGE` | 文件大小非页整数倍 |
| `ROOT_PAGE_OUT_OF_RANGE` | 根页越界 |
| `NOT_A_TABLE_BTREE_PAGE` | 根/子页非表 B-tree 页 |
| `CELL_POINTER_ARRAY_OVERFLOW` / `CONTENT_AREA_INVALID` / `CELL_POINTER_OUT_OF_BOUNDS` | 指针数组与单元边界 |
| `TRUNCATED_CELL` | 截断单元（varint/负载越页） |
| `ROWID_NOT_INCREASING` | 叶内行键未严格递增 |
| `KEY_BOUND_CONFLICT` | 分隔键与子树键范围冲突 |
| `CHILD_PAGE_OUT_OF_RANGE` | 子页号越界 |
| `OVERFLOW_PAGE_OUT_OF_RANGE` / `OVERFLOW_CHAIN_TRUNCATED` / `OVERFLOW_CHAIN_OVERRUN` | 溢出链越界/截断/超长 |
| `PAGE_OWNERSHIP_CONFLICT` | 活页重复归属（含共享溢出页、祖先回指成环） |
| `LIVE_PAGE_ON_FREELIST` | 活页进入空闲链 |
| `FREELIST_DUPLICATE` / `FREELIST_PAGE_OUT_OF_RANGE` / `FREELIST_TRUNK_LEAF_COUNT` / `FREELIST_COUNT_MISMATCH` | 空闲链完整性 |
| `BASE64_INVALID` / `SNAPSHOT_TOO_LARGE` / `ROOT_PAGE_INVALID` / `SNAPSHOT_MISSING` | 提交载荷问题 |

## 验收场景（`app/fixtures.py` + `scripts/smoke.py`）

合法快照：三级表 B-tree（根 2 → 内部页 11 → 叶 3/4，根右子叶 5），
rowid 7 携带 2500 字节 BLOB，恰好溢出到 6、7 两页；空闲干页 8 带叶 9、10。
违规快照逐一构造：共享溢出页、祖先回指、键界越界、活页进入空闲干链、
截断单元、根页越界、溢出链截断/超长、空闲链计数不符及各类头部违规；
每个场景断言接口与页面展示同一首个违规证据（错误码、页面号、偏移一致）。

行键路径另有 `trace_gap_snapshot`（叶 3 持有 1/2/4——叶内缺失 rowid 3；叶 4 持有
6/7/8——rowid 5 落在分隔边界 4 与 6 之间）与 `second_valid_snapshot`（根即叶、
持有 100/200）。Compose 验收（`tests/test_trace*.py` 与 `scripts/smoke.py`）覆盖：
多级树命中（含逐级页/指针/半开键界/原始偏移）、叶内缺失、分隔键间缺口、树外查询，
以及失败裁决、首次未提交和提交另一份快照后旧结论失效（409 / 改按新树回答）。

## 布局

```
app/sqlite_audit.py   解析与审计核心（纯标准库，含行键下降 trace_rowid_path）
app/fixtures.py       确定性快照构造器与验收场景
app/server.py         HTTP 服务（API + 页面 + 健康端点 + 行键路径查询）
tests/                单元测试（审计器 + 服务 + 行键路径）
scripts/smoke.py      API/HTTP 冒烟（verify 服务调用）
Dockerfile            构建检查：构建期运行单元测试
docker-compose.yml    web + verify（退出码报告结果）
```
