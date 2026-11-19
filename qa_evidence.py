#!/usr/bin/env python3
"""qa_evidence.py —— 证据审计门禁（Evidence-First Gate）。

只做审计，不产出任何新结论、不改动任何技术判断：

1. **脱敏漏报扫描**：出现形似真实密钥的串（32/64 位小写 hex、
   ``wx``+16 位 hex、``ding``+字母数字）而所在行没有 ``REDACTED``
   标记时，视为脱敏漏报 —— 退出码 2，优先级高于任何格式问题。
   若同一行同时含 SHA-256 / SPKI / pin / public.key / 指纹 等
   "公开摘要"上下文，则判为公开指纹并豁免（计数后打印，可用
   ``--no-public-digest-exempt`` 关闭该豁免）。

2. **四元组审计**：对 ``threat_model.md`` 中每个 ``T-xx`` finding
   检查 SAMPLE / LOCATOR / COMMAND / ARTIFACT 是否齐全，其中
   ARTIFACT 必须是 ``evidence/`` 下**真实存在**的文件。

3. **落盘**：缺证据的 finding 追加到 ``unverified_hypotheses.md``，
   并在 ``threat_model.md`` 对应位置插入 ``>  UNVERIFIED`` 标注
   （只插入、不删除任何原文；重复运行不会产生重复标注）。

退出码：``0`` 全部齐全；``1`` 存在缺失；``2`` 脱敏漏报。

用法::

    python qa_evidence.py                     # 审计 + 落盘 + 标注
    python qa_evidence.py --dry-run           # 只看结果，不写文件
    python qa_evidence.py --marker-target row # 标注插在 §2 表格行前
    python qa_evidence.py --json audit.json   # 额外输出机器可读结果
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
THREAT = ROOT / "threat_model.md"
REPORT = ROOT / "_re_workspace" / "逆向与安全评估报告_脱敏.md"
UNVERIFIED = ROOT / "unverified_hypotheses.md"
EVIDENCE = ROOT / "evidence"

MARK = ">  UNVERIFIED"
MARK_RE = re.compile(r"^>\s+UNVERIFIED\b.*$")
FIELDS = ("SAMPLE", "LOCATOR", "COMMAND", "ARTIFACT")

EXP_MAP = {
    "T-1": "EXP-1、EXP-2",
    "T-2": "EXP-3、EXP-4、EXP-6",
    "T-3": "EXP-5",
}

# --- 文件读取与写回（保留原换行风格）--------------------------------

def read_text(path):
    """读取文本，返回 (以 \\n 归一的正文, 检测到的换行符)。"""
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    return text.replace("\r\n", "\n"), nl

def write_text(path, text, nl):
    """按指定换行符写回 UTF-8（无 BOM）。"""
    data = text.replace("\r\n", "\n").replace("\n", nl).encode("utf-8")
    path.write_bytes(data)

# --- finding / 小节定位 ---------------------------------------------

HEAD_RE = re.compile(r"^#{1,6}\s")
SECT_RE = re.compile(r"^###\s+\d+\.\d+\s+(T-\d+)\b")
FID_RE = re.compile(r"^T-\d+$")
SCORE_RE = re.compile(r"^\d{1,2}(?:\.\d)?$")
SEVERITIES = ("Critical", "High", "Medium", "Low")

def split_cells(line):
    """把 Markdown 表格行拆成单元格（去首尾管道符）。"""
    return [c.strip() for c in line.strip().strip("|").split("|")]

def collect_findings(lines):
    """从 §2 评分总表取 finding：# 列是 T-xx 的行（≥10 列）。"""
    out = {}
    for idx, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = split_cells(line)
        if len(cells) < 10 or not FID_RE.match(cells[0]):
            continue
        fid = cells[0]
        if fid in out:
            continue
        score, sev = "", ""
        for cell in cells:
            plain = cell.replace("*", "").strip()
            if SCORE_RE.match(plain):
                score = plain
            elif plain in SEVERITIES:
                sev = plain
        out[fid] = {
            "idx": idx,
            "title": cells[1],
            "score": score,
            "sev": sev,
        }
    return out

def collect_sections(lines):
    """取 `### 3.x T-1 ...` 小节的起止行号。"""
    heads = [i for i, ln in enumerate(lines) if HEAD_RE.match(ln)]
    out = {}
    for pos, idx in enumerate(heads):
        m = SECT_RE.match(lines[idx])
        if not m:
            continue
        end = heads[pos + 1] if pos + 1 < len(heads) else len(lines)
        out[m.group(1)] = {"idx": idx, "end": end}
    return out

def region_text(lines, fid, rows, sects):
    """finding 的审计区 = §2 表格行 + §3.x 小节正文。"""
    parts = []
    if fid in rows:
        parts.append(lines[rows[fid]["idx"]])
    if fid in sects:
        sect = sects[fid]
        parts.extend(lines[sect["idx"]:sect["end"]])
    return "\n".join(parts)


REPORT_ID_RE = re.compile(r"^[A-Z]+-\d+$")


def collect_id_map(lines):
    """从 §5 表取 威胁编号 -> [报告编号]，用于把报告正文并入审计区。"""
    out = {}
    for line in lines:
        if not line.startswith("|"):
            continue
        cells = split_cells(line)
        if len(cells) != 5:
            continue
        first = cells[0].split()[0] if cells[0] else ""
        if REPORT_ID_RE.match(first) and FID_RE.match(cells[1]):
            out.setdefault(cells[1], []).append(first)
    return out


def report_context(rep_lines, fid, id_map):
    """报告正文中提及该 finding（或对应报告编号）的行。"""
    keys = [fid] + id_map.get(fid, [])
    hits = []
    for line in rep_lines:
        for key in keys:
            if re.search(r"\b%s\b" % re.escape(key), line):
                hits.append(line)
                break
    return "\n".join(hits)


# --- 四元组审计 -----------------------------------------------------

PAT = {
    "SAMPLE": re.compile(r"\bSAMPLE\b\s*[:=]\s*`?([0-9a-fA-F]{16})`?"),
    "LOCATOR": re.compile(r"\bLOCATOR\b\s*[:=]\s*`?([^`\s|]{3,})`?"),
    "COMMAND": re.compile(r"\bCOMMAND\b\s*[:=]\s*(.+)"),
    "ARTIFACT": re.compile(
        r"\bARTIFACT\b\s*[:=]\s*`?(evidence[/\\][^`\s|]+)"),
}

PLACEHOLDER = re.compile(
    r"(?i)(\bTODO\b|\bTBD\b|\bYOUR_[A-Z0-9_]*\b|\bPLACEHOLDER\b|"
    r"\bXXX+\b|\.\.\.|…|<[^<>]*>|\?\?)")

TOOL_RE = re.compile(
    r"(?i)\b(python|python3|py|adb|frida|curl|tshark|tcpdump|netsh|"
    r"apksigner|aapt|unzip|strings|openssl|java|jarsigner|"
    r"select-string|test-netconnection|tee-object|grep)\b")

TRAIL = ").,;。；） "

def check_quadruple(region):
    """返回 {字段: (是否通过, 取值, 说明)}。"""
    res = {}
    for name in FIELDS:
        m = PAT[name].search(region)
        if not m:
            res[name] = (False, "", "缺失")
            continue
        val = m.group(1).strip().strip("`").strip()
        if not val or PLACEHOLDER.search(val):
            res[name] = (False, val, "占位符/未填")
            continue
        if name == "SAMPLE":
            res[name] = (True, val, "")
        elif name == "COMMAND":
            ok = len(val) >= 8 and TOOL_RE.search(val) is not None
            res[name] = (True, val, "") if ok else (False, val, "非命令")
        elif name == "ARTIFACT":
            rel = val.replace("\\", "/").rstrip(TRAIL)
            if (ROOT / rel).is_file():
                res[name] = (True, rel, "")
            elif (EVIDENCE / Path(rel).name).is_file():
                res[name] = (True, rel, "")
            else:
                res[name] = (False, rel, "磁盘不存在")
        else:
            res[name] = (True, val, "")
    return res

# --- 硬规则①：脱敏漏报扫描 ------------------------------------------

SECRET_PATTERNS = (
    ("HEX64", re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{64}(?![0-9A-Za-z])")),
    ("HEX32", re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{32}(?![0-9A-Za-z])")),
    ("WX_APPID", re.compile(r"\bwx[0-9a-f]{16}\b")),
    ("DING", re.compile(r"\bding[a-z0-9]{10,24}\b")),
)

PUBLIC_CTX = re.compile(
    r"(?i)(sha-?256|sha-?1\b|spki|\bpin\b|指纹|digest|checksum|"
    r"public\.key|公钥)")

REDACTED = "REDACTED"

def scan_secrets(doc_paths, exempt=True):
    """返回 (漏报列表, 公开摘要豁免计数)。"""
    hits, skipped = [], 0
    for path in doc_paths:
        text, _ = read_text(path)
        for no, line in enumerate(text.split("\n"), 1):
            if REDACTED in line:
                continue
            found = []
            for kind, pat in SECRET_PATTERNS:
                for m in pat.finditer(line):
                    found.append((kind, m.group(0)))
            if not found:
                continue
            if exempt and PUBLIC_CTX.search(line):
                skipped += len(found)
                continue
            for kind, val in found:
                hits.append({
                    "file": path.name,
                    "line": no,
                    "kind": kind,
                    "shape": val[:4] + "…" + "(len=%d)" % len(val),
                })
    return hits, skipped

# --- 硬规则②：标注与台账落盘 ----------------------------------------

HEADER = (
    "# 未验证假设清单（Unverified Hypotheses）\n"
    "\n"
    "> 由 `qa_evidence.py` 自动追加。本文件所有条目均为**假设，非发现**：\n"
    "> 缺少 SAMPLE / LOCATOR / COMMAND / ARTIFACT 四元组，禁止进入评分表。\n"
    "> 补齐证据后重跑 `python qa_evidence.py`，`threat_model.md` 中的标注会\n"
    "> 自动撤除；本文件作为历史台账保留，不自动删除。\n"
)

def remove_marks(lines):
    """移除历史标注行，返回 (新行列表, 移除条数)。"""
    kept, removed = [], 0
    for line in lines:
        if MARK_RE.match(line):
            removed += 1
            continue
        kept.append(line)
    return kept, removed

def marker_text(missing):
    return "%s（缺 %s；详见 unverified_hypotheses.md）" % (
        MARK, ", ".join(missing))


def squeeze_blanks(lines, idx):
    """把插入点前的连续空行压到 1 行，返回修正后的插入行号。"""
    while idx > 1 and not lines[idx - 1].strip():
        if lines[idx - 2].strip():
            break
        del lines[idx - 1]
        idx -= 1
    return idx

def entry_block(fid, info, res, ts):
    """生成一条台账条目（含缺失明细）。"""
    missing = [n for n in FIELDS if not res[n][0]]
    exp = EXP_MAP.get(
        fid, "TODO(NEED-EVIDENCE: 在 EXPERIMENTS_NEEDED.md 中补充实验)")
    out = [
        "",
        "## %s %s" % (fid, info["title"]),
        "",
        "- 判定：**假设，非发现**（四元组不全，禁止进入评分表）",
        "- 缺失四元组：%s" % ", ".join(missing),
        "- 现有评分：%s / %s（不得作为已证实结论引用）" % (
            info["score"] or "见 §2", info["sev"] or "见 §2"),
        "- 来源：threat_model.md §2 评分总表 + §3.x（%s）" % fid,
        "- 待补实验：EXPERIMENTS_NEEDED.md → %s" % exp,
        "- 记录时间（UTC）：%s" % ts,
        "- 缺失明细：",
    ]
    for name in missing:
        out.append("  - %s：%s" % (name, res[name][2] or "缺失"))
    out.append(
        "- 补齐方式：在 threat_model.md 该 finding 区块写入 SAMPLE / "
        "LOCATOR / COMMAND / ARTIFACT 四行，ARTIFACT 必须是 evidence/ "
        "下真实存在的文件，然后重跑 `python qa_evidence.py`。")
    return "\n".join(out) + "\n"

def append_entries(path, blocks):
    """追加台账条目，按 finding 去重；返回本次新增的 finding 列表。"""
    if path.is_file():
        text, nl = read_text(path)
    else:
        text, nl = HEADER, "\r\n"
    added = []
    for fid, block in blocks:
        if re.search(r"(?m)^##\s+%s\b" % re.escape(fid), text):
            continue
        text = text.rstrip("\n") + "\n" + block
        added.append(fid)
    if not text.endswith("\n"):
        text += "\n"
    write_text(path, text, nl)
    return added

# --- 控制台输出 -----------------------------------------------------

def doc_paths():
    return [p for p in (THREAT, REPORT) if p.is_file()]

def print_secret_section(docs, hits, skipped):
    print("=== 1/3 脱敏漏报扫描 ===")
    for path in docs:
        print("文件 : %s" % path.relative_to(ROOT))
    print("公开摘要豁免 : %d 处（行内含 SHA-256/SPKI/pin/public.key）"
          % skipped)
    print("脱敏漏报 : %d 处" % len(hits))
    for hit in hits:
        print("  - %(file)s:%(line)d [%(kind)s] %(shape)s" % hit)
    print("状态 : %s" % ("PASS" if not hits else "FAIL -> exit 2"))
    print()

def print_table(results):
    print("=== 2/3 四元组审计 ===")
    fmt = "%-8s%-9s%-9s%-9s%-10s%s"
    print(fmt % ("finding", "SAMPLE", "LOCATOR", "COMMAND", "ARTIFACT",
                 "verdict"))
    for fid, res in results:
        cells = ["OK" if res[n][0] else "MISS" for n in FIELDS]
        verdict = "PASS" if all(res[n][0] for n in FIELDS) else "FAIL"
        print(fmt % tuple([fid] + cells + [verdict]))
    total = len(results)
    ok = sum(1 for _, r in results if all(r[n][0] for n in FIELDS))
    print()
    print("合计 : %d 条 finding，四元组齐全 %d 条，缺证据 %d 条"
          % (total, ok, total - ok))
    print()

def dump_json(path, payload):
    write_text(Path(path), json.dumps(payload, ensure_ascii=False,
                                      indent=2) + "\n", "\r\n")
    print("JSON : %s" % path)

def result_payload(fid, res, rows):
    return {
        "verdict": "PASS" if all(res[n][0] for n in FIELDS) else "FAIL",
        "missing": [n for n in FIELDS if not res[n][0]],
        "score": rows[fid]["score"],
        "severity": rows[fid]["sev"],
        "fields": {n: {"ok": res[n][0], "value": res[n][1],
                       "note": res[n][2]} for n in FIELDS},
    }

# --- 主流程 ---------------------------------------------------------

def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(
        description="证据审计门禁：脱敏漏报 + SAMPLE/LOCATOR/COMMAND/"
                    "ARTIFACT 四元组审计，并对缺证据 finding 落盘标注。")
    ap.add_argument("--dry-run", action="store_true",
                    help="只审计，不写台账、不插入标注")
    ap.add_argument("--marker-target", choices=("section", "row"),
                    default="section",
                    help="标注位置：section=§3.x 标题前（默认，不破坏表格）；"
                         "row=§2 表格行前（字面插在行首，会打断表格）")
    ap.add_argument("--no-public-digest-exempt", action="store_true",
                    help="关闭公开摘要豁免（SHA-256/SPKI/pin 也判为漏报）")
    ap.add_argument("--json", metavar="PATH", default=None,
                    help="把审计结果写成 JSON")
    args = ap.parse_args(argv)

    docs = doc_paths()
    for path in (THREAT, REPORT):
        if not path.is_file():
            print("WARN 文档不存在，已跳过：%s" % path.name)
    if not THREAT.is_file():
        print("ERROR 缺少 threat_model.md，无法审计")
        return 1

    text, nl = read_text(THREAT)
    lines = text.split("\n")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 硬规则①：脱敏漏报（优先级最高）
    hits, skipped = scan_secrets(docs, not args.no_public_digest_exempt)
    print_secret_section(docs, hits, skipped)
    if hits:
        if args.json:
            dump_json(args.json, {
                "generated": ts,
                "docs": [p.name for p in docs],
                "secrets": {"violations": hits,
                            "public_digest_exempt": skipped},
                "findings": {},
                "exit": 2,
            })
        print("结论 : exit 2 —— 发现疑似未脱敏密钥，请先运行 "
              "python _re_workspace\\sanitize_report.py 并复核；"
              "本次未写入任何标注。")
        return 2

    # 硬规则②：四元组审计（threat_model.md 正文 + 报告侧相关行）
    rows = collect_findings(lines)
    sects = collect_sections(lines)
    id_map = collect_id_map(lines)
    rep_lines = []
    if REPORT.is_file():
        rep_text, _ = read_text(REPORT)
        rep_lines = rep_text.split("\n")
    results = []
    for fid in sorted(rows):
        region = region_text(lines, fid, rows, sects)
        region += "\n" + report_context(rep_lines, fid, id_map)
        results.append((fid, check_quadruple(region)))
    print_table(results)

    lacking = [(fid, r) for fid, r in results
               if not all(r[n][0] for n in FIELDS)]

    print("=== 3/3 落盘 ===")
    if args.dry_run:
        print("--dry-run：跳过 unverified_hypotheses.md 与标注写入")
    else:
        blocks = [(fid, entry_block(fid, rows[fid], r, ts))
                  for fid, r in lacking]
        added = append_entries(UNVERIFIED, blocks)
        print("unverified_hypotheses.md : 新增 %d 条（%s）" % (
            len(added), ", ".join(added) if added else "无（已存在）"))

        kept, removed = remove_marks(lines)
        print("threat_model.md : 移除历史标注 %d 处" % removed)
        if lacking:
            nrows = collect_findings(kept)
            nsects = collect_sections(kept)
            plan = []
            for fid, res in lacking:
                miss = [n for n in FIELDS if not res[n][0]]
                mark = marker_text(miss)
                if args.marker_target == "row" and fid in nrows:
                    plan.append((nrows[fid]["idx"], [mark]))
                elif fid in nsects:
                    plan.append((nsects[fid]["idx"], [mark, ""]))
                elif fid in nrows:
                    plan.append((nrows[fid]["idx"], [mark]))
            for idx, block in sorted(plan, key=lambda x: x[0],
                                     reverse=True):
                if args.marker_target != "row":
                    idx = squeeze_blanks(kept, idx)
                kept[idx:idx] = block
            print("threat_model.md : 插入 `%s` %d 处（%s 模式）" % (
                MARK, len(plan), args.marker_target))
        write_text(THREAT, "\n".join(kept), nl)

    if args.json:
        dump_json(args.json, {
            "generated": ts,
            "docs": [p.name for p in docs],
            "secrets": {"violations": [], "public_digest_exempt": skipped},
            "findings": {fid: result_payload(fid, res, rows)
                         for fid, res in results},
            "exit": 1 if lacking else 0,
        })

    print()
    if lacking:
        detail = ", ".join(fid for fid, _ in lacking)
        print("结论 : exit 1 —— %d/%d 条 finding 缺证据（%s），"
              "已标注为「假设，非发现」"
              % (len(lacking), len(results), detail))
        return 1
    print("结论 : exit 0 —— 全部 finding 四元组齐全")
    return 0

if __name__ == "__main__":
    sys.exit(main())
