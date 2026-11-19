# -*- coding: utf-8 -*-
"""把本项目的中文 Markdown 报告转成 Word 可读的 HTML（供 Word COM 另存为 .doc）。

只支持本项目实际用到的子集：h1~h3、表格、围栏代码块、有序/无序列表、引用块、
段落，以及行内 `code` 与 **bold**。不做通用 Markdown 实现。
"""
from __future__ import annotations

import html
import io
import os
import re
import sys

CSS = """
@page { size: A4; margin: 1.8cm 1.6cm; }
body { font-family: "Microsoft YaHei", "微软雅黑", SimSun, serif;
       font-size: 10.5pt; line-height: 1.45; color: #1a1a1a; }
h1 { font-size: 20pt; text-align: center; margin: 0 0 4pt 0; }
h2 { font-size: 14pt; margin: 14pt 0 5pt 0; padding-bottom: 3pt;
     border-bottom: 1pt solid #9bb3d4; page-break-after: avoid; }
h3 { font-size: 11.5pt; margin: 10pt 0 3pt 0; page-break-after: avoid; }
p { margin: 2.5pt 0; }
ul, ol { margin: 2.5pt 0 2.5pt 16pt; }
li { margin: 1.5pt 0; }
table { border-collapse: collapse; width: 100%; margin: 5pt 0 7pt 0;
        font-size: 8.5pt; }
th, td { border: 0.5pt solid #808080; padding: 2pt 4pt; vertical-align: top; }
th { background: #e8eef7; font-weight: bold; text-align: left; }
pre { font-family: Consolas, "Courier New", monospace; font-size: 8pt;
      background: #f5f5f5; border: 0.5pt solid #c0c0c0; padding: 4pt;
      margin: 4pt 0; white-space: pre-wrap; }
blockquote { margin: 4pt 0 4pt 10pt; padding-left: 7pt;
             border-left: 2.5pt solid #9bb3d4; color: #333; }
code { font-family: Consolas, "Courier New", monospace; font-size: 9pt;
       color: #a31515; }
th code, td code { font-size: 8pt; }
.note { font-size: 9pt; color: #555; margin-top: 14pt;
        border-top: 0.5pt solid #ccc; padding-top: 4pt; }
"""


def inline(text: str) -> str:
    """行内标记：先转义，再处理 code 与 bold。"""
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return text


def split_row(line: str) -> list:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def is_sep(line: str) -> bool:
    return bool(re.fullmatch(r"\|[\s:\-|]+\|", line.strip()))


def convert(md: str, src_name: str = "") -> str:
    lines = md.splitlines()
    title = next((l[2:].strip() for l in lines if l.startswith("# ")),
                 "安全评估综合报告")
    out = [
        '<html><head><meta charset="utf-8"><title>%s</title>' % html.escape(title),
        "<style>%s</style></head><body>" % CSS,
    ]
    i, n = 0, len(lines)
    state = {"list": None}
    para = []

    def flush_para():
        if para:
            raw = "".join(para)
            del para[:]
            m = re.fullmatch(r"\*\*(.+)\*\*", raw.strip())
            if m and out and out[-1].startswith("<h1>"):
                out.append('<p class="sub">%s</p>' % inline(m.group(1)))
            else:
                out.append("<p>%s</p>" % inline(raw))

    def close_list():
        if state["list"]:
            out.append("</%s>" % state["list"])
            state["list"] = None

    while i < n:
        stripped = lines[i].strip()

        if stripped.startswith("```"):
            flush_para()
            close_list()
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append("<pre>%s</pre>" % html.escape("\n".join(buf)))
            continue

        if stripped.startswith("|") and i + 1 < n and is_sep(lines[i + 1]):
            flush_para()
            close_list()
            header = split_row(lines[i])
            out.append("<table><tr>%s</tr>"
                       % "".join("<th>%s</th>" % inline(c) for c in header))
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                cells = split_row(lines[i])
                cells += [""] * (len(header) - len(cells))
                out.append("<tr>%s</tr>"
                           % "".join("<td>%s</td>" % inline(c) for c in cells))
                i += 1
            out.append("</table>")
            continue

        m = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if m:
            flush_para()
            close_list()
            level = len(m.group(1))
            out.append("<h%d>%s</h%d>" % (level, inline(m.group(2)), level))
            i += 1
            continue

        if stripped.startswith(">"):
            flush_para()
            close_list()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip())
                i += 1
            body = "".join("<p>%s</p>" % inline(s) for s in buf if s)
            out.append("<blockquote>%s</blockquote>" % body)
            continue

        m = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m:
            flush_para()
            if state["list"] != "ol":
                close_list()
                out.append("<ol>")
                state["list"] = "ol"
            out.append("<li>%s</li>" % inline(m.group(2)))
            i += 1
            continue

        if stripped.startswith("- "):
            flush_para()
            if state["list"] != "ul":
                close_list()
                out.append("<ul>")
                state["list"] = "ul"
            out.append("<li>%s</li>" % inline(stripped[2:]))
            i += 1
            continue

        if not stripped:
            flush_para()
            close_list()
            i += 1
            continue

        para.append(stripped)
        i += 1

    flush_para()
    close_list()
    out.append('<p class="note">本文档由 Markdown 源文件'
               "《%s》转换生成，"
               "源文件为唯一修订入口。</p>" % src_name)
    out.append("</body></html>")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: _md2doc.py <input.md> <output.html>")
        return 2
    md = io.open(sys.argv[1], encoding="utf-8").read()
    doc = convert(md, os.path.basename(sys.argv[1]))
    io.open(sys.argv[2], "w", encoding="utf-8-sig", newline="\r\n").write(doc)
    print("wrote %s (%d chars)" % (sys.argv[2], len(doc)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

