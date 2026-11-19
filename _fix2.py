# -*- coding: utf-8 -*-
"""小修：术语措辞 + §8 优先级表的 CVSS 列改为 Base / Temporal（脚本取值）。"""
import io
import sys

sys.path.insert(0, r"D:\ddd\_re_workspace")
import cvss_check as C

DOC = r"D:\ddd\threat_model.md"
PY = r"D:\ddd\_re_workspace\cvss_check.py"


def load(path):
    """读入并按 CRLF 归一，返回 (文本, 是否 CRLF)。"""
    raw = io.open(path, encoding="utf-8", newline="").read()
    return raw.replace("\r\n", "\n"), "\r\n" in raw


def save(path, text, crlf):
    """按原换行风格写回 UTF-8。"""
    io.open(path, "w", encoding="utf-8", newline="").write(
        text.replace("\n", "\r\n") if crlf else text)


def swap(text, old, new, label):
    """唯一命中替换。"""
    assert text.count(old) == 1, "%s: count=%d" % (label, text.count(old))
    return text.replace(old, new, 1)


# --- 1. 措辞：委托指令 -> 需求原文（两个文件各一处）----------------
for path in (PY, DOC):
    text, crlf = load(path)
    text = swap(text, "委托指令写作 `RC:UR`", "需求原文写作 `RC:UR`",
                "wording:" + path)
    save(path, text, crlf)
    print("wording ok:", path)

# --- 2. §8 优先级表：CVSS 列并列 Base / Temporal -------------------
text, crlf = load(DOC)
text = swap(text, "| 优先级 | 威胁 | CVSS | 处置时限 | 判定依据 |",
            "| 优先级 | 威胁 | Base / Temporal | 处置时限 | 判定依据 |",
            "s8-head")
for find in C.FINDINGS:
    m = C.measure(find)
    fid = find["id"]
    old = "| P0 | %s | %s | " % (fid, C._fmt(m["base"]))
    new = "| P0 | %s | %s / %s | " % (fid, C._fmt(m["base"]),
                                      C._fmt(m["temporal"]))
    text = swap(text, old, new, "s8-" + fid)
save(DOC, text, crlf)
print("s8 ok")
