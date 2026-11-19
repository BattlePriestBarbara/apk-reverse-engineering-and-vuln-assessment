# -*- coding: utf-8 -*-
"""去掉 _patch_rem.py 重跑造成的 B1b 重复块（第 56-95 行中的第二份）。"""
import io

P = r"D:\ddd\remediation_plan.md"
raw = io.open(P, encoding="utf-8", newline="").read()
crlf = "\r\n" in raw
L = raw.replace("\r\n", "\n").split("\n")

idx = [n for n, l in enumerate(L) if l.startswith("**轮换强度与回滚")]
assert len(idx) == 2, idx
a, b = idx
assert L[a:b] == L[b:b + (b - a)], "两段内容不一致"
assert L[b + (b - a)].startswith("### P0-2"), L[b + (b - a)]
del L[b:b + (b - a)]
out = "\n".join(L)
assert out.count("**轮换强度与回滚") == 1
assert out.count("### P0-2 明文 HTTP") == 1
io.open(P, "w", encoding="utf-8", newline="").write(
    out.replace("\n", "\r\n") if crlf else out)
print("dedupe ok: removed lines %d-%d" % (b + 1, b + (b - a)))
