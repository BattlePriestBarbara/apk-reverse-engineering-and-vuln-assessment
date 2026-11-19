# -*- coding: utf-8 -*-
"""Markdown 结构自检（沿用 _re_workspace/qa_md.py 的三条规则）：
代码围栏配对、表格列数一致、标题不重复。
"""
import io
import re
import sys
from collections import Counter

bad_total = 0
for p in sys.argv[1:]:
    lines = io.open(p, encoding="utf-8").read().splitlines()
    fences, tbl, bad = 0, [], 0
    for i, l in enumerate(lines, 1):
        if l.strip().startswith("```"):
            fences += 1
        if l.startswith("|"):
            tbl.append((i, l))
        else:
            if tbl:
                head = tbl[0][1].count("|")
                for n, t in tbl:
                    if t.count("|") != head:
                        print("%s 列数不一致 line %d（期望 %d 实际 %d）: %s"
                              % (p, n, head, t.count("|"), t[:60]))
                        bad += 1
                tbl = []
    heads = [l for l in lines if re.match(r"^#{2,3} ", l)]
    dup = [h for h, c in Counter(heads).items() if c > 1]
    bad_total += bad
    print("%s | 围栏 %d（%s）| 表格问题 %d | 重复标题 %s | 行数 %d"
          % (p.split("\\")[-1], fences,
             "配对" if fences % 2 == 0 else "★未闭合", bad,
             dup if dup else "无", len(lines)))
print("合计问题 =", bad_total)
sys.exit(0 if bad_total == 0 else 1)
