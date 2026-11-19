# -*- coding: utf-8 -*-
"""把 PowerShell 重定向出来的 UTF-16 日志转成 UTF-8，便于读取。"""
import io
import sys

for name in sys.argv[1:]:
    text = io.open(name, encoding="utf-16", errors="replace").read()
    out = name.replace(".txt", "b.txt")
    io.open(out, "w", encoding="utf-8", newline="\n").write(text)
    print("->", out)
