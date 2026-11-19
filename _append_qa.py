# -*- coding: utf-8 -*-
"""把 cvss_check.py --verify 生成的 QA 行原样追加到文末（不手写数值）。"""
import io

DOC = r"D:\ddd\threat_model.md"
QA = r"D:\ddd\_qa.txt"

qa = io.open(QA, encoding="utf-8").read().strip()
assert qa.startswith("QA: cvss_check.py"), qa
text = io.open(DOC, encoding="utf-8", newline="").read()
assert "QA: cvss_check.py" not in text, "文末已有 QA 行"
body = text.rstrip("\r\n") + "\r\n\r\n> " + qa + "\r\n"
io.open(DOC, "w", encoding="utf-8", newline="").write(body)
print("追加：", qa)
