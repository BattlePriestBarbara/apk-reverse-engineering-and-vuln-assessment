# -*- coding: utf-8 -*-
"""临时：校验 cvss_check 的 Base/Temporal/Environmental 实现。"""
import sys

sys.path.insert(0, r"D:\ddd\_re_workspace")
import cvss_check as C

CASES = [
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", 8.2),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N", 9.3),
    ("AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 7.1),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", 6.5),
    ("AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 8.2),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
]
bad = 0
for vec, want in CASES:
    got, _sev, _d = C.base_score(vec)
    flag = "OK " if abs(got - want) < 1e-9 else "BAD"
    bad += 0 if flag == "OK " else 1
    print("%s %-42s %5.1f (want %.1f)" % (flag, vec, got, want))

T = {
    "T-1": ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "E:POC/RL:OF/RC:UR"),
    "T-2": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", "E:POC/RL:OF/RC:UR"),
    "T-3": ("AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "E:POC/RL:W/RC:UR"),
}
print()
for fid, (vec, tspec) in T.items():
    ts, td = C.temporal_score(vec, tspec)
    ep, ed = C.environmental_score(vec, "CR:H/IR:H/AR:M", "")
    ef, edf = C.environmental_score(vec, "CR:H/IR:H/AR:M", tspec)
    base, _s, bd = C.base_score(vec)
    print("%s base=%.1f temp=%.1f (factor=%.6f) env_pure=%.1f "
          "(MISS=%.4f MImpact=%.4f Pre=%.1f) env_full=%.1f"
          % (fid, base, ts, td["factor"], ep, ed["MISS"], ed["MImpact"],
             ed["Pre"], ef))
    tr, _ = C.temporal_score(vec, "E:POC/RL:%s/RC:R" % (
        "W" if fid == "T-3" else "OF"))
    print("        RC:R 备选 temporal=%.1f" % tr)
print()
print("known: base9.8 + E:U/RL:O/RC:C ->",
      C.temporal_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "E:U/RL:OF/RC:C")[0])
print("bad =", bad)
