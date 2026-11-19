# -*- coding: utf-8 -*-
"""一次性补丁：threat_model.md（补 §5 / 修 T-2 Scope / 加 T-3 前提 / 冻结行）。

所有替换都断言"原文恰好出现一次"，找不到即中止，避免把文档改坏。
"""
import io

P = r"D:\ddd\threat_model.md"
SEC5 = r"D:\ddd\_sec5.md"

raw = io.open(P, encoding="utf-8", newline="").read()
text = raw.replace("\r\n", "\n")
log = []


def sub(old, new, label):
    """断言唯一命中后替换。"""
    global text
    n = text.count(old)
    assert n == 1, "%s: count=%d" % (label, n)
    text = text.replace(old, new, 1)
    log.append(label)


# --- 1. 文首口径说明 ------------------------------------------------
sub("""> 评分口径：CVSS v3.1 **基础指标（Base Metrics）**，不含 Temporal 与
> Environmental —— 后者取决于客户实际部署与补偿控制，单列敏感性分析。
> 复算工具：`_re_workspace/cvss_check.py`（按 FIRST 规范实现 Roundup 与
> 各分项公式，可对任意向量复算，杜绝手工查表误差）。""",
    """> 评分口径：CVSS v3.1 **Base + Temporal + Environmental** 三组并列 ——
> Base 见 §2/§3，Temporal 与 Environmental 见 §5；Scope 等争议指标另在
> §4 给出备选取值区间，不改变 §2 主表取值。
> 复算工具：`_re_workspace/cvss_check.py`（按 FIRST §7.1/§7.2/§7.3 实现
> Roundup 与各分项公式；`--emit-block` 生成 §5，`--verify` 反向比对，
> 杜绝手工查表误差）。""", "head-note")

# --- 2. §1 口径表 ---------------------------------------------------
sub("| 标准 | CVSS v3.1（FIRST），仅 Base 组 |",
    "| 标准 | CVSS v3.1（FIRST），Base + Temporal + Environmental（§5） |",
    "s1-standard")

sub("""`Base=Roundup(min(Impact+Expl,10))`，S:C 时再乘 1.08 后取 min 10 |""",
    """`Base=Roundup(min(Impact+Expl,10))`，S:C 时再乘 1.08 后取 min 10；`Temporal=Roundup(Base×E×RL×RC)`；`MISS=min(1-(1-CR×MC)(1-IR×MI)(1-AR×MA),0.915)`，`ModifiedImpact` 在 MS:C 时指数为 13（见 §5.3） |""",
    "s1-formula")

sub("""| 复算命令 | `python _re_workspace/cvss_check.py "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"` |""",
    """| 复算命令 | Base：`python _re_workspace/cvss_check.py "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"`；加时间/环境指标：`--temporal E:POC/RL:OF/RC:UR --environmental CR:H/IR:H/AR:M`；生成 §5 正文：`--emit-block`；反向校验：`--verify threat_model.md` |""",
    "s1-cmd")

# --- 3. §2 总表：T-2 的 Scope 措辞改规范口径 ------------------------
sub("按同域（应用 ↔ 其平台账号）保守取 S:U",
    "S:U 为规范判定：影响限于该 OAuth App 的授权域、未越界至"
    "资源所有者（终端用户）安全域（见 §3.2），非保守下调",
    "s2-t2-scope")

# --- 4. §3.2 T-2：S 行改规范口径 + 反例边界 -------------------------
sub("""| S | `U` | 攻击者与被影响对象同处"该应用 ↔ 其第三方平台账号"这一权限域（若甲方认为用户账号体系属独立安全域，则升为 S:C → 9.3，见 §4） |""",
    """| S | `U` | 规范口径：`S:U` 的判据是 AppSecret 泄露的影响被限定在**该 OAuth App 的授权域**内 —— `access_token` 仍受用户显式授权的 scope 约束，未越界至资源所有者（终端用户）的安全域。故 `S:U` 是规范判定，非保守下调（若甲方另行认定用户账号体系属独立安全域，备选 S:C → 9.3 见 §4） |""",
    "s32-s-row")

sub("""Base = Roundup(min(4.2167+3.8870, 10)) = 8.2
```""",
    """Base = Roundup(min(4.2167+3.8870, 10)) = 8.2
```

> **反例边界（写进判定条件，不藏脚注）**：若该 App 使用
> `client_credentials` 模式（无用户上下文）且 token 可访问跨租户数据，
> 则须重评 `S:C` —— 待 **EXP-6** 确认授权模式后定稿
> （`EXPERIMENTS_NEEDED.md` §2 EXP-6，产物 `evidence/EXP-6_grant_type.txt`）。""",
    "s32-counterexample")

# --- 5. §3.3 T-3：AV:A 成立前提（主动降调） --------------------------
sub("""Base = Roundup(min(4.2167+2.8353, 10)) = 7.1
```""",
    """Base = Roundup(min(4.2167+2.8353, 10)) = 7.1
```

> **`AV:A` 成立前提（主动降调，换可信度）**：该明文流量须离开政务外网
> （公众 WiFi / 运营商侧 / 家宽带）。若链路全程在政务专网内，实际可达性
> 降至 `AV:A` + `AC:H`，建议按 6.5（敏感性区间下限）排期；但 P0-2 的
> 301 + HSTS 不因该降级而延后（`remediation_plan.md` §1 P0-2）。""",
    "s33-premise")

# --- 6. §4 末尾：分数冻结声明 + 插入新的 §5 -------------------------
FREEZE = """> **分数待 EXP-N 取证后冻结**：T-1 → EXP-1 / EXP-2，T-2 → EXP-3 /
> EXP-4 / EXP-6，T-3 → EXP-5。四元组（SAMPLE / LOCATOR / COMMAND /
> ARTIFACT）补齐前，§2 与 §5 的分数只用于排期，不得作为已证实结论对外
> 引用 —— `python qa_evidence.py` 仍为 exit 1，即本文件当前状态。"""

sec5 = io.open(SEC5, encoding="utf-8").read().replace("\r\n", "\n").strip("\n")
sub("## 5. 与报告章节的对应关系",
    FREEZE + "\n\n" + sec5 + "\n\n## 6. 与报告章节的对应关系",
    "insert-sec5")

# --- 7. 章节重编号：原 §6 / §7 → §7 / §8 ---------------------------
sub("## 6. 评分局限与置信度", "## 7. 评分局限与置信度", "renum-6")
sub("## 7. 修复优先级（与 CVSS 的对齐）",
    "## 8. 修复优先级（与 CVSS 的对齐）", "renum-7")

# --- 8. 文末交接补 P0-5（与 remediation 同步） ----------------------
sub("""具体操作见 `remediation_plan.md`（P0-1 密钥轮换 / P0-2 HTTPS 强制 /
P0-3 第三方凭据轮换）。""",
    """具体操作见 `remediation_plan.md`（P0-1 密钥轮换 / P0-2 HTTPS 强制 /
P0-3 第三方凭据轮换 / P0-5 泄露期检测与事件响应）。""",
    "tail-p05")

io.open(P, "w", encoding="utf-8", newline="").write(
    text.replace("\n", "\r\n"))
print("已写入 %s" % P)
print("实际生效的替换：%d 处 -> %s" % (len(log), ", ".join(log)))

