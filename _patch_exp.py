# -*- coding: utf-8 -*-
"""补 EXPERIMENTS_NEEDED.md：总览加一行 + 新增 EXP-6（OAuth 授权模式）。"""
import io

P = r"D:\ddd\EXPERIMENTS_NEEDED.md"

raw = io.open(P, encoding="utf-8", newline="").read()
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")

ROW_OLD = ("| EXP-5 | T-3 | AV:A「需处于同一广播域/链路」（§3.3 AV 行） "
           "| 7.1 | 6.5 | 120 min | [ ] TODO |")
ROW_NEW = ROW_OLD + (
    "\n| EXP-6 | T-2 | OAuth 授权模式「token 受用户授权 scope 约束，"
    "S:U 成立」 | 维持 8.2（S:U） | 若为 client_credentials 且可读跨租户数据"
    " → 重评 9.3（S:C，§4 备选） | 20 min | [ ] TODO |")
assert text.count(ROW_OLD) == 1
text = text.replace(ROW_OLD, ROW_NEW, 1)

EXP6 = """### EXP-6  确认 OAuth 授权模式（T-2 的 S:U 反例边界）

> 编号说明：需求侧曾建议把本节编号为「EXP-2」，但 `EXP-2` 已被 T-1 的
> C/I 面实测占用（见 §1 总览）。为不破坏 `threat_model.md` /
> `qa_evidence.py` 中既有的 EXP-1..EXP-5 交叉引用，新增实验顺延为
> **EXP-6**，产物文件名同步为 `evidence/EXP-6_grant_type.txt`。

- 验证命题：`threat_model.md` §3.2 S 行的规范判据——"`access_token`
  仍受用户显式授权的 scope 约束，未越界至资源所有者（终端用户）的安全域"。
  该判据成立的**前提**是 token 由用户上下文换得（`authorization_code`
  等）；若为 `client_credentials`（无用户上下文），该论证失去依据，
  须重评 `S:C`。
- 若成立（带用户上下文的授权模式）→ 向量保持
  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`，Base = 8.2
- 若不成立（`client_credentials` 且 token 可读跨租户数据）→ 须重评
  `S:C`，回退向量 `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N`，Base = 9.3
  （§4 已发布备选，不新增分数）
- 前置条件：
  - 甲方书面授权；凭据 `YOUR_APPID_HERE` / `YOUR_APPSECRET_HERE`
  - token 接口：`TODO(NEED-EVIDENCE: 以平台官方文档确认 token 接口路径与
    参数名，填入 YOUR_PLATFORM_HOST/YOUR_TOKEN_PATH)`
  - 取证位置：发起换 token 的测试机（本机出网流量，无需中间人）
- 步骤：
  1. 记录本次取证的操作说明（谁、何时、触发什么动作）：
     `TODO(NEED-EVIDENCE: 手工写入 evidence\\EXP-6_grant_type.txt 首段：
     操作人 / 时间 / 触发的流程名 / 环境标识)`
  2. 优先走服务端日志取证（HTTPS 无需解密，证据链最短）：
     `TODO(NEED-EVIDENCE: 运维导出该 App 最近 24h 的 token 接口访问日志，
     只保留 grant_type 与时间戳，脱敏后落盘 evidence\\EXP-6_grant_type.txt)`
  3. 无法取服务端日志时，退化为本机抓包：
     `tshark -D`（先确认接口名），再
     `tshark -i YOUR_IFACE -f "tcp port 443" -w evidence\\EXP-6_grant_type.pcapng`
  4. 提取 grant_type（日志路径或 pcap 解析任选其一）：
     `Select-String -Path evidence\\EXP-6_grant_type.txt -Pattern 'grant_type=(authorization_code|client_credential[s]?)' | Select-Object -ExpandProperty Line`
  5. 若命中 `client_credential`，再判定能否跨租户（复用 EXP-4 的接口清单）：
     `TODO(NEED-EVIDENCE: 用该 token 访问 1 个非本 App 绑定租户的只读接口，
     记录是否返回他人数据，落盘 evidence\\EXP-6_cross_tenant.txt)`
- 判定标准：
  - **PASS（S:U 成立 → 维持 8.2）**：step4 命中 `authorization_code`
    或等价带用户上下文的模式；或虽命中 `client_credential`，但 step5
    只能读到本 App 自身租户数据。
  - **FAIL（S:U 失去依据 → 9.3）**：step4 命中 `client_credential` **且**
    step5 返回非本租户数据。此时 §2 与 §3.2 的 `S` 取值失去规范判据，
    须按 EXP-6 结论重评并在文首变更记录留痕（**本次不改动**）；
    回退分数由 `cvss_check.py` 现算确认：
    `python _re_workspace\\cvss_check.py "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"`
  - **未取证**：step2 与 step3 都失败 → 记"未取证"，**不得**默认维持
    S:U；§4 的"分数待 EXP-N 取证后冻结"继续有效。
- 产物路径：`evidence/EXP-6_grant_type.txt`（必需）、
  `evidence/EXP-6_grant_type.pcapng`（可选）、
  `evidence/EXP-6_cross_tenant.txt`（条件必需：命中 client_credentials 时）
- 预计耗时：20 min
- 状态：[ ] TODO

---

## 3. 完成后如何闭环（强制）"""

OLD_TAIL = """---

## 3. 完成后如何闭环（强制）"""
assert text.count(OLD_TAIL) == 1
text = text.replace(OLD_TAIL, EXP6, 1)

io.open(P, "w", encoding="utf-8", newline="").write(
    text.replace("\n", "\r\n") if crlf else text)
print("ok: %s（EXP-6 已追加，总览已加行）" % P)
