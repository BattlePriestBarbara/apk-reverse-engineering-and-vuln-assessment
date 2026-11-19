## 5. Temporal 与 Environmental 评分

> 本章不使用查表值：Base / Temporal / Environmental 三组分数与中间量（ISS、
> Impact、Exploitability、MISS、ModifiedImpact）全部由 `_re_workspace/cvss_check.py`
> 现场复算 —— 本章正文由 `--emit-block` 生成，`--verify` 反向逐项比对，
> 偏差写本文末「QA」行。Base 向量一个字母都不动（除非 EXP-1 判 FAIL）。

### 5.1 时间指标（Temporal）

| 威胁 | E（利用成熟度） | RL（修复级别） | RC（报告可信度） | 取值理由 |
| --- | --- | --- | --- | --- |
| T-1 | `P` | `O` | `U` | 签名算法已离线还原并做成 dry-run PoC（E:P）；P0-1 官方修复方案已随本路线图发布（RL:O）；证据四元组未闭合，报告可信度按未确认（RC:U） |
| T-2 | `P` | `O` | `U` | 平台侧换取 token 的路径已确认可执行（E:P）；P0-3 给出了官方处置方案（RL:O）；授权模式待 EXP-6 定稿（RC:U） |
| T-3 | `P` | `W` | `U` | 抓包取证已复现（E:P）；P0-2 是缓解而非改协议（RL:W）；影响面随网络位置波动（RC:U） |

> 符号：`E:P`=POC、`RL:O`=OF、`RL:W`=W、`RC:U`=UR。CVSS v3.1 的
> Report Confidence 只有 `X/U/R/C` 四个合法取值，委托指令写作 `RC:UR`，
> 按 `RC:U`（Unconfirmed）计算；若甲方改判 `RC:R`，Temporal 变为 T-1=7.9 / T-2=6.5 / T-3=5.9。

### 5.2 Base 与 Temporal 并列

| 威胁 | Base 向量 | Base | Temporal 向量 | Temporal | RC:R 备选 | 变化 |
| --- | --- | --- | --- | --- | --- | --- |
| T-1 | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` | **10.0** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:P/RL:O/RC:U` | **7.6** | 7.9 | -2.4 |
| T-2 | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` | **8.2** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:P/RL:O/RC:U` | **6.2** | 6.5 | -2.0 |
| T-3 | `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | **7.1** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N/E:P/RL:W/RC:U` | **5.6** | 5.9 | -1.5 |

> 向量串可直接粘进 CVSS v3.1 计算器核对（`CVSS:3.1/` + Base + `/E:../RL:../RC:..`）。
> Temporal 只可能下调当前风险；下调后同轴比较仍是 T-1 7.6 > T-2 6.2 > T-3 5.6，
> **修复优先级排序不变**——三项的相对次序在 Base / Temporal / Environmental
> 三组口径下一致，故排序不依赖口径选择。

### 5.3 环境指标（Environmental，等保三级数据分级）

CR / IR / AR 取 `H / H / M`（1.5 / 1.5 / 1.0）：政务数据分级里「保密性、
完整性」按最高档、「可用性」按中档计入。Modified 基向量未逐项改写，
故 `ModifiedScope` 随 `S` 取值（T-1 为 C，T-2/T-3 为 U），MISS 受 0.915 上限约束。

| 威胁 | CR | IR | AR | MISS | ModifiedImpact | 纯分级 Env | 完整 Env |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-1 | H(1.5) | H(1.5) | M(1.0) | 0.9150 | 6.1280 | **10.0** | **7.6** |
| T-2 | H(1.5) | H(1.5) | M(1.0) | 0.8928 | 5.7318 | **9.7** | **7.3** |
| T-3 | H(1.5) | H(1.5) | M(1.0) | 0.8928 | 5.7318 | **8.6** | **6.8** |

> 两列的差别只有一件事：**纯分级 Env** 把 E/RL/RC 留在 `X`（Not Defined，
> 系数 1.0），只看数据分级权重对 Impact 的抬升；**完整 Env** 再叠加 5.1 的
> 时间因子，即规范 §7.3 的 EnvironmentalScore 终值。两者都是合法向量组合。

> T-1 的「纯分级 Env」10.0 与 Base 10.0 同分：**Base 已封顶，Environmental
> 不改变分值，但确认 P0 处置优先级成立** —— Impact 与 Exploitability
> 之和在 1.08 系数下已越过 10.0 上限，任何 ≤1.5 的数据权重都
> 无法再抬高它，故这 10.0 是「下限即上限」，不是巧合。

> T-2 / T-3 的「纯分级 Env」高于 Base，属正常现象：Environment 允许
> 因数据分级（CR/IR=H）把 Impact 抬到 Base 之上；但三项的**排序在任何一
> 组口径下都不变**（T-1 > T-2 > T-3），故 P0 排期不依赖口径选择。

### 5.4 评分与合规映射的衔接（不再是两张皮）

本节的 CR/IR/AR 不是拍脑袋的 H/H/M，取值直接沿用 `remediation_plan.md`
**§7 合规映射** 的条款编号：等保 2.0 三级 **8.1.4.8**（数据保密性—密钥
管理）与 **8.1.4.2**（通信传输完整性/保密性）支撑 CR/IR 取 H；《个人信息
保护法》**第 6 条**（最小必要）约束 IR 不低于 M。反向也有对应：`threat_model.md`
§8 的优先级表与 `remediation_plan.md` §1 的 P0-1/P0-2/P0-3 一一对应
（T-1→P0-1、T-2→P0-3、T-3→P0-2），其 **§4 验收标准** 的 A-1/A-3/A-4 就是
三项威胁「修复后分数失效」的判定口；A-8 则把闭环延伸到泄露期检测（P0-5）。
合规与评分由此共用同一组条款号与同一个复核入口。

### 5.5 复算记录（机器可校验）

下面每行由 `cvss_check.py --emit-block` 生成，`--verify` 会按同一组向量
重算并逐项比对，偏差非 0 即 exit 1：

```text
CVSSREC T-1 ISS=0.8064 Impact=5.7576 Expl=3.8870 Base=10.0 Temporal=7.6 EnvPure=10.0 EnvFull=7.6
CVSSREC T-2 ISS=0.6568 Impact=4.2167 Expl=3.8870 Base=8.2 Temporal=6.2 EnvPure=9.7 EnvFull=7.3
CVSSREC T-3 ISS=0.6568 Impact=4.2167 Expl=2.8353 Base=7.1 Temporal=5.6 EnvPure=8.6 EnvFull=6.8
```

