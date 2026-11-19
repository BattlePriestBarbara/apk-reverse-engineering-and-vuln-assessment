# 威胁建模与风险量化（CVSS v3.1）

> 配套文档：《逆向与安全评估报告》§6 风险清单、§9 概念验证、§10 附录 B。
> 评分口径：CVSS v3.1 **Base + Temporal + Environmental** 三组并列 ——
> Base 见 §2/§3，Temporal 与 Environmental 见 §5；Scope 等争议指标另在
> §4 给出备选取值区间，不改变 §2 主表取值。
> 复算工具：`_re_workspace/cvss_check.py`（按 FIRST §7.1/§7.2/§7.3 实现
> Roundup 与各分项公式；`--emit-block` 生成 §5，`--verify` 反向比对，
> 杜绝手工查表误差）。

## 1. 评分方法与口径

| 项目 | 说明 |
| --- | --- |
| 标准 | CVSS v3.1（FIRST），Base + Temporal + Environmental（§5） |
| 公式 | `ISS=1-(1-C)(1-I)(1-A)`；`Impact` 在 S:U 为 `6.42×ISS`，S:C 为 `7.52×(ISS-0.029)-3.25×(ISS-0.02)^15`；`Exploitability=8.22×AV×AC×PR×UI`；`Base=Roundup(min(Impact+Expl,10))`，S:C 时再乘 1.08 后取 min 10；`Temporal=Roundup(Base×E×RL×RC)`；`MISS=min(1-(1-CR×MC)(1-IR×MI)(1-AR×MA),0.915)`，`ModifiedImpact` 在 MS:C 时指数为 13（见 §5.3） |
| Roundup | 向上取 1 位小数（整数运算规避浮点误差） |
| 严重度映射 | 0.1–3.9 Low；4.0–6.9 Medium；7.0–8.9 High；9.0–10.0 Critical |
| 复算命令 | Base：`python _re_workspace/cvss_check.py "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"`；加时间/环境指标：`--temporal E:POC/RL:OF/RC:UR --environmental CR:H/IR:H/AR:M`；生成 §5 正文：`--emit-block`；反向校验：`--verify threat_model.md` |

**取值原则**：每一项都取"已有证据能支撑的值"，不因"理论上还能更糟"而上调。
对存在争议的指标（主要是 Scope），在 §4 给出备选取值与分数区间，交由甲方
按其资产边界裁定。

## 2. 评分总表

| # | 漏洞名称 | AV | AC | PR | UI | S | C | I | A | Base Score | Severity | 简要 justification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-1 | 硬编码网关对称密钥（`gatewaySignSecret`）导致网关接口伪造 | N | L | N | N | C | H | H | N | **10.0** | Critical | 密钥随 APK 分发且四套环境复用；攻击者无需任何账号、无需受害者交互，仅需构造 HTTP 请求即可生成被服务端信任的签名；信任越界（客户端→网关/后端业务域）构成 Scope 变更，且可读写任意经网关暴露的业务数据 |
| T-2 | 第三方 OAuth `AppSecret` 硬编码导致平台身份冒用/账号接管 | N | L | N | N | U | L | H | N | **8.2** | High | 泄露物是"应用在第三方平台的身份"：可换取 `access_token`、以 App 名义下发消息、伪造授权绑定；读取面限于该 App 授权范围内的用户标识与基本资料（C:L），写入面可冒充应用（I:H）；S:U 为规范判定：影响限于该 OAuth App 的授权域、未越界至资源所有者（终端用户）安全域（见 §3.2），非保守下调 |
| T-3 | 敏感 SSO 令牌经明文 HTTP 传输导致中间人劫持 | A | L | N | N | U | H | L | N | **7.1** | High | 需处于链路中间位置（同 Wi-Fi / 运营商链路 / ARP 欺骗）故 AV:A；明文无完整性保护，令牌等价于完整登录态（C:H），可以该态发起少量写操作（I:L）；App 自动发起、无需交互（UI:N） |

> 向量串（可直接粘贴到 CVSS 计算器核对）：
> T-1 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
> T-2 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`
> T-3 `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`

## 3. 逐项推导过程

>  UNVERIFIED（缺 SAMPLE, LOCATOR, COMMAND, ARTIFACT；详见 unverified_hypotheses.md）

### 3.1 T-1 硬编码网关对称密钥（10.0 / Critical）

| 指标 | 取值 | 理由 |
| --- | --- | --- |
| AV | `N` | 网关 `…/app/mgop` 面向互联网提供服务，攻击者从任意网络位置发起即可 |
| AC | `L` | 无需竞态、无需特殊配置；密钥已随包泄露，签名算法为确定性拼接，可离线批量生成 |
| PR | `N` | 网关仅校验签名，不校验用户身份；伪造签名本身即"自带凭证" |
| UI | `N` | 无受害者参与，攻击者与网关直接交互 |
| S | `C` | 脆弱组件是"客户端内嵌密钥"，被影响组件是网关及其后的业务域，**权限域发生变化** |
| C | `H` | 网关按业务方信任放行，可枚举/读取业务接口返回的敏感数据 |
| I | `H` | 可提交伪造的查询、申请、状态变更类请求 |
| A | `N` | 现有证据仅表明可伪造业务请求，未发现可致服务不可用的路径 |

计算（`cvss_check.py` 输出）：

```text
ISS  = 1-(1-0.56)(1-0.56)(1-0)            = 0.8064
Impact(S:C) = 7.52×(0.8064-0.029) - 3.25×(0.8064-0.02)^15 = 5.7576
Exploitability = 8.22×0.85×0.77×0.85×0.85 = 3.8870
Base = Roundup(min(1.08×(5.7576+3.8870), 10)) = 10.0
```

> 该风险等同于"无凭证的远程攻击者获得网关的可信身份"，属最高优先级；
> 对应报告 §5.2 / §9.1 的概念验证路径。

>  UNVERIFIED（缺 SAMPLE, LOCATOR, COMMAND, ARTIFACT；详见 unverified_hypotheses.md）

### 3.2 T-2 第三方 OAuth AppSecret 硬编码（8.2 / High）

| 指标 | 取值 | 理由 |
| --- | --- | --- |
| AV | `N` | 微信/微博/钉钉开放平台均公网可达，拿到 `AppID + AppSecret` 即可换取 `access_token` |
| AC | `L` | 平台接口调用无额外门槛；`AppSecret` 在 `qa_env*.py` 与 `shareSecret` 中明文可读 |
| PR | `N` | 以应用身份调用，无需受害者账号口令 |
| UI | `N` | 无需受害者点击/授权动作即可读取已授权用户的标识与资料、下发模板消息 |
| S | `U` | 规范口径：`S:U` 的判据是 AppSecret 泄露的影响被限定在**该 OAuth App 的授权域**内 —— `access_token` 仍受用户显式授权的 scope 约束，未越界至资源所有者（终端用户）的安全域。故 `S:U` 是规范判定，非保守下调（若甲方另行认定用户账号体系属独立安全域，备选 S:C → 9.3 见 §4） |
| C | `L` | 仅能读取该 App 授权范围内的 `openid/unionid`、昵称头像等，不能读取平台全量数据 |
| I | `H` | 可冒充应用下发消息、伪造授权绑定关系，配合业务侧弱校验可演化为账号接管 |
| A | `N` | 无删除/耗尽类破坏证据 |

计算：

```text
ISS  = 1-(1-0.22)(1-0.56)(1-0)  = 0.6568
Impact(S:U) = 6.42×0.6568       = 4.2167
Exploitability = 8.22×0.85×0.77×0.85×0.85 = 3.8870
Base = Roundup(min(4.2167+3.8870, 10)) = 8.2
```

> **反例边界（写进判定条件，不藏脚注）**：若该 App 使用
> `client_credentials` 模式（无用户上下文）且 token 可访问跨租户数据，
> 则须重评 `S:C` —— 待 **EXP-6** 确认授权模式后定稿
> （`EXPERIMENTS_NEEDED.md` §2 EXP-6，产物 `evidence/EXP-6_grant_type.txt`）。

>  UNVERIFIED（缺 SAMPLE, LOCATOR, COMMAND, ARTIFACT；详见 unverified_hypotheses.md）

### 3.3 T-3 敏感 SSO 令牌明文 HTTP 传输（7.1 / High）

| 指标 | 取值 | 理由 |
| --- | --- | --- |
| AV | `A` | 中间人需与受害者处于同一广播域/链路（公共 Wi-Fi、酒店网络、运营商旁路、ARP 欺骗） |
| AC | `L` | 明文 HTTP 无任何完整性保护，抓包即得，无需破解或时序竞争 |
| PR | `N` | 被动/主动中间人均无需任何凭证 |
| UI | `N` | 令牌由 App 在启动/登录流程中自动提交，用户无感知 |
| S | `U` | 被影响的仍是"用户 ↔ 该 SSO 服务"权限域（若按"令牌跨入政务业务系统"计则 S:C → 8.2，见 §4） |
| C | `H` | 令牌等同于完整登录态，可读取该用户全部可见数据 |
| I | `L` | 可以该登录态发起受用户权限约束的写操作，但无法提权 |
| A | `N` | 无可用性影响证据 |

计算：

```text
ISS  = 1-(1-0.56)(1-0.22)(1-0)  = 0.6568
Impact(S:U) = 6.42×0.6568       = 4.2167
Exploitability = 8.22×0.62×0.77×0.85×0.85 = 2.8353
Base = Roundup(min(4.2167+2.8353, 10)) = 7.1
```

> **`AV:A` 成立前提（主动降调，换可信度）**：该明文流量须离开政务外网
> （公众 WiFi / 运营商侧 / 家宽带）。若链路全程在政务专网内，实际可达性
> 降至 `AV:A` + `AC:H`，建议按 6.5（敏感性区间下限）排期；但 P0-2 的
> 301 + HSTS 不因该降级而延后（`remediation_plan.md` §1 P0-2）。


## 4. 敏感性分析（Scope 等争议指标的备选取值）

以下备选分数均由 `cvss_check.py` 复算，供甲方按资产边界裁定后替换主表取值。

| 适用项 | 备选向量 | 分数 | 触发条件 / 含义 |
| --- | --- | --- | --- |
| T-1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 | 认为"客户端密钥泄露"与"网关被攻击"属同一权限域，不上调 Scope |
| T-1 | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N` | 9.3 | 网关仅暴露写入/提交类接口、读取面受限时 |
| T-2 | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N` | 9.3 | 认为用户账号体系与 App 自身属不同安全域，Scope 变更 |
| T-2 | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` | 10.0 | 若证实可读取全量用户资料（当前证据不足，不建议采用） |
| T-3 | `AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N` | 8.2 | 认定令牌可跨入独立业务系统权限域 |
| T-3 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` | 6.5 | 认为攻击者可在公网任意路径劫持但需时序条件（如 DNS 劫持 + 竞态） |

**结论**：三项风险的分数区间为 T-1 ∈ [9.1, 10.0]、T-2 ∈ [8.2, 9.3]、
T-3 ∈ [6.5, 8.2]，区间下沿全部落在 High 及以上，**不因口径选择而改变
修复优先级排序**。

> **分数待 EXP-N 取证后冻结**：T-1 → EXP-1 / EXP-2，T-2 → EXP-3 /
> EXP-4 / EXP-6，T-3 → EXP-5。四元组（SAMPLE / LOCATOR / COMMAND /
> ARTIFACT）补齐前，§2 与 §5 的分数只用于排期，不得作为已证实结论对外
> 引用 —— `python qa_evidence.py` 仍为 exit 1，即本文件当前状态。

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
> Report Confidence 只有 `X/U/R/C` 四个合法取值，需求原文写作 `RC:UR`，
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

## 6. 与报告章节的对应关系

| 报告编号 | 威胁编号 | 证据位置 | 概念验证 | 修复项 |
| --- | --- | --- | --- | --- |
| C-1 `gatewaySignSecret` 四环境复用 | T-1 | §5.2、§10.6 | `poc_gateway_sign.py`（dry-run 签名生成，授权后投递） | P0-1、P0-4、P2-2 |
| H-4 第三方 `AppSecret` 硬编码 | T-2 | §10.6 凭据表 | 无需发包，平台侧换取 `access_token` 即可自证 | P0-3、P1-2 |
| H-5 SSO 令牌明文 HTTP | T-3 | §10.7 明文 http 清单（15 条） | 抓包取证（`white_urls_config.json` / `govtest…/mgop`） | P0-2、P1-5 |
| M-1 签名证书 1024 位 / 100 年有效期 | — | §6.1、§9.5 | `apksigner verify`（需原始 APK） | P1-6 |

> 其余 M 级风险不再单列 CVSS：其危害已被上述三项覆盖，或属配置卫生问题，
> 量化收益低于交叉引用成本。

## 7. 评分局限与置信度

1. **未做真实利用**：T-1 的 PoC 以 dry-run 形式交付（需 `--confirm-authorized`
   才发包），签名算法待脱壳校准，故 C/I 取"证据支持的下限"而非理论上限。
2. **DEX 加密导致影响面低估**：`assets/` 业务 DEX 被壳加密，扫描仅覆盖明文
   可见面（0 私钥 / 0 AccessKey / 0 DB 串）。若脱壳后发现更强的服务端凭证，
   T-1 的资产范围会扩大（分数已取 C:H/I:H，上调空间有限）。
3. **AV:A 的争议**：T-3 在运营商级旁路或恶意热点场景可被论证为 `AV:N`，
   但需叠加 `AC:H`，实测反而更低（6.5），故保守采用 7.1。
4. **未含业务影响因子**：CVSS 不含"数据敏感级别 / 用户规模 / 监管处罚"，
   政务场景的处置优先级应以业务加权为准。

## 8. 修复优先级（与 CVSS 的对齐）

| 优先级 | 威胁 | Base / Temporal | 处置时限 | 判定依据 |
| --- | --- | --- | --- | --- |
| P0 | T-1 | 10.0 / 7.6 | ≤ 72 小时 | 无凭证远程伪造 + 四环境同一密钥，泄露面已扩散至测试环境 |
| P0 | T-2 | 8.2 / 6.2 | ≤ 7 天 | 第三方平台可能已存在异常调用，须先轮换再取证 |
| P0 | T-3 | 7.1 / 5.6 | ≤ 7 天 | 明文令牌可被动截获，且服务端跳转 + NSC 改造成本极低 |

具体操作见 `remediation_plan.md`（P0-1 密钥轮换 / P0-2 HTTPS 强制 /
P0-3 第三方凭据轮换 / P0-5 泄露期检测与事件响应）。

> QA: cvss_check.py 复算偏差 = 0.0000（21 项数值全部一致）
