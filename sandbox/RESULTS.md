# 攻击模拟结果（离线靶场）

- **样本**：`<APK_DIR>`（已解码 APK）中逆向得到的网关签名契约
- **执行**：`python sandbox/attack_sim.py --json sandbox/attack_result.json`
- **产物**：`sandbox/attack_result.json`（sha256 `<REDACTED-PARTIAL>`）、
  `evidence/EXP-8_sandbox_attack.txt`（stdout 全文）
- **流量**：0 —— 进程内调用 + NetGuard 拦截 + 容器侧 `--network none`
- **退出码**：0（8 场景 × 3 剖面 = 24 组断言全部成立）

## 1. 实验条件

| 项目 | 取值 | 说明 |
| --- | --- | --- |
| 时间基准 | 固定 `NOW_MS` | 与墙钟解耦，结果可复现 |
| 网关基线 | `as4134` + `dev-known-1`，P99 = 120 次/小时 | 模拟"正常的 30 天基线" |
| 限速阈值 | 3 × P99 = 360 次/小时 | 与 `remediation_plan.md` P0-5 同口径 |
| 时间窗 | ±300 秒 | 同上 |
| 密钥 | `LAB_ONLY_OLD_KEY_NOT_REAL` / `LAB_ONLY_NEW_KEY_NOT_REAL` | 显式占位，非真实凭据 |

## 2. 结果矩阵

| 场景 | 攻击手法 | baseline（现状） | hardened（双钥+检测） | rotated（旧钥吊销） |
| --- | --- | --- | --- | --- |
| A1 | 泄露旧钥伪造签名 | 200 | 200（打标 v1_offasn + v1_newdevice） | 401 |
| A2 | 签名原样重放 | 200 → 200 | 200 → 401（replay） | 401 → 401 |
| A3 | 时间戳回拨 600 秒 | 200 | 401（ts_window） | 401 |
| A4 | 版本降级（v1 钥报 v2） | 200 | 401（keyver_mismatch） | 401 |
| A5 | 未签名参数注入 amount | 200（amount 生效） | 400（unsigned_param） | 401 |
| A6 | 单来源 900 次/小时 | 200 × 900 | 200 × 360 + 429 × 540（v1_burst） | 401 × 900 |
| A7 | 新钥 + 陌生来源（对照） | 401（现状无 v2 分支） | 200，无打标 | 200，无打标 |
| A8 | 缺设备指纹 | 200（计算 headless 但不消费） | 200（headless 打标） | 401 |

## 3. 逐条解读

**A1 是本次最重要的一条。** `baseline` 直接 200：任何人拿到 APK 里的
`gatewaySignSecret` 就能为任意业务请求签名，这与 `threat_model.md` T-1
（10.0 / Critical）的判定完全一致。`hardened` 也返回 200，只多两个打标——
这不是实现缺陷，而是**刻意复刻"旧钥尚未吊销"的窗口期**：只要 v1 还在
keyring 里，验签就会成功，检测只能"看见"不能"挡住"。只有 `rotated`
（v1 移出 keyring）才是 401。**结论：P0-1 的根因修复是轮换，不是检测。**

**A2～A4 属于同一类"协议实现缺口"。** 现状网关不校验 nonce 重放、不校验
时间窗、不把 keyver 纳入签名，所以三条全部 200。补齐后它们分别落到
`replay` / `ts_window` / `keyver_mismatch`。其中 A4 值得单列：它说明
"自报版本"若只放在 header 而不进签名，等于给攻击者一个免费开关——这也
反证了 `poc_gateway_sign.py` 里把 `keyver` 写进 payload 的设计是必要的。

**A5 是一条独立的参数完整性缺陷。** 它不依赖密钥泄露的"后续利用"，而是
签名覆盖面本身不足：只签 `appKey/timestamp/nonce` 时，夹带的 `amount`
会原样进入业务层（baseline 的 `applied` 里确实出现了 `amount`）。补
参数白名单后 400 直接拒。

**A6 说明限速必须是服务端行为。** baseline 900 次全部 200；hardened 到
360 次开始 429，并打 `v1_burst`。注意阈值是"3 × P99"，P99 缺失时应
跳过而非按 0 处理（这条在 `tests/test_poc_oracle.py` 的冷启动用例里已覆盖）。

**A7 是防误报的对照组。** 新钥 v2 + 陌生来源 + 陌生设备，`hardened` 与
`rotated` 都是 200 且**零打标**——证明 P0-5 的 R-1/R-2 只对旧钥生效，
不会把正常的新用户打成攻击者。`baseline` 之所以 401，是因为现状根本没有
v2 分支（这本身也是一个发现：**轮换前必须先具备双钥并行能力**）。

**A8 说明"缺失设备指纹"是可观测信号。** `headless` 打标在三个剖面都会
计算，差别只在是否被消费；rotated 下先因旧钥被拒（401），到了检测层之前
就结束了。

## 4. 与整改项的映射

| 攻击 | 阻断它的整改项 | 只打标的整改项 | 残余风险 |
| --- | --- | --- | --- |
| A1 | P0-1 轮换（v1 下线） | P0-5 R-1/R-2 | 轮换完成前，泄露钥始终可用 |
| A2 | nonce 去重（P0-4） | — | 需要服务端共享 nonce 存储 |
| A3 | 时间窗校验（P0-4） | — | 客户端时钟漂移需容忍度配置 |
| A4 | keyver 参与签名（P0-1） | P0-5 R-1 | 旧客户端若不支持 keyver 需灰度 |
| A5 | 参数白名单 / 全参签名（P0-4） | — | 需逐接口梳理可签字段 |
| A6 | 服务端限速（P0-5 R-3） | `v1_burst` 告警 | 分布式来源需按 ASN 聚合 |
| A7 | —（对照组） | — | 若基线本身缺失，误报会淹没告警 |
| A8 | 设备指纹强校验 | `headless` 打标 | 指纹可伪造，只作辅助信号 |

## 5. 复现

```bash
# 宿主（零 socket，NetGuard 兜底）
python sandbox/attack_sim.py --json sandbox/attack_result.json

# 容器（更强隔离；本地须已有 python:3.12-slim，脚本绝不 pull）
sh sandbox/run_in_docker.sh
docker compose -f sandbox/docker-compose.yml run --rm lab

# 回归
python -m unittest tests.test_sandbox_attacks -v
```

## 6. 局限

1. 靶场是**契约复刻**，不是被测网关本体。它证明"按文档实现能拦住这些
   攻击"，不证明线上已如此实现；线上验证属 A-8b。
2. `X-Key-Ver` 是自报头，仅用于取标签，不参与鉴权；真实版本由"哪把钥
   验通"决定。
3. 未模拟分布式来源（多 ASN 轮换）、未模拟真实业务参数语义（`amount`
   只是占位字段名），因此 A5/A6 的结论是"机制成立"，不是"金额可改"。
4. 本机 Docker 引擎不可用（Docker Desktop 无法启动，缺 WSL 引擎数据盘），
   容器路径**未实跑**；宿主路径已实跑并与容器共用同一份脚本与断言。
