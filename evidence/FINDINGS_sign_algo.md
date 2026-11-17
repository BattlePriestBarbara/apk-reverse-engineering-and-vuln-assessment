# FINDINGS_sign_algo —— EXP-1 取证结论（拼接模板与失败分支）

> 状态：**BLOCKED（未取证）**。本文件目前只定义"要回答什么、用什么证据回答"，
> 不含任何结论。空白处必须用 `evidence/golden_samples.json` 里的真实采样填充，
> 填之前一律保持 `TODO(NEED-EVIDENCE: ...)`。

## 0. 取证前置（当前全部缺失）

| 项 | 值 | 状态 |
| --- | --- | --- |
| 样本 APK | 解包树 `<APK_DIR>`（`classes.dex` / `AndroidManifest.xml` / `lib/`）存在，**原始 `.apk` 文件缺失** | 缺 apk |
| 包名 | `com.example.govapp.activity`（源：解包树 `AndroidManifest.xml` 的 provider authorities，与报告 §1 一致） | 已确认（静态） |
| 启动组件 | `com.example.govbase.gov.main.LoadingActivity` | 已确认（静态） |
| 测试环境域名 TEST_HOST | `TODO(NEED-EVIDENCE: 工单里的测试环境域名)` | 缺 |
| 授权工单号 | `TODO(NEED-EVIDENCE: X-Authorized-Pentest 工单号)` | 缺 |
| frida-server 版本 | `TODO(NEED-EVIDENCE: adb shell /data/local/tmp/frida-server --version)` | 缺 |
| 设备 / adb | 本机无 `adb`，`frida-ls-devices` 只有 local/barebone/socket（无 Android 设备） | 缺 |

## 0b. 静态预判（来自解包样本，可复核，但不是运行时证据）

| 观察 | 数值 | 取证含义 |
| --- | --- | --- |
| `classes.dex` 中字符串 `gatewaySignSecret` | 1 处 | 密钥名在明文 dex 内可定位，说明签名逻辑大概率在 **Java 层** |
| `classes.dex` 中字符串 `HmacSHA256` | 6 处 | 与 `Mac.doFinal:HmacSHA256` 的预期 hook 点吻合 |
| `lib/arm64-v8a/*.so` 中 `Java_*nativeSign` 类符号 | 0 个 | "签名在 so 内"这条路**静态不可证**；不排除 `RegisterNatives` 动态注册 |
| `lib/arm64-v8a` 中 `Java_*Sign*` 命中 | 8 个，均为第三方 | 商汤活体、CNTrust 外签、**邦邦 APK 签名校验** `Java_android_utils_Signature_getSignature`、微博 OAuth |
| `classes.dex` 中 `<HOST-17>` | 488 处 | App 内部大量硬编码**生产域名**，运行即可能访问生产 —— 故 `frida_dump_sign.js` 在 `okhttp3.Request$Builder.build` 里对生产域名抛 `IOException` 硬阻断，宿主侧再 `exit 5` |

> 陷阱：`libsignature_balanar.so` 的 `Java_android_utils_Signature_getSignature`
> 是**邦邦的 APK 签名指纹校验**，不是网关签名。`frida_dump_sign.js` 已用
> `NATIVE_DENY` 把它连同商汤/微博符号一起排除，避免误取证。

## a) 拼接模板到底是什么？


**待回答**：待签原文的字段顺序、分隔符（`&` 还是 `|`）、是否先做 body
MD5、`timestamp`/`nonce` 的位置。

**唯一可接受的证据**：`javax.crypto.Mac.doFinal` 或
`MessageDigest.doFinal` 的入参 `MSG` 字段（hex + ascii 片段），即日志行

```
[HOOK=Mac.doFinal:HmacSHA256/1] [KEY=……(len=N)] [MSG=……(len=N)] [OUT=……] ...
```

`MSG` 的 ascii 片段（`golden_samples.json` 里的 `payload_ascii`）必须能看出
键名与分隔符；`sorted_kv` 只有在该片段确实是 `k=v` 拼接时才非空。

| 结论项 | 结论 | 证据（seq / HOOK / 片段） |
| --- | --- | --- |
| 算法 | `TODO(NEED-EVIDENCE: Mac 算法名取自 [HOOK=Mac.doFinal:<algo>])` | — |
| 字段顺序 | `TODO(NEED-EVIDENCE: 引用 payload_ascii 前 120 字符)` | — |
| 分隔符 | `TODO(NEED-EVIDENCE: 看 MSG ascii 里的分隔符是 & 还是竖线)` | — |
| 是否含 body 摘要 | `TODO(NEED-EVIDENCE: 对比 GET/POST 两类接口的 MSG)` | — |
| timestamp 单位 | `TODO(NEED-EVIDENCE: 提取的 13 位 vs 10 位)` | — |

## b) 失败分支行为（坏签名发到测试环境）

**待回答**：把 `sign` 改坏后，测试环境返回 401 / 403 / 还是 200 + 业务降级？

**唯一可接受的证据**：一次带 `X-Authorized-Pentest` 头、只打 TEST_HOST 的
请求记录（HTTP 码 + body 前 200 字节）。

```bash
# TODO(NEED-EVIDENCE: 用 golden_samples.json 的 payload_raw 回放，sign 改坏)
# 必须带 TEST_HOST 与 X-Authorized-Pentest，禁止打生产域名
```

| 项 | 值 | 状态 |
| --- | --- | --- |
| HTTP 状态码 | `TODO(NEED-EVIDENCE: curl -w '%{http_code}')` | 缺 |
| body 前 200 字节 | `TODO(NEED-EVIDENCE: 同上，脱敏后贴)` | 缺 |
| 是否返回业务数据 | `TODO(NEED-EVIDENCE: 判断 200 是否含真实业务字段)` | 缺 |

> 该结果决定 T-1 的 `I:H` 是否站得住：若坏签名仍返回 200 且带业务数据，
> `I` 需下调（具体值需人工重算 CVSS，本文件不预置任何分数）。

## c) 密钥同一性（EXP-1 核心）

| 项 | 值 | 状态 |
| --- | --- | --- |
| A 组样本数 | `TODO(NEED-EVIDENCE: collect_golden.py --device-label A)` | 缺 |
| B 组样本数 | `TODO(NEED-EVIDENCE: collect_golden.py --device-label B)` | 缺 |
| A 组 key_sha256 | `TODO(NEED-EVIDENCE: compare_keys.py 输出)` | 缺 |
| B 组 key_sha256 | `TODO(NEED-EVIDENCE: compare_keys.py 输出)` | 缺 |
| 判定 | `TODO(NEED-EVIDENCE: compare_keys.py 的 [VERDICT])` | 缺 |

判定规则（已实现于 `evidence/compare_keys.py`）：

- 10/10 一致 → `GLOBAL_SECRET` → T-1 保持 `S:C / AV:N / PR:N`，Base 10.0
- 出现任何不一致 → `PER_INSTANCE` → T-1 回退 `S:U`，Base 9.1

## d) 运行手册（样本到手后照抄）

```powershell
# 0) 设备：frida-server 已起，App 已安装
set TARGET_PACKAGE=com.example.govapp.activity
set TEST_HOST=YOUR_TEST_HOST
set PENTEST_TICKET=YOUR_TICKET

# 1) 先干跑校验（不连设备、不落盘）
python evidence/collect_golden.py --dry-run

# 2) 设备 A（账号甲）采 3 接口 x 3 轮
python evidence/collect_golden.py --device-label A --sid A

# 3) 设备 B（账号乙 / 清数据重装）再采一轮
python evidence/collect_golden.py --device-label B --sid B --append

# 4) 判定（不会改任何文档）
python evidence/compare_keys.py
```

产物：`evidence/golden_samples.json`（已在 `.gitignore`）、`evidence/SHA256SUMS.txt`。

## e) 产物清单

见同目录 `SHA256SUMS.txt`（每次采集后由 `collect_golden.py` 自动刷新）。
