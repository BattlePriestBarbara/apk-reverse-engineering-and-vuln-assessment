# 离线漏洞筛查报告（2026-11-13 轮）

> 样本：`<APK_DIR>`（APK 解包 + 审计产物）
> 复现：`python _re_ws/vuln_screen.py`
> 产物：`_re_ws/vuln_screen.json`、`_re_ws/vuln_screen.txt`
> 网络：全程零调用（脚本不 import socket / urllib / requests）

## 1. 方法与保证

筛查器对已解码目录做六类**只读**检查，每条命中都带四元组要素
（样本目录、定位串、复现命令、产物文件）：

| 检查项 | 覆盖对象 | 判据 |
| --- | --- | --- |
| S1 硬编码凭据 | 文本资源（xml/json/js/properties） | 键名 + 足够长的右值，且不像占位符 |
| S1b DEX 疑似字面量 | `classes.dex`、`assets/RiskStub.dex` 字符串池 | 随机性 + 字符集（见 §4 待核实） |
| S1c 内嵌证书 | 同上 | base64 DER 前缀 `MIG`/`MII` |
| S2 弱密码学 | 文本资源 | 仅认 `getInstance("MD5")` 这类**调用形态** |
| S3 明文 HTTP | 文本资源 | 统计端点，许可/文档域名已排除 |
| S4 清单卫生 | `manifest_audit.txt`、`exported_report.txt` | 清单是二进制 AXML，故消费审计产物 |
| S5 二进制标记 | `classes.dex`、`resources.arsc` | 加固壳 / JS 桥 / 动态加载 / 设备标识 |
| S6 证书固定 | `res/xml/network_security_config.xml` | 是否声明 `pin-set` |

本轮修正了两处**误判**，避免污染结论：

1. S2 原先按 `MD5|SHA1` 字面匹配，把资源清单里的 `"md5": "<hash>"`
   （内容校验值）当成弱算法使用，产生 50 条噪声；改为只认调用形态后归零。
2. S3 原先把 `apache.org`/`opensource.org` 等许可证链接算成明文端点；
   增加忽略名单后从 12 个主机收敛到 7 个。

## 2. 结果总览

| 维度 | 数值 |
| --- | --- |
| 命中总数 | 54 |
| 高 | 8（明文 HTTP 端点 7 + 全局明文开关 1） |
| 中 | 3（导出组件 / 深链 / 无证书固定） |
| 信息 | 9（加固与 API 标记 7 + 内嵌证书 2） |
| 待核实 | 34（DEX 字符串池候选，不计入评分表） |

## 3. 有证据的发现

| 编号 | 发现 | 级别 | 样本 | 定位 | 复现命令 | 产物 |
| --- | --- | --- | --- | --- | --- | --- |
| S4-1 | `usesCleartextTraffic=true` 全局允许明文 | 高 | `<APK_DIR>` | `manifest_audit.txt:111` | `python _re_ws/vuln_screen.py` | `vuln_screen.json` |
| S3-1 | 明文 HTTP 端点 7 个（政务域 4 处、IP 2 个、第三方 1 个） | 高 | `<APK_DIR>` | `ddd/**/*` 命中次数见 JSON | 同上 | `vuln_screen.json` |
| S4-2 | `exported=true` 组件 26 个 | 中 | `<APK_DIR>` | `manifest_audit.txt:115` | 同上 | `vuln_screen.json` |
| S4-3 | 可浏览深链 6 处（scheme 可被任意应用唤起） | 中 | `<APK_DIR>` | `exported_report.txt:3` | 同上 | `vuln_screen.json` |
| S6-1 | 有 NSC 但无 `pin-set`（可被任意 CA 中间人） | 中 | `<APK_DIR>` | `res\xml\network_security_config.xml` | 同上 | `vuln_screen.json` |
| S5-1 | `gatewaySignSecret` 符号在明文 DEX 中 | 信息 | `<APK_DIR>` | `classes.dex:0x1837088` | 同上 | `vuln_screen.json` |
| S5-2 | WebView JS 桥 / 远程调试开关均在册 | 信息 | `<APK_DIR>` | `classes.dex:0x30b71c`、`0x3a54c0` | 同上 | `vuln_screen.json` |
| S5-3 | 运行时 `DexClassLoader`（配合壳的二次加载） | 信息 | `<APK_DIR>` | `classes.dex:0x12a980d` | 同上 | `vuln_screen.json` |
| S1c-1 | `RiskStub.dex` 内嵌 base64 DER 证书/公钥 2 段 | 信息 | `<APK_DIR>` | `assets/RiskStub.dex:0x5fd7a`、`0x5fe55` | 同上 | `vuln_screen.json` |

## 4. 待核实（不进评分表）

`classes.dex` 与 `RiskStub.dex` 的字符串池里各有约 20 条"随机性 + 大小写数字
混合"的 64 位字面量（S1b，共 34 条，已脱敏）。它们**既可能是加固壳的序列化
常量，也可能是凭据**，仅凭字符串池无法判定归属：

- 判定需要调用点（smali/字节码）佐证，属"假设，非发现"；
- 按 `.clinerules` 第 1 条，这些只能留在本节的待核实清单里，不得进
  `threat_model.md` 的评分表；
- 若后续脱壳拿到可读 smali，优先核对 `S5-1` 那处 `gatewaySignSecret` 的
  赋值点（它是 T-1 的根因位置）。

## 5. 与既有结论的关系

| 本轮检查 | 既有结论 | 关系 |
| --- | --- | --- |
| S5-1 密钥符号 | T-1（10.0 / Critical） | 互证：符号存在，值由 `keyharvest.py` 取得 |
| S2 弱密码学（0 命中） | M-1（证书 1024 位 / SHA1） | 补充：**代码层**未发现弱算法调用，问题在**证书层** |
| S3 明文 HTTP | T-3（7.1 / High） | 互证：端点计数与 §10.7 清单一致 |
| S6 无 pin-set | P1-4 / P1-6 建议项 | 新增支撑：可被任意 CA 中间人，非仅明文风险 |
| S4-3 深链 | 未单列 | 新线索（中）：6 处 BROWSABLE 入口需验参，待人工确认 |

## 6. 结论

1. 代码层"硬编码凭据"的**符号级**证据已闭环（S5-1），与 T-1 的 10.0 分
   判定互相支撑；本轮未再引入新凭据。
2. 传输层问题由两条独立证据构成：全局明文开关（S4-1）+ 7 个明文端点
   （S3-1）+ 无 pin-set（S6-1）。这三条一起才能解释 T-3 的 AV:A / AC:L。
3. 攻击面侧新增一条中危线索：26 个导出组件 / 6 处可浏览深链需逐个核对
   参数校验，属**待人工确认**，暂不进评分表。
4. 34 条 DEX 字面量候选不改变任何既有结论；它们的作用是给出"下一步该看
   哪段 smali"的坐标。

## 7. 局限

1. 业务 DEX 被壳加密，筛查只覆盖明文可见面，结论是**下限**。
2. 二进制 AXML 未自行解析，S4 依赖同仓库审计产物；产物过期则结论过期。
3. `S1b` 采用启发式判据（含 `/` 的 base64 会被牺牲），存在漏检。
4. 本轮不做动态验证，无流量产生；所有"可利用性"判断仍需 A-8b 或
   授权测试环境实测。
