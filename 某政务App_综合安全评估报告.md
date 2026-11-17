# 某省政务服务 App 安全评估综合报告

**静态分析 · 动态分析 · 零流量攻击模拟**

## 0. 文档信息

| 项目 | 内容 |
| --- | --- |
| 报告版本 | v1.0（2026-11-13） |
| 评估对象 | `<APK_DIR>`（已解包的 APK 目录，4,185 个文件 / 212.6 MB） |
| 应用标识 | 包名 `com.example.govapp.activity`，启动组件 `com.example.govbase.gov.main.LoadingActivity` |
| 样本指纹 | `versionName 7.43.0` / `versionCode 74300`；`classes.dex` 45,946,008 B，SHA-256 `<SHA256-1>` |
| 评估范围 | 客户端静态面（配置、资源、DEX 字符串池、密码学材料）、本地授权环境动态尝试、离线攻击模拟 |
| 排除范围 | 未对任何生产/测试服务发起请求；未做服务端渗透；未做第三方平台的账号操作 |
| 密级 | 内部机密（凭据仅以「长度 + 指纹」呈现，原值单独受控存放） |
| 配套文档 | `某政务App_逆向与安全评估报告.md`、`threat_model.md`、`remediation_plan.md`、`VULN_SCREEN_REPORT.md`、`sandbox/RESULTS.md` |
| 复核入口 | `python _re_ws/vuln_screen.py`、`python sandbox/attack_sim.py`、`python -m unittest discover -s tests`、`python _re_ws/cvss_check.py --verify threat_model.md` |

## 1. 执行摘要

**一句话结论**：加固壳本身质量不低（DEX 方法体加密 + VMP + 反调试，静态与动态都拦住了），
但**壳之外的一切几乎全部失守**——网关签名密钥随包分发且四套环境复用，全域允许明文 HTTP，
导出组件无权限约束；三层分析相互独立地指向同一个根因：**信任锚放在了客户端里**。

| 层次 | 主要动作 | 核心结论 | 主要证据 |
| --- | --- | --- | --- |
| 静态分析 | 解包、AXML 树解析、DEX 字符串池、密码学材料、全树扫描、离线筛查器 | 4 严重 / 5 高危 / 6 中危 / 3 低危；密钥明文可提取；41 个明文端点；26 个导出组件 | `manifest_audit.txt`、`keyharvest.txt`、`vuln_screen.json` |
| 动态分析 | LDPlayer 9 + Frida 17.18.0 脱壳尝试、APK 原样重打包、崩溃取证 | **未取得明文 DEX**（失败点在 ARM64 翻译层，不在壳强度）；排除若干路径并取得 4 条新证据 | `dyn_diag.txt`、`logcat3.txt`、`dmesg.txt` |
| 攻击模拟 | 8 类攻击 × 3 种网关剖面 = 24 组断言，全程零流量 | 现状下**旧钥可直接伪造签名（200）**；检测只能"看见"、轮换才能"挡住"；另有独立的未签名参数注入缺陷 | `sandbox/attack_result.json`、`evidence/EXP-8_sandbox_attack.txt` |

| 关键量化指标 | 数值 |
| --- | --- |
| 静态风险条目 | 18 条（C 级 4 / H 级 5 / M 级 6 / L 级 3） |
| 风险最高项 Base 分 | T-1 网关密钥伪造 **10.0 / Critical**（S:C） |
| 明文 HTTP 端点 | 配置文件 **41** 个；DEX 字符串池 **187** 条（含 **9** 条裸公网 IP） |
| 导出组件 | 组件总数 298，`exported=true` **26** 个，其中 **19** 个未声明 permission，合计对外可见入口 **27** 个 |
| WebView 白名单 | **6,192** 条（去重 5,615），裸 IP 718、内网/回环 437、demo/test 334 |
| 攻击模拟断言 | **24 / 24 成立**，进程退出码 0 |
| 自动化验证 | 单元测试 **34** 项通过；CVSS 复算偏差 **0.0000**（21 项）；文档/风格检查 0 问题 |

**建议立即执行的三件事**：① 轮换网关签名密钥并下线旧钥（P0-1，72 小时）；
② 关闭全局明文并强制 HTTPS（P0-2，7 天）；③ 在网关侧上线旧钥调用检测与限速（P0-5，7～30 天）。

## 2. 合规与边界声明

本次评估严格遵循《网络安全法》第二十七条与授权测试边界，所有活动可被第三方复核：

| 约束 | 落实方式 | 如何验证 |
| --- | --- | --- |
| 仅限授权范围 | 单一样本 `<APK_DIR>`；生产域名在 PoC 中硬拦截 | `poc_gateway_sign.py` 遇生产域名即 `exit 5`，日志留痕 |
| 零网络流量 | 分析/筛查/靶场模块均不 import `socket`/`urllib`/`http`/`requests`；运行时 `NetGuard` 拦截 + 容器 `--network none` | `evidence/EXP-8_sandbox_attack.txt` 首段自检输出 |
| 不触碰在线系统 | 攻击模拟对端是本地契约复刻 `mock_gateway.py` | `sandbox/README.md` §2 |
| 不出网拉取 | 容器脚本预检本地镜像，缺镜像即 `exit 3` 并给离线导入指引 | `sandbox/run_in_docker.sh` |
| 不落真实凭据 | 靶场密钥为 `LAB_ONLY_*_NOT_REAL` 显式占位；本报告凭据只给长度与指纹 | 全文检索可确认无明文密钥 |
| 证据可复现 | 每条结论附样本 / 定位 / 命令 / 产物四元组 | `qa_evidence.py` 审计（当前 3/3 未闭环，见 §7.1） |



## 3. 评估对象与方法

### 3.1 样本指纹

| 项 | 值 |
| --- | --- |
| 解包目录 | `<APK_DIR>`（4,185 条目 / 212.6 MB，原 APK 未保留，由目录原样重建） |
| 包名 / 启动组件 | `com.example.govapp.activity` / `com.example.govbase.gov.main.LoadingActivity` |
| 版本 | `versionName 7.43.0`、`versionCode 74300`，`minSdk 23`、`targetSdk 30` |
| 签名证书 | `CN=vendor` 自签名，**1024 位 RSA + SHA1withRSA**，有效期 2014-08-17 → 2114-07-24（100 年） |
| 证书指纹 | SHA-256 `<REDACTED-PARTIAL>`，SPKI pin `<SHA256-2>` |
| 加固方案 | 娜迦 SecNeo（`com.secneo.apkwrapper.*`）+ 梆梆 Bangcle（`libDexHelper.so` / `libdexvmp.so`）+ 阿里 Sophix 残留 |
| DEX 体积 | `classes.dex` 45,946,008 B，SHA-256 `<SHA256-1>`（方法体加密，字符串池明文） |
| 签名块 | `SIG.SF` 含 `X-Android-APK-Signed: 2, 3` → 原包带 v2/v3 签名块 |

### 3.2 工具链

| 工具 | 用途 |
| --- | --- |
| apktool 3.0.3 / jadx 1.5.6 | 二进制 manifest 与 `resources.arsc` 解码；壳代码反编译 |
| openssl / jarsigner / apksigner | 证书解析、指纹计算、签名校验 |
| Python 3 自研脚本（50 余个，见 `_re_ws`） | AXML 树解析、DEX 字符串池、密码学材料提取、弱钥检测、全树扫描、离线筛查 |
| LDPlayer 9.1.50（Android 9 / SDK 28 / root）+ Frida 17.18.0 | 本地动态脱壳尝试（spawn/attach、libc hook、内存 DEX 扫描） |
| Docker（可选）/ Python 标准库 | 零流量攻击靶场与断言 |

### 3.3 三层方法的分工与递进

| 层次 | 回答的问题 | 不能回答的问题 | 本轮产出 |
| --- | --- | --- | --- |
| 静态 | 包里有什么——配置、常量、端点、组件、密码学材料 | 控制流、运行时行为、服务端是否真的信任 | 18 条风险 + 54 条筛查命中 |
| 动态 | 它运行时做了什么——加载、解密、崩溃、环境判定 | 服务端响应语义（本机无授权测试环境） | 脱壳可行性判定 + 4 条新静态证据 |
| 模拟 | 按逆向出的契约，攻击能走到哪一步、整改是否有效 | 线上网关真实实现（须 A-8b 实测） | 24 组断言 + 3 条硬结论 |

> 三层的价值在于**相互约束**：静态给出"密钥在包里"，动态给出"脱壳路径与失败点"，
> 模拟给出"拿到密钥后能做什么、怎样才算修好"。任何一层单独都不足以支撑整改决策。

## 4. 第一层：静态分析

### 4.1 加固机制的实际边界

| 观察 | 数值 | 安全含义 |
| --- | --- | --- |
| `dexdata0` 加密载荷 | 45.9 MB，其中 34.6 MB 结构保留、**11.3 MB 为真密文** | 方法体不可读，但类型描述符与字符串常量明文 |
| 类型 / 方法 / 字符串 | 可枚举 | 端点、键名、类目录可静态取证 |
| 反分析特征 | `/proc/self/status`、`/proc/self/maps`、`ptrace`、`emulator` 判定 | 反调试 + 反模拟器 |
| 壳库混放 | `lib/arm64-v8a/libDexHelper-x86.so` 实为 **x86-64**（`e_machine=0x3e`，1,146,765 B） | 按 `os.arch` 选分支，暴露双架构布局 |
| 加固的实际效果 | 阻止了业务逻辑审计 | 但**保护不了打包配置**——本次全部风险来自壳之外 |

> **方法论结论**：加固把"代码被读"的成本抬高了，却没有降低"配置被读"的成本。
> 密钥、端点、白名单、组件声明全部位于壳的保护范围之外。

### 4.2 风险清单汇总（18 条）

| 编号 | 标题 | 等级 | 验证状态 | 主要影响面 |
| --- | --- | --- | --- | --- |
| C-1 | 网关签名密钥硬编码，生产/预发/测试/内网四套环境复用 | 严重 | 已验证（静态） | 网关接口伪造 |
| C-2 | 全局允许明文 HTTP，敏感接口与模板确实走 `http://` | 严重 | 已验证（静态） | 中间人劫持 |
| C-3 | `dxAppOpenUrl` 零校验直通路由器，`gotoApaasPage` 信任服务端 URL | 严重 | 已验证（静态） | 任意 URI 唤起本地能力 |
| C-4 | WebView 白名单规模失控：含内网 IP、测试域名、畸形条目 | 严重 | 已验证（静态） | 白名单绕过 |
| H-1 | `FileSelectorProvider` 声明 `<root-path path="">` | 高危 | 已验证（静态） | 任意本地文件变 content URI |
| H-2 | 发行包内携带真实格式公民个人信息 | 高危 | **待复核（见 §12.3）** | 个人信息泄露 |
| H-3 | 26 个组件导出、19 个无权限，含支付/登录回调 | 高危 | 已验证（静态） | 伪造回调、登录劫持 |
| H-4 | 多平台 AppSecret / API Key 硬编码 | 高危 | 已验证（静态） | 第三方身份冒用 |
| H-5 | SSO 票据拦截规则把 `authCode` 送往非政府域名的明文接口 | 高危 | 已验证（静态） | 令牌外泄 |
| M-1 | 签名证书 1024 位 RSA + SHA-1，有效期 100 年 | 中危 | 已验证（静态） | 签名可伪造风险面 |
| M-2 | 业务源码以明文 `.java` 随包分发（71 个文件） | 中危 | 已验证（静态） | 逻辑泄露 |
| M-3 | 把桌面平台原生库打进 APK | 中危 | 已验证（静态） | 体积与攻击面 |
| M-4 | 88 项权限，含多项高危 / 不可获得权限 | 中危 | 已验证（静态） | 权限过度申请 |
| M-5 | `privacyStrategy.json` 自证高频敏感 API 采集 | 中危 | 已验证（静态） | 合规风险 |
| M-6 | 发行包保留测试组件、开发提示与内网地址 | 中危 | 已验证（静态） | 测试面暴露 |
| L-1 | 关闭堆指针标记，开启 `largeHeap` / `extractNativeLibs` | 低危 | 已验证（静态） | 加固削弱 |
| L-2 | 仍开启 `requestLegacyExternalStorage` | 低危 | 已验证（静态） | 存储越权面 |
| L-3 | 第三方 SDK 回调 Activity 未声明 `exported` 而按默认导出 | 低危 | 已验证（静态） | 隐式导出 |

> 亦需**避免过度修复**的正面事实：`allowBackup=false`、release 不可调试、
> 生产 NSC 未信任用户证书（仅 `<debug-overrides>` 内信任）、5 个 FileProvider 均
> `exported=false`、`gov://` 敏感深链承载页均关闭导出、全树 0 条私钥块。

### 4.3 密码学材料清单（值均脱敏，仅给长度与指纹）

| 材料 | 规格 | 用途 | 结论 |
| --- | --- | --- | --- |
| 签名证书 `META-INF/SIG.RSA` | RSA 1024 / SHA1withRSA / 自签 / 100 年 | APK 签名 | 低于 2048 位建议值；私钥**未**随包 |
| `security_public_key`（`resources.arsc`） | RSA 1024 | 日志/参数加密 | 与签名证书**模数不同**（非同一钥） |
| `assets/bid-log-key-public.key` 及 `_t` 副本 | RSA 2048 | 业务日志验签 | 两文件 **SPKI 完全一致**，预发与生产同钥 |
| `assets/future-key-public.key` | RSA 2048 | 预留轮换钥 | 独立钥，可作为轮换落点 |
| `assets/key` | 720 B base64 高熵 | 用途未知 | 需业务方确认，列入待核实 |
| `grs_sp.bks` / `hmsincas.bks` / `hmsrootcas.bks` | BKS 信任库 1,470 / 3,670 / 34,118 B | 华为 HMS 与 GRS | 自带信任库，需核对是否含过期根 |
| `tsa.cer` | 某省数据管理中心时间戳证书 | 时间戳 | 有效期 2017-06 → **2019-06 已过期** |
| `assets/geo_global_ca.cer` | 856 B，非标准 DER | 地理 CA | 无法解析，需人工确认 |

**弱钥可行性验证（7 类检测，全部未命中）**：试除至 2,000,000、完全幂判定、Fermat
（3e5 轮）、Pollard p−1（B1=1e5）、Wiener 连分数、Brent rho（3e5 次）、两两 gcd 共模。
结论：**公钥在实务上无法推出私钥**；1024 位的风险在于长期合规与算力演进，而非"当场可破"。
故 M-1 的正确处置是升级到 2048/EC 并重签，而不是"假定已泄露"。

**对称密钥与凭据（仅记录存在性与长度）**：`gatewaySignSecret`（len=24，四套环境同值，
C-1 核心）、微信与微博 `shareSecret`（两条，两个 appId 共用其一）、mPaaS `appSecret`、
百川 `appsecret`、UMeng `crash.key`、`Jupiter.UCInitKey`（2 项 base64）、高德 key、
HMS `appid`、`MIPUSH_APPKEY`。全部原值存放于受控产物 `keyharvest.txt`，本报告不复制。

### 4.4 传输层：明文面到底有多大

| 口径 | 数值 | 来源 |
| --- | --- | --- |
| 清单开关 | `usesCleartextTraffic=true`，NSC 的 `base-config cleartextTrafficPermitted=true` | `manifest_audit.txt:111` |
| 配置文件内 `http://` 端点 | **41** 个 | `qa_http.py` |
| DEX 字符串池去重 `http://` 端点 | **187** 条，其中裸公网 IP **9** 条 | `qa_dex7.py` |
| 本轮离线筛查器（文本资源 + 忽略名单） | **7** 个主机 / 12 条命中 | `vuln_screen.json` |
| 证书固定 | NSC 存在但**无 `<pin-set>`** | `res/xml/network_security_config.xml` |

三类口径并不矛盾，而是**覆盖范围不同**：配置层只统计可读配置文件；DEX 池包含全部
硬编码常量；筛查器只认"业务端点形态"并排除许可证/规范类域名（`apache.org`、
`opensource.org`、`w3.org`、`schemas.android.com` 等）。最需要关注的是三处**语义敏感**的明文：

1. `assets/license_center_config.json` 的 4 条 `ep_source_*.js|json`——可执行脚本走明文，
   直接影响 C-3 的注入链；
2. `assets/sso_config.json` 把票据换取指向**非政府域名**的 `http://…/uc/auth/token`，
   与 H-5 的 `authCode` 外发路径一致；
3. DEX 池内的 `uaa/authorize`、`sso/usp.do` 等认证端点走 `http://`，即 T-3 的取值依据。

### 4.5 组件与攻击面

| 指标 | 数值 | 说明 |
| --- | --- | --- |
| 组件总数 | 298 | Activity / Service / Receiver / Provider |
| `exported=true` | 26 | 均可被任意本地应用拉起 |
| 其中未声明 permission | 19 | 无任何调用方校验 |
| 对外可见入口合计 | 27 | 含 1 个声明了 intent-filter 但未写 `exported` 的默认导出组件 |
| 与支付/登录/分享/推送相关 | 10 | 含支付结果回调、第三方登录返回页 |
| BROWSABLE 深链 | 6 | scheme：`agoo`、`gov`、`ut.[REDACTED_APPID:8]`、`gov` |
| 权限声明 | 88 项 | 含多项 high-risk 权限 |

关键点：`FileSelectorProvider` 虽是 `exported=false`，但声明了 `<root-path path="">`
并开启 `grantUriPermissions`——**根目录授权**才是 H-1 的成因，与导出口径无关。

### 4.6 WebView 白名单：机器拼接的痕迹

| 指标 | 数值 |
| --- | --- |
| 总条目 / 去重 | 6,192 / 5,615 |
| 裸 IP 条目 | 718 |
| 内网 / 回环 / 链路本地 | 437 |
| 含 demo、test、dev 或非常规 TLD | 334 |
| 非 `.cn` 结尾 | 2,990 |
| 畸形 `host+数字`（端口拼接错误） | 50 |

50 条形如 `x.x.x.x` 后直接粘连数字的畸形项，说明该文件由脚本批量生成且缺少校验；
同时测试域名（`govtest`、`pre-portal`、`appcashier.test`）出现在**生产包**内。
若匹配算法是 `startsWith`/`contains`，则 `<HOST-3>.evil.tld` 可绕过（待脱壳确认）。

### 4.7 离线筛查器复跑（本轮新增，可一键复核）

| 检查项 | 覆盖对象 | 命中 | 说明 |
| --- | --- | --- | --- |
| S1 硬编码凭据 | 文本资源 | 0 | 凭据均在 AXML/DEX 面，不在文本资源 |
| S1c 内嵌证书 | DEX 字符串池 | 2 | `RiskStub.dex` 内 base64 DER 两段 |
| S2 弱密码学 | 文本资源（仅认调用形态） | 0 | 代码层无弱算法调用，问题在证书层 |
| S3 明文 HTTP | 文本资源 | 7 主机 | 已排除许可证/规范域名 |
| S4 清单卫生 | `manifest_audit.txt` / `exported_report.txt` | 3 | 明文开关、26 导出、6 深链 |
| S5 二进制标记 | `classes.dex` / `resources.arsc` | 7 | 密钥符号、JS 桥、动态加载、调试开关等 |
| S6 证书固定 | NSC | 1 | 有 NSC 无 `pin-set` |
| 合计 / 待核实 | — | **54** | 高 8、中 3、信息 9、待核实 34 |

本轮同时修正了两处会污染结论的误判：S2 原按 `MD5|SHA1` 字面匹配，把资源清单里的
`"md5": "<hash>"` 校验值当成弱算法（50 条噪声归零）；S3 原把许可证链接当明文端点
（主机数 12 → 7）。34 条"待核实"为 DEX 字符串池中的高熵字面量，缺调用点佐证，
按规则**不进评分表**。

### 4.8 静态分析无法回答的问题

1. `IRouterService.goToUri()` 内部是否另有 scheme/host 过滤（决定 C-3 是否成立）；
2. WebView 白名单的匹配算法（`equals` / `startsWith` / `contains` / 正则）；
3. 网络层是否启用 `CertificatePinner` 或 mPaaS MGS 绑定（决定 C-2 的可拦截性）；
4. `gatewaySignSecret` 的拼接模板与失败分支（决定链 D 的工时）；
5. 本地存储是否加密（`EncryptedSharedPreferences` / SQLCipher）；
6. `assets/key` 的用途。

## 5. 第二层：动态分析

> 结论先说：**本轮未能取得明文 DEX**，且失败点已定位到 **ARM64 翻译层（houdini64）**，
> 不是壳的强度问题，也不是 hook 写错。这一节的价值在于"排除路径 + 留下可复用工具链 +
> 取得 4 条新静态证据"，而不是"脱壳成功"。

### 5.1 本地实验环境

| 项 | 取值 | 取证方式 |
| --- | --- | --- |
| 模拟器 | LDPlayer 9（9.1.50），实例 `leidian0` | 注册表 + `adb shell df -h /data`（可用 23 GB） |
| Android | 9（SDK 28），`ro.build.type=user`，`ro.debuggable=1` | `getprop` |
| CPU / ABI | `x86_64,x86,arm64-v8a,…`；`primaryCpuAbi=arm64-v8a`；arm64 由 **houdini64** 翻译 | `getprop`、`dumpsys package` |
| root | `adb root` 后 `uid=0(root)`，SELinux `u:r:su:s0`，`permissive=1` | `adb shell id`、`dmesg` |
| Frida | 客户端与 server 均 17.18.0（x86_64 与 arm64 两个 server 都在本地） | `frida --version`、`/data/local/tmp/fsx --version` |
| 目标进程 | `com.example.govapp.activity`，`native-code: arm64-v8a` | `aapt dump badging` |

### 5.2 安装包原样重建（可复用的技巧）

| 步骤 | 结果 |
| --- | --- |
| 输入 | `<APK_DIR>`，4,185 条目 / **222,978,409 B** |
| 输出 | `govsvc_rebuild.apk`，**128,549,687 B**（122.6 MB），耗时 12.8 s |
| 签名 | 逐条目内容逐字节不变 → `MANIFEST.MF` 摘要仍成立，**v1 签名继续有效** |
| 校验 | `jarsigner -verify` 通过，提示签名者证书 **2114-07-25** 到期（与 M-1 吻合） |
| 安装 | `adb install -r -t` → **Success**，`primaryCpuAbi=arm64-v8a`，证书仍为原 `CN=vendor` |
| 副作用 | `system_server` 警告 `resources.arsc in APK is compressed`（不影响安装/启动） |
| 已知差异 | 原包带 v2/v3 签名块，重打包只保留 v1 —— **换真机必须用原始完整签名包** |

### 5.3 崩溃证据链（两种场景、两次不同信号）

| 场景 | 信号 | tombstone 关键帧 | 判读 |
| --- | --- | --- | --- |
| spawn + Frida | `SIGABRT` | `#00 syscall+24`、`#01 abort+101`、`#02 <anonymous:0x763912f6e000>` | 由壳解密出的**匿名可执行内存主动 abort()** |
| 裸 `am start`（不注入） | `SIGSEGV / SEGV_ACCERR` | `#00 libDexHelper-x86.so+0x5a4b6`；另一线程 `<anonymous+0xfbf60>` 取指失败 | 无 frida 同样崩溃 → **崩溃与注入无关** |

启动轨迹（`dyn_diag.txt`，60 行）中的关键序列：

```text
[579ms] open  …/base.apk.x86_64.flock
[583ms] mmap  45,948,928  prot=0x1        ← ≈ classes.dex 体积 45,946,008
[604ms] open  …/lib/arm64/libDexHelper-x86.so   ← 壳开始接管
[607ms] dlopen_ext /system/lib64/arm64/nb/libtcb.so  ← houdini 的 arm64 翻译桥
        → 进程消失（约 1 s）
```

### 5.4 观察与推断分开写

| 类型 | 内容 |
| --- | --- |
| 观察 | 不注入 frida 也崩，且两次都发生在壳接管之后 → 崩溃与调试器无关 |
| 观察 | `bypass.js` 已替换 x86_64 的 `abort`/`exit`/`_exit` 并挂 `android_set_abort_message`，但**两个钩子一次都没被调用** |
| 推断 | 真正执行自毁的代码**不走 x86_64 的 bionic**；结合 607 ms 的 `libtcb.so` 加载，可判定该段二级代码是 **arm64**，经 houdini 翻译执行 |
| 推断 | 因此本机失败点 = 翻译层，而非壳强度；换 arm64 真机有望通过该关卡 |

### 5.5 顺带取得的 4 条新静态证据

| 编号 | 证据 | 影响 |
| --- | --- | --- |
| D-1 | `lib/arm64-v8a/libDexHelper-x86.so` 的 `e_machine=0x3e`（x86-64，1,146,765 B），而 `libDexHelper.so` 为 `0xb7`（AArch64，983,549 B） | 解释同名壳库并存；说明壳按 `os.arch` 选分支 |
| D-2 | 壳库 6,932 条去重可打印串中筛出 `/proc/self/maps`、`ptrace`、`libc_ptrace`、`emulator`、`hookX86Fun` | 确认具备 maps 扫描 + ptrace 反调试 + 模拟器判定 |
| D-3 | houdini 启动阶段读取 `/data/local/cfg-nnayn/` 下 **33** 个配置/数据文件 | 该路径即现成的模拟器指纹，壳可直接据此判定 |
| D-4 | `SIG.SF` 含 `X-Android-APK-Signed: 2, 3` | 原包带 v2/v3 签名块；v1-only 重打包在**任何设备**上都有该差异 |

### 5.6 路径结论

| 路径 | 结论 |
| --- | --- |
| 本机 LDPlayer 9 + houdini64 | **不可行**：壳的 arm64 二级代码在翻译层直接崩；arm64 frida-server 也无法承载 |
| 同为 x86 宿主 + ARM 翻译的模拟器（MuMu 12 等） | 预期同样受限于翻译层，**未验证** |
| **arm64 真机 + arm64 frida-server** | **推荐路径**：原生执行，Java 桥可用，随后 hook `InMemoryDexClassLoader`/`DexFile` + 内存 `dex\n035` 扫描 |
| 原始完整签名 APK（v1+v2/v3） | **必要前提**：无法排除壳对 v2 签名块存在性的校验 |

已备好可直接复用的工具链：`pack_apk.py`（重建）、`fz.py`（attach/spawn）、`unpack.py`
（接收分片）、`dump_mem.js`（内存 DEX 扫描）、`hook_io.js`、`diag.js`、`bypass.js`、
`probe_java.js`、`probe_hook.js`。

### 5.7 动态分析对结论的贡献

| 贡献 | 说明 |
| --- | --- |
| 抬分 | **0 条**——未取得明文 DEX，未新增任何可利用证据 |
| 降险 | 排除了"模拟器即可脱壳"的捷径，避免整改方误判审计已完成 |
| 定界 | 明确 `gatewaySignSecret` 的算法与失败分支须靠真机脱壳或黑盒比对取得（EXP-1） |
| 前提 | 指出真机复现必须用原始 v2/v3 签名包，避免二次失败 |

## 6. 第三层：零流量攻击模拟

### 6.1 设计思路：为什么是"契约复刻"而不是"打真网关"

链 D（密钥提取 → 伪造签名 → 接口滥用）的可行性取决于**签名契约**（算法、字段序、
分隔符、时间窗、keyver 是否入签）。本轮把逆向与文档得到的契约实现为一个本地替身
`mock_gateway.py`，并用三种剖面模拟"整改到不同阶段"的网关：

| 剖面 | 语义 | 复刻的现实阶段 |
| --- | --- | --- |
| `baseline` | 旧钥单钥、不校验 nonce/时间窗/keyver、不限速 | 现状（对应 C-1 / C-2） |
| `hardened` | 新旧双钥并行 + 重放/时间窗/keyver 校验 + 参数白名单 + 服务端限速，但旧钥仍可用 | P0-1 第 3～6 步（双钥过渡期） |
| `rotated` | 旧钥已移出 keyring | P0-1 第 7 步（吊销完成） |

固定实验条件保证可复现：`NOW_MS` 常量（与墙钟解耦）、基线来源 `AS4134` + 设备
`dev-known-1`、P99 = 120 次/小时、**阈值 3 × P99 = 360**、时间窗 ±300 秒、
密钥为 `LAB_ONLY_*_NOT_REAL` 占位。

### 6.2 零流量的三重保证

| 层 | 机制 | 失败时的行为 |
| --- | --- | --- |
| 代码层 | 靶场与筛查器不 import `socket`/`urllib`/`http`/`requests` | 静态可查，无隐性依赖 |
| 运行时 | `NetGuard`：替换 `socket.socket`/`create_connection` 等，并挂 `meta_path` 拦截网络模块导入 | 启动自检失败即 `exit 2`（**fail closed**） |
| 容器层 | `network_mode: none`、`read_only`、`cap_drop: ALL`、`tmpfs /tmp`、非 root 10001 | 网络命名空间内无接口 |

### 6.3 结果矩阵（8 类攻击 × 3 剖面 = 24 组断言，全部成立）

| 场景 | 攻击手法 | baseline（现状） | hardened（双钥+检测） | rotated（旧钥吊销） |
| --- | --- | --- | --- | --- |
| A1 | 泄露旧钥伪造签名 | **200** | **200**（打标 `v1_offasn` + `v1_newdevice`） | 401 |
| A2 | 签名原样重放 | 200 → 200 | 200 → 401（`replay`） | 401 → 401 |
| A3 | 时间戳回拨 600 秒 | 200 | 401（`ts_window`） | 401 |
| A4 | 版本降级（v1 钥报 v2） | 200 | 401（`keyver_mismatch`） | 401 |
| A5 | 未签名参数注入 `amount` | 200（`amount` **生效**） | 400（`unsigned_param`） | 401 |
| A6 | 单来源 900 次/小时 | 200 × 900 | 200 × 360 + 429 × 540（`v1_burst`） | 401 × 900 |
| A7 | 新钥 + 陌生来源（对照组） | 401（现状无 v2 分支） | 200，**零打标** | 200，零打标 |
| A8 | 缺设备指纹 | 200（算了 `headless` 但不消费） | 200（`headless` 打标） | 401 |

产物：`sandbox/attack_result.json`（sha256 `<REDACTED-PARTIAL>`）、
`evidence/EXP-8_sandbox_attack.txt`（stdout 全文，首段即 NetGuard 自检）。

### 6.4 三条硬结论

1. **信任根悖论（最重要）**：`hardened` 下 A1 仍然 200。只要旧钥还在 keyring 里，
   验签就会成功——**检测只能"看见"，轮换才能"挡住"**。这条把 P0-1 的处置顺序钉死了：
   先双钥并行（能让新客户端用新钥），再灰度切换，最后吊销旧钥。
2. **零误报基线**：A7 在新钥 + 陌生来源 + 陌生设备下**没有任何打标**，证明 P0-5 的
   R-1/R-2 只对旧钥生效，不会把正常新用户当成攻击者。同时暴露一个前置缺陷：
   现状**没有 v2 分支**（A7 baseline = 401）——**轮换前必须先具备双钥并行能力**。
3. **A5 是独立缺陷**：签名只覆盖 `appKey/timestamp/nonce` 时，夹带的 `amount` 会原样
   进入业务层。它与密钥泄露无关，需单独修（参数白名单或全参签名）。

### 6.5 与整改项的映射

| 攻击 | 阻断它的整改项 | 仅打标的整改项 | 残余风险 |
| --- | --- | --- | --- |
| A1 | P0-1 轮换（v1 下线） | P0-5 的 R-1/R-2 | 轮换完成前，泄露钥始终可用 |
| A2 | nonce 去重（P0-4） | — | 需服务端共享 nonce 存储 |
| A3 | 时间窗校验（P0-4） | — | 客户端时钟漂移需容忍度配置 |
| A4 | keyver 参与签名（P0-1） | P0-5 的 R-1 | 旧客户端不支持 keyver 需灰度 |
| A5 | 参数白名单 / 全参签名（P0-4） | — | 需逐接口梳理可签字段 |
| A6 | 服务端限速（P0-5 的 R-3） | `v1_burst` 告警 | 分布式来源需按 ASN 聚合 |
| A7 | 对照组，无需整改 | — | 基线缺失会导致误报淹没告警 |
| A8 | 设备指纹强校验 | `headless` 打标 | 指纹可伪造，仅作辅助信号 |

### 6.6 容器化与复跑

`Dockerfile`（`python:3.12-slim`，非 root 10001）、`docker-compose.yml`（`network_mode: none`
等硬化项）、`run_in_docker.sh`（**拒绝 `docker pull`**，缺镜像即 `exit 3`）均已就绪。

> **本轮未能在容器内实跑**：本机 Docker 引擎不可用（Docker Desktop 无法启动，
> `%LOCALAPPDATA%\Docker\wsl` 缺引擎数据盘）。修复它需要联网下载引擎组件，属
> "产生流量"，按授权边界未执行。因此**宿主路径是本轮的等价验证路径**——同一份
> `attack_sim.py`、同一组断言、同样 `exit 0`；容器路径在镜像就绪后原样复跑即可。

## 7. 威胁建模与量化（CVSS v3.1）

| 编号 | 威胁 | 向量 | Base | Temporal | Env（完整） | 等级 |
| --- | --- | --- | --- | --- | --- | --- |
| T-1 | 硬编码网关对称密钥导致接口伪造 | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` | **10.0** | 7.6 | 7.6 | Critical |
| T-2 | 第三方 OAuth AppSecret 硬编码 | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` | **8.2** | 6.2 | 7.3 | High |
| T-3 | SSO 令牌经明文 HTTP 传输 | `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | **7.1** | 5.6 | 6.8 | High |

计算口径与复核：`Iss` 与 `Impact` 按 FIRST §7.1/§7.2 实现（`S:C` 时指数取 15、
`MISS` 上限 0.915），`Roundup` 用整数运算规避浮点误差；`cvss_check.py --verify`
逐项比对 **21 项数值，偏差 0.0000**。三项在 Base / Temporal / Environmental 三组
口径下排序一致（T-1 > T-2 > T-3），故整改优先级不依赖口径选择。

T-1 的 10.0 属"下限即上限"：Impact 与 Exploitability 之和在 1.08 系数下已越过 10.0
封顶，任何 ≤1.5 的数据分级权重都无法再抬高它。

### 7.1 证据门禁状态（必须如实标注）

| 威胁 | 四元组状态 | 现有评分可否直接引用 | 待补实验 |
| --- | --- | --- | --- |
| T-1 | 缺 SAMPLE / LOCATOR / COMMAND / ARTIFACT | **不可**（标注 `UNVERIFIED`） | EXP-1、EXP-2 |
| T-2 | 同上 | **不可** | EXP-3、EXP-4、EXP-6 |
| T-3 | 同上 | **不可** | EXP-5 |

`qa_evidence.py` 当前 `exit 1`（3/3 缺证据），`threat_model.md` 对应区块已插入
`> UNVERIFIED` 标注，台账见 `unverified_hypotheses.md`。

> 需要说明的边界：本轮静态筛查已把 T-1 的**符号级**证据闭环（`gatewaySignSecret`
> 位于 `classes.dex:0x1837088`，命令与产物齐全），但"符号存在"不等于"密钥值可提取
> 且可离线生成签名"——后者仍需 EXP-1 的运行时采样。因此本报告不因筛查结果而撤销
> `UNVERIFIED` 标注。

## 8. 攻击链：三层证据如何拼成完整路径

| 链 | 路径 | 前置条件 | 可行性 | 本轮验证到哪一步 |
| --- | --- | --- | --- | --- |
| A | 中间人 → 模板/脚本篡改 → 任意 URI → 本地文件外泄 | 控制用户网络链路 | 高 | 明文面与模板地址已静态确认（C-2）；`goToUri` 过滤待脱壳 |
| B | 任意本地应用 → 伪造支付/登录回调 | 无（普通应用即可） | 高 | 导出组件与无权限状态已静态确认（H-3） |
| C | 外链唤起 → 任意页面在受信 WebView 加载 → JS Bridge | 白名单匹配可绕过 | 中 | 白名单规模与畸形项已确认（C-4）；匹配算法待脱壳 |
| D | 密钥提取 → 伪造网关签名 → 服务端接口滥用 | 需签名契约 | 中 | **本轮把契约侧闭环**：模拟证明现状 200、轮换后 401（T-1） |

链 D 是本次评估中最需要业务方立即验证的一条，也是三层分析**唯一**都被用到的一条：
静态给出"密钥在包里"，动态给出"脱壳门槛与算法未知项"，模拟给出"拿到密钥后能否伪造、
修到什么程度才失效"。

## 9. 整改路线图

### 9.1 P0：立即处置

| 编号 | 事项 | 时限 | 关键动作 | 验收项 |
| --- | --- | --- | --- | --- |
| P0-1 | 网关密钥轮换（`gatewaySignSecret`） | ≤ 72 小时启动 / 7 天完成 | 资产盘点 → 生成 256 bit 新钥入 KMS → 服务端**双钥并行** → 灰度切换 → 观测旧钥 → 吊销 → 复盘 | A-1、A-6、A-8a |
| P0-2 | 明文 HTTP → HTTPS 强制 | ≤ 7 天 | NSC 改 `cleartextTrafficPermitted=false`、服务端 301 跳转、清退 `http://` 模板与令牌接口 | A-3 |
| P0-3 | 第三方凭据轮换与收口 | ≤ 7 天 | 重置 AppSecret、开启 IP 白名单、调 90 天调用日志 | A-4 |
| P0-4 | 泄露影响面排查 | ≤ 3 天 | 按签名/令牌/凭据三类回溯异常调用，确认是否存在越权读取 | — |
| P0-5 | 泄露期检测与事件响应 | ≤ 30 天 | R-1 旧钥+h 非历史来源、R-2 旧钥+新设备、R-3 单来源限速（3 × P99），动作树第 ① 步冻结 keyver | A-8a / A-8b |

> 不变式：P0 的轮换与 P1 的"移除硬编码"必须成对推进——只轮换不迁移，新密钥在一个
> 版本周期后仍会重新沉淀回客户端。本轮的模拟结果（A1 在 `hardened` 仍 200）就是这条
> 不变式的实证。

### 9.2 P1 / P2 概要

| 级别 | 编号 | 事项 | 时限 |
| --- | --- | --- | --- |
| P1 | P1-1 | 硬编码改服务端动态下发（设备绑定 + TTL） | ≤ 1 个月 |
| P1 | P1-2 | 第三方凭据最小化（按端拆分、按需授权） | ≤ 1 个月 |
| P1 | P1-3 | 加固壳兼容性调整（保障可测试性） | ≤ 3 周 |
| P1 | P1-4 | CI 密钥扫描门禁（提交前 + 全量 SARIF） | ≤ 2 周 |
| P1 | P1-5 | 令牌生命周期与重放防护 | ≤ 1 个月 |
| P1 | P1-6 | 签名证书升级至 RSA-2048/EC 并重签 | ≤ 1 个月 |
| P2 | P2-1 | Android Keystore / TEE 保护核心密钥 | ≤ 1 季度 |
| P2 | P2-2 | mTLS / 挑战-响应替代单一对称签名 | ≤ 1 季度 |
| P2 | P2-3 | 网关信任模型重构 | 次季度 |
| P2 | P2-4 | 密钥全生命周期治理 | ≤ 1 季度 |

### 9.3 验收标准（可直接抄入整改确认单）

| 编号 | 验收项 | 判定标准 |
| --- | --- | --- |
| A-1 | 旧网关密钥下线 | 旧钥签名的请求返回签名错误；`keyver="v1"` 指标 7 天为 0 |
| A-2 | 全仓库无秘密 | `gitleaks detect` 0 命中；新 APK `strings` 无 `gatewaySignSecret` |
| A-3 | 无明文传输 | 抓包无 `http://`；`usesCleartextTraffic=false` 生效 |
| A-4 | 第三方凭据收口 | AppSecret 已重置、IP 白名单开启、90 天日志无异常来源 |
| A-5 | 签名完整性 | `apksigner verify --print-certs -v` 显示 v1/v2/v3 且证书为 RSA-2048/EC |
| A-6 | 客户端不再持长期密钥 | 反编译/内存 dump 无长期密钥；下发密钥 TTL ≤ 24 小时 |
| A-7 | 交付物脱敏 | `sanitize_report.py` 复跑 0 替换（幂等） |
| A-8a | 检测逻辑（离线可自动） | `python -m unittest tests.test_poc_oracle -v` 全绿：旧钥报文必带 `keyver=v1` 且入签，分类器给出 `suspect=v1_offasn`，基线内来源不误报 |
| A-8b | 检测落地（测试环境人工） | 网关真实打标落库并进入动作树第 ① 步，留存日志——**离线测不了，须实测** |

> 在 A-8b 完成前，《整改确认单》只能勾 A-8a，不得勾满 A-8。

### 9.4 合规映射

| 要求 | 条款 | 对应整改 |
| --- | --- | --- |
| 通信传输完整性 / 保密性 | 等保 2.0 三级 8.1.4.2 | P0-2、P1-5 |
| 数据保密性（密钥管理） | 等保 2.0 三级 8.1.4.8 | P0-1、P1-1、P2-4 |
| 身份鉴别与不可否认 | 等保 2.0 三级 8.1.4.1 | P2-2、P2-3 |
| 个人信息最小必要 | 《个人信息保护法》第 6 条 | P1-2、P2-4 |
| 个人信息泄露补救与告知 | 《个人信息保护法》第 57 条 | P0-5 |
| 供应链安全 | 等保 2.0 三级 8.1.4.4 | P1-3、P1-4、P2-4 |

## 10. 证据台账

| 产物 | 内容 | 校验 / 状态 | 复现命令 |
| --- | --- | --- | --- |
| `_re_ws/vuln_screen.json` / `.txt` | 54 条筛查命中（含定位、证据、命令） | exit 0 | `python _re_ws/vuln_screen.py` |
| `VULN_SCREEN_REPORT.md` | 离线筛查报告（四元组表 + 待核实清单） | 文档检查 0 问题 | — |
| `sandbox/attack_result.json` | 8 × 3 结果矩阵 | sha256 `<REDACTED-PARTIAL>` | `python sandbox/attack_sim.py --json sandbox/attack_result.json` |
| `evidence/EXP-8_sandbox_attack.txt` | 靶场 stdout 全文（首段 NetGuard 自检） | exit 0 | 同上（输出重定向） |
| `sandbox/mock_gateway.py` / `attack_sim.py` | 契约复刻 + 攻击脚本 | 风格检查 0 问题 | — |
| `sandbox/Dockerfile` / `docker-compose.yml` / `run_in_docker.sh` | 硬化编排与离线守卫 | 就绪，**未实跑**（引擎不可用） | `sh sandbox/run_in_docker.sh` |
| `tests/test_sandbox_attacks.py` | 10 个回归用例（含子进程验证 NetGuard） | 通过 | `python -m unittest discover -s tests` |
| `evidence/SHA256SUMS.txt` | 4 个取证脚本/文档的哈希 | 可校验 | — |
| `_re_ws/keyharvest.txt` | 密码学材料提取（含原值，**受控**） | 已脱敏引用 | `python _re_ws/keyharvest.py` |
| `_re_ws/keyweakness.txt` | 7 类弱钥检测结果 | 全部未命中 | `python _re_ws/keyweakness.py` |
| `_re_ws/manifest_audit.txt` / `exported_report.txt` | 组件、权限、深链审计 | 已用于 S4 | `python _re_ws/manifest_audit.py` |
| `_re_ws/{hunt3,white_urls_stats,scan_findings}.txt` | 敏感常量、白名单统计、全树扫描 | 已用于 §4.4～4.6 | 对应脚本 |
| `_re_ws/{dyn_diag,logcat3,dmesg}.txt` | 动态轨迹与 tombstone | 已用于 §5.3～5.5 | `python _re_ws/fz.py` |
| `threat_model.md` / `remediation_plan.md` | 量化与路线图 | SHA256 本轮未改动 | `python _re_ws/cvss_check.py --verify threat_model.md` |
| `unverified_hypotheses.md` / `EXPERIMENTS_NEEDED.md` | 未验证台账与实验设计 | 3/3 未闭环 | `python qa_evidence.py` |

## 11. 结论与下一步

**结论**：

1. 本次评估的核心问题不是"代码写得不安全"，而是**信任锚放错了位置**——网关把
   "客户端持有密钥"当作身份凭据，而客户端是不可信环境。加固能提高读代码的门槛，
   却改变不了"密钥随包分发"这一事实。
2. 三层分析各自的结论一致且互不替代：静态定性（有什么）、动态定界（能拿到多少）、
   模拟定量（拿到后能做什么、修到什么程度失效）。
3. 整改的关键顺序被模拟结果钉死：**先具备双钥并行能力 → 再灰度切换 → 最后吊销旧钥**；
   只做检测不做轮换，等于把"看见攻击"当成"阻断攻击"。

| 下一步 | 前提 / 依赖 | 产出 | 影响 |
| --- | --- | --- | --- |
| A-8b：测试环境实测旧钥告警落库 | 授权测试环境 + 测试域名 | 网关日志与告警截图 | 才能勾满 A-8，闭环 P0-5 |
| EXP-1：arm64 真机脱壳取签名模板 | arm64 真机 + **原始 v1+v2/v3 签名包** | `golden_samples.json` + `FINDINGS_sign_algo.md` | 决定 T-1 的 S:C 是否成立（10.0 或回退 9.1） |
| EXP-6：确认第三方 OAuth 授权模式 | 平台侧应用后台只读权限 | 授权模式结论 | 解 T-2 的 S:U / S:C 争议 |
| 补齐 T-1/T-3 四元组 | 上述实验产物 | `threat_model.md` 写入四元组 | `qa_evidence.py` 才有望 exit 0 |
| 容器路径实跑 | 本地已有 `python:3.12-slim` 镜像 | 容器内结果矩阵 | 与宿主结果交叉验证（不改结论） |

## 12. 局限、口径差异与待复核项

### 12.1 局限性

1. **DEX 方法体不可读**：所有"控制流类"结论（`goToUri` 过滤、白名单匹配算法、
   证书绑定、签名模板）均未确证，属待脱壳或待黑盒比对项。
2. **未做服务端测试**：`gatewaySignSecret` 的线上可用性、接口越权均需授权后由业务方
   或红队在测试环境验证；本报告未对任何线上域名发包。
3. **动态未成功**：仅完成一次失败的脱壳尝试（本机翻译层限制），未取得明文 DEX。
4. **模拟是契约复刻**：证明"按文档实现能拦住这些攻击"，**不证明**线上已如此实现。
5. **未覆盖**：`.so` 二进制逆向（仅字符串/符号层）、Sophix 热更新拉取逻辑、
   人脸核身 SDK 本地活体强度、SE 访问控制。
6. **业务影响未纳入 CVSS**：政务数据分级、用户规模、监管处罚需业务加权后再排期。

### 12.2 口径差异说明（避免误读为矛盾）

| 现象 | 差异来源 | 正确读法 |
| --- | --- | --- |
| 导出组件数 19 / 26 / 27 | 19 = 未声明 permission 的导出组件；26 = `exported="true"` 总数；27 = 再加 1 个默认导出 | 三个数都对，指代不同 |
| 明文端点 7 / 41 / 187 | 7 = 业务形态主机（筛查器，含忽略名单）；41 = 配置文件端点；187 = DEX 池去重 | 覆盖范围依次放大 |
| 风险 18 条 vs 筛查 54 条 | 18 = 分级风险条目；54 = 原始命中（含信息级与待核实） | 命中不等于风险 |
| 目标 SDK 30 与 Android 11+ 行为 | `targetSdk=30` 时部分新限制不生效 | 这解释了 L-1/L-2 的成因 |

### 12.3 H-2（包内 PII）本轮未能复现 —— 待复核

这是本报告**唯一**对原结论做出降级处理的一项，理由与证据如下：

| 复核动作 | 结果 |
| --- | --- |
| 检索原报告引用的 `queryPerson.json` | 全树**未找到**文件名含 `queryPerson` 的文件 |
| 全树文本扫描（2,075 个文件） | 身份证 **0**、统一社会信用代码 **0**、手机号 **1**（`res/raw/rvtools_inject_js.js`，为注入脚本示例号码） |
| 18 位数字启发式复扫 | 命中 10 条，均为 `PageCache_Page_Interactive.json` 中的**文章 ID**，非证件号 |
| 关键词 `身份证` 检索 | 仅 `assets/work_rule_parse.js` 出现字样（规则文本，非数据） |
| 转义形式（`\u8eab\u4efd\u8bc1`）检索 | 无命中 |

结论：**在当前样本树中无法复现"包内携带真实公民个人信息"**。可能原因是原报告基于
另一份样本/更早的解包产物，或数据位于需解码的配置。处置建议：由业务方提供原证据路径，
或按 H-2 独立复现一次；**在复现前，H-2 不应作为已证实高危项引用**，也不影响其他结论。

### 12.4 文档自身的一致性

本轮所有数字均可用 §10 的命令重跑；`VULN_SCREEN_REPORT.md`、`sandbox/RESULTS.md`、
`sandbox/README.md`、本报告均通过 Markdown 结构检查（围栏配对、表格列数、重复标题）；
`threat_model.md` 的 SHA256 在本轮**未发生变化**（评分与标注均由脚本维护）。

## 附录 A：一键复现清单

```bash
# 1) 离线筛查（零网络）
python _re_ws/vuln_screen.py

# 2) 零流量攻击模拟（宿主路径，等价于容器路径）
python sandbox/attack_sim.py --json sandbox/attack_result.json

# 3) 容器路径（本地须已有 python:3.12-slim，脚本绝不 pull）
sh sandbox/run_in_docker.sh

# 4) 回归测试（34 项）
python -m unittest discover -s tests

# 5) CVSS 复算校验（期望 Δ = 0.0000，21 项）
python _re_ws/cvss_check.py --verify threat_model.md

# 6) 证据门禁（当前 3/3 未闭环 → exit 1，属预期）
python qa_evidence.py

# 7) PoC（默认 dry-run，仅生成签名不发包）
python _re_ws/poc_gateway_sign.py --keyver v1 --dry-run
```

> 第 7 条即使显式指定 URL，只要命中生产域名即 `exit 5`；发包必须同时满足
> `--confirm-authorized` 与授权工单，缺一不可。

## 附录 B：交付物与 .doc 的生成方式

| 交付物 | 说明 |
| --- | --- |
| `某政务App_综合安全评估报告.md` | **唯一修订入口**（UTF-8，可直接进 Git 评审） |
| `某政务App_综合安全评估报告.doc` | Word 二进制文档，由 md 机械转换生成，含 37 张表格与页码 |
| `某政务App_综合安全评估报告.pdf` | 由 .doc 导出的只读版本，便于分发与打印（17 页） |

生成流程（可重复执行，保证 md 与 doc 内容一致）：

```bash
python _san2/_html_build.py        # md -> 中间 HTML（_san2/_build）
powershell -NoProfile -ExecutionPolicy Bypass -File _san2/_word_export.ps1
                                   # HTML -> .doc（另存 97-2003）与 .pdf（导出）
```

Word 转换负责三件 md 无法表达的事：按内容比例把表格列宽铺满版心（避免窄列截断）、
跨页表头自动重复、页脚生成「第 X 页 / 共 Y 页」。因此**修改结论请只改 md**，
再重跑上述两条命令；不要在 Word 里手工编辑 .doc，否则下次生成会被覆盖。






