# 某省政务服务 App（com.example.govapp.activity / “某政务App”）逆向分析与安全评估报告

| 项目 | 内容 |
|---|---|
| 分析对象 | `<APK_DIR>`（已解压的 APK 目录，共 4,185 个文件，212.6 MB） |
| 应用包名 | `com.example.govapp.activity` |
| 启动组件 | `com.example.govbase.gov.main.LoadingActivity` |
| 应用名资源 | `@string/app_name`（图标 `@mipmap/ic_govapp_launcher`，即“某政务App”） |
| 开发/签名方 | 某软件公司（`CN=vendor, OU=<HOST-16>, O=某公司, L=某市, ST=某市, C=CN`） |
| classes.dex | 45,946,008 字节，SHA-256 `<SHA256-1>` |
| 加固方案 | 娜迦 SecNeo APKProtect（`com.secneo.apkwrapper.*`）+ 梆梆 Bangcle（`libDexHelper.so` / `libdexvmp.so`）+ 阿里 Sophix 热修复残留 |
| 版本号 | `versionName = 7.43.0`，`versionCode = 74300`（`apktool.yml`，已用 apktool 3.0.3 从 AXML 资源引用解析） |
| SDK 范围 | `minSdkVersion = 23`，`targetSdkVersion = 30` |
| 签名证书 | `CN=vendor` 自签名，**1024 位 RSA + SHA1withRSA**，有效期 2014-08-17 → 2114-07-24（100 年） |

## 0. 结论摘要

该 App 的**加固强度较高**（DEX 方法体加密 + VMP + 反调试，字符串池仍为明文）；但**加固之外的一切几乎全部失守**：

1. **生产包内置 4 套环境（生产 / 预发 / 测试 / 内网 IP）的网关配置，且 4 套共用同一个网关签名密钥 `gatewaySignSecret`**——密钥硬编码在 manifest 的 meta-data 里，可直接提取用于伪造签名请求。
2. **全域允许明文 HTTP**（`cleartextTrafficPermitted="true"` 且 `usesCleartextTraffic="true"`）：配置文件里有 **41 个** `http://` 端点（文件上传、页面模板、`parser.js` 解析器、证照/搜索历史 JSON、SSO 票据换取接口，且指向非政府域名 `partnercdn.com`）；DEX 字符串池里另有 **187 条去重 `http://` 端点**，其中 **9 条是裸公网 IP**（如 `http://<PUBLIC_IP-1>:8081/uaa/authorize`、`http://<PUBLIC_IP-2>/gateway/identification/simulate/face/initialize`），另有生产域名却走 http 的 `http://<HOST-1>/sso/usp.do`。
3. **`dxAppOpenUrl` 事件处理器把模板传入的任意字符串直接交给路由器 `goToUri()`，无 scheme / host 校验**；而模板可由 HTTP 明文下发 → 中间人可注入 URI 进而调用本地能力。
4. **WebView 白名单 `white_urls_config.json` 有 6,192 条（去重 5,615）**，其中 718 条是裸 IP、437 条是内网/回环地址、334 条为 demo/test 或非常规 TLD、2,990 条非 `.cn` 域名，还包含大量畸形 `host+数字` 字符串——说明白名单是机器拼接生成、且测试环境域名被放进了生产包。
5. **交付包内直接躺着真实格式的公民个人信息**：姓名、校验位有效的身份证号、手机号、会话 `bizKey`、`traceId`（`"env":"pre"`），另有 3 条企业侧记录（其中 `unifiedSocialId` 经 GB 32100 校验为构造值，说明是测试环境真实身份 + 人造企业数据）。
6. **19 个组件 `exported=true` 且未声明任何 `permission`**（另有 1 个含 intent-filter 但未声明 `exported` 的组件按默认规则同样导出，总计 27 个对外可见入口），其中 10 个与支付/登录/分享/推送直接相关，任意本地应用可伪造支付结果回调、劫持第三方登录返回。
7. 签名证书为 **1024 位 RSA + SHA1withRSA** 自签名、有效期 100 年（2014→2114）；包内另有**一把独立的 1024 位 RSA 公钥** `security_public_key`（日志/参数加密用），两把模数不同——完整公钥 PEM、SHA-1/SHA-256/SPKI 三类指纹、`assets` 下 3 个 RSA-2048 公钥与 CA 信任库清单见 **§10（附录 B）**。
8. `FileSelectorProvider` 声明了 **`<root-path path="">`（整个文件系统根）**，配合 JS 桥可把任意本地文件变成 content URI。

> 说明：本次以**静态分析为主**。DEX 方法体被加密（`dexdata0` 记录，45.9 MB，其中 34.6 MB 区段结构保留、11.3 MB 为真密文，详见 §2.2），因此**业务逻辑分支（权限校验、加密实现、网络层校验）未经动态脱壳无法确证**；但类型描述符与字符串常量明文可读，故网络端点、密钥键名等可用字符串证据静态核对。报告中已逐条标注“已验证 / 需动态确认”。
>
> 另：已在本地 LDPlayer 9 + Frida 17.18.0 上做过一次完整动态脱壳尝试，**因 ARM64 翻译层（houdini64）无法承载壳的 arm64 二级代码而失败**；过程、证据与真机复用工具链见 **§9（附录 A）**。

## 1. 分析方法与产物

| 工具 | 用途 |
|---|---|
| apktool 3.0.3 + JRE | 二进制 manifest / resources.arsc / res 解码（`_re_ws/apktool_out`） |
| jadx 1.5.6 | 对 `classes.dex` 反编译（结果仅为壳代码，主体在加密载荷中） |
| Python 3 | 自研脚本（下方清单）；全部按字节/编码感知方式解析，避免 PowerShell 重定向的 UTF-16 污染 |
| `openssl` | 解析 `META-INF/SIG.RSA` 的 PKCS#7 证书，输出密钥长度、算法、有效期与 SHA-1/SHA-256 指纹 |
| LDPlayer 9（9.1.50 / Android 9 / SDK 28 / root）+ frida 17.18.0（x86_64 server）+ jarsigner | 动态脱壳尝试：原样重建 APK、spawn/attach、libc hook、内存 dex 扫描（过程与结论见 §9） |

自研脚本均位于 `<RE_WS>`：

| 脚本 | 作用 |
|---|---|
| `dex_probe.py` / `dex_stub.py` | DEX 头解析、字符串池/类/方法枚举、载荷定位 |
| `qa_dex2.py` / `qa_dex4.py` | `dexdata0` 记录头定位与 1 MB 分箱熵剖面（判定“结构区段 / 真密文”边界） |
| `qa_dex6.py` / `qa_dex7.py` / `qa_dex8.py` | 载荷内明文串统计、URL 提取去重、裸 IP 端点与 assets 交叉比对 |
| `manifest_audit.py` | 组件、权限、application 属性审计 |
| `provider_map.py` | Provider 与 `<paths>` 资源映射、导出组件/深链清单 |
| `scan_secrets.py` → **`scan_text2.py`** | 全量文本扫描（`scan_text2.py` 修正了 UTF-16LE BOM 漏检问题） |
| `scan_pii.py` | 身份证/手机号/统一社会信用代码扫描 |
| `axml_strings.py` / `axml_tree.py` | 二进制 AXML 字符串池与真实节点树还原（关键证据来源） |
| `decode_assets.py` | BOM 感知解码 assets 配置（`decoded/*.txt`） |
| `white_urls_stats.py` / `exported_report.py` | 白名单与导出组件量化统计 |
| `evidence_scan.py` / `evidence3.py` / `arsc_secrets.py` | 配置项、AXML 池、resources.arsc 中密钥的定点取证 |
| `qa_counts.py` / `qa_lines.py` / `qa_http.py` | 报告终检：组件导出统计（298 组件 / 26 导出 / 19 无权限）、引用行号逐行核对、`http://` 端点穷举（41 个） |
| `qa_white.py` / `qa_manifest_meta.py` / `qa_env3.py` | 白名单条目与尾部数字域统计、meta-data 全量键值枚举、四套环境密钥逐块提取 |
| `qa_pii2.py` / `qa_misc.py` / `list_js.py` / `probe_payload.py` | `queryPerson.json` 字段树、`lib/` 平台目录与 assets 配置、源码文件清单（71）、载荷明/密文探测 |
| `qa_md.py` / `qa_refs.py` | 交付前自检：Markdown 表格列数/围栏配对/重复标题，以及报告引用的 41 个脚本是否全部存在 |
| `keyharvest.py` / `harvest2.py` | 密码学材料提取：签名证书公钥与四类指纹、`security_public_key` 完整值、`assets` 公钥与 CA 库、源码内密钥常量扫描（§10） |
| `keyweakness.py` / `hunt3.py` | 弱钥可行性验证（7 类检测）与全树敏感常量/内网端点扫描（§10.7–§10.8） |
| `pack_apk.py` / `fz.py` / `unpack.py`（配套 `dump_mem.js`、`hook_io.js`、`diag.js`、`bypass.js`、`bypass2.js`、`probe_java.js`、`probe_hook.js`） | 动态脱壳：APK 原样重建（保 v1 签名）、spawn/attach 运行器、内存 `dex\n035` 扫描与分片落盘、系统调用轨迹诊断与自毁拦截（详见 §9） |


## 2. 加固机制与脱壳评估

### 2.1 壳的结构（已验证）

`AndroidManifest.xml` 中 `application` 已被替换：

```xml
android:name="com.secneo.apkwrapper.AW"
android:appComponentFactory="com.secneo.apkwrapper.AP"
```

`classes.dex` 本身只是一个**壳存根**：

| 项 | 值 |
|---|---|
| `string_ids_size` | 273 |
| `type_ids_size` | 81 |
| `method_ids_size` | 165 |
| `class_defs_size` | **5** |
| `data_off` / `data_size` | 4000 / 13,528 |

壳字符串池中出现的高价值标识（`_re_ws/dex_stub.txt`）：

- `###SOPHIX###`、`###HAVEX86###`、`###HAVEX8664###` —— Sophix 热修复/加固标记
- `DexHelper`、`DexHelper-x86` —— 梆梆 Bangcle 脱壳器名称（`libDexHelper.so`、`libDexHelper-x86.so`、`libdexvmp.so`、`libdexjni.so` 均在包内）
- `/proc/self/exe`、`/proc/self/status`、`/system/bin/app_process` —— 反调试 / 进程自检
- `ISSOPHIX`、`ACFNAME`、`APPNAME`、`ARM_LIBRARY`

除 `classes.dex` 外没有 `classes2.dex` 等分包，**全部业务代码都在加密载荷里**。另有一个**明文** DEX 随包放在 assets：`assets/RiskStub.dex`（472,688 B，`dex\n035`，405 个类 / 4,602 字符串 / 3,553 方法），是壳用于风险检测的 stub（配套 `assets/arm64-v8a/libRiskStub.so`），可被 jadx 直接反编译——但它与业务逻辑无关，**不能替代脱壳**。

### 2.2 加密载荷 `dexdata0`（已验证）

DEX 尾部（偏移 17,528，正好等于 `data_off + data_size = 4,000 + 13,528`）紧跟一个自描述容器：

```
01 00 00 00 | 14 d0 bc 02 | 08 00 00 00 | "dexdata0" 00 | ...
ver = 1     len = 45,928,468  nameLen = 8    name = dexdata0
```

- 单条记录、`name="dexdata0"`、长度 45,928,468 字节，载荷自偏移 **17,549** 起；声明长度比文件实际剩余字节（45,928,459）**多 9 字节**（尾部对齐/校验字段未计入）；
- 记录头与文件长度相互印证：`17,549 + 45,928,468 = 45,946,017 ≈ 45,946,008` → **整段载荷就藏在这一个 `classes.dex` 里，包内不存在独立的 `dexdata0` 文件**；
- 全文件仅出现 1 次 `PK\x03\x04`（偏移 8,342,244）且**无法解析为 ZIP**；载荷内 `dex\n035` 出现 **0** 次 → 没有可直接加载的明文 DEX / ZIP。

**关键修正：载荷不是“整段密文”。** 1 MB 分箱熵剖面（`qa_dex4.py`）把载荷劈成两个区段：

| 区段 | 偏移范围 | 长度（字节） | 1 MB 分箱熵 | 形态 |
|---|---|---|---|---|
| A | 17,549 – 34,620,557 | 34,603,008（= 0x2100000） | **5.49 – 6.79** | 结构保留：类型/方法描述符与字符串常量**明文可读**，仅方法体被加密 |
| B | 34,620,557 – 45,946,008 | 11,325,451 | **7.998 – 8.000** | 真密文 |

区段 A 的明文残留（`qa_dex6.py` 直接 `count`）：`Lcom/alibaba` **11,587** 次、`Landroid/` 3,413 次、`Ljava/` 3,334 次、`Lcom/alipay` 2,513 次、`https://` 461 次、`http://` 238 次、`goToUri` 9 次、`gatewaySignSecret` 1 次；≥20 字符可打印串 13.6 万条，其中 3.2 万条是 `Lcom/ali/zw/biz/rxdatasource/model/BillBean;` 这类类名（含方法签名）。同样口径统计区段 B 只有 542 条。

由此得到一条对本次评估很关键的**方法论结论**：

- **方法体（`code_item` 指令流）不可反编译**，业务逻辑仍只能动态验证 → 正文所有“需动态确认”标注保持不变；
- **但字符串池（类型描述符、方法签名、字符串常量）是明文**，因此可用“字符串证据”做静态核对：C-2 补充的 187 条 DEX 内 `http://` 端点、H-4 的密钥键名、`goToUri` / `TesseractRouter` 等方法名，均取自该区段，可复现；
- 反向证据同样有效：区段 A 中 `CertificatePinner` / `certificatePinner` 命中 **0** 次 → 提示未使用 OkHttp 证书绑定（削弱“已被证书绑定兜底”的辩解，但仍需动态确认）。

### 2.3 反分析面（部分验证）

- `lib/arm64-v8a` 共 68 个 `.so`（102.7 MB），与对抗相关：`libDexHelper.so`、`libDexHelper-x86.so`、`libdexvmp.so`、`libdexjni.so`、`libentryexpro.so`（SecNeo 入口）、`libbangcle_risk.so`、`libnllvm1755524409775.so`（随机命名、疑似 LLVM 混淆运行时）、`libxyvp.so`、`libmsaoaidsec.so`、`libipdetector.so`、`libnet_tool.so`、`libwind.so`。注：其中 `libDexHelper-x86.so` **实为 x86-64 ELF**（`e_machine 0x3e`）却被放在 arm64 目录，`libDexHelper.so` 才是 AArch64 —— 实测差异见 §9.5。
- `assets/arm64-v8a/libRiskStub.so`（369,552 B）—— 从 assets 二次释放的 so，绕过 `lib/` 静态扫描。
- `privacyStrategy.json` 中存在 `getExecPs`、`getPackageListByShell` 等敏感调用（见 M-5）。

**脱壳建议（后续工作）**：`frida` hook `DexHelper` / `InMemoryDexClassLoader`，或 `frida-dexdump` 在 attach 后 dump 内存中的 `dex\n035`；也可 hook `libDexHelper.so` 的 `JNI_OnLoad` 后关掉其反调试。脱壳后可继续验证：`IRouterService.goToUri` 实现、网络层证书校验、`gatewaySignSecret` 的签名算法、WebView 白名单的匹配方式（`startsWith`/`contains`/精确 `equals`）。**该路线已在本机实测，因 ARM64 翻译层限制未取得明文 DEX——过程与失败点见 §9（含真机复用工具链）。**

## 3. 漏洞清单（按严重度）

> 等级：**严重** / **高危** / **中危** / **低危**。所有“已验证”项均给出可复核的文件与行号/偏移。

### C-1【严重】网关签名密钥硬编码，且生产/测试/预发/内网四套环境共用同一把密钥（已验证）

**位置**：`AndroidManifest.xml` → `<meta-data android:name="alibaba_gov_module_config">`（AXML 字符串池，全文见 `_re_ws/metadata.txt`）。

```
gatewaySignSecret = [REDACTED_SECRET:24]      ← 4 套环境完全相同（qa_env3.py 逐块提取）
```

| 环境 | meta-data key | `gatewayUrl` | `baseHost` | 文件上传接口 |
|---|---|---|---|---|
| 生产 | `alibaba_gov_module_config` | `https://<HOST-2>/app/mgop` | `https://<HOST-3>` | `https://<HOST-4>/…/fileupload` |
| 预发 | `…_pre` | `https://<HOST-5>/app/mgop` | `https://<HOST-6>` | `http://<HOST-7>/…/fileupload` |
| 测试 | `…_test` | `http://<HOST-8>/app/mgop` | `http://<PUBLIC_IP-3>` | `http://<HOST-7>/…/fileupload` |
| 内网 | `…_dev` | `http://<PUBLIC_IP-4>:8068/app/mgop` | `http://<HOST-8>` | `http://<HOST-7>/…/fileupload` |

**影响**：
1. `gatewaySignSecret` 是网关请求签名（HMAC）的对称密钥，提取后可**离线构造合法签名**，绕过服务端“请求来自官方客户端”的校验，进行批量调用、参数篡改与越权枚举。
2. 生产与测试**共用同一把密钥**；而测试网关是**明文 HTTP**（`http://<HOST-8>/app/mgop`），意味着抓一次测试环境的包就能同时拿到请求签名与签名算法，随后**原样用于生产网关**——测试环境一泄露，生产即等价失守。
3. 包内保留 `http://<PUBLIC_IP-4>:8068`、`http://<PUBLIC_IP-3>` 等**测试/内网直连地址**，为内网探测提供现成入口。

**修复**：签名密钥改为运行时协商下发（设备绑定 + TEE/白盒保护）或改非对称签名；release 剥离 test/pre/内网配置；测试环境使用独立密钥。

### C-2【严重】全局允许明文 HTTP，敏感接口/脚本/模板确实走 `http://`（已验证）

**位置**：`res/xml/network_security_config.xml`（AXML 还原，`axml_tree.py`）：

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true"/>
  <debug-overrides>
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

叠加 manifest 的 `android:usesCleartextTraffic="true"`：**对全部域名放开明文**，无任何 `<domain-config>` 例外表。

**已确认的 `http://` 端点**（`scan_text2.txt` 第 44-84 行，共 **41** 个不同 URL，全部为明文）：

```
http://<HOST-7>/wireless/endpoint/portal/file_manager/fileupload   ← 文件上传（pre/test/dev 三套配置；prod 用 https）
http://<HOST-4>/                                                 ← 运营后台（prod 配置内）
http://<HOST-3>/overrideSpace/tools/parser.js                  ← 可执行解析脚本
http://<HOST-3>/overrideSpace/search/ParseHistory.js           ← 个人搜索历史解析
http://<HOST-3>/overrideSpace/search/ParseRecommend.js
http://<HOST-3>/overrideSpace/search/app_search_history.json   ← 搜索历史数据
http://<HOST-3>/overrideSpace/search/app_search_result.json    ← 搜索结果
http://<HOST-3>/overrideSpace/license/ep_source_auth_list.json ← 证照授权清单
http://<HOST-3>/overrideSpace/license/ep_source_license_list.json ← 我的证照清单
http://<HOST-3>/overrideSpace/license/app_my_license_empty.json
http://<HOST-9>/oss/upload/<REDACTED-PARTIAL>/pre/templates/*.json    ← 页面模板（2 个）
http://<HOST-6>/overrideSpace/tools/parser.js
http://<HOST-6>/overrideSpace/search/ParserSearchResult_v1_5.js
http://<HOST-10>
http://<HOST-11>/art/2023/5/18/art_1229699341_10820.html               ← 政策原文页（4 个）
http://<HOST-12>/uc/auth/token                                 ← SSO 票据换取（非政府域名）
http://<HOST-13>/upload/e5b795d4-….json                    ← POC 资源
http://<HOST-8>/app/mgop                                      ← 测试网关
http://<PUBLIC_IP-4>:8068/app/mgop  http://<PUBLIC_IP-3>                    ← 测试机裸 IP
http://<PUBLIC_IP-5>  http://<PUBLIC_IP-6>:8080/dist/#/  http://<PUBLIC_IP-7>:8080
```

**补充：DEX 字符串池里的明文端点更多**（`qa_dex7.py`，取自 §2.2 区段 A 的明文串）：`(?:https?)://…` 共命中 642 次、去重 **535** 条，其中 `http://` **187** 条、`https://` **348** 条。**9 条是裸公网 IP 的明文端点，且这些 IP 在 assets/config 中一次都没出现**（`qa_dex8.py`），说明它们写死在业务/SDK 代码里：

```
http://<PUBLIC_IP-1>:8081/uaa/authorize                                  ← OAuth2 授权端点，明文 + 裸 IP
http://<PUBLIC_IP-8>:8080/usp.do                                       ← usp.do 的另一台裸 IP + 8080
http://<PUBLIC_IP-9>:8088/yjj/sso/login                               ← 医保（yjj）SSO 登录
http://<PUBLIC_IP-10>/sso/mobile.do?   http://<PUBLIC_IP-11>/sso/mobile.do ← OAuth 跳转（明文）
http://<PUBLIC_IP-2>/gateway/identification/simulate/face/initialize  ← 人脸核身“simulate”接口
http://<PUBLIC_IP-12>/gateway/identification/simulate/face/initialize   ← 同上（第二台）
http://<PUBLIC_IP-13>   http://<PUBLIC_IP-3>                                ← 两个裸 IP 根地址
```

> 第 10 条 `http://<HOST-1>/sso/usp.do` 不是裸 IP（是生产域名但走 http），与 `https://<HOST-1>/sso/usp.do` 同时存在于字符串池 —— 见下段。

对照 `https://<HOST-1>/sso/usp.do`（同一接口的 https 版本）也在池中：**同一套 SSO 接口同时存在 http/https 两个入口**，说明服务端支持 TLS，客户端仍保留了明文调用路径。这 187 条端点是否都被业务路径实际调用，需动态验证（方法体不可读），但“明文 URL 已固化进代码常量池”本身是可复现的包内事实。

**最硬的一条证据**：不必依赖“切环境”——**生产配置块本身**（`alibaba_gov_module_config`，10,285 字符）里就有 7 处 `http://`，其中 4 处是**运行时会真正加载**的资源：

```
"EPLicenseCenter": { "baseUrl": "http://<HOST-3>", … }   ← 电子证照模块地址（生产）
  egov://license/my       templateUrl = http://<HOST-3>/overrideSpace/license/ep_source_license_list_v2.json
  egov://license/auth_me  templateUrl = http://<HOST-3>/overrideSpace/license/ep_source_auth_list_v2.json
  parserUrl（3 处）                    = http://<HOST-3>/overrideSpace/tools/parser.js
  另 2 处：http://<HOST-10>、http://<HOST-4>/
```

即“我的证照”“授权我的”两个页面在**生产环境**下就是用 `http://` 拉取模板与 `parser.js`。


> `assets/ep_pbk_common_js_entry.html:6` 本地入口用的是 `https://<HOST-3>/overrideSpace/tools/parser.js`（已逐行核对），说明开发者清楚要写 https；但**运行时配置仍下发 http**：`search_config.json:206-207`（`ParserSearchResult_v1_5.js`）、`:258`（`"debug": "http://<HOST-8>"`）、`:259`（`"canary": "http://<HOST-6>"`）。即“本地壳用 https、真正生效的远程配置用 http”。

**影响**：搜索历史、电子证照授权清单（`ep_source_auth_list/license_list`）、页面模板可被中间人读取/篡改；`parser.js`、`ParseHistory.js` 是**可执行脚本**，篡改后可在 App 的 JS 引擎/WebView 内执行任意逻辑（与 C-3 组合成完整攻击链）；文件上传接口明文传输，用户证件材料可被截获。**更严重的是认证类端点也在明文清单里**：`uaa/authorize`（OAuth2 授权码）、`sso/usp.do`（统一用户服务）、`yjj/sso/login`（医保登录）、`simulate/face/initialize`（人脸核身初始化）全部可被同网段攻击者截获或伪造响应 —— 授权码/票据被截获即等价账号接管，核身初始化被替换即可把活体检测流程指向攻击者控制的“永远通过”环境。

**修复**：`cleartextTrafficPermitted="false"`；所有 `<HOST-17>`/`<HOST-18>` 强制 TLS；配置下发改 https 并做主机白名单；第三方（`partnercdn.com`）SSO 接口强制 https + 证书绑定；同时清理 DEX 中 187 条明文 URL（尤其 9 条裸 IP），把基址改为编译期注入或签名配置下发。

### C-3【严重】`dxAppOpenUrl` 零校验直通路由器；`gotoApaasPage` 信任服务端返回的 URL（已验证）

**位置 1**：`assets/com/alibaba/tesseract/page/events/AppOpenUrlEventHandler.java:51`（事件名常量在第 32 行：`TAG_ID = DXHashUtil.hash("dxAppOpenUrl")`）

```java
public static final long TAG_ID = DXHashUtil.hash("dxAppOpenUrl");
...
routerService.goToUri(runtimeContext.getContext(), args[0].toString(), bundle);  // 无 scheme / host 校验
```

模板事件参数 `args[0]` 可为**任意字符串**：`file://`、`content://`、`intent://…#Intent;…end`、`weixin://`、`alipays://`、`router://`。而模板由服务端下发且允许明文 HTTP（C-2），构成“**模板注入 → 任意 URI 执行**”链路：可读取/外发本地文件（配合 H-1 的 `root-path`）、拉起任意导出组件、绕过页面级权限判断直达内部路由。

**位置 2**：`assets/com/alibaba/tesseract/page/manager/TesseractRouter.java:35-61`

```java
new RequestBuilder(copyParameters(url, getBaseHost() + "/portal/app/redirect", filterKeys))
...
newUrl = jsonObject.getString("data");      // 完全信任服务端返回
routerService.goToUri(context, newUrl);     // 直接路由
// 失败降级：routerService.goToUri(context, url.replace("_apaas_=true", ""));
```

`getBaseHost()` 读 `baseHost`，而该配置存在 **http** 变体（`http://<HOST-8>`、`http://<PUBLIC_IP-3>`）。中间人篡改 `/portal/app/redirect` 响应里的 `data` 即可让 App 路由到任意 URI。同时 `copyParameters()` 把原 URL 的**全部查询参数**（可能含 ticket/authCode）拼到重定向地址——baseHost 一旦被替换，票据直接外泄。

**修复**：`goToUri` 前强制校验 scheme ∈ 白名单（`https`/`gov`/`gov`）、host ∈ 白名单，禁止 `intent://`、`file://`、`javascript:`；对重定向返回的 `data` 做同样校验并限定同源 https；`copyParameters` 改显式白名单。

### C-4【严重】WebView 白名单规模失控：含内网 IP、测试域名与畸形条目（已验证）

**位置**：`assets/white_urls_config.json`（148,113 字节）

**统计**（`white_urls_stats.py` → `white_urls_stats.txt`）：

| 指标 | 数量 |
|---|---|
| 总条目 | 6,192 |
| 去重后 | 5,615 |
| 裸 IP 条目 | 718 |
| 内网/回环/链路本地 IP | **437**（`<PRIVATE_IP-1>`、`<PRIVATE_IP-2>`、`<MALFORMED_IP-1>`、`<PRIVATE_IP-3>`、`127.0.0.1` …） |
| `host+数字` 畸形条目（IP 形态） | 50（`220.191.236.2055`、`<MALFORMED_IP-2>`、`<MALFORMED_IP-3>` …；域名形态另见下行） |
| demo/test/dev 或非常规 TLD | 334（`<HOST-19>`、`<HOST-20>`、`<HOST-21>`、`<HOST-22>`、`<HOST-23>`、`jupiter.doc.test`、`<HOST-24>` …） |
| 非 `.cn` 结尾 | 2,990 |
| “错拼”域名（`域名+数字` 尾部粘连） | 125（`www.hfi-health.com1`、`<HOST-25>.cn9`、`<HOST-26>.cn8`、`<HOST-27>.cn3` …） |

**影响**：
1. 放行 **RFC1918 内网地址与 `127.0.0.1`**：配合明文放行，WebView 可被诱导访问内网/本机服务（SSRF 类），在办公网内可探测内网资产或本机端口；
2. 放行大量 **test/demo 域名**：测试环境鉴权弱、接口同构，成为绕过生产防护的侧门；
3. `host+端口` 粘连与错拼域名说明该文件是**脚本从真实 URL 截取拼接**生成。若匹配逻辑是 `contains`/`startsWith`（需脱壳确认），则 `<HOST-28>`、`<HOST-29>` 之类均可绕过。

**修复**：按域精确匹配（`Uri.parse(url).getHost()` 后 `equals`）+ 强制 https + 移除 IP 与内网段；release 自动剔除 test/demo；禁止 `contains` 式匹配。

### H-1【高危】`FileSelectorProvider` 暴露整个文件系统根（已验证）

**位置**：`res/xml/file_selector_file_paths.xml`（AXML 还原，`axml_tree.py`）

```xml
<paths>
  <external-path name="external" path=""/>        <!-- 整个外部存储 -->
  <files-path name="files" path=""/>              <!-- 整个应用私有目录 -->
  <cache-path name="cache" path=""/>
  <external-files-path name="external_files" path="."/>
  <external-cache-path name="external_cache" path="."/>
  <root-path name="storage" path=""/>             <!-- ★ 文件系统根 / -->
  <external-path name="storage" path="storage/"/>
</paths>
```

**准确的组件属性**（`provider_map.py` 解析二进制 manifest）：

```
com.example.govbase.fileselector.FileSelectorProvider
  authorities        = com.example.govapp.activity.fileSelectorProvider
  exported           = false          ← 更正：早期记录为 true，实际不导出
  grantUriPermissions = true
  meta-data          = @xml/file_selector_file_paths
```

**影响**：Provider 不导出，外部应用无法直接访问，因此等级定为**高危而非严重**。但 `grantUriPermissions=true` + `root-path path=""` 意味着：只要 App 内部有一处把该 Provider 的 URI 授予外部（分享、带 `FLAG_GRANT_READ_URI_PERMISSION` 的 Intent、交给 WebView/外部浏览器），被授予方即可读取**任意路径**（`/data/data/*`、`/sdcard/*`、其他应用私有目录）。结合 C-3 的任意 URI 路由与 JS 桥，可形成“模板调用文件选择 API → 得到根目录 content URI → 经 `dxAppOpenUrl` 交给外部”的链条。`res/xml/file_paths.xml` 中 `share_files`、`my_images` 同样使用 `path="."` 的宽范围映射。

**修复**：删除 `<root-path>`；`external-path`/`files-path` 收敛到具体子目录；仅在必要场景授予 URI 权限并对每次授权做路径校验（`getCanonicalPath().startsWith(allowedDir)`）。

### H-2【高危】发行包内携带真实格式公民个人信息（已验证）

**位置**：`assets/queryPerson.json`（UTF-16LE + BOM，3,916 B = 单行 1,957 字符 JSON；解码副本 `_re_ws/decoded/queryPerson.json.txt`）

**内容**（本报告已对姓名/证件/手机号脱敏，完整原值见本地解码文件）：

```
success: true,  env: "pre",  traceId: "<TRACE-ID>"

legalAccountList[0..2]  ← 3 个法人账号（accountId <ACCOUNT-ID-1> / <ACCOUNT-ID-2> / <ACCOUNT-ID-3>）
  legalPersonInfo.name = "某省某**测试用企业" / "某省某*测试用企业2" / "某省某*测试用企业"   ← 企业名内嵌真实姓名
  legalPersonInfo.unifiedSocialId = "<USCC-3>" / "<USCC-1>" / "<USCC-2>"
  personInfo.userName   = "*某"（原值 2 字）        ← 真实姓名，明文字段
  personInfo.userNameEnc= "*某"                     ← 服务端返回原样：只遮了第 1 个字
  personInfo.phone      = "<PHONE-MASKED>"             ← 本报告打码；原值为 11 位明文
  personInfo.phoneEnc   = "<PHONE-MASKED>"
  personInfo.idNo       = "<IDCARD-MASKED>"      ← 本报告打码；原值为完整 18 位
  personInfo.idNoEnc    = "3****************5"      ← 只留首尾
  attributes.bizKey     = "LEGAL_SWITCH_BIZ_KEY_<uuid>"
  account               = "<ACCOUNT-2>" / "<ACCOUNT-3>" / "<ACCOUNT-4>"
personAccountList[0]
  personInfo 同上；account = "<ACCOUNT>"；bizKey = "PERSON_SWITCH_BIZ_KEY_<uuid>"
```

- **3 条企业侧记录**（各带一个 18 位 `unifiedSocialId`）、**4 条 `bizKey`**（`LEGAL_SWITCH_BIZ_KEY_*` ×3 + `PERSON_SWITCH_BIZ_KEY_*` ×1）、**4 个账号**；
- **企业侧代码校验**（按 GB 32100-2015 重算校验位）：`<USCC-1>`、`<USCC-2>` 校验位自洽（`4`、`J`），但后者前缀 `8` 属未分配的登记管理部门码；`<USCC-3>` 含 GB 32100 明确剔除的字母 `S`，**不可能**是真实代码 —— 说明企业侧字段是测试环境人工构造，而 `personInfo` 的身份证/手机号/姓名是真的；
- **身份证号校验位计算通过**（`list_js.py`：前 17 位加权和 mod 11 → 校验位 `5`，与第 18 位一致），符合真实公民身份号码规则（前 6 位为行政区划码、第 7–14 位为出生日期）；手机号 `<PHONE-1>` 为有效号段；
- 注意结构上的失误：同一对象里 `phone`（明文）与 `phoneEnc`（`<PHONE-MASKED>`）、`idNo`（明文）与 `idNoEnc` 同时存在 —— **脱敏逻辑只作用于 `*Enc` 字段，明文副本原样返回并落了盘**；
- 虽然企业名带“测试用企业”，但**姓名、身份证、手机号是真实格式且随正式版 APK 分发**，任何下载者都能提取；若确属真实公民（很可能是开发/测试人员的真实身份），即构成《个人信息保护法》意义上的个人信息泄露事件。

**影响**：直接 PII 泄露 + 可作撞库/社工语料；若 `bizKey` 仍是有效会话令牌，可进一步越权（需服务端确认失效状态）。

> 取证校正：`scan_pii.py` 另在 `res/raw/rvtools_inject_js.js:29` 报出一处“手机号”，逐行核对后确认是 `errorCode: <PHONE-2>`（错误码误报，非 PII）。本条目只计入 `queryPerson.json` 内的真实 PII。

**修复**：立即从 assets 删除该文件及任何抓包回放数据；改为运行时请求、不入包；对已泄露账号做令牌失效与风险排查；在 CI 中加入身份证/手机号正则门禁，禁止 PII 入库/入包。

### H-3【高危】19 个组件导出且未声明任何权限，含支付/登录回调（已验证）

**统计口径**（`manifest_audit.txt` 全量解析，脚本 `qa_counts.py`；四个组件节 + alias 合计 **298** 个组件节点，不含 `meta-data` 106 条与 `uses-library` 3 条）：

```
组件节点总数                        298     （activity 233 / activity-alias 1 / service 37 / receiver 12 / provider 15）
android:exported="true"              26
其中未声明 android:permission        19      ← 本条目
含 intent-filter 却未声明 exported    1      （com.sina.weibo.sdk.share.ShareResultActivity，按规则默认导出）
android:exported="false"            107
未声明 exported                     165
```

19 个“导出且无权限”的完整清单：

```
com.example.govbase.gov.main.LoadingActivity          （launcher，正常）
com.example.govbase.gov.router.RouteActivity          （gov:// 与 ut.[REDACTED_APPID:8]:// 深链入口）
com.example.govbiz.common.activity.HelpPushActivity            （agoo://…/thirdpush 推送落地页，外部可直接构造）
com.example.govbase.gov.login.ZWThridAppAuthActivity
com.example.govapp.activity.wxapi.WXPayEntryActivity
com.example.govapp.activity.wxapi.WXEntryActivity
com.example.govapp.activity.ddshare.DDShareActivity
com.example.govbase.wauth.ZWWAuthTmpActivity
com.thunisoft.meet.MeetActivity
com.alipay.sdk.app.PayResultActivity
com.alipay.sdk.app.AlipayResultActivity
com.xiaomi.mipush.sdk.NotificationClickedActivity
com.umeng.message.UMessageNotifyActivity
com.taobao.accs.data.MsgDistributeService
com.huawei.hms.support.api.push.service.HmsMsgService
com.vivo.push.sdk.service.CommandClientService
com.alipay.tianyan.mobilesdk.TianyanLoggingService
com.example.govbiz.common.MfrMzMessageReceiver
org.android.agoo.xiaomi.MiPushBroadcastReceiver
```

其中与资金/身份直接相关、可利用性最高的 10 个：

| 组件 | 类型 | 风险 |
|---|---|---|
| `com.alipay.sdk.app.PayResultActivity` | Activity | 任意应用可发送伪造的支付宝支付结果 Intent，诱导客户端展示“支付成功” |
| `com.alipay.sdk.app.AlipayResultActivity` | Activity | 同上 |
| `com.example.govapp.activity.wxapi.WXPayEntryActivity` | Activity | 微信支付回调可被伪造；若服务端未二次查单即可绕过 |
| `com.example.govapp.activity.wxapi.WXEntryActivity` | Activity | 微信登录 code 回调可被劫持/伪造，抢占登录态 |
| `com.example.govbase.gov.login.ZWThridAppAuthActivity` | Activity（无 filter 也导出） | 任意应用可直接拉起第三方登录并注入 extras |
| `com.example.govbase.wauth.ZWWAuthTmpActivity` | Activity | 认证/授权临时页可被外部拉起 |
| `com.thunisoft.meet.MeetActivity` | Activity | 会议组件可被外部直接拉起 |
| `com.example.govapp.activity.ddshare.DDShareActivity` | Activity | 钉钉分享回调可伪造 |
| `com.taobao.accs.data.MsgDistributeService` | Service | 可被外部 start/bind，向 ACCS 通道注入消息 |
| `com.example.govbiz.common.MfrMzMessageReceiver` | Receiver | 广播可被外部伪造触发 |

**额外发现（深链入口）**：对外可用的 scheme 只有 3 个 —— `gov://` 与 `ut.[REDACTED_APPID:8]://` 指向 `RouteActivity`（`exported=true`），`agoo://com.example.govapp.activity/thirdpush` 指向 `HelpPushActivity`（`exported=true`，推送落地页，外部应用可直接构造该深链触发）。**好消息是**：`gov://login/main`（`ZWLoginActivityV3`）、`gov://userlogin/main`（`ZWLoginActivity`）、`gov://scan/scancode`（`ScanCodeCaptureActivity`、`CaptureActivity`）这 4 个敏感深链目标**均已正确设置 `exported=false`**，外部应用无法直接唤醒（见 §4）；但它们仍可被 C-3 的 `goToUri()` 从**应用内部**触达，因此不构成缓解 C-3 的理由。

> 计数说明：`provider_map.txt` 的同类清单列为 18 项，与本节的 19 项差异来自 `com.umeng.message.UMessageNotifyActivity`（`<activity-alias>` 节点，`qa_counts.py` 计入、`provider_map.py` 未计入）。

**另**：`com.sina.weibo.sdk.share.ShareResultActivity` 是唯一“含 intent-filter 却未显式声明 `exported`”的组件，按 Android 规则默认为导出；由于 `targetSdk=30` 未触发 Android 12 的强制显式声明要求，该隐患会一直保留。

**修复**：回调类组件一律 `android:exported="false"`（微信/支付宝回调若必须导出，则加签名级自定义 `android:permission` 或校验 `callingPackage`/签名摘要）；支付结果以**服务端主动查单**为准，绝不信任客户端回调。

### H-4【高危】多平台 AppSecret / API Key 硬编码（已验证）

**位置**：`AndroidManifest.xml` 的多个 `<meta-data>`（AXML 字符串池）、`resources.arsc` 字符串池、`assets/supplierconfig.json`。汇总：

| 平台/用途 | 键 | 值 |
|---|---|---|
| 网关签名 | `gatewaySignSecret` | `[REDACTED_SECRET:24]` |
| 微信（分享/朋友圈） | `shareKey` + `shareSecret` | 生产块 `[REDACTED_APPID:18]`、测试块 `[REDACTED_APPID:18]`（预发/内网块两者混用）；两个 appId **共用同一** `shareSecret` = `[REDACTED_HEX32:32]` |
| 微博 | `shareKey` + `shareSecret` | `[REDACTED_APPID:10]` + `[REDACTED_HEX32:32]` |
| 钉钉 | `shareKey` | `[REDACTED_APPID:20]`（`shareSecret` 为空） |
| 微信支付 | `pay[]` → `WechatPayService.appKey` | `[REDACTED_APPID:18]`（与微信分享同一 appId；`AliPay`/`UnionPay` 的 `appKey` 均为空串） |
| mPaaS / UT | `appId` / `appSecret` / `appKey` / `baseLine` | `[REDACTED_HEX32:32]` / `[REDACTED_SECRET:18]` / `[REDACTED_HEX32:32]_android` / `[REDACTED_HEX32:32]` |
| 阿里百川 / 热修复（`com.alibaba.app.*`） | `appkey` / `appsecret` | `[REDACTED_APPID:8]` / `[REDACTED_HEX32:32]` |
| 友盟（APM/UT） | `atmConfig`（两套） | ①`atm_server_host=<HOST-30>`、`atm_channel=channel_govsvc`、`atm_appkey=[REDACTED_APPID:8]`（该值同时被用作深链 scheme `ut.[REDACTED_APPID:8]`）；②`atm_server_host=https://<HOST-14>/`、`atm_channel=android`、`atm_appkey=[REDACTED_SECRET:25]` |
| 小米推送 | `MIPUSH_APPID` / `MIPUSH_APPKEY` | `[REDACTED_APPID:19].0` / `[REDACTED_APPID:13].0`（manifest 原文如此：打包时被写成浮点，`[REDACTED_APPID:19]` 已超出 double 的 15–17 位有效数字，**末 2 位不可信**，需用小米后台核对真实 appid） |
| 华为 HMS | `com.huawei.hms.client.appid` | `[REDACTED_APPID:9]` |
| 高德地图 | `amap_api_v2_apikey` | `[REDACTED_KEY:19]`（AXML 字符串池共 4 个变体：`[REDACTED_KEY:9]` / `[REDACTED_KEY:12]` / `[REDACTED_KEY:19]` / `[REDACTED_KEY:20]`，系池内截断/拼接所致，完整值需动态确认） |
| 友盟崩溃上报 | `crash.key`（`channel=Umeng`） | `[REDACTED_HEX24:24]` |
| 日志/参数加密 | `security_public_key`（`resources.arsc`） | 1024 位 RSA 公钥，完整 216 字符 base64 = `[REDACTED_RSA1024_PUBKEY]`；SPKI SHA-256 = `<SHA256-3>`（完整值与模数见 §10.2） |
| UC 内核 | `Jupiter.UCInitKey`（2 项数组） | `[REDACTED_B64:88]`、`[REDACTED_B64:88]` |
| vivo 推送 | `com.vivo.push.api_key` / `app_id`（manifest）+ `assets/supplierconfig.json` | `[REDACTED_UUID:36]` / `[REDACTED_APPID:5]`；`supplierconfig.json` 内另写 `{"appid":[REDACTED_APPID:9]}`（68 B，两处 appid 不一致） |

> 出处：含 `gatewaySignSecret`/`share`/`pay` 的前 5 行取自 `alibaba_gov_module_config` 环境配置 JSON（`qa_h4.py` 交叉核对，四个环境块均含 `share` 与 `pay` 两段，输出见 `qa_h4.out`）；`com.alibaba.app.*`、`MIPUSH_*`、`com.huawei.hms.client.appid`、`amap_api_v2_apikey` 为独立 `<meta-data>`（`qa_manifest_meta.py` 逐条枚举，见 `qa_manifest_meta.out`）；`crash.key` 与 `Jupiter.UCInitKey`（2 元素数组）同在环境配置 JSON 内。

**影响**：
- **微信 AppSecret 泄露最严重**：持有 `appId + AppSecret` 可调用微信开放平台接口换取 `access_token`，进而以该政务应用的官方身份调用用户信息、发送模板消息、操作素材——等同于账号被接管；
- mPaaS `appSecret` 可用于伪造设备注册/推送通道；高德 key 可被盗刷配额；`security_public_key` 为 **1024 位 RSA**，本身强度不足（见 M-1）。

**修复**：所有 AppSecret 一律不得入包——改为服务端代签（App 只持短期票据）；已泄露的密钥立即轮换并核查调用日志；`security_public_key` 升级至 RSA-2048/3072 或改用 ECDH/X25519。

### H-5【高危】SSO 票据拦截规则把 `authCode` 送往非政府域名的明文接口（已验证）

**位置**：`assets/sso_config.json`（564 B），`data[]` 三条规则，逐行核对如下（第 4 行即 `urlPrefix`）：

```json
{
  "data": [
    {  // 第 3-9 行
      "urlPrefix": "http://<HOST-12>/uc/auth/token",   // ← 第 4 行：非政府域名 + 明文 HTTP
      "params": { "_as": "inner" },
      "checkParamKey": "authCode"
    },
    {  // 第 10-17 行
      "urlPrefix": "https://<HOST-1>/sso/mobile.do",
      "params": { "_as": "person", "_acout": "0" },
      "checkParamKey": "ticket"
    },
    {  // 第 18-25 行
      "urlPrefix": "https://<HOST-15>/opensso/spsaehandler/metaAlias/sp",
      "params": { "_as": "legal", "_acout": "0" },
      "checkParamKey": "ticket"
    }
  ]
}
```

**影响**：该配置是“URL 拦截→换取登录态”的规则表。规则 1 会在 URL 里出现 `authCode` 时触发，把票据 POST 到 **`partnercdn.com`（第三方商业域名）且走 http**。任何能诱导 App 加载带 `authCode` 参数的页面的攻击者（例如通过 C-3 的任意 URI 路由、或外部链接唤起 `RouteActivity`），都能触发这次外发；在明文链路上该 `authCode` 可被直接截获并用于换取用户会话 → **账号接管**。

**修复**：该规则改为 `https://` 且域名收敛到 `*.gov.cn`；`checkParamKey` 命中时校验来源 host 是否在白名单；票据一次性使用并绑定设备指纹。

### M-1【中危】签名证书为 1024 位 RSA + SHA-1，且有效期 100 年（已验证）

**位置**：`META-INF/SIG.RSA`（PKCS#7，941 B）、`META-INF/SIG.SF`、`META-INF/MANIFEST.MF`（483 KB）

`openssl pkcs7 -inform DER -in SIG.RSA -print_certs -text` 输出：

```
Subject:  C=CN, ST=某市, L=某市, O=某公司, OU=<HOST-16>, CN=vendor
Issuer:   C=CN, ST=某市, L=某市, O=某公司, OU=<HOST-16>, CN=vendor   ← 自签名
Serial:   [REDACTED_SERIAL]
Signature Algorithm: sha1WithRSAEncryption
Public-Key: (1024 bit)                       ← 低于当前最低要求 2048
Not Before: Aug 17 22:10:31 2014 GMT
Not After : Jul 24 22:10:31 2114 GMT         ← 有效期 100 年
SHA-1   : <CERT-FINGERPRINT>
SHA-256 : <CERT-FINGERPRINT>
```

**影响**：
- **1024 位 RSA 已被 NIST 于 2013 年弃用**（SP 800-57 规定 2013 年后不得新用于数字签名）；一旦签名私钥被伪造，攻击者可发布同包名 + 同证书的“合法”更新包，绕过 Android 的升级验签，实现**供应链投毒**——对政务 App 这是最高价值攻击面。
- **算法坑位要分开看（本次实测修正）**：证书的**自签名**用 `sha1WithRSAEncryption`，但 **APK 逐条目摘要全部是 SHA-256**——`MANIFEST.MF` 里 `SHA-256-Digest` 共 **4,182 条、`SHA1-Digest` 0 条**，`SIG.SF` 的清单摘要亦为 `SHA-256-Digest-Manifest`。因此“SHA-1 选择前缀碰撞 → 无钥伪造 v1 签名”这条路径**在本样本上不成立**，本项的评分依据应落在 **1024 位密钥强度 + 100 年有效期 + 开发商共用证书**，而不是 SHA-1 碰撞。
- `SIG.SF` 首部含 `X-Android-APK-Signed: 2, 3`——该属性由 `apksigner` 在启用 v2/v3 时写入（用于防剥离），可**静态证明原包同时带 v2 与 v3 签名**，即原包并非“仅 v1”。
- 有效期 100 年意味着密钥泄露后无法依赖到期失效。
- `CN=vendor` 是**开发商证书**而非某省政务云证书：多家客户共用同一签名密钥，任一家失守即波及全部。

**修复**：换用 RSA-4096/EC P-384 新密钥、SHA-256withRSA 证书自签名；使用**政务专用签名密钥**并由 HSM/云密钥托管；保持 v2/v3 签名不被剥离并启用 `rotation` 轮换属性；建立密钥轮换与吊销流程。

> 注：解压目录本身不含 APK Signing Block，但 `SIG.SF` 的 `X-Android-APK-Signed: 2, 3` 已可静态证明原包带 v2/v3；而 §9.2 的重打包只能保留 v1 —— 因此“v2/v3 块缺失”是本次动态尝试与原包之间的**已确认差异**（见 §9.5 第 4 条），不是待验证假设。

### M-2【中危】业务源码以明文 `.java` 随包分发（已验证）

**位置**：`assets/com/alibaba/tesseract/**`（53 个 `.java`）、根目录 `com/unionpay/client3/tsm/`（4 个 `.java`）、`assets/`（7 个 `.js`，含 `assets/bridge/bridge.js`）、`res/raw/`（7 个 `.js`）—— 按文件系统精确统计共 **71** 个源码文件（57 `.java` + 14 `.js`）。早期 `jslist.out` 报 64 是因 glob 漏计 `res/raw` 下 7 个 `.js`，已在此更正。

```
assets\com\alibaba\tesseract\page\activity\BaseTesseractFragment.java      50,409 B
assets\com\alibaba\tesseract\page\view\SwitchButtonView.java               11,664 B
assets\com\alibaba\tesseract\page\view\DXZWTextViewWidgetNode.java         11,281 B
assets\com\alibaba\tesseract\page\manager\BaseSubscribeUtil.java            8,339 B
assets\com\alibaba\tesseract\page\events\AppOpenUrlEventHandler.java         7,656 B   ← C-3 证据
assets\com\alibaba\tesseract\page\manager\TesseractRouter.java              4,123 B   ← C-3 证据
com\unionpay\client3\tsm\ITsmConnection.java                                4,805 B
com\unionpay\client3\tsm\SeAppInfo.java                                     4,411 B
com\unionpay\client3\tsm\ITsmConnectionCallback.java                        3,736 B
res\raw\rvtools_inject_js.js                                                2,710 B   ← 页面采集注入脚本
res\raw\workerjs_v8.js / images.js / dom_structure.js                                 
```

**影响**：
- 这份源码**解释了绝大多数的攻击面**：路由跳转、事件处理、页面缓存、`SiteSwitchHelper`（多站点切换）、`ChannelSwitchEventSubscriber`、`MsgOpenAndReadEventSubscriber`（消息已读回执）等内部机制全部可读。
- 攻击者无需脱壳即可精确构造恶意模板/URI；`rvtools_inject_js.js` 还暴露了 App 在网页里注入的采集逻辑（`location.href`、全量资源 URL、`performance` 数据）。

**修复**：`.java` 源文件不应进入构建产物（检查 `sourceSets.assets.srcDirs` 与 `packagingOptions`，把模板工程目录从 assets 排除）；JS 注入脚本做混淆并去掉调试注释。

### M-3【中危】把桌面平台的原生库打进了 APK（已验证）

**位置**：`lib/` 下只有 **1 个 Android ABI 目录**（`arm64-v8a`，68 个文件 / 102.7 MB），却另有 **7 个非 Android 平台目录**，全部是 barchart-udt（Netty UDT 传输库）在开发机上的 JNI 构建产物（`qa_misc.py` 实测）：

```
lib/amd64-Windows-gpp/jni/barchart-udt-core-2.3.0-SNAPSHOT.dll        618,159 B
lib/amd64-Windows-gpp/jni/libstdc++_64-6.dll                        1,038,336 B
lib/amd64-Windows-gpp/jni/libgcc_s_sjlj_64-1.dll                      103,936 B
lib/x86-Windows-gpp/jni/barchart-udt-core-2.3.0-SNAPSHOT.dll          507,393 B
lib/x86-Windows-gpp/jni/libstdc++-6.dll                               863,744 B
lib/x86_64-MacOSX-gpp/jni/libbarchart-udt-core-2.3.0-SNAPSHOT.jnilib  308,200 B
lib/i386-MacOSX-gpp/jni/libbarchart-udt-core-2.3.0-SNAPSHOT.jnilib    296,904 B
lib/amd64-Linux-gpp/jni/history.xml              （1 文件, 2,014 B）
lib/i386-Linux-gpp/jni/history.xml               （1 文件, 1,996 B）
lib/arm-Linux-gpp/jni/history.xml                （1 文件, 1,971 B）
```

7 个目录合计 **3.68 MB**；`history.xml` 共 **7 份**（每个 `*-gpp` 目录 1 份），内容是 barchart-udt 的 JNI 构建清单：完整编译器参数（`4.7.1 -m64 -shared … -lstdc++ -lws2_32`）、相对构建路径（`..\..\..\..\obj\amd64-Windows-gpp\*.o`）与十六进制时间戳（**不含主机名**）。

**影响**：
1. 这些 `.dll` / `.jnilib` 在 Android 上完全无法加载，属构建配置错误（`jniLibs.srcDirs` 指向了本地产物目录）；同时包内**没有 `armeabi-v7a` / `x86`**，意味着只支持 64 位 ARM 设备。
2. 体积浪费约 **3.7 MB**，且 `history.xml` 暴露了 JNI 编译器的完整参数与相对构建路径（足以还原构建方式，但不含主机名）。
3. 说明**构建流水线缺少产物白名单**——同类疏漏正是 C-1（四套环境配置未剥离）、H-2（PII 未清理）、M-2（源码入包）的共同根因。

**修复**：`jniLibs.srcDirs = ['libs/android']` 或 `ndk.abiFilters` 显式限定；构建后自动校验 `lib/` 下只允许 `arm64-v8a/armeabi-v7a/x86/x86_64`；加入 APK 体积与内容白名单门禁。

### M-4【中危】88 项权限，包含多项高危/不可获得的权限（已验证）

**位置**：`AndroidManifest.xml`（`manifest_audit.txt` 第 6-94 行，共 **88** 项 `uses-permission`）

与政务场景不匹配、且明显超出最小权限的：

| 权限 | 说明 |
|---|---|
| `MANAGE_EXTERNAL_STORAGE` | 全盘文件管理（Android 11+ 需特殊审批），与 H-1 的 `root-path` 叠加 |
| `QUERY_ALL_PACKAGES` | 枚举**全部已安装应用**，可直接构建用户画像 |
| `READ_PRIVILEGED_PHONE_STATE` | **仅系统应用可授予**，普通应用声明无效，但说明代码里曾有读取 IMEI/IMSI 的强需求（见 M-5） |
| `READ_INTERNAL_STORAGE` / `WRITE_INTERNAL_STORAGE` | 非公开权限字符串（拼写残留） |
| `MOUNT_UNMOUNT_FILESYSTEMS` | 挂载/卸载文件系统，系统级权限 |
| `SYSTEM_ALERT_WINDOW` | 悬浮窗，可做覆盖攻击（overlay） |
| `REQUEST_INSTALL_PACKAGES` | 触发 APK 安装 —— 配合明文更新通道即为 RCE 链的一环 |
| `WRITE_SETTINGS` / `GET_TASKS` / `RESTART_PACKAGES` | 修改系统设置、读取任务栈 |
| `BODY_SENSORS`、`ACTIVITY_RECOGNITION`、`RECORD_AUDIO`、`CAMERA` | 敏感个人信息（人脸核身/活体检测所需，但需最小化） |
| `com.android.browser.permission.READ_HISTORY_BOOKMARKS` | 读取浏览器历史书签 |
| `miui.permission.READ_STEPS`、`com.asus.msa.SupplementaryDID.ACCESS`、`freemme.permission.msa` | 厂商步数/设备标识（MSA 移动安全联盟 OAID） |
| `org.simalliance.openmobileapi.SMARTCARD` | 读取 SIM 卡 SE（电子证照/数字身份用） |

**影响**：`READ_PRIVILEGED_PHONE_STATE`、`MOUNT_UNMOUNT_FILESYSTEMS` 等声明在普通应用中恒为 `DENIED`，但**其存在即证明代码路径尝试过这些能力**；`QUERY_ALL_PACKAGES + MANAGE_EXTERNAL_STORAGE + SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES` 的组合在恶意软件中很常见，一旦 App 被中间人/恶意模板控制（C-3），危害被权限集成倍放大。

**修复**：按实际功能裁剪权限；`QUERY_ALL_PACKAGES` 改用 `<queries>` 精确声明；移除所有无法获得的系统权限声明；`REQUEST_INSTALL_PACKAGES` 若仅用于热更新，改为站内静默更新 + 签名校验。

### M-5【中危】`privacyStrategy.json` 自证了高频敏感 API 采集（已验证）

**位置**：`assets/privacyStrategy.json`（`decoded/privacyStrategy.json.txt`）

```json
{
  "getLastKnownLocation": 60000,  "getProvider": 60000,
  "addTestProvider": 60000,       "setTestProviderEnabled": 60000,
  "setTestProviderStatus": 60000,
  "getImei": 60000,               "getSubscriberId": 60000,
  "getInstalledPackages": 60000,
  "getPackageListByShell": 60000, "getExecPs": 60000
}
```

这是敏感 API 的**调用频率节流表（60 秒一次）**，即“合规化的隐私采集清单”。它直接证明 App 会：

1. 读取 **IMEI / IMSI（getSubscriberId）** —— Android 10+ 已禁止，说明仍需兼容旧设备采集；
2. 读取**已安装应用列表**，并且**通过 shell 执行 `pm list packages`**（`getPackageListByShell`）；
3. **通过 shell 执行 `ps`**（`getExecPs`）—— 读取全系统进程列表，可用于检测 Frida/调试器/多开分身；
4. 读取位置，并可能 `addTestProvider` / `setTestProviderEnabled`（开启模拟位置提供者）。

叠加 `res/raw/rvtools_inject_js.js`（注入网页后收集 `location.href`、全部资源 URL、`performance` 计时），构成**设备指纹 + 浏览行为**的完整采集面。

**影响**：作为政务 App，IMEI/应用列表/进程列表属于**超范围收集个人信息**，《App违法违规收集使用个人信息行为认定方法》《信息安全技术 移动互联网应用程序（App）收集个人信息基本要求》均将其列为重点整治项；`getExecPs` 的进程枚举也用于反调试，属对抗性设计。

**修复**：删除 `getImei`/`getSubscriberId`/`getPackageListByShell`/`getExecPs` 调用（改用 OAID + 业务必需的设备指纹）；在隐私政策中逐项披露并取得单独同意；上线前用官方检测工具（如信通院 App 收集个人信息检测）自检。

### M-6【中危】发行包内保留测试组件、开发提示与内网地址（已验证）

**位置与内容**：

1. **测试 Activity 随包（2 个）**：`com.example.cloudapp.activity.TestActivity`（`manifest_audit.txt:128`）、`com.example.govbiz.phsdk.PHTestActivity`（`:234`）—— 名字直指“测试”，未在 release 中移除。二者未声明任何属性（无 `exported`、无 intent-filter），因此**不可被外部直接唤起**，但残余调试入口仍可能被内部路由（如 C-3 的 `goToUri` 传 `router://`）触达，风险取决于其内部实现（**需动态确认**）；
2. **开发提示文案**：`assets/dtconfig.properties`（782 B，**UTF-8**）→ 第 6 行 `dev_tip=开发中`（若按 Windows CP936/GBK 打开会显示为 `寮€鍙戜腑`，这正是早期误判为“GBK 乱码”的原因，文件本身是干净的 UTF-8）；第 3 行还是模板占位符 `name=name`（未替换）；同文件另有 `default_city_code=339900`、`share=dtgov://share`、`event=apply_use_times`；
3. **内网/开发机地址**：
   ```
   default_url     = http://<PUBLIC_IP-5>                 ← 阿里云裸 IP，明文
   integrated_url  = http://<PUBLIC_IP-6>:8080/dist/#/     ← 裸 IP + 8080，明文
   ```
4. **Scheme 与路由常量**（可被外部应用直接利用）：
   ```
   scheme            = dtgov://
   login_activity    = router://LoginActivity
   bridge_activity   = router://BridgeActivity?url=          ← ★ 可直接注入任意 url
   banner_page       = dtgov://pageexhibition?pageexhibitionid=
   ```
   `bridge_activity=router://BridgeActivity?url=` 意味着**任何外部应用/网页只要唤起 `dtgov://…`，就能让 App 打开指定 URL 的 BridgeActivity**，与 C-3 的零校验路由、C-4 的超宽白名单叠加，构成“外部链接 → 任意页面加载”的稳定入口；
5. **发布标记不一致**：`assets/channel.config` 声明 `release_type=release`，但 `release_version=20180906170000`（2018 年的构建标记留在 7.43.0 包里），且 `channel_id=alipay`（渠道号写成了竞品名，属复制模板未改），说明该文件常年未维护，`release_type` 不可作为“已剥离测试配置”的依据；
6. `assets/payment.json` 是 3 元素数组（`AliPay` / `UnionPay` / `WeChatPay`），其中 `WeChatPay` 的 `implClass` 为空字符串 —— 支付插件装配完全依赖这份**明文、体积可忽略、可被模板/配置覆盖**的清单，若被篡改（C-2 明文下发或本地可写）即可导致支付实现被替换（**需动态确认**装配时的完整性校验）。
7. **过期的政务时间戳证书**：APK 根目录带 `tsa.cer`（921 B），`CN=某省可信电子证照时间戳服务器`，签发者 `CN=PROVCA OCA1`，有效期截至 **2019-06-14** —— 已过期 7 年仍随包分发（详见 §10.4）。

**修复**：删除 `TestActivity` 与 `dev_tip` 等开发痕迹；`BridgeActivity` 增加 host 白名单与签名校验；配置文件中禁止出现裸 IP；把 `channel.config` 纳入构建自动生成流程。

### L-1【低危】关闭了 Android 11+ 的堆指针标记，并开启 `largeHeap`、`extractNativeLibs`（已验证）

**位置**：`AndroidManifest.xml` → `<application>` 属性（`manifest_audit.txt:96-111`）

```
android:allowNativeHeapPointerTagging = false   ← 关闭 ARM64 堆指针标记（削弱 UAF/越界的利用难度提升）
android:extractNativeLibs            = true     ← so 从 APK 解压到 /data/data/<pkg>/lib，可被替换/篡改后加载
android:largeHeap                    = true     ← 申请更大堆（~512MB），降低 OOM 门槛
android:allowBackup                  = false    ← 正确
android:debuggable                   = 未设置    ← 正确
```

**影响**：`allowNativeHeapPointerTagging=false` 是明确为了让 native 库兼容性/性能而**主动放弃一项内存安全缓解**；`extractNativeLibs=true` 使 `.so` 落地到可写目录，配合 C-3 的任意路径读取/写入面，理论上存在 so 替换后劫持加载的可能（需 root 或在应用私有目录有写权限的其他漏洞配合）。

**修复**：`allowNativeHeapPointerTagging` 恢复默认（true）；`extractNativeLibs=false`（`useLegacyPackaging=false`）；`largeHeap` 按实际需要关闭。

### L-2【低危】仍开启 `requestLegacyExternalStorage`（已验证）

`android:requestLegacyExternalStorage = true`（targetSdk=30），与 `MANAGE_EXTERNAL_STORAGE`、`READ/WRITE_EXTERNAL_STORAGE` 并存，说明大量代码仍按“直接读写 `/sdcard` 公共目录”的方式实现。配合 H-1 的 `external-path path=""`，文件选择器可触达全部分区存储。

**修复**：迁移到 MediaStore/SAF；移除 legacy 开关；`targetSdk` 升级到 33+（同时会强制显式声明 `android:exported`，可自动消除 H-3 里的“默认值陷阱”）。

### L-3【低危】第三方 SDK 的回调 Activity 未声明 `exported`，按默认规则导出（已验证）

**先纠正一个易错点**：`assets/dtconfig.properties` 中的 `scheme=dtgov://`、`share=dtgov://share` **并没有在 manifest 注册**，外部应用无法靠它们唤起 App；`router://`、`alipays://`、`weixin://` 同样只是内部路由常量/第三方唤起目标，不是本 App 的入口。manifest 中真实注册的 scheme 只有 4 个：

```
gov          → RouteActivity（exported=true）        ← 深链入口
ut.[REDACTED_APPID:8]   → RouteActivity（exported=true）        ← 友盟统计 id 被复用为 scheme
agoo          → HelpPushActivity（exported=true）     ← 阿里推送落地页
gov           → 4 条深链，目标均 exported=false       ← 已被正确关闭
```

**真正的问题**在 intent-filter + 默认导出规则：`com.sina.weibo.sdk.share.ShareResultActivity` 注册了 2 个 filter（`com.sina.weibo.sdk.action.ACTION_SDK_REQ_ACTIVITY`、`com.sina.weibo.sdk.action.ACTION_SDK_REQ_STORY`，均 `CATEGORY_DEFAULT`）但**未写 `android:exported`**，`targetSdk=30` 下默认导出。

**影响**：任意应用可直接向 `ShareResultActivity` 投递这两个 action 的 Intent（伪造“分享成功”结果、注入 `com.sina.weibo.sdk.share.*` extras），若 SDK 侧未校验调用方，可影响分享埋点/奖励判定；提升 `targetSdk` 至 31+ 会强制显式声明，可一并消除该陷阱（见 L-2 修复）。

**修复**：为 `ShareResultActivity` 显式写 `android:exported=“false”`（其回调由 SDK 内部同进程投递，无需导出）；升级 `targetSdk` 至 33+；对 `RouteActivity` 的 `gov://` / `ut.[REDACTED_APPID:8]://` 入参做 host/path 白名单与来源校验。

## 4. 做得对的地方（避免过度修复）

| 项 | 现状 | 说明 |
|---|---|---|
| `android:allowBackup` | `false` | 未开启 adb backup / 云备份，避免应用数据被 `bmgr` 导出 |
| `android:debuggable` | 未设置 | release 不可调试 |
| 用户 CA 信任 | 仅位于 `<debug-overrides>` 内 | **未在生产配置中信任用户证书**，因此“安装自定义 CA 即可抓包”并不成立，这一点是正确的（早期草稿曾误记为全局信任，此处更正） |
| `networkSecurityConfig` | 已声明该文件 | 有正确的基础设施，只是 `base-config` 取值错误（C-2），改一行即可 |
| `FileSelectorProvider` | `exported=false` | 外部应用不能直接 query/open（风险来自 `grantUriPermissions` + `root-path`，见 H-1） |
| 加固 | SecNeo + Bangcle VMP | 确实阻止了静态业务逻辑审计——**但代价是安全责任转移**：本次审计能发现的问题全部来自加固壳之外的配置与资源，说明加固保护不了“打包配置”这一类风险 |
| `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` | 已声明 | androidx 的运行时注册广播保护机制已生效 |
| `gov://` 敏感深链 | 目标 Activity 均 `exported=false` | `gov://login/main`、`gov://userlogin/main`、`gov://scan/scancode` 的承载页都显式关闭了导出，外部应用无法直接唤醒（对比 H-3 里导出的支付回调，说明团队**知道**这个机制，只是没有一致执行） |
| `GovUpgradeFileProvider` 等 5 个 FileProvider | 均 `exported=false` | Provider 层面没有对外暴露；问题只在 `paths` 范围（H-1） |
| 私钥未随包分发 | 全树扫描 0 条私钥块 | 174 个可读文本文件里**没有** PEM/PKCS#8 私钥、没有 `.jks`/`.p12` 私钥材料；32–64 位十六进制常量 18 条中 16 条是资源 MD5 校验值、2 条是分享 AppSecret（§10.7）。因此“客户端私钥泄露 → 伪造服务端签名”不成立，风险面应聚焦对称密钥 `gatewaySignSecret`（C-1）与配置（§10）。另经 7 类弱钥检测（小因子/共模/Fermat/p−1/Wiener/完全幂/rho）实测全部不命中，公钥在实务上不可推出私钥（§10.8） |

## 5. 组合攻击链（按可行性排序）

### 链 A：中间人 → 模板脚本篡改 → 任意 URI → 本地文件外泄

```
① 用户在公共 Wi-Fi 打开 App（C-2：全局允许明文）
② App 用 http:// 拉取模板 JSON / parser.js / ParseHistory.js（C-2 已确认这类地址存在）
②′ 同时可截获 DEX 内固化的明文认证端点：`uaa/authorize`、`sso/usp.do`、`yjj/sso/login`、`simulate/face/initialize`（C-2 补充清单）→ 直接拿授权码/票据，或替换核身初始化响应
③ 攻击者替换模板内容，注入事件 {"event":"dxAppOpenUrl","args":["content://…/root/…"]}（C-3）
④ AppOpenUrlEventHandler 零校验 → routerService.goToUri() → 打开 FileSelectorProvider 的根目录 URI（H-1）
⑤ 结合 WebView / 外部浏览器把文件内容外发
```
**可行性**：高（只需控制网络链路），**影响**：任意用户文件/证照材料泄露。

### 链 B：任意本地应用 → 伪造支付/登录回调

```
① 恶意应用构造 Intent 直接启动 com.alipay.sdk.app.PayResultActivity 或 WXPayEntryActivity（H-3）
② 传入 resultStatus=9000（成功）等 extras
③ 若服务端未主动查单，即出现“未付款但订单已完成”
```
**可行性**：高（无需特殊权限），**影响**：资金损失 / 登录态被抢占。

### 链 C：外链唤起 → 任意页面在受信 WebView 内加载 → JS Bridge 调用

```
① 网页唤起 dtgov://…或 router://BridgeActivity?url=https://evil（M-6）
② 白名单匹配若为 contains/startsWith（C-4 待脱壳确认），evil 域可伪装成 <HOST-3>.xxx
③ 页面在 App 的 WebView 内获得 JS Bridge 能力，直接调用 dxAppOpenUrl / 文件选择 / 支付
```
**可行性**：中（依赖白名单匹配实现），**影响**：钓鱼 + 本地能力滥用。

### 链 D：密钥提取 → 伪造网关签名 → 服务端接口滥用

```
① 从 manifest meta-data 取出 gatewaySignSecret（C-1）
② 逆向其签名算法（需脱壳，或直接对现网接口做黑盒比对）
③ 离线构造签名，批量调用 <HOST-2> 的 /app/mgop 接口
④ 若接口存在 IDOR/越权，可批量拉取他人办件、证照信息
```
**可行性**：中（需脱壳或黑盒试探），**影响**：数据批量泄露——**这是本次评估中最需要业务方立即验证的一条**。

## 6. 严重度矩阵与修复优先级

### 6.1 汇总

| 编号 | 标题 | 等级 | 验证状态 | 主要影响面 |
|---|---|---|---|---|
| C-1 | 网关签名密钥硬编码，四环境共用 | 严重 | 已验证 | 服务端信任边界 |
| C-2 | 全局允许明文 HTTP（41 个配置端点 + 187 个 DEX 内端点） | 严重 | 已验证 | 传输机密性/完整性 |
| C-3 | `dxAppOpenUrl` 零校验路由 + 重定向信任服务端 | 严重 | 已验证（代码）/ 实现待脱壳 | 本地能力滥用 |
| C-4 | WebView 白名单 6,192 条含内网 IP/测试域名 | 严重 | 已验证（数据）/ 匹配逻辑待脱壳 | 页面加载边界 |
| H-1 | `FileSelectorProvider` 根目录映射 | 高 | 已验证（配置） | 本地文件 |
| H-2 | 包内携带真实格式 PII | 高 | 已验证 | 个人信息保护合规 |
| H-3 | 支付/登录回调组件导出无权限 | 高 | 已验证 | 资金/账号 |
| H-4 | 多平台 AppSecret / Key 硬编码 | 高 | 已验证 | 第三方账号接管 |
| H-5 | SSO `authCode` 发往非政府域名 http | 高 | 已验证（配置） | 账号接管 |
| M-1 | 1024 位 RSA + SHA-1 签名证书（包内另有第二把 1024 位公钥 `security_public_key`，见 §10.2） | 中 | 已验证 | 供应链/更新包 |
| M-2 | 71 个 `.java`/`.js` 源码入包 | 中 | 已验证 | 攻击面暴露 |
| M-3 | 桌面平台 `.dll`/`.jnilib` 入包 | 中 | 已验证 | 构建卫生 |
| M-4 | 88 项权限含系统级权限 | 中 | 已验证 | 权限过度 |
| M-5 | `privacyStrategy.json` 证明 IMEI/进程采集 | 中 | 已验证 | 隐私合规 |
| M-6 | 测试 Activity / `dev_tip` / 裸 IP / Bridge 注入点 | 中 | 已验证 | 调试入口 |
| L-1 | 关闭堆指针标记、`extractNativeLibs` | 低 | 已验证 | 纵深防御 |
| L-2 | `requestLegacyExternalStorage=true` | 低 | 已验证 | 分区存储 |
| L-3 | 微博 SDK 回调 Activity 未声明 `exported`（默认导出） | 低 | 已验证 | 伪造分享回调 |

合计 **18 项**：严重 4 / 高危 5 / 中危 6 / 低危 3。

### 6.2 修复顺序（按“投入产出比”排序）

| 优先级 | 处置项 | 工时估计 | 备注 |
|---|---|---|---|
| **P0（本周）** | 轮换 `gatewaySignSecret` 与全部 `shareSecret`/`appSecret`；服务端核查签名伪造调用日志 | 0.5 人日（客户端改动另计） | C-1、H-4；**假设已泄露**处理 |
| **P0** | 从 assets 删除 `queryPerson.json` 等抓包回放；对其中账号/`bizKey` 做失效处理 | 0.5 人日 | H-2，涉及合规上报判断 |
| **P0** | `cleartextTrafficPermitted="false"` + 清掉全部 `http://` 配置与裸 IP | 1 人日 + 灰度 | C-2、M-6；需服务端同步改 https |
| **P1（本迭代）** | `goToUri` 增加 scheme/host 白名单；`gotoApaasPage` 校验返回 `data` | 2 人日 | C-3 |
| **P1** | 支付/登录/分享回调 `exported=false` + 签名级自定义 permission；支付结果改服务端查单 | 2 人日 | H-3 |
| **P1** | `sso_config.json` 改 https、域名收敛到 `*.gov.cn` | 0.5 人日 | H-5 |
| **P1** | 删除 `<root-path>`，收敛 `<paths>` | 0.5 人日 | H-1 |
| **P1** | 重建 WebView 白名单（精确域 + 强制 https + 去 IP/测试域），匹配改 `equals` | 3 人日（含回归） | C-4 |
| **P2（下个版本）** | 换 RSA-4096/SHA-256 新签名密钥 + v2/v3 签名 + HSM | 5 人日（含升级路径规划） | M-1，需协调所有分发渠道 |
| **P2** | 构建流水线内容白名单（禁 `.java`/`.dll`/`.jnilib`/测试配置/PII） | 3 人日 | M-2、M-3、C-1 的根因 |
| **P2** | 权限裁剪、隐私采集项下线（IMEI/进程/应用列表） | 3 人日 | M-4、M-5 |
| **P2** | `targetSdk` 升到 33+，迁移分区存储 | 5 人日 | L-1、L-2、H-3 兜底 |
| **P3** | 移除 `TestActivity`、`dev_tip`；`BridgeActivity` 加来源校验 | 1 人日 | M-6、L-3 |

## 7. 复核方法（任何人可在 5 分钟内重现关键结论）

所有脚本位于 `<RE_WS>`（Python 3 + `apktool 3.0.3`），输入目录为 `<APK_DIR>`：

```powershell
# 1. 版本/签名
Get-Content <RE_WS>\apktool_out\apktool.yml            # 7.43.0 / 74300 / minSdk 23 / targetSdk 30
openssl pkcs7 -inform DER -in <APK_DIR>\META-INF\SIG.RSA -print_certs -text   # 1024bit + SHA1 + 2014→2114

# 2. 加固与载荷
python <RE_WS>\dex_stub.py        # 5 个 class_defs + dexdata0（45,928,468 B）
python <RE_WS>\qa_dex2.py         # 记录头 @17,528：ver=1 len=45,928,468 name="dexdata0"
python <RE_WS>\qa_dex4.py         # 1MB 分箱熵：34.6MB 区段 5.49–6.79 / 11.3MB 区段 7.999
python <RE_WS>\qa_dex7.py         # 载荷内 URL：去重 535（http 187 / https 348）
python <RE_WS>\qa_dex8.py         # 9 条裸 IP 明文端点，assets 中 0 命中
python <RE_WS>\probe_payload.py   # 载荷内无明文 ZIP/DEX（PK 仅 1 次且不可解析）
# jadx -d <RE_WS>\jadx_stub <APK_DIR>\classes.dex   # 可选：反编译壳代码（仅 com.secneo.apkwrapper.*）

# 3. 配置与密钥（AXML 必须用树解析，字符串池读取会漏）
python <RE_WS>\axml_tree.py       # network_security_config / file_selector_file_paths 真实节点
python <RE_WS>\arsc_secrets.py    # resources.arsc 中的 security_public_key / ucweb_sercret_key
python <RE_WS>\evidence_scan.py   # alibaba_gov_module_config 四套环境 + gatewaySignSecret

# 4. 组件与权限
python <RE_WS>\manifest_audit.py  > manifest_audit.txt    # 88 权限 / 233 Activity / application 属性
python <RE_WS>\provider_map.py    > provider_map.txt      # FileSelectorProvider exported=false + grantUriPermissions
python <RE_WS>\exported_report.py > exported_report.txt   # 26 个 exported=true 的组件与深链
python <RE_WS>\qa_counts.py                              # 组件统计：298 组件 / 26 导出 / 19 导出且无权限

# 5. 文本/PII/白名单
python <RE_WS>\scan_text2.py      > scan_text2.txt        # 41 个 http:// URL（BOM 感知；勿用 scan_secrets.py，它漏 UTF-16LE）
python <RE_WS>\list_js.py                                # 57 .java + 14 .js = 71；身份证校验位验算
python <RE_WS>\white_urls_stats.py > white_urls_stats.txt # 6,192 / 718 IP / 437 内网

# 6. 报告终检（逐条复核正文数字）
python <RE_WS>\qa_counts.py                              # 298 组件 / 26 导出 / 19 导出且无权限 / 1 默认导出
python <RE_WS>\qa_manifest_meta.py                       # 逐条枚举 meta-data，核对 H-4 的键值与四套环境
python <RE_WS>\qa_env3.py                                # 打印生产配置块内的 7 处 http:// 与 gatewaySignSecret
python <RE_WS>\qa_pii2.py                                # 解析 queryPerson.json 的字段结构与脱敏字段
python <RE_WS>\qa_misc.py                                # lib/ 平台目录、dtconfig.properties、channel.config
python <RE_WS>\qa_white.py                               # 白名单条目数 / 尾部数字域 / C-3 两处源码行号
python <RE_WS>\qa_http.py                                # 复核 http:// 端点总数（41）
python <RE_WS>\qa_lines.py                               # 逐行核对正文引用的行号
python <RE_WS>\qa_h4.py                                  # 交叉核对 H-4 密钥表（share/pay/atmConfig/crash/Jupiter + 独立 meta-data）
python <RE_WS>\qa_dt2.py                                 # 逐行打印 dtconfig.properties / channel.config（UTF-8 校验 + M-6 引用）
python <RE_WS>\qa_md.py                                  # Markdown 结构自检（表格列数、代码围栏配对、重复标题）
python <RE_WS>\qa_refs.py                                # 校验本报告引用的每个 .py 脚本是否真实存在

# 6.5 密码学材料（附录 B）
python <RE_WS>\keyharvest.py                             # 证书公钥/四类指纹+PEM、security_public_key、assets 公钥与 CA 库
python <RE_WS>\harvest2.py                               # 源码/配置内密钥常量扫描（结果：0 条私钥）
python <RE_WS>\keyweakness.py                            # 7 类弱钥检测（全不命中 → 公钥不可推出私钥）
python <RE_WS>\hunt3.py                                  # 全树 DB 串/AccessKey/AES 常量/内网端点扫描

# 7. 动态脱壳（附录 A；需模拟器或 arm64 真机，且仅限授权环境）
python <RE_WS>\pack_apk.py                               # 由解压目录原样重建 APK（122.6 MB，v1 签名仍有效）
python <RE_WS>\unpack.py com.example.govapp.activity <RE_WS>\diag.js 15   # spawn + 加载/系统调用轨迹
python <RE_WS>\unpack.py com.example.govapp.activity <RE_WS>\dump_mem.js 60 # 内存 dex 扫描落盘
```

> 注：在 PowerShell 5.1 里用 `> xxx.out` 重定向，文件是 **UTF-16LE + BOM**；读回请用 `[IO.File]::ReadAllText($f,[Text.Encoding]::Unicode)`，或 Python `open(f,'rb').read().decode('utf-16')`。若按 UTF-8 打开会看到满屏 `\x00` 而误判为“空输出”。

**产物索引**（均在 `<RE_WS>`）：

| 文件 | 内容 |
|---|---|
| `metadata.txt` (51 KB) | manifest 全部 `<meta-data>` 键值（含四套环境） |
| `manifest_audit.txt` (84 KB) | 组件/权限/application 属性全文 |
| `provider_map.txt` | Provider ↔ `<paths>` 映射、深链清单 |
| `exported_report.txt` (21 KB) | 导出组件明细 |
| `scan_text2.txt` | 全量敏感字符串命中（BOM 感知） |
| `axml_tree.txt` / `policy.out` | 网络安全配置、文件路径配置的真实节点树 |
| `arsc_secrets.txt` | `resources.arsc` 中的密钥 |
| `decoded/*.txt` | assets 内 BOM 编码配置的解码副本 |
| `white_urls_stats.txt` / `wstats.out` | 白名单统计与样本 |
| `qa_dex2.out` / `qa_dex4.out` / `qa_dex7.out` / `qa_dex8.out` | 载荷记录头、分箱熵剖面、URL 去重清单、裸 IP 端点与 assets 交叉比对 |
| `qa_white.out` / `qa_manifest_meta.out` / `qa_pii2.out` / `qa_misc.out` / `qa_misc2.out` | 终检输出：白名单条目与尾部数字域、meta-data 全量键值、`queryPerson.json` 字段树、`lib/` 目录与 `dtconfig`/`channel.config`/`payment.json` |
| `qa_counts.out` / `qa_h4.out` / `qa_h4d.out` / `qa_md.out` | 组件统计（298/26/19）、H-4 密钥交叉核对、`UCInitKey`/`crash.key` 溯源、Markdown 结构自检 |
| `jslist.out` | 71 个源码文件清单（57 `.java` + 14 `.js`）+ 身份证校验位验算结果 |
| `dex_stub.txt` / `riskstub.txt` | 壳 DEX 字符串池、`libRiskStub.so` 符号 |
| `dyn_diag.txt` (60 行) / `dyn_bypass.txt` | 动态尝试运行记录：模块加载与系统调用轨迹、自毁钩子未触发（§9.4） |
| `logcat2.txt` / `logcat3.txt` / `dmesg.txt` | 崩溃 tombstone（`SIGSEGV/SIGABRT`、`libDexHelper-x86.so+0x5a4b6`）与 houdini64 段错误（§9.3–9.4） |
| `pkg_dump.txt` / `apk_all.txt` | 装机后 `dumpsys package` 关键字段、全盘 APK 搜索结果 |
| `dexhelper_x86_strings.txt` | `libDexHelper-x86.so` 的 6,932 条去重字符串（反调试 / 模拟器判定特征，§9.5） |
| `govsvc_rebuild.apk`（122.6 MB） | 由解压目录原样重建的安装包（4,185 条目，v1 签名有效，§9.2） |
| `keyharvest.txt` / `signer.pem` / `security_public_key.pem` | 签名证书公钥（RSA-1024）与 SHA-1/SHA-256/SPKI 三类指纹、`security_public_key` 完整 base64 与模数（§10.1–10.2） |
| `srckeys.txt` | 174 个可读文本文件的密钥常量扫描结果：0 条私钥，16 条资源 MD5 + 2 条分享 AppSecret（§10.7） |
| `keyweakness.txt` / `hunt3.txt` | 4 把公钥的 7 类弱钥检测明细（全不命中）、2,156 个文件的敏感常量与内网端点扫描（§10.7–§10.8） |
| `apktool_out/` | apktool 全量解码（`res/`、`AndroidManifest.xml`、`apktool.yml`） |
| `jadx_stub/`（未保留） | 早期 jadx 反编译壳 DEX 的中间产物，仅含 `com.secneo.apkwrapper.*` 壳代码，参考价值低故未随工作区留存；需要时用 §7 第 2 步的 `jadx -d …` 重新生成 |

## 8. 局限性与声明

1. **以静态分析为主，另有一次失败的动态尝试**。本次在本地模拟器上运行过 App、并做了 Frida 脱壳尝试（§9），但受 ARM64 翻译层（houdini64）限制**未取得明文 DEX**；未对线上服务发起任何请求。所有“已验证”指**证据在包内可复现**，不等于“线上可利用”；所有“需动态确认”指依赖被加固的 Java 代码或服务端行为。
2. **DEX 方法体不可读（但字符串池可读）**。`classes.dex` 头部只描述 5 个类的壳存根，业务代码藏在同一文件的 17,549 起的加密载荷内（`dexdata0`，45.9 MB），由 Bangcle VMP 运行时解密。经熵剖面与字符串统计（§2.2）确认：**34.6 MB 结构区段仅方法体加密，类型描述符/方法签名/字符串常量明文可读；11.3 MB 为真密文**。因此：网络端点、类名目录、常量键名可静态取证，但**控制流与时序无法静态判定**。以下问题必须在脱壳或动态测试后补测：
   - `IRouterService.goToUri()` 内部是否另有 scheme/host 过滤（若已过滤，C-3 等级需下调为“潜在”）；
   - WebView 白名单的匹配算法（`equals` / `startsWith` / `contains` / 正则）——决定 C-4 是否可被 `evil.com` 前缀绕过；
   - 网络层是否做了证书绑定（`OkHttp` 的 `CertificatePinner`、mPaaS 的 MGS 配置）——决定 C-2 的实际可拦截性；
   - `gatewaySignSecret` 的签名算法（HMAC-SHA1/256？参与字段？时间戳窗口？）——决定链 D 的可行工时；
   - `bizKey` 是否仍为有效服务端会话（决定 H-2 的越权价值）；
   - 本地数据库/SharedPreferences 是否加密（`EncryptedSharedPreferences`/SQLCipher）——需真机。
3. **未做服务端测试**。`gatewaySignSecret` 的可用性、签名接口是否存在越权，都需要在**获得授权**的前提下由业务方自查或红队验证；本报告未对任何线上域名发送请求。
4. **未覆盖**：`.so` 的二进制逆向（`libDexHelper.so`、`libdexvmp.so`、`libRiskStub.so` 仅做了字符串/符号层面的观察）、Sophix 热更新通道的实际拉取逻辑、人脸核身 SDK（`libsensetime`）的本地活体检测强度、`org.simalliance.openmobileapi` 的 SE 访问控制。
5. **敏感值处理**：报告正文中的合作方身份、包名、主机名、IP、文件路径、哈希与证书指纹、以及全部密钥类值（`gatewaySignSecret`、各平台 AppSecret/AppKey、RSA 公钥与模数、证书序列号）均已替换为稳定占位符——同一原文在同一套文档中保持同一编号，可按编号在受控的内部分析环境中回查原值。**本报告应按“内部机密”级别管理，不得公开分发。**
6. 所有结论基于 `<APK_DIR>` 这一份样本（`versionName 7.43.0` / `versionCode 74300` / `classes.dex` SHA-256 `<SHA256-1>`）；其他版本需重新验证。

## 9. 附录 A：动态脱壳（Frida）尝试记录

> 本节记录一次**本地授权环境下的动态尝试**（自建模拟器 + 自建 frida-server，**未连接任何线上服务**）。结论先说：**在本机现有环境下无法完成脱壳**；但尝试排除了若干候选路径，留下了可复用的工具链、可复现的证据，以及对壳的环境判定能力的新增静态证据。全部原始输出见 `dyn_diag.txt`、`dyn_bypass.txt`、`dmesg.txt`、`logcat2.txt`、`logcat3.txt`。

### 9.1 环境

| 项 | 值 | 取证方式 |
|---|---|---|
| 模拟器 | LDPlayer 9（雷电）**9.1.50**，实例 `leidian0`（系统盘 3.5 GB；`/data` 25 GB、可用 23 GB） | 注册表 `HKLM\SOFTWARE\leidian\ldplayer9` → `InstallDir=<DRIVE>:\leidian\LDPlayer9`；`adb shell df -h /data` |
| Android | **9（SDK 28）**，`ro.build.type=user`，**`ro.debuggable=1`** | `getprop` |
| CPU / ABI | `ro.product.cpu.abilist = x86_64,x86,arm64-v8a,armeabi-v7a,armeabi`；`ro.dalvik.vm.isa.arm64 = x86_64`；`primaryCpuAbi=arm64-v8a` | `getprop`、`dumpsys package`；**arm64 指令由 houdini64 翻译执行** |
| root | `adb root` → `uid=0(root)`、SELinux 域 `u:r:su:s0`；`dmesg` 中 `avc: denied … permissive=1` | `adb shell id` |
| Frida | 客户端 **17.18.0**（`…\02-Dynamic-Instrumentation\frida\.venv`，Python 3.12）；server **17.18.0** 的 x86_64 与 arm64 均在本地 | `frida --version`、`/data/local/tmp/fsx --version` |
| 目标进程 | `com.example.govapp.activity`，`versionCode 74300 / versionName 7.43.0 / minSdk 23 / targetSdk 30`，`native-code: 'arm64-v8a'` | `aapt dump badging`、`dumpsys package` |

### 9.2 安装包重建（一个可复用的技巧）

原始 APK 在本机未保留——`<DRIVE>:\` 全盘用 `Get-ChildItem -Recurse -Filter *.apk` 只找到 3 个大于 10 MB 的包：本次重建的 `govsvc_rebuild.apk`（122.6 MB）、本工作区里 19.4 MB 的残缺 `repack.apk`（3,418 条目，**无 `lib/`、无 `classes.dex`**，装上也起不来），以及与本项目无关的 LSPosed `manager.apk`（22.3 MB）。因此用 `pack_apk.py` 把 `<APK_DIR>` **原样重打包**：

- 4,185 条目，输入 **222,978,409 B** → 输出 **128,549,687 B（122.6 MB）**，耗时 12.8 s；
- 条目**内容**逐字节不变，故 `META-INF/MANIFEST.MF` 的逐条目摘要仍成立，**v1 签名继续有效**：`jarsigner -verify` 通过，并提示“签名者证书将于 **2114-07-25** 到期”（与 M-1 的 `SIG.RSA` 有效期吻合）；
- `adb install -r -t` → **Success**；安装后 `primaryCpuAbi=arm64-v8a`、签名证书仍为原始 `CN=vendor`（v1 回落校验），因此**壳的证书自校验不会被触发**；
- 唯一副作用：`system_server` 警告 `resources.arsc in APK '…/base.apk' is compressed`（不影响安装与启动）；
- **未覆盖的差异**：原包还带 v2/v3 APK Signing Block，重打包只能保留 v1。Android 9 接受 v1，但**若壳额外校验 v2 签名块存在性，仍可能被判定为篡改**——本次未能排除该假设（见 9.5 第 4 条）。

### 9.3 Frida 侧的两个硬约束（均已实测）

1. **arm64 frida-server 在 houdini64 下必崩**。`frida-server-17.18.0-android-arm64` 推入后 `--version` 能正常打印 `17.18.0`，但一进入服务态立即被翻译层接管并死亡：

   ```
   # dmesg
   [  409.629132] fs64[3012]: segfault at 0 ip 0000000008093c86 sp 0000763910203e90 error 4 in houdini64[8048000+3d6000]
   # logcat
   F/libc (3023): Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0 in tid 3030 (fs64)
   ```
2. **Frida 17 不再内置 Java 桥**。进程内探针（`probe_java.js`）返回 `{arch:'x64', pointerSize:8, java:'undefined', file:'function'}`——`Java.perform` 不可用，需 `frida-java-bridge` 自行打包（本机无 `node`，无法 `frida-compile`）或改用 frida 16.x。另注：Frida 17 已删除静态 `Module.getExportByName`，需改用 `Module.getGlobalExportByName` / 模块实例方法，否则 hook 会**静默失效**。

**可用能力（对照实验）**：x86_64 server 的 `spawn` / `attach` 正常，`Interceptor` 对 x86_64 libc 确实生效——spawn `com.android.settings` 后 3 秒内统计到 `open` **63**、`mmap` **169**、`mprotect` **110**、`write` **31** 次调用。因此下文“钩子没触发”不是工具问题，而是目标进程的代码路径问题。

### 9.4 目标应用的真实启动轨迹与崩溃

`diag.js`（hook `dlopen` / `android_dlopen_ext` / `open` / `fopen` / `mprotect` / `mmap`，并每 100 ms 轮询模块表）在 spawn 后记录到如下关键序列（完整输出 `dyn_diag.txt`，60 行）：

```
[579ms] open  …/base.apk.x86_64.flock
[583ms] mmap  45,948,928  prot=0x1                      ← ≈ classes.dex 体积（45,946,008）
[604ms] open  …/lib/arm64/libDexHelper-x86.so           ← 壳开始接管
[607ms] dlopen_ext /system/lib64/arm64/nb/libtcb.so      ← houdini 的 arm64 翻译桥
        → 进程消失（约 1 s）
```

tombstone（`logcat3.txt`，同时写入 `/data/tombstones/tombstone_01`）：

- **spawn 模式**：`signal 6 (SIGABRT)`，`#00 syscall+24`、`#01 abort+101`、`#02 <anonymous:0x763912f6e000>` —— 由一段**匿名可执行内存**（壳解密出的二级代码）**主动调用 `abort()`**；
- **裸 `am start`（完全不注入 frida）**：`signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)`，`#00 …libDexHelper-x86.so+0x5a4b6`；另一线程在 `<anonymous:0x763872c0f000+0xfbf60>` 同样 `SEGV_ACCERR`（往无执行权限页取指）。

**判读（观察与推断分开写）**：

1. 崩溃与 frida **无关**——不注入 frida 同样崩，且两次都发生在壳接管之后；
2. `bypass.js` 把 **x86_64** 的 `abort` / `exit` / `_exit` 全部替换，并 hook 了 `android_set_abort_message`，但这两个钩子**一次都没被调用**（`dyn_bypass.txt`：1 ms 完成替换与挂钩，554 ms 收到扫描指令后事件循环停止推进）→ 说明**真正执行自毁的代码不走 x86_64 的 bionic**；结合 607 ms 处 `libtcb.so` 的加载，可推断该段二级代码是 **arm64**、经 houdini 翻译执行；
3. 由此，本机的失败点是 **arm64 翻译层**，不是壳的强度问题，也不是 hook 写错。

### 9.5 顺带得到的静态新证据（补 §2.1 / §2.3）

1. **`lib/arm64-v8a/` 里混放着一个 x86-64 壳库**：`libDexHelper-x86.so` 的 ELF 头 `e_machine = 0x3e`（x86-64，**1,146,765 B**），而 `libDexHelper.so` 是 `0xb7`（AArch64，**983,549 B**）。本机进程是 x86_64，壳按 `os.arch` 选中了 x86-64 分支——tombstone 里出现的正是它。这也解释了 §2.1 中两个同名壳库为何并存于同一目录。
2. **该壳库的反分析特征串**（从 6,932 条去重可打印串中筛出）：`/proc/self/maps`、`ptrace`、`libc_ptrace`、`emulator`、`hookX86Fun`；结合 §2.3 的 `/proc/self/status`，可确认壳具备 **maps 扫描 + ptrace 反调试 + 模拟器判定** 三项能力（`hookX86Fun` 的语义为推测）。
3. **翻译层指纹**：启动阶段 houdini 读取 `/data/local/cfg-nnayn/` 下 **33 个**配置/数据文件（`app_device`、`app_sysprop`、`app_xpt` 等均出现在 `dyn_diag.txt`）；这类路径对壳而言是现成的模拟器指纹。
4. **已确认的差异（原为假设）**：`SIG.SF` 含 `X-Android-APK-Signed: 2, 3`，证明原包带 v2/v3 签名块；§9.2 的重打包只保留 v1。壳若校验 v2/v3 块存在性就会判定篡改，且这一差异**在任何设备上都存在**，因此换真机必须使用原始完整签名包（该修正在 M-1 中同步更新）。

### 9.6 结论与后续可行路径

| 路径 | 结论 |
|---|---|
| 本机 LDPlayer 9 + houdini64 | **不可行**：壳的 arm64 二级代码在该翻译层直接崩；arm64 frida-server 也无法承载 → 谈不上 hook 与 dump |
| 换同为 x86 宿主 + ARM 翻译的模拟器（MuMu 12 等） | 预期同样受限于翻译层，**未验证**；本机只找到 `<DRIVE>:\Program Files\MuMuVMMVbox` 引擎目录，按 3 层深度搜索未见播放器主程序 `MuMuManager.exe` |
| **arm64 真机 + frida-server arm64** | **推荐**：arm64 原生执行，Java 桥可用（frida 16.x 自带，或 frida 17 + `frida-java-bridge` 打包），随后 hook `InMemoryDexClassLoader` / `DexFile` 并配合 `dex\n035` 内存扫描即可落盘 |
| 原始完整签名 APK（v1+v2） | **必要前提**：本次为 v1-only 重打包，无法排除壳对 v2 签名块的校验 |

**已备好、可直接在 arm64 真机复用的工具链**（均在 `<RE_WS>`）：

| 脚本 / 文件 | 作用 |
|---|---|
| `pack_apk.py` | 由解压目录原样重建可安装 APK（保 v1 签名，4,185 条目） |
| `fz.py` | 通用 attach / spawn 运行器（`-H 127.0.0.1:39571`） |
| `unpack.py` | spawn 目标、接收 dex 分片并写入 `dumps/` |
| `dump_mem.js` | 全内存 `dex\n035` / `cdex` 扫描 + 8 MB 分片回传 |
| `hook_io.js` | `open` / `openat` / `write` / `mprotect` / `mmap` hook + dex 写入捕获 |
| `diag.js` | 模块加载与系统调用轨迹诊断（本次主证据） |
| `bypass.js` / `bypass2.js` | 替换 `abort` / `exit` / `_exit`、读取 `android_set_abort_message` 自毁原因，自毁被挡后继续扫描 |
| `probe_java.js` / `probe_hook.js` | 运行时能力探针（Java 桥是否存在、libc hook 是否生效） |

真机复现命令（把 server 换成 arm64 版即可）：

```powershell
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/fs
adb shell "su -c 'chmod 755 /data/local/tmp/fs; /data/local/tmp/fs -l 0.0.0.0:27042 &'"
adb forward tcp:27042 tcp:27042
python <RE_WS>\unpack.py com.example.govapp.activity <RE_WS>\dump_mem.js 60
```

> 脱壳不是目的而是手段：拿到明文 DEX 后，应优先回答 §8 第 2 条列出的 6 个问题（`goToUri` 过滤、白名单匹配算法、证书绑定、`gatewaySignSecret` 算法、`bizKey` 有效性、本地存储加密）。

## 10. 附录 B：密码学材料与关键数据清单

> 本节把报告正文里散落的公钥/密钥/证书**逐个落地成可取用的形态**（含指纹与 PEM），便于业务方自查与轮换核对。生成方式：`keyharvest.py`（证书与公钥）、`harvest2.py`（源码常量），原始输出见 `keyharvest.txt`、`srckeys.txt`。

### 10.1 签名证书的完整公钥（M-1 的展开）

`META-INF/SIG.RSA` 是 PKCS#7 容器（941 B），解出后为一张**自签名**证书：

| 字段 | 值 |
|---|---|
| Subject / Issuer | `C=CN, ST=某市, L=某市, O=某公司, OU=<HOST-16>, CN=vendor`（自签名） |
| Serial | `[REDACTED_SERIAL]`（[REDACTED_SERIAL_DEC]） |
| 签名算法 | `sha1WithRSAEncryption` |
| 有效期 | 2014-08-17 22:10:31 → **2114-07-24 22:10:31**（GMT，100 年） |
| 公钥 | **RSA 1024 bit**，`e = 65537 (0x10001)`；证书 DER 593 B、SPKI 162 B |
| SHA-1 证书指纹 | `<CERT-FINGERPRINT>` |
| SHA-256 证书指纹 | `<CERT-FINGERPRINT>` |
| **SHA-256(SPKI)**（证书绑定 pin） | `<SHA256-2>` |
| 模数 n | `[REDACTED_MODULUS]` |

公钥本体（SPKI PEM，可用 `openssl rsa -pubin -in signer_pub.pem -text` 复核）：

```
[REDACTED_RSA1024_PUBKEY_PEM]
```

> 公钥本身不是秘密（它公开在每台装了该 App 的手机上）。它在攻击侧的价值是**识别与投毒定位**：拿到这把公钥即可确认“同名同签名”的仿冒包会被 Android 当作合法升级（强度问题见 M-1）。

### 10.2 `security_public_key`：日志/参数加密用的 RSA 公钥（完整值）

H-4 中此前只能给出截断值；`apktool_out/res/values/strings.xml` 里取到**完整 216 字符** base64（`keyharvest.py` 输出）：

```
[REDACTED_RSA1024_PUBKEY]
```

| 项 | 值 |
|---|---|
| 位长 / 指数 | **RSA 1024 bit** / `65537` |
| SPKI SHA-256 | `<SHA256-3>` |
| 模数 n | `[REDACTED_MODULUS]` |

- 与 10.1 的签名公钥**模数不同**，是**两把独立的 1024 位 RSA 密钥**——即包内至少两处不足 2048 位（M-1 只提了签名证书，此处补全）；
- 用途按 H-4 记为“日志/参数加密”；具体填充方式（PKCS#1 v1.5 还是 OAEP）与参与字段**需脱壳后确认**。

### 10.3 `assets/` 下的 RSA-2048 公钥（3 个文件 / 2 把钥）

| 文件 | 位长 | SPKI SHA-256 | 判读 |
|---|---|---|---|
| `assets/bid-log-key-public.key`（450 B） | 2048 | `<SHA256-4>` | 埋点日志上报加密，正文 `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…` |
| `assets/bid-log-key-public_t.key`（450 B） | 2048 | 同上（与上一份**逐字节相同**） | 测试副本，生产/测试共用同一把公钥 |
| `assets/future-key-public.key`（450 B） | 2048 | `<SHA256-5>` | 另一把钥，命名 `future` → 预留/轮换用 |

> 三者都是**公钥**，本身不构成泄密；风险在于它们暴露了客户端的加密协议栈（哪类数据用哪把钥、如何轮换），配合明文 `.java`/`.js` 模板源码（M-2）可推断请求体构造方式。

### 10.4 随包的 CA 信任库与两个“非证书”文件

| 文件 | 大小 | 结论 |
|---|---|---|
| `assets/grs_sp.bks` | 1,470 B | BKS v2 密钥库（GlobalSign 根，供 mPaaS/阿里 SDK 使用）；枚举条目需 BouncyCastle 提供者 |
| `assets/hmsincas.bks` | 3,670 B | 华为 HMS 中间 CA 集 |
| `assets/hmsrootcas.bks` | 34,118 B | 华为 HMS 根 CA 集 |
| `assets/geo_global_ca.cer` | 856 B | **不是 DER/PEM 证书**：头 `c5 d0 90 96 70 0c 2a fe …` 为高熵数据，按 base64 解码后 153 B 仍非 ASN.1 → 加密/封装过的证书材料，用途**需动态确认** |
| `tsa.cer`（APK 根目录） | 921 B | `CN=某省可信电子证照时间戳服务器`，签发者 `CN=PROVCA OCA1`，**已于 2019-06-14 过期**；不应出现在此版本发行包里（残留物，归入 M-6） |

### 10.5 `assets/key`：用途未知的 720 B 高熵材料

- 文件 961 B，内容是**纯 base64 文本**（无 PEM 头）；解码后 **720 B 随机数据**，头 `e5 3d 50 19 cd ac ab df …`，无 ASN.1/PEM 结构；
- 不是任何可直接解析的 PEM/DER 密钥（无 `30 82` 之类 ASN.1 头，标准 PKCS#12 亦以 `30 82` 起始）；最可能是**加密过的密钥容器**或对称密钥材料；
- **不应在报告里宣称“私钥已泄露”**——用途与解密方式需动态确认；但它说明“客户端确实持有可解密材料”，对链 A / 链 C 的可行性是正向证据。

### 10.6 明文分享配置里的另一套凭据（与 H-4 的补充关系）

`assets/alibaba_gov_share.json`（5 条 share 服务定义，明文 JSON）：

| type | shareKey | shareSecret |
|---|---|---|
| `WeChatShare` / `WeChatMomentsShare` | `[REDACTED_APPID:18]`（**测试 appId**） | `[REDACTED_HEX32:32]` |
| `DingTalkShare` | `[REDACTED_APPID:20]` | 空 |
| `WeiboShare` | `[REDACTED_APPID:10]` | `[REDACTED_HEX32:32]` |
| `CopyLinkShare` | 空 | 空 |

与 H-4 的 manifest 环境配置对照，多出两点信息：

1. 包内**同时存在两套分享凭据**——生产的微信 appId `[REDACTED_APPID:18]` 与钉钉 `[REDACTED_APPID:20]` 只在环境配置里；这份 assets 文件里是**测试 appId** 与**另一把钉钉 key**（`[REDACTED_APPID:20]`）；
2. 微信两个 appId **共用同一个 AppSecret**（`83471fce…`），轮换必须两处同改，否则测试/生产互相失效——这是“生产与测试共用凭据”的又一例证，佐证 C-1 的判断。

### 10.7 反向结论：私钥没有随包泄漏

对 174 个可读文本文件（`*.java` / `*.js` / `*.json` / `*.properties` / `res/raw/*`）做密钥常量扫描（`harvest2.py`，输出 `srckeys.txt`）：

- **没有任何** `-----BEGIN … PRIVATE KEY-----`（PEM/PKCS#8）私钥，也没有 `.jks`/`.p12` 形式的私钥材料；
- 32–64 位十六进制常量共 18 条：其中 16 条来自 `theme_orange.json`（主题包）、`bio_res.json`（`libtoyger.so` 下载校验）、`ultron_mock.json`（mock 数据），均为 **MD5 资源校验值**；仅 2 条是 AppSecret（即 10.6 的微信/微博分享密钥）；
- 因此“**私钥外泄 → 直接伪造服务端签名**”这条路径不成立；链 D 依赖的是**对称密钥** `gatewaySignSecret`（C-1），这一点必须写清，避免误判风险面（已补入 §4）。
- **旁证（`hunt3.py` → `hunt3.txt`，2,156 个文件定向扫描）**：数据库/中间件连接串 **0** 条；阿里云 `LTAI…`、腾讯云 `AKID…`、AWS `AKIA…` 形态 AccessKey **0** 条；32 字节 base64（AES-256 候选）**0** 条；内网域名（`.corp/.local/.intra/.lan`）**0** 条。私有地址命中 **367 个（去重）但全部位于 `assets/white_urls_config.json`**，属 C-4 已记录的 WebView 白名单问题（不是后端拓扑泄露）；另有 15 条明文 `http://` 端点，均已被 C-2 / H-5 覆盖。

### 10.8 私钥可推导性评估：7 类弱钥检测实测（全部未命中）

`keyweakness.py`（输出 `keyweakness.txt`，耗时 17 s）对包内 4 把公钥做“弱钥”可见性攻击检测——只做多项式/亚指数级排查，不做通用数域筛：

| 检测项 | 参数 | 签名证书(1024) | `security_public_key`(1024) | `bid-log`(2048) | `future-key`(2048) |
|---|---|---|---|---|---|
| 小素数试除 | 148,933 个素数（< 2×10⁶） | 无因子 | 无因子 | 无因子 | 无因子 |
| 两两共模 gcd | 4 把钥、6 组 | 全部 = 1（互素） | 全部 = 1 | 全部 = 1 | 全部 = 1 |
| Fermat 分解 | 3×10⁵ 轮（p、q 接近） | 未命中 | 未命中 | 未命中 | 未命中 |
| Pollard p−1 | B1 = 10⁵ | 未命中 | 未命中 | 未命中 | 未命中 |
| Wiener 连分数 | d 过小 | 未命中 | 未命中 | 未命中 | 未命中 |
| 完全幂 | k = 2…7 | 否 | 否 | 否 | 否 |
| Brent rho | 3×10⁵ 次迭代 | 未命中 | 未命中 | 未命中 | 未命中 |

**结论（三条边界）**：

1. **不能由公钥推出私钥**：弱钥特征全部不成立，剩余路径只有通用数域筛（GNFS）整数分解。公开分解记录止于 **RSA-250（829 bit，2020 年）**，1024 bit 至今无公开记录，成本约高 2–3 个数量级（千万核·小时级），不是本项目可行手段。
2. **拿再多签名样本也推不出 `d`**：APK v1 的 RSA 签名是**确定性**的（PKCS#1 v1.5、无 nonce），不存在 ECDSA/DSA 那种“弱随机数 → 由 `(r,s)` 反解私钥”的通道；RSA 加密（`security_public_key`）同样单向。
3. **私钥的现实来源只有工程侧**：开发者/CI 的 keystore（`.jks`）、构建机磁盘、代码托管、外包交付物。这也是 M-1 的重点——“`CN=vendor` 被多家政务客户共用” + “100 年有效期内无法吊销”，而不是“能否算出来”。

**若私钥失窃，影响边界**（避免误判）：

| 能做 | 不能做 |
|---|---|
| 用同包名 + 同证书签出“合法”更新包（供应链投毒，Android 视为正常升级） | 读取服务端数据或越权调接口（仍需凭据与会话） |
| 通过 v1/v2/v3 全部验签，绕过“防覆盖安装”保护 | 解密 HTTPS 流量（那是 TLS 私钥，与代码签名密钥无关） |
| 让壳的证书自校验通过（§2.3 的证书绑定失效） | 伪造用户身份，或解开 `assets/key` 等本地密文 |

> 注：`assets/key`（720 B 高熵）与 `geo_global_ca.cer` 属**封装/加密材料**，静态不可解，算法与明文需脱壳后确认（§10.5、§10.4）。

---

*报告生成方式：静态分析 + 自研脚本取证；所有关键结论均给出可复现的文件路径与命令。动态脱壳尝试的过程、失败点与可在 arm64 真机复用的工具链见 **§9（附录 A）**；证书公钥、四类指纹与包内全部密钥/证书清单见 **§10（附录 B）**。如需继续推进，下一步为“在 arm64 真机上用原始签名包完成脱壳 + 动态验证 C-3/C-4/D 链”，这需要独立的测试环境与授权。*





