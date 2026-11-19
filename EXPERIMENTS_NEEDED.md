# 待补实验清单（Evidence Backlog）

> 本文档**只写实验设计**，不含任何实验结果、不含任何真实值。
> 目的：为 `threat_model.md` 中 T-1 / T-2 / T-3 的**抬分假设**提供人类实验依据。
> 在实验结论落盘前，相关评分只能以"假设，非发现"存在，且必须被
> `qa_evidence.py` 标注为 `>  UNVERIFIED`。

## 0. 约定

| 项目 | 约定 |
| --- | --- |
| 占位符 | 只允许显式哨兵：`YOUR_APK_PATH`、`YOUR_TEST_GATEWAY_HOST`、`YOUR_SECRET_HERE` 等 `YOUR_*` 形式；**禁止**任何拟真值（密钥 / AppID / CN / IP / 接口路径 / 版本号） |
| 未知事实 | 一律写 `TODO(NEED-EVIDENCE: <获取该事实的具体命令>)`，不得用"大概/据说"填充 |
| 执行前提 | 仅限甲方书面授权的**测试环境**；生产域名由 `poc_gateway_sign.py` 硬拦截 |
| 落盘 | 每条实验的原始输出写入 `evidence/`，文件名见各实验"产物路径" |
| 与评分的关系 | 实验成立 → 维持 `threat_model.md` 现有向量；不成立 → 回退到 §4 已发布的备选向量（不新增分数） |
| 闭环 | 补齐 SAMPLE / LOCATOR / COMMAND / ARTIFACT 四元组后跑 `python qa_evidence.py`，标注自动撤除 |

## 1. 总览

| EXP | Finding | 被检验的抬分假设（原文断言） | 成立则 | 不成立则 | 耗时 | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| EXP-1 | T-1 | S:C「权限域发生变化」（§3.1 S 行） | 10.0 | 9.1 | 60 min | [ ] TODO |
| EXP-2 | T-1 | C:H「可读取敏感数据」+ I:H「可提交伪造写请求」 | 10.0 | 9.3 | 90 min | [ ] TODO |
| EXP-3 | T-2 | 「拿到 AppID + AppSecret 即可换 access_token」+ I:H | 8.2 | TODO(NEED-EVIDENCE) | 45 min | [ ] TODO |
| EXP-4 | T-2 | S:U「同处一个权限域」（反向检验 S:C） | 9.3 | 8.2 | 60 min | [ ] TODO |
| EXP-5 | T-3 | AV:A「需处于同一广播域/链路」（§3.3 AV 行） | 7.1 | 6.5 | 120 min | [ ] TODO |
| EXP-6 | T-2 | OAuth 授权模式「token 受用户授权 scope 约束，S:U 成立」 | 维持 8.2（S:U） | 若为 client_credentials 且可读跨租户数据 → 重评 9.3（S:C，§4 备选） | 20 min | [ ] TODO |

> `EXP-3` 的"不成立"分支无法预先落到某个已发布分数：若平台侧存在 IP 白名单 /
> 权限收回等拦截，回退向量取决于拦截点位置，必须先由实验确定拦截点，
> 再按 CVSS v3.1 规范重算——此即下方 `TODO(NEED-EVIDENCE: ...)` 的含义，
> **不是**允许自行发明分数。

---

## 2. 实验设计

### EXP-1  证明伪造签名可越过客户端信任域直达网关后端业务（T-1 的 S:C）

- 验证命题：`threat_model.md` §3.1 S 行原句——"脆弱组件是'客户端内嵌密钥'，
  被影响组件是网关及其后的业务域，**权限域发生变化**"。
- 若成立 → 向量保持 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`，Base = 10.0
- 若不成立 → 回退向量 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`，Base = 9.1
  （§4 已发布备选，不新增分数）
- 前置条件：
  - 测试环境网关主机 `YOUR_TEST_GATEWAY_HOST` + 网关路径 `YOUR_GATEWAY_PATH`
  - 测试环境专用密钥（**不得**使用生产密钥）：`YOUR_TEST_ENV_SECRET_HERE`
  - 样本 APK：`YOUR_APK_PATH`；样本 SHA-256 前 16 位在步骤 1 现场计算
  - 设备：1 台测试机 `YOUR_DEVICE_SERIAL`（`adb devices` 可见）
  - frida 版本：`TODO(NEED-EVIDENCE: frida --version 与
    adb -s YOUR_DEVICE_SERIAL shell frida-server --version 各跑一次)`
  - 运维配合项：测试网关上游转发日志导出权限
- 步骤：
  1. 现场计算样本指纹（产出 SAMPLE，禁止手填）：
     `python -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path(r'YOUR_APK_PATH').read_bytes()).hexdigest()[:16])"`
  2. 先做离线 dry-run，确认参数与签名链路（不发包）：
     `python _re_workspace\poc_gateway_sign.py --url https://YOUR_TEST_GATEWAY_HOST/YOUR_GATEWAY_PATH --app-key YOUR_APP_KEY_HERE --secret YOUR_SECRET_HERE --algorithm hmac-sha256-sorted`
  3. 授权投递，且**不携带任何用户凭证**（密钥走 stdin，避免落命令行历史）：
     `python _re_workspace\poc_gateway_sign.py --url https://YOUR_TEST_GATEWAY_HOST/YOUR_GATEWAY_PATH --app-key YOUR_APP_KEY_HERE --secret-stdin --algorithm hmac-sha256-sorted --confirm-authorized 2>&1 | Tee-Object -FilePath evidence\EXP-1_forged_request.log`
  4. 复核请求成分中"无用户身份"：
     `Select-String -Path evidence\EXP-1_forged_request.log -Pattern 'cookie|authorization|token'`
  5. 响应体另存（先脱敏再入库）：
     `TODO(NEED-EVIDENCE: 把 step3 的响应体另存为 evidence\EXP-1_response.json，清除个人数据后再提交)`
  6. 取上游转发日志（运维侧，按 step3 的 trace-id 过滤）：
     `TODO(NEED-EVIDENCE: 运维在测试网关导出该请求的上游转发记录，确认签名通过后是否直接转发、是否追加用户身份头，落盘 evidence\EXP-1_upstream_forward.txt)`
- 判定标准：
  - **PASS（S:C 成立）**：同时满足 ① step3 日志显示 HTTP 2xx；
    ② step4 输出**无**任何 cookie/authorization/token 命中；
    ③ step5 响应体存在非空业务数据字段；
    ④ step6 上游日志显示"签名校验通过 → 直接转发"，且**未**追加用户身份头。
  - **FAIL（回退 S:U 9.1）**：上述任一不满足，其中 ② 命中用户凭证、
    或 ④ 显示后端要求二次鉴权（用户令牌/会话）即视为权限域未跨越。
  - 不允许"部分符合 / 大致成立"这类结论；四条必须逐条打勾。
- 产物路径：`evidence/EXP-1_forged_request.log`、`evidence/EXP-1_response.json`、
  `evidence/EXP-1_upstream_forward.txt`
- 预计耗时：60 min
- 状态：[ ] TODO

### EXP-2  实测伪造签名可读的敏感字段面与可写的业务接口（T-1 的 C:H / I:H）

- 验证命题：§3.1 C 行"网关按业务方信任放行，可枚举/读取业务接口返回的
  敏感数据"；I 行"可提交伪造的查询、申请、状态变更类请求"。
- 若成立 → 向量保持 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`，Base = 10.0
- 若不成立 → 回退向量 `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N`，Base = 9.3
  （§4 已发布备选：读取面受限、仅写入面成立）
- 前置条件：
  - EXP-1 已 PASS（否则本实验无需执行，T-1 直接按 9.1 处理）
  - 测试环境数据库只读账号 + 单条测试数据的回滚手段
  - 接口清单来源：`TODO(NEED-EVIDENCE: 从 _re_workspace\逆向与安全评估报告_脱敏.md 的接口清单表导出只读接口 3 条、写接口 1 条，分别填入 YOUR_READONLY_ENDPOINT_1、YOUR_READONLY_ENDPOINT_2、YOUR_READONLY_ENDPOINT_3、YOUR_WRITE_ENDPOINT_1)`
- 步骤：
  1. 只读接口 ×3，各投递一次：
     `python _re_workspace\poc_gateway_sign.py --url https://YOUR_TEST_GATEWAY_HOST/YOUR_READONLY_ENDPOINT_1 --app-key YOUR_APP_KEY_HERE --secret-stdin --algorithm hmac-sha256-sorted --confirm-authorized 2>&1 | Tee-Object -FilePath evidence\EXP-2_readonly_1.log`
     （对 `_2`、`_3` 重复，文件名同步替换）
  2. 字段敏感度分级（人工，输出 CSV）：
     `TODO(NEED-EVIDENCE: 逐字段标注是否属个人信息，写入 evidence\EXP-2_field_classification.csv，列头固定为 endpoint,field,pii)`
  3. 写操作最小验证（仅测试环境、单次、可回滚）：参数全部用哨兵值，
     `python _re_workspace\poc_gateway_sign.py --url https://YOUR_TEST_GATEWAY_HOST/YOUR_WRITE_ENDPOINT_1 --app-key YOUR_APP_KEY_HERE --secret-stdin --algorithm hmac-sha256-sorted --confirm-authorized 2>&1 | Tee-Object -FilePath evidence\EXP-2_write_check.log`
  4. 数据库侧确认写入是否落库（只读查询，禁止修改）：
     `TODO(NEED-EVIDENCE: 用只读账号查询步骤 3 的测试数据，记录影响行数到 evidence\EXP-2_write_check.log 尾部)`
  5. 统计 PII 占比：
     `python -c "import csv;r=list(csv.DictReader(open(r'evidence\EXP-2_field_classification.csv',encoding='utf-8')));p=[x for x in r if x['pii'].strip().lower() in ('1','true','y')];print('fields',len(r),'pii',len(p))"`
- 判定标准：
  - **PASS（C:H）**：3 个只读接口中 ≥2 个返回 2xx 且命中 ≥1 个 `pii=1`
    字段（身份标识/联系方式/住址类）。
  - **PASS（I:H）**：步骤 3 返回 2xx，且步骤 4 在测试库确认落库 1 行。
  - **FAIL（回退 9.3）**：只读接口仅返回公开字典/配置类数据，或写接口被
    业务层二次校验拒绝；此时按 §4 `S:C/C:L/I:H` = 9.3 取值。
  - 若只读 PASS、写 FAIL → 回退向量取 `S:C/C:H/I:L`，分数
    `TODO(NEED-EVIDENCE: python _re_workspace\cvss_check.py "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N")`
- 产物路径：`evidence/EXP-2_readonly_1.log`、`evidence/EXP-2_readonly_2.log`、
  `evidence/EXP-2_readonly_3.log`、`evidence/EXP-2_write_check.log`、
  `evidence/EXP-2_field_classification.csv`
- 预计耗时：90 min
- 状态：[ ] TODO

### EXP-3  用泄露的 AppSecret 换取 access_token 并冒充应用（T-2 的 AV/AC/PR/UI + I:H）

- 验证命题：§3.2 AV 行"微信/微博/钉钉开放平台均公网可达，拿到
  `AppID + AppSecret` 即可换取 `access_token`"；PR 行"以应用身份调用，
  无需受害者账号口令"；UI 行"无需受害者点击/授权动作"；I 行"可冒充应用
  下发消息、伪造授权绑定关系"。
- 若成立 → 向量保持 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`，Base = 8.2
- 若不成立 → 回退向量与分数 `TODO(NEED-EVIDENCE: 先由步骤 2/5 确定平台侧
  拦截点（IP 白名单 / 权限已收回 / 密钥已轮换），据此选定回退向量，再跑
  python _re_workspace\cvss_check.py "<回退向量>")`
- 前置条件：
  - 甲方书面授权 + **仅限甲方自有 App**；若生产密钥尚未轮换，
    先按 P0-3 完成轮换，实验使用轮换后的测试凭据，避免污染取证
  - 凭据：`YOUR_APPID_HERE`、`YOUR_APPSECRET_HERE`（实验后立即视为泄露）
  - 平台侧 token 接口：`TODO(NEED-EVIDENCE: 以平台官方文档确认 token 接口
    路径与参数名，填入 YOUR_PLATFORM_HOST/YOUR_TOKEN_PATH)`
  - 测试用已授权用户 1 个（仅取 openid，不采集其它数据）
- 步骤：
  1. 确认"公网可达"这一 AV:N 前提（无需凭据）：
     `Test-NetConnection -ComputerName YOUR_PLATFORM_HOST -Port 443 | Select-Object ComputerName,TcpTestSucceeded`
  2. 换 token（输出先落盘，日志中不得出现 secret 明文）：
     `curl.exe -s "https://YOUR_PLATFORM_HOST/YOUR_TOKEN_PATH?grant_type=client_credential&appid=YOUR_APPID_HERE&secret=YOUR_APPSECRET_HERE" | Tee-Object -FilePath evidence\EXP-3_token.json`
  3. 判定 token 是否有效：
     `python -c "import json;d=json.load(open(r'evidence\EXP-3_token.json',encoding='utf-8'));print('has_token',bool(d.get('access_token')),'expires_in',d.get('expires_in'),'errcode',d.get('errcode'))"`
  4. 读取已授权用户标识（C:L）：
     `curl.exe -s "https://YOUR_PLATFORM_HOST/YOUR_USERINFO_PATH?access_token=YOUR_TOKEN_HERE&openid=YOUR_TEST_OPENID" | Tee-Object -FilePath evidence\EXP-3_userinfo.json`
  5. 冒充应用下发 1 条消息（I:H，仅发给测试账号，模板用哨兵 `YOUR_TEMPLATE_ID`）：
     `curl.exe -s -X POST "https://YOUR_PLATFORM_HOST/YOUR_SENDMSG_PATH?access_token=YOUR_TOKEN_HERE" -H "Content-Type: application/json" -d "{\"touser\":\"YOUR_TEST_OPENID\",\"template_id\":\"YOUR_TEMPLATE_ID\"}" | Tee-Object -FilePath evidence\EXP-3_send_msg.json`
  6. 记录"全程无用户交互"：
     `TODO(NEED-EVIDENCE: 导出本次主机命令历史与设备录屏，证明未使用用户 Cookie、未扫码、无授权弹窗，落盘 evidence\EXP-3_no_user_interaction.txt)`
- 判定标准：
  - **PASS**：step3 输出 `has_token True` 且 `expires_in` 为正整数；
    step4 返回该 App 已授权用户的 openid（无 errcode 报错）；
    step5 返回 `errcode 0` 且测试账号实际收到消息；
    step6 证明全程无用户交互。四条全中才算 PASS。
  - **FAIL**：step3 出现 `invalid appsecret` 类错误，或平台以 IP 白名单 /
    权限收回拒绝，或 step5 被拒 —— 此时按"不成立"分支走
    `TODO(NEED-EVIDENCE)` 重算，**禁止**沿用 8.2。
  - 仅"能换 token、消息发不出"记**部分成立**：C:L 保留、I:H 必须下调，
    回退分数由 `cvss_check.py` 现算（同样不得手填）。
- 产物路径：`evidence/EXP-3_token.json`、`evidence/EXP-3_userinfo.json`、
  `evidence/EXP-3_send_msg.json`、`evidence/EXP-3_no_user_interaction.txt`
- 预计耗时：45 min
- 状态：[ ] TODO

### EXP-4  验证 App 身份 token 能否跨入用户账号权限域（T-2 的 S:U / S:C 争议）

- 验证命题：§3.2 S 行"攻击者与被影响对象同处'该应用 ↔ 其第三方平台账号'
  这一权限域"——本实验检验该断言的**反面**：token 能否驱动用户账号级能力。
- 若成立（证明跨域，即 S:C）→ 向量升级为
  `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N`，Base = 9.3（§4 已发布备选）
- 若不成立（仍在同域）→ 向量保持 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`，
  Base = 8.2
- 前置条件：
  - EXP-3 已 PASS 并持有可用 token（本实验是 EXP-3 的下游，不可单独执行）
  - 测试环境存在"第三方绑定登录"入口
  - `TODO(NEED-EVIDENCE: 列出平台侧是否存在"代用户操作 / 写入绑定关系"类
    接口，确认本 App 权限范围内可用者，填入 YOUR_BIND_PATH)`
- 步骤：
  1. 写入绑定关系（仅测试用户 `YOUR_TEST_OPENID`）：
     `curl.exe -s -X POST "https://YOUR_PLATFORM_HOST/YOUR_BIND_PATH?access_token=YOUR_TOKEN_HERE" -H "Content-Type: application/json" -d "{\"openid\":\"YOUR_TEST_OPENID\"}" | Tee-Object -FilePath evidence\EXP-4_bind.json`
  2. 用该绑定关系回到业务系统入口，判断能否以该用户身份进入：
     `TODO(NEED-EVIDENCE: 在测试环境用绑定关系登录业务系统，记录是否需要
     用户口令/短信验证，结果落盘 evidence\EXP-4_login_check.txt)`
  3. 记录权限域判定的证据链（以谁的身份、拿到谁的权限）：
     `TODO(NEED-EVIDENCE: 截取登录后可见数据范围（仅测试账号），与 EXP-3 的
     C:L 读取面比对，落盘 evidence\EXP-4_scope_diff.md)`
- 判定标准：
  - **PASS（S:C 成立 → 9.3）**：step2 仅凭 step1 的绑定关系即可进入业务系统
    并看到该用户数据，且 step3 显示数据面超出"App 授权范围"。
  - **FAIL（保持 S:U → 8.2）**：step2 仍要求用户口令 / 短信 / 活体等二次验证，
    或绑定关系无法换取业务会话。
  - step1 返回平台错误（权限范围内无此能力）→ 同样记 FAIL，并注明
    "权限范围内不存在该能力"，维持 8.2。
- 产物路径：`evidence/EXP-4_bind.json`、`evidence/EXP-4_login_check.txt`、
  `evidence/EXP-4_scope_diff.md`
- 预计耗时：60 min
- 状态：[ ] TODO

### EXP-5  验证明文 SSO 令牌只能在链路内截获（T-3 的 AV:A）

- 验证命题：§3.3 AV 行"中间人需与受害者处于同一广播域/链路（公共 Wi-Fi、
  酒店网络、运营商旁路、ARP 欺骗）"；AC 行"明文 HTTP 无任何完整性保护，
  抓包即得"；C 行"令牌等同于完整登录态"。
- 若成立 → 向量保持 `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`，Base = 7.1
- 若不成立 → 回退向量 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`，Base = 6.5
  （§4 已发布备选：公网任意路径可劫持但需时序条件）；若同时证明令牌跨入
  独立业务系统权限域 → 另一备选 `AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`，
  Base = 8.2（§4）
- 前置条件：
  - 受控 AP/路由器 1 台（具备镜像口或可运行 tcpdump）：`YOUR_AP_SSID`
  - 测试设备 1 台 `YOUR_DEVICE_SERIAL` + 测试账号（仅测试数据）
  - 抓包主机 1 台；工具版本 `TODO(NEED-EVIDENCE: tshark -v 与 AP 侧
    tcpdump --version 各跑一次)`
  - 链路外对照组：1 台云主机（与受害者不同二层）
- 步骤：
  1. 在受控 AP 上开启抓包（镜像口或 AP 本机）：
     `TODO(NEED-EVIDENCE: 按 AP 型号确认抓包方式；若为 OpenWrt 可用
     tcpdump -i br-lan -w /tmp/EXP-5.pcap，随后 scp 回 evidence\EXP-5_mitm.pcapng)`
  2. 在测试设备上复现启动/登录流程（**纯被动，不注入任何修改**）：
     `adb -s YOUR_DEVICE_SERIAL shell am start -n YOUR_PKG_NAME/YOUR_LAUNCH_ACTIVITY`
  3. 停抓并导出明文请求清单：
     `tshark -r evidence\EXP-5_mitm.pcapng -Y "http.request" -T fields -e http.host -e http.request.uri | Tee-Object -FilePath evidence\EXP-5_http_requests.txt`
  4. 判定"同链路必要性"（对照组）：在链路外云主机以同样手段尝试截获同一
     流程流量
     `TODO(NEED-EVIDENCE: 在链路外主机重复 step1~3，确认是否有任何流量可见，
     结果落盘 evidence\EXP-5_offlink_control.txt)`
  5. 令牌等价性验证（C:H，仅测试账号）：把 step3 抓到的令牌用于一次只读请求
     `TODO(NEED-EVIDENCE: 用抓到的令牌对测试环境发起 1 次只读请求，脱敏后
     记录响应字段集合到 evidence\EXP-5_token_replay.txt)`
- 判定标准：
  - **PASS（AV:A 成立 → 7.1）**：step3 中至少 1 条明文 HTTP 请求的 URI 含
    令牌类参数；**且** step4 在链路外可见流量为 0（证明必须先入链路）。
  - **FAIL（回退 AV:N/AC:H → 6.5）**：step4 在链路外同样能截获 → AV 改判 N，
    并须说明所需时序条件（用以支撑 AC:H），分数取 §4 的 6.5。
  - **补充判定（C:H）**：step5 能用令牌读到该测试账号数据 → C:H 成立；若令牌
    被服务端绑定会话指纹而失效 → C 需下调，
    `TODO(NEED-EVIDENCE: python _re_workspace\cvss_check.py "<调整后向量>")`
- 产物路径：`evidence/EXP-5_mitm.pcapng`、`evidence/EXP-5_http_requests.txt`、
  `evidence/EXP-5_offlink_control.txt`、`evidence/EXP-5_token_replay.txt`
- 预计耗时：120 min
- 状态：[ ] TODO

### EXP-6  确认 OAuth 授权模式（T-2 的 S:U 反例边界）

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
     `TODO(NEED-EVIDENCE: 手工写入 evidence\EXP-6_grant_type.txt 首段：
     操作人 / 时间 / 触发的流程名 / 环境标识)`
  2. 优先走服务端日志取证（HTTPS 无需解密，证据链最短）：
     `TODO(NEED-EVIDENCE: 运维导出该 App 最近 24h 的 token 接口访问日志，
     只保留 grant_type 与时间戳，脱敏后落盘 evidence\EXP-6_grant_type.txt)`
  3. 无法取服务端日志时，退化为本机抓包：
     `tshark -D`（先确认接口名），再
     `tshark -i YOUR_IFACE -f "tcp port 443" -w evidence\EXP-6_grant_type.pcapng`
  4. 提取 grant_type（日志路径或 pcap 解析任选其一）：
     `Select-String -Path evidence\EXP-6_grant_type.txt -Pattern 'grant_type=(authorization_code|client_credential[s]?)' | Select-Object -ExpandProperty Line`
  5. 若命中 `client_credential`，再判定能否跨租户（复用 EXP-4 的接口清单）：
     `TODO(NEED-EVIDENCE: 用该 token 访问 1 个非本 App 绑定租户的只读接口，
     记录是否返回他人数据，落盘 evidence\EXP-6_cross_tenant.txt)`
- 判定标准：
  - **PASS（S:U 成立 → 维持 8.2）**：step4 命中 `authorization_code`
    或等价带用户上下文的模式；或虽命中 `client_credential`，但 step5
    只能读到本 App 自身租户数据。
  - **FAIL（S:U 失去依据 → 9.3）**：step4 命中 `client_credential` **且**
    step5 返回非本租户数据。此时 §2 与 §3.2 的 `S` 取值失去规范判据，
    须按 EXP-6 结论重评并在文首变更记录留痕（**本次不改动**）；
    回退分数由 `cvss_check.py` 现算确认：
    `python _re_workspace\cvss_check.py "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"`
  - **未取证**：step2 与 step3 都失败 → 记"未取证"，**不得**默认维持
    S:U；§4 的"分数待 EXP-N 取证后冻结"继续有效。
- 产物路径：`evidence/EXP-6_grant_type.txt`（必需）、
  `evidence/EXP-6_grant_type.pcapng`（可选）、
  `evidence/EXP-6_cross_tenant.txt`（条件必需：命中 client_credentials 时）
- 预计耗时：20 min
- 状态：[ ] TODO

---

## 3. 完成后如何闭环（强制）

1. 把原始输出放进 `evidence/`，文件名与"产物路径"逐字一致
   （`qa_evidence.py` 会检查文件是否真的存在于磁盘）。
2. 在 `threat_model.md` 对应 finding 区块（§3.x 小节末尾）追加四行，
   值必须来自实验产物，不得手填：

   ```text
   SAMPLE: <sha256 前 16 位>
   LOCATOR: <dex/so 偏移 或 类#方法签名>
   COMMAND: <本次实际执行的完整命令>
   ARTIFACT: evidence/<真实文件名>
   ```

3. 跑 `python qa_evidence.py`：该 finding 的 `>  UNVERIFIED` 标注应自动消失；
   若仍存在，说明四元组不完整（脚本会打印缺哪一项）。
4. 实验结论若推翻抬分假设，**只允许**改 `threat_model.md` 的向量取值并
   引用本文档的 EXP 编号；不允许只改分数而不留痕。

## 4. 禁止事项

- 禁止把本文档里的任何 `YOUR_*` 哨兵替换成真实值后提交。
- 禁止在未获授权的情况下执行步骤中的任何 `--confirm-authorized` 命令。
- 禁止用"结果大致符合预期"替代"判定标准"里的可验证条件。
- 禁止新增 CVSS 分数：回退分支只能引用 `threat_model.md` §4 已发布的备选，
  或由 `cvss_check.py` 现算，并把命令与输出一并留档。
