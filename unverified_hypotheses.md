# 未验证假设清单（Unverified Hypotheses）

> 由 `qa_evidence.py` 自动追加。本文件所有条目均为**假设，非发现**：
> 缺少 SAMPLE / LOCATOR / COMMAND / ARTIFACT 四元组，禁止进入评分表。
> 补齐证据后重跑 `python qa_evidence.py`，`threat_model.md` 中的标注会
> 自动撤除；本文件作为历史台账保留，不自动删除。

## T-1 硬编码网关对称密钥（`gatewaySignSecret`）导致网关接口伪造

- 判定：**假设，非发现**（四元组不全，禁止进入评分表）
- 缺失四元组：SAMPLE, LOCATOR, COMMAND, ARTIFACT
- 现有评分：10.0 / Critical（不得作为已证实结论引用）
- 来源：threat_model.md §2 评分总表 + §3.x（T-1）
- 待补实验：EXPERIMENTS_NEEDED.md → EXP-1、EXP-2
- 记录时间（UTC）：2026-11-12T13:46:29Z
- 缺失明细：
  - SAMPLE：缺失
  - LOCATOR：缺失
  - COMMAND：缺失
  - ARTIFACT：缺失
- 补齐方式：在 threat_model.md 该 finding 区块写入 SAMPLE / LOCATOR / COMMAND / ARTIFACT 四行，ARTIFACT 必须是 evidence/ 下真实存在的文件，然后重跑 `python qa_evidence.py`。

## T-2 第三方 OAuth `AppSecret` 硬编码导致平台身份冒用/账号接管

- 判定：**假设，非发现**（四元组不全，禁止进入评分表）
- 缺失四元组：SAMPLE, LOCATOR, COMMAND, ARTIFACT
- 现有评分：8.2 / High（不得作为已证实结论引用）
- 来源：threat_model.md §2 评分总表 + §3.x（T-2）
- 待补实验：EXPERIMENTS_NEEDED.md → EXP-3、EXP-4
- 记录时间（UTC）：2026-11-12T13:46:29Z
- 缺失明细：
  - SAMPLE：缺失
  - LOCATOR：缺失
  - COMMAND：缺失
  - ARTIFACT：缺失
- 补齐方式：在 threat_model.md 该 finding 区块写入 SAMPLE / LOCATOR / COMMAND / ARTIFACT 四行，ARTIFACT 必须是 evidence/ 下真实存在的文件，然后重跑 `python qa_evidence.py`。

## T-3 敏感 SSO 令牌经明文 HTTP 传输导致中间人劫持

- 判定：**假设，非发现**（四元组不全，禁止进入评分表）
- 缺失四元组：SAMPLE, LOCATOR, COMMAND, ARTIFACT
- 现有评分：7.1 / High（不得作为已证实结论引用）
- 来源：threat_model.md §2 评分总表 + §3.x（T-3）
- 待补实验：EXPERIMENTS_NEEDED.md → EXP-5
- 记录时间（UTC）：2026-11-12T13:46:29Z
- 缺失明细：
  - SAMPLE：缺失
  - LOCATOR：缺失
  - COMMAND：缺失
  - ARTIFACT：缺失
- 补齐方式：在 threat_model.md 该 finding 区块写入 SAMPLE / LOCATOR / COMMAND / ARTIFACT 四行，ARTIFACT 必须是 evidence/ 下真实存在的文件，然后重跑 `python qa_evidence.py`。
