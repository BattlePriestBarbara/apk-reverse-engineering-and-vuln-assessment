# 离线攻击靶场（sandbox）

> 授权范围：本目录全部内容只用于**甲方自有测试环境**的评估交付，不针对任何
> 在线系统。所有密钥均为 `LAB_ONLY_*` 占位串，不含真实凭据。

## 1. 为什么是这个形态

被测系统的攻击面在**网关侧**（`…/app/mgop` 的 HMAC 签名契约），而 PoC 需要的
"真实网关"不允许被访问（会产生流量、且涉及生产域名）。因此本靶场用
`mock_gateway.py` 复刻逆向得到的签名契约，在同一进程里跑攻击者与网关，
再用三种"配置剖面"回答一个问题：

> **整改走到哪一步，才能挡住哪一类攻击？**

| 剖面 | 含义 | 与整改项的对应 |
| --- | --- | --- |
| `baseline` | 只验 HMAC，单钥（已泄露），无时间窗 / 无 nonce / 无版本绑定 / 无参数白名单 / 无限速 | 现状（T-1 成立的前提） |
| `hardened` | 双钥并行 + 时间窗 + nonce 去重 + keyver 绑定 + 未签名参数拒绝 + 频次限速，旧钥按 P0-5 打标 | P0-1 半程、P0-5 |
| `rotated` | v1 移出 keyring（旧钥吊销），其余同 `hardened` | P0-1 完成 |

## 2. 零流量的三重保证

1. **代码层**：`mock_gateway.py` / `attack_sim.py` 不 import `socket`、
   `urllib`、`http.client`、`requests`；请求是直接调用 `handle()`。
2. **运行期**：`NetGuard` 把 `socket.socket` / `create_connection` /
   `create_server` / `socketpair` 换成抛 `RuntimeError` 的空壳，并用
   `sys.meta_path` 拦截 `urllib` / `http` / `requests` 等导入；启动即自检
   （`A0`），自检不过直接 `exit 2`，实验不跑。
3. **容器层**：`--network none` + `--read-only` + `--cap-drop ALL` +
   `no-new-privileges`，容器内没有网卡可用。

`run_in_docker.sh` **不会** 执行 `docker pull`：本地缺基础镜像就 `exit 3`
并给离线导入命令（`docker save` / `docker load`）。这是硬约束——拉镜像本身
就是流量。

## 3. 怎么跑

```bash
# 方式一：宿主直跑（无需 Docker，零 socket）
python sandbox/attack_sim.py --json sandbox/attack_result.json
# 或： powershell -File sandbox/run_offline.ps1

# 方式二：容器内（推荐，隔离更强；要求本地已有 python:3.12-slim）
sh sandbox/run_in_docker.sh
# 或： docker compose -f sandbox/docker-compose.yml run --rm lab
```

退出码：`0` 全部断言通过；`1` 有断言不符；`2` NetGuard 自检失败；
`3` 环境不具备（无 docker / 守护进程不可用 / 缺基础镜像）。

## 4. 场景与结果

见 [RESULTS.md](RESULTS.md)。摘要：8 个场景 × 3 剖面 = 24 组观测，
`baseline` 放行 A1～A6，`hardened` 拦住 A2～A6 但 A1 仍 200（只打标），
`rotated` 才让旧钥全线 401。

## 5. 目录

| 文件 | 作用 |
| --- | --- |
| `mock_gateway.py` | 网关替身：验签 + 三种剖面的检测层（无 socket） |
| `attack_sim.py` | 8 类攻击 + 断言 + NetGuard + 结果落盘 |
| `Dockerfile` | 离线镜像（基础镜像需本地已存在） |
| `docker-compose.yml` | `network_mode: none` 等硬化编排 |
| `run_in_docker.sh` | 容器执行（缺镜像即拒绝，绝不 pull） |
| `run_offline.ps1` | 宿主执行（NetGuard 兜底） |
| `attack_result.json` | 最近一次实跑的结果矩阵（机器可读） |

## 6. 已知边界

- `mock_gateway.py` 是**契约复刻**，不是被测网关：它能证明"若网关按文档
  实现三层校验，则下列攻击会被拦"，不能证明线上网关已如此实现。线上验证
  需 A-8b（测试环境实跑）。
- `X-Key-Ver` 自报头不参与鉴权，仅用于取标签；真实版本由"哪把钥验通"决定。
- `hardened` 剖面对 A1 只打标不阻断，是刻意复刻"旧钥未吊销"的窗口期语义。
