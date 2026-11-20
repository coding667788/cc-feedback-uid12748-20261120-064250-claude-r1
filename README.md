# 本地联合登录服务模拟器

Windows 原生 Python 3.12、仅标准库、离线运行的联合登录（多租户 + 多身份提供方 +
多客户端策略）模拟器。全部输入为合成数据，持久化使用 SQLite，两个阶段
（回调确认、凭据兑换）各自的关键写入与请求回执在**同一事务**中提交。

## 运行

```bash
python -m solution --input cases.json --output result.json          # 自包含运行（内存态）
python -m solution --input cases.json --output result.json --db s.db  # 持久化到 SQLite 文件
python -m unittest discover -s tests -v                              # 自动化测试
```

`--db` 省略时状态仅存于内存；指定 `--db` 时状态跨进程持久化——第二次运行若数据库
已初始化则自动跳过 `setup`，用于“两个阶段独立重启”和多进程交错场景。

## 目录结构

```
solution/
  __main__.py    CLI 入口（--input/--output/--db）
  runner.py      载入 cases 并执行
  service.py     业务规则（SQLite 实现，单事务语义）
  store.py       SQLite 模式与事务封装（BEGIN IMMEDIATE / WAL / busy_timeout）
  reference.py   独立参考实现（纯内存、不共享代码），用于交叉核对
  worker.py      子进程执行器（屏障文件 + 崩溃注入点），供并发/崩溃测试使用
  errors.py      全部错误码
cases.json       可重放合成用例（80 个操作）
tests/           unittest：规则、参考核对、多进程交错与崩溃恢复
```

## 规则

### 实体

- **租户 tenant** → 多个**身份提供方 provider**（登记 issuer 字符串，可吊销）、
  多个**客户端 client**（精确回调字符串集合、权限授予集合，可吊销、可收缩权限）、
  **设备 device**（带单调递增的代数 generation，重置时 +1）。
- **外部主体**身份 = `(tenant, provider, sub)` 三元组：同名主体跨提供方、跨租户
  完全独立（cases.json 中 alice 在 t1/p1、t1/p2、t2/p3 下是三个互不影响的主体）。

### 阶段一：发起挑战 challenge

冻结：租户、提供方、客户端、**发起设备代数**、回调字符串、权限集合、
`SHA-256(验证值)`、到期时刻。校验：租户/提供方/客户端/设备存在且未吊销、回调
字符串与客户端登记值**精确相等**、权限非空且 ⊆ 客户端当前授予、`expires_at > now`、
nonce 在同一 `(tenant, client)` 内唯一（**同号可跨客户端**复用）。
挑战 ID = `CH-<request_id>`。

### 阶段二：回调确认 callback

输入为绑定挑战的模拟已验签声明（claim）与全局唯一声明 ID。依次校验
（顺序固定，见 README 末尾错误码表）：

1. 挑战存在；2. 声明绑定的挑战与目标一致；3. **声明 ID 全局未消费**；
4. 挑战仍 pending；5. `now < expires_at`（**恰好到期即失效**）；
6. 声明时间 `iat <= now < exp`；7. 设备当前代数 == 挑战冻结代数；
8. 声明 issuer == 提供方登记 issuer；9. 提供方未吊销；
10. 声明 aud == 挑战客户端；11. 客户端未吊销且挑战权限仍被授予；
12. 主体非空且未被吊销。

全部通过后**在同一事务中**：消费声明（`claims` 主键，一次消费）、签发唯一兑换凭据
（`CR-<request_id>`）、挑战置 `callback_done`、写入请求回执。任何一步失败整体回滚，
声明不被消费。

### 阶段三：兑换 redeem

依次校验：凭据存在；未被消费；未失效（**失效是粘性的，重复确认不能复活**）；
挑战未到期；**发起设备仍属同代**；回调、客户端与挑战相同；`SHA-256(verifier)`
与挑战摘要相同；目标权限与挑战许可**完全相等**（集合相等，顺序无关）；并**重新读取**
提供方、客户端、主体当前状态（未吊销、权限仍 ⊆ 客户端当前授予）。
全部通过后在**同一事务中**：凭据 `issued → consumed`（守卫式 UPDATE，一次消费）、
写入会话（`SE-<request_id>`）、挑战置 `redeemed`、写入请求回执。
**失败兑换不消费凭据、不留任何痕迹**（完整失败原子性），可用新 request_id 重试。

### 失效事件（粘性）

`revoke_provider` / `revoke_client` / `revoke_subject` / `shrink_client_scopes` /
`reset_device` 各自在同一事务中更新状态并把匹配的**未兑换**凭据置为
`invalidated`（权限收缩只使权限集不再 ⊆ 新授予的凭据失效）。已失效凭据此后任何
兑换都返回 `E_CREDENTIAL_INVALID`，无法复活。

### 幂等回执

每个**成功**操作在同一事务中写入 `receipts(request_id)`。相同 request_id 重发时
直接返回回执内容（`"replayed": true`），不重复执行、不产生第二会话；不同
request_id 操作同一凭据则按一次消费规则拒绝。失败操作不写回执。

## 输入 / 输出

### cases.json

```json
{
  "meta": {...},
  "setup": {"tenants": [...], "providers": [...], "clients": [...],
            "devices": [...]},
  "operations": [
    {"request_id": "ch-1", "op": "challenge", "now": 1000, "tenant_id": "t1",
     "provider_id": "p1", "client_id": "c1", "device_id": "d1",
     "callback": "https://app1.example/cb", "scopes": ["read", "write"],
     "verifier": "verifier-alpha", "nonce": "N-001", "expires_at": 2000},
    {"request_id": "cb-1", "op": "callback", "now": 1100, "challenge_id": "CH-ch-1",
     "claim": {"claim_id": "CL-0001", "challenge_id": "CH-ch-1",
               "iss": "https://idp-alpha.example", "aud": "c1", "sub": "alice",
               "iat": 1050, "exp": 1900}},
    {"request_id": "rd-1", "op": "redeem", "now": 1200, "credential_id": "CR-cb-1",
     "callback": "https://app1.example/cb", "client_id": "c1",
     "verifier": "verifier-alpha", "scopes": ["write", "read"]},
    {"request_id": "reset-d2", "op": "reset_device", "now": 1400, "device_id": "d2"}
  ]
}
```

操作类型：`challenge`、`callback`、`redeem`、`revoke_provider`、`revoke_client`、
`revoke_subject`、`shrink_client_scopes`、`reset_device`。时间全部为输入给定的
逻辑整数，无墙钟依赖，完全可重放。

### result.json

```json
{
  "results": [
    {"request_id": "rd-1", "op": "redeem", "status": "ok", "error": null,
     "session_id": "SE-rd-1"},
    {"request_id": "rd-4", "op": "redeem", "status": "error",
     "error": "E_CREDENTIAL_INVALID"}
  ],
  "summary": {"sessions_total": 8, "sessions": [...],
              "credentials": {"issued": 1, "consumed": 8, "invalidated": 5},
              "claims_consumed": 14,
              "challenges": {"pending": 5, "callback_done": 6, "redeemed": 8},
              "devices": {"d1": 5, "d2": 3, "d3": 1}}
}
```

## 错误码

| 阶段 | 错误码 | 含义 |
|---|---|---|
| 通用 | `E_UNKNOWN_OP` / `E_CONFLICT` | 未知操作 / 存储冲突 |
| 挑战 | `E_TENANT_UNKNOWN` | 租户不存在 |
| 挑战 | `E_PROVIDER_UNKNOWN` / `E_PROVIDER_REVOKED` | 提供方不存在 / 已吊销 |
| 挑战 | `E_CLIENT_UNKNOWN` / `E_CLIENT_REVOKED` | 客户端不存在 / 已吊销 |
| 挑战 | `E_DEVICE_UNKNOWN` | 设备不存在 |
| 挑战 | `E_CALLBACK_NOT_REGISTERED` | 回调字符串未精确登记 |
| 挑战 | `E_SCOPE_NOT_GRANTED` | 权限为空或超出客户端授予 |
| 挑战 | `E_EXPIRY_PAST` | 到期时刻不在未来 |
| 挑战 | `E_NONCE_REUSED` | 同客户端 nonce 重复（跨客户端允许同号） |
| 回调 | `E_CHALLENGE_UNKNOWN` | 挑战不存在 |
| 回调 | `E_CHALLENGE_MISMATCH` | 声明有效但不属于目标挑战 |
| 回调 | `E_CLAIM_REPLAYED` | 声明 ID 已消费（全局一次） |
| 回调 | `E_CHALLENGE_STATE` | 挑战已不在 pending |
| 回调/兑换 | `E_CHALLENGE_EXPIRED` | `now >= expires_at`（恰好到期即失效） |
| 回调 | `E_CLAIM_TIME` | 声明 `iat` 在未来或 `now >= exp` |
| 回调/兑换 | `E_DEVICE_GENERATION` | 设备代数已变迁（重置） |
| 回调 | `E_ISSUER_MISMATCH` / `E_AUDIENCE_MISMATCH` | 签发方 / 受众不符 |
| 回调 | `E_SUBJECT_INVALID` / `E_SUBJECT_REVOKED` | 主体为空 / 已吊销 |
| 兑换 | `E_CREDENTIAL_UNKNOWN` | 凭据不存在 |
| 兑换 | `E_CREDENTIAL_CONSUMED` | 凭据已消费（一次消费） |
| 兑换 | `E_CREDENTIAL_INVALID` | 凭据已失效（粘性，不可复活） |
| 兑换 | `E_CALLBACK_MISMATCH` / `E_CLIENT_MISMATCH` | 回调 / 客户端与挑战不符 |
| 兑换 | `E_VERIFIER_MISMATCH` | 验证值摘要不符 |
| 兑换 | `E_SCOPE_MISMATCH` | 目标权限与挑战许可不完全相等 |
| 兑换 | `E_SCOPE_SHRUNK` | 权限不再 ⊆ 客户端当前授予 |

## 多进程交错与崩溃恢复

`tests/test_concurrency.py` 用独立进程（`python -m solution.worker`，屏障文件定时）
固定三个交错，并用 `SIM_CRASH_AFTER` 环境变量注入崩溃点：

1. **重复回调争用**：两进程同时提交同一 `claim_id` → 恰好一个 `ok`、一个
   `E_CLAIM_REPLAYED`，库中仅 1 条已消费声明、1 张凭据。
2. **权限收缩先于兑换**：收缩先提交 → 兑换得到 `E_CREDENTIAL_INVALID`，会话数 0。
3. **旧设备回调先发后到**：设备重置先提交，旧代数回调后处理 →
   `E_DEVICE_GENERATION`，声明与凭据均不产生。
4. **杀死于“会话已写未提交”**：`SIM_CRASH_AFTER=session_insert`，进程退出码 3；
   重启后无会话、无回执、凭据仍 `issued`；同请求重发成功且只产生 1 个会话。
5. **杀死于“已提交未返回”**：`SIM_CRASH_AFTER=commit`；重启后回执已存在，同请求
   重发放回同一 `session_id`（`replayed: true`），不同请求操作同一凭据得到
   `E_CREDENTIAL_CONSUMED`，会话总数恒为 1。

两阶段独立重启由 `test_two_phase_restart` 展示：挑战+回调在第一个进程完成并退出，
兑换在第二个进程对同一 `--db` 文件完成。

## 实测结果（本机，Python 3.12.8 / SQLite 3.45.3 / Windows 11）

```
$ python -m solution --input cases.json --output result.json
processed 80 operations: 47 ok, 33 error; sessions_total=8

summary: sessions_total=8
  sessions   = [SE-rd-1, SE-rd-11, SE-rd-14, SE-rd-2, SE-rd-22, SE-rd-23, SE-rd-3, SE-rd-5]
  credentials= {issued: 1, consumed: 8, invalidated: 5}
  claims_consumed=14
  challenges = {pending: 5, callback_done: 6, redeemed: 8}
  devices    = {d1: 5, d2: 3, d3: 1}

$ python -m unittest discover -s tests -v
Ran 15 tests in 3.575s
OK
```

cases.json 的 80 个操作覆盖：完整三段流程、跨提供方/跨租户同名主体独立、
有效但不属于目标挑战的声明（`E_CHALLENGE_MISMATCH`）、同 nonce 跨客户端允许 /
同客户端拒绝、挑战与声明**恰好到期**、声明重放、回执幂等重放、主体/提供方/
客户端吊销、权限收缩（部分凭据幸存）、设备重置、失败兑换原子性（失败后可换
request_id 成功），以及上表全部错误码。`tests/test_reference.py` 用独立参考
实现（`solution/reference.py`，纯内存、与 SQLite 实现不共享代码）对同一输入
逐操作比对，结果与汇总完全一致。
