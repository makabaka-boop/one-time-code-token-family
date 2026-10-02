# Node.js + SQLite 授权服务

模拟 OAuth 2.1（PKCE）授权码流程的授权服务，供两个预先登记的模拟客户端使用。

## 安全机制一览

| 需求 | 实现 |
| --- | --- |
| 用户确认范围后签发短期授权码 | `authorize()`，授权码默认 60 秒过期 |
| 兑换必须同时匹配客户端、精确回调地址、随机验证值摘要 | `exchangeCode()` 校验 client 凭据、逐字符匹配的 `redirect_uri`、PKCE S256（拒绝 plain） |
| 授权码只能成功兑换一次 | 条件更新 `SET consumed=1 WHERE consumed=0`，事务内判定 `changes === 1` |
| 访问令牌有到期时间 | 默认 5 分钟；`introspectAccessToken()` 依据注入时钟判活 |
| 刷新令牌每次使用都轮换 | 旧 RT 标记 `used`，签发全新 RT + AT |
| 已用过的 RT 再次出现 → 撤销整个家族（含最新令牌） | 检测重放即撤销家族并失效家族内全部访问令牌 |
| 所有到期判断使用可注入时钟 | `SystemClock` / `FakeClock`，服务内不直接调用 `Date.now()` |
| 兑换 / 轮换 / 撤销并发原子性 | `BEGIN IMMEDIATE` 事务 + 条件更新 + `busy_timeout` |
| 重启后旧码 / 旧令牌不复活 | 状态全部落 SQLite 持久化，内存中不保存任何凭据 |

凭据（授权码、验证值摘要、AT、RT）一律只以 SHA-256 摘要落库，明文只在签发响应中出现一次。

## 两个登记客户端

- `client-a` / `secret-a` → `https://client-a.example.com/callback`，范围 `read:profile read:messages`
- `client-b` / `secret-b` → `https://client-b.example.com/oauth/cb`，范围 `read:profile`

## 关键设计点

### 1. 精确回调地址

`redirect_uri` 与登记值做逐字符相等比较（`!==`），不做前缀匹配；
带 query 的变体、路径大小写差异都会被拒绝。

### 2. 授权码单次兑换（并发安全）

```sql
UPDATE auth_codes SET consumed = 1, consumed_at_ms = ?
WHERE code_hash = ? AND consumed = 0
```

在 `BEGIN IMMEDIATE` 事务内执行：并发请求中只有一个事务能把 `consumed` 从 0 改成 1，
其余看到 `changes = 0` 即拒绝。

### 3. 刷新令牌轮换 + 家族重放撤销

```
授权 -> 家族 F -> RT1/AT1
刷新(RT1) -> 标记 RT1 used，签发 RT2/AT2
刷新(RT2) -> 标记 RT2 used，签发 RT3/AT3
重放(RT1) -> 家族 F 撤销：RT1/RT2/RT3 全废，AT1/AT2/AT3 全部失活
```

实现要点：better-sqlite3 的 `db.transaction(fn)` 在 `fn` 抛异常时会**回滚整个事务**。
因此重放路径在事务内完成撤销写操作后返回哨兵值（`REPLAY_DETECTED`），
由事务提交后的外层代码再抛出 `invalid_grant`，保证撤销不会被回滚。

跨客户端出示他人家族的刷新令牌时只拒绝、不撤销（该家族不属于调用方）。
过期 RT 不触发家族撤销（过期不等同于被盗重放）。

### 4. `BEGIN IMMEDIATE`

SQLite 默认 deferred 事务在“先 SELECT 再升级写锁”时，
多个并发事务会在锁升级点直接收到 `SQLITE_BUSY`（不会自动重试）。
所有写事务使用 `BEGIN IMMEDIATE`，进入即取写锁，其他连接在
`busy_timeout = 5000` 内排队，保证多线程 / 多连接下的原子性。

### 5. 可注入时钟

构造服务时传入 `{ nowMs() }`：

```js
const clock = new FakeClock();
const server = new AuthorizationServer({ db, clock });
clock.advance(60_001); // 授权码此刻判定过期，无需真实等待
```

## 测试

```bash
npm test        # 16 个用例：交叉兑换、并发刷新、范围越权、重放家族撤销、重启持久性
npm run demo    # 端到端演示
```

并发用例通过 `worker_threads` 启动 4 个独立线程（各自独立数据库连接），
经 `SharedArrayBuffer` 屏障同时发起兑换 / 刷新；
另经手动压测验证 16 线程下仍是“恰好一次成功 + 家族撤销”。

## 目录结构

```
src/
  clock.js    可注入时钟（SystemClock / FakeClock）
  crypto.js   随机凭据、SHA-256 摘要、PKCE S256 校验
  db.js       SQLite 迁移与登记客户端
  errors.js   RFC 6749 风格错误
  server.js   授权服务核心
test/
  auth.test.js        测试用例
  lib/helpers.js      测试夹具与并发执行器
  lib/tokenWorker.js  worker 线程入口
examples/demo.js      端到端演示
```
