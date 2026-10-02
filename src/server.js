'use strict';

const crypto = require('node:crypto');
const { OAuthError } = require('./errors');
const { SystemClock } = require('./clock');
const { randomToken, sha256, verifyPkceS256 } = require('./crypto');

const DEFAULT_TTL = {
  codeTtlMs: 60_000, // 授权码：短期 60s
  accessTokenTtlMs: 300_000, // 访问令牌：5 分钟
  refreshTokenTtlMs: 1_209_600_000, // 刷新令牌：14 天
};

const S256_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** 事务返回值：检测到刷新令牌重放，家族已在事务内撤销，提交后由外层抛错。 */
const REPLAY_DETECTED = Symbol('replayDetected');

/** 以空白拆分 scope，去重并排序，返回归一化数组。 */
function normalizeScope(scope) {
  if (typeof scope !== 'string') return [];
  return [...new Set(scope.split(/\s+/).filter(Boolean))].sort();
}

/** a 是否为 b 的子集（数组均已归一化）。 */
function isSubset(a, b) {
  const setB = new Set(b);
  return a.every((s) => setB.has(s));
}

function timingEqualString(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

class AuthorizationServer {
  /**
   * @param {object} opts
   * @param {import('better-sqlite3').Database} opts.db 已迁移的数据库连接
   * @param {{nowMs():number}} [opts.clock] 可注入时钟，默认系统时钟
   */
  constructor({ db, clock = new SystemClock(), ...ttls }) {
    this.db = db;
    this.clock = clock;
    this.codeTtlMs = ttls.codeTtlMs ?? DEFAULT_TTL.codeTtlMs;
    this.accessTokenTtlMs = ttls.accessTokenTtlMs ?? DEFAULT_TTL.accessTokenTtlMs;
    this.refreshTokenTtlMs = ttls.refreshTokenTtlMs ?? DEFAULT_TTL.refreshTokenTtlMs;

    this.#prepareStatements();

    // IMMEDIATE 事务：进入即获取保留锁→写锁，并发写请求按 busy_timeout 排队，
    // 杜绝 deferred 事务“读锁升级写锁”时的 SQLITE_BUSY 死锁。
    this.exchangeCodeTx = this.db.transaction((params) => this.#exchangeCodeTx(params));
    this.refreshTx = this.db.transaction((params) => this.#refreshTx(params));
  }

  #prepareStatements() {
    const db = this.db;
    this.stmts = {
      findClient: db.prepare('SELECT * FROM clients WHERE client_id = ?'),
      insertCode: db.prepare(`
        INSERT INTO auth_codes
          (code_hash, client_id, user_subject, redirect_uri, scope,
           code_challenge, expires_at_ms)
        VALUES
          (@code_hash, @client_id, @user_subject, @redirect_uri, @scope,
           @code_challenge, @expires_at_ms)`),
      findCode: db.prepare('SELECT * FROM auth_codes WHERE code_hash = ?'),
      consumeCode: db.prepare(
        'UPDATE auth_codes SET consumed = 1, consumed_at_ms = ? WHERE code_hash = ? AND consumed = 0'),
      insertFamily: db.prepare(`
        INSERT INTO token_families (family_id, client_id, user_subject, granted_scope)
        VALUES (@family_id, @client_id, @user_subject, @granted_scope)`),
      findFamily: db.prepare('SELECT * FROM token_families WHERE family_id = ?'),
      findRefresh: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
      markRefreshUsed: db.prepare(
        'UPDATE refresh_tokens SET used = 1, used_at_ms = ? WHERE token_hash = ? AND used = 0'),
      insertRefresh: db.prepare(`
        INSERT INTO refresh_tokens
          (token_hash, family_id, client_id, created_at_ms, expires_at_ms)
        VALUES (@token_hash, @family_id, @client_id, @created_at_ms, @expires_at_ms)`),
      insertAccess: db.prepare(`
        INSERT INTO access_tokens
          (token_hash, family_id, client_id, user_subject, scope,
           created_at_ms, expires_at_ms)
        VALUES (@token_hash, @family_id, @client_id, @user_subject, @scope,
                @created_at_ms, @expires_at_ms)`),
      findAccess: db.prepare('SELECT * FROM access_tokens WHERE token_hash = ?'),
      invalidateFamilyAccess: db.prepare(
        'UPDATE access_tokens SET invalidated = 1 WHERE family_id = ? AND invalidated = 0'),
      revokeFamily: db.prepare(
        'UPDATE token_families SET revoked = 1, revoked_at_ms = ?, revoke_reason = ? WHERE family_id = ?'),
    };
  }

  #authenticateClient(clientId, clientSecret) {
    if (!clientId || typeof clientId !== 'string') {
      throw new OAuthError('invalid_client', '缺少 client_id', 401);
    }
    const client = this.stmts.findClient.get(clientId);
    if (!client || !clientSecret || !timingEqualString(client.client_secret, clientSecret)) {
      throw new OAuthError('invalid_client', '客户端身份验证失败', 401);
    }
    return client;
  }

  /**
   * 1) 授权端点：用户已确认权限范围后，签发短期授权码。
   *
   * 授权端点只按 client_id 识别客户端（浏览器场景无密钥），
   * 但 redirect_uri 必须与登记地址逐字符一致，且必须事先提交 PKCE 挑战。
   *
   * @returns {{code: string, scope: string, expiresIn: number}}
   *   明文授权码只在返回值中出现一次，库里只存 SHA-256 摘要。
   */
  authorize({ clientId, redirectUri, scope, codeChallenge, userSubject }) {
    const client = this.stmts.findClient.get(clientId);
    if (!client) {
      throw new OAuthError('invalid_client', `未知客户端: ${clientId}`, 401);
    }
    if (!redirectUri || redirectUri !== client.redirect_uri) {
      throw new OAuthError('invalid_request', 'redirect_uri 与登记的精确回调地址不匹配');
    }
    if (typeof codeChallenge !== 'string' || !S256_CHALLENGE_PATTERN.test(codeChallenge)) {
      throw new OAuthError('invalid_request', 'code_challenge 必须是 S256 的 base64url 摘要（43 字符）');
    }
    if (typeof userSubject !== 'string' || !userSubject) {
      throw new OAuthError('invalid_request', '缺少用户主体 userSubject');
    }

    const requested = normalizeScope(scope);
    if (requested.length === 0) {
      throw new OAuthError('invalid_scope', '授权范围不能为空');
    }
    if (!isSubset(requested, normalizeScope(client.scope))) {
      throw new OAuthError('invalid_scope',
        `请求的范围超出客户端登记范围: ${requested.join(' ')}`);
    }
    const grantedScope = requested.join(' ');

    const now = this.clock.nowMs();
    const code = randomToken();
    this.stmts.insertCode.run({
      code_hash: sha256(code),
      client_id: client.client_id,
      user_subject: userSubject,
      redirect_uri: client.redirect_uri,
      scope: grantedScope,
      code_challenge: codeChallenge,
      expires_at_ms: now + this.codeTtlMs,
    });

    return { code, scope: grantedScope, expiresIn: Math.ceil(this.codeTtlMs / 1000) };
  }

  /**
   * 2) 兑换授权码。
   *
   * 必须同时满足：客户端匹配 + 精确回调地址匹配 + PKCE 验证值摘要匹配，
   * 且授权码未使用、未过期。整段在一个 SQLite 事务中完成，
   * 并发下只有一个请求能把 consumed 从 0 改成 1。
   *
   * 使用 BEGIN IMMEDIATE：事务一开始就取写锁，其余并发请求在
   * busy_timeout 内排队，避免多个“先读后升级”事务互相死锁。
   */
  exchangeCode(params) {
    return this.exchangeCodeTx.immediate(params);
  }

  #exchangeCodeTx({ clientId, clientSecret, code, redirectUri, codeVerifier }) {
    const client = this.#authenticateClient(clientId, clientSecret);
    if (!code || typeof code !== 'string') {
      throw new OAuthError('invalid_grant', '缺少授权码');
    }
    const row = this.stmts.findCode.get(sha256(code));
    if (!row) {
      throw new OAuthError('invalid_grant', '授权码无效');
    }
    if (row.consumed) {
      throw new OAuthError('invalid_grant', '授权码已被兑换，不能重复使用');
    }
    if (row.client_id !== client.client_id) {
      throw new OAuthError('invalid_grant', '授权码不属于该客户端');
    }
    if (!redirectUri || redirectUri !== row.redirect_uri) {
      throw new OAuthError('invalid_grant', 'redirect_uri 与授权时登记的地址不匹配');
    }
    const now = this.clock.nowMs();
    if (now >= row.expires_at_ms) {
      throw new OAuthError('invalid_grant', '授权码已过期');
    }
    // PKCE：verifier 的 S256 摘要必须与授权时提交的 challenge 一致。
    verifyPkceS256(row.code_challenge, codeVerifier);

    // 条件更新兜底并发：只有一个事务能把 consumed 0 -> 1。
    const result = this.stmts.consumeCode.run(now, row.code_hash);
    if (result.changes !== 1) {
      throw new OAuthError('invalid_grant', '授权码已被兑换，不能重复使用');
    }

    return this.#issueNewTokenSet({
      clientId: row.client_id,
      userSubject: row.user_subject,
      scope: row.scope,
      now,
    });
  }

  /**
   * 3) 刷新访问令牌。
   *
   * - 刷新令牌每次使用都会轮换（旧 RT 标记 used，签发新 RT/AT）。
   * - 已用过的刷新令牌再次出现 = 重放：立即撤销整个令牌家族，
   *   家族内所有访问令牌（包括最新签发的）一并失效。
   * - 过期 RT 不轮换、不撤销家族，仅拒绝。
   * - 跨客户端出示他人家族的 RT：拒绝，不影响该家族。
   * - 请求收窄 scope 可以，但绝不能超出最初授权范围。
   */
  refresh(params) {
    // 事务回调不能在“已执行撤销写操作”之后抛错，否则 better-sqlite3
    // 会把整个事务（连同撤销）回滚。因此重放路径返回 REPLAY 标记，
    // 由这里在事务提交后再抛出对客户端可见的错误。
    const result = this.refreshTx.immediate(params);
    if (result === REPLAY_DETECTED) {
      throw new OAuthError('invalid_grant',
        '检测到刷新令牌重放，整个令牌家族（含最新令牌）已被撤销');
    }
    return result;
  }

  #refreshTx({ clientId, clientSecret, refreshToken, scope }) {
    const client = this.#authenticateClient(clientId, clientSecret);
    if (!refreshToken || typeof refreshToken !== 'string') {
      throw new OAuthError('invalid_grant', '缺少 refresh_token');
    }

    const row = this.stmts.findRefresh.get(sha256(refreshToken));
    if (!row) {
      throw new OAuthError('invalid_grant', '刷新令牌无效');
    }
    if (row.client_id !== client.client_id) {
      // 另一个客户端拿来兑换：直接拒绝。该家族不属于调用方，不替别人做撤销。
      throw new OAuthError('invalid_grant', '刷新令牌不属于该客户端');
    }

    const family = this.stmts.findFamily.get(row.family_id);
    if (!family) {
      throw new OAuthError('invalid_grant', '令牌家族不存在');
    }
    if (family.revoked) {
      throw new OAuthError('invalid_grant', '令牌家族已被撤销');
    }

    const now = this.clock.nowMs();

    if (row.used) {
      // 重放检测：被盗刷新令牌被二次使用。即使它已过期也照样撤销家族。
      this.#revokeFamily(family.family_id, now, 'refresh_token_reuse');
      return REPLAY_DETECTED;
    }

    if (now >= row.expires_at_ms) {
      throw new OAuthError('invalid_grant', '刷新令牌已过期');
    }

    let newScope = family.granted_scope;
    if (scope !== undefined) {
      const requested = normalizeScope(scope);
      if (requested.length === 0) {
        throw new OAuthError('invalid_scope', '请求的范围不能为空');
      }
      if (!isSubset(requested, normalizeScope(family.granted_scope))) {
        throw new OAuthError('invalid_scope', '刷新时请求的范围超出最初授权范围');
      }
      newScope = requested.join(' ');
    }

    // 条件更新保证并发轮换时只有一个赢家；
    // 其余并发请求看到 0 行改动 => 令牌刚被用掉 => 按重放处理并撤销家族。
    const used = this.stmts.markRefreshUsed.run(now, row.token_hash);
    if (used.changes !== 1) {
      this.#revokeFamily(family.family_id, now, 'refresh_token_reuse');
      return REPLAY_DETECTED;
    }

    return this.#issueTokenSetInFamily({
      family,
      scope: newScope,
      now,
    });
  }

  /** 授权码兑换时：新建令牌家族并签发首组令牌。 */
  #issueNewTokenSet({ clientId, userSubject, scope, now }) {
    const familyId = randomToken(16);
    this.stmts.insertFamily.run({
      family_id: familyId,
      client_id: clientId,
      user_subject: userSubject,
      granted_scope: scope,
    });
    return this.#persistTokens({ familyId, clientId, userSubject, scope, now });
  }

  /** 刷新轮换时：复用既有家族签发下一组令牌。 */
  #issueTokenSetInFamily({ family, scope, now }) {
    return this.#persistTokens({
      familyId: family.family_id,
      clientId: family.client_id,
      userSubject: family.user_subject,
      scope,
      now,
    });
  }

  #persistTokens({ familyId, clientId, userSubject, scope, now }) {
    const refreshToken = randomToken();
    const accessToken = randomToken();

    this.stmts.insertRefresh.run({
      token_hash: sha256(refreshToken),
      family_id: familyId,
      client_id: clientId,
      created_at_ms: now,
      expires_at_ms: now + this.refreshTokenTtlMs,
    });
    this.stmts.insertAccess.run({
      token_hash: sha256(accessToken),
      family_id: familyId,
      client_id: clientId,
      user_subject: userSubject,
      scope,
      created_at_ms: now,
      expires_at_ms: now + this.accessTokenTtlMs,
    });

    return {
      tokenType: 'Bearer',
      accessToken,
      refreshToken,
      scope,
      expiresIn: Math.floor(this.accessTokenTtlMs / 1000),
    };
  }

  #revokeFamily(familyId, now, reason) {
    this.stmts.revokeFamily.run(now, reason, familyId);
    // 家族撤销连坐家族内所有访问令牌，包括“最新令牌”。
    this.stmts.invalidateFamilyAccess.run(familyId);
  }

  /** 资源服务器侧校验访问令牌。 */
  introspectAccessToken(accessToken) {
    const row = this.stmts.findAccess.get(sha256(accessToken));
    if (!row) {
      return { active: false };
    }
    const family = this.stmts.findFamily.get(row.family_id);
    if (!family) {
      return { active: false };
    }
    const now = this.clock.nowMs();
    const active = !row.invalidated
      && !family.revoked
      && now < row.expires_at_ms;
    return {
      active,
      clientId: row.client_id,
      userSubject: row.user_subject,
      scope: row.scope,
      familyId: row.family_id,
      expiresAtMs: row.expires_at_ms,
    };
  }

  /** 刷新令牌状态（主要供测试/审计使用）。 */
  introspectRefreshToken(refreshToken) {
    const row = this.stmts.findRefresh.get(sha256(refreshToken));
    if (!row) {
      return { present: false };
    }
    const now = this.clock.nowMs();
    return {
      present: true,
      familyId: row.family_id,
      clientId: row.client_id,
      used: !!row.used,
      expired: now >= row.expires_at_ms,
      expiresAtMs: row.expires_at_ms,
    };
  }

  getFamilyState(familyId) {
    const family = this.stmts.findFamily.get(familyId);
    if (!family) return null;
    return {
      familyId: family.family_id,
      clientId: family.client_id,
      grantedScope: family.granted_scope,
      revoked: !!family.revoked,
      revokedAtMs: family.revoked_at_ms,
      revokeReason: family.revoke_reason,
    };
  }

  close() {
    this.db.close();
  }
}

module.exports = { AuthorizationServer, normalizeScope, isSubset, DEFAULT_TTL };
