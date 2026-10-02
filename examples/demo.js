'use strict';

/**
 * 端到端演示（不依赖测试框架）：
 *   授权 -> 兑换 -> 刷新轮换 -> 重放旧刷新令牌 -> 家族撤销
 *
 * 运行：npm run demo
 */
const crypto = require('node:crypto');
const path = require('node:path');
const { openDatabase } = require('../src/db');
const { AuthorizationServer } = require('../src/server');
const { SystemClock } = require('../src/clock');

function pkce() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

function show(label, value) {
  console.log(`\n=== ${label} ===`);
  console.log(typeof value === 'string' ? value : value);
}

const dbFile = process.env.DEMO_DB || path.join(__dirname, '..', 'demo.db');
const db = openDatabase(dbFile);
const server = new AuthorizationServer({ db, clock: new SystemClock() });

const client = {
  clientId: 'client-a',
  clientSecret: 'secret-a',
  redirectUri: 'https://client-a.example.com/callback',
};

// 1. 用户确认范围后，授权服务签发短期授权码
const { codeVerifier, codeChallenge } = pkce();
const { code } = server.authorize({
  clientId: client.clientId,
  redirectUri: client.redirectUri,
  scope: 'read:profile read:messages',
  codeChallenge,
  userSubject: 'user-42',
});
show('1. 授权码（60s 有效）', code);

// 2. 客户端用“客户端身份 + 精确回调地址 + PKCE verifier”兑换
const t1 = server.exchangeCode({
  clientId: client.clientId,
  clientSecret: client.clientSecret,
  code,
  redirectUri: client.redirectUri,
  codeVerifier,
});
show('2. 首次令牌', {
  accessToken: t1.accessToken.slice(0, 24) + '…',
  refreshToken: t1.refreshToken.slice(0, 24) + '…',
  scope: t1.scope,
  expiresIn: t1.expiresIn,
});

// 3. 刷新令牌轮换
const t2 = server.refresh({
  clientId: client.clientId,
  clientSecret: client.clientSecret,
  refreshToken: t1.refreshToken,
});
show('3. 轮换后的新令牌（旧 RT 已作废）', {
  accessToken: t2.accessToken.slice(0, 24) + '…',
  refreshToken: t2.refreshToken.slice(0, 24) + '…',
});
console.log('旧刷新令牌 used =', server.introspectRefreshToken(t1.refreshToken).used);

// 4. 攻击者重放旧刷新令牌
console.log('\n=== 4. 重放旧刷新令牌 ===');
try {
  server.refresh({
    clientId: client.clientId,
    clientSecret: client.clientSecret,
    refreshToken: t1.refreshToken,
  });
} catch (err) {
  console.log('服务拒绝:', err.errorDescription);
}

// 5. 家族已被撤销：最新访问令牌与最新刷新令牌同时失效
const familyId = server.introspectRefreshToken(t2.refreshToken).familyId;
show('5. 家族状态', server.getFamilyState(familyId));
console.log('最新访问令牌 active =', server.introspectAccessToken(t2.accessToken).active);
try {
  server.refresh({
    clientId: client.clientId,
    clientSecret: client.clientSecret,
    refreshToken: t2.refreshToken,
  });
} catch (err) {
  console.log('最新刷新令牌也被拒绝:', err.errorDescription);
}

server.close();
console.log('\n演示完成。数据库文件:', dbFile);
