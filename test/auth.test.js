'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  CLIENT_A,
  CLIENT_B,
  createServer,
  makePkce,
  authorize,
  grant,
  makeTempDb,
  runConcurrentWorkers,
} = require('./lib/helpers');
const { openDatabase } = require('../src/db');
const { AuthorizationServer } = require('../src/server');
const { FakeClock, SystemClock } = require('../src/clock');

test('授权端点：校验客户端、精确回调地址、PKCE 与范围', () => {
  const { server } = createServer();
  const pkce = makePkce();

  assert.throws(
    () => authorize(server, CLIENT_A, { scope: 'read:profile', pkce: { ...pkce, codeChallenge: 'plain-not-supported-xxxxx'.slice(0, 43) } }),
    /code_challenge/);

  // 回调地址必须与登记地址逐字符一致，即使同一域名下的路径变体也不行。
  assert.throws(
    () => server.authorize({
      clientId: CLIENT_A.clientId,
      redirectUri: 'https://client-a.example.com/callback?extra=1',
      scope: 'read:profile',
      codeChallenge: pkce.codeChallenge,
      userSubject: 'user-1',
    }),
    /redirect_uri/);

  // 未知客户端
  assert.throws(
    () => authorize(server, { clientId: 'client-x', redirectUri: 'https://x' }, { scope: 'read:profile' }),
    /未知客户端/);

  // 范围越权：client-b 只登记了 read:profile
  assert.throws(
    () => authorize(server, CLIENT_B, { scope: 'read:messages' }),
    /超出客户端登记范围/);

  // 空 scope
  assert.throws(
    () => authorize(server, CLIENT_A, { scope: '   ' }),
    /范围不能为空/);

  // 正常签发
  const res = authorize(server, CLIENT_A, { scope: 'read:profile read:messages' });
  assert.ok(res.code.length > 20);
  assert.equal(res.expiresIn, 60);
});

test('兑换：成功路径返回访问令牌与刷新令牌，且只存摘要', () => {
  const { server, db } = createServer();
  const pkce = makePkce();
  const auth = authorize(server, CLIENT_A, { scope: 'read:profile', pkce });

  const tokens = server.exchangeCode({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    code: auth.code,
    redirectUri: CLIENT_A.redirectUri,
    codeVerifier: pkce.codeVerifier,
  });

  assert.equal(tokens.tokenType, 'Bearer');
  assert.ok(tokens.accessToken);
  assert.ok(tokens.refreshToken);
  assert.notEqual(tokens.accessToken, tokens.refreshToken);
  assert.equal(tokens.scope, 'read:profile');
  assert.equal(tokens.expiresIn, 300);

  // 数据库里不能出现明文授权码/令牌
  const codeRows = db.prepare('SELECT code_hash FROM auth_codes').all();
  assert.equal(codeRows.length, 1);
  assert.notEqual(codeRows[0].code_hash, auth.code);

  const introspection = server.introspectAccessToken(tokens.accessToken);
  assert.equal(introspection.active, true);
  assert.equal(introspection.clientId, 'client-a');
  assert.equal(introspection.userSubject, 'user-1');
});

test('兑换：客户端密钥错误被拒', () => {
  const { server } = createServer();
  const pkce = makePkce();
  const auth = authorize(server, CLIENT_A, { scope: 'read:profile', pkce });

  assert.throws(
    () => server.exchangeCode({
      clientId: CLIENT_A.clientId,
      clientSecret: 'wrong-secret',
      code: auth.code,
      redirectUri: CLIENT_A.redirectUri,
      codeVerifier: pkce.codeVerifier,
    }),
    /身份验证失败/);
});

test('兑换：两个客户端交叉兑换均失败（码与客户端、回调、verifier 必须同时匹配）', () => {
  const { server } = createServer();
  const pkceA = makePkce();
  const pkceB = makePkce();

  const codeA = authorize(server, CLIENT_A, { scope: 'read:profile', pkce: pkceA }).code;
  const codeB = authorize(server, CLIENT_B, { scope: 'read:profile', pkce: pkceB }).code;

  // client-b 拿 client-a 的码，即使带自己的正确密钥/回调/verifier
  assert.throws(
    () => server.exchangeCode({
      clientId: CLIENT_B.clientId,
      clientSecret: CLIENT_B.clientSecret,
      code: codeA,
      redirectUri: CLIENT_B.redirectUri,
      codeVerifier: pkceB.codeVerifier,
    }),
    /授权码不属于该客户端|redirect_uri/);

  // client-a 拿 client-b 的码
  assert.throws(
    () => server.exchangeCode({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      code: codeB,
      redirectUri: CLIENT_A.redirectUri,
      codeVerifier: pkceA.codeVerifier,
    }),
    /授权码不属于该客户端|redirect_uri/);

  // 回调地址对不上（客户端正确，地址用另一个客户端的）
  assert.throws(
    () => server.exchangeCode({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      code: codeA,
      redirectUri: CLIENT_B.redirectUri,
      codeVerifier: pkceA.codeVerifier,
    }),
    /redirect_uri/);

  // verifier 错误
  assert.throws(
    () => server.exchangeCode({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      code: codeA,
      redirectUri: CLIENT_A.redirectUri,
      codeVerifier: pkceB.codeVerifier,
    }),
    /code_verifier/);

  // 交叉尝试之后，原主仍可正常兑换（码未被污染）
  const tokens = server.exchangeCode({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    code: codeA,
    redirectUri: CLIENT_A.redirectUri,
    codeVerifier: pkceA.codeVerifier,
  });
  assert.ok(tokens.accessToken);
});

test('兑换：授权码只能成功兑换一次（同线程顺序重放）', () => {
  const { server } = createServer();
  const tokens = grant(server, CLIENT_A, 'read:profile');
  assert.ok(tokens.accessToken);

  // 无法直接重放，因为 grant 内部已消费；这里用第二个授权码验证二次兑换报错
  const pkce = makePkce();
  const { code } = authorize(server, CLIENT_A, { scope: 'read:profile', pkce });
  const args = {
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    code,
    redirectUri: CLIENT_A.redirectUri,
    codeVerifier: pkce.codeVerifier,
  };
  assert.ok(server.exchangeCode(args).accessToken);
  assert.throws(() => server.exchangeCode(args), /已被兑换/);
});

test('兑换：过期授权码无法使用（注入时钟）', () => {
  const { server, clock } = createServer();
  const pkce = makePkce();
  const { code } = authorize(server, CLIENT_A, { scope: 'read:profile', pkce });

  clock.advance(60_001);

  assert.throws(
    () => server.exchangeCode({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      code,
      redirectUri: CLIENT_A.redirectUri,
      codeVerifier: pkce.codeVerifier,
    }),
    /已过期/);
});

test('刷新：轮换出全新令牌，旧刷新令牌失效', () => {
  const { server } = createServer();
  const first = grant(server, CLIENT_A, 'read:profile');

  const second = server.refresh({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    refreshToken: first.refreshToken,
  });
  assert.notEqual(second.refreshToken, first.refreshToken);
  assert.notEqual(second.accessToken, first.accessToken);

  const oldInfo = server.introspectRefreshToken(first.refreshToken);
  assert.equal(oldInfo.used, true);
  assert.equal(oldInfo.expired, false);

  const newInfo = server.introspectRefreshToken(second.refreshToken);
  assert.equal(newInfo.used, false);
});

test('刷新：旧刷新令牌重放 -> 撤销整个家族，最新访问令牌也失效', () => {
  const { server } = createServer();
  const first = grant(server, CLIENT_A, 'read:profile');
  const familyId = server.introspectRefreshToken(first.refreshToken).familyId;

  const second = server.refresh({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    refreshToken: first.refreshToken,
  });
  const third = server.refresh({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    refreshToken: second.refreshToken,
  });

  // 最新的访问令牌在重放之前是有效的
  assert.equal(server.introspectAccessToken(third.accessToken).active, true);

  // 攻击者拿最早的 first.refreshToken 来重放
  assert.throws(
    () => server.refresh({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      refreshToken: first.refreshToken,
    }),
    /重放/);

  const state = server.getFamilyState(familyId);
  assert.equal(state.revoked, true);
  assert.equal(state.revokeReason, 'refresh_token_reuse');

  // 最新令牌（third 的 AT/RT）全部失效
  assert.equal(server.introspectAccessToken(third.accessToken).active, false);
  assert.equal(server.introspectAccessToken(second.accessToken).active, false);
  assert.throws(
    () => server.refresh({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      refreshToken: third.refreshToken,
    }),
    /家族已被撤销/);

  // 中间轮次的 RT 再出现也一律拒绝
  assert.throws(
    () => server.refresh({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      refreshToken: second.refreshToken,
    }),
    /家族已被撤销/);
});

test('刷新：允许收窄访问令牌范围，且禁止超出最初授权范围', () => {
  const { server } = createServer();
  const first = grant(server, CLIENT_A, 'read:profile read:messages');

  const narrowed = server.refresh({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    refreshToken: first.refreshToken,
    scope: 'read:profile',
  });
  assert.equal(narrowed.scope, 'read:profile');
  assert.equal(server.introspectAccessToken(narrowed.accessToken).scope, 'read:profile');

  // 收窄只作用于本次访问令牌；家族初始授权未变，
  // 后续刷新仍可在“最初授权范围”内重新选择（标准 OAuth 语义）。
  const widenedBack = server.refresh({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    refreshToken: narrowed.refreshToken,
    scope: 'read:messages',
  });
  assert.equal(widenedBack.scope, 'read:messages');

  // 但绝不能索要最初授权范围之外的权限
  assert.throws(
    () => server.refresh({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      refreshToken: widenedBack.refreshToken,
      scope: 'write:profile',
    }),
    /超出最初授权范围/);
});

test('刷新：另一个客户端交叉使用刷新令牌被拒，且不影响原家族', () => {
  const { server } = createServer();
  const first = grant(server, CLIENT_A, 'read:profile');
  const familyId = server.introspectRefreshToken(first.refreshToken).familyId;

  assert.throws(
    () => server.refresh({
      clientId: CLIENT_B.clientId,
      clientSecret: CLIENT_B.clientSecret,
      refreshToken: first.refreshToken,
    }),
    /不属于该客户端/);

  // 原家族完好，client-a 仍可正常轮换
  const rotated = server.refresh({
    clientId: CLIENT_A.clientId,
    clientSecret: CLIENT_A.clientSecret,
    refreshToken: first.refreshToken,
  });
  assert.ok(rotated.accessToken);
  assert.equal(server.getFamilyState(familyId).revoked, false);
});

test('刷新：过期刷新令牌不能使用（注入时钟）', () => {
  const { server, clock } = createServer();
  const first = grant(server, CLIENT_A, 'read:profile');

  clock.advance(1_209_600_001); // 超过 14 天

  assert.throws(
    () => server.refresh({
      clientId: CLIENT_A.clientId,
      clientSecret: CLIENT_A.clientSecret,
      refreshToken: first.refreshToken,
    }),
    /已过期/);
});

test('访问令牌：到期后 introspect 失活', () => {
  const { server, clock } = createServer();
  const first = grant(server, CLIENT_A, 'read:profile');

  assert.equal(server.introspectAccessToken(first.accessToken).active, true);
  clock.advance(300_001);
  assert.equal(server.introspectAccessToken(first.accessToken).active, false);
});

test('并发：同一授权码被多线程同时兑换，恰好成功一次', async () => {
  const { file, cleanup } = makeTempDb();
  try {
    const pkce = makePkce();
    let code;

    // 主线程准备好授权码
    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock: new SystemClock() });
      code = authorize(server, CLIENT_A, { scope: 'read:profile', pkce }).code;
      server.close();
    }

    const results = await runConcurrentWorkers(file, 4, {
      op: 'exchangeCode',
      args: {
        clientId: CLIENT_A.clientId,
        clientSecret: CLIENT_A.clientSecret,
        code,
        redirectUri: CLIENT_A.redirectUri,
        codeVerifier: pkce.codeVerifier,
      },
    });

    const successes = results.filter((r) => r.ok);
    const failures = results.filter((r) => !r.ok);
    assert.equal(successes.length, 1, '必须恰好一个线程兑换成功');
    assert.equal(failures.length, 3);
    for (const f of failures) {
      assert.match(f.message, /已被兑换/);
    }

    // 落库核实：只有一组令牌、一个家族
    const db = openDatabase(file);
    const check = new AuthorizationServer({ db, clock: new SystemClock() });
    assert.equal(db.prepare('SELECT COUNT(*) c FROM auth_codes WHERE consumed = 1').get().c, 1);
    assert.equal(db.prepare('SELECT COUNT(*) c FROM token_families').get().c, 1);
    assert.equal(db.prepare('SELECT COUNT(*) c FROM refresh_tokens').get().c, 1);
    assert.equal(check.introspectAccessToken(successes[0].value.accessToken).active, true);
    check.close();
  } finally {
    cleanup();
  }
});

test('并发：同一刷新令牌被多线程同时刷新，一个成功且家族被撤销', async () => {
  const { file, cleanup } = makeTempDb();
  try {
    let refreshToken;
    let familyId;

    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock: new SystemClock() });
      const tokens = grant(server, CLIENT_A, 'read:profile');
      refreshToken = tokens.refreshToken;
      familyId = server.introspectRefreshToken(refreshToken).familyId;
      server.close();
    }

    const results = await runConcurrentWorkers(file, 4, {
      op: 'refresh',
      args: {
        clientId: CLIENT_A.clientId,
        clientSecret: CLIENT_A.clientSecret,
        refreshToken,
      },
    });

    const successes = results.filter((r) => r.ok);
    assert.equal(successes.length, 1, '并发轮换恰好一个赢家');

    const db = openDatabase(file);
    const check = new AuthorizationServer({ db, clock: new SystemClock() });
    const state = check.getFamilyState(familyId);
    assert.equal(state.revoked, true);
    assert.equal(state.revokeReason, 'refresh_token_reuse');

    // 赢家签发的“最新访问令牌”也因家族撤销而立刻失活
    assert.equal(check.introspectAccessToken(successes[0].value.accessToken).active, false);

    // 赢家拿到的新 RT 同样不可再用
    const winner = successes[0].value;
    assert.throws(
      () => check.refresh({
        clientId: CLIENT_A.clientId,
        clientSecret: CLIENT_A.clientSecret,
        refreshToken: winner.refreshToken,
      }),
      /家族已被撤销/);
    check.close();
  } finally {
    cleanup();
  }
});

test('重启：已消费授权码、已轮换刷新令牌在重启后依然无效', () => {
  const { file, cleanup } = makeTempDb();
  const ttl = {
    codeTtlMs: 10_000,
    accessTokenTtlMs: 60_000,
    refreshTokenTtlMs: 600_000,
  };
  try {
    const clock = new FakeClock();

    // 第一次进程：授权 -> 兑换 -> 刷新
    let usedCodeArgs;
    let rotatedRefresh;
    let latestRefresh;
    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock, ...ttl });
      const pkce = makePkce();
      const { code } = authorize(server, CLIENT_A, { scope: 'read:profile', pkce });
      usedCodeArgs = {
        clientId: CLIENT_A.clientId,
        clientSecret: CLIENT_A.clientSecret,
        code,
        redirectUri: CLIENT_A.redirectUri,
        codeVerifier: pkce.codeVerifier,
      };
      const first = server.exchangeCode(usedCodeArgs);
      const second = server.refresh({
        clientId: CLIENT_A.clientId,
        clientSecret: CLIENT_A.clientSecret,
        refreshToken: first.refreshToken,
      });
      rotatedRefresh = first.refreshToken;
      latestRefresh = second.refreshToken;
      server.close();
    }

    // 模拟重启：新连接、新服务实例、同一个持久化文件
    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock, ...ttl });

      assert.throws(() => server.exchangeCode(usedCodeArgs), /已被兑换/);
      assert.throws(
        () => server.refresh({
          clientId: CLIENT_A.clientId,
          clientSecret: CLIENT_A.clientSecret,
          refreshToken: rotatedRefresh,
        }),
        /重放/);

      // 重放旧 RT 导致家族撤销：最新 RT 也不能复活
      assert.throws(
        () => server.refresh({
          clientId: CLIENT_A.clientId,
          clientSecret: CLIENT_A.clientSecret,
          refreshToken: latestRefresh,
        }),
        /家族已被撤销/);

      server.close();
    }

    // 再重启一次仍然无效
    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock, ...ttl });
      const familyId = server.introspectRefreshToken(latestRefresh).familyId;
      assert.equal(server.getFamilyState(familyId).revoked, true);
      server.close();
    }
  } finally {
    cleanup();
  }
});

test('重启：重启不会使未到期的授权码提前失效，但过期判断仍由注入时钟控制', () => {
  const { file, cleanup } = makeTempDb();
  const ttl = { codeTtlMs: 10_000, accessTokenTtlMs: 60_000, refreshTokenTtlMs: 600_000 };
  try {
    const clock = new FakeClock(5_000_000_000);
    const pkce = makePkce();
    let pendingCodeArgs;
    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock, ...ttl });
      const { code } = authorize(server, CLIENT_A, { scope: 'read:profile', pkce });
      pendingCodeArgs = {
        clientId: CLIENT_A.clientId,
        clientSecret: CLIENT_A.clientSecret,
        code,
        redirectUri: CLIENT_A.redirectUri,
        codeVerifier: pkce.codeVerifier,
      };
      server.close();
    }

    // 重启且时钟未推进：码仍在有效期内，可正常兑换
    {
      const db = openDatabase(file);
      const server = new AuthorizationServer({ db, clock, ...ttl });
      const tokens = server.exchangeCode(pendingCodeArgs);
      assert.ok(tokens.accessToken);
      server.close();
    }
  } finally {
    cleanup();
  }
});
