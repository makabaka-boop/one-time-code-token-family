'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker } = require('node:worker_threads');
const { openDatabase } = require('../../src/db');
const { AuthorizationServer } = require('../../src/server');
const { FakeClock } = require('../../src/clock');

const CLIENT_A = {
  clientId: 'client-a',
  clientSecret: 'secret-a',
  redirectUri: 'https://client-a.example.com/callback',
};
const CLIENT_B = {
  clientId: 'client-b',
  clientSecret: 'secret-b',
  redirectUri: 'https://client-b.example.com/oauth/cb',
};

function createServer(ttl = {}) {
  const db = openDatabase(':memory:');
  const clock = new FakeClock();
  const server = new AuthorizationServer({ db, clock, ...ttl });
  return { server, db, clock };
}

/** 生成符合 PKCE 规则的 verifier 和 S256 challenge。 */
function makePkce() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url'); // 43 字符
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return { codeVerifier, codeChallenge };
}

function authorize(server, client, { scope, userSubject = 'user-1', pkce = makePkce() } = {}) {
  const res = server.authorize({
    clientId: client.clientId,
    redirectUri: client.redirectUri,
    scope,
    codeChallenge: pkce.codeChallenge,
    userSubject,
  });
  return { ...res, ...pkce };
}

/** 走完整授权 + 兑换流程，返回首组令牌。 */
function grant(server, client, scope, userSubject = 'user-1') {
  const pkce = makePkce();
  const auth = authorize(server, client, { scope, userSubject, pkce });
  const tokens = server.exchangeCode({
    clientId: client.clientId,
    clientSecret: client.clientSecret,
    code: auth.code,
    redirectUri: client.redirectUri,
    codeVerifier: pkce.codeVerifier,
  });
  return tokens;
}

function makeTempDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-svc-'));
  const file = path.join(dir, 'auth.db');
  const cleanup = () => {
    fs.rmSync(dir, { recursive: true, force: true });
  };
  return { file, cleanup };
}

/**
 * 在 n 个独立线程里同时对同一个数据库文件发起调用。
 * worker 先在共享屏障上等待，全部就绪后由主线程统一放行。
 */
async function runConcurrentWorkers(dbFile, n, { op, args, ttl }) {
  const barrier = new Int32Array(new SharedArrayBuffer(4));
  const ready = new Int32Array(new SharedArrayBuffer(4));
  const workers = [];
  const messages = [];

  const resultPromise = Promise.all(Array.from({ length: n }, (_, i) =>
    new Promise((resolve, reject) => {
      const worker = new Worker(path.join(__dirname, 'tokenWorker.js'), {
        workerData: { dbFile, op, args, ttl, barrier, ready },
      });
      worker.once('message', (msg) => {
        messages[i] = msg;
        resolve();
      });
      worker.once('error', reject);
      workers.push(worker);
    })));

  // 轮询直到所有 worker 完成初始化并阻塞在屏障上。
  for (let i = 0; i < 500 && Atomics.load(ready, 0) < n; i += 1) {
    await new Promise((r) => setTimeout(r, 4));
  }
  if (Atomics.load(ready, 0) < n) {
    throw new Error('并发 worker 未能全部就绪');
  }
  Atomics.store(barrier, 0, 1);
  Atomics.notify(barrier, 0);
  await resultPromise;

  await Promise.all(workers.map((w) => w.terminate()));
  return messages;
}

module.exports = {
  CLIENT_A,
  CLIENT_B,
  createServer,
  makePkce,
  authorize,
  grant,
  makeTempDb,
  runConcurrentWorkers,
};
