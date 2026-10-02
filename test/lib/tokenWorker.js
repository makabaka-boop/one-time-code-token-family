'use strict';

/**
 * 并发测试用 worker：独立线程 + 独立数据库连接，
 * 与其他线程同时操作同一个 SQLite 文件。
 *
 * workerData: { dbFile, op, args, ttl?, barrier: Int32Array }
 * 生命周期：
 *   1. 打开数据库，构造服务；
 *   2. 在共享屏障上等待（所有 worker 到齐）；
 *   3. 主线程 Atomics.notify 后同时发起调用；
 *   4. 回传 { ok: true, value } | { ok: false, error, message }。
 */
const { workerData, parentPort } = require('node:worker_threads');
const { openDatabase } = require('../../src/db');
const { AuthorizationServer } = require('../../src/server');
const { SystemClock } = require('../../src/clock');

const db = openDatabase(workerData.dbFile);
const server = new AuthorizationServer({ db, clock: new SystemClock(), ...(workerData.ttl || {}) });

try {
  Atomics.add(workerData.ready, 0, 1);
  Atomics.wait(workerData.barrier, 0, 0);
  const value = server[workerData.op](workerData.args);
  parentPort.postMessage({ ok: true, value });
} catch (err) {
  parentPort.postMessage({
    ok: false,
    error: err.error || err.name,
    message: err.message,
  });
} finally {
  server.close();
}
