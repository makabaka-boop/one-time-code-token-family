'use strict';

const path = require('node:path');
const Database = require('better-sqlite3');

/**
 * 两个预先登记的模拟客户端。
 * redirect_uri 是“精确回调地址”：授权与兑换时必须逐字符匹配，
 * 不做前缀匹配，也不允许同注册项之外的地址。
 */
const CLIENTS = [
  {
    clientId: 'client-a',
    clientSecret: 'secret-a',
    redirectUri: 'https://client-a.example.com/callback',
    scope: 'read:profile read:messages',
  },
  {
    clientId: 'client-b',
    clientSecret: 'secret-b',
    redirectUri: 'https://client-b.example.com/oauth/cb',
    scope: 'read:profile',
  },
];

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS clients (
  client_id     TEXT PRIMARY KEY,
  client_secret TEXT NOT NULL,
  redirect_uri  TEXT NOT NULL,
  scope         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash        TEXT PRIMARY KEY,
  client_id        TEXT NOT NULL REFERENCES clients(client_id),
  user_subject     TEXT NOT NULL,
  redirect_uri     TEXT NOT NULL,
  scope            TEXT NOT NULL,
  code_challenge   TEXT NOT NULL,
  expires_at_ms    INTEGER NOT NULL,
  consumed         INTEGER NOT NULL DEFAULT 0,
  consumed_at_ms   INTEGER
);

-- 刷新令牌家族：一次授权对应一个家族，家族级撤销会连带最新令牌。
CREATE TABLE IF NOT EXISTS token_families (
  family_id      TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL REFERENCES clients(client_id),
  user_subject   TEXT NOT NULL,
  granted_scope  TEXT NOT NULL,
  revoked        INTEGER NOT NULL DEFAULT 0,
  revoked_at_ms  INTEGER,
  revoke_reason  TEXT
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash    TEXT PRIMARY KEY,
  family_id     TEXT NOT NULL REFERENCES token_families(family_id),
  client_id     TEXT NOT NULL REFERENCES clients(client_id),
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  used          INTEGER NOT NULL DEFAULT 0,
  used_at_ms    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash    TEXT PRIMARY KEY,
  family_id     TEXT NOT NULL REFERENCES token_families(family_id),
  client_id     TEXT NOT NULL REFERENCES clients(client_id),
  user_subject  TEXT NOT NULL,
  scope         TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  invalidated   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_access_family ON access_tokens(family_id);
`;

/**
 * 打开（或创建）数据库并完成迁移。
 * @param {string} filename SQLite 文件路径；':memory:' 为内存库
 */
function openDatabase(filename = ':memory:') {
  const db = new Database(filename);
  // 并发写请求在 WAL 下串行排队，最多等 5 秒而不是立刻抛 SQLITE_BUSY。
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.exec(SCHEMA);

  const stmt = db.prepare(`
    INSERT INTO clients (client_id, client_secret, redirect_uri, scope)
    VALUES (@client_id, @client_secret, @redirect_uri, @scope)
    ON CONFLICT(client_id) DO UPDATE SET
      client_secret = excluded.client_secret,
      redirect_uri  = excluded.redirect_uri,
      scope         = excluded.scope
  `);
  for (const c of CLIENTS) {
    stmt.run({
      client_id: c.clientId,
      client_secret: c.clientSecret,
      redirect_uri: c.redirectUri,
      scope: c.scope,
    });
  }

  return db;
}

module.exports = { openDatabase, CLIENTS, SCHEMA };
