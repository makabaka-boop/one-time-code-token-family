'use strict';

const crypto = require('node:crypto');
const { OAuthError } = require('./errors');

/**
 * 生成高熵随机字符串（base64url，无填充）。
 * 32 字节随机量，足够作为授权码 / 令牌的不可猜测凭据。
 */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * 凭据一律以 SHA-256 摘要落库（授权码、验证值摘要、访问/刷新令牌），
 * 即使数据库文件泄露也无法直接拿到底文明文令牌。
 */
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * PKCE S256：code_verifier 必须是 43~128 个 base64url 字符，
 * code_challenge 必须是其 SHA-256(base64url 无填充)。
 * plain 方法明确拒绝，强制使用 S256。
 */
function verifyPkceS256(codeChallenge, codeVerifier) {
  if (typeof codeVerifier !== 'string' ||
      codeVerifier.length < 43 || codeVerifier.length > 128 ||
      !BASE64URL_PATTERN.test(codeVerifier)) {
    throw new OAuthError('invalid_grant', 'code_verifier 格式不合法');
  }
  const computed = sha256(codeVerifier);
  const expected = Buffer.from(codeChallenge);
  const actual = Buffer.from(computed);
  // 两个等长 base64url 串的定长比较，直接用 timingSafeEqual 防时序侧信道。
  if (expected.length !== actual.length ||
      !crypto.timingSafeEqual(expected, actual)) {
    throw new OAuthError('invalid_grant', 'code_verifier 与 code_challenge 不匹配');
  }
}

module.exports = { randomToken, sha256, verifyPkceS256 };
