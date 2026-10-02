'use strict';

/**
 * OAuth 2.0 风格的错误类型，error 取值对齐 RFC 6749 第 5.2 节。
 */
class OAuthError extends Error {
  constructor(error, errorDescription, statusCode = 400) {
    super(errorDescription ? `${error}: ${errorDescription}` : error);
    this.name = 'OAuthError';
    this.error = error;
    this.errorDescription = errorDescription || null;
    this.statusCode = statusCode;
  }
}

module.exports = { OAuthError };
