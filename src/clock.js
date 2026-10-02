'use strict';

/**
 * 可注入时钟。
 *
 * - SystemClock：生产环境使用，返回真实系统时间。
 * - FakeClock：测试使用，时间只能通过 advance() 显式向前推进，
 *   这样到期判断与墙钟无关，测试结果可复现。
 *
 * 服务内部所有“当前时间”都必须取自 clock.nowMs()，
 * 不允许直接调用 Date.now()。
 */
class SystemClock {
  nowMs() {
    return Date.now();
  }
}

class FakeClock {
  constructor(startMs = 1_700_000_000_000) {
    this._now = startMs;
  }

  nowMs() {
    return this._now;
  }

  advance(ms) {
    if (!Number.isInteger(ms) || ms < 0) {
      throw new TypeError('advance(ms) 需要非负整数');
    }
    this._now += ms;
    return this._now;
  }
}

module.exports = { SystemClock, FakeClock };
