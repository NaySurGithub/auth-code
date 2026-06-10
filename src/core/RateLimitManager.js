class RateLimitManager {
    constructor(adapter, config) {
        this.adapter = adapter;
        this.config = config || {};
    }

    async checkLimit(key, maxAttempts, windowMs) {
        const attempts = await this.adapter.getRateLimitAttempts(key);
        const now = Date.now();
        const windowStart = now - windowMs;
        const recentAttempts = attempts.filter(a => a.timestamp > windowStart);
        if (recentAttempts.length >= maxAttempts) {
            return false;
        }
        await this.adapter.recordRateLimitAttempt(key, now);
        return true;
    }

    async resetLimit(key) {
        await this.adapter.clearRateLimitAttempts(key);
    }
}

module.exports = RateLimitManager;