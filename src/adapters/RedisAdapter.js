const BaseAdapter = require('./BaseAdapter');

class RedisAdapter extends BaseAdapter {
    constructor(redisClient, config) {
        super();
        this.client = redisClient;
        this.prefix = config.prefix || 'auth:';
    }

    async saveSession(userId, jti, expiresAt) {
        const ttl = Math.floor((expiresAt - Date.now()) / 1000);
        if (ttl > 0) {
            await this.client.set(`${this.prefix}session:${userId}:${jti}`, '1', { EX: ttl });
            await this.client.sAdd(`${this.prefix}user_sessions:${userId}`, jti);
        }
    }
    async getSession(userId, jti) {
        const exists = await this.client.exists(`${this.prefix}session:${userId}:${jti}`);
        return exists ? { userId, jti } : null;
    }
    async revokeSession(userId, jti) {
        await this.client.del(`${this.prefix}session:${userId}:${jti}`);
        await this.client.sRem(`${this.prefix}user_sessions:${userId}`, jti);
    }
    async revokeAllSessions(userId) {
        const jtis = await this.client.sMembers(`${this.prefix}user_sessions:${userId}`);
        if (jtis.length > 0) {
            const keys = jtis.map(j => `${this.prefix}session:${userId}:${j}`);
            await this.client.del(keys);
        }
        await this.client.del(`${this.prefix}user_sessions:${userId}`);
    }
    async saveMFA(userId, secret, backupCodes) { await this.client.set(`${this.prefix}mfa:${userId}`, JSON.stringify({ secret, backupCodes })); }
    async getMFA(userId) { const data = await this.client.get(`${this.prefix}mfa:${userId}`); return data ? JSON.parse(data) : null; }
    async deleteMFA(userId) { await this.client.del(`${this.prefix}mfa:${userId}`); }
    async recordLoginAttempt(ip, success) {
        const key = `${this.prefix}brute:${ip}`;
        if (!success) { await this.client.incr(key); await this.client.expire(key, 300); } 
        else { await this.client.del(key); }
    }
    async checkBruteForce(ip) { const attempts = await this.client.get(`${this.prefix}brute:${ip}`); return parseInt(attempts || 0) >= 5; }
    async saveUser(userId, username, email, password, role) { await this.client.hSet(`${this.prefix}user:${userId}`, { username, email, password, role }); }
    async getUserByEmail(email) {
        const keys = await this.client.keys(`${this.prefix}user:*`);
        for (const key of keys) {
            const user = await this.client.hGetAll(key);
            if (user.email === email) return { userId: key.split(':')[2], ...user };
        }
        return null;
    }
    async getUserById(userId) { const data = await this.client.hGetAll(`${this.prefix}user:${userId}`); return Object.keys(data).length ? { userId, ...data } : null; }
    async getUserByProviderId(provider, providerId) { return null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { await this.client.hSet(`${this.prefix}user:${userId}`, { username: name, email, provider, providerId, role: 'user' }); }
}

module.exports = RedisAdapter;