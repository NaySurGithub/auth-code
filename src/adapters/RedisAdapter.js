const BaseAdapter = require('./BaseAdapter');
const crypto = require('crypto');

class RedisAdapter extends BaseAdapter {
    constructor(redisClient, config) {
        super();
        this.client = redisClient;
        this.prefix = config.prefix || 'auth:';
    }

    async saveSession(userId, jti, expiresAt, deviceInfo) { const ttl = Math.floor((expiresAt - Date.now()) / 1000); if (ttl > 0) { await this.client.set(`${this.prefix}session:${userId}:${jti}`, JSON.stringify({ deviceInfo }), { EX: ttl }); await this.client.sAdd(`${this.prefix}user_sessions:${userId}`, jti); } }
    async getSession(userId, jti) { const d = await this.client.get(`${this.prefix}session:${userId}:${jti}`); return d ? { userId, jti, ...JSON.parse(d) } : null; }
    async revokeSession(userId, jti) { await this.client.del(`${this.prefix}session:${userId}:${jti}`); await this.client.sRem(`${this.prefix}user_sessions:${userId}`, jti); }
    async revokeAllSessions(userId) { const j = await this.client.sMembers(`${this.prefix}user_sessions:${userId}`); if (j.length) await this.client.del(j.map(x => `${this.prefix}session:${userId}:${x}`)); await this.client.del(`${this.prefix}user_sessions:${userId}`); }
    async getSessions(userId) { const j = await this.client.sMembers(`${this.prefix}user_sessions:${userId}`); const sessions = []; for (const jti of j) { const d = await this.client.get(`${this.prefix}session:${userId}:${jti}`); if (d) sessions.push({ jti, ...JSON.parse(d) }); } return sessions; }

    async saveMFA(userId, secret, backupCodes, type = 'totp') { await this.client.set(`${this.prefix}mfa:${userId}:${type}`, JSON.stringify({ secret, backupCodes })); }
    async getMFA(userId, type = 'totp') { const d = await this.client.get(`${this.prefix}mfa:${userId}:${type}`); return d ? JSON.parse(d) : null; }
    async deleteMFA(userId, type = 'totp') { await this.client.del(`${this.prefix}mfa:${userId}:${type}`); }

    async recordLoginAttempt(ip, success) { const k = `${this.prefix}brute:${ip}`; if (!success) { await this.client.incr(k); await this.client.expire(k, 300); } else await this.client.del(k); }
    async checkBruteForce(ip) { return parseInt(await this.client.get(`${this.prefix}brute:${ip}`) || 0) >= 5; }

    async saveUser(userId, username, email, password, role) { await this.client.hSet(`${this.prefix}user:${userId}`, { username, email, password, role, emailVerified: 'false', lastLoginMethod: 'password' }); }
    async getUserByEmail(email) { const keys = await this.client.keys(`${this.prefix}user:*`); for (const k of keys) { const u = await this.client.hGetAll(k); if (u.email === email) return { userId: k.split(':')[2], ...u, emailVerified: u.emailVerified === 'true' }; } return null; }
    async getUserById(userId) { const d = await this.client.hGetAll(`${this.prefix}user:${userId}`); return Object.keys(d).length ? { userId, ...d, emailVerified: d.emailVerified === 'true' } : null; }
    async getUserByProviderId(provider, providerId) { const keys = await this.client.keys(`${this.prefix}user:*`); for (const k of keys) { const u = await this.client.hGetAll(k); if (u.provider === provider && u.providerId === providerId) return { userId: k.split(':')[2], ...u }; } return null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { await this.client.hSet(`${this.prefix}user:${userId}`, { username: name, email, provider, providerId, role: 'user', emailVerified: 'true', lastLoginMethod: `oauth:${provider}` }); }
    async updateLastLoginMethod(userId, method) { await this.client.hSet(`${this.prefix}user:${userId}`, 'lastLoginMethod', method); }

    async createRole(role) { await this.client.set(`${this.prefix}role:${role.name}`, JSON.stringify(role)); }
    async getRole(roleName) { const d = await this.client.get(`${this.prefix}role:${roleName}`); return d ? JSON.parse(d) : null; }
    async updateRole(roleName, roleData) { await this.client.set(`${this.prefix}role:${roleName}`, JSON.stringify(roleData)); }
    async deleteRole(roleName) { await this.client.del(`${this.prefix}role:${roleName}`); }
    async getAllRoles() { const keys = await this.client.keys(`${this.prefix}role:*`); const roles = []; for (const k of keys) { const d = await this.client.get(k); if (d) roles.push(JSON.parse(d)); } return roles; }

    async assignRoleToUser(userId, roleName) { await this.client.sAdd(`${this.prefix}user_roles:${userId}`, roleName); }
    async removeRoleFromUser(userId, roleName) { await this.client.sRem(`${this.prefix}user_roles:${userId}`, roleName); }
    async removeRoleFromAllUsers(roleName) { const keys = await this.client.keys(`${this.prefix}user_roles:*`); for (const k of keys) await this.client.sRem(k, roleName); }
    async getUserRoles(userId) { return await this.client.sMembers(`${this.prefix}user_roles:${userId}`); }

    async createApiKey(userId, name, permissions, expiresAt) { const keyId = `ak_${Math.random().toString(36).substring(2, 15)}`; const keyValue = `live_${Math.random().toString(36).substring(2, 25)}`; const ttl = Math.floor((expiresAt - Date.now()) / 1000); await this.client.set(`${this.prefix}apikey_val:${keyValue}`, JSON.stringify({ keyId, userId, name, permissions, expiresAt: expiresAt.toISOString(), active: true }), { EX: ttl > 0 ? ttl : undefined }); await this.client.sAdd(`${this.prefix}user_apikeys:${userId}`, keyId); return { keyId, keyValue }; }
    async getApiKey(keyValue) { const d = await this.client.get(`${this.prefix}apikey_val:${keyValue}`); if (!d) return null; const k = JSON.parse(d); return k.active && new Date(k.expiresAt) > new Date() ? k : null; }
    async revokeApiKey(keyId) { const keys = await this.client.keys(`${this.prefix}apikey_val:*`); for (const k of keys) { const d = await this.client.get(k); if (d) { const p = JSON.parse(d); if (p.keyId === keyId) { p.active = false; await this.client.set(k, JSON.stringify(p)); } } } }
    async getUserApiKeys(userId) { const ids = await this.client.sMembers(`${this.prefix}user_apikeys:${userId}`); const keys = []; const vkeys = await this.client.keys(`${this.prefix}apikey_val:*`); for (const vk of vkeys) { const d = await this.client.get(vk); if (d) { const p = JSON.parse(d); if (ids.includes(p.keyId)) keys.push({ keyId: p.keyId, name: p.name, expiresAt: new Date(p.expiresAt), active: p.active }); } } return keys; }

    async saveMagicLink(userId, token, expiresAt) { const ttl = Math.floor((expiresAt - Date.now()) / 1000); await this.client.set(`${this.prefix}magiclink:${token}`, userId, { EX: ttl > 0 ? ttl : undefined }); }
    async getMagicLink(token) { const u = await this.client.get(`${this.prefix}magiclink:${token}`); return u ? { userId: u, expiresAt: new Date(Date.now() + 1000) } : null; }
    async deleteMagicLink(token) { await this.client.del(`${this.prefix}magiclink:${token}`); }

    async getRateLimitAttempts(key) { const d = await this.client.get(`${this.prefix}ratelimit:${key}`); return d ? JSON.parse(d) : []; }
    async recordRateLimitAttempt(key, timestamp) { const a = await this.getRateLimitAttempts(key); a.push({ timestamp }); await this.client.set(`${this.prefix}ratelimit:${key}`, JSON.stringify(a), { EX: 300 }); }
    async clearRateLimitAttempts(key) { await this.client.del(`${this.prefix}ratelimit:${key}`); }

    async saveWebAuthnChallenge(userId, challenge) { await this.client.set(`${this.prefix}webauthn_challenge:${userId}`, challenge, { EX: 300 }); }
    async getWebAuthnChallenge(userId) { return await this.client.get(`${this.prefix}webauthn_challenge:${userId}`); }
    async clearWebAuthnChallenge(userId) { await this.client.del(`${this.prefix}webauthn_challenge:${userId}`); }

    async saveWebAuthnCredential(userId, registrationInfo) { const credId = Buffer.from(registrationInfo.credentialID).toString('base64url'); const publicKey = Buffer.from(registrationInfo.credentialPublicKey).toString('base64'); await this.client.sAdd(`${this.prefix}webauthn_creds:${userId}`, JSON.stringify({ id: credId, publicKey, counter: registrationInfo.counter, transports: registrationInfo.transports || [] })); }
    async getWebAuthnCredentials(userId) { return (await this.client.sMembers(`${this.prefix}webauthn_creds:${userId}`)).map(c => { const p = JSON.parse(c); return { id: p.id, type: 'public-key', transports: p.transports }; }); }
    async getWebAuthnCredentialById(credentialId) { const keys = await this.client.keys(`${this.prefix}webauthn_creds:*`); for (const k of keys) { for (const c of await this.client.sMembers(k)) { const p = JSON.parse(c); if (p.id === credentialId) return { ...p, publicKey: Buffer.from(p.publicKey, 'base64') }; } } return null; }
    async updateWebAuthnCredentialCounter(credentialId, counter) { const keys = await this.client.keys(`${this.prefix}webauthn_creds:*`); for (const k of keys) { const creds = await this.client.sMembers(k); const updated = []; let found = false; for (const c of creds) { const p = JSON.parse(c); if (p.id === credentialId) { p.counter = counter; found = true; } updated.push(JSON.stringify(p)); } if (found) { await this.client.del(k); if (updated.length) await this.client.sAdd(k, ...updated); break; } } }

    async saveEmailVerification(userId, email, token, expiresAt) { const ttl = Math.floor((expiresAt - Date.now()) / 1000); await this.client.set(`${this.prefix}emailver:${token}`, JSON.stringify({ userId, email }), { EX: ttl > 0 ? ttl : undefined }); }
    async getEmailVerification(token) { const d = await this.client.get(`${this.prefix}emailver:${token}`); return d ? JSON.parse(d) : null; }
    async deleteEmailVerification(token) { await this.client.del(`${this.prefix}emailver:${token}`); }
    async markEmailAsVerified(userId) { await this.client.hSet(`${this.prefix}user:${userId}`, 'emailVerified', 'true'); }

    async savePasswordReset(userId, email, token, expiresAt) { const ttl = Math.floor((expiresAt - Date.now()) / 1000); await this.client.set(`${this.prefix}pwdreset:${token}`, JSON.stringify({ userId, email }), { EX: ttl > 0 ? ttl : undefined }); }
    async getPasswordReset(token) { const d = await this.client.get(`${this.prefix}pwdreset:${token}`); return d ? JSON.parse(d) : null; }
    async deletePasswordReset(token) { await this.client.del(`${this.prefix}pwdreset:${token}`); }
    async updateUserPassword(userId, hashedPassword) { await this.client.hSet(`${this.prefix}user:${userId}`, 'password', hashedPassword); }

    async generateOneTimeToken(userId, purpose, expiresAt) { const token = crypto.randomBytes(32).toString('hex'); const ttl = Math.floor((expiresAt - Date.now()) / 1000); await this.client.set(`${this.prefix}ott:${token}`, JSON.stringify({ userId, purpose }), { EX: ttl > 0 ? ttl : undefined }); return token; }
    async verifyOneTimeToken(token, purpose) { const d = await this.client.get(`${this.prefix}ott:${token}`); if (!d) return null; const p = JSON.parse(d); if (p.purpose !== purpose) return null; await this.client.del(`${this.prefix}ott:${token}`); return p.userId; }
}

module.exports = RedisAdapter;