const BaseAdapter = require('./BaseAdapter');
const crypto = require('crypto');

class MemoryAdapter extends BaseAdapter {
    constructor() {
        super();
        this.sessions = new Map();
        this.mfa = new Map();
        this.loginAttempts = new Map();
        this.users = new Map();
        this.roles = new Map();
        this.userRoles = new Map();
        this.apiKeys = new Map();
        this.magicLinks = new Map();
        this.rateLimits = new Map();
        this.webauthnChallenges = new Map();
        this.webauthnCredentials = new Map();
        this.emailVerifications = new Map();
        this.passwordResets = new Map();
        this.oneTimeTokens = new Map();
    }

    async saveSession(userId, jti, expiresAt, deviceInfo) { this.sessions.set(`${userId}:${jti}`, { userId, jti, expiresAt, deviceInfo }); }
    async getSession(userId, jti) { const s = this.sessions.get(`${userId}:${jti}`); return (s && s.expiresAt > new Date()) ? s : null; }
    async revokeSession(userId, jti) { this.sessions.delete(`${userId}:${jti}`); }
    async revokeAllSessions(userId) { for (const [k, s] of this.sessions.entries()) if (s.userId === userId) this.sessions.delete(k); }
    async getSessions(userId) { const sessions = []; for (const [k, s] of this.sessions.entries()) if (s.userId === userId && s.expiresAt > new Date()) sessions.push({ jti: s.jti, expiresAt: s.expiresAt, device: s.deviceInfo || 'Unknown' }); return sessions; }

    async saveMFA(userId, secret, backupCodes, type = 'totp') { this.mfa.set(`${userId}:${type}`, { userId, secret, backupCodes, type }); }
    async getMFA(userId, type = 'totp') { return this.mfa.get(`${userId}:${type}`) || null; }
    async deleteMFA(userId, type = 'totp') { this.mfa.delete(`${userId}:${type}`); }

    async recordLoginAttempt(ip, success) { if (!this.loginAttempts.has(ip)) this.loginAttempts.set(ip, []); this.loginAttempts.get(ip).push({ success, timestamp: Date.now() }); }
    async checkBruteForce(ip) { const a = this.loginAttempts.get(ip) || []; return a.filter(x => !x.success && x.timestamp > Date.now() - 300000).length >= 5; }

    async saveUser(userId, username, email, password, role) { this.users.set(userId, { userId, username, email, password, role, emailVerified: false, lastLoginMethod: null }); if (!this.userRoles.has(userId)) this.userRoles.set(userId, new Set()); this.userRoles.get(userId).add(role || 'user'); }
    async getUserByEmail(email) { for (const u of this.users.values()) if (u.email === email) return u; return null; }
    async getUserById(userId) { return this.users.get(userId) || null; }
    async getUserByProviderId(provider, providerId) { for (const u of this.users.values()) if (u.provider === provider && u.providerId === providerId) return u; return null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { this.users.set(userId, { userId, username: name, email, provider, providerId, role: 'user', emailVerified: true, lastLoginMethod: `oauth:${provider}` }); if (!this.userRoles.has(userId)) this.userRoles.set(userId, new Set()); this.userRoles.get(userId).add('user'); }
    async updateLastLoginMethod(userId, method) { const u = this.users.get(userId); if (u) u.lastLoginMethod = method; }

    async createRole(role) { this.roles.set(role.name, role); }
    async getRole(roleName) { return this.roles.get(roleName) || null; }
    async updateRole(roleName, roleData) { this.roles.set(roleName, roleData); }
    async deleteRole(roleName) { this.roles.delete(roleName); }
    async getAllRoles() { return Array.from(this.roles.values()); }

    async assignRoleToUser(userId, roleName) { if (!this.userRoles.has(userId)) this.userRoles.set(userId, new Set()); this.userRoles.get(userId).add(roleName); }
    async removeRoleFromUser(userId, roleName) { if (this.userRoles.has(userId)) this.userRoles.get(userId).delete(roleName); }
    async removeRoleFromAllUsers(roleName) { for (const r of this.userRoles.values()) r.delete(roleName); }
    async getUserRoles(userId) { const r = this.userRoles.get(userId); return r ? Array.from(r) : []; }

    async createApiKey(userId, name, permissions, expiresAt) { const keyId = `ak_${Math.random().toString(36).substring(2, 15)}`; const keyValue = `live_${Math.random().toString(36).substring(2, 25)}`; this.apiKeys.set(keyValue, { keyId, userId, name, permissions, expiresAt, active: true }); return { keyId, keyValue }; }
    async getApiKey(keyValue) { const k = this.apiKeys.get(keyValue); return (k && k.active && k.expiresAt > new Date()) ? k : null; }
    async revokeApiKey(keyId) { for (const [v, k] of this.apiKeys.entries()) if (k.keyId === keyId) k.active = false; }
    async getUserApiKeys(userId) { const keys = []; for (const k of this.apiKeys.values()) if (k.userId === userId) keys.push({ keyId: k.keyId, name: k.name, expiresAt: k.expiresAt, active: k.active }); return keys; }

    async saveMagicLink(userId, token, expiresAt) { this.magicLinks.set(token, { userId, expiresAt }); }
    async getMagicLink(token) { const l = this.magicLinks.get(token); return (l && l.expiresAt > new Date()) ? l : null; }
    async deleteMagicLink(token) { this.magicLinks.delete(token); }

    async getRateLimitAttempts(key) { return this.rateLimits.get(key) || []; }
    async recordRateLimitAttempt(key, timestamp) { if (!this.rateLimits.has(key)) this.rateLimits.set(key, []); this.rateLimits.get(key).push({ timestamp }); }
    async clearRateLimitAttempts(key) { this.rateLimits.delete(key); }

    async saveWebAuthnChallenge(userId, challenge) { this.webauthnChallenges.set(userId, challenge); }
    async getWebAuthnChallenge(userId) { return this.webauthnChallenges.get(userId) || null; }
    async clearWebAuthnChallenge(userId) { this.webauthnChallenges.delete(userId); }

    async saveWebAuthnCredential(userId, registrationInfo) { if (!this.webauthnCredentials.has(userId)) this.webauthnCredentials.set(userId, []); const credId = Buffer.from(registrationInfo.credentialID).toString('base64url'); const publicKey = Buffer.from(registrationInfo.credentialPublicKey); this.webauthnCredentials.get(userId).push({ id: credId, publicKey, counter: registrationInfo.counter, transports: registrationInfo.transports || [] }); }
    async getWebAuthnCredentials(userId) { return (this.webauthnCredentials.get(userId) || []).map(c => ({ id: c.id, type: 'public-key', transports: c.transports })); }
    async getWebAuthnCredentialById(credentialId) { for (const c of this.webauthnCredentials.values()) { const f = c.find(x => x.id === credentialId); if (f) return f; } return null; }
    async updateWebAuthnCredentialCounter(credentialId, counter) { for (const c of this.webauthnCredentials.values()) { const f = c.find(x => x.id === credentialId); if (f) f.counter = counter; } }

    async saveEmailVerification(userId, email, token, expiresAt) { this.emailVerifications.set(token, { userId, email, expiresAt }); }
    async getEmailVerification(token) { return this.emailVerifications.get(token) || null; }
    async deleteEmailVerification(token) { this.emailVerifications.delete(token); }
    async markEmailAsVerified(userId) { const u = this.users.get(userId); if (u) u.emailVerified = true; }

    async savePasswordReset(userId, email, token, expiresAt) { this.passwordResets.set(token, { userId, email, expiresAt }); }
    async getPasswordReset(token) { return this.passwordResets.get(token) || null; }
    async deletePasswordReset(token) { this.passwordResets.delete(token); }
    async updateUserPassword(userId, hashedPassword) { const u = this.users.get(userId); if (u) u.password = hashedPassword; }

    async generateOneTimeToken(userId, purpose, expiresAt) { const token = crypto.randomBytes(32).toString('hex'); this.oneTimeTokens.set(token, { userId, purpose, expiresAt }); return token; }
    async verifyOneTimeToken(token, purpose) { const data = this.oneTimeTokens.get(token); if (!data || data.purpose !== purpose || data.expiresAt < new Date()) return null; this.oneTimeTokens.delete(token); return data.userId; }
}

module.exports = MemoryAdapter;