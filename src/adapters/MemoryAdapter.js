const BaseAdapter = require('./BaseAdapter');

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
    }

    async saveSession(userId, jti, expiresAt) {
        this.sessions.set(`${userId}:${jti}`, { userId, jti, expiresAt });
    }

    async getSession(userId, jti) {
        const session = this.sessions.get(`${userId}:${jti}`);
        return (session && session.expiresAt > new Date()) ? session : null;
    }

    async revokeSession(userId, jti) {
        this.sessions.delete(`${userId}:${jti}`);
    }

    async revokeAllSessions(userId) {
        for (const [key, session] of this.sessions.entries()) {
            if (session.userId === userId) this.sessions.delete(key);
        }
    }

    async saveMFA(userId, secret, backupCodes, type = 'totp') {
        this.mfa.set(`${userId}:${type}`, { userId, secret, backupCodes, type });
    }

    async getMFA(userId, type = 'totp') {
        return this.mfa.get(`${userId}:${type}`) || null;
    }

    async deleteMFA(userId, type = 'totp') {
        this.mfa.delete(`${userId}:${type}`);
    }

    async recordLoginAttempt(ip, success) {
        if (!this.loginAttempts.has(ip)) this.loginAttempts.set(ip, []);
        this.loginAttempts.get(ip).push({ success, timestamp: Date.now() });
    }

    async checkBruteForce(ip) {
        const attempts = this.loginAttempts.get(ip) || [];
        const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
        return attempts.filter(a => !a.success && a.timestamp > fiveMinutesAgo).length >= 5;
    }

    async saveUser(userId, username, email, password, role) {
        this.users.set(userId, { userId, username, email, password, role });
        if (!this.userRoles.has(userId)) this.userRoles.set(userId, new Set());
        this.userRoles.get(userId).add(role || 'user');
    }

    async getUserByEmail(email) {
        for (const user of this.users.values()) {
            if (user.email === email) return user;
        }
        return null;
    }

    async getUserById(userId) {
        return this.users.get(userId) || null;
    }

    async getUserByProviderId(provider, providerId) {
        for (const user of this.users.values()) {
            if (user.provider === provider && user.providerId === providerId) return user;
        }
        return null;
    }

    async createUserFromOAuth(userId, provider, providerId, email, name) {
        this.users.set(userId, { userId, username: name, email, provider, providerId, role: 'user' });
        if (!this.userRoles.has(userId)) this.userRoles.set(userId, new Set());
        this.userRoles.get(userId).add('user');
    }

    async createRole(role) {
        this.roles.set(role.name, role);
    }

    async getRole(roleName) {
        return this.roles.get(roleName) || null;
    }

    async updateRole(roleName, roleData) {
        this.roles.set(roleName, roleData);
    }

    async deleteRole(roleName) {
        this.roles.delete(roleName);
    }

    async getAllRoles() {
        return Array.from(this.roles.values());
    }

    async assignRoleToUser(userId, roleName) {
        if (!this.userRoles.has(userId)) this.userRoles.set(userId, new Set());
        this.userRoles.get(userId).add(roleName);
    }

    async removeRoleFromUser(userId, roleName) {
        if (this.userRoles.has(userId)) this.userRoles.get(userId).delete(roleName);
    }

    async removeRoleFromAllUsers(roleName) {
        for (const roles of this.userRoles.values()) {
            roles.delete(roleName);
        }
    }

    async getUserRoles(userId) {
        const roles = this.userRoles.get(userId);
        return roles ? Array.from(roles) : [];
    }

    async createApiKey(userId, name, permissions, expiresAt) {
        const keyId = `ak_${Math.random().toString(36).substring(2, 15)}`;
        const keyValue = `live_${Math.random().toString(36).substring(2, 25)}`;
        this.apiKeys.set(keyValue, { keyId, userId, name, permissions, expiresAt, active: true });
        return { keyId, keyValue };
    }

    async getApiKey(keyValue) {
        const apiKey = this.apiKeys.get(keyValue);
        if (apiKey && apiKey.active && apiKey.expiresAt > new Date()) {
            return apiKey;
        }
        return null;
    }

    async revokeApiKey(keyId) {
        for (const [keyValue, apiKey] of this.apiKeys.entries()) {
            if (apiKey.keyId === keyId) {
                apiKey.active = false;
            }
        }
    }

    async getUserApiKeys(userId) {
        const keys = [];
        for (const apiKey of this.apiKeys.values()) {
            if (apiKey.userId === userId) {
                keys.push({ keyId: apiKey.keyId, name: apiKey.name, expiresAt: apiKey.expiresAt, active: apiKey.active });
            }
        }
        return keys;
    }

    async saveMagicLink(userId, token, expiresAt) {
        this.magicLinks.set(token, { userId, expiresAt });
    }

    async getMagicLink(token) {
        const link = this.magicLinks.get(token);
        if (link && link.expiresAt > new Date()) {
            return link;
        }
        return null;
    }

    async deleteMagicLink(token) {
        this.magicLinks.delete(token);
    }

    async getRateLimitAttempts(key) {
        return this.rateLimits.get(key) || [];
    }

    async recordRateLimitAttempt(key, timestamp) {
        if (!this.rateLimits.has(key)) this.rateLimits.set(key, []);
        this.rateLimits.get(key).push({ timestamp });
    }

    async clearRateLimitAttempts(key) {
        this.rateLimits.delete(key);
    }

    async saveWebAuthnChallenge(userId, challenge) {
        this.webauthnChallenges.set(userId, challenge);
    }

    async getWebAuthnChallenge(userId) {
        return this.webauthnChallenges.get(userId) || null;
    }

    async clearWebAuthnChallenge(userId) {
        this.webauthnChallenges.delete(userId);
    }

    async saveWebAuthnCredential(userId, credentialInfo) {
        if (!this.webauthnCredentials.has(userId)) this.webauthnCredentials.set(userId, []);
        this.webauthnCredentials.get(userId).push({
            id: credentialInfo.credential.id,
            publicKey: credentialInfo.credential.publicKey,
            counter: credentialInfo.credential.counter,
            transports: credentialInfo.credential.transports
        });
    }

    async getWebAuthnCredentials(userId) {
        return this.webauthnCredentials.get(userId) || [];
    }

    async getWebAuthnCredentialById(credentialId) {
        for (const creds of this.webauthnCredentials.values()) {
            const cred = creds.find(c => c.id === credentialId);
            if (cred) return cred;
        }
        return null;
    }

    async updateWebAuthnCredentialCounter(credentialId, counter) {
        for (const creds of this.webauthnCredentials.values()) {
            const cred = creds.find(c => c.id === credentialId);
            if (cred) cred.counter = counter;
        }
    }
}

module.exports = MemoryAdapter;