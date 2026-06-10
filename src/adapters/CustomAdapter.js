const BaseAdapter = require('./BaseAdapter');

class CustomAdapter extends BaseAdapter {
    constructor(handlers) {
        super();
        this.h = handlers || {};
    }

    async saveSession(userId, jti, expiresAt, deviceInfo) { if (this.h.saveSession) await this.h.saveSession(userId, jti, expiresAt, deviceInfo); }
    async getSession(userId, jti) { return this.h.getSession ? await this.h.getSession(userId, jti) : null; }
    async revokeSession(userId, jti) { if (this.h.revokeSession) await this.h.revokeSession(userId, jti); }
    async revokeAllSessions(userId) { if (this.h.revokeAllSessions) await this.h.revokeAllSessions(userId); }
    async getSessions(userId) { return this.h.getSessions ? await this.h.getSessions(userId) : []; }
    async saveMFA(userId, secret, backupCodes, type = 'totp') { if (this.h.saveMFA) await this.h.saveMFA(userId, secret, backupCodes, type); }
    async getMFA(userId, type = 'totp') { return this.h.getMFA ? await this.h.getMFA(userId, type) : null; }
    async deleteMFA(userId, type = 'totp') { if (this.h.deleteMFA) await this.h.deleteMFA(userId, type); }
    async recordLoginAttempt(ip, success) { if (this.h.recordLoginAttempt) await this.h.recordLoginAttempt(ip, success); }
    async checkBruteForce(ip) { return this.h.checkBruteForce ? await this.h.checkBruteForce(ip) : false; }
    async saveUser(userId, username, email, password, role) { if (this.h.saveUser) await this.h.saveUser(userId, username, email, password, role); }
    async getUserByEmail(email) { return this.h.getUserByEmail ? await this.h.getUserByEmail(email) : null; }
    async getUserById(userId) { return this.h.getUserById ? await this.h.getUserById(userId) : null; }
    async getUserByProviderId(provider, providerId) { return this.h.getUserByProviderId ? await this.h.getUserByProviderId(provider, providerId) : null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { if (this.h.createUserFromOAuth) await this.h.createUserFromOAuth(userId, provider, providerId, email, name); }
    async updateLastLoginMethod(userId, method) { if (this.h.updateLastLoginMethod) await this.h.updateLastLoginMethod(userId, method); }
    async createRole(role) { if (this.h.createRole) await this.h.createRole(role); }
    async getRole(roleName) { return this.h.getRole ? await this.h.getRole(roleName) : null; }
    async updateRole(roleName, roleData) { if (this.h.updateRole) await this.h.updateRole(roleName, roleData); }
    async deleteRole(roleName) { if (this.h.deleteRole) await this.h.deleteRole(roleName); }
    async getAllRoles() { return this.h.getAllRoles ? await this.h.getAllRoles() : []; }
    async assignRoleToUser(userId, roleName) { if (this.h.assignRoleToUser) await this.h.assignRoleToUser(userId, roleName); }
    async removeRoleFromUser(userId, roleName) { if (this.h.removeRoleFromUser) await this.h.removeRoleFromUser(userId, roleName); }
    async removeRoleFromAllUsers(roleName) { if (this.h.removeRoleFromAllUsers) await this.h.removeRoleFromAllUsers(roleName); }
    async getUserRoles(userId) { return this.h.getUserRoles ? await this.h.getUserRoles(userId) : []; }
    async createApiKey(userId, name, permissions, expiresAt) { return this.h.createApiKey ? await this.h.createApiKey(userId, name, permissions, expiresAt) : { keyId: 'custom', keyValue: 'custom' }; }
    async getApiKey(keyValue) { return this.h.getApiKey ? await this.h.getApiKey(keyValue) : null; }
    async revokeApiKey(keyId) { if (this.h.revokeApiKey) await this.h.revokeApiKey(keyId); }
    async getUserApiKeys(userId) { return this.h.getUserApiKeys ? await this.h.getUserApiKeys(userId) : []; }
    async saveMagicLink(userId, token, expiresAt) { if (this.h.saveMagicLink) await this.h.saveMagicLink(userId, token, expiresAt); }
    async getMagicLink(token) { return this.h.getMagicLink ? await this.h.getMagicLink(token) : null; }
    async deleteMagicLink(token) { if (this.h.deleteMagicLink) await this.h.deleteMagicLink(token); }
    async getRateLimitAttempts(key) { return this.h.getRateLimitAttempts ? await this.h.getRateLimitAttempts(key) : []; }
    async recordRateLimitAttempt(key, timestamp) { if (this.h.recordRateLimitAttempt) await this.h.recordRateLimitAttempt(key, timestamp); }
    async clearRateLimitAttempts(key) { if (this.h.clearRateLimitAttempts) await this.h.clearRateLimitAttempts(key); }
    async saveWebAuthnChallenge(userId, challenge) { if (this.h.saveWebAuthnChallenge) await this.h.saveWebAuthnChallenge(userId, challenge); }
    async getWebAuthnChallenge(userId) { return this.h.getWebAuthnChallenge ? await this.h.getWebAuthnChallenge(userId) : null; }
    async clearWebAuthnChallenge(userId) { if (this.h.clearWebAuthnChallenge) await this.h.clearWebAuthnChallenge(userId); }
    async saveWebAuthnCredential(userId, registrationInfo) { if (this.h.saveWebAuthnCredential) await this.h.saveWebAuthnCredential(userId, registrationInfo); }
    async getWebAuthnCredentials(userId) { return this.h.getWebAuthnCredentials ? await this.h.getWebAuthnCredentials(userId) : []; }
    async getWebAuthnCredentialById(credentialId) { return this.h.getWebAuthnCredentialById ? await this.h.getWebAuthnCredentialById(credentialId) : null; }
    async updateWebAuthnCredentialCounter(credentialId, counter) { if (this.h.updateWebAuthnCredentialCounter) await this.h.updateWebAuthnCredentialCounter(credentialId, counter); }
    async saveEmailVerification(userId, email, token, expiresAt) { if (this.h.saveEmailVerification) await this.h.saveEmailVerification(userId, email, token, expiresAt); }
    async getEmailVerification(token) { return this.h.getEmailVerification ? await this.h.getEmailVerification(token) : null; }
    async deleteEmailVerification(token) { if (this.h.deleteEmailVerification) await this.h.deleteEmailVerification(token); }
    async markEmailAsVerified(userId) { if (this.h.markEmailAsVerified) await this.h.markEmailAsVerified(userId); }
    async savePasswordReset(userId, email, token, expiresAt) { if (this.h.savePasswordReset) await this.h.savePasswordReset(userId, email, token, expiresAt); }
    async getPasswordReset(token) { return this.h.getPasswordReset ? await this.h.getPasswordReset(token) : null; }
    async deletePasswordReset(token) { if (this.h.deletePasswordReset) await this.h.deletePasswordReset(token); }
    async updateUserPassword(userId, hashedPassword) { if (this.h.updateUserPassword) await this.h.updateUserPassword(userId, hashedPassword); }
    async generateOneTimeToken(userId, purpose, expiresAt) { return this.h.generateOneTimeToken ? await this.h.generateOneTimeToken(userId, purpose, expiresAt) : null; }
    async verifyOneTimeToken(token, purpose) { return this.h.verifyOneTimeToken ? await this.h.verifyOneTimeToken(token, purpose) : null; }
}

module.exports = CustomAdapter;