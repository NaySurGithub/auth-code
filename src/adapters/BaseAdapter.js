class BaseAdapter {
    async saveSession(userId, jti, expiresAt, deviceInfo) { throw new Error('Method not implemented'); }
    async getSession(userId, jti) { throw new Error('Method not implemented'); }
    async revokeSession(userId, jti) { throw new Error('Method not implemented'); }
    async revokeAllSessions(userId) { throw new Error('Method not implemented'); }
    async getSessions(userId) { throw new Error('Method not implemented'); }
    async saveMFA(userId, secret, backupCodes, type = 'totp') { throw new Error('Method not implemented'); }
    async getMFA(userId, type = 'totp') { throw new Error('Method not implemented'); }
    async deleteMFA(userId, type = 'totp') { throw new Error('Method not implemented'); }
    async recordLoginAttempt(ip, success) { throw new Error('Method not implemented'); }
    async checkBruteForce(ip) { throw new Error('Method not implemented'); }
    async saveUser(userId, username, email, password, role) { throw new Error('Method not implemented'); }
    async getUserByEmail(email) { throw new Error('Method not implemented'); }
    async getUserById(userId) { throw new Error('Method not implemented'); }
    async getUserByProviderId(provider, providerId) { throw new Error('Method not implemented'); }
    async createUserFromOAuth(userId, provider, providerId, email, name) { throw new Error('Method not implemented'); }
    async updateLastLoginMethod(userId, method) { throw new Error('Method not implemented'); }
    async createRole(role) { throw new Error('Method not implemented'); }
    async getRole(roleName) { throw new Error('Method not implemented'); }
    async updateRole(roleName, roleData) { throw new Error('Method not implemented'); }
    async deleteRole(roleName) { throw new Error('Method not implemented'); }
    async getAllRoles() { throw new Error('Method not implemented'); }
    async assignRoleToUser(userId, roleName) { throw new Error('Method not implemented'); }
    async removeRoleFromUser(userId, roleName) { throw new Error('Method not implemented'); }
    async removeRoleFromAllUsers(roleName) { throw new Error('Method not implemented'); }
    async getUserRoles(userId) { throw new Error('Method not implemented'); }
    async createApiKey(userId, name, permissions, expiresAt) { throw new Error('Method not implemented'); }
    async getApiKey(keyValue) { throw new Error('Method not implemented'); }
    async revokeApiKey(keyId) { throw new Error('Method not implemented'); }
    async getUserApiKeys(userId) { throw new Error('Method not implemented'); }
    async saveMagicLink(userId, token, expiresAt) { throw new Error('Method not implemented'); }
    async getMagicLink(token) { throw new Error('Method not implemented'); }
    async deleteMagicLink(token) { throw new Error('Method not implemented'); }
    async getRateLimitAttempts(key) { throw new Error('Method not implemented'); }
    async recordRateLimitAttempt(key, timestamp) { throw new Error('Method not implemented'); }
    async clearRateLimitAttempts(key) { throw new Error('Method not implemented'); }
    async saveWebAuthnChallenge(userId, challenge) { throw new Error('Method not implemented'); }
    async getWebAuthnChallenge(userId) { throw new Error('Method not implemented'); }
    async clearWebAuthnChallenge(userId) { throw new Error('Method not implemented'); }
    async saveWebAuthnCredential(userId, registrationInfo) { throw new Error('Method not implemented'); }
    async getWebAuthnCredentials(userId) { throw new Error('Method not implemented'); }
    async getWebAuthnCredentialById(credentialId) { throw new Error('Method not implemented'); }
    async updateWebAuthnCredentialCounter(credentialId, counter) { throw new Error('Method not implemented'); }
    async saveEmailVerification(userId, email, token, expiresAt) { throw new Error('Method not implemented'); }
    async getEmailVerification(token) { throw new Error('Method not implemented'); }
    async deleteEmailVerification(token) { throw new Error('Method not implemented'); }
    async markEmailAsVerified(userId) { throw new Error('Method not implemented'); }
    async savePasswordReset(userId, email, token, expiresAt) { throw new Error('Method not implemented'); }
    async getPasswordReset(token) { throw new Error('Method not implemented'); }
    async deletePasswordReset(token) { throw new Error('Method not implemented'); }
    async updateUserPassword(userId, hashedPassword) { throw new Error('Method not implemented'); }
    async generateOneTimeToken(userId, purpose, expiresAt) { throw new Error('Method not implemented'); }
    async verifyOneTimeToken(token, purpose) { throw new Error('Method not implemented'); }
}

module.exports = BaseAdapter;