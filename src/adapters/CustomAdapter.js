const BaseAdapter = require('./BaseAdapter');

class CustomAdapter extends BaseAdapter {
    constructor(handlers) {
        super();
        this.handlers = handlers;
    }
    async saveSession(userId, jti, expiresAt) { if (this.handlers.saveSession) await this.handlers.saveSession(userId, jti, expiresAt); }
    async getSession(userId, jti) { if (this.handlers.getSession) return await this.handlers.getSession(userId, jti); return null; }
    async revokeSession(userId, jti) { if (this.handlers.revokeSession) await this.handlers.revokeSession(userId, jti); }
    async revokeAllSessions(userId) { if (this.handlers.revokeAllSessions) await this.handlers.revokeAllSessions(userId); }
    async saveMFA(userId, secret, backupCodes) { if (this.handlers.saveMFA) await this.handlers.saveMFA(userId, secret, backupCodes); }
    async getMFA(userId) { if (this.handlers.getMFA) return await this.handlers.getMFA(userId); return null; }
    async deleteMFA(userId) { if (this.handlers.deleteMFA) await this.handlers.deleteMFA(userId); }
    async recordLoginAttempt(ip, success) { if (this.handlers.recordLoginAttempt) await this.handlers.recordLoginAttempt(ip, success); }
    async checkBruteForce(ip) { if (this.handlers.checkBruteForce) return await this.handlers.checkBruteForce(ip); return false; }
    async saveUser(userId, username, email, password, role) { if (this.handlers.saveUser) await this.handlers.saveUser(userId, username, email, password, role); }
    async getUserByEmail(email) { if (this.handlers.getUserByEmail) return await this.handlers.getUserByEmail(email); return null; }
    async getUserById(userId) { if (this.handlers.getUserById) return await this.handlers.getUserById(userId); return null; }
    async getUserByProviderId(provider, providerId) { if (this.handlers.getUserByProviderId) return await this.handlers.getUserByProviderId(provider, providerId); return null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { if (this.handlers.createUserFromOAuth) await this.handlers.createUserFromOAuth(userId, provider, providerId, email, name); }
}

module.exports = CustomAdapter;