const BaseAdapter = require('./BaseAdapter');

class MongoAdapter extends BaseAdapter {
    constructor(mongoose, config) {
        super();
        this.Session = mongoose.model('AuthSession', new mongoose.Schema({ userId: String, jti: String, expiresAt: Date, deviceInfo: Object }));
        this.MFA = mongoose.model('AuthMFA', new mongoose.Schema({ userId: String, type: { type: String, default: 'totp' }, secret: String, backupCodes: [String] }));
        this.LoginAttempt = mongoose.model('AuthLoginAttempt', new mongoose.Schema({ ip: String, success: Boolean, timestamp: { type: Date, default: Date.now } }));
        this.User = mongoose.model('AuthUser', new mongoose.Schema({ userId: { type: String, unique: true }, username: String, email: { type: String, unique: true }, password: String, role: { type: String, default: 'user' }, provider: String, providerId: String, emailVerified: { type: Boolean, default: false }, lastLoginMethod: String }));
        this.Role = mongoose.model('AuthRole', new mongoose.Schema({ name: { type: String, unique: true }, permissions: [String], inherits: [String] }));
        this.UserRole = mongoose.model('AuthUserRole', new mongoose.Schema({ userId: String, roleName: String }));
        this.ApiKey = mongoose.model('AuthApiKey', new mongoose.Schema({ keyId: { type: String, unique: true }, keyValueHash: { type: String, unique: true }, userId: String, name: String, permissions: [String], expiresAt: Date, active: { type: Boolean, default: true } }));
        this.MagicLink = mongoose.model('AuthMagicLink', new mongoose.Schema({ userId: String, token: { type: String, unique: true }, expiresAt: Date }));
        this.RateLimit = mongoose.model('AuthRateLimit', new mongoose.Schema({ key: String, timestamp: Date }));
        this.WebAuthnChallenge = mongoose.model('AuthWebAuthnChallenge', new mongoose.Schema({ userId: { type: String, unique: true }, challenge: String }));
        this.WebAuthnCredential = mongoose.model('AuthWebAuthnCredential', new mongoose.Schema({ userId: String, credentialId: { type: String, unique: true }, publicKey: Buffer, counter: Number, transports: [String] }));
        this.EmailVerification = mongoose.model('AuthEmailVerification', new mongoose.Schema({ userId: String, email: String, token: { type: String, unique: true }, expiresAt: Date }));
        this.PasswordReset = mongoose.model('AuthPasswordReset', new mongoose.Schema({ userId: String, email: String, token: { type: String, unique: true }, expiresAt: Date }));
        this.OTT = mongoose.model('AuthOTT', new mongoose.Schema({ userId: String, purpose: String, token: { type: String, unique: true }, expiresAt: Date }));
    }

    async saveSession(userId, jti, expiresAt, deviceInfo) { await this.Session.create({ userId, jti, expiresAt, deviceInfo }); }
    async getSession(userId, jti) { return await this.Session.findOne({ userId, jti, expiresAt: { $gt: new Date() } }); }
    async revokeSession(userId, jti) { await this.Session.deleteOne({ userId, jti }); }
    async revokeAllSessions(userId) { await this.Session.deleteMany({ userId }); }
    async getSessions(userId) { return await this.Session.find({ userId, expiresAt: { $gt: new Date() } }, 'jti expiresAt deviceInfo'); }

    async saveMFA(userId, secret, backupCodes, type = 'totp') { await this.MFA.findOneAndUpdate({ userId, type }, { userId, type, secret, backupCodes }, { upsert: true }); }
    async getMFA(userId, type = 'totp') { return await this.MFA.findOne({ userId, type }); }
    async deleteMFA(userId, type = 'totp') { await this.MFA.deleteOne({ userId, type }); }

    async recordLoginAttempt(ip, success) { await this.LoginAttempt.create({ ip, success }); }
    async checkBruteForce(ip) { const c = await this.LoginAttempt.countDocuments({ ip, success: false, timestamp: { $gte: new Date(Date.now() - 300000) } }); return c >= 5; }

    async saveUser(userId, username, email, password, role) { await this.User.create({ userId, username, email, password, role }); }
    async getUserByEmail(email) { return await this.User.findOne({ email }); }
    async getUserById(userId) { return await this.User.findOne({ userId }); }
    async getUserByProviderId(provider, providerId) { return await this.User.findOne({ provider, providerId }); }
    async createUserFromOAuth(userId, provider, providerId, email, name) { await this.User.create({ userId, username: name, email, provider, providerId, role: 'user', emailVerified: true, lastLoginMethod: `oauth:${provider}` }); }
    async updateLastLoginMethod(userId, method) { await this.User.updateOne({ userId }, { lastLoginMethod: method }); }

    async createRole(role) { await this.Role.create(role); }
    async getRole(roleName) { return await this.Role.findOne({ name: roleName }); }
    async updateRole(roleName, roleData) { await this.Role.findOneAndUpdate({ name: roleName }, roleData); }
    async deleteRole(roleName) { await this.Role.deleteOne({ name: roleName }); }
    async getAllRoles() { return await this.Role.find(); }

    async assignRoleToUser(userId, roleName) { await this.UserRole.create({ userId, roleName }); }
    async removeRoleFromUser(userId, roleName) { await this.UserRole.deleteOne({ userId, roleName }); }
    async removeRoleFromAllUsers(roleName) { await this.UserRole.deleteMany({ roleName }); }
    async getUserRoles(userId) { return (await this.UserRole.find({ userId })).map(d => d.roleName); }

    async createApiKey(userId, name, permissions, expiresAt) { const crypto = require('crypto'); const keyId = `ak_${Math.random().toString(36).substring(2, 15)}`; const keyValue = `live_${Math.random().toString(36).substring(2, 25)}`; const hash = crypto.createHash('sha256').update(keyValue).digest('hex'); await this.ApiKey.create({ keyId, keyValueHash: hash, userId, name, permissions, expiresAt, active: true }); return { keyId, keyValue }; }
    async getApiKey(keyValue) { const crypto = require('crypto'); const hash = crypto.createHash('sha256').update(keyValue).digest('hex'); const k = await this.ApiKey.findOne({ keyValueHash: hash, active: true, expiresAt: { $gt: new Date() } }); return k ? { keyId: k.keyId, userId: k.userId, name: k.name, permissions: k.permissions, expiresAt: k.expiresAt, active: k.active } : null; }
    async revokeApiKey(keyId) { await this.ApiKey.updateOne({ keyId }, { active: false }); }
    async getUserApiKeys(userId) { return (await this.ApiKey.find({ userId })).map(k => ({ keyId: k.keyId, name: k.name, expiresAt: k.expiresAt, active: k.active })); }

    async saveMagicLink(userId, token, expiresAt) { await this.MagicLink.create({ userId, token, expiresAt }); }
    async getMagicLink(token) { return await this.MagicLink.findOne({ token, expiresAt: { $gt: new Date() } }); }
    async deleteMagicLink(token) { await this.MagicLink.deleteOne({ token }); }

    async getRateLimitAttempts(key) { return await this.RateLimit.find({ key, timestamp: { $gte: new Date(Date.now() - 300000) } }); }
    async recordRateLimitAttempt(key, timestamp) { await this.RateLimit.create({ key, timestamp: new Date(timestamp) }); }
    async clearRateLimitAttempts(key) { await this.RateLimit.deleteMany({ key }); }

    async saveWebAuthnChallenge(userId, challenge) { await this.WebAuthnChallenge.findOneAndUpdate({ userId }, { userId, challenge }, { upsert: true }); }
    async getWebAuthnChallenge(userId) { const d = await this.WebAuthnChallenge.findOne({ userId }); return d ? d.challenge : null; }
    async clearWebAuthnChallenge(userId) { await this.WebAuthnChallenge.deleteOne({ userId }); }

    async saveWebAuthnCredential(userId, registrationInfo) { const credId = Buffer.from(registrationInfo.credentialID).toString('base64url'); const publicKey = Buffer.from(registrationInfo.credentialPublicKey); await this.WebAuthnCredential.create({ userId, credentialId: credId, publicKey, counter: registrationInfo.counter, transports: registrationInfo.transports || [] }); }
    async getWebAuthnCredentials(userId) { return (await this.WebAuthnCredential.find({ userId })).map(d => ({ id: d.credentialId, type: 'public-key', transports: d.transports })); }
    async getWebAuthnCredentialById(credentialId) { return await this.WebAuthnCredential.findOne({ credentialId }); }
    async updateWebAuthnCredentialCounter(credentialId, counter) { await this.WebAuthnCredential.updateOne({ credentialId }, { counter }); }

    async saveEmailVerification(userId, email, token, expiresAt) { await this.EmailVerification.create({ userId, email, token, expiresAt }); }
    async getEmailVerification(token) { return await this.EmailVerification.findOne({ token }); }
    async deleteEmailVerification(token) { await this.EmailVerification.deleteOne({ token }); }
    async markEmailAsVerified(userId) { await this.User.updateOne({ userId }, { emailVerified: true }); }

    async savePasswordReset(userId, email, token, expiresAt) { await this.PasswordReset.create({ userId, email, token, expiresAt }); }
    async getPasswordReset(token) { return await this.PasswordReset.findOne({ token }); }
    async deletePasswordReset(token) { await this.PasswordReset.deleteOne({ token }); }
    async updateUserPassword(userId, hashedPassword) { await this.User.updateOne({ userId }, { password: hashedPassword }); }

    async generateOneTimeToken(userId, purpose, expiresAt) { const crypto = require('crypto'); const token = crypto.randomBytes(32).toString('hex'); await this.OTT.create({ userId, purpose, token, expiresAt }); return token; }
    async verifyOneTimeToken(token, purpose) { const d = await this.OTT.findOne({ token, purpose, expiresAt: { $gt: new Date() } }); if (!d) return null; await this.OTT.deleteOne({ token }); return d.userId; }
}

module.exports = MongoAdapter;