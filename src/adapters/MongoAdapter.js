const BaseAdapter = require('./BaseAdapter');

class MongoAdapter extends BaseAdapter {
    constructor(mongoose, config) {
        super();
        this.Session = mongoose.model('AuthSession', new mongoose.Schema({
            userId: { type: String, required: true, index: true },
            jti: { type: String, required: true, index: true },
            expiresAt: { type: Date, required: true, index: true }
        }));
        this.MFA = mongoose.model('AuthMFA', new mongoose.Schema({
            userId: { type: String, required: true, unique: true },
            secret: { type: String, required: true },
            backupCodes: [{ type: String }]
        }));
        this.LoginAttempt = mongoose.model('AuthLoginAttempt', new mongoose.Schema({
            ip: { type: String, required: true, index: true },
            success: { type: Boolean, required: true },
            timestamp: { type: Date, default: Date.now, index: true }
        }));
        this.User = mongoose.model('AuthUser', new mongoose.Schema({
            userId: { type: String, required: true, unique: true },
            username: String,
            email: { type: String, unique: true },
            password: String,
            role: { type: String, default: 'user' },
            provider: String,
            providerId: String
        }));
    }

    async saveSession(userId, jti, expiresAt) { await this.Session.create({ userId, jti, expiresAt }); }
    async getSession(userId, jti) { return await this.Session.findOne({ userId, jti, expiresAt: { $gt: new Date() } }); }
    async revokeSession(userId, jti) { await this.Session.deleteOne({ userId, jti }); }
    async revokeAllSessions(userId) { await this.Session.deleteMany({ userId }); }
    async saveMFA(userId, secret, backupCodes) { await this.MFA.findOneAndUpdate({ userId }, { userId, secret, backupCodes }, { upsert: true, new: true }); }
    async getMFA(userId) { return await this.MFA.findOne({ userId }); }
    async deleteMFA(userId) { await this.MFA.deleteOne({ userId }); }
    async recordLoginAttempt(ip, success) { await this.LoginAttempt.create({ ip, success }); }
    async checkBruteForce(ip) {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const failedAttempts = await this.LoginAttempt.countDocuments({ ip, success: false, timestamp: { $gte: fiveMinutesAgo } });
        return failedAttempts >= 5;
    }
    async saveUser(userId, username, email, password, role) { await this.User.create({ userId, username, email, password, role }); }
    async getUserByEmail(email) { return await this.User.findOne({ email }); }
    async getUserById(userId) { return await this.User.findOne({ userId }); }
    async getUserByProviderId(provider, providerId) { return await this.User.findOne({ provider, providerId }); }
    async createUserFromOAuth(userId, provider, providerId, email, name) { await this.User.create({ userId, username: name, email, provider, providerId, role: 'user' }); }
}

module.exports = MongoAdapter;