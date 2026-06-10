const crypto = require('crypto');

class PasswordResetManager {
    constructor(adapter, config) {
        this.adapter = adapter;
        this.config = config || {};
    }

    async generateResetToken(email) {
        const user = await this.adapter.getUserByEmail(email);
        if (!user) {
            if (this.config.onExistingUserSignUp) {
                await this.config.onExistingUserSignUp({ user: { email } });
            }
            return null;
        }
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
        await this.adapter.savePasswordReset(user.userId || user.id, email, token, expiresAt);
        return token;
    }

    async sendResetPasswordEmail(email, callbackURL = '/reset-password') {
        const token = await this.generateResetToken(email);
        if (!token) return null;
        const url = `${this.config.frontendUrl || ''}${callbackURL}?token=${token}`;
        const user = await this.adapter.getUserByEmail(email);
        if (this.config.sendResetPassword) {
            await this.config.sendResetPassword({ user, url, token });
        }
        return url;
    }

    async resetPassword(token, newPassword) {
        const reset = await this.adapter.getPasswordReset(token);
        if (!reset) throw new Error('Invalid or expired reset token');
        if (new Date() > reset.expiresAt) {
            await this.adapter.deletePasswordReset(token);
            throw new Error('Reset token has expired');
        }
        const CryptoManager = require('./CryptoManager');
        const cryptoManager = new CryptoManager(this.config);
        const hashedPassword = await cryptoManager.hash(newPassword);
        await this.adapter.updateUserPassword(reset.userId, hashedPassword);
        await this.adapter.deletePasswordReset(token);
        await this.adapter.revokeAllSessions(reset.userId);
        return reset.userId;
    }
}

module.exports = PasswordResetManager;