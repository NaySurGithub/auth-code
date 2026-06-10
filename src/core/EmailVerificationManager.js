const crypto = require('crypto');

class EmailVerificationManager {
    constructor(adapter, config) {
        this.adapter = adapter;
        this.config = config || {};
    }

    async generateVerificationToken(userId, email) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        await this.adapter.saveEmailVerification(userId, email, token, expiresAt);
        
        return token;
    }

    async verifyEmail(token) {
        const verification = await this.adapter.getEmailVerification(token);
        
        if (!verification) {
            throw new Error('Invalid or expired verification token');
        }

        if (new Date() > verification.expiresAt) {
            await this.adapter.deleteEmailVerification(token);
            throw new Error('Verification token has expired');
        }

        if (this.config.beforeEmailVerification) {
            const user = await this.adapter.getUserById(verification.userId);
            await this.config.beforeEmailVerification(user);
        }

        await this.adapter.markEmailAsVerified(verification.userId);
        await this.adapter.deleteEmailVerification(token);

        if (this.config.afterEmailVerification) {
            const user = await this.adapter.getUserById(verification.userId);
            await this.config.afterEmailVerification(user);
        }

        return verification.userId;
    }

    async isEmailVerified(userId) {
        const user = await this.adapter.getUserById(userId);
        return user && user.emailVerified === true;
    }

    async sendVerificationEmail(userId, email, callbackURL = '/') {
        const token = await this.generateVerificationToken(userId, email);
        const url = `${this.config.frontendUrl || ''}/auth/verify-email?token=${token}&callbackURL=${encodeURIComponent(callbackURL)}`;

        if (this.config.sendVerificationEmail) {
            const user = await this.adapter.getUserById(userId);
            await this.config.sendVerificationEmail({ user, url, token });
        }

        return url;
    }
}

module.exports = EmailVerificationManager;