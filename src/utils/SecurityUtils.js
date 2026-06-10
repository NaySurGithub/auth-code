const crypto = require('crypto');

class SecurityUtils {
    static async checkHaveIBeenPwned(password) {
        const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!response.ok) return false;
        const text = await response.text();
        return text.split('\n').some(line => line.split(':')[0] === suffix);
    }

    static async verifyCaptcha(token, secretKey, provider = 'recaptcha') {
        if (provider === 'recaptcha') {
            const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;
            const res = await fetch(url, { method: 'POST' });
            const data = await res.json();
            return data.success;
        }
        if (provider === 'hcaptcha') {
            const url = 'https://hcaptcha.com/siteverify';
            const params = new URLSearchParams({ secret: secretKey, response: token });
            const res = await fetch(url, { method: 'POST', body: params });
            const data = await res.json();
            return data.success;
        }
        return true;
    }

    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return input.replace(/['";\\]/g, '').trim();
    }
}

module.exports = SecurityUtils;