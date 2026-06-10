const BaseAdapter = require('./BaseAdapter');

class MySQLAdapter extends BaseAdapter {
    constructor(pool, config) {
        super();
        this.pool = pool;
    }

    async saveSession(userId, jti, expiresAt) { await this.pool.execute('INSERT INTO auth_sessions (user_id, jti, expires_at) VALUES (?, ?, ?)', [userId, jti, expiresAt]); }
    async getSession(userId, jti) { const [rows] = await this.pool.execute('SELECT user_id, jti FROM auth_sessions WHERE user_id = ? AND jti = ? AND expires_at > NOW()', [userId, jti]); return rows[0] || null; }
    async revokeSession(userId, jti) { await this.pool.execute('DELETE FROM auth_sessions WHERE user_id = ? AND jti = ?', [userId, jti]); }
    async revokeAllSessions(userId) { await this.pool.execute('DELETE FROM auth_sessions WHERE user_id = ?', [userId]); }
    async saveMFA(userId, secret, backupCodes) { await this.pool.execute('INSERT INTO auth_mfa (user_id, secret, backup_codes) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE secret = ?, backup_codes = ?', [userId, secret, JSON.stringify(backupCodes), secret, JSON.stringify(backupCodes)]); }
    async getMFA(userId) { const [rows] = await this.pool.execute('SELECT secret, backup_codes FROM auth_mfa WHERE user_id = ?', [userId]); return rows[0] ? { ...rows[0], backupCodes: JSON.parse(rows[0].backup_codes) } : null; }
    async deleteMFA(userId) { await this.pool.execute('DELETE FROM auth_mfa WHERE user_id = ?', [userId]); }
    async recordLoginAttempt(ip, success) { await this.pool.execute('INSERT INTO auth_login_attempts (ip, success, timestamp) VALUES (?, ?, NOW())', [ip, success ? 1 : 0]); }
    async checkBruteForce(ip) { const [rows] = await this.pool.execute('SELECT COUNT(*) as count FROM auth_login_attempts WHERE ip = ? AND success = 0 AND timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)', [ip]); return rows[0].count >= 5; }
    async saveUser(userId, username, email, password, role) { await this.pool.execute('INSERT INTO auth_users (user_id, username, email, password, role) VALUES (?, ?, ?, ?, ?)', [userId, username, email, password, role]); }
    async getUserByEmail(email) { const [rows] = await this.pool.execute('SELECT * FROM auth_users WHERE email = ?', [email]); return rows[0] || null; }
    async getUserById(userId) { const [rows] = await this.pool.execute('SELECT * FROM auth_users WHERE user_id = ?', [userId]); return rows[0] || null; }
    async getUserByProviderId(provider, providerId) { const [rows] = await this.pool.execute('SELECT * FROM auth_users WHERE provider = ? AND provider_id = ?', [provider, providerId]); return rows[0] || null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { await this.pool.execute('INSERT INTO auth_users (user_id, username, email, provider, provider_id, role) VALUES (?, ?, ?, ?, ?, ?)', [userId, name, email, provider, providerId, 'user']); }
}

module.exports = MySQLAdapter;