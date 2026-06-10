const BaseAdapter = require('./BaseAdapter');
const crypto = require('crypto');

class MySQLAdapter extends BaseAdapter {
    constructor(pool, config) {
        super();
        this.pool = pool;
        this.initialized = false;
    }

    async initializeDatabase() {
        if (this.initialized) return;
        const tables = [
            `CREATE TABLE IF NOT EXISTS auth_users (user_id VARCHAR(36) PRIMARY KEY, username VARCHAR(255), email VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255), role VARCHAR(50) DEFAULT 'user', provider VARCHAR(50), provider_id VARCHAR(255), email_verified TINYINT DEFAULT 0, last_login_method VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX idx_email (email), INDEX idx_provider (provider, provider_id))`,
            `CREATE TABLE IF NOT EXISTS auth_sessions (user_id VARCHAR(36) NOT NULL, jti VARCHAR(255) NOT NULL, expires_at DATETIME NOT NULL, device_info JSON, PRIMARY KEY (user_id, jti), INDEX idx_expires (expires_at), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_mfa (user_id VARCHAR(36) NOT NULL, type VARCHAR(20) DEFAULT 'totp', secret VARCHAR(255) NOT NULL, backup_codes TEXT, PRIMARY KEY (user_id, type), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_login_attempts (id INT AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(45) NOT NULL, success TINYINT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, INDEX idx_ip_time (ip, timestamp))`,
            `CREATE TABLE IF NOT EXISTS auth_roles (name VARCHAR(50) PRIMARY KEY, permissions TEXT, inherits TEXT)`,
            `CREATE TABLE IF NOT EXISTS auth_user_roles (user_id VARCHAR(36) NOT NULL, role_name VARCHAR(50) NOT NULL, PRIMARY KEY (user_id, role_name), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE, FOREIGN KEY (role_name) REFERENCES auth_roles(name) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_api_keys (key_id VARCHAR(50) PRIMARY KEY, key_value_hash VARCHAR(255) UNIQUE NOT NULL, user_id VARCHAR(36) NOT NULL, name VARCHAR(255), permissions TEXT, expires_at DATETIME NOT NULL, active TINYINT DEFAULT 1, INDEX idx_user (user_id), INDEX idx_hash (key_value_hash), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_magic_links (token VARCHAR(255) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, expires_at DATETIME NOT NULL, INDEX idx_expires (expires_at), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_rate_limits (id INT AUTO_INCREMENT PRIMARY KEY, \`key\` VARCHAR(255) NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, INDEX idx_key_time (\`key\`, timestamp))`,
            `CREATE TABLE IF NOT EXISTS auth_webauthn_challenges (user_id VARCHAR(36) PRIMARY KEY, challenge TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_webauthn_credentials (credential_id VARCHAR(255) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, public_key BLOB NOT NULL, counter INT DEFAULT 0, transports TEXT, INDEX idx_user (user_id), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_email_verifications (token VARCHAR(255) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, email VARCHAR(255) NOT NULL, expires_at DATETIME NOT NULL, INDEX idx_expires (expires_at), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_password_resets (token VARCHAR(255) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, email VARCHAR(255) NOT NULL, expires_at DATETIME NOT NULL, INDEX idx_expires (expires_at), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`,
            `CREATE TABLE IF NOT EXISTS auth_ott (token VARCHAR(255) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, purpose VARCHAR(50) NOT NULL, expires_at DATETIME NOT NULL, INDEX idx_expires (expires_at), FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE CASCADE)`
        ];
        for (const sql of tables) { await this.pool.execute(sql); }
        this.initialized = true;
    }

    async saveSession(userId, jti, expiresAt, deviceInfo) { await this.pool.execute('INSERT INTO auth_sessions (user_id, jti, expires_at, device_info) VALUES (?, ?, ?, ?)', [userId, jti, expiresAt, deviceInfo ? JSON.stringify(deviceInfo) : null]); }
    async getSession(userId, jti) { const [r] = await this.pool.execute('SELECT user_id, jti, device_info as deviceInfo FROM auth_sessions WHERE user_id = ? AND jti = ? AND expires_at > NOW()', [userId, jti]); return r[0] ? { ...r[0], deviceInfo: r[0].deviceInfo ? JSON.parse(r[0].deviceInfo) : null } : null; }
    async revokeSession(userId, jti) { await this.pool.execute('DELETE FROM auth_sessions WHERE user_id = ? AND jti = ?', [userId, jti]); }
    async revokeAllSessions(userId) { await this.pool.execute('DELETE FROM auth_sessions WHERE user_id = ?', [userId]); }
    async getSessions(userId) { const [r] = await this.pool.execute('SELECT jti, expires_at as expiresAt, device_info as deviceInfo FROM auth_sessions WHERE user_id = ? AND expires_at > NOW()', [userId]); return r.map(x => ({ ...x, deviceInfo: x.deviceInfo ? JSON.parse(x.deviceInfo) : null })); }

    async saveMFA(userId, secret, backupCodes, type = 'totp') { await this.pool.execute('INSERT INTO auth_mfa (user_id, type, secret, backup_codes) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE secret = ?, backup_codes = ?', [userId, type, secret, JSON.stringify(backupCodes), secret, JSON.stringify(backupCodes)]); }
    async getMFA(userId, type = 'totp') { const [r] = await this.pool.execute('SELECT secret, backup_codes FROM auth_mfa WHERE user_id = ? AND type = ?', [userId, type]); return r[0] ? { ...r[0], backupCodes: JSON.parse(r[0].backup_codes) } : null; }
    async deleteMFA(userId, type = 'totp') { await this.pool.execute('DELETE FROM auth_mfa WHERE user_id = ? AND type = ?', [userId, type]); }

    async recordLoginAttempt(ip, success) { await this.pool.execute('INSERT INTO auth_login_attempts (ip, success, timestamp) VALUES (?, ?, NOW())', [ip, success ? 1 : 0]); }
    async checkBruteForce(ip) { const [r] = await this.pool.execute('SELECT COUNT(*) as count FROM auth_login_attempts WHERE ip = ? AND success = 0 AND timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)', [ip]); return r[0].count >= 5; }

    async saveUser(userId, username, email, password, role) { await this.pool.execute('INSERT INTO auth_users (user_id, username, email, password, role, email_verified) VALUES (?, ?, ?, ?, ?, ?)', [userId, username, email, password, role, 0]); }
    async getUserByEmail(email) { const [r] = await this.pool.execute('SELECT *, email_verified as emailVerified FROM auth_users WHERE email = ?', [email]); return r[0] ? { ...r[0], emailVerified: r[0].emailVerified === 1 } : null; }
    async getUserById(userId) { const [r] = await this.pool.execute('SELECT *, email_verified as emailVerified FROM auth_users WHERE user_id = ?', [userId]); return r[0] ? { ...r[0], emailVerified: r[0].emailVerified === 1 } : null; }
    async getUserByProviderId(provider, providerId) { const [r] = await this.pool.execute('SELECT * FROM auth_users WHERE provider = ? AND provider_id = ?', [provider, providerId]); return r[0] || null; }
    async createUserFromOAuth(userId, provider, providerId, email, name) { await this.pool.execute('INSERT INTO auth_users (user_id, username, email, provider, provider_id, role, email_verified, last_login_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userId, name, email, provider, providerId, 'user', 1, `oauth:${provider}`]); }
    async updateLastLoginMethod(userId, method) { await this.pool.execute('UPDATE auth_users SET last_login_method = ? WHERE user_id = ?', [method, userId]); }

    async createRole(role) { await this.pool.execute('INSERT INTO auth_roles (name, permissions, inherits) VALUES (?, ?, ?)', [role.name, JSON.stringify(role.permissions), JSON.stringify(role.inherits)]); }
    async getRole(roleName) { const [r] = await this.pool.execute('SELECT * FROM auth_roles WHERE name = ?', [roleName]); return r[0] ? { ...r[0], permissions: JSON.parse(r[0].permissions), inherits: JSON.parse(r[0].inherits) } : null; }
    async updateRole(roleName, roleData) { await this.pool.execute('UPDATE auth_roles SET permissions = ?, inherits = ? WHERE name = ?', [JSON.stringify(roleData.permissions), JSON.stringify(roleData.inherits), roleName]); }
    async deleteRole(roleName) { await this.pool.execute('DELETE FROM auth_roles WHERE name = ?', [roleName]); }
    async getAllRoles() { const [r] = await this.pool.execute('SELECT * FROM auth_roles'); return r.map(x => ({ ...x, permissions: JSON.parse(x.permissions), inherits: JSON.parse(x.inherits) })); }

    async assignRoleToUser(userId, roleName) { await this.pool.execute('INSERT IGNORE INTO auth_user_roles (user_id, role_name) VALUES (?, ?)', [userId, roleName]); }
    async removeRoleFromUser(userId, roleName) { await this.pool.execute('DELETE FROM auth_user_roles WHERE user_id = ? AND role_name = ?', [userId, roleName]); }
    async removeRoleFromAllUsers(roleName) { await this.pool.execute('DELETE FROM auth_user_roles WHERE role_name = ?', [roleName]); }
    async getUserRoles(userId) { const [r] = await this.pool.execute('SELECT role_name FROM auth_user_roles WHERE user_id = ?', [userId]); return r.map(x => x.role_name); }

    async createApiKey(userId, name, permissions, expiresAt) { const keyId = `ak_${Math.random().toString(36).substring(2, 15)}`; const keyValue = `live_${Math.random().toString(36).substring(2, 25)}`; const hash = crypto.createHash('sha256').update(keyValue).digest('hex'); await this.pool.execute('INSERT INTO auth_api_keys (key_id, key_value_hash, user_id, name, permissions, expires_at, active) VALUES (?, ?, ?, ?, ?, ?, ?)', [keyId, hash, userId, name, JSON.stringify(permissions), expiresAt, 1]); return { keyId, keyValue }; }
    async getApiKey(keyValue) { const hash = crypto.createHash('sha256').update(keyValue).digest('hex'); const [r] = await this.pool.execute('SELECT key_id, user_id, name, permissions, expires_at, active FROM auth_api_keys WHERE key_value_hash = ? AND active = 1 AND expires_at > NOW()', [hash]); return r[0] ? { ...r[0], permissions: JSON.parse(r[0].permissions), active: r[0].active === 1 } : null; }
    async revokeApiKey(keyId) { await this.pool.execute('UPDATE auth_api_keys SET active = 0 WHERE key_id = ?', [keyId]); }
    async getUserApiKeys(userId) { const [r] = await this.pool.execute('SELECT key_id, name, expires_at, active FROM auth_api_keys WHERE user_id = ?', [userId]); return r.map(x => ({ keyId: x.key_id, name: x.name, expiresAt: x.expires_at, active: x.active === 1 })); }

    async saveMagicLink(userId, token, expiresAt) { await this.pool.execute('INSERT INTO auth_magic_links (token, user_id, expires_at) VALUES (?, ?, ?)', [token, userId, expiresAt]); }
    async getMagicLink(token) { const [r] = await this.pool.execute('SELECT user_id FROM auth_magic_links WHERE token = ? AND expires_at > NOW()', [token]); return r[0] || null; }
    async deleteMagicLink(token) { await this.pool.execute('DELETE FROM auth_magic_links WHERE token = ?', [token]); }

    async getRateLimitAttempts(key) { const [r] = await this.pool.execute('SELECT timestamp FROM auth_rate_limits WHERE `key` = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)', [key]); return r.map(x => ({ timestamp: x.timestamp.getTime() })); }
    async recordRateLimitAttempt(key, timestamp) { await this.pool.execute('INSERT INTO auth_rate_limits (`key`, timestamp) VALUES (?, FROM_UNIXTIME(?))', [key, Math.floor(timestamp / 1000)]); }
    async clearRateLimitAttempts(key) { await this.pool.execute('DELETE FROM auth_rate_limits WHERE `key` = ?', [key]); }

    async saveWebAuthnChallenge(userId, challenge) { await this.pool.execute('INSERT INTO auth_webauthn_challenges (user_id, challenge) VALUES (?, ?) ON DUPLICATE KEY UPDATE challenge = ?', [userId, challenge, challenge]); }
    async getWebAuthnChallenge(userId) { const [r] = await this.pool.execute('SELECT challenge FROM auth_webauthn_challenges WHERE user_id = ?', [userId]); return r[0] ? r[0].challenge : null; }
    async clearWebAuthnChallenge(userId) { await this.pool.execute('DELETE FROM auth_webauthn_challenges WHERE user_id = ?', [userId]); }

    async saveWebAuthnCredential(userId, registrationInfo) { const credId = Buffer.from(registrationInfo.credentialID).toString('base64url'); const publicKey = Buffer.from(registrationInfo.credentialPublicKey); await this.pool.execute('INSERT INTO auth_webauthn_credentials (user_id, credential_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)', [userId, credId, publicKey, registrationInfo.counter, JSON.stringify(registrationInfo.transports || [])]); }
    async getWebAuthnCredentials(userId) { const [r] = await this.pool.execute('SELECT credential_id, transports FROM auth_webauthn_credentials WHERE user_id = ?', [userId]); return r.map(x => ({ id: x.credential_id, type: 'public-key', transports: JSON.parse(x.transports) })); }
    async getWebAuthnCredentialById(credentialId) { const [r] = await this.pool.execute('SELECT credential_id, public_key, counter FROM auth_webauthn_credentials WHERE credential_id = ?', [credentialId]); return r[0] ? { id: r[0].credential_id, publicKey: r[0].public_key, counter: r[0].counter } : null; }
    async updateWebAuthnCredentialCounter(credentialId, counter) { await this.pool.execute('UPDATE auth_webauthn_credentials SET counter = ? WHERE credential_id = ?', [counter, credentialId]); }

    async saveEmailVerification(userId, email, token, expiresAt) { await this.pool.execute('INSERT INTO auth_email_verifications (user_id, email, token, expires_at) VALUES (?, ?, ?, ?)', [userId, email, token, expiresAt]); }
    async getEmailVerification(token) { const [r] = await this.pool.execute('SELECT user_id, email FROM auth_email_verifications WHERE token = ?', [token]); return r[0] || null; }
    async deleteEmailVerification(token) { await this.pool.execute('DELETE FROM auth_email_verifications WHERE token = ?', [token]); }
    async markEmailAsVerified(userId) { await this.pool.execute('UPDATE auth_users SET email_verified = 1 WHERE user_id = ?', [userId]); }

    async savePasswordReset(userId, email, token, expiresAt) { await this.pool.execute('INSERT INTO auth_password_resets (user_id, email, token, expires_at) VALUES (?, ?, ?, ?)', [userId, email, token, expiresAt]); }
    async getPasswordReset(token) { const [r] = await this.pool.execute('SELECT user_id, email FROM auth_password_resets WHERE token = ?', [token]); return r[0] || null; }
    async deletePasswordReset(token) { await this.pool.execute('DELETE FROM auth_password_resets WHERE token = ?', [token]); }
    async updateUserPassword(userId, hashedPassword) { await this.pool.execute('UPDATE auth_users SET password = ? WHERE user_id = ?', [hashedPassword, userId]); }

    async generateOneTimeToken(userId, purpose, expiresAt) { const token = crypto.randomBytes(32).toString('hex'); await this.pool.execute('INSERT INTO auth_ott (user_id, purpose, token, expires_at) VALUES (?, ?, ?, ?)', [userId, purpose, token, expiresAt]); return token; }
    async verifyOneTimeToken(token, purpose) { const [r] = await this.pool.execute('SELECT user_id FROM auth_ott WHERE token = ? AND purpose = ? AND expires_at > NOW()', [token, purpose]); if (!r[0]) return null; await this.pool.execute('DELETE FROM auth_ott WHERE token = ?', [token]); return r[0].user_id; }
}

module.exports = MySQLAdapter;