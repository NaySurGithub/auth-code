const JWTManager = require('./core/JWTManager');
const CryptoManager = require('./core/CryptoManager');
const RoleManager = require('./core/RoleManager');
const RateLimitManager = require('./core/RateLimitManager');
const WebAuthnManager = require('./core/WebAuthnManager');
const EmailManager = require('./core/EmailManager');
const MongoAdapter = require('./adapters/MongoAdapter');
const RedisAdapter = require('./adapters/RedisAdapter');
const MySQLAdapter = require('./adapters/MySQLAdapter');
const CustomAdapter = require('./adapters/CustomAdapter');
const MemoryAdapter = require('./adapters/MemoryAdapter');
const OAuthManager = require('./providers/OAuthManager');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class AuthEngine {
    constructor(config) {
        this.jwt = new JWTManager(config);
        this.crypto = new CryptoManager(config);
        this.oauth = new OAuthManager(config);
        
        if (config.adapter === 'memory') {
            this.adapter = new MemoryAdapter();
        } else if (config.adapter === 'mongo') {
            this.adapter = new MongoAdapter(config.mongoose, config);
        } else if (config.adapter === 'redis' || config.adapter === 'upstash') {
            this.adapter = new RedisAdapter(config.redisClient, config);
        } else if (config.adapter === 'mysql') {
            this.adapter = new MySQLAdapter(config.mysqlPool, config);
        } else if (config.adapter === 'custom') {
            this.adapter = new CustomAdapter(config.customHandlers);
        } else {
            throw new Error('Invalid adapter specified');
        }

        this.roleManager = new RoleManager(this.adapter);
        this.roleManager.initialize();

        this.rateLimit = new RateLimitManager(this.adapter, config.rateLimit);
        
        if (config.webauthn) {
            this.webauthn = new WebAuthnManager(config.webauthn, this.adapter);
        }

        if (config.email) {
            this.email = new EmailManager(config.email);
        }

        this.config = config;
    }

    initialize() { return (req, res, next) => next(); }

    register() {
        return async (req, res, next) => {
            try {
                const { username, email, password, role } = req.body;
                if (!username || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
                const isBruteForced = await this.adapter.checkBruteForce(req.ip);
                if (isBruteForced) return res.status(429).json({ error: 'Too many attempts' });
                const hashedPassword = await this.crypto.hash(password);
                const userId = uuidv4();
                await this.adapter.saveUser(userId, username, email, hashedPassword, role || 'user');
                await this.adapter.recordLoginAttempt(req.ip, true);
                res.status(201).json({ message: 'User registered successfully', userId });
            } catch (error) {
                await this.adapter.recordLoginAttempt(req.ip, false);
                res.status(500).json({ error: 'Registration failed' });
            }
        };
    }

    login() {
        return async (req, res, next) => {
            try {
                const { email, password } = req.body;
                const isBruteForced = await this.adapter.checkBruteForce(req.ip);
                if (isBruteForced) return res.status(429).json({ error: 'Too many attempts' });
                const user = await this.adapter.getUserByEmail(email);
                if (!user || !(await this.crypto.verify(password, user.password))) {
                    await this.adapter.recordLoginAttempt(req.ip, false);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                const mfaData = await this.adapter.getMFA(user.userId || user.id);
                const userId = user.userId || user.id;
                const tokens = this.jwt.generateTokens({ sub: userId, role: user.role, mfaEnabled: !!mfaData });
                const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
                await this.adapter.saveSession(userId, tokens.jti, expiresAt);
                res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
                await this.adapter.recordLoginAttempt(req.ip, true);
                res.json({ accessToken: tokens.accessToken, requiresMFA: !!mfaData });
            } catch (error) {
                await this.adapter.recordLoginAttempt(req.ip, false);
                res.status(500).json({ error: 'Login failed' });
            }
        };
    }

    logout() {
        return async (req, res, next) => {
            try {
                const refreshToken = req.cookies?.refreshToken;
                if (refreshToken) {
                    const decoded = this.jwt.verifyToken(refreshToken, 'refresh');
                    if (decoded) await this.adapter.revokeSession(decoded.sub, decoded.jti);
                }
                res.clearCookie('refreshToken');
                res.json({ message: 'Logged out successfully' });
            } catch (error) {
                res.status(500).json({ error: 'Logout failed' });
            }
        };
    }

    async generateMFASecret(userId) {
        const secret = speakeasy.generateSecret({ name: `AuthCode:${userId}` });
        const backupCodes = Array.from({ length: 8 }, () => Math.random().toString(36).substring(2, 8).toUpperCase());
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
        await this.adapter.saveMFA(userId, secret.base32, backupCodes, 'totp');
        return { secret: secret.base32, qrCode, backupCodes };
    }

    async verifyAndEnableMFA(userId, token) {
        const mfaData = await this.adapter.getMFA(userId, 'totp');
        if (!mfaData) throw new Error('MFA not initialized');
        const isValid = speakeasy.totp.verify({ secret: mfaData.secret, encoding: 'base32', token, window: 1 });
        if (!isValid) throw new Error('Invalid token');
        return true;
    }

    async disableMFA(userId, token) {
        const mfaData = await this.adapter.getMFA(userId, 'totp');
        if (!mfaData) return true;
        const isValid = speakeasy.totp.verify({ secret: mfaData.secret, encoding: 'base32', token, window: 1 }) || (mfaData.backupCodes && mfaData.backupCodes.includes(token));
        if (isValid) {
            await this.adapter.deleteMFA(userId, 'totp');
            return true;
        }
        throw new Error('Invalid token');
    }

    async sendEmailMFACode(userId) {
        const user = await this.adapter.getUserById(userId);
        if (!user) throw new Error('User not found');
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        await this.adapter.saveMFA(userId, code, [], 'email');
        if (this.email) {
            await this.email.send({
                to: user.email,
                subject: 'Your MFA Code',
                html: `<p>Your authentication code is: <strong>${code}</strong></p>`
            });
        }
        return true;
    }

    async verifyEmailMFACode(userId, code) {
        const mfaData = await this.adapter.getMFA(userId, 'email');
        if (!mfaData) throw new Error('Email MFA not initialized');
        if (mfaData.secret === code) {
            await this.adapter.deleteMFA(userId, 'email');
            return true;
        }
        throw new Error('Invalid code');
    }

    async sendMagicLink(email) {
        const user = await this.adapter.getUserByEmail(email);
        if (!user) throw new Error('User not found');
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
        await this.adapter.saveMagicLink(user.userId || user.id, token, expiresAt);
        if (this.email) {
            const link = `${this.config.frontendUrl}/auth/verify-magic?token=${token}`;
            await this.email.send({
                to: email,
                subject: 'Your Magic Login Link',
                html: `<p>Click here to login: <a href="${link}">${link}</a></p>`
            });
        }
        return true;
    }

    async verifyMagicLink(token) {
        const link = await this.adapter.getMagicLink(token);
        if (!link) throw new Error('Invalid or expired magic link');
        const user = await this.adapter.getUserById(link.userId);
        await this.adapter.deleteMagicLink(token);
        const tokens = this.jwt.generateTokens({ sub: user.userId || user.id, role: user.role });
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await this.adapter.saveSession(user.userId || user.id, tokens.jti, expiresAt);
        return tokens;
    }

    async createApiKey(userId, name, permissions, daysValid = 30) {
        const expiresAt = new Date(Date.now() + daysValid * 24 * 60 * 60 * 1000);
        return await this.adapter.createApiKey(userId, name, permissions, expiresAt);
    }

    async revokeApiKey(keyId) {
        await this.adapter.revokeApiKey(keyId);
    }

    async getUserApiKeys(userId) {
        return await this.adapter.getUserApiKeys(userId);
    }

    async generateWebAuthnRegistrationOptions(userId) {
        const user = await this.adapter.getUserById(userId);
        return await this.webauthn.generateRegistrationOptions(userId, user.email);
    }

    async verifyWebAuthnRegistration(userId, response) {
        return await this.webauthn.verifyRegistrationResponse(userId, response);
    }

    async generateWebAuthnAuthenticationOptions(userId) {
        return await this.webauthn.generateAuthenticationOptions(userId);
    }

    async verifyWebAuthnAuthentication(userId, response) {
        return await this.webauthn.verifyAuthenticationResponse(userId, response);
    }

    async revokeAllSessions(userId) {
        await this.adapter.revokeAllSessions(userId);
    }

    getOAuthUrl(provider, redirectUri) {
        const state = uuidv4();
        return { url: this.oauth.getAuthUrl(provider, redirectUri, state), state };
    }

    handleOAuthCallback(provider) {
        return async (req, res, next) => {
            try {
                const { code, state } = req.query;
                const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback/${provider}`;
                const userInfo = await this.oauth.exchangeCode(provider, code, redirectUri);
                let user = await this.adapter.getUserByProviderId(provider, userInfo.id);
                if (!user) {
                    const userId = uuidv4();
                    await this.adapter.createUserFromOAuth(userId, provider, userInfo.id, userInfo.email, userInfo.name || userInfo.login);
                    user = await this.adapter.getUserById(userId);
                }
                const userId = user.userId || user.id;
                const tokens = this.jwt.generateTokens({ sub: userId, role: user.role });
                const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
                await this.adapter.saveSession(userId, tokens.jti, expiresAt);
                res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
                res.redirect(`${this.config.frontendUrl}?token=${tokens.accessToken}`);
            } catch (error) {
                res.redirect(`${this.config.frontendUrl}?error=oauth_failed`);
            }
        };
    }

    async createRole(roleData) { return await this.roleManager.createRole(roleData); }
    async updateRole(roleName, updates) { return await this.roleManager.updateRole(roleName, updates); }
    async deleteRole(roleName) { return await this.roleManager.deleteRole(roleName); }
    async getAllRoles() { return await this.roleManager.getAllRoles(); }
    async assignRole(userId, roleName) { return await this.roleManager.assignRole(userId, roleName); }
    async removeRole(userId, roleName) { return await this.roleManager.removeRole(userId, roleName); }
    async getUserRoles(userId) { return await this.roleManager.getUserRoles(userId); }
    async getUserPermissions(userId) { return await this.roleManager.getUserPermissions(userId); }
    async hasPermission(userId, permission) { return await this.roleManager.hasPermission(userId, permission); }
}

module.exports = AuthEngine;