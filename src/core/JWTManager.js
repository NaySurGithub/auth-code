const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

class JWTManager {
    constructor(config) {
        this.secret = config.secret;
        this.accessTokenExpiry = config.accessTokenExpiry || '15m';
        this.refreshTokenExpiry = config.refreshTokenExpiry || '7d';
        this.issuer = config.issuer || 'auth-code';
    }

    generateTokens(payload) {
        const jti = uuidv4();
        const accessToken = jwt.sign(
            { ...payload, jti, type: 'access' },
            this.secret,
            { expiresIn: this.accessTokenExpiry, issuer: this.issuer }
        );
        const refreshToken = jwt.sign(
            { ...payload, jti, type: 'refresh' },
            this.secret,
            { expiresIn: this.refreshTokenExpiry, issuer: this.issuer }
        );
        return { accessToken, refreshToken, jti };
    }

    verifyToken(token, type = 'access') {
        try {
            const decoded = jwt.verify(token, this.secret, { issuer: this.issuer });
            if (decoded.type !== type) {
                throw new Error('Invalid token type');
            }
            return decoded;
        } catch (error) {
            return null;
        }
    }
}

module.exports = JWTManager;