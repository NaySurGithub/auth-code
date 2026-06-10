const protect = (authEngine) => async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const refreshToken = req.cookies?.refreshToken;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const decoded = authEngine.jwt.verifyToken(token, 'access');
        if (decoded) {
            const session = await authEngine.adapter.getSession(decoded.sub, decoded.jti);
            if (session) {
                req.user = decoded;
                return next();
            }
        }
    }

    if (refreshToken) {
        const decoded = authEngine.jwt.verifyToken(refreshToken, 'refresh');
        if (decoded) {
            const session = await authEngine.adapter.getSession(decoded.sub, decoded.jti);
            if (session) {
                const tokens = authEngine.jwt.generateTokens({ sub: decoded.sub, role: decoded.role });
                res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
                req.user = { ...decoded, jti: tokens.jti };
                return next();
            }
        }
    }
    res.status(401).json({ error: 'Unauthorized' });
};

module.exports = protect;