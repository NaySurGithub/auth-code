const requireApiKey = (authEngine) => async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }

    const keyData = await authEngine.adapter.getApiKey(apiKey);
    if (!keyData) {
        return res.status(401).json({ error: 'Invalid or expired API key' });
    }

    req.apiKey = keyData;
    req.user = { sub: keyData.userId, role: 'api_key', permissions: keyData.permissions };
    next();
};

module.exports = requireApiKey;