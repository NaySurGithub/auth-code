const speakeasy = require('speakeasy');

const requireMFA = (authEngine) => async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const mfaData = await authEngine.adapter.getMFA(req.user.sub);
    if (!mfaData) return next();

    const mfaToken = req.headers['x-mfa-token'] || (req.body && req.body.mfaToken);
    if (!mfaToken) return res.status(401).json({ error: 'MFA token required' });

    const isValid = speakeasy.totp.verify({ secret: mfaData.secret, encoding: 'base32', token: mfaToken, window: 1 });
    const isBackup = mfaData.backupCodes && mfaData.backupCodes.includes(mfaToken);

    if (isValid || isBackup) {
        if (isBackup) {
            const newBackupCodes = mfaData.backupCodes.filter(code => code !== mfaToken);
            await authEngine.adapter.saveMFA(req.user.sub, mfaData.secret, newBackupCodes);
        }
        return next();
    }
    res.status(401).json({ error: 'Invalid MFA token' });
};

module.exports = requireMFA;