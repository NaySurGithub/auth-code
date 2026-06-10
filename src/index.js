const AuthEngine = require('./AuthEngine');
const protect = require('./middlewares/protect');
const requireRole = require('./middlewares/requireRole');
const requireMFA = require('./middlewares/requireMFA');
const requirePermission = require('./middlewares/requirePermission');
const requireAnyPermission = require('./middlewares/requireAnyPermission');
const requireAllPermissions = require('./middlewares/requireAllPermissions');
const requireApiKey = require('./middlewares/requireApiKey');

module.exports = {
    AuthEngine,
    protect,
    requireRole,
    requireMFA,
    requirePermission,
    requireAnyPermission,
    requireAllPermissions,
    requireApiKey
};