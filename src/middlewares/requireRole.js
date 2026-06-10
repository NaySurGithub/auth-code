const requireRole = (allowedRoles) => (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
    if (roles.includes(req.user.role)) return next();
    res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
};

module.exports = requireRole;