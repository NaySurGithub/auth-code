const requireAnyPermission = (authEngine, permissions) => async (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const hasPermission = await authEngine.roleManager.hasAnyPermission(req.user.sub, permissions);
    if (!hasPermission) {
        return res.status(403).json({ error: `Missing one of permissions: ${permissions.join(', ')}` });
    }

    next();
};

module.exports = requireAnyPermission;