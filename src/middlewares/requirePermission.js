const requirePermission = (authEngine, permission) => async (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const hasPermission = await authEngine.roleManager.hasPermission(req.user.sub, permission);
    if (!hasPermission) {
        return res.status(403).json({ error: `Missing permission: ${permission}` });
    }

    next();
};

module.exports = requirePermission;