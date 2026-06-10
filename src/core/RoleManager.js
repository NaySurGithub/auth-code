class RoleManager {
    constructor(adapter) {
        this.adapter = adapter;
        this.defaultRoles = {
            user: {
                name: 'user',
                permissions: ['profile:read', 'profile:write'],
                inherits: []
            },
            admin: {
                name: 'admin',
                permissions: ['*'],
                inherits: ['user']
            }
        };
    }

    async initialize() {
        for (const role of Object.values(this.defaultRoles)) {
            const existing = await this.adapter.getRole(role.name);
            if (!existing) {
                await this.adapter.createRole(role);
            }
        }
    }

    async createRole(roleData) {
        if (!roleData.name || !roleData.permissions) {
            throw new Error('Role name and permissions are required');
        }

        const existing = await this.adapter.getRole(roleData.name);
        if (existing) {
            throw new Error(`Role '${roleData.name}' already exists`);
        }

        const role = {
            name: roleData.name,
            permissions: roleData.permissions,
            inherits: roleData.inherits || []
        };

        await this.adapter.createRole(role);
        return role;
    }

    async updateRole(roleName, updates) {
        const role = await this.adapter.getRole(roleName);
        if (!role) {
            throw new Error(`Role '${roleName}' not found`);
        }

        if (updates.permissions) role.permissions = updates.permissions;
        if (updates.inherits) role.inherits = updates.inherits;

        await this.adapter.updateRole(roleName, role);
        return role;
    }

    async deleteRole(roleName) {
        if (['user', 'admin'].includes(roleName)) {
            throw new Error('Cannot delete default roles');
        }

        await this.adapter.deleteRole(roleName);
        await this.adapter.removeRoleFromAllUsers(roleName);
    }

    async getAllRoles() {
        return await this.adapter.getAllRoles();
    }

    async getRolePermissions(roleName) {
        const role = await this.adapter.getRole(roleName);
        if (!role) return [];

        let permissions = new Set(role.permissions);

        for (const inheritedRole of role.inherits) {
            const inheritedPermissions = await this.getRolePermissions(inheritedRole);
            inheritedPermissions.forEach(p => permissions.add(p));
        }

        return Array.from(permissions);
    }

    async getUserPermissions(userId) {
        const userRoles = await this.adapter.getUserRoles(userId);
        let allPermissions = new Set();

        for (const roleName of userRoles) {
            const rolePermissions = await this.getRolePermissions(roleName);
            rolePermissions.forEach(p => allPermissions.add(p));
        }

        return Array.from(allPermissions);
    }

    async hasPermission(userId, permission) {
        const permissions = await this.getUserPermissions(userId);
        return permissions.includes('*') || permissions.includes(permission);
    }

    async hasAnyPermission(userId, permissions) {
        const userPermissions = await this.getUserPermissions(userId);
        if (userPermissions.includes('*')) return true;
        return permissions.some(p => userPermissions.includes(p));
    }

    async hasAllPermissions(userId, permissions) {
        const userPermissions = await this.getUserPermissions(userId);
        if (userPermissions.includes('*')) return true;
        return permissions.every(p => userPermissions.includes(p));
    }

    async assignRole(userId, roleName) {
        const role = await this.adapter.getRole(roleName);
        if (!role) {
            throw new Error(`Role '${roleName}' not found`);
        }
        await this.adapter.assignRoleToUser(userId, roleName);
    }

    async removeRole(userId, roleName) {
        await this.adapter.removeRoleFromUser(userId, roleName);
    }

    async getUserRoles(userId) {
        return await this.adapter.getUserRoles(userId);
    }
}

module.exports = RoleManager;