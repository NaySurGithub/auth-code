```markdown
# @nayonnpm/auth-code

The ultimate, production-ready authentication and authorization system for Node.js and Express. 
Build secure applications in seconds with JWT, Sessions, RBAC, MFA, OAuth, API Keys, Magic Links, and WebAuthn.

## 📦 Installation
```bash
npm install @nayonnpm/auth-code
```
*Note: Depending on your chosen adapter, you may also need to install peer dependencies like `mongoose`, `redis`, or `mysql2`.*

## ⚙️ Initialization & Configuration
```javascript
const { AuthEngine } = require('@nayonnpm/auth-code');

const auth = new AuthEngine({
    adapter: 'memory', // 'memory', 'mongo', 'redis', 'mysql', 'custom'
    secret: 'your-super-secret-jwt-key-change-in-prod',
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    frontendUrl: 'https://yourfrontend.com',
    // Optional: Email configuration for Magic Links / Email MFA
    email: {
        host: 'smtp.example.com',
        port: 587,
        user: 'your-email',
        pass: 'your-password',
        from: 'noreply@yourdomain.com'
    },
    // Optional: WebAuthn configuration
    webauthn: {
        rpID: 'yourdomain.com',
        rpName: 'Your App Name',
        origin: 'https://yourdomain.com'
    },
    // Optional: Rate Limiting
    rateLimit: {
        login: { attempts: 5, windowMs: 15 * 60 * 1000 }
    }
});
```

## 🔐 1. Core Authentication

### `auth.register()`
Express middleware to handle user registration, password hashing, and brute-force protection.
**Example:**
```javascript
app.post('/auth/register', auth.register());
// Request Body: { "username": "john", "email": "john@test.com", "password": "secure123", "role": "user" }
// Response: { "message": "User registered successfully", "userId": "uuid-..." }
```

### `auth.login()`
Express middleware to validate credentials, check MFA status, and issue JWTs + Refresh Token cookie.
**Example:**
```javascript
app.post('/auth/login', auth.login());
// Request Body: { "email": "john@test.com", "password": "secure123" }
// Response: { "accessToken": "eyJ...", "requiresMFA": false }
// Sets HttpOnly Cookie: refreshToken=eyJ...
```

### `auth.logout()`
Express middleware to clear the refresh token cookie and revoke the current session.
**Example:**
```javascript
app.post('/auth/logout', auth.logout());
// Response: { "message": "Logged out successfully" }
```

## 🛡️ 2. Middlewares

### `protect(auth)`
Validates the `Authorization: Bearer <token>` header or the `refreshToken` cookie. Populates `req.user`.
**Example:**
```javascript
const { protect } = require('@nayonnpm/auth-code');
app.get('/dashboard', protect(auth), (req, res) => {
    res.json({ user: req.user }); // req.user = { sub, role, jti, type }
});
```

### `requireRole(roleName)`
Ensures the authenticated user has the exact specified role.
**Example:**
```javascript
const { requireRole } = require('@nayonnpm/auth-code');
app.get('/admin', protect(auth), requireRole('admin'), (req, res) => {
    res.json({ message: "Admin access granted" });
});
```

### `requirePermission(auth, permission)`
Checks if the user has a specific granular permission (e.g., 'post:delete').
**Example:**
```javascript
const { requirePermission } = require('@nayonnpm/auth-code');
app.delete('/posts/:id', protect(auth), requirePermission(auth, 'post:delete'), (req, res) => {
    res.json({ message: "Post deleted" });
});
```

### `requireAnyPermission(auth, permissionsArray)`
Checks if the user has at least one of the specified permissions.
**Example:**
```javascript
const { requireAnyPermission } = require('@nayonnpm/auth-code');
app.get('/analytics', protect(auth), requireAnyPermission(auth, ['analytics:read', 'admin:all']), (req, res) => {
    res.json({ data: "..." });
});
```

### `requireAllPermissions(auth, permissionsArray)`
Checks if the user has ALL of the specified permissions.
**Example:**
```javascript
const { requireAllPermissions } = require('@nayonnpm/auth-code');
app.post('/critical-action', protect(auth), requireAllPermissions(auth, ['action:execute', 'action:approve']), (req, res) => {
    res.json({ message: "Action approved" });
});
```

### `requireApiKey(auth)`
Validates the `x-api-key` header instead of a JWT. Populates `req.user` with the key's permissions.
**Example:**
```javascript
const { requireApiKey } = require('@nayonnpm/auth-code');
app.get('/api/v1/data', requireApiKey(auth), (req, res) => {
    // req.user.permissions contains the permissions assigned to this API key
    res.json({ data: "secure" });
});
```

## 👑 3. Roles & Permissions Management

### `auth.createRole(roleData)`
Creates a new custom role with specific permissions and optional inheritance.
**Example:**
```javascript
await auth.createRole({
    name: 'editor',
    permissions: ['post:read', 'post:write', 'comment:moderate'],
    inherits: ['user'] // Automatically inherits 'profile:read', 'profile:write'
});
```

### `auth.updateRole(roleName, updates)`
Updates the permissions or inheritance of an existing role.
**Example:**
```javascript
await auth.updateRole('editor', { permissions: ['post:read', 'post:write', 'post:delete'] });
```

### `auth.deleteRole(roleName)`
Deletes a custom role and removes it from all users. (Cannot delete 'user' or 'admin').
**Example:**
```javascript
await auth.deleteRole('editor');
```

### `auth.getAllRoles()`
Returns an array of all defined roles.
**Example:**
```javascript
const roles = await auth.getAllRoles();
// Returns: [{ name: 'user', permissions: [...], inherits: [] }, ...]
```

### `auth.assignRole(userId, roleName)`
Assigns a role to a specific user.
**Example:**
```javascript
await auth.assignRole('user-uuid-123', 'editor');
```

### `auth.removeRole(userId, roleName)`
Removes a specific role from a user.
**Example:**
```javascript
await auth.removeRole('user-uuid-123', 'editor');
```

### `auth.getUserRoles(userId)`
Returns an array of role names assigned to the user.
**Example:**
```javascript
const roles = await auth.getUserRoles('user-uuid-123');
// Returns: ['user', 'editor']
```

### `auth.getUserPermissions(userId)`
Resolves and returns all effective permissions for a user, including inherited ones.
**Example:**
```javascript
const perms = await auth.getUserPermissions('user-uuid-123');
// Returns: ['profile:read', 'profile:write', 'post:read', 'post:write', 'comment:moderate']
```

### `auth.hasPermission(userId, permission)`
Boolean check for a specific permission.
**Example:**
```javascript
const canDelete = await auth.hasPermission('user-uuid-123', 'post:delete');
// Returns: false
```

## 📱 4. Multi-Factor Authentication (MFA)

### `auth.generateMFASecret(userId)`
Generates a TOTP secret, QR code URL, and backup codes.
**Example:**
```javascript
const mfaData = await auth.generateMFASecret('user-uuid-123');
// Returns: { secret: 'JBSWY3DPEHPK3PXP', qrCode: 'data:image/png...', backupCodes: ['A1B2C3', ...] }
```

### `auth.verifyAndEnableMFA(userId, token)`
Verifies the 6-digit TOTP code from the user's authenticator app and enables MFA.
**Example:**
```javascript
await auth.verifyAndEnableMFA('user-uuid-123', '123456');
// Returns: true (or throws Error)
```

### `auth.disableMFA(userId, token)`
Disables TOTP MFA. Requires either a valid current TOTP code or a backup code.
**Example:**
```javascript
await auth.disableMFA('user-uuid-123', '123456'); // or a backup code like 'A1B2C3'
// Returns: true
```

### `auth.sendEmailMFACode(userId)`
Generates a 6-digit code and sends it to the user's registered email.
**Example:**
```javascript
await auth.sendEmailMFACode('user-uuid-123');
// Returns: true (Email is sent via configured transporter)
```

### `auth.verifyEmailMFACode(userId, code)`
Verifies the code sent via email.
**Example:**
```javascript
await auth.verifyEmailMFACode('user-uuid-123', '654321');
// Returns: true (or throws Error)
```

## 🔗 5. Passwordless Authentication (Magic Links)

### `auth.sendMagicLink(email)`
Generates a secure, time-limited (15 min) token and "sends" it to the user's email.
**Example:**
```javascript
await auth.sendMagicLink('john@test.com');
// Returns: true
```

### `auth.verifyMagicLink(token)`
Validates the token from the URL, logs the user in, and returns new JWTs.
**Example:**
```javascript
const tokens = await auth.verifyMagicLink('magic-link-token-from-url');
// Returns: { accessToken: 'eyJ...', refreshToken: 'eyJ...' }
```

## 🌐 6. OAuth 2.0 (Google / GitHub)

### `auth.getOAuthUrl(provider, redirectUri)`
Generates the authorization URL to redirect the user to the provider.
**Example:**
```javascript
app.get('/auth/google', (req, res) => {
    const { url } = auth.getOAuthUrl('google', 'https://yourapp.com/auth/callback/google');
    res.redirect(url);
});
```

### `auth.handleOAuthCallback(provider)`
Express middleware to handle the callback, exchange the code, create/find the user, and set cookies.
**Example:**
```javascript
app.get('/auth/callback/google', auth.handleOAuthCallback('google'));
// Redirects to: config.frontendUrl + '?token=' + accessToken
```

## 🔑 7. API Keys for Developers

### `auth.createApiKey(userId, name, permissions, daysValid)`
Generates a new API key for a user. Returns the keyId and the secret keyValue (shown only once).
**Example:**
```javascript
const newKey = await auth.createApiKey('user-uuid-123', 'Mobile App', ['data:read', 'data:write'], 30);
// Returns: { keyId: 'ak_...', keyValue: 'live_xxxxxxxxxxxx' }
```

### `auth.revokeApiKey(keyId)`
Invalidates an API key immediately.
**Example:**
```javascript
await auth.revokeApiKey('ak_...');
```

### `auth.getUserApiKeys(userId)`
Returns a list of all API keys for a user (without the secret keyValue).
**Example:**
```javascript
const keys = await auth.getUserApiKeys('user-uuid-123');
// Returns: [{ keyId: 'ak_...', name: 'Mobile App', expiresAt: Date, active: true }]
```

## 🗝️ 8. WebAuthn / Passkeys

### `auth.generateWebAuthnRegistrationOptions(userId)`
Generates the options object to be passed to the browser's `navigator.credentials.create()`.
**Example:**
```javascript
const options = await auth.generateWebAuthnRegistrationOptions('user-uuid-123');
// Returns: { challenge: '...', rp: {...}, user: {...}, pubKeyCredParams: [...] }
```

### `auth.verifyWebAuthnRegistration(userId, clientResponse)`
Verifies the response from the browser after registration and saves the credential.
**Example:**
```javascript
const isValid = await auth.verifyWebAuthnRegistration('user-uuid-123', browserResponse);
// Returns: true (or throws Error)
```

### `auth.generateWebAuthnAuthenticationOptions(userId)`
Generates options for the browser's `navigator.credentials.get()` during login.
**Example:**
```javascript
const options = await auth.generateWebAuthnAuthenticationOptions('user-uuid-123');
// Returns: { challenge: '...', allowCredentials: [...] }
```

### `auth.verifyWebAuthnAuthentication(userId, clientResponse)`
Verifies the login assertion and updates the credential counter.
**Example:**
```javascript
const isValid = await auth.verifyWebAuthnAuthentication('user-uuid-123', browserResponse);
// Returns: true (or throws Error)
```

## 🛑 9. Session Management

### `auth.revokeAllSessions(userId)`
Invalidates all active sessions (including refresh tokens) for a specific user.
**Example:**
```javascript
await auth.revokeAllSessions('user-uuid-123');
```

## 💾 10. Adapters Guide

### Memory Adapter (Default for testing)
```javascript
adapter: 'memory'
```

### MongoDB Adapter
```javascript
const mongoose = require('mongoose');
adapter: 'mongo',
mongoose: mongoose
```

### Redis / Upstash Adapter
```javascript
const redis = require('redis');
const client = redis.createClient({ url: 'redis://...' });
await client.connect();
adapter: 'redis', // or 'upstash'
redisClient: client
```

### MySQL Adapter
```javascript
const mysql = require('mysql2/promise');
const pool = mysql.createPool({ host: 'localhost', user: 'root', password: '...', database: 'auth' });
adapter: 'mysql',
mysqlPool: pool
```

### Custom Adapter
```javascript
adapter: 'custom',
customHandlers: {
    async saveSession(userId, jti, expiresAt) { /* your logic */ },
    async getSession(userId, jti) { /* your logic */ },
    // ... implement all BaseAdapter methods
}
```

## ⚖️ License
MIT © nayonnpm
```