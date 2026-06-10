 # @nayonnpm/auth-code
 
 The ultimate, production-ready, enterprise-grade authentication and authorization system for Node.js and Express.
 
 ## 📦 Installation
 ```bash
 npm install @nayonnpm/auth-code
 ```
 *(Optional peer dependencies based on your adapter: `mongoose`, `mysql2`, `redis`)*
 
 ## 🚀 Quick Start
 ```javascript
 const express = require('express');
 const { AuthEngine, protect, requireRole, requirePermission } = require('@nayonnpm/auth-code');
 
 const app = express();
 app.use(express.json());
 
 const auth = new AuthEngine({
     adapter: 'memory', 
     secret: 'your-super-secret-jwt-key',
     accessTokenExpiry: '15m',
     refreshTokenExpiry: '7d',
     frontendUrl: 'https://yourfrontend.com'
 });
 
 app.post('/auth/register', auth.register());
 app.post('/auth/login', auth.login());
 app.get('/admin', protect(auth), requireRole('admin'), (req, res) => res.json({ ok: true }));
 
 app.listen(3000, () => console.log('Server running'));
 ```
 
 ## 🧠 Core Architecture
 ### 1. Adapters (Database Agnostic)
 The system supports multiple storage backends. Choose one during initialization:
 - `'memory'`: Built-in, zero-config, ideal for testing (data resets on restart).
 - `'mongo'`: Requires a `mongoose` instance. Auto-hashes API keys.
 - `'mysql'`: Requires a `mysql2` pool. Features auto-table creation via `await auth.adapter.initializeDatabase()`.
 - `'redis'` / `'upstash'`: Requires a `redis` client instance.
 - `'custom'`: Pass your own handler functions via `customHandlers` object.
 
 ### 2. Security Features (Built-in)
 - **JWT + Refresh Tokens**: Secure tokens with JTI tracking and session revocation.
 - **Brute Force Protection**: Automatic IP-based lockout after 5 failed attempts (5-minute window).
 - **Have I Been Pwned (HIBP)**: Optional password compromise checking during registration (`security: { checkHIBP: true }`).
 - **Captcha Integration**: Built-in support for reCAPTCHA and hCaptcha (`captcha: { enabled: true, secretKey: '...', provider: 'recaptcha' }`).
 - **SQL Injection Proof**: All database adapters use parameterized queries or ORM methods exclusively.
 - **Input Sanitization**: `SecurityUtils.sanitizeInput()` available for custom routes.
 
 ## 🌐 OAuth 2.0 (30+ Providers)
 Pre-configured out of the box. Just add your `clientId` and `clientSecret`.
 Supported: `google`, `github`, `discord`, `microsoft`, `twitter`, `spotify`, `twitch`, `linkedin`, `facebook`, `gitlab`, `reddit`, `slack`, `vk`, `zoom`, `dropbox`, `figma`, `line`, `naver`, `notion`, `paypal`, `roblox`, `salesforce`, `vercel`, `wechat`, `kick`, `linear`, `railway`, `huggingface`, `kakao`, `polar`, `cognito`, `atlassian`, `apple`, `tiktok`.
 
 ```javascript
 const auth = new AuthEngine({
     oauth: {
         providers: {
             discord: { clientId: '...', clientSecret: '...', scope: 'identify email' },
             custom_sso: { 
                 authUrl: '...', tokenUrl: '...', userInfoUrl: '...',
                 clientId: '...', clientSecret: '...', tokenFormat: 'json'
             }
         }
     }
 });
 
 app.get('/auth/discord', (req, res) => {
     const { url } = auth.getOAuthUrl('discord', 'https://yourapp.com/callback/discord');
     res.redirect(url);
 });
 app.get('/auth/callback/discord', auth.handleOAuthCallback('discord'));
 ```
 
 ## 🔐 Advanced Authentication
 ### Multi-Factor Authentication (MFA)
 Supports TOTP (Google Authenticator) and Email-based OTP.
 ```javascript
 // 1. Generate QR Code for TOTP
 const { qrCode, secret, backupCodes } = await auth.generateMFASecret(userId);
 // 2. Verify and Enable
 await auth.verifyAndEnableMFA(userId, '123456');
 // 3. Email MFA Fallback
 await auth.sendEmailMFACode(userId);
 await auth.verifyEmailMFACode(userId, '654321');
 ```
 
 ### WebAuthn / Passkeys (Passwordless)
 Native support for biometric authentication (Touch ID, Face ID, Windows Hello, YubiKey).
 ```javascript
 const auth = new AuthEngine({
     webauthn: { rpID: 'yourdomain.com', rpName: 'My App', origin: 'https://yourdomain.com' }
 });
 // Registration
 const options = await auth.generateWebAuthnRegistrationOptions(userId);
 await auth.verifyWebAuthnRegistration(userId, browserResponse);
 // Authentication
 const authOptions = await auth.generateWebAuthnAuthenticationOptions(userId);
 await auth.verifyWebAuthnAuthentication(userId, browserResponse);
 ```
 
 ### Email Verification & Password Reset
 ```javascript
 const auth = new AuthEngine({
     emailVerification: {
         sendOnSignUp: true,
         sendOnSignIn: true,
         autoSignInAfterVerification: true,
         sendVerificationEmail: async ({ user, url, token }) => { /* send email */ }
     },
     emailAndPassword: {
         requireEmailVerification: true,
         sendResetPassword: async ({ user, url, token }) => { /* send email */ }
     }
 });
 
 // Trigger manually
 await auth.sendVerificationEmail('user@email.com', '/dashboard');
 await auth.verifyEmail('token_from_url');
 await auth.sendResetPasswordEmail('user@email.com');
 await auth.resetPassword('token_from_url', 'newSecurePassword123');
 ```
 
 ## 👑 Role-Based Access Control (RBAC)
 Granular permissions with inheritance support.
 ```javascript
 await auth.createRole({ name: 'editor', permissions: ['post:read', 'post:write'], inherits: ['user'] });
 await auth.assignRole(userId, 'editor');
 
 // Middlewares
 app.delete('/posts/:id', protect(auth), requirePermission(auth, 'post:delete'), handler);
 app.get('/analytics', protect(auth), requireAnyPermission(auth, ['analytics:read', 'admin:all']), handler);
 ```
 
 ## 🔑 API Keys for Developers
 Generate scoped, expiring API keys for third-party integrations.
 ```javascript
 // Create
 const { keyId, keyValue } = await auth.createApiKey(userId, 'Mobile App', ['data:read'], 30); // 30 days
 // Revoke
 await auth.revokeApiKey(keyId);
 // Middleware
 const { requireApiKey } = require('@nayonnpm/auth-code');
 app.get('/api/data', requireApiKey(auth), (req, res) => {
     // req.user is populated with the API key's permissions
     res.json({ data: 'secure' });
 });
 ```
 
 ## 🖥️ Multi-Session & Device Management
 Track and manage active user sessions across devices.
 ```javascript
 // Get all active sessions for a user
 const sessions = await auth.getActiveSessions(userId);
 // Revoke a specific session (e.g., "Log out of other devices")
 await auth.revokeSession(userId, specificJti);
 // Revoke all sessions
 await auth.revokeAllSessions(userId);
 ```
 
 ## 🎟️ One-Time Tokens (OTT)
 Secure, single-use tokens for sensitive actions (e.g., email change confirmation).
 ```javascript
 // Generate (valid for 1 hour by default)
 const token = await auth.generateOTT(userId, 'email_change', 1);
 // Verify (automatically invalidates after successful verification)
 const verifiedUserId = await auth.verifyOTT(token, 'email_change');
 ```
 
 ## 🌍 Internationalization (i18n)
 Built-in translation support for error messages.
 ```javascript
 const auth = new AuthEngine({
     lang: 'fr', // 'en' or 'fr' (default: 'en')
     i18n: {
         fr: { invalid_credentials: 'Identifiants invalides' } // Custom overrides
     }
 });
 // Used internally: this.i18n.t('invalid_credentials')
 ```
 
 ## 🧪 Test Utils
 Built-in utilities for fast, isolated unit testing.
 ```javascript
 const { createMockAuth } = require('@nayonnpm/auth-code/src/utils/TestUtils');
 
 describe('Auth Tests', () => {
     it('should generate valid tokens', () => {
         const { auth, generateToken, mockEmails } = createMockAuth();
         const tokens = generateToken('test-user', 'admin');
         expect(tokens.accessToken).toBeDefined();
     });
 });
 ```
 
 ## 📄 OpenAPI Specification
 Auto-generate Swagger/OpenAPI documentation for your auth routes.
 ```javascript
 const spec = auth.generateOpenAPISpec();
 app.get('/api-docs.json', (req, res) => res.json(spec));
 ```
 
 ## ⚖️ License
 MIT © nayonnpm