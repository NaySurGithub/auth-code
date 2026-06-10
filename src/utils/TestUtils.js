const { AuthEngine } = require('../AuthEngine');

function createMockAuth(overrides = {}) {
    const mockEmails = [];
    const auth = new AuthEngine({
        adapter: 'memory',
        secret: 'test-secret-key',
        accessTokenExpiry: '5m',
        refreshTokenExpiry: '1h',
        email: {
            send: async ({ to, subject, html }) => {
                mockEmails.push({ to, subject, html });
            }
        },
        ...overrides
    });

    return {
        auth,
        mockEmails,
        generateToken: (userId = 'test-user', role = 'user') => {
            return auth.jwt.generateTokens({ sub: userId, role });
        }
    };
}

module.exports = { createMockAuth };