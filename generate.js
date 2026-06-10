const fs = require('fs');
const path = require('path');
const { AuthEngine } = require('@nayonnpm/auth-code');

// 1. Initialiser AuthEngine (une config minimale suffit pour générer le spec)
const auth = new AuthEngine({
    adapter: 'memory',
    secret: 'dummy-secret-for-docs-generation',
    frontendUrl: 'https://yourdomain.com'
});

// 2. Générer la spécification OpenAPI de base
const openApiSpec = auth.generateOpenAPISpec();

// 3. Enrichir la documentation avec des détails supplémentaires
openApiSpec.info = {
    title: 'Auth Code API Documentation',
    version: '2.0.0',
    description: 'Complete API reference for @nayonnpm/auth-code authentication and authorization system. Supports JWT, OAuth, WebAuthn, MFA, RBAC, and more.'
};

openApiSpec.servers = [
    {
        url: 'http://localhost:3000',
        description: 'Development server'
    },
    {
        url: 'https://api.yourdomain.com',
        description: 'Production server'
    }
];

openApiSpec.components = {
    securitySchemes: {
        BearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Enter your JWT access token (without "Bearer " prefix)'
        },
        ApiKeyAuth: {
            type: 'apiKey',
            in: 'header',
            name: 'x-api-key',
            description: 'Enter your developer API key'
        }
    },
    schemas: {
        User: {
            type: 'object',
            properties: {
                userId: { type: 'string', format: 'uuid' },
                email: { type: 'string', format: 'email' },
                role: { type: 'string' }
            }
        },
        ErrorResponse: {
            type: 'object',
            properties: {
                error: { type: 'string' }
            }
        }
    }
};

// Tu peux ajouter manuellement d'autres routes ici si nécessaire
openApiSpec.paths['/auth/logout'] = {
    post: {
        summary: 'Logout user',
        description: 'Invalidates the current refresh token cookie and session.',
        responses: {
            200: { description: 'Successfully logged out' },
            500: { description: 'Internal server error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } }
        }
    }
};

// 4. Écrire le résultat dans le fichier docs.json
const outputPath = path.join(__dirname, 'docs.json');
fs.writeFileSync(outputPath, JSON.stringify(openApiSpec, null, 2), 'utf-8');

console.log(`✅ OpenAPI documentation successfully generated at: ${outputPath}`);