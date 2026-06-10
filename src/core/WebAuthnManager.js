const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');

class WebAuthnManager {
    constructor(config, adapter) {
        this.rpID = config.rpID;
        this.rpName = config.rpName;
        this.origin = config.origin;
        this.adapter = adapter;
        this.pendingAuthChallenges = new Map();
    }

    async generateRegistrationOptions(userId, username) {
        const user = await this.adapter.getUserById(userId);
        const userIdBuffer = Buffer.from(userId);
        
        const options = await generateRegistrationOptions({
            rpName: this.rpName,
            rpID: this.rpID,
            userID: userIdBuffer,
            userName: username || (user ? user.email : 'user'),
            timeout: 60000,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred'
            }
        });
        
        await this.adapter.saveWebAuthnChallenge(userId, options.challenge);
        return options;
    }

    async verifyRegistrationResponse(userId, response) {
        const challenge = await this.adapter.getWebAuthnChallenge(userId);
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: challenge,
            expectedOrigin: this.origin,
            expectedRPID: this.rpID
        });
        
        if (verification.verified) {
            await this.adapter.saveWebAuthnCredential(userId, verification.registrationInfo);
            await this.adapter.clearWebAuthnChallenge(userId);
        }
        return verification.verified;
    }

    async generateAuthenticationOptions(userId) {
        if (this.pendingAuthChallenges.has(userId)) {
            console.log('⏸️  Reusing existing challenge for user:', userId);
            return this.pendingAuthChallenges.get(userId);
        }

        const credentials = await this.adapter.getWebAuthnCredentials(userId);
        
        if (!credentials || credentials.length === 0) {
            throw new Error('No credentials found. Register first.');
        }

        console.log('🔑 Found', credentials.length, 'credential(s) for user:', userId);

        const options = await generateAuthenticationOptions({
            rpID: this.rpID,
            timeout: 60000,
            allowCredentials: credentials.map(c => ({
                id: c.id,
                type: 'public-key',
                transports: c.transports || []
            })),
            userVerification: 'preferred'
        });
        
        await this.adapter.saveWebAuthnChallenge(userId, options.challenge);
        this.pendingAuthChallenges.set(userId, options);
        
        setTimeout(() => this.pendingAuthChallenges.delete(userId), 120000);
        
        console.log('🔐 Auth options sent. Challenge:', options.challenge);
        return options;
    }

    async verifyAuthenticationResponse(userId, response) {
        const challenge = await this.adapter.getWebAuthnChallenge(userId);
        const credential = await this.adapter.getWebAuthnCredentialById(response.id);
        
        if (!credential) {
            throw new Error('Credential not found on server');
        }

        this.pendingAuthChallenges.delete(userId);

        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge: challenge,
            expectedOrigin: this.origin,
            expectedRPID: this.rpID,
            credential: {
                id: credential.id,
                publicKey: credential.publicKey,
                counter: credential.counter
            }
        });

        if (verification.verified) {
            await this.adapter.updateWebAuthnCredentialCounter(credential.id, verification.authenticationInfo.newCounter);
            await this.adapter.clearWebAuthnChallenge(userId);
        }
        return verification.verified;
    }
}

module.exports = WebAuthnManager;