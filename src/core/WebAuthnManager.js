const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');

class WebAuthnManager {
    constructor(config, adapter) {
        this.rpID = config.rpID;
        this.rpName = config.rpName;
        this.origin = config.origin;
        this.adapter = adapter;
    }

    async generateRegistrationOptions(userId, username) {
        const user = await this.adapter.getUserById(userId);
        const options = await generateRegistrationOptions({
            rpName: this.rpName,
            rpID: this.rpID,
            userID: Buffer.from(userId),
            userName: username || user.email,
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
        const credentials = await this.adapter.getWebAuthnCredentials(userId);
        const options = await generateAuthenticationOptions({
            rpID: this.rpID,
            allowCredentials: credentials.map(c => ({
                id: c.id,
                type: 'public-key',
                transports: c.transports
            })),
            userVerification: 'preferred'
        });
        await this.adapter.saveWebAuthnChallenge(userId, options.challenge);
        return options;
    }

    async verifyAuthenticationResponse(userId, response) {
        const challenge = await this.adapter.getWebAuthnChallenge(userId);
        const credential = await this.adapter.getWebAuthnCredentialById(response.id);
        if (!credential) return false;

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