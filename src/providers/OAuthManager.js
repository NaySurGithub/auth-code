class OAuthManager {
    constructor(config) {
        this.providers = config.providers || (config.oauth && config.oauth.providers) || {};
    }

    getAuthUrl(provider, redirectUri, state) {
        const providerConfig = this.providers[provider];
        if (!providerConfig) throw new Error(`Provider '${provider}' not configured`);
        
        const params = new URLSearchParams({
            client_id: providerConfig.clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: providerConfig.scope || 'openid profile email',
            state: state
        });
        
        if (provider === 'google') {
            return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
        }
        if (provider === 'github') {
            return `https://github.com/login/oauth/authorize?${params.toString()}`;
        }
        throw new Error(`Provider '${provider}' not supported`);
    }

    async exchangeCode(provider, code, redirectUri) {
        const providerConfig = this.providers[provider];
        if (!providerConfig) throw new Error(`Provider '${provider}' not configured`);

        const params = new URLSearchParams({
            client_id: providerConfig.clientId,
            client_secret: providerConfig.clientSecret,
            code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code'
        });

        let url = '';
        let headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        let responseType = 'json';

        if (provider === 'google') {
            url = 'https://oauth2.googleapis.com/token';
        } else if (provider === 'github') {
            url = 'https://github.com/login/oauth/access_token';
            headers['Accept'] = 'application/json';
        } else {
            throw new Error(`Provider '${provider}' not supported`);
        }

        const response = await fetch(url, {
            method: 'POST',
            headers,
            body: params.toString()
        });

        const data = responseType === 'json' ? await response.json() : await response.text();
        const token = responseType === 'json' ? data.access_token : new URLSearchParams(data).get('access_token');

        if (provider === 'google') {
            const userInfo = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
                headers: { Authorization: `Bearer ${token}` }
            });
            return await userInfo.json();
        }
        if (provider === 'github') {
            const userInfo = await fetch('https://api.github.com/user', {
                headers: { Authorization: `Bearer ${token}`, 'Accept': 'application/json' }
            });
            return await userInfo.json();
        }
    }
}

module.exports = OAuthManager;