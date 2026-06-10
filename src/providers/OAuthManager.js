const DEFAULT_PROVIDERS = {
    google: {
        authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
        defaultScope: 'openid profile email',
        tokenFormat: 'json',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    github: {
        authUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        userInfoUrl: 'https://api.github.com/user',
        defaultScope: 'user:email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}`, Accept: 'application/json' })
    },
    discord: {
        authUrl: 'https://discord.com/api/oauth2/authorize',
        tokenUrl: 'https://discord.com/api/oauth2/token',
        userInfoUrl: 'https://discord.com/api/users/@me',
        defaultScope: 'identify email',
        tokenFormat: 'json',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    microsoft: {
        authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
        defaultScope: 'User.Read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    twitter: {
        authUrl: 'https://twitter.com/i/oauth2/authorize',
        tokenUrl: 'https://api.twitter.com/2/oauth2/token',
        userInfoUrl: 'https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url',
        defaultScope: 'users.read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    spotify: {
        authUrl: 'https://accounts.spotify.com/authorize',
        tokenUrl: 'https://accounts.spotify.com/api/token',
        userInfoUrl: 'https://api.spotify.com/v1/me',
        defaultScope: 'user-read-email user-read-private',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    twitch: {
        authUrl: 'https://id.twitch.tv/oauth2/authorize',
        tokenUrl: 'https://id.twitch.tv/oauth2/token',
        userInfoUrl: 'https://api.twitch.tv/helix/users',
        defaultScope: 'user:read:email',
        tokenFormat: 'form',
        userInfoHeaders: (token, clientId) => ({ Authorization: `Bearer ${token}`, 'Client-Id': clientId })
    },
    linkedin: {
        authUrl: 'https://www.linkedin.com/oauth/v2/authorization',
        tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
        userInfoUrl: 'https://api.linkedin.com/v2/userinfo',
        defaultScope: 'openid profile email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    facebook: {
        authUrl: 'https://www.facebook.com/v18.0/dialog/oauth',
        tokenUrl: 'https://graph.facebook.com/v18.0/oauth/access_token',
        userInfoUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture',
        defaultScope: 'email public_profile',
        tokenFormat: 'json',
        userInfoHeaders: () => ({})
    },
    gitlab: {
        authUrl: 'https://gitlab.com/oauth/authorize',
        tokenUrl: 'https://gitlab.com/oauth/token',
        userInfoUrl: 'https://gitlab.com/api/v4/user',
        defaultScope: 'read_user',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    reddit: {
        authUrl: 'https://www.reddit.com/api/v1/authorize',
        tokenUrl: 'https://www.reddit.com/api/v1/access_token',
        userInfoUrl: 'https://oauth.reddit.com/api/v1/me',
        defaultScope: 'identity',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    slack: {
        authUrl: 'https://slack.com/oauth/v2/authorize',
        tokenUrl: 'https://slack.com/api/oauth.v2.access',
        userInfoUrl: 'https://slack.com/api/users.info',
        defaultScope: 'users:read',
        tokenFormat: 'json',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    vk: {
        authUrl: 'https://oauth.vk.com/authorize',
        tokenUrl: 'https://oauth.vk.com/access_token',
        userInfoUrl: 'https://api.vk.com/method/users.get?fields=photo_100&v=5.131',
        defaultScope: 'email',
        tokenFormat: 'form',
        userInfoHeaders: () => ({})
    },
    zoom: {
        authUrl: 'https://zoom.us/oauth/authorize',
        tokenUrl: 'https://zoom.us/oauth/token',
        userInfoUrl: 'https://api.zoom.us/v2/users/me',
        defaultScope: 'user:read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    dropbox: {
        authUrl: 'https://www.dropbox.com/oauth2/authorize',
        tokenUrl: 'https://api.dropboxapi.com/oauth2/token',
        userInfoUrl: 'https://api.dropboxapi.com/2/users/get_current_account',
        defaultScope: 'account_info.read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    figma: {
        authUrl: 'https://www.figma.com/oauth',
        tokenUrl: 'https://www.figma.com/api/oauth/token',
        userInfoUrl: 'https://api.figma.com/v1/me',
        defaultScope: 'files:read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    line: {
        authUrl: 'https://access.line.me/oauth2/v2.1/authorize',
        tokenUrl: 'https://api.line.me/oauth2/v2.1/token',
        userInfoUrl: 'https://api.line.me/v2/profile',
        defaultScope: 'profile openid email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    naver: {
        authUrl: 'https://nid.naver.com/oauth2.0/authorize',
        tokenUrl: 'https://nid.naver.com/oauth2.0/token',
        userInfoUrl: 'https://openapi.naver.com/v1/nid/me',
        defaultScope: 'name email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    notion: {
        authUrl: 'https://api.notion.com/v1/oauth/authorize',
        tokenUrl: 'https://api.notion.com/v1/oauth/token',
        userInfoUrl: 'https://api.notion.com/v1/users/me',
        defaultScope: '',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}`, 'Notion-Version': '2022-06-28' })
    },
    paypal: {
        authUrl: 'https://www.paypal.com/signin/authorize',
        tokenUrl: 'https://api-m.paypal.com/v1/oauth2/token',
        userInfoUrl: 'https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=openid',
        defaultScope: 'openid profile email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    roblox: {
        authUrl: 'https://apis.roblox.com/oauth/v1/authorize',
        tokenUrl: 'https://apis.roblox.com/oauth/v1/token',
        userInfoUrl: 'https://apis.roblox.com/oauth/v1/userinfo',
        defaultScope: 'openid profile',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    salesforce: {
        authUrl: 'https://login.salesforce.com/services/oauth2/authorize',
        tokenUrl: 'https://login.salesforce.com/services/oauth2/token',
        userInfoUrl: 'https://login.salesforce.com/services/oauth2/userinfo',
        defaultScope: 'openid profile email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    vercel: {
        authUrl: 'https://vercel.com/oauth/authorize',
        tokenUrl: 'https://api.vercel.com/v2/oauth/access_token',
        userInfoUrl: 'https://api.vercel.com/www/user',
        defaultScope: 'read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    wechat: {
        authUrl: 'https://open.weixin.qq.com/connect/qrconnect',
        tokenUrl: 'https://api.weixin.qq.com/sns/oauth2/access_token',
        userInfoUrl: 'https://api.weixin.qq.com/sns/userinfo',
        defaultScope: 'snsapi_login',
        tokenFormat: 'json',
        userInfoHeaders: () => ({})
    },
    kick: {
        authUrl: 'https://id.kick.com/oauth/authorize',
        tokenUrl: 'https://id.kick.com/oauth/token',
        userInfoUrl: 'https://api.kick.com/public/v1/users/me',
        defaultScope: 'user:read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    linear: {
        authUrl: 'https://linear.app/oauth/authorize',
        tokenUrl: 'https://api.linear.app/oauth/token',
        userInfoUrl: 'https://api.linear.app/graphql',
        defaultScope: 'read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    railway: {
        authUrl: 'https://railway.app/oauth/authorize',
        tokenUrl: 'https://railway.app/oauth/token',
        userInfoUrl: 'https://backboard.railway.app/graphql/v2',
        defaultScope: 'read',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    huggingface: {
        authUrl: 'https://huggingface.co/oauth/authorize',
        tokenUrl: 'https://huggingface.co/oauth/token',
        userInfoUrl: 'https://huggingface.co/oauth/userinfo',
        defaultScope: 'openid profile',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    kakao: {
        authUrl: 'https://kauth.kakao.com/oauth/authorize',
        tokenUrl: 'https://kauth.kakao.com/oauth/token',
        userInfoUrl: 'https://kapi.kakao.com/v2/user/me',
        defaultScope: 'profile_nickname account_email',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    polar: {
        authUrl: 'https://polar.sh/oauth2/authorize',
        tokenUrl: 'https://polar.sh/api/v1/oauth2/token',
        userInfoUrl: 'https://polar.sh/api/v1/oauth2/userinfo',
        defaultScope: 'openid',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    cognito: {
        authUrl: 'https://YOUR_DOMAIN.auth.YOUR_REGION.amazoncognito.com/oauth2/authorize',
        tokenUrl: 'https://YOUR_DOMAIN.auth.YOUR_REGION.amazoncognito.com/oauth2/token',
        userInfoUrl: 'https://YOUR_DOMAIN.auth.YOUR_REGION.amazoncognito.com/oauth2/userInfo',
        defaultScope: 'openid email profile',
        tokenFormat: 'form',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    atlassian: {
        authUrl: 'https://auth.atlassian.com/authorize',
        tokenUrl: 'https://auth.atlassian.com/oauth/token',
        userInfoUrl: 'https://api.atlassian.com/me',
        defaultScope: 'read:me',
        tokenFormat: 'json',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    },
    apple: {
        authUrl: 'https://appleid.apple.com/auth/authorize',
        tokenUrl: 'https://appleid.apple.com/auth/token',
        userInfoUrl: null,
        defaultScope: 'name email',
        tokenFormat: 'form',
        userInfoHeaders: () => ({})
    },
    tiktok: {
        authUrl: 'https://www.tiktok.com/v2/auth/authorize/',
        tokenUrl: 'https://open.tiktokapis.com/v2/oauth/token/',
        userInfoUrl: 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url',
        defaultScope: 'user.info.basic',
        tokenFormat: 'json',
        userInfoHeaders: (token) => ({ Authorization: `Bearer ${token}` })
    }
};

class OAuthManager {
    constructor(config) {
        const userProviders = config.oauth?.providers || config.providers || {};
        this.providers = {};
        
        for (const [key, defaults] of Object.entries(DEFAULT_PROVIDERS)) {
            this.providers[key] = { ...defaults, ...(userProviders[key] || {}) };
        }
        
        for (const [key, customConfig] of Object.entries(userProviders)) {
            if (!this.providers[key]) {
                this.providers[key] = customConfig;
            }
        }
    }

    getAuthUrl(provider, redirectUri, state) {
        const config = this.providers[provider];
        if (!config || !config.authUrl) throw new Error(`Provider '${provider}' not configured`);
        
        const params = new URLSearchParams({
            client_id: config.clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: config.scope || config.defaultScope || '',
            state: state
        });

        if (provider === 'wechat') {
            params.set('appid', config.clientId);
            params.set('redirect_uri', encodeURIComponent(redirectUri));
            return `${config.authUrl}?${params.toString()}`;
        }

        return `${config.authUrl}?${params.toString()}`;
    }

    async exchangeCode(provider, code, redirectUri) {
        const config = this.providers[provider];
        if (!config || !config.tokenUrl) throw new Error(`Provider '${provider}' not configured`);

        const params = new URLSearchParams({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code'
        });

        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        if (provider === 'twitch' && config.clientId) {
            headers['Client-Id'] = config.clientId;
        }
        if (provider === 'tiktok') {
            headers['Client-Key'] = config.clientId;
        }

        const response = await fetch(config.tokenUrl, {
            method: 'POST',
            headers,
            body: params.toString()
        });

        let data;
        if (config.tokenFormat === 'form') {
            const text = await response.text();
            data = Object.fromEntries(new URLSearchParams(text));
        } else {
            data = await response.json();
        }

        const token = data.access_token;
        if (!token) throw new Error(`Failed to get access token from ${provider}`);

        if (!config.userInfoUrl) {
            return { id: token, email: null, name: provider };
        }

        let userInfoUrl = config.userInfoUrl;
        if (provider === 'vk' && data.user_id) {
            userInfoUrl += `&user_ids=${data.user_id}&access_token=${token}`;
        } else if (provider === 'wechat' && data.openid) {
            userInfoUrl += `?access_token=${token}&openid=${data.openid}`;
        } else if (provider === 'paypal') {
            userInfoUrl += `&schema=openid`;
        }

        const userInfoRes = await fetch(userInfoUrl, {
            headers: config.userInfoHeaders ? config.userInfoHeaders(token, config.clientId) : {}
        });
        
        let userInfo = await userInfoRes.json();

        if (provider === 'twitter') {
            return { id: userInfo.data.id, email: null, name: userInfo.data.name, username: userInfo.data.username };
        }
        if (provider === 'twitch') {
            const userData = userInfo.data[0];
            return { id: userData.id, email: userData.email, name: userData.display_name, username: userData.login };
        }
        if (provider === 'vk') {
            const userData = userInfo.response[0];
            return { id: userData.id, email: data.email, name: `${userData.first_name} ${userData.last_name}` };
        }
        if (provider === 'naver') {
            return { id: userInfo.response.id, email: userInfo.response.email, name: userInfo.response.name };
        }
        if (provider === 'kakao') {
            return { id: userInfo.id, email: userInfo.kakao_account?.email, name: userInfo.properties?.nickname };
        }
        if (provider === 'line') {
            return { id: userInfo.userId, email: null, name: userInfo.displayName };
        }
        if (provider === 'discord') {
            return { id: userInfo.id, email: userInfo.email, name: userInfo.global_name || userInfo.username };
        }
        if (provider === 'tiktok') {
            return { 
                id: userInfo.data.user.open_id, 
                email: null, 
                name: userInfo.data.user.display_name 
            };
        }

        return { 
            id: userInfo.id || userInfo.sub, 
            email: userInfo.email, 
            name: userInfo.name || userInfo.displayName || userInfo.login || userInfo.username 
        };
    }
}

module.exports = OAuthManager;