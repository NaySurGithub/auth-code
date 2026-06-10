const defaultDict = {
    en: {
        invalid_credentials: 'Invalid email or password',
        email_not_verified: 'Please verify your email address first',
        too_many_attempts: 'Too many attempts. Please try again later',
        password_pwned: 'This password has been compromised. Please choose another.',
        captcha_failed: 'Captcha verification failed',
        session_expired: 'Your session has expired'
    },
    fr: {
        invalid_credentials: 'Email ou mot de passe invalide',
        email_not_verified: 'Veuillez d\'abord vérifier votre adresse email',
        too_many_attempts: 'Trop de tentatives. Veuillez réessayer plus tard',
        password_pwned: 'Ce mot de passe a été compromis. Veuillez en choisir un autre.',
        captcha_failed: 'La vérification du captcha a échoué',
        session_expired: 'Votre session a expiré'
    }
};

class I18n {
    constructor(config) {
        this.lang = config.lang || 'en';
        this.customDict = config.i18n || {};
    }

    t(key) {
        return (this.customDict[this.lang] && this.customDict[this.lang][key]) || 
               (defaultDict[this.lang] && defaultDict[this.lang][key]) || 
               key;
    }
}

module.exports = I18n;