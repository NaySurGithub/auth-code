const bcrypt = require('bcrypt');

class CryptoManager {
    constructor(config) {
        this.saltRounds = config.saltRounds || 10;
    }

    async hash(password) {
        return await bcrypt.hash(password, this.saltRounds);
    }

    async verify(password, hash) {
        return await bcrypt.compare(password, hash);
    }
}

module.exports = CryptoManager;