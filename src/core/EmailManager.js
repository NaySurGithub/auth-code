const nodemailer = require('nodemailer');

class EmailManager {
    constructor(config) {
        this.config = config;
        this.transporter = nodemailer.createTransport({
            host: config.host || 'smtp.gmail.com',
            port: config.port || 587,
            secure: config.secure || false,
            auth: {
                user: config.user,
                pass: config.pass
            }
        });
    }

    async send({ to, subject, html, text }) {
        await this.transporter.sendMail({
            from: this.config.from,
            to,
            subject,
            html,
            text
        });
    }
}

module.exports = EmailManager;