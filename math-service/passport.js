const jwtStrategy = require('passport-jwt').Strategy;
const jwtExtract = require('passport-jwt').ExtractJwt;

const fs = require('fs');
const PUBLIC_KEY = fs.readFileSync('./rsa_public.pem', 'utf8');

const options = {
    jwtFromRequest: jwtExtract.fromAuthHeaderAsBearerToken(),
    secretOrKey: PUBLIC_KEY,
    algorithms: ['RS256']
};

const strategy = new jwtStrategy(options, (payload, done) => {
    try {
        user = payload.sub;
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (error) {
        return done(error, null);
    }
});

module.exports = (passport) => {
    passport.use(strategy);
}