const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");
const passport = require('passport')
const {User} = require('../models')

const options = {
    secretOrKey: process.env.JWT_SECRET_KEY || 'qwertyuiop',
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
}

passport.use(new JwtStrategy(options, async (payload, done) => {
    try {
        const user = await User.findOne({ where: { id: payload.id } });
        if (!user) {
            done(new Error('user not found'), false)
        }
        if (payload.iat * 1000 < new Date(user.lastUpdatePassword).getTime()) {
          done(new Error('you are unauthorized'), false)
        }
    
        done(null, user) // req.user = user
    } catch (err) {
        done(err, false)
    }
}))