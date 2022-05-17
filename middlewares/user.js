const {User} = require('../models')
exports.findUser = async( req,res,next)=> {
    try {
        const { userId } = req.body;
    
        const user = await User.findByPk(userId);
        if (!user) {
          createError("user not found", 400);
        }
        next()
    } catch (error) {
        next(error);
    }
}