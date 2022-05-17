const { User } = require("../models");
module.exports = async (userId) => {
  const user = await User.findByPk(userId);
  if (!user) {
    createError("user not found", 404);
    return null;
  } else {
    return user;
  }
};
