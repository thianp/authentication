const createError = require("../utils/createError");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User } = require("../models");
exports.register = async (req, res, next) => {
  try {
    const { username, email, password, confirmPassword, birthDate } = req.body;
    if (password !== confirmPassword) {
      // # Method 1
      //   return res.status(400).json({ message: "passwords do not match" });

      // # Method 2
      createError("passwords do not match", 400);
    }
    if (!password) {
      createError("password is required", 400);
    }
    if (password.length < 6) {
      createError("password must be at least 6 characters", 400);
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      birthDate,
    });
    res.status(201).json({ message: "user created successfully" });
  } catch (error) {
    next(error);
  }
};

exports.updateUser = async (req, res, next) => {
  try {

    const { email, oldPassword, newPassword, confirmNewPassword, birthDate } =
      req.body;
    const isMatch = await bcrypt.compare(oldPassword, req.user.password);
    if (!isMatch) {
      createError("invalid password", 400);
    }
    // อยู่ใน UserAuthMiddleWare แล้ว
    // const user = await User.findOne({ where: { id:req.user.id } });

    // if (!user) {
    //   createError("user not found", 404);
    // }
    
    const isCorrect = await bcrypt.compare(oldPassword, req.user.password);
    if (!isCorrect) {
      createError("username or password is not correct", 400);
    }

    if (newPassword !== confirmNewPassword) {
      createError("new passwords do not match", 400);
    }
    if (!newPassword) {
      createError("new password is required", 400);
    }
    if (newPassword.length < 6) {
      createError("new password must be at least 6 characters", 400);
    }

    const value = {email, birthDate}

    if (newPassword) {
      console.log(newPassword);
      const hashedPassword = await bcrypt.hash(newPassword, 10)
      value.lastUpdatePassword = new Date()
      value.password = hashedPassword
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const result = await User.update(
      // { email, password: hashedPassword, birthDate, },
      value,
      { where: { id: req.user.id } }
    );
    res.status(200).json({ message: "user updated successfully", result });
  } catch (error) {
    next(error);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username) {
      createError("username is required", 400);
    }
    if (!password) {
      createError("password is required", 400);
    }
    if (password.length < 6) {
      createError("password must be at least 6 characters", 400);
    }
    const user = await User.findOne({ where: { username } });
    if (!user) {
      createError("username or password is not correct", 400);
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      createError("username or password is not correct", 400);
    }
    const payload = { id: user.id, username: user.username };
    const SECRET_KEY = "qwertyuiop";
    const option = { expiresIn: "30d" };
    const token = jwt.sign(payload, SECRET_KEY, option);
    res.json({ message: "login successfully", token: token });
  } catch (error) {
    next(error);
  }
};
