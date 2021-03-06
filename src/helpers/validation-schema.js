const Joi = require("joi");
const { joiPassword } = require("joi-password");

module.exports.registerUserSchema = Joi.object({
  username: Joi.string().min(6).max(13).alphanum().required(),
  email: Joi.string().email().required(),
  password: joiPassword
    .string()
    .min(8)
    .minOfSpecialCharacters(1)
    .minOfUppercase(1)
    .minOfNumeric(1)
    .required(),
  confirm_password: Joi.ref("password"),
});

module.exports.emailLoginSchema = Joi.object({
  user: Joi.string().email().required(),
  password: joiPassword
    .string()
    .min(8)
    .minOfSpecialCharacters(1)
    .minOfUppercase(1)
    .minOfNumeric(1)
    .required(),
});

module.exports.usernameLoginSchema = Joi.object({
  user: Joi.string().min(6).max(13).alphanum().required(),
  password: joiPassword
    .string()
    .min(8)
    .minOfSpecialCharacters(1)
    .minOfUppercase(1)
    .minOfNumeric(1)
    .required(),
});

module.exports.updateProfileSchema = Joi.object({
  username: Joi.string().min(6).max(13).alphanum(),
  fullname: Joi.string().max(30),
  bio: Joi.string().max(100),
  address: Joi.string().max(100),
});

module.exports.sendResetPassEmailSchema = Joi.object({
  email: Joi.string().email().required(),
});

module.exports.setNewPassword = Joi.object({
  password: joiPassword
    .string()
    .min(8)
    .minOfSpecialCharacters(1)
    .minOfUppercase(1)
    .minOfNumeric(1)
    .required(),
  confirm_password: Joi.ref("password"),
  UID: Joi.string().required(),
});
