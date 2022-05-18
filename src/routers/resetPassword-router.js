const routers = require("express").Router();

// import Controller
const { resetPassword } = require("../controllers");

routers.post("/auth/send-email", resetPassword.sendResetPasswordLink);
routers.get("/auth/verify-link/:token", resetPassword.verifyResetPassword);
routers.patch("/auth/change-password", resetPassword.setNewPassword);

module.exports = routers;
