const routers = require("express").Router();

// import controller

const { users } = require("../controllers");
const authorize = require("../helpers/authorize");

routers.post("/users/register", users.registerUser);
routers.get("/users/getuser", authorize, users.getUser);
routers.get("/users/getuserbyid/:uid", users.getUserById);
routers.get("/auth/verify", users.verifyUser);
routers.get("/auth/refresh-token", users.refreshToken);
routers.post("/auth/login", users.loginUser);
routers.get("/auth/keeplogin", authorize, users.keepLogin);

module.exports = routers;
