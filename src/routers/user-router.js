const routers = require("express").Router();

// import controller

const { users } = require("../controllers");

routers.post("/users/register", users.registerUser);
routers.get("/users/getuser", users.getUser);
routers.get("/users/getuserbyid/:uid", users.getUserById);
routers.get("/auth/verify", users.verifyUser);
routers.get("/auth/refresh-token", users.refreshToken);

module.exports = routers;
