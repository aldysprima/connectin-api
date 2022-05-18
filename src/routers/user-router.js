const routers = require("express").Router();

// import controller

const { users } = require("../controllers");
const authorize = require("../helpers/authorize");
const uploader = require("../helpers/multer");

routers.post("/users/register", users.registerUser);
routers.get("/users/getuser", authorize, users.getUser);
routers.get("/users/getuserbyid/:uid", users.getUserById);
routers.patch("/users/updateprofile/:uid", users.updateUser);
routers.get("/auth/verify/:token", users.verifyUser);
routers.get("/auth/refresh-token", users.refreshToken);
routers.post("/auth/login", users.loginUser);
routers.get("/auth/keeplogin", authorize, users.keepLogin);
routers.post(
  "/users/add-profile-picture/:uid",
  uploader.single("image"),
  users.AddProfilePicture
);

module.exports = routers;
