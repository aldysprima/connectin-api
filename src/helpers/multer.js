const multer = require("multer");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/profiles");
  },
  filename: function (req, file, cb) {
    cb(null, `IMG-` + Date.now() + ".jpg");
  },
});

module.exports = multer({ storage: storage, limits: 1000000 });
