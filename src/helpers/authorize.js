const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const token = req.header("Auth-Token");

  try {
    // 1. CHECK IF TOKEN EXIST
    if (!token) {
      return res.status(400).send("Unauthorized");
    }
    // 2. VERIFY TOKEN
    const { uid } = jwt.verify(token, process.env.JWT_PASS);

    // 3. MODIFY OBJECT REQ
    req.uid = uid;
    next();
  } catch (error) {
    return res.status(400).send(error.message);
  }
};
