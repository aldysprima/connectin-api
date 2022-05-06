const database = require("../config").promise();
const { registerUserSchema } = require("../helpers/validation-schema");

const uuid = require("uuid");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

///////////REGISTER USER/////////////
module.exports.registerUser = async (req, res) => {
  const { username, email, password, confirm_password } = req.body;

  try {
    // 1. verify password & confirm password
    if (password !== confirm_password) {
      return res
        .status(400)
        .send("Password and confirm password doesn't match");
    }
    // 2. Verify req.body by our schema
    const { error } = registerUserSchema.validate(req.body);
    if (error) {
      console.log(error);
      return res.status(400).send(error.details[0].message);
    }

    // 3. Verify if username is unique
    const CHECK_USERNAME = `select * from users where username = ?`;
    const [USERNAME] = await database.execute(CHECK_USERNAME, [username]);
    if (USERNAME.length) {
      return res.status(400).send("Username has already exists");
    }

    // 4. Verify if email is unique
    const CHECK_EMAIL = `select * from users where email = ?`;
    const [EMAIL] = await database.execute(CHECK_EMAIL, [email]);
    if (EMAIL.length) {
      return res.status(400).send("Email has already Taken");
    }

    // 5. Generate uuid

    uid = uuid.v4();
    console.log(req.body);

    // 6. Hash Password
    const salt = await bcrypt.genSalt(10);
    console.log("Salt :", salt);

    const hashedPassword = await bcrypt.hash(password, salt);
    console.log("plain password :", password);
    console.log("Hashed Password :", hashedPassword);

    // 7. Do Query Insert to database

    const INSERT_USER = `insert into users(uid, username, email, password) values(?, ?, ?, ?)`;
    const [INFO] = await database.execute(INSERT_USER, [
      uid,
      username,
      email,
      hashedPassword,
    ]);

    // 8. Create Web Token
    const token = jwt.sign({ username, email }, process.env.JWT_PASS, {
      expiresIn: "120s",
    });

    // 9. Store Tokens to our database
    const STORE_TOKEN = `insert into tokens(uid, jwt) values(?, ?)`;
    await database.execute(STORE_TOKEN, [uid, token]);

    // 10. send Email to the client
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "aldysprima.soc@gmail.com",
        pass: process.env.MAIL_PASS,
      },
      tls: { rejectUnauthorized: false },
    });

    transporter.sendMail({
      from: "aldysprima.soc@gmail.com",
      to: email,
      subject: "Verify Your Newly-Created Connect.In Account ",
      html: `
      <h1>Thanks For Signing Up for Connect.In!</h1>
      <p>We're Happy that you're here. Let's get your account verified by clicking the link below</p>
      <p>By Verifying your account, you get access to all of the features available on our Platform</p>
      <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
      `,
    });

    res
      .header("UID", uid)
      .status(201)
      .send("Account Has Been Created, Please verify Your Account");
  } catch (error) {
    console.log("error :", error);
    res.status(500).send("Internal service Error");
  }
};

///////////GET ALL USERS/////////////

module.exports.getUser = async (req, res) => {
  try {
    const GET_USERS = `select * from users`;

    const [USERS] = await database.execute(GET_USERS);

    for (let i = 0; i < USERS.length; i++) {
      delete USERS[i].password;
    }

    res.status(200).send(USERS);
  } catch (error) {
    console.log("error :", error);
    res.status(500).send("Internal service Error");
  }
};

///////////GET USERS BY UID/////////////

module.exports.getUserById = async (req, res) => {
  const uid = req.params.uid;

  try {
    const CHECK_USER = `select * from users where uid = ? `;
    const [USER] = await database.execute(CHECK_USER, [uid]);
    if (!USER.length) {
      res.status(404).send(`User with UID ${uid} is not found`);
    }
    delete USER[0].password;
    res.status(200).send(USER[0]);
  } catch (error) {
    console.log("error :", error);
    res.status(500).send("Internal service Error");
  }
};

///////////VERIFY USER ACCOUNT/////////////
module.exports.verifyUser = async (req, res) => {
  const token = req.body.token;
  const uid = req.header("UID");

  try {
    // 1. TOKEN VALIDATION
    const CHECK_TOKEN = `select * from tokens where uid = ? AND jwt = ?`;
    const [TOKEN] = await database.execute(CHECK_TOKEN, [uid, token]);
    if (!TOKEN.length) {
      return res.status(404).send("Token Is Invalid");
    } else {
      try {
        jwt.verify(token, process.env.JWT_PASS);
      } catch (error) {
        return res
          .status(400)
          .send(`An Error has occured: ${error.name} ${error.expiredAt}`);
      }
    }
    // 3. CHANGE USER STATUS
    const UPDATE_USER_STATUS = `update users set status = 1 where uid = ?`;
    await database.execute(UPDATE_USER_STATUS, [uid]);
    // 4. DELETE TOKEN
    const DELETE_TOKEN = "delete from tokens where uid = ? and jwt = ?";
    await database.execute(DELETE_TOKEN, [uid, token]);
    // 5. CREATE RESPOND
    return res.status(200).send("OK");
  } catch (error) {
    console.log("error :", error);
    return res.status(500).send("Internal service Error");
  }
};
