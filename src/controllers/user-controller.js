const database = require("../config").promise();
const {
  registerUserSchema,
  emailLoginSchema,
  usernameLoginSchema,
  updateProfileSchema,
} = require("../helpers/validation-schema");

const uuid = require("uuid");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const transporter = require("../helpers/transporter");

/////////////////////////////////////
///////////AUTH USER/////////////
/////////////////////////////////////

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
    // 6. Hash Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    // 7. Do Query Insert to database
    const INSERT_USER = `insert into users(uid, username, email, password) values(?, ?, ?, ?)`;
    const [INFO] = await database.execute(INSERT_USER, [
      uid,
      username,
      email,
      hashedPassword,
    ]);
    // 8. Create Web Token
    const token = jwt.sign({ UID: uid }, process.env.JWT_PASS, {
      expiresIn: "120s",
    });
    // 9. Store Tokens to our database
    const STORE_TOKEN = `insert into tokens(uid, jwt) values(?, ?)`;
    await database.execute(STORE_TOKEN, [uid, token]);
    // 10. send Email to the client

    await transporter.sendMail({
      from: "'Connect.In' <aldysprima.soc@gmail.com>",
      to: email,
      subject: "Verify Your Newly-Created Connect.In Account ",
      html: `
      <h1>Thanks For Signing Up for Connect.In!</h1>
      <p>We're Happy that you're here. Let's get your account verified by clicking the link below</p>
      <p>By Verifying your account, you get access to all of the features available on our Platform</p>
      <p>${process.env.API_URL}/auth/verify/${token}</p>
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

///////////VERIFY USER ACCOUNT/////////////
module.exports.verifyUser = async (req, res) => {
  const token = req.params.token;
  try {
    // 1. TOKEN VALIDATION
    const CHECK_TOKEN = `select * from tokens where jwt = ?`;
    const [TOKEN] = await database.execute(CHECK_TOKEN, [token]);
    if (!TOKEN.length) {
      return res.status(404).send("Token Is Invalid");
    } else {
      try {
        jwt.verify(token, process.env.JWT_PASS);
      } catch (error) {
        return res.status(400).send(`
          <div style="display: flex; flex-direction: column; align-items: center; justify-content: center;    background-color: #ecf0f1; height:100vh; width: 100vw;">
              <h1 style="font-family: sans-serif; color:#2980b9">Uh-Oh</h1>
              <p style="font-family: sans-serif; color: #3498db">Looks like your token is already expired.</p>
              <p style="font-family: sans-serif; color: #3498db">Go to your profile to request new verification email</p>
          </div>
          `);
      }
    }
    // 2. CHANGE USER STATUS
    const UPDATE_USER_STATUS = `update users set status = 1 where uid = ?`;
    await database.execute(UPDATE_USER_STATUS, [TOKEN[0].uid]);
    // 3. DELETE TOKEN
    const DELETE_TOKEN = "delete from tokens where uid = ? and jwt = ?";
    await database.execute(DELETE_TOKEN, [TOKEN[0].uid, token]);
    // 4. CREATE RESPOND
    return res.status(200).send(`
      <div 
      style="display: flex; flex-direction: column; align-items: center; justify-content: center; background-color: #ecf0f1; height:100vh; width: 100vw; "
      >
        <h1 style="font-family: sans-serif; color:#2980b9">Congratulations!</h1>
        <p style="font-family: sans-serif; color: #3498db">Account Has Been Verified</p>
        <a href="http://localhost:3000" style="font-family: sans-serif; color:#3498db; text-decoration: none">Login</a>
      </div>
    `);
  } catch (error) {
    console.log("error :", error);
    return res.status(500).send("Internal service Error");
  }
};

///////////REFRESH TOKEN/RESEND VERIFICATION EMAIL/////////////
module.exports.refreshToken = async (req, res) => {
  const token = req.body.token;
  const uid = req.header("UID");

  try {
    // 1. CHECK IF THE TOKEN IS EXIST
    const CHECK_TOKEN = `select * from tokens where uid = ? AND jwt = ?`;
    const [TOKEN] = await database.execute(CHECK_TOKEN, [uid, token]);
    if (!TOKEN.length) {
      return res.status(404).send("Token Is Invalid");
    }

    // 2. IF IT EXIST, IS IT ALREADY EXPIRED OR NOT?
    const current = new Date().getTime();
    const created = new Date(TOKEN[0].createdAt).getTime();
    const step = current - created;
    const remaining = Math.floor((120000 - step) / 1000);
    if (step < 120000) {
      return res
        .status(400)
        .send(`Please wait for ${remaining}s to refresh token`);
    }

    // 3. CREATE NEW TOKEN
    const newToken = jwt.sign({ UID: uid }, process.env.JWT_PASS, {
      expiresIn: "120s",
    });
    const now = new Date();

    // 4. UPDATE TO DATABASE
    const UPDATE_TOKEN = `UPDATE tokens set jwt = ?, createdAt = ? where uid = ?`;
    await database.execute(UPDATE_TOKEN, [newToken, now, uid]);

    // 5. SEND NEW TOKEN TO CLIENT
    const GET_USER_EMAIL = `SELECT email from users where uid = ?`;
    const [EMAIL] = await database.execute(GET_USER_EMAIL, [uid]);

    await transporter.sendMail({
      from: "'Connect.In' <aldysprima.soc@gmail.com>",
      to: EMAIL[0].email,
      subject: "Verify Your Newly-Created Connect.In Account ",
      html: `
      <h1>Thanks For Signing Up for Connect.In!</h1>
      <p>We're Happy that you're here. Let's get your account verified by clicking the link below</p>
      <p>By Verifying your account, you get access to all of the features available on our Platform</p>
      <p>${process.env.API_URL}/auth/verify/${newToken}</p>
      `,
    });

    // 6. CREATE RESPOND
    res
      .status(200)
      .send("Refresh Token has been sent. Kindly check your email");
  } catch (error) {
    console.log("error :", error);
    return res.status(500).send("Internal service Error");
  }
};

///////////LOGIN USER/////////////
module.exports.loginUser = async (req, res) => {
  const { user, password } = req.body;

  try {
    // 1. VALIDATE REQ BODY
    if (user.includes("@")) {
      const { error } = emailLoginSchema.validate(req.body);
      if (error) {
        console.log(error);
        return res.status(400).send(error.details[0].message);
      }
    } else {
      const { error } = usernameLoginSchema.validate(req.body);
      if (error) {
        console.log(error);
        return res.status(400).send(error.details[0].message);
      }
    }
    // 2. CHECK IF USER IS EXIST
    const CHECK_USER = `select * from users where username = ? or email = ?`;
    const [USER] = await database.execute(CHECK_USER, [user, user]);
    if (!USER.length) {
      return res.status(400).send("Username or Email not found");
    }

    // 3. IF USER EXIST, COMPARE PASSWORD
    const valid = await bcrypt.compare(password, USER[0].password);
    if (!valid) {
      return res.status(400).send("Wrong Password!");
    }

    // 4. CREATE TOKEN
    const token = jwt.sign({ uid: USER[0].uid }, process.env.JWT_PASS);
    delete USER[0].password;

    res.header("Auth-Token", `Bearer ${token}`).status(200).send(USER[0]);
  } catch (error) {
    console.log("error :", error);
    return res.status(500).send("Internal service Error");
  }
};

///////////KEEP LOGIN/////////////
module.exports.keepLogin = async (req, res) => {
  // const token = req.header("Auth-Token");
  const uid = req.uid;

  try {
    // // 1. CHECK IF REQ CONTAINS TOKEN
    // if (!token) {
    //   return res.status(400).send("Unauthorized");
    // }
    // // 2. IF TOKEN EXIST, VALIDATE TOKEN
    // const { uid } = jwt.verify(token, process.env.JWT_PASS);
    // if (!uid) {
    //   return res.status(400).send("Invalid Token");
    // }
    // 3. IF TOKEN VALID, DO QUERY TO GET USER DATA
    const GET_USER = `select * from users where uid = ?`;
    const [USER] = await database.execute(GET_USER, [uid]);
    // 4. CREATE RESPOND
    delete USER[0].password;
    return res.status(200).send(USER[0]);
  } catch (error) {
    console.log("error :", error);
    return res.status(500).send("Internal service Error");
  }
};

/////////////////////////////////////
///////////RUD USER/////////////
/////////////////////////////////////

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

///////////UPDATE USER PROFILE/////////////
module.exports.updateUser = async (req, res) => {
  const uid = req.params.uid;
  const body = req.body;

  try {
    // 1. CHECK IF THE BODY IS EMPTY
    const isEmpty = !Object.values(body).length;
    if (isEmpty) {
      return res.status(404).send("Please specify data you want to update");
    }

    // 2. VALIDATE REQ BODY
    const { error } = updateProfileSchema.validate(body);
    if (error) {
      return res.status(404).send(error.details[0].message);
    }

    // 3. CHECK NEW USERNAME VALUE IF IT CONTAINS IN REQ.BODY

    if (body.username) {
      const CHECK_USERNAME = `Select * from users where username = ?`;
      const [USERNAME] = await database.execute(CHECK_USERNAME, [
        body.username,
      ]);
      if (USERNAME.length) {
        return res.status(400).send("Username is already exist");
      }
    }

    // 4. DEFINE QUERY UPDATE
    let values = [];
    for (let key in body) {
      values.push(`${key} = '${body[key]}'`);
    }

    const UPDATE_USER = `update users set ${values} where uid = ? `;
    await database.execute(UPDATE_USER, [uid]);

    // SEND RESPOND
    res.status(200).send("Data Has Been Updated");
  } catch (error) {
    console.log("error :", error);
    res.status(500).send("Internal service Error");
  }
};
