const database = require("../config").promise();

// Import Schema from Joi

const {
  sendResetPassEmailSchema,
  setNewPassword,
} = require("../helpers/validation-schema");

//

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const transporter = require("../helpers/transporter");

///////
// Send Link to registered email
//////

module.exports.sendResetPasswordLink = async (req, res) => {
  const body = req.body;

  try {
    //1. Validate Email
    const { error } = sendResetPassEmailSchema.validate(body);
    if (error) {
      console.log(error);
      return res.status(400).send(error.details[0].message);
    }
    //2. Check if Email is registered
    const CHECK_EMAIL = `select * from users where email = ?`;
    const [EMAIL] = await database.execute(CHECK_EMAIL, [body.email]);
    if (!EMAIL.length) {
      return res.status(404).send("Email is not registered");
    }
    //3. generate token
    const token = jwt.sign({ UID: EMAIL[0].uid }, process.env.JWT_PASS, {
      expiresIn: "180s",
    });

    //4. Send Email
    await transporter.sendMail({
      from: "'Connect.In' <aldysprima.soc@gmail.com>",
      to: EMAIL[0].email,
      subject: "Reset Password Confirmation",
      html: `
        <h1 style="text-align: center;">Reset Your Password</h1>
        <p>We have received your request to reset the password for your account</p>
        <p>To reset your password, click on the link below</p>
        <p>${process.env.CLIENT_URL}/reset-password/${token}</p>
        `,
    });
    res.status(200).send("Email has been sent to reset your password");
  } catch (error) {
    console.log("error :", error);
    return res.status(500).send("Internal service Error");
  }
};

///////
// Verify reset password Link
//////

module.exports.verifyResetPassword = async (req, res) => {
  const token = req.params.token;

  try {
    try {
      const { UID } = await jwt.verify(token, process.env.JWT_PASS);
      res.status(200).send(UID);
    } catch (error) {
      return res.status(400).send(error.name);
    }
  } catch (error) {
    return res.status(500).send("Internal service Error");
  }
};

///////
// Set New Password
//////

module.exports.setNewPassword = async (req, res) => {
  const { password, UID, confirm_password } = req.body;
  try {
    // 1. verify password & confirm password
    if (password !== confirm_password) {
      return res
        .status(400)
        .send("Password and confirm password doesn't match");
    }

    // 2. Validate New Password
    const { error } = setNewPassword.validate(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }

    // 3. Hash New Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 4. Update Password
    const UPDATE_PASSWORD = `update users set password = ? where uid = ?`;
    await database.execute(UPDATE_PASSWORD, [hashedPassword, UID]);

    res.status(200).send("Password Has Been Changed");
  } catch (error) {
    return res.status(500).send("Internal service Error");
  }
};
