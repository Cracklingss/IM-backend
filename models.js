const db = require("./db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { get } = require("./routes");
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;

const login = async (req, res) => {
  const { email, password } = req.body;

  const [ user ] = await db.query(`SELECT * FROM users WHERE email = ?`, [email]);
  console.log(user);

  if(!user){
    return res.json({ message: "No user found" });
  }

  const payload = { email: user.email, isOnboarded: user.isOnboarded };

  const validPass = await bcrypt.compare(password, user.password);
  console.log(validPass);
  if(!validPass) return res.json({ status: false, message: "Invalid Email or Password" });

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 60 * 60 * 1000,
  })

  res.json({ status: true, message: "Login Successful!", isOnboarded: user.isOnboarded });
}

const logout = async (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "strict"
  })

  res.json({ status: true, message: "Logout Successfull" });
}

const changePass = async (req, res) => {
  console.log(req.body);
  const { email, currentPassword, newPassword } = req.body.formData;
  console.log(email,currentPassword,newPassword);

  try {
    const rows = await db.query(`SELECT password FROM users WHERE email = ?`, [email]);

    if (rows.length === 0) {
      return res.json({ status: false, message: "User not found" });
    }

    const oldPassDB = rows[0].password;

    const validPass = await bcrypt.compare(currentPassword, oldPassDB);
    if (!validPass) {
      return res.json({ status: false, message: "Current Password Invalid!" });
    }

    const hashedNewPass = await bcrypt.hash(newPassword, 10);

    await db.query(`UPDATE users SET password = ? WHERE email = ?`, [hashedNewPass, email]);

    res.json({ status: true, message: "Password changed successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: false, message: "Server error" });
  }
};

const forgotPass = async (req, res) => {
  console.log(req.body);
  const { email, petsName, newPass } = req.body;

  const [result] = await db.query(`SELECT petsName FROM users WHERE email = ?`, [email]);
  console.log(result);

  if(result.petsName === petsName){
    const hashedNewPass = await bcrypt.hash(newPass, 10);
    await db.query(`
      UPDATE users
      SET password = ?
      WHERE email = ?
    `, [hashedNewPass, email]);
  }
  res.json({ status: true, message: "Success" });
}

const changeProfile = async (req, res) => {
  console.log(req.body);
  const { firstName, lastName, petsName } = req.body;
  const token = req.cookies.token;
  console.log(token);

  if (!token) {
    return res.status(401).json({ status: false, message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    await db.query(`
      UPDATE users
      SET firstName = ?, lastName = ?, petsName = ?
      WHERE email = ?
    `, [firstName, lastName, petsName, email]);

    res.json({ status: true, message: "Profile updated successfully!", email: email });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: false, message: "Server error" });
  }
};

const getCookies = async (req, res) => {
  const token = req.cookies.token;
  const decoded = jwt.verify(token, JWT_SECRET);
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  const [ user ] = await db.query(`SELECT * FROM users WHERE email = ?`, [decoded.email]);


  try {
    res.json({ email: decoded.email, firstName: user.firstName, lastName: user.lastName, petsName: user.petsName });
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

const onBoarding = async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { firstName, lastName, petsName } = req.body;

    await db.query(
      `UPDATE users SET firstName = ?, lastName = ?, petsName = ?, isOnboarded = TRUE WHERE email = ?`,
      [firstName, lastName, petsName, decoded.email]
    );

    res.json({ status: true, message: "Onboarding completed!" });
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

module.exports = { login, logout, changePass, forgotPass, changeProfile, getCookies, onBoarding };