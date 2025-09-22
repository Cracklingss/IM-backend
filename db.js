const mysql = require("serverless-mysql");
const bcrypt = require("bcryptjs");

const db = mysql({
  config: {
    host: "localhost",
    database: "section_a",
    user: "root",
    password: "",
    port: 3306,
  },
});

// const insertUser = async () => {
//   try {
//     const email = "jameboy@gmail.com";
//     const password = "123456";
//     const petsName = "Brownie";

//     const existing = await db.query(
//       `SELECT id FROM users WHERE email = ? LIMIT 1`,
//       [email]
//     );

//     if (existing.length > 0) {
//       console.log("Email already exists. Choose another.");
//       return;
//     }

//     const hashedPass = await bcrypt.hash(password, 10);

//     const result = await db.query(
//       `INSERT INTO users(email, password, petsName) VALUES(?, ?, ?)`,
//       [email, hashedPass, petsName]
//     );

//     console.log("User inserted:", result);
//   } catch (err) {
//     console.error("Error inserting user:", err);
//   } finally {
//     await db.end();
//   }
// };

// insertUser();

module.exports = db;