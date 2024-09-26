const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
var crypto = require("crypto");
const secret = "abcdefg";
const { signupSchema } = require("./schema");
const express = require("express");
const app = express();
app.use(express.json());
app.listen(3000);
const mysql = require("mysql2");
const pool = mysql
  .createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "kaka",
  })
  .promise();

app.post("/password", verifyUser, async (req, res) => {
  try {
    const { email } = req.user;
    const { password } = req.body;
    const passwordSchema = Joi.object({
      password: Joi.string().required(),
    });
    const { error, value } = passwordSchema.validate(req.body);
    if (error) {
      return res.json({ error: error.message });
    } else {
      const hashpassword = await bcrypt.hash(password, 10);

      const [[last]] = await pool.query(
        "select * from  `users`WHERE  email=?",
        [email]
      );
      if (!last) {
        return res.json({ msg: "Invalid PIN" });
      }
      await pool.query("UPDATE `users` SET `password` = ? WHERE  `email` = ?", [
        hashpassword,
        email,
      ]);
      res.json({
        msg: "pin is correct so your password updated",
      });
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});

app.post("/otp", async (req, res) => {
  try {
    const { email, pin } = req.body;
    const passwordSchema = Joi.object({
      email: Joi.string().email().required(),
      pin: Joi.string().required(),
    });
    const { error, value } = passwordSchema.validate(req.body);
    if (error) {
      return res.json({ error: error.message });
    } else {
      const [[last]] = await pool.query("select * from  `users`WHERE pin=? ", [
        pin,
      ]);
      if (!last) {
        return res.json({ msg: "Invalid PIN/email" });
      } else {
        const token = jwt.sign({ email: email }, secret);
        res.json({
          msg: "pin is correct so your jwt updated",
          jwt: token,
        });
      }
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});

app.post("/forgotpassword", async (req, res) => {
  try {
    const email = req.body.email;
    const passwordSchema = Joi.object({
      email: Joi.string().email().required(),
    });
    const { error, value } = passwordSchema.validate(req.body);
    if (error) {
      return res.json({ error: error.message });
    } else {
      const pin = crypto.randomInt(100000, 999999);
      const [sql] = await pool.query(
        "SELECT COUNT(email) AS emailCount FROM users WHERE email = ?",
        [email]
      );

      const emailCount = sql[0].emailCount;

      if (emailCount > 0) {
        const query = await pool.query(
          "UPDATE `users` SET `pin` = ? WHERE  `email` = ?",
          [pin, email]
        );
        res.json({
          msg: "Use this PIN to reset your password",
          pin: pin,
        });
      } else {
        res.status(404).json({ msg: "Email does not exist" });
      }
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [[userDetails]] = await pool.query(
      "select * from  `users` WHERE  email=?",
      [email]
    );
    const a = console.table(userDetails);
    const passwordcheck = await bcrypt.compare(password, userDetails.password);
    if (passwordcheck && userDetails.email === email) {
      return res.json({
        msg: "login success",
      });
    } else {
      return res.json({ msg: "login failed" });
    }
  } catch (err) {
    console.error("Error during password reset:", err);
    res.status(500).json({ msg: "Internal server error" });
    throw err;
  }
});

app.post("/userregistration", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashpassword = await bcrypt.hash(password, 10);
    const { error, value } = signupSchema.validate(req.body);
    if (error) {
      return res.json({ error: error.message });
    } else {
      const [sql] = await pool.query(
        "SELECT COUNT(email) AS emailCount FROM users WHERE email = ?",
        [email]
      );
      const emailCount = sql[0].emailCount;
      if (emailCount > 0) {
        res.json({ msg: "email already exists" });
      } else {
        const qwerty = await pool.query(
          "INSERT INTO `users`(`username`, `email`, `password`) VALUES (?,?,?)",
          [username, email, hashpassword]
        );
        res.json({ msg: "registration done successfully" });
      }
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});

function verifyUser(req, res, next) {
  var token = req.headers.authorization;
  try {
    if (!token) {
      return res.send("Access Denied");
    }
    console.log(token);
    let verify = token.split(" ")[1];
    let verified = jwt.verify(verify, secret);
    console.log(verified);
    req.user = verified;
    next();
  } catch (err) {
    res.send(`Invalid Token ${err.message}`);
  }
}
