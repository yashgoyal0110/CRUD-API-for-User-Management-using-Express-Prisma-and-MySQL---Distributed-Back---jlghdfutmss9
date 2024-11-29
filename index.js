const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  console.log("getApi");
});
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email) {
      return res.status(400).json({
        error: "Email is required",
      });
    }
    if (!password) {
      return res.status(400).json({
        error: "Password is required",
      });
    }
    let existingUser = await prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      return res.status(400).json({
        error: "Email already in use",
      });
    }
    let bcryptedPass = await bcrypt.hash(password, 10);
    const createdUser = await prisma.user.create({
      data: {
        name,
        email,
        password: bcryptedPass,
      },
    });

    return res.status(201).json({
      message: "User created successfully",
      userId: createdUser.id,
    });
  } catch (err) {
    console.log(err.message);
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });
    if (!existingUser) {
      return res.status(404).json({
        error: "User not found",
      });
    }
    const userPassword = existingUser.password;
    const matchedPass = await bcrypt.compare(password, userPassword);
    if (matchedPass === false) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }
    return res.status(200).json({
      userdata: {
        id: existingUser.id,
        name: existingUser.name,
        email: existingUser.email,
      },
      accesstoken: jwt.sign(
        { email: existingUser.email },
        process.env.JWT_SECRET
      ),
    });
  } catch (err) {
    return res.status(500).json({ err: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports = app;
