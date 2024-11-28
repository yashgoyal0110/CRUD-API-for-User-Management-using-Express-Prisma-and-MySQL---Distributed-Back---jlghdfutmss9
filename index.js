const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const jwt = require('jsonwebtoken')

dotenv.config();

const app = express();

app.use(express.json());
let bcryptKey =
  "68d97a7b7965450091cd86a139a66caaca857c05511860b11b0064e388ba105328de791c8336dd7561f52ea7f2fa64f2d09810cfea12978b571cdceab05270b";
app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if(!email){
    return res.status(400).json({
      "error" : "Email is required"
    })
  }
  if(!password){
    return res.status(400).json({
      "error" : "Password is required"
    })
  }
  let existingUser = await prisma.User.findUnique({
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
});

app.post('/api/auth/login', async(req, res)=>{
  const {email, password} = req.body;
  if(!email || !password){
    return res.status(400).json({
      "error": "Email and password are required"
    })
  }
  let existingUser = await prisma.User.findUnique({
    where: { email },
  });
  if(!existingUser){
    return res.status(404).json({
      "error": "User not found"
    })
  }
  let userPassword = existingUser.password
  let matchedPass = await bcrypt.compare(password, userPassword)
  if(!matchedPass){
    return res.status(401).json({
      "error": "Invalid credentials"
    })
  }
  return res.status(200).json({
    userdata: {"id" : existingUser.id, "name" : existingUser.name, "email" : existingUser.email}, accesstoken: jwt.sign(existingUser, bcryptKey)
  })
})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports = app;
