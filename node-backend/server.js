require('dotenv').config();
const jwt = require('jsonwebtoken');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dns').setServers(['8.8.8.8', '8.8.4.4']);
const user= require("./model/user");
const authMiddleware = require("./middleware/authMiddleware.js");
const app = express();
app.use(express.json());

// =====================
// MongoDB Connection
// =====================

mongoose.connect(
  process.env.MONGODB_URI, 
)
.then(() => console.log("✅ MongoDB Connected"))
.catch((err) => console.log("❌ MongoDB Connection Error:", err.message));

// =====================
// User Schema & Model
// =====================

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", userSchema);

// =====================
// Create User Route
// =====================

app.post("/create-user", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email, and password are required",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    res.json({
      message: "User saved successfully",
      user,
    });

  } catch (error) {
    res.status(500).json({
      message: "Error saving user",
      error: error.message,
    });
  }
});

// =====================
// Register Route
// =====================

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }

    // 🔥 Hash password
    const hashedPassword = await bcrypt.hash(password, 10);


const user = await User.create({
  name,
  email,
  password: hashedPassword,
});

const isMatch = await bcrypt.compare(password, user.password);

if (!isMatch) {
  return res.status(401).json({
    message: "Invalid password",
  });
}
    res.status(201).json({
      message: "User registered successfully",
    });

  } catch (error) {
    res.status(500).json({
      message: "Registration failed",
      error: error.message,
    });
  }
});


// ================= LOGIN =================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password required",
      });
    }

    // Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // 🔥 Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid password",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
    });

  } catch (error) {
    res.status(500).json({
      message: "Login failed",
      error: error.message,
    });
  }
});

// ================= PROFILE =================
app.get("/api/profile", async (req, res) => {
  try {
    // 1️⃣ Header se token lo
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Extract token from "Bearer <token>"
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : authHeader;

    // 2️⃣ Token verify karo
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "mysecretkey");

    // 3️⃣ User find karo
    const user = await User.findById(decoded.id).select("-password");

    res.status(200).json(user);

  } catch (error) {
    res.status(401).json({
      message: "Invalid token",
    });
  }
});


// ================= SERVER =================
app.listen(5000, () => {
  console.log("Express server running on port 5000");
});    