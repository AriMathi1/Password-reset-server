const express = require("express");
const cors = require("cors");
const mongodb = require("mongodb");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const MongoClient = mongodb.MongoClient;
require("dotenv").config();
const { sendResetEmail, generateResetToken } = require("./utils/email");

const app = express.Router();

const URL = process.env.DB || "mongodb://127.0.0.1:27017";
mongoose.connect(URL);

const { User } = require("./models/users");

app.use(express.json());

function authorizer(req, res, next) {
    try {
        const token = req.header("Authorization")?.split(" ")[1];
        if (!token) {
            res.status(401).json({ message: "Not Authorized" });
        }
        console.log(token)
        const payload = jwt.verify(token, process.env.SECRET_KEY);
        if (payload) {
            next();
        } else {
            res.status(401).json({ message: "Not Authorized" });
        }
    } catch (error) {
        res.status(500).json({ message: "something went wrong" });
    }
}

app.post("/register", async (req, res) => {
    try {
        const salt = await bcryptjs.genSalt(10)
        const hash = await bcryptjs.hashSync(req.body.password, salt)
        console.log(hash)

        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hash,
        });

        await user.save();

        res.json({ message: "User registered" });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
});

app.post("/login", async (req, res) => {
    try {
        //find the user by email
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(401).json({ message: "Email or Password is incorrect" });
        }
        //hash the password and compare with user password
        const isPasswordSame = bcryptjs.compareSync(req.body.password, user.password);

        if (isPasswordSame) {
            let token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
                expiresIn: "1h"
            });
            return res.json({ message: "success", token });
        } else {
            return res.status(401).json({ message: "Email or Password is incorrect" });
        }
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "something went wrong" });
    }
});

app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email input
        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            // For security reasons, don't reveal if email exists or not
            return res.status(200).json({
                message: "If your email is registered, you will receive a password reset link"
            });
        }

        // Generate a reset token
        const resetToken = generateResetToken();

        // Set token expiration (1 hour from now)
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour in milliseconds

        // Save token and expiry to user record
        user.resetToken = resetToken;
        user.resetTokenExpiry = resetTokenExpiry;
        await user.save();

        // Send reset email
        const emailResult = await sendResetEmail(user.email, resetToken);

        if (!emailResult.success) {
            console.error("Failed to send email:", emailResult.error);
            return res.status(500).json({ message: "Failed to send reset email" });
        }

        // Return success message (same as if user not found for security)
        return res.status(200).json({
            message: "If your email is registered, you will receive a password reset link"
        });

    } catch (error) {
        console.error("Forgot password error:", error);
        res.status(500).json({ message: "Something went wrong" });
    }
});

/**
 * 2. Verify Reset Token Endpoint
 * - Checks if token exists and is not expired
 */
app.get("/reset-password/:token", async (req, res) => {
    try {
        const { token } = req.params;

        // Find user with this token and ensure it's not expired
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiry: { $gt: new Date() } // Token expiry must be greater than current time
        });

        if (!user) {
            return res.status(400).json({
                valid: false,
                message: "Password reset link is invalid or has expired"
            });
        }

        // Token is valid
        return res.status(200).json({
            valid: true,
            message: "Token is valid"
        });

    } catch (error) {
        console.error("Token verification error:", error);
        res.status(500).json({
            valid: false,
            message: "Something went wrong"
        });
    }
});

/**
 * 3. Reset Password Endpoint
 * - Updates password if token is valid
 */
app.post("/reset-password/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const { password, confirmPassword } = req.body;

        // Validate password input
        if (!password || !confirmPassword) {
            return res.status(400).json({ message: "Password and confirmation are required" });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Check password strength (optional but recommended)
        if (password.length < 8) {
            return res.status(400).json({ message: "Password must be at least 8 characters long" });
        }

        // Find user with this token and ensure it's not expired
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiry: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({ message: "Password reset link is invalid or has expired" });
        }

        // Hash the new password
        const salt = await bcryptjs.genSalt(10);
        const hashedPassword = await bcryptjs.hash(password, salt);

        // Update user's password and clear reset token fields
        user.password = hashedPassword;
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();

        return res.status(200).json({ message: "Password has been reset successfully" });

    } catch (error) {
        console.error("Password reset error:", error);
        res.status(500).json({ message: "Something went wrong" });
    }
});

module.exports = app;