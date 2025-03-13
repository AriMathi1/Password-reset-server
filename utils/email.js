const nodemailer = require("nodemailer");
require("dotenv").config();

// Configure email transporter
const configureTransporter = () => {
  // For production, use your preferred email service
  // Example with Gmail SMTP
  return nodemailer.createTransport({
    service: "gmail", // Or use SMTP details directly
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
};

// Send password reset email
const sendResetEmail = async (email, resetToken) => {
  try {
    const transporter = configureTransporter();
    
    // Create reset URL (frontend URL will depend on your setup)
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    // Set up email options
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request",
      html: `
        <h1>Password Reset</h1>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetUrl}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };
    
    // Send the email
    const info = await transporter.sendMail(mailOptions);
    console.log("Password reset email sent: ", info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error("Error sending reset email:", error);
    return { success: false, error: error.message };
  }
};

// Generate random reset token
const generateResetToken = () => {
  // Generate a random 32-byte hex string
  return require("crypto").randomBytes(32).toString("hex");
};

module.exports = {
  sendResetEmail,
  generateResetToken
};