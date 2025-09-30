const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { pool } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { sendEmailVerification, sendWelcomeEmail, sendPasswordResetEmail } = require('../utils/email');

const router = express.Router();

// Register
router.post('/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('name').trim().isLength({ min: 2 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { email, password, name } = req.body;

    // Check if user exists
    const [existingUser] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate email verification token
    const verificationToken = jwt.sign(
      { email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Create user
    const [result] = await pool.execute(
      'INSERT INTO users (email, password, name, provider, email_verification_token, onboarding_completed) VALUES (?, ?, ?, ?, ?, ?)',
      [email, hashedPassword, name, 'email', verificationToken, false]
    );

    const userId = result.insertId;

    // Send email verification
    try {
      await sendEmailVerification(email, name, verificationToken);
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      // Don't fail registration if email fails
    }

    res.status(201).json({
      message: 'User created successfully. Please check your email to verify your account.',
      user: { id: userId, email, name }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
router.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { email, password } = req.body;

    // Find user
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];

    // Check if email is verified
    if (!user.email_verified) {
      return res.status(401).json({ message: 'Please verify your email before signing in' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// OAuth Sign In (for NextAuth.js)
router.post('/oauth-signin', async (req, res) => {
  try {
    const { email, name, provider, providerId } = req.body;

    if (!email || !name || !provider) {
      return res.status(400).json({ message: 'Missing required OAuth data' });
    }

    // Check if user exists
    const [existingUsers] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    let user;

    if (existingUsers.length > 0) {
      // Update existing user
      user = existingUsers[0];
      await pool.execute(
        'UPDATE users SET name = ?, provider = ?, provider_id = ?, email_verified = ? WHERE id = ?',
        [name, provider, providerId, true, user.id]
      );
      user.name = name;
    } else {
      // Create new user
      const [result] = await pool.execute(
        'INSERT INTO users (email, name, provider, provider_id, email_verified, onboarding_completed) VALUES (?, ?, ?, ?, ?, ?)',
        [email, name, provider, providerId, true, false]
      );

      user = { id: result.insertId, email, name };
    }

    res.json({
      message: 'OAuth sign in successful',
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name
      }
    });
  } catch (error) {
    console.error('OAuth sign in error:', error);
    res.status(500).json({ message: 'Server error during OAuth sign in' });
  }
});

// Email Verification
router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: 'Verification token is required' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Find user and verify email
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ? AND email_verification_token = ?',
      [decoded.email, token]
    );

    if (users.length === 0) {
      // Check if user exists but is already verified
      const [existingUsers] = await pool.execute(
        'SELECT email_verified FROM users WHERE email = ?',
        [decoded.email]
      );
      
      if (existingUsers.length > 0 && existingUsers[0].email_verified) {
        return res.status(400).json({ 
          message: 'Email is already verified. You can sign in to your account.',
          alreadyVerified: true
        });
      }
      
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    const user = users[0];

    // Update user as verified
    await pool.execute(
      'UPDATE users SET email_verified = TRUE, email_verification_token = NULL WHERE id = ?',
      [user.id]
    );

    // Send welcome email
    try {
      await sendWelcomeEmail(user.email, user.name);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
    }

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Verification token has expired' });
    }
    console.error('Email verification error:', error);
    res.status(500).json({ message: 'Server error during email verification' });
  }
});


// Forgot Password
router.post('/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { email } = req.body;

    // Check if user exists
    const [users] = await pool.execute(
      'SELECT id, name FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = users[0];

    // Generate reset token
    const resetToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Store reset token in database
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour
    await pool.execute(
      'UPDATE users SET reset_password_token = ?, reset_password_expires = ? WHERE id = ?',
      [resetToken, resetExpires, user.id]
    );

    // Send password reset email
    try {
      await sendPasswordResetEmail(email, user.name, resetToken);
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      return res.status(500).json({ message: 'Failed to send password reset email' });
    }

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

// Reset Password
router.post('/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { token, password } = req.body;

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Check if token exists and is not expired
    const [users] = await pool.execute(
      'SELECT id FROM users WHERE id = ? AND reset_password_token = ? AND reset_password_expires > NOW()',
      [decoded.userId, token]
    );

    if (users.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Update password and clear reset token
    await pool.execute(
      'UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?',
      [hashedPassword, decoded.userId]
    );

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Reset token has expired' });
    }
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error during logout' });
  }
});

module.exports = router;
