const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { pool } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, email, name, username, birthday, house_unit, street_name, barangay, city_municipality, province, zip_code, avatar, email_verified, onboarding_completed, created_at FROM users WHERE id = ?',
      [req.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user: users[0] });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ message: 'Server error while fetching profile' });
  }
});

// Update user profile
router.put('/profile', [
  authenticateToken,
  body('name').optional().trim().isLength({ min: 2 }),
  body('email').optional().isEmail().normalizeEmail(),
  body('username').optional().trim().isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
  body('birthday').optional().isISO8601(),
  body('house_unit').optional().trim().isLength({ max: 100 }),
  body('street_name').optional().trim().isLength({ max: 100 }),
  body('barangay').optional().trim().isLength({ max: 100 }),
  body('city_municipality').optional().trim().isLength({ max: 100 }),
  body('province').optional().trim().isLength({ max: 100 }),
  body('zip_code').optional().trim().isLength({ max: 10 }),
  body('avatar').optional().custom((value) => {
    if (!value) return true; // Allow empty values
    // Check if it's a base64 string or a URL
    if (value.startsWith('data:image/') || value.startsWith('http')) {
      return true;
    }
    throw new Error('Avatar must be a valid base64 image or URL');
  })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { name, email, username, birthday, house_unit, street_name, barangay, city_municipality, province, zip_code, avatar } = req.body;
    const updates = [];
    const values = [];

    // Check for duplicate email if provided
    if (email) {
      const [existingUsers] = await pool.execute(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        [email, req.userId]
      );
      if (existingUsers.length > 0) {
        return res.status(400).json({ message: 'Email already in use' });
      }
    }

    // Check for duplicate username if provided
    if (username) {
      const [existingUsers] = await pool.execute(
        'SELECT id FROM users WHERE username = ? AND id != ?',
        [username, req.userId]
      );
      if (existingUsers.length > 0) {
        return res.status(400).json({ message: 'Username already in use' });
      }
    }

    // Build update query
    if (name) {
      updates.push('name = ?');
      values.push(name);
    }
    if (email) {
      updates.push('email = ?');
      values.push(email);
    }
    if (username) {
      updates.push('username = ?');
      values.push(username);
    }
    if (birthday) {
      updates.push('birthday = ?');
      values.push(birthday);
    }
    if (house_unit) {
      updates.push('house_unit = ?');
      values.push(house_unit);
    }
    if (street_name) {
      updates.push('street_name = ?');
      values.push(street_name);
    }
    if (barangay) {
      updates.push('barangay = ?');
      values.push(barangay);
    }
    if (city_municipality) {
      updates.push('city_municipality = ?');
      values.push(city_municipality);
    }
    if (province) {
      updates.push('province = ?');
      values.push(province);
    }
    if (zip_code) {
      updates.push('zip_code = ?');
      values.push(zip_code);
    }
    if (avatar) {
      updates.push('avatar = ?');
      values.push(avatar);
    }

    if (updates.length === 0) {
      return res.status(400).json({ message: 'No fields to update' });
    }

    values.push(req.userId);

    await pool.execute(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    // Get updated user
    const [users] = await pool.execute(
      'SELECT id, email, name, username, birthday, house_unit, street_name, barangay, city_municipality, province, zip_code, avatar, email_verified, onboarding_completed FROM users WHERE id = ?',
      [req.userId]
    );

    res.json({
      message: 'Profile updated successfully',
      user: users[0]
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error while updating profile' });
  }
});

// Change password
router.put('/change-password', [
  authenticateToken,
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
    }

    const { currentPassword, newPassword } = req.body;

    // Get current user
    const [users] = await pool.execute(
      'SELECT password FROM users WHERE id = ?',
      [req.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, users[0].password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    await pool.execute(
      'UPDATE users SET password = ? WHERE id = ?',
      [hashedPassword, req.userId]
    );

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error while changing password' });
  }
});

// Complete onboarding
router.post('/complete-onboarding', authenticateToken, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE users SET onboarding_completed = TRUE WHERE id = ?',
      [req.userId]
    );

    res.json({
      message: 'Onboarding completed successfully'
    });
  } catch (error) {
    console.error('Complete onboarding error:', error);
    res.status(500).json({ message: 'Server error while completing onboarding' });
  }
});

module.exports = router;
