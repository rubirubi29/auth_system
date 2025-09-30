const mysql = require('mysql2/promise');
require('dotenv').config();

// Create connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'auth_system',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Database connected successfully');
    connection.release();
    
    // Create tables if they don't exist
    await createTables();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    process.exit(1);
  }
}

// Create tables
async function createTables() {
  try {
    // Create users table (simplified)
    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        username VARCHAR(50) UNIQUE,
        password VARCHAR(255),
        provider VARCHAR(50) DEFAULT 'email',
        provider_id VARCHAR(255),
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_token VARCHAR(255),
        reset_password_token VARCHAR(255),
        reset_password_expires DATETIME,
        birthday DATE,
        house_unit VARCHAR(100),
        street_name VARCHAR(100),
        barangay VARCHAR(100),
        city_municipality VARCHAR(100),
        province VARCHAR(100),
        zip_code VARCHAR(10),
        avatar VARCHAR(500),
        onboarding_completed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `;

    await pool.execute(createUsersTable);
    
    // Create indexes for better performance
    const createIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(email_verification_token)',
      'CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_password_token)'
    ];

    for (const indexQuery of createIndexes) {
      try {
        await pool.execute(indexQuery);
      } catch (error) {
        // Index might already exist, ignore error
      }
    }
    
    console.log('✅ Database tables created/verified successfully');
  } catch (error) {
    console.error('❌ Error creating tables:', error.message);
  }
}

module.exports = { pool, testConnection };
