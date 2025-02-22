const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const pool = new Pool({
  user: 'agoravotedb',
  host: 'localhost',
  database: 'avdb',
  password: 'agoravotedb&99$',
  port: 5432,
});

const saltRounds = 10;
const jwtSecret = 'your_jwt_secret';

async function createUser(username, email, password) {
  const client = await pool.connect();
  try {
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const result = await client.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING *',
      [username, email, passwordHash]
    );
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function authenticateUser(username, password) {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (user && await bcrypt.compare(password, user.password_hash)) {
      const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
      return { user, token };
    }
    return null;
  } finally {
    client.release();
  }
}

async function createRefreshToken(userId) {
  const client = await pool.connect();
  try {
    const token = jwt.sign({ userId }, jwtSecret, { expiresIn: '7d' });
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await client.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [userId, token, expiresAt]
    );
    return token;
  } finally {
    client.release();
  }
}

async function verifyRefreshToken(token) {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM refresh_tokens WHERE token = $1', [token]);
    const refreshToken = result.rows[0];
    if (refreshToken && refreshToken.expires_at > new Date()) {
      return jwt.verify(token, jwtSecret);
    }
    return null;
  } finally {
    client.release();
  }
}

// test connection - can delete

async function testConnection() {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT NOW()');
    console.log(res.rows[0]);
  } finally {
    client.release();
  }
}

// test connection - end

testConnection().catch(err => console.error('Error testing connection:', err));

module.exports = {
  createUser,
  authenticateUser,
  createRefreshToken,
  verifyRefreshToken,
};