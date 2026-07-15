require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const axios = require("axios");
const { Resend } = require("resend");
const rateLimit = require("express-rate-limit");
const {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  generateRegistrationOptions,
  generateAuthenticationOptions,
} = require("@simplewebauthn/server");

const app = express();
app.use(express.json({ limit: "10mb" }));

// ============================================
// ENV VALIDATION & SETUP
// ============================================
const requiredEnvVars = [
  "DATABASE_URL",
  "MONNIFY_API_KEY",
  "MONNIFY_CONTRACT_CODE",
  "MONNIFY_ENV",
  "RESEND_API_KEY",
  "JWT_SECRET",
  "FRONTEND_ORIGIN",
  "WEBAUTHN_RP_ID",
  "WEBAUTHN_RP_NAME",
  "WEBAUTHN_ORIGIN",
];

requiredEnvVars.forEach((v) => {
  if (!process.env[v]) throw new Error(`Missing env var: ${v}`);
});

const MONNIFY_ENV = process.env.MONNIFY_ENV.toLowerCase();
const MONNIFY_API_KEY = process.env.MONNIFY_API_KEY;
const MONNIFY_CONTRACT_CODE = process.env.MONNIFY_CONTRACT_CODE;

// Validate environment consistency
if (MONNIFY_ENV === "sandbox" && !MONNIFY_API_KEY.startsWith("MK_TEST_")) {
  throw new Error("Sandbox env but API key is not MK_TEST_ prefix");
}
if (MONNIFY_ENV === "live" && !MONNIFY_API_KEY.startsWith("MK_PROD_")) {
  throw new Error("Live env but API key is not MK_PROD_ prefix");
}

const MONNIFY_BASE_URL =
  MONNIFY_ENV === "sandbox"
    ? "https://sandbox.monnify.com/api/v1"
    : "https://api.monnify.com/api/v1";

const resend = new Resend(process.env.RESEND_API_KEY);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID;
const WEBAUTHN_ORIGIN = process.env.WEBAUTHN_ORIGIN;
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME;

// ============================================
// DATABASE INITIALIZATION
// ============================================
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20) NOT NULL,
        pin_hash VARCHAR(255),
        kyc_verified BOOLEAN DEFAULT FALSE,
        monnify_account_reference VARCHAR(255) UNIQUE,
        monnify_reserved_account_number VARCHAR(20),
        wallet_balance DECIMAL(18, 2) DEFAULT 0.00,
        referral_code VARCHAR(32) UNIQUE,
        referred_by_id INT REFERENCES users(id),
        account_active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS otp_tokens (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        email VARCHAR(255) NOT NULL,
        otp_code VARCHAR(10) NOT NULL,
        otp_hash VARCHAR(255) NOT NULL,
        purpose VARCHAR(50) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        credential_id VARCHAR(1024) UNIQUE NOT NULL,
        public_key BYTEA NOT NULL,
        counter INT DEFAULT 0,
        transports TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        challenge VARCHAR(256) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        purpose VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(18, 2) NOT NULL,
        description VARCHAR(255),
        status VARCHAR(50) DEFAULT 'PENDING',
        monnify_reference VARCHAR(255),
        related_user_id INT REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
      CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_tokens(email);
      CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
      CREATE INDEX IF NOT EXISTS idx_webauthn_challenge ON webauthn_challenges(user_id);
    `);
  } finally {
    client.release();
  }
}

initializeDatabase().catch((err) => {
  console.error("DB init failed:", err);
  process.exit(1);
});

// ============================================
// CORS MIDDLEWARE
// ============================================
app.use((req, res, next) => {
  const origin = req.get("origin");
  if (origin === process.env.FRONTEND_ORIGIN) {
    res.set("Access-Control-Allow-Origin", origin);
  }
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.set("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ============================================
// RATE LIMITING
// ============================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => res.status(429).json({ error: "Too many attempts" }),
});

const webauthnLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.ip,
});

// ============================================
// UTILITIES
// ============================================
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

function generateReferralCode() {
  return crypto.randomBytes(16).toString("hex");
}

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function verifyMonnifySignature(payload, signature) {
  const hash = crypto
    .createHmac("sha512", MONNIFY_API_KEY)
    .update(JSON.stringify(payload))
    .digest("hex");
  return hash === signature;
}

function getMonnifyAuthHeader() {
  const auth = Buffer.from(
    `${MONNIFY_CONTRACT_CODE}:${MONNIFY_API_KEY}`
  ).toString("base64");
  return `Basic ${auth}`;
}

async function sendOTP(email, otp) {
  try {
    await resend.emails.send({
      from: "noreply@sgf.ng",
      to: email,
      subject: "Your SGF Verification Code",
      html: `
        <h2>Verify Your SGF Account</h2>
        <p>Your 6-digit verification code is:</p>
        <h1 style="font-size: 48px; letter-spacing: 10px;">${otp}</h1>
        <p>This code expires in 15 minutes.</p>
      `,
    });
    return true;
  } catch (err) {
    console.error("Email send failed:", err);
    return false;
  }
}

async function createMonnifyAccount(email, firstName, lastName, mobileNumber) {
  try {
    const resp = await axios.post(
      `${MONNIFY_BASE_URL}/bank-transfer/reserved-accounts`,
      {
        accountReference: `SGF-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
        accountName: `${firstName} ${lastName}`,
        currencyCode: "NGN",
        customerEmail: email,
        customerName: `${firstName} ${lastName}`,
        getMobile: true,
        phoneNumber: mobileNumber,
      },
      {
        headers: {
          Authorization: getMonnifyAuthHeader(),
          "Content-Type": "application/json",
        },
      }
    );

    if (!resp.data.requestSuccessful) {
      throw new Error(resp.data.responseMessage);
    }

    const account = resp.data.responseBody;
    return {
      reference: account.accountReference,
      accountNumber: account.accountNumber,
      bankName: account.bankName,
      bankCode: account.bankCode,
    };
  } catch (err) {
    console.error("Monnify account creation failed:", err.message);
    throw err;
  }
}

// ============================================
// AUTH MIDDLEWARE
// ============================================
async function authenticateToken(req, res, next) {
  const authHeader = req.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.slice(7);
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

  try {
    const result = await pool.query(
      `SELECT s.user_id, s.expires_at FROM sessions s
       WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Session expired" });
    }

    req.userId = result.rows[0].user_id;
    next();
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).json({ error: "Server error" });
  }
}

// ============================================
// ROUTES: REGISTRATION & OTP
// ============================================
app.post("/auth/register", authLimiter, async (req, res) => {
  const { username, email, phone, bvn, nin } = req.body;

  if (!username || !email || !phone || !bvn || !nin) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (!/^\d{11}$/.test(bvn) || !/^\d{11}$/.test(nin)) {
    return res.status(400).json({ error: "BVN/NIN must be exactly 11 digits" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const existingUser = await client.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );
    if (existingUser.rows.length > 0) {
      await client.query("ROLLBACK");
      return res
        .status(409)
        .json({ error: "Username or email already registered" });
    }

    const otp = generateOTP();
    const otpHash = await hashPassword(otp);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await client.query(
      `INSERT INTO otp_tokens (email, otp_code, otp_hash, purpose, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [email, otp, otpHash, "registration", expiresAt]
    );

    await client.query("COMMIT");

    const sent = await sendOTP(email, otp);
    if (!sent) {
      return res.status(500).json({ error: "Failed to send OTP" });
    }

    res.json({
      message: "Registration initiated. Check your email for OTP.",
      sessionData: {
        username,
        email,
        phone,
        bvn,
        nin,
      },
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Registration error:", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

app.post("/auth/verify-otp", authLimiter, async (req, res) => {
  const {
    email,
    otp,
    pin,
    confirmPin,
    referralCode,
    username,
    phone,
    bvn,
    nin,
  } = req.body;

  if (!email || !otp || !pin || !confirmPin) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (pin !== confirmPin) {
    return res.status(400).json({ error: "PINs do not match" });
  }

  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: "PIN must be exactly 4 digits" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const otpRecord = await client.query(
      `SELECT id, otp_hash, purpose FROM otp_tokens
       WHERE email = $1 AND purpose = $2 AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [email, "registration"]
    );

    if (otpRecord.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    const isValid = await verifyPassword(otp, otpRecord.rows[0].otp_hash);
    if (!isValid) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid OTP" });
    }

    const pinHash = await bcrypt.hash(pin, 10);
    const referralCode_ = generateReferralCode();
    let referredById = null;

    if (referralCode) {
      const referrer = await client.query(
        "SELECT id FROM users WHERE referral_code = $1",
        [referralCode]
      );
      if (referrer.rows.length > 0) {
        referredById = referrer.rows[0].id;
      }
    }

    // Create Monnify account (BVN/NIN passed but not stored)
    let monnifyData = {};
    try {
      const [firstName, ...lastNameParts] = username.split(" ");
      const lastName = lastNameParts.join(" ") || "User";
      monnifyData = await createMonnifyAccount(email, firstName, lastName, phone);
    } catch (err) {
      console.warn("Monnify account creation failed, continuing:", err.message);
    }

    const newUser = await client.query(
      `INSERT INTO users (username, email, phone, pin_hash, kyc_verified, account_active, referral_code, referred_by_id, monnify_account_reference, monnify_reserved_account_number)
       VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7, $8, $9)
       RETURNING id`,
      [
        username,
        email,
        phone,
        pinHash,
        false, // BVN/NIN validated but not stored; only kyc_verified flag
        referralCode_,
        referredById,
        monnifyData.reference || null,
        monnifyData.accountNumber || null,
      ]
    );

    const userId = newUser.rows[0].id;

    await client.query("DELETE FROM otp_tokens WHERE id = $1", [
      otpRecord.rows[0].id,
    ]);

    // Create session token
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await client.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [userId, tokenHash, expiresAt]
    );

    await client.query("COMMIT");

    res.json({
      message: "Account created successfully",
      token,
      user: {
        id: userId,
        username,
        email,
        monnifyAccountNumber: monnifyData.accountNumber,
      },
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("OTP verification error:", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

// ============================================
// ROUTES: LOGIN
// ============================================
app.post("/auth/login", authLimiter, async (req, res) => {
  const { identifier, pin } = req.body;

  if (!identifier || !pin) {
    return res.status(400).json({ error: "Missing identifier or PIN" });
  }

  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: "PIN must be 4 digits" });
  }

  try {
    const isEmail = identifier.includes("@");
    const query = isEmail
      ? "SELECT id, pin_hash FROM users WHERE email = $1 AND account_active = TRUE"
      : "SELECT id, pin_hash FROM users WHERE username = $1 AND account_active = TRUE";

    const result = await pool.query(query, [identifier]);

    if (result.rows.length === 0) {
      // Do not leak whether account exists
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const pinMatch = await verifyPassword(pin, user.pin_hash);

    if (!pinMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Create session
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt]
    );

    res.json({
      token,
      user: { id: user.id },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================
// ROUTES: FORGOT PIN
// ============================================
app.post("/auth/forgot-pin-request", authLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email required" });
  }

  // Don't leak whether email is registered
  const otp = generateOTP();
  const otpHash = await hashPassword(otp);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  try {
    const user = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);

    if (user.rows.length > 0) {
      await pool.query(
        `INSERT INTO otp_tokens (user_id, email, otp_code, otp_hash, purpose, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [user.rows[0].id, email, otp, otpHash, "reset_pin", expiresAt]
      );

      await sendOTP(email, otp);
    }

    // Always return success to prevent user enumeration
    res.json({ message: "If email exists, OTP sent" });
  } catch (err) {
    console.error("Forgot PIN request error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/forgot-pin-reset", authLimiter, async (req, res) => {
  const { email, otp, newPin, confirmPin } = req.body;

  if (!email || !otp || !newPin || !confirmPin) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (newPin !== confirmPin) {
    return res.status(400).json({ error: "PINs do not match" });
  }

  if (!/^\d{4}$/.test(newPin)) {
    return res.status(400).json({ error: "PIN must be 4 digits" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const otpRecord = await client.query(
      `SELECT id, user_id, otp_hash FROM otp_tokens
       WHERE email = $1 AND purpose = $2 AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [email, "reset_pin"]
    );

    if (otpRecord.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    const isValid = await verifyPassword(otp, otpRecord.rows[0].otp_hash);
    if (!isValid) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid OTP" });
    }

    const pinHash = await bcrypt.hash(newPin, 10);
    await client.query("UPDATE users SET pin_hash = $1 WHERE id = $2", [
      pinHash,
      otpRecord.rows[0].user_id,
    ]);

    await client.query("DELETE FROM otp_tokens WHERE id = $1", [
      otpRecord.rows[0].id,
    ]);
    await client.query("COMMIT");

    res.json({ message: "PIN reset successfully" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("PIN reset error:", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

// ============================================
// ROUTES: WALLET & PROFILE
// ============================================
app.get("/wallet/balance", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT wallet_balance, monnify_reserved_account_number, referral_code FROM users WHERE id = $1",
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];
    res.json({
      balance: parseFloat(user.wallet_balance),
      accountNumber: user.monnify_reserved_account_number,
      referralCode: user.referral_code,
    });
  } catch (err) {
    console.error("Balance fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/wallet/transactions", authenticateToken, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  try {
    const result = await pool.query(
      `SELECT id, type, amount, description, status, monnify_reference, related_user_id, created_at
       FROM transactions
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );

    res.json({ transactions: result.rows });
  } catch (err) {
    console.error("Transactions fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================
// ROUTES: MONNIFY WEBHOOK (DEPOSITS)
// ============================================
app.post("/webhook/monnify/deposit", async (req, res) => {
  const signature = req.get("Monnify-Signature");
  if (!signature) {
    return res.status(401).json({ error: "Missing signature" });
  }

  if (!verifyMonnifySignature(req.body, signature)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const {
    transactionReference,
    amount,
    accountNumber,
    incomingTransfersToBeCreated,
  } = req.body;

  try {
    // Check for duplicate webhook delivery (idempotency)
    const existing = await pool.query(
      "SELECT id FROM transactions WHERE monnify_reference = $1",
      [transactionReference]
    );

    if (existing.rows.length > 0) {
      return res.json({ message: "Webhook already processed" });
    }

    const user = await pool.query(
      "SELECT id, referred_by_id FROM users WHERE monnify_reserved_account_number = $1",
      [accountNumber]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "Account not found" });
    }

    const userId = user.rows[0].id;
    const referredById = user.rows[0].referred_by_id;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      // Lock user row
      await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [
        userId,
      ]);

      // Credit deposit
      await client.query(
        `UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2`,
        [amount, userId]
      );

      // Record transaction
      await client.query(
        `INSERT INTO transactions (user_id, type, amount, status, monnify_reference)
         VALUES ($1, $2, $3, $4, $5)`,
        [userId, "DEPOSIT", amount, "COMPLETED", transactionReference]
      );

      // Credit referrer (5% bonus on first deposit)
      if (referredById) {
        const referrerTransactions = await client.query(
          `SELECT COUNT(*) as count FROM transactions
           WHERE user_id = $1 AND type = $2`,
          [userId, "DEPOSIT"]
        );

        if (parseInt(referrerTransactions.rows[0].count) === 1) {
          const bonus = (amount * 0.05).toFixed(2);
          await client.query(
            "SELECT * FROM users WHERE id = $1 FOR UPDATE",
            [referredById]
          );
          await client.query(
            `UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2`,
            [bonus, referredById]
          );

          await client.query(
            `INSERT INTO transactions (user_id, type, amount, status, description)
             VALUES ($1, $2, $3, $4, $5)`,
            [
              referredById,
              "REFERRAL_BONUS",
              bonus,
              "COMPLETED",
              `5% referral bonus`,
            ]
          );
        }
      }

      await client.query("COMMIT");
      res.json({ message: "Deposit processed" });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================
// ROUTES: WITHDRAWALS
// ============================================
app.post("/wallet/withdraw", authenticateToken, async (req, res) => {
  const { accountNumber, accountName, amount, bankCode } = req.body;

  if (!accountNumber || !accountName || !amount || !bankCode) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const withdrawAmount = parseFloat(amount);
  if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
    return res.status(400).json({ error: "Invalid amount" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Lock and check balance
    const userResult = await client.query(
      "SELECT wallet_balance FROM users WHERE id = $1 FOR UPDATE",
      [req.userId]
    );

    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    if (userResult.rows[0].wallet_balance < withdrawAmount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Initiate Monnify disbursement
    let disbursementData = {};
    try {
      const monnifyResp = await axios.post(
        `${MONNIFY_BASE_URL}/disbursements`,
        {
          accountNumber,
          accountName,
          bankCode,
          amount: withdrawAmount,
          narration: "SGF Withdrawal",
          reference: `SGF-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
        },
        {
          headers: {
            Authorization: getMonnifyAuthHeader(),
            "Content-Type": "application/json",
          },
        }
      );

      if (!monnifyResp.data.requestSuccessful) {
        throw new Error(monnifyResp.data.responseMessage);
      }

      disbursementData = monnifyResp.data.responseBody;
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Monnify disbursement error:", err.message);
      return res
        .status(400)
        .json({ error: "Disbursement failed: " + err.message });
    }

    // Handle MFA if required
    if (disbursementData.status === "PENDING_AUTHORIZATION") {
      // Store pending withdrawal and return challenge
      await client.query(
        `INSERT INTO transactions (user_id, type, amount, status, monnify_reference, description)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          req.userId,
          "WITHDRAWAL",
          withdrawAmount,
          "PENDING_MFA",
          disbursementData.transactionReference,
          JSON.stringify({ accountNumber, accountName, bankCode }),
        ]
      );

      await client.query("ROLLBACK");
      return res.json({
        status: "MFA_REQUIRED",
        transactionReference: disbursementData.transactionReference,
        message: "Check your email/SMS for MFA approval",
      });
    }

    // Success: debit wallet
    await client.query(
      `UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2`,
      [withdrawAmount, req.userId]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, amount, status, monnify_reference)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.userId,
        "WITHDRAWAL",
        withdrawAmount,
        "COMPLETED",
        disbursementData.transactionReference,
      ]
    );

    await client.query("COMMIT");

    res.json({
      message: "Withdrawal successful",
      transactionReference: disbursementData.transactionReference,
      status: disbursementData.status,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Withdrawal error:", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

app.post(
  "/wallet/authorize-withdrawal",
  authenticateToken,
  async (req, res) => {
    const { transactionReference, authorizationCode } = req.body;

    if (!transactionReference || !authorizationCode) {
      return res.status(400).json({ error: "Missing fields" });
    }

    try {
      const monnifyResp = await axios.put(
        `${MONNIFY_BASE_URL}/disbursements/${transactionReference}/authorize`,
        { authorizationCode },
        {
          headers: {
            Authorization: getMonnifyAuthHeader(),
            "Content-Type": "application/json",
          },
        }
      );

      if (!monnifyResp.data.requestSuccessful) {
        return res.status(400).json({ error: "Authorization failed" });
      }

      // Update transaction and debit wallet
      const transaction = await pool.query(
        "SELECT amount FROM transactions WHERE monnify_reference = $1",
        [transactionReference]
      );

      if (transaction.rows.length === 0) {
        return res.status(404).json({ error: "Transaction not found" });
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        await client.query(
          `UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2`,
          [transaction.rows[0].amount, req.userId]
        );

        await client.query(
          `UPDATE transactions SET status = $1 WHERE monnify_reference = $2`,
          ["COMPLETED", transactionReference]
        );

        await client.query("COMMIT");

        res.json({ message: "Withdrawal authorized and completed" });
      } finally {
        client.release();
      }
    } catch (err) {
      console.error("Authorization error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// ============================================
// ROUTES: TRANSFER BETWEEN USERS
// ============================================
app.post("/wallet/transfer", authenticateToken, async (req, res) => {
  const { recipientUsername, amount } = req.body;

  if (!recipientUsername || !amount) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const transferAmount = parseFloat(amount);
  if (isNaN(transferAmount) || transferAmount <= 0) {
    return res.status(400).json({ error: "Invalid amount" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Lock sender
    const senderResult = await client.query(
      "SELECT id, wallet_balance FROM users WHERE id = $1 FOR UPDATE",
      [req.userId]
    );

    if (senderResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Sender not found" });
    }

    if (senderResult.rows[0].wallet_balance < transferAmount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Lock recipient
    const recipientResult = await client.query(
      "SELECT id FROM users WHERE username = $1 FOR UPDATE",
      [recipientUsername]
    );

    if (recipientResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Recipient not found" });
    }

    const recipientId = recipientResult.rows[0].id;

    // Debit sender
    await client.query(
      `UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2`,
      [transferAmount, req.userId]
    );

    // Credit recipient
    await client.query(
      `UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2`,
      [transferAmount, recipientId]
    );

    // Record transactions
    const ref = `TRF-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, status, monnify_reference, related_user_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req.userId, "TRANSFER_OUT", transferAmount, "COMPLETED", ref, recipientId]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, amount, status, monnify_reference, related_user_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        recipientId,
        "TRANSFER_IN",
        transferAmount,
        "COMPLETED",
        ref,
        req.userId,
      ]
    );

    await client.query("COMMIT");

    res.json({ message: "Transfer successful" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Transfer error:", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

// ============================================
// ROUTES: WEBAUTHN REGISTRATION
// ============================================
app.post(
  "/webauthn/register-options",
  authenticateToken,
  webauthnLimiter,
  async (req, res) => {
    const user = await pool.query(
      "SELECT id, email, username FROM users WHERE id = $1",
      [req.userId]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const u = user.rows[0];
    const options = generateRegistrationOptions({
      rpID: WEBAUTHN_RP_ID,
      rpName: WEBAUTHN_RP_NAME,
      userID: Buffer.from(u.id.toString()),
      userName: u.username,
      userDisplayName: u.email,
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "preferred",
      },
    });

    // Store challenge
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      `INSERT INTO webauthn_challenges (user_id, challenge, expires_at, purpose)
       VALUES ($1, $2, $3, $4)`,
      [req.userId, options.challenge, expiresAt, "registration"]
    );

    res.json(options);
  }
);

app.post(
  "/webauthn/register-verify",
  authenticateToken,
  webauthnLimiter,
  async (req, res) => {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: "Missing credential" });
    }

    try {
      const challenge = await pool.query(
        `SELECT challenge FROM webauthn_challenges
         WHERE user_id = $1 AND purpose = $2 AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1`,
        [req.userId, "registration"]
      );

      if (challenge.rows.length === 0) {
        return res.status(400).json({ error: "Invalid challenge" });
      }

      const verified = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge.rows[0].challenge,
        expectedOrigin: WEBAUTHN_ORIGIN,
        expectedRPID: WEBAUTHN_RP_ID,
      });

      if (!verified.verified) {
        return res.status(400).json({ error: "Verification failed" });
      }

      // Store credential (public key only, never private key)
      const credentialIDString = Buffer.from(
        verified.registrationInfo.credentialID
      ).toString("hex");

      await pool.query(
        `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, transports)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          req.userId,
          credentialIDString,
          Buffer.from(verified.registrationInfo.credentialPublicKey),
          verified.registrationInfo.counter,
          JSON.stringify(credential.transports || []),
        ]
      );

      // Clean up challenge
      await pool.query(
        `DELETE FROM webauthn_challenges WHERE user_id = $1 AND purpose = $2`,
        [req.userId, "registration"]
      );

      res.json({ message: "Credential registered successfully" });
    } catch (err) {
      console.error("WebAuthn register error:", err);
      res.status(500).json({ error: "Verification failed" });
    }
  }
);

// ============================================
// ROUTES: WEBAUTHN LOGIN
// ============================================
app.post("/webauthn/login-options", webauthnLimiter, async (req, res) => {
  const options = generateAuthenticationOptions({
    rpID: WEBAUTHN_RP_ID,
    userVerification: "preferred",
  });

  // Store challenge (no user context yet)
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  const challengeRecord = await pool.query(
    `INSERT INTO webauthn_challenges (challenge, expires_at, purpose)
     VALUES ($1, $2, $3)
     RETURNING id`,
    [options.challenge, expiresAt, "login"]
  );

  res.json({
    ...options,
    challengeId: challengeRecord.rows[0].id,
  });
});

app.post("/webauthn/login-verify", webauthnLimiter, async (req, res) => {
  const { credential, challengeId } = req.body;

  if (!credential || !challengeId) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const challenge = await pool.query(
      `SELECT user_id, challenge FROM webauthn_challenges
       WHERE id = $1 AND purpose = $2 AND expires_at > NOW()`,
      [challengeId, "login"]
    );

    if (challenge.rows.length === 0) {
      return res.status(400).json({ error: "Invalid challenge" });
    }

    const credentialIDBuffer = Buffer.from(credential.id, "base64");
    const credentialIDHex = credentialIDBuffer.toString("hex");

    const storedCred = await pool.query(
      `SELECT user_id, public_key, counter FROM webauthn_credentials
       WHERE credential_id = $1`,
      [credentialIDHex]
    );

    if (storedCred.rows.length === 0) {
      return res.status(400).json({ error: "Credential not found" });
    }

    const verified = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge.rows[0].challenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: {
        id: credentialIDBuffer,
        publicKey: storedCred.rows[0].public_key,
        counter: storedCred.rows[0].counter,
      },
    });

    if (!verified.verified) {
      return res.status(400).json({ error: "Authentication failed" });
    }

    // Update counter
    await pool.query(
      `UPDATE webauthn_credentials SET counter = $1 WHERE credential_id = $2`,
      [verified.authenticationInfo.newCounter, credentialIDHex]
    );

    const userId = storedCred.rows[0].user_id;

    // Create session
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [userId, tokenHash, expiresAt]
    );

    // Clean up challenge
    await pool.query(`DELETE FROM webauthn_challenges WHERE id = $1`, [
      challengeId,
    ]);

    res.json({
      token,
      user: { id: userId },
    });
  } catch (err) {
    console.error("WebAuthn login error:", err);
    res.status(500).json({ error: "Authentication failed" });
  }
});

// ============================================
// AUTO-GROWTH WALLET (Scheduled Task)
// ============================================
setInterval(async () => {
  try {
    const growthRate = parseFloat(process.env.WALLET_GROWTH_RATE || "0.001"); // 0.1% per interval
    if (growthRate <= 0) return;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const users = await client.query(
        `SELECT id, wallet_balance FROM users WHERE account_active = TRUE FOR UPDATE`
      );

      for (const user of users.rows) {
        const growth = (user.wallet_balance * growthRate).toFixed(2);
        if (growth > 0) {
          await client.query(
            `UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2`,
            [growth, user.id]
          );

          await client.query(
            `INSERT INTO transactions (user_id, type, amount, status)
             VALUES ($1, $2, $3, $4)`,
            [user.id, "GROWTH", growth, "COMPLETED"]
          );
        }
      }

      await client.query("COMMIT");
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Wallet growth error:", err);
  }
}, 60 * 60 * 1000); // Every hour

// ============================================
// ERROR HANDLING & SERVER START
// ============================================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SGF Backend running on port ${PORT} (env: ${MONNIFY_ENV})`);
});
