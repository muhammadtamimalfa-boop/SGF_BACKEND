require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');

const app = express();

// ===== CORS =====
// Locked to your real frontend origin(s) only. Set FRONTEND_URL in Railway
// Variables to your Vercel URL, e.g. https://sgf-frontend.vercel.app
// (no trailing slash). Requests from any other origin will be rejected by
// the browser. Server-to-server calls (like Monnify's webhook) are NOT
// affected by CORS — CORS only applies to browser fetch() calls.
const allowedOrigins = (process.env.FRONTEND_URL || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

if (allowedOrigins.length === 0) {
  console.warn('WARNING: FRONTEND_URL is not set — CORS will reject all browser requests. Set it in Railway Variables to your Vercel URL.');
}

app.use(cors({
  origin: (origin, callback) => {
    // Allow no-origin requests (e.g. curl, Postman, server-to-server) —
    // browsers always send an Origin header for cross-site fetch calls,
    // so this doesn't weaken protection against unwanted browser access.
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.warn(`CORS rejected request from origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  }
}));

// Capture the raw body string alongside the parsed JSON — Monnify's webhook
// signature is computed over the exact raw bytes Monnify sent, so we can't
// reconstruct it reliably from the re-serialized parsed object.
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // for Neon
});

// ===== GROWTH CONFIG =====
// Set your own rate/interval here. Example below is a PLACEHOLDER (0.1% per DAY),
// NOT the original 0.1%-per-minute value — that compounded to ~82%/hour and
// would have bankrupted the platform. Replace GROWTH_RATE and GROWTH_INTERVAL_MS
// with your real numbers before going live.
const GROWTH_RATE = 0.001; // 0.1% per interval
const GROWTH_INTERVAL_MS = 24 * 60 * 60 * 1000; // once per day

// ===== MONNIFY CONFIG =====
// Keys come from Railway environment variables — never hardcode these,
// and never paste them into chat, docs, or commit messages either.
const MONNIFY_API_KEY = process.env.MONNIFY_API_KEY;
const MONNIFY_SECRET_KEY = process.env.MONNIFY_SECRET_KEY;
const MONNIFY_CONTRACT_CODE = process.env.MONNIFY_CONTRACT_CODE;
const MONNIFY_SOURCE_ACCOUNT = process.env.MONNIFY_SOURCE_ACCOUNT;

// ===== EXPLICIT MODE SWITCH =====
// No more silent fallback to live. You MUST set MONNIFY_ENV in Railway to
// either 'sandbox' or 'live' — the server refuses to start if it's missing
// or misspelled, and refuses to start if it doesn't match your API key
// prefix (MK_TEST_ = sandbox key, MK_PROD_ = live key). This makes it
// impossible to end up live/sandbox-mismatched without noticing.
const MONNIFY_ENV = (process.env.MONNIFY_ENV || '').toLowerCase();
const MONNIFY_URLS = {
  sandbox: 'https://sandbox.monnify.com',
  live: 'https://api.monnify.com'
};

if (!MONNIFY_URLS[MONNIFY_ENV]) {
  throw new Error(
    `MONNIFY_ENV must be set to 'sandbox' or 'live' in Railway Variables (currently: '${process.env.MONNIFY_ENV || '(not set)'}'). Refusing to start with an ambiguous Monnify environment.`
  );
}

if (MONNIFY_API_KEY) {
  const keyLooksLikeTest = MONNIFY_API_KEY.startsWith('MK_TEST_');
  const keyLooksLikeLive = MONNIFY_API_KEY.startsWith('MK_PROD_') || MONNIFY_API_KEY.startsWith('MK_LIVE_');

  if (MONNIFY_ENV === 'live' && keyLooksLikeTest) {
    throw new Error('MONNIFY_ENV is "live" but MONNIFY_API_KEY looks like a sandbox test key (MK_TEST_...). Refusing to start — this would be a live-mode misconfiguration.');
  }
  if (MONNIFY_ENV === 'sandbox' && keyLooksLikeLive) {
    throw new Error('MONNIFY_ENV is "sandbox" but MONNIFY_API_KEY looks like a live key. Refusing to start — double-check your Railway Variables.');
  }
}

const MONNIFY_BASE_URL = MONNIFY_URLS[MONNIFY_ENV];
console.log(`Monnify running in ${MONNIFY_ENV.toUpperCase()} mode against ${MONNIFY_BASE_URL}`);

if (!MONNIFY_API_KEY || !MONNIFY_SECRET_KEY || !MONNIFY_CONTRACT_CODE) {
  console.warn('WARNING: Monnify env vars are missing. Set MONNIFY_API_KEY, MONNIFY_SECRET_KEY, MONNIFY_CONTRACT_CODE in Railway Variables.');
}
if (!MONNIFY_SOURCE_ACCOUNT) {
  console.warn('WARNING: MONNIFY_SOURCE_ACCOUNT is not set. Withdrawals will fail without it — this is your Monnify wallet/settlement account number.');
}

// Monnify access tokens last about 1 hour. Cache in memory so we don't
// re-authenticate on every single request.
let monnifyTokenCache = { token: null, expiresAt: 0 };

async function getMonnifyToken() {
  if (monnifyTokenCache.token && Date.now() < monnifyTokenCache.expiresAt) {
    return monnifyTokenCache.token;
  }
  const basicAuth = Buffer.from(`${MONNIFY_API_KEY}:${MONNIFY_SECRET_KEY}`).toString('base64');
  const resp = await fetch(`${MONNIFY_BASE_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${basicAuth}`, 'Content-Type': 'application/json' }
  });
  const data = await resp.json();
  if (!data.requestSuccessful) throw new Error('Monnify auth failed: ' + JSON.stringify(data));

  monnifyTokenCache.token = data.responseBody.accessToken;
  // Refresh a little early (55 min) so we never use an expired token mid-request.
  monnifyTokenCache.expiresAt = Date.now() + 55 * 60 * 1000;
  return monnifyTokenCache.token;
}

// Verifies a Monnify webhook actually came from Monnify: recomputes the
// HMAC-SHA512 hash of the raw request body using our secret key and compares
// it against the 'monnify-signature' header, using a timing-safe comparison.
// Without this check, anyone who finds the webhook URL could POST a fake
// "SUCCESSFUL_TRANSACTION" event and credit their own wallet for free.
function verifyMonnifySignature(req) {
  const signature = req.headers['monnify-signature'];
  if (!signature || !req.rawBody) return false;
  const expected = crypto.createHmac('sha512', MONNIFY_SECRET_KEY).update(req.rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false; // lengths differ or invalid hex — definitely not a match
  }
}



// HELPERS
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const generateRefCode = () => 'SGF' + crypto.randomBytes(3).toString('hex').toUpperCase();

// ===== RATE LIMITING =====
// Login and OTP endpoints are the classic brute-force targets (guessing a
// 4-digit PIN or a 6-digit OTP is very feasible without a limit). These are
// deliberately tight — a real user will never hit them in normal use.
//
// keyGenerator uses IP by default, which is fine on Railway since it sits
// behind a proxy that sets X-Forwarded-For correctly.

const otpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,                    // 3 OTP requests per IP per window
  message: { ok: false, msg: 'Too many OTP requests. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,                   // allow a few mistyped OTPs, but not brute force
  message: { ok: false, msg: 'Too many attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,                    // a few wrong PIN attempts, not thousands
  message: { ok: false, msg: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ===== EMAIL (Resend) =====
// Sends real OTP emails instead of console.log. Falls back to console
// logging if RESEND_API_KEY isn't set, so local dev still works without it.
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const EMAIL_FROM = process.env.EMAIL_FROM || 'SGF <onboarding@resend.dev>';

async function sendOtpEmail(toEmail, otp, purpose = 'verify your account') {
  if (!resend) {
    console.log(`=====================`);
    console.log(`[DEV MODE — Resend not configured] OTP for ${toEmail}: ${otp}`);
    console.log(`=====================`);
    return;
  }
  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to: toEmail,
      subject: `Your SGF verification code: ${otp}`,
      html: `
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:24px">
          <h2 style="color:#16a34a">SGF</h2>
          <p>Use this code to ${purpose}:</p>
          <div style="font-size:32px;font-weight:800;letter-spacing:4px;background:#f0faf0;padding:16px;border-radius:12px;text-align:center;color:#16a34a">${otp}</div>
          <p style="color:#64748b;font-size:13px;margin-top:16px">This code expires in 10 minutes. If you didn't request this, you can safely ignore this email.</p>
        </div>
      `
    });
  } catch (e) {
    // Don't let an email-sending failure block the API response — the OTP
    // is already saved in the DB, so the user can still retry/resend.
    console.error('Resend email failed:', e);
  }
}

// 1. REGISTER - SEND OTP
app.post('/api/auth/register', otpRequestLimiter, async (req, res) => {
  const { email, username, phone } = req.body;
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length > 0) return res.json({ ok: false, msg: 'Username already taken' });

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 mins
    const refCode = generateRefCode();

    const result = await pool.query(
      `INSERT INTO users(email, username, phone, otp_code, otp_expiry, referral_code)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
      [email, username, phone, otp, otpExpiry, refCode]
    );

    await sendOtpEmail(email, otp, 'verify your SGF account');
    res.json({ ok: true, msg: 'OTP sent to your email', userId: result.rows[0].id });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, msg: 'Server error' });
  }
});

// 2. VERIFY OTP + SET PIN + REFERRAL
app.post('/api/auth/verify-otp', otpVerifyLimiter, async (req, res) => {
  const { userId, otp, pin, refCode } = req.body;
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE id=$1', [userId]);
    if (userRes.rows.length === 0) return res.json({ ok: false, msg: 'User not found' });
    const user = userRes.rows[0];

    if (user.otp_code !== otp || new Date() > user.otp_expiry)
      return res.json({ ok: false, msg: 'Invalid or Expired OTP' });

    const hashedPin = bcrypt.hashSync(pin, 10);
    let referredBy = null;

    if (refCode) {
      const refUser = await pool.query('SELECT id FROM users WHERE referral_code=$1', [refCode]);
      if (refUser.rows.length > 0) referredBy = refUser.rows[0].id;
    }

    await pool.query(
      `UPDATE users SET pin=$1, is_verified=true, otp_code=null, otp_expiry=null, referred_by=$2 WHERE id=$3`,
      [hashedPin, referredBy, userId]
    );

    res.json({ ok: true, msg: 'Account verified. You can login now' });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, msg: 'Server error' });
  }
});

// 3. LOGIN WITH PIN
// FIX: original endpoint only accepted { email, pin }, but the app logs in with
// a username. Now accepts EITHER identifier field so the frontend doesn't
// need to collect email at login.
app.post('/api/auth/login-pin', loginLimiter, async (req, res) => {
  const { email, username, pin } = req.body;
  try {
    if (!email && !username) return res.json({ ok: false, msg: 'Username or email required' });

    const userRes = email
      ? await pool.query('SELECT * FROM users WHERE email=$1', [email])
      : await pool.query('SELECT * FROM users WHERE username=$1', [username]);

    if (userRes.rows.length === 0) return res.json({ ok: false, msg: 'User not found' });
    const user = userRes.rows[0];

    if (!user.is_verified) return res.json({ ok: false, msg: 'Please verify OTP first' });
    if (!bcrypt.compareSync(pin, user.pin)) return res.json({ ok: false, msg: 'Invalid PIN' });

    res.json({
      ok: true,
      msg: 'Login successful',
      user: { id: user.id, username: user.username, referral_code: user.referral_code }
    });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, msg: 'Server error' });
  }
});

// 4. FORGOT PIN - SEND OTP
app.post('/api/auth/forgot-pin', otpRequestLimiter, async (req, res) => {
  const { email } = req.body;
  try {
    const userRes = await pool.query('SELECT id FROM users WHERE email=$1', [email]);

    // Always return the same success message whether or not the email
    // exists, so this endpoint can't be used to check which emails are
    // registered (user enumeration). We only actually send an OTP if the
    // account is real.
    if (userRes.rows.length > 0) {
      const otp = generateOTP();
      const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
      await pool.query('UPDATE users SET otp_code=$1, otp_expiry=$2 WHERE email=$3', [otp, otpExpiry, email]);
      await sendOtpEmail(email, otp, 'reset your SGF PIN');
    }

    res.json({ ok: true, msg: 'If that email is registered, a reset code has been sent' });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, msg: 'Server error' });
  }
});

// 5. RESET PIN
app.post('/api/auth/reset-pin', otpVerifyLimiter, async (req, res) => {
  const { email, otp, newPin } = req.body;
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (userRes.rows.length === 0) return res.json({ ok: false, msg: 'Invalid or Expired OTP' });
    const user = userRes.rows[0];

    if (user.otp_code !== otp || new Date() > user.otp_expiry)
      return res.json({ ok: false, msg: 'Invalid or Expired OTP' });

    const hashedPin = bcrypt.hashSync(newPin, 10);
    await pool.query('UPDATE users SET pin=$1, otp_code=null, otp_expiry=null WHERE email=$2', [hashedPin, email]);
    res.json({ ok: true, msg: 'PIN reset successful' });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, msg: 'Server error' });
  }
});

// 6. CREATE MONNIFY ACCOUNT - REAL
// Calls Monnify's Reserved Account API to get a real virtual account number
// tied to your CONTRACT_CODE. Each user gets their own permanent account
// number that customers can pay into directly. Monnify requires the
// customer's email/username as the accountReference, which must be unique.
app.post('/api/wallet/create-account', async (req, res) => {
  const { userId, username, email } = req.body;
  if (!userId || !username || !email) {
    return res.json({ ok: false, msg: 'userId, username, and email are required' });
  }
  try {
    const accRes = await pool.query('SELECT * FROM monnify_accounts WHERE user_id=$1', [userId]);
    if (accRes.rows.length > 0) return res.json({ ok: true, ...accRes.rows[0] });

    const token = await getMonnifyToken();
    const monnifyRes = await fetch(`${MONNIFY_BASE_URL}/api/v2/bank-transfer/reserved-accounts`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountReference: `SGF-${userId}-${Date.now()}`, // must be unique per reservation
        accountName: `SGF ${username}`,
        currencyCode: 'NGN',
        contractCode: MONNIFY_CONTRACT_CODE,
        customerEmail: email,
        customerName: username,
        getAllAvailableBanks: true // gives the customer a choice of partner banks to pay into
      })
    });
    const data = await monnifyRes.json();
    if (!data.requestSuccessful) {
      console.error('Monnify create-account failed:', data);
      return res.json({ ok: false, msg: data.responseMessage || 'Could not create account' });
    }

    // Monnify can return multiple account numbers (one per partner bank) when
    // getAllAvailableBanks is true — we store the first as the primary display account.
    const accounts = data.responseBody.accounts || [];
    const primary = accounts[0] || {};
    const accountNumber = primary.accountNumber || data.responseBody.accountNumber;
    const bankName = primary.bankName || 'Monnify';
    const accountName = data.responseBody.accountName;

    await pool.query(
      'INSERT INTO monnify_accounts(user_id, account_number, account_name, bank_name, account_reference) VALUES($1,$2,$3,$4,$5)',
      [userId, accountNumber, accountName, bankName, data.responseBody.accountReference]
    );
    res.json({ ok: true, accountNumber, accountName, bankName, allAccounts: accounts });
  } catch (e) {
    console.error('create-account error:', e);
    res.json({ ok: false, msg: 'Server error creating account' });
  }
});

// 7. GET WALLET
app.get('/api/wallet/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const userRes = await pool.query('SELECT wallet_balance, principal FROM users WHERE id=$1', [userId]);
    if (userRes.rows.length === 0) return res.json({ ok: false, msg: 'User not found' });

    const refRes = await pool.query('SELECT COUNT(*) FROM users WHERE referred_by=$1', [userId]);
    const accRes = await pool.query('SELECT account_number, account_name, bank_name FROM monnify_accounts WHERE user_id=$1', [userId]);

    res.json({
      ok: true,
      wallet_balance: parseFloat(userRes.rows[0].wallet_balance) || 0,
      principal: parseFloat(userRes.rows[0].principal) || 0,
      referrals: parseInt(refRes.rows[0].count),
      account: accRes.rows[0] || null
    });
  } catch (e) {
    console.error('wallet fetch error:', e);
    res.json({ ok: false, msg: 'Server error fetching wallet' });
  }
});

// 8. TRANSFER
// FIX: now uses a single checked-out client with row locking (SELECT ... FOR UPDATE)
// so BEGIN/COMMIT/ROLLBACK are actually atomic, and two concurrent transfers
// from the same user can't both pass the balance check.
app.post('/api/transfer', async (req, res) => {
  const { fromUserId, toUsername, amount, pin } = req.body;

  if (!(amount > 0)) return res.json({ ok: false, msg: 'Invalid amount' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const fromRes = await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE', [fromUserId]);
    if (fromRes.rows.length === 0) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'User not found' }); }
    const fromUser = fromRes.rows[0];

    if (!bcrypt.compareSync(pin, fromUser.pin)) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'Invalid PIN' }); }
    if (parseFloat(fromUser.wallet_balance) < amount) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'Insufficient balance' }); }

    const toRes = await client.query('SELECT * FROM users WHERE username=$1 FOR UPDATE', [toUsername]);
    if (toRes.rows.length === 0) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'Recipient not found' }); }
    const toUser = toRes.rows[0];

    if (toUser.id === fromUser.id) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'Cannot transfer to yourself' }); }

    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id=$2', [amount, fromUserId]);
    await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2', [amount, toUser.id]);
    await client.query('INSERT INTO transactions(user_id, amount, type) VALUES($1,$2,$3)', [fromUserId, -amount, 'transfer_out']);
    await client.query('INSERT INTO transactions(user_id, amount, type) VALUES($1,$2,$3)', [toUser.id, amount, 'transfer_in']);

    await client.query('COMMIT');
    res.json({ ok: true, msg: 'Transfer successful' });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.json({ ok: false, msg: 'Transfer failed' });
  } finally {
    client.release();
  }
});

// 9. WITHDRAW
// FIX: 10x lock removed per instruction — now just checks balance >= amount.
// FIX (this pass): now actually sends money out via Monnify's Disbursement
// API instead of only debiting the internal wallet. Requires the user's real
// bank account number + bank code in the request body.
//
// IMPORTANT — read before testing on live:
// 1. Monnify disburmbursements are OFF by default on LIVE (they're on by
//    default on sandbox). You must email [email protected] and ask them
//    to enable disbursements for your live account.
// 2. Live disbursement requests are IP-whitelisted. Send Monnify your
//    Railway server's static outbound IP first, or every request will fail
//    with a D06 error. (Railway's default egress IP can change — you may
//    need a static-IP add-on or a proxy for this to stay reliable.)
// 3. MFA is on by default: a transfer can come back with status
//    PENDING_AUTHORIZATION, meaning Monnify will text/email an OTP that must
//    be submitted via a separate "authorize transfer" call before the money
//    actually moves. The code below handles the OK case; add an OTP-submit
//    endpoint if you hit PENDING_AUTHORIZATION in practice.
app.post('/api/withdraw', async (req, res) => {
  const { userId, amount, pin, bankCode, accountNumber, accountName } = req.body;

  if (!(amount > 0)) return res.json({ ok: false, msg: 'Invalid amount' });
  if (!bankCode || !accountNumber || !accountName) {
    return res.json({ ok: false, msg: 'Bank code, account number, and account name are required' });
  }
  if (!MONNIFY_SOURCE_ACCOUNT) {
    return res.json({ ok: false, msg: 'Server misconfigured: MONNIFY_SOURCE_ACCOUNT is not set' });
  }

  const client = await pool.connect();
  const withdrawRef = `WD-${userId}-${Date.now()}`;
  try {
    await client.query('BEGIN');

    const userRes = await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE', [userId]);
    if (userRes.rows.length === 0) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'User not found' }); }
    const user = userRes.rows[0];

    if (!bcrypt.compareSync(pin, user.pin)) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'Invalid PIN' }); }
    if (parseFloat(user.wallet_balance) < amount) { await client.query('ROLLBACK'); return res.json({ ok: false, msg: 'Insufficient balance' }); }

    // Debit the wallet FIRST, inside the transaction, before calling out to
    // Monnify. If the disbursement call fails below, we roll back so the
    // user's balance is never wrongly reduced without money actually moving.
    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id=$2', [amount, userId]);
    await client.query(
      "INSERT INTO transactions(user_id, amount, type, tx_ref, status) VALUES($1,$2,$3,$4,$5)",
      [userId, -amount, 'withdraw', withdrawRef, 'pending']
    );

    // Call Monnify Disbursement API
    const token = await getMonnifyToken();
    const disbRes = await fetch(`${MONNIFY_BASE_URL}/api/v2/disbursements/single`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount,
        reference: withdrawRef,
        narration: 'SGF Withdrawal',
        destinationBankCode: bankCode,
        destinationAccountNumber: accountNumber,
        destinationAccountName: accountName,
        currency: 'NGN',
        sourceAccountNumber: MONNIFY_SOURCE_ACCOUNT // your Monnify wallet/settlement account number
      })
    });
    const disbData = await disbRes.json();

    if (!disbData.requestSuccessful) {
      // Disbursement failed outright — roll back the debit entirely.
      await client.query('ROLLBACK');
      console.error('Monnify disbursement failed:', disbData);
      return res.json({ ok: false, msg: disbData.responseMessage || 'Withdrawal failed' });
    }

    const status = disbData.responseBody?.status; // e.g. SUCCESS, PENDING_AUTHORIZATION, PROCESSING
    await client.query("UPDATE transactions SET status=$1 WHERE tx_ref=$2", [status || 'processing', withdrawRef]);
    await client.query('COMMIT');

    if (status === 'PENDING_AUTHORIZATION') {
      return res.json({ ok: true, msg: 'Withdrawal requires OTP authorization — check Monnify dashboard/notifications', status });
    }
    res.json({ ok: true, msg: 'Withdrawal submitted to bank', status });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Withdraw error:', e);
    res.json({ ok: false, msg: 'Withdrawal failed' });
  } finally {
    client.release();
  }
});

// 9b. AUTHORIZE WITHDRAWAL OTP
// Monnify has MFA/OTP enabled by DEFAULT on both sandbox and live disbursement
// accounts. This means the withdraw endpoint above will almost always come
// back with status PENDING_AUTHORIZATION on first use — that's expected,
// not a bug. When that happens, Monnify emails an OTP to your registered
// Monnify account email (not the end-user's email), and this endpoint
// submits that OTP to complete the transfer.
//
// If you'd rather not deal with OTP-per-withdrawal at all, you can ask
// Monnify to disable MFA entirely by emailing [email protected] — but note
// their docs require you to explicitly indemnify them for misuse if you do,
// since it means any request authenticated with your API keys goes through
// automatically with no human-in-the-loop check.
app.post('/api/withdraw/authorize', async (req, res) => {
  const { withdrawRef, otp } = req.body;
  if (!withdrawRef || !otp) return res.json({ ok: false, msg: 'withdrawRef and otp are required' });

  try {
    const token = await getMonnifyToken();
    const resp = await fetch(`${MONNIFY_BASE_URL}/api/v2/disbursements/single/validate-otp`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ reference: withdrawRef, authorizationCode: otp })
    });
    const data = await resp.json();

    if (!data.requestSuccessful) {
      return res.json({ ok: false, msg: data.responseMessage || 'OTP authorization failed' });
    }

    const status = data.responseBody?.status; // e.g. SUCCESS after authorization
    await pool.query("UPDATE transactions SET status=$1 WHERE tx_ref=$2", [status || 'processing', withdrawRef]);

    res.json({ ok: true, msg: 'Withdrawal authorized', status });
  } catch (e) {
    console.error('withdraw/authorize error:', e);
    res.json({ ok: false, msg: 'Server error authorizing withdrawal' });
  }
});

// 10a. GET BANK LIST
// Frontend needs this to populate a bank dropdown for withdrawals.
// Cached in memory for an hour since the bank list rarely changes.
let bankListCache = { data: null, expiresAt: 0 };
app.get('/api/banks', async (req, res) => {
  try {
    if (bankListCache.data && Date.now() < bankListCache.expiresAt) {
      return res.json({ ok: true, banks: bankListCache.data });
    }
    const token = await getMonnifyToken();
    const resp = await fetch(`${MONNIFY_BASE_URL}/api/v1/banks`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await resp.json();
    if (!data.requestSuccessful) return res.json({ ok: false, msg: 'Could not fetch banks' });

    bankListCache.data = data.responseBody;
    bankListCache.expiresAt = Date.now() + 60 * 60 * 1000;
    res.json({ ok: true, banks: data.responseBody });
  } catch (e) {
    console.error('banks error:', e);
    res.json({ ok: false, msg: 'Server error fetching banks' });
  }
});

// 10b. VERIFY BANK ACCOUNT (Name Enquiry)
// Call this BEFORE withdraw so the user can see and confirm whose account
// they're sending to. Monnify requires destinationAccountName to match what
// they have on file, or the transfer fails — this lets you catch typos early
// instead of losing a disbursement attempt.
app.post('/api/verify-account', async (req, res) => {
  const { accountNumber, bankCode } = req.body;
  if (!accountNumber || !bankCode) return res.json({ ok: false, msg: 'accountNumber and bankCode required' });
  try {
    const token = await getMonnifyToken();
    const resp = await fetch(
      `${MONNIFY_BASE_URL}/api/v1/disbursements/account/validate?accountNumber=${accountNumber}&bankCode=${bankCode}`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    const data = await resp.json();
    if (!data.requestSuccessful) return res.json({ ok: false, msg: data.responseMessage || 'Could not verify account' });
    res.json({ ok: true, accountName: data.responseBody.accountName });
  } catch (e) {
    console.error('verify-account error:', e);
    res.json({ ok: false, msg: 'Server error verifying account' });
  }
});

// 10. HISTORY
app.get('/api/history/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const txs = await pool.query('SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [userId]);
    res.json({ ok: true, transactions: txs.rows });
  } catch (e) {
    console.error('history fetch error:', e);
    res.json({ ok: false, msg: 'Server error fetching history' });
  }
});

// 11. GROWTH ENGINE
// FIX: interval/rate now driven by GROWTH_CONFIG at the top of this file.
// Replace GROWTH_RATE / GROWTH_INTERVAL_MS with your real figures before launch.
setInterval(async () => {
  try {
    await pool.query(`UPDATE users SET wallet_balance = wallet_balance + (principal * ${GROWTH_RATE}) WHERE principal > 0`);
    console.log('Growth applied');
  } catch (e) { console.error('Growth error', e) }
}, GROWTH_INTERVAL_MS);

// 12. MONNIFY WEBHOOK
// FIX (this pass): now verifies the 'monnify-signature' header via HMAC-SHA512
// before trusting ANYTHING in the request. Without this, anyone who finds
// this URL could POST a fake SUCCESSFUL_TRANSACTION and credit their own
// wallet for free — this is the single most important fix for a live-money
// integration. Also guards against duplicate webhook deliveries (Monnify can
// retry) by checking paymentReference hasn't already been credited.
//
// FIX (earlier pass, still in effect): referral bonus only pays out on the
// user's FIRST deposit, using a locked client so the check can't race with
// another webhook call for the same user.
app.post('/api/webhook/monnify', async (req, res) => {
  if (!verifyMonnifySignature(req)) {
    console.warn('Rejected webhook: invalid or missing monnify-signature');
    return res.sendStatus(401);
  }

  const { eventType, eventData } = req.body;
  if (eventType !== 'SUCCESSFUL_TRANSACTION') return res.sendStatus(200);

  const { amountPaid, paymentReference, customer } = eventData;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Duplicate-delivery guard: Monnify may resend the same webhook if our
    // response is slow or dropped. If we've already recorded this exact
    // paymentReference as a deposit, skip crediting again.
    const dupCheck = await client.query(
      "SELECT id FROM transactions WHERE tx_ref=$1 AND type='deposit'",
      [paymentReference]
    );
    if (dupCheck.rows.length > 0) { await client.query('ROLLBACK'); return res.sendStatus(200); }

    const userRes = await client.query('SELECT * FROM users WHERE email=$1 FOR UPDATE', [customer.email]);
    if (userRes.rows.length === 0) { await client.query('ROLLBACK'); return res.sendStatus(200); }
    const user = userRes.rows[0];

    // Check BEFORE crediting this deposit whether they've ever deposited before
    const priorDeposits = await client.query(
      "SELECT COUNT(*) FROM transactions WHERE user_id=$1 AND type='deposit'",
      [user.id]
    );
    const isFirstDeposit = parseInt(priorDeposits.rows[0].count) === 0;

    await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, principal = principal + $1 WHERE id=$2', [amountPaid, user.id]);
    await client.query('INSERT INTO transactions(user_id, amount, type, tx_ref) VALUES($1,$2,$3,$4)', [user.id, amountPaid, 'deposit', paymentReference]);

    if (isFirstDeposit && user.referred_by) {
      const bonus = amountPaid * 0.05;
      await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id=$2', [bonus, user.referred_by]);
      await client.query('INSERT INTO transactions(user_id, amount, type) VALUES($1,$2,$3)', [user.referred_by, bonus, 'referral_bonus']);
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Webhook error', e);
  } finally {
    client.release();
  }
  res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SGF Server running on ${PORT}`));
