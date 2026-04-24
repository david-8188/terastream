require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
const limiter = rateLimit({ windowMs: 60000, max: 60 });
app.use(limiter);

// ── DATABASE CONNECTION ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('DB Error:', err));

// ── SCHEMAS ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, lowercase: true },
  passwordHash: { type: String, required: true },
  plan:         { type: String, enum: ['free','credits','lifetime'], default: 'free' },
  credits:      { type: Number, default: 10 },
  creditsResetAt: { type: Date, default: Date.now },
  totalWatched: { type: Number, default: 0 },
  createdAt:    { type: Date, default: Date.now }
});

const bookmarkSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  url:       String,
  title:     String,
  createdAt: { type: Date, default: Date.now }
});

const User     = mongoose.model('User', userSchema);
const Bookmark = mongoose.model('Bookmark', bookmarkSchema);

// ── RAZORPAY ──────────────────────────────────────────────────────────────────
const razorpay = new Razorpay({
  key_id:     process.env.RZP_KEY,
  key_secret: process.env.RZP_SECRET
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_secret_123';

function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

async function resetCreditsIfNeeded(user) {
  const now = new Date();
  const last = new Date(user.creditsResetAt);
  const hoursSince = (now - last) / 36e5;
  if (hoursSince >= 24 && user.plan === 'free') {
    user.credits = 10;
    user.creditsResetAt = now;
    await user.save();
  }
  return user;
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'iTeraPlay backend running ✅', version: '1.0.0' });
});

// ── AUTH: REGISTER ────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(400).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    const token = makeToken(user._id);

    res.json({
      token,
      user: { id: user._id, email: user.email, plan: user.plan, credits: user.credits }
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ── AUTH: LOGIN ───────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid)
      return res.status(400).json({ error: 'Invalid email or password' });

    await resetCreditsIfNeeded(user);
    const token = makeToken(user._id);

    res.json({
      token,
      user: { id: user._id, email: user.email, plan: user.plan, credits: user.credits }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ── AUTH: GET PROFILE ─────────────────────────────────────────────────────────
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    let user = await User.findById(req.userId).select('-passwordHash');
    user = await resetCreditsIfNeeded(user);
    res.json({ user });
  } catch {
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// ── VIDEO: PLAY ───────────────────────────────────────────────────────────────
app.post('/api/video/play', authMiddleware, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url)
      return res.status(400).json({ error: 'Video URL is required' });

    let user = await User.findById(req.userId);
    await resetCreditsIfNeeded(user);

    // Check credits (lifetime users skip this)
    if (user.plan !== 'lifetime' && user.credits <= 0)
      return res.status(403).json({ error: 'No credits left. Please upgrade your plan.' });

    // Call XAPIVerse TeraBox API
    const fetch = (await import('node-fetch')).default;
    const apiRes = await fetch(
      `https://terabox-downloader-direct-download-link-generator.p.rapidapi.com/fetch?url=${encodeURIComponent(url)}`,
      {
        method: 'GET',
        headers: {
          'x-rapidapi-key':  process.env.RAPIDAPI_KEY,
          'x-rapidapi-host': 'terabox-downloader-direct-download-link-generator.p.rapidapi.com'
        }
      }
    );

    if (!apiRes.ok)
      return res.status(502).json({ error: 'Could not fetch video from TeraBox' });

    const data = await apiRes.json();

    // Deduct 1 credit
    if (user.plan !== 'lifetime') {
      user.credits -= 1;
    }
    user.totalWatched += 1;
    await user.save();

    res.json({
      success: true,
      creditsLeft: user.credits,
      videoData: data
    });
  } catch (err) {
    console.error('Play error:', err);
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

// ── BOOKMARKS: GET ────────────────────────────────────────────────────────────
app.get('/api/bookmarks', authMiddleware, async (req, res) => {
  try {
    const bookmarks = await Bookmark.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ bookmarks });
  } catch {
    res.status(500).json({ error: 'Failed to get bookmarks' });
  }
});

// ── BOOKMARKS: ADD ────────────────────────────────────────────────────────────
app.post('/api/bookmarks', authMiddleware, async (req, res) => {
  try {
    const { url, title } = req.body;
    const exists = await Bookmark.findOne({ userId: req.userId, url });
    if (exists)
      return res.status(400).json({ error: 'Already bookmarked' });

    const bookmark = await Bookmark.create({ userId: req.userId, url, title });
    res.json({ bookmark });
  } catch {
    res.status(500).json({ error: 'Failed to add bookmark' });
  }
});

// ── BOOKMARKS: DELETE ─────────────────────────────────────────────────────────
app.delete('/api/bookmarks/:id', authMiddleware, async (req, res) => {
  try {
    await Bookmark.deleteOne({ _id: req.params.id, userId: req.userId });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Failed to delete bookmark' });
  }
});

// ── PAYMENTS: CREATE ORDER ────────────────────────────────────────────────────
app.post('/api/payment/create-order', authMiddleware, async (req, res) => {
  try {
    const { plan } = req.body;
    const plans = {
      credits100:  { amount: 5000,  currency: 'INR', credits: 100  },
      credits200:  { amount: 19900, currency: 'INR', credits: 200  },
      lifetime:    { amount: 39900, currency: 'INR', credits: 99999 }
    };

    const selected = plans[plan];
    if (!selected)
      return res.status(400).json({ error: 'Invalid plan' });

    const order = await razorpay.orders.create({
      amount:   selected.amount,
      currency: selected.currency,
      notes:    { userId: req.userId.toString(), plan, credits: selected.credits }
    });

    res.json({ orderId: order.id, amount: selected.amount, currency: selected.currency });
  } catch (err) {
    console.error('Order error:', err);
    res.status(500).json({ error: 'Failed to create payment order' });
  }
});

// ── PAYMENTS: VERIFY & ADD CREDITS ───────────────────────────────────────────
app.post('/api/payment/verify', authMiddleware, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;

    // Verify signature (security check)
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSig = crypto
      .createHmac('sha256', process.env.RZP_SECRET)
      .update(body)
      .digest('hex');

    if (expectedSig !== razorpay_signature)
      return res.status(400).json({ error: 'Payment verification failed' });

    // Add credits to user
    const credits = { credits100: 100, credits200: 200, lifetime: 99999 };
    const user = await User.findById(req.userId);

    if (plan === 'lifetime') {
      user.plan = 'lifetime';
      user.credits = 99999;
    } else {
      user.plan = 'credits';
      user.credits += credits[plan] || 0;
    }

    await user.save();
    res.json({ success: true, credits: user.credits, plan: user.plan });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ── START SERVER ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
