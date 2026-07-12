'use strict';
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const MagicLink = require('../models/MagicLink');
const OTPVerification = require('../models/OTPVerification');
const Verification = require('../models/Verification');
const Company = require('../models/Company');
const { hashEmail, extractDomain, generateOTP, generateMagicToken } = require('../utils/crypto');
const { sendMagicLink, sendOTP } = require('../config/email');

// ─── JWT helpers ────────────────────────────────────────────────────────────

const signToken = (userId) =>
  jwt.sign({ sub: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE || '7d'
  });

// ─── Controllers ─────────────────────────────────────────────────────────────

/**
 * POST /api/v1/auth/register
 * Body: { email, displayName }
 *
 * Creates or finds a user by their hashed personal email, then sends a magic link.
 * PRIVACY: raw email exists only in this function scope; never written to a log.
 */
const register = async (req, res) => {
  try {
    const { email, displayName } = req.body;
    if (!email || !displayName) {
      return res.status(400).json({ success: false, error: 'email and displayName are required' });
    }

    // Upsert user by hashed email (pre-save hook hashes it automatically)
    let user = await User.findByEmail(email);
    if (!user) {
      user = await User.create({ personal_email: email, display_name: displayName });
    }

    // Generate token and store magic link
    const rawToken = generateMagicToken();
    await MagicLink.create({ token: rawToken, user_id: user._id });

    // Send — raw email is only in this scope and is not persisted
    await sendMagicLink(email, rawToken);

    // Immediately discard reference to raw email (null assignment makes intent explicit)
    // eslint-disable-next-line no-param-reassign
    req.body.email = null;

    return res.status(202).json({
      success: true,
      data: { message: 'Magic link sent. Check your inbox.' }
    });
  } catch (err) {
    console.error('[register]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

/**
 * GET /api/v1/auth/verify-magic/:token
 * Validates magic link, returns JWT.
 * PRIVACY: no email ever returned in this response.
 */
const verifyMagicLink = async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) return res.status(400).json({ success: false, error: 'Token required' });

    const link = await MagicLink.findOne({ token, used: false });
    if (!link) return res.status(401).json({ success: false, error: 'Invalid or already-used token' });

    if (link.expires_at < new Date()) {
      return res.status(401).json({ success: false, error: 'Token expired' });
    }

    // Mark as used (single-use)
    link.used = true;
    await link.save();

    const user = await User.findById(link.user_id).select('-personal_email');
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const jwtToken = signToken(String(user._id));

    return res.status(200).json({
      success: true,
      data: {
        token: jwtToken,
        user: {
          userId: user._id,
          displayName: user.display_name,
          avatarUrl: user.avatar_url || null,
          createdAt: user.created_at
        }
      }
    });
  } catch (err) {
    console.error('[verifyMagicLink]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

/**
 * POST /api/v1/auth/verify-work
 * Body: { workEmail }
 *
 * PRIVACY CRITICAL PATH:
 *  1. Extract domain from workEmail
 *  2. Hash workEmail
 *  3. Send OTP to workEmail
 *  4. Immediately delete workEmail from memory — only hash + domain persist
 */
const requestWorkVerification = async (req, res) => {
  try {
    // PRIVACY: workEmail is a local variable — it must NOT be logged, stored, or forwarded
    let { workEmail } = req.body;
    const userId = req.user._id;

    if (!workEmail) {
      return res.status(400).json({ success: false, error: 'workEmail is required' });
    }

    // Step 1 & 2: domain extraction and hashing happen before anything else
    const domain = extractDomain(workEmail);
    const emailHash = hashEmail(workEmail);

    // Step 3: find or create company by domain
    let company = await Company.findOne({ domain_name: domain });
    if (!company) {
      company = await Company.create({
        domain_name: domain,
        display_name: domain.split('.')[0].charAt(0).toUpperCase() + domain.split('.')[0].slice(1)
      });
    }

    // Generate OTP
    const otp = generateOTP();

    // Expire any existing unused OTP for this user+company
    await OTPVerification.deleteMany({ user_id: userId, company_domain_id: company._id, used: false });

    // Persist only the hash — the raw email is NEVER written to the DB
    await OTPVerification.create({
      work_email_hash: emailHash,
      otp_code: otp,
      company_domain_id: company._id,
      user_id: userId
    });

    // Step 3: send OTP (workEmail is still in scope here — required for delivery)
    await sendOTP(workEmail, otp);

    // Step 4: PRIVACY — immediately discard raw work email from memory
    workEmail = null; // eslint-disable-line no-param-reassign
    req.body.workEmail = null;

    return res.status(202).json({
      success: true,
      data: {
        message: 'OTP sent to your work inbox. It expires in 15 minutes.',
        company: { domain, displayName: company.display_name }
      }
    });
  } catch (err) {
    console.error('[requestWorkVerification]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

/**
 * POST /api/v1/auth/verify-otp
 * Body: { workEmailHash, otp }
 *
 * Validates the OTP, creates a Verification record, marks OTP used.
 * PRIVACY: no raw work email is ever passed here — only its hash.
 */
const verifyOTP = async (req, res) => {
  try {
    const { workEmailHash, otp } = req.body;
    const userId = req.user._id;

    if (!workEmailHash || !otp) {
      return res.status(400).json({ success: false, error: 'workEmailHash and otp are required' });
    }

    const otpRecord = await OTPVerification.findOne({
      work_email_hash: workEmailHash,
      user_id: userId,
      used: false
    });

    if (!otpRecord) {
      return res.status(401).json({ success: false, error: 'OTP not found or already used' });
    }

    if (otpRecord.expires_at < new Date()) {
      return res.status(401).json({ success: false, error: 'OTP expired' });
    }

    if (otpRecord.otp_code !== String(otp)) {
      return res.status(401).json({ success: false, error: 'Invalid OTP' });
    }

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Create or update Verification link (user ↔ company — no email stored)
    await Verification.findOneAndUpdate(
      { user_id: userId, company_domain_id: otpRecord.company_domain_id },
      { user_id: userId, company_domain_id: otpRecord.company_domain_id, verified_at: new Date() },
      { upsert: true, new: true }
    );

    const company = await Company.findById(otpRecord.company_domain_id).select('domain_name display_name');

    return res.status(200).json({
      success: true,
      data: {
        message: 'Work email verified successfully.',
        verification: {
          companyDomain: company.domain_name,
          companyDisplayName: company.display_name,
          verifiedAt: new Date()
        }
      }
    });
  } catch (err) {
    console.error('[verifyOTP]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

/**
 * GET /api/v1/auth/me
 * PRIVACY: personal_email (hashed) and any sensitive fields are excluded from the response.
 */
const getMe = async (req, res) => {
  try {
    // Exclude personal_email even though it is only a hash — no identity field should leak
    const user = await User.findById(req.user._id).select('-personal_email');
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    // Fetch verification status
    const verification = await Verification.findOne({ user_id: user._id })
      .populate('company_domain_id', 'domain_name display_name');

    return res.status(200).json({
      success: true,
      data: {
        userId: user._id,
        displayName: user.display_name,
        avatarUrl: user.avatar_url || null,
        createdAt: user.created_at,
        verification: verification
          ? {
              companyDomain: verification.company_domain_id.domain_name,
              companyDisplayName: verification.company_domain_id.display_name,
              verifiedAt: verification.verified_at
            }
          : null
      }
    });
  } catch (err) {
    console.error('[getMe]', err.message);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

module.exports = { register, verifyMagicLink, requestWorkVerification, verifyOTP, getMe };
