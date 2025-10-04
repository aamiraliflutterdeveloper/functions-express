// server.js (CommonJS)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

// Load service account
let serviceAccount;
try {
  serviceAccount = require(path.join(__dirname, 'serviceAccountKey.json'));
} catch (err) {
  console.error('serviceAccountKey.json not found in project folder.', err);
  process.exit(1);
}

// Initialize admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// Email transport
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: GMAIL_USER, pass: GMAIL_PASS },
});

const app = express();
app.use(cors());
app.use(express.json());

function errorResponse(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

// Health
app.get('/', (req, res) => res.send('Unhinged Express OTP API is running'));

// sendOtp
app.post('/sendOtp', async (req, res) => {
  const { email, otp, uid } = req.body;
  if (!email || !otp) return errorResponse(res, 400, 'Missing email or otp');

  try {
    // Send mail
    await transporter.sendMail({
      from: `Unhinged App <${GMAIL_USER}>`,
      to: email,
      subject: 'Your OTP Code',
      text: `Your verification code is: ${otp}`,
      html: `<div style="font-family:Arial,sans-serif"><h3>Your OTP</h3><div style="font-size:22px;background:#f4f4f4;padding:10px">${otp}</div><p>Expires in 5 minutes</p></div>`,
    });

    // Save OTP to Firestore.
    // Try to update doc by uid first (common pattern in your app), else find by email.
    let userDocRef = db.collection('users').doc(uid);
    let userSnap = uid ? await userDocRef.get() : null;

    if (!userSnap || !userSnap.exists) {
      // try query by uid field
      if (uid) {
        const snap = await db.collection('users').where('uid', '==', uid).limit(1).get();
        if (!snap.empty) {
          userDocRef = snap.docs[0].ref;
        }
      }
      // else try by email
      if (!userDocRef) {
        const snap2 = await db.collection('users').where('email', '==', email).limit(1).get();
        if (!snap2.empty) userDocRef = snap2.docs[0].ref;
      }
    }

    const expiryAt = admin.firestore.Timestamp.fromDate(new Date(Date.now() + 5 * 60 * 1000));
    if (userDocRef) {
      await userDocRef.set({ otp: otp.toString(), otpExpiresAt: expiryAt }, { merge: true });
    } else {
      console.warn('No user doc found to save OTP. Consider creating the user doc when signing up.');
    }

    return res.json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    console.error('sendOtp error', err);
    return errorResponse(res, 500, 'Failed to send OTP. ' + (err.message || ''));
  }
});

// verifyOtp
app.post('/verifyOtp', async (req, res) => {
  const { email, otp, uid } = req.body;
  if (!email || !otp || !uid) return errorResponse(res, 400, 'Missing email, uid, or otp');

  try {
    // Find user doc by doc id (uid), else by uid field, else by email
    let userDocRef = db.collection('users').doc(uid);
    let userDocSnap = await userDocRef.get();

    if (!userDocSnap.exists) {
      const snap = await db.collection('users').where('uid', '==', uid).limit(1).get();
      if (!snap.empty) {
        userDocSnap = snap.docs[0];
        userDocRef = snap.docs[0].ref;
      } else {
        const snap2 = await db.collection('users').where('email', '==', email).limit(1).get();
        if (!snap2.empty) {
          userDocSnap = snap2.docs[0];
          userDocRef = snap2.docs[0].ref;
        }
      }
    }

    if (!userDocSnap || !userDocSnap.exists) {
      return errorResponse(res, 400, 'User not found in Firestore');
    }

    const data = userDocSnap.data();
    const storedOtp = data?.otp;
    const otpExpiresAt = data?.otpExpiresAt;

    if (!storedOtp) return errorResponse(res, 400, 'OTP not found. Request a new OTP');
    if (!otpExpiresAt) return errorResponse(res, 400, 'OTP expiry missing. Request new OTP');

    const expiryDate = otpExpiresAt.toDate ? otpExpiresAt.toDate() : new Date(otpExpiresAt);
    if (new Date() > expiryDate) return errorResponse(res, 400, 'OTP expired. Request new OTP');

    if (storedOtp.toString() !== otp.toString()) {
      return errorResponse(res, 400, 'Invalid OTP');
    }

    // mark verified in Firestore
    await userDocRef.update({
      emailVerified: true,
      otp: admin.firestore.FieldValue.delete(),
      otpExpiresAt: admin.firestore.FieldValue.delete(),
      verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // update firebase auth (requires service account with permission)
    try {
      await admin.auth().updateUser(uid, { emailVerified: true });
    } catch (authErr) {
      console.error('Failed to update auth user:', authErr);
      // don't fail the whole flow if auth update fails; still return success
    }

    return res.json({ success: true, message: 'Email verified successfully', user: { email, uid } });
  } catch (err) {
    console.error('verifyOtp error', err);
    return errorResponse(res, 500, 'Failed to verify OTP. ' + (err.message || ''));
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
